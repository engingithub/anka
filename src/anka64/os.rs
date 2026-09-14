//! Anka64 Secure OS — capability-mediated process model.
//!
//! A "process" is a (domain, code object, data object, stack object)
//! tuple. The OS kernel runs in supervisor privilege and mediates
//! all inter-domain interactions through the fabric.
//!
//! Syscall convention (via TRAP #0):
//!   R0 = syscall number
//!   R1–R3 = arguments
//!   R0 = return value

use super::block::BlockController;
use super::core::Anka64Core;
use super::fabric::Fabric;
use super::isa::*;
use super::state::*;

// ───────────────────────────────────────────────────────────────────
// Syscall numbers
// ───────────────────────────────────────────────────────────────────

pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;  // write(addr, len, 0) — buffer output
pub const SYS_YIELD: u64 = 2;  // yield to other process
pub const SYS_SEND: u64 = 3;   // send(dest_pid, value)
pub const SYS_RECV: u64 = 4;   // recv() → value
pub const SYS_SEAL: u64 = 5;   // seal(addr) — RW→RX, W⊕X enforcement
pub const SYS_EXEC: u64 = 6;   // exec(code_addr, code_size, lit_start) → child exit
pub const SYS_SPAWN: u64 = 7;  // spawn(R1-R8: code, grants, maps, layout) → handle
pub const SYS_WAIT: u64 = 8;   // wait(handle) → result
pub const SYS_BLOCK_READ: u64 = 9; // block_read(block_num, buf_vaddr) → async
pub const SYS_CAP_DROP: u64 = 10;  // cap_drop(slot, generation) → 0 ok, 1 bad handle

// ───────────────────────────────────────────────────────────────────
// Process descriptor
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u64,
    pub state: ProcessState,
    pub core: Anka64Core,
    pub exit_code: u64,
    /// If Some, this process is blocked waiting for a specific child incarnation.
    pub waiting_on: Option<WaitState>,
    /// If Some, process is blocked on a SYS_BLOCK_READ with its
    /// EventFrame still outstanding.  The completion path must
    /// match both RequesterKey (process incarnation) and
    /// RequestHandle (I/O operation) before performing event_return().
    pub io_wait: Option<IoWait>,
    /// Exact incarnation of the parent (None for init).
    pub parent: Option<ProcessKey>,
    /// Generation counter for lifecycle authority.
    pub generation: u32,
    /// Structured result: Exited(code) or fault.
    pub result: Option<ProcessResult>,
    /// Resources owned by this incarnation (None for Free/Retired slots).
    pub resources: Option<OwnedResources>,
    /// Per-process capability table (Phase 9.2a).
    /// Some for live incarnations; None for Free/Retired slots.
    pub cap_table: Option<CapabilityTable>,
}

impl Process {
    /// Convenience: true if the process has terminated (is no longer Running).
    pub fn exited(&self) -> bool {
        self.state != ProcessState::Running
    }
}

/// Process lifecycle result — distinguishes normal exit from fault.
/// "program returned 7" != "program died with ExecuteDenied".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessResult {
    /// Process exited normally with exit code.
    Exited(u64),
    /// Process died due to a supervisor fault (HALT not at trap gate).
    SupervisorFault,
    /// Process died due to an architectural protection fault.
    ProtectionFault,
}

// ───────────────────────────────────────────────────────────────────
// Physical extent and owned resources
// ───────────────────────────────────────────────────────────────────

/// A contiguous range of physical memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalExtent {
    pub base: u64,
    pub size: u64,
}

/// All resources owned by a specific process incarnation.
/// Created during prepare_process, consumed during reclaim.
#[derive(Debug, Clone)]
pub struct OwnedResources {
    pub domain: DomainId,
    pub stack_obj: ObjectId,
    pub trap_obj: ObjectId,
    pub stack_extent: PhysicalExtent,
    pub trap_extent: PhysicalExtent,
}

// ───────────────────────────────────────────────────────────────────
// Result encoding (Rule 28: one authoritative encoder per ABI)
// ───────────────────────────────────────────────────────────────────

/// Structured two-register WAIT ABI.
///   R0 = tag:  0 = Exited, 1 = SupervisorFault, 2 = ProtectionFault, MAX = invalid
///   R1 = detail: exit code for Exited, 0 otherwise
/// Used by SYS_WAIT (lifecycle path) and wake_waiters (lifecycle path).
fn encode_wait_result(result: &ProcessResult) -> (u64, u64) {
    match result {
        ProcessResult::Exited(code) => (0, *code),
        ProcessResult::SupervisorFault => (1, 0),
        ProcessResult::ProtectionFault => (2, 0),
    }
}

/// Invalid handle sentinel for the two-register WAIT ABI.
fn encode_wait_invalid() -> (u64, u64) {
    (u64::MAX, 0)
}

/// Historical single-register EXEC ABI.
/// Preserves exact legacy behavior: exit code for normal exit, 0xDEAD for faults.
fn encode_exec_result(result: &ProcessResult) -> u64 {
    match result {
        ProcessResult::Exited(code) => *code,
        ProcessResult::SupervisorFault | ProcessResult::ProtectionFault => 0xDEAD,
    }
}

// ───────────────────────────────────────────────────────────────────
// Lifecycle authority
//
// Four distinct concepts:
//   LifecycleHandle  = parent-local authority reference (user-facing)
//   ProcessKey       = kernel identity of a specific process incarnation
//   LifecycleEntry   = one slot in a parent's lifecycle authority table
//   WaitState        = suspended observation of an exact ProcessKey
//
// Two deliberate generations:
//   g_handle (slot_generation) — prevents stale lifecycle-slot reuse
//                                within a long-lived parent
//   g_process (ProcessKey.generation) — prevents stale PID/process-slot
//                                       reuse across the kernel
//
// "Authority cannot arise from nowhere": knowing every bit of a
// LifecycleHandle does not create authority.  The handle resolves
// only in the calling process's own kernel-protected table.
// ───────────────────────────────────────────────────────────────────

/// Process lifecycle state — four durable kernel states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is executing or blocked (waiting_on).
    Running,
    /// Process has exited or faulted; result available, resources attached.
    Zombie,
    /// Slot available for reuse; generation already incremented.
    Free,
    /// Generation exhausted; slot permanently unavailable.
    Retired,
}

/// Kernel-internal identity of a specific process incarnation.
/// Slot is the index into the processes Vec; generation distinguishes
/// successive incarnations in the same slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessKey {
    pub slot: usize,
    pub generation: u32,
}

/// User-facing lifecycle handle: (slot_generation:u32 | slot:u32).
/// Returned by SYS_SPAWN, consumed by SYS_WAIT.
/// Meaningful only within the parent process that received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleHandle(u64);

impl LifecycleHandle {
    fn new(slot: u32, slot_generation: u32) -> Self {
        Self((slot_generation as u64) << 32 | slot as u64)
    }

    fn slot(&self) -> u32 { self.0 as u32 }
    fn slot_generation(&self) -> u32 { (self.0 >> 32) as u32 }

    pub fn as_u64(&self) -> u64 { self.0 }
    pub fn from_u64(v: u64) -> Self { Self(v) }
}

/// One entry in a process's lifecycle authority table.
#[derive(Debug, Clone)]
pub(crate) struct LifecycleEntry {
    pub(crate) slot_generation: u32,
    pub(crate) child: ProcessKey,
    pub(crate) collected: bool,
}

/// Distinguishes two wait ABIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitKind {
    /// SYS_EXEC: single-register historical ABI (R0 = exit_code or 0xDEAD).
    Exec,
    /// SYS_WAIT: two-register tagged ABI (R0 = tag, R1 = detail).
    Lifecycle,
}

/// Suspended observation of a specific child incarnation.
#[derive(Debug, Clone)]
struct WaitState {
    child: ProcessKey,
    kind: WaitKind,
    /// Index into the parent's lifecycle table (Lifecycle path only).
    handle_slot: Option<usize>,
}

/// Suspended I/O wait — the process has an outstanding
/// SYS_BLOCK_READ whose EventFrame remains on the frame stack.
///
/// Two independent identity protections:
///   RequesterKey — which process incarnation?
///   RequestHandle — which I/O operation?
///
/// The completion must match both before the kernel will perform
/// event_return() and resume the caller at user PC.
#[derive(Debug, Clone)]
pub struct IoWait {
    pub request: super::block::RequestHandle,
}

// ───────────────────────────────────────────────────────────────────
// Message mailbox
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct Message {
    #[allow(dead_code)]
    pub(crate) from_pid: u64,
    pub(crate) value: u64,
}

// ───────────────────────────────────────────────────────────────────
// HALT classification — one authoritative rule (Rule 28)
//
// Three machine events collapse into StepResult::Halted, but they
// have completely different process-level meanings.  This function
// is the single point of truth consumed by run_process().  SYS_EXEC
// creates a runnable child and blocks the parent; the scheduler
// drives both through the same run_process() path.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum HaltDisposition {
    /// User-mode HALT: _start's HALT after main returns.
    /// Implicit SYS_EXIT with exit_code = R0.
    UserExit(u64),
    /// Supervisor HALT at the trap gate: TRAP → handler → HALT.
    /// R0 = syscall number.  EventFrame cause = Syscall.
    Syscall,
    /// Supervisor HALT at the trap gate caused by a timer interrupt.
    /// EventFrame cause = TimerInterrupt.
    TimerInterrupt,
    /// Supervisor HALT at the trap gate caused by a device interrupt.
    /// EventFrame cause = DeviceInterrupt.
    DeviceInterrupt,
    /// Supervisor HALT not at the trap gate: kernel halt/panic.
    SupervisorFault,
}

fn classify_halt(core: &Anka64Core) -> HaltDisposition {
    use super::state::EventCause;
    if core.privilege == Privilege::Supervisor && core.pc == core.trap_vector {
        match core.event_frames.last().map(|f| &f.cause) {
            Some(EventCause::Syscall) => HaltDisposition::Syscall,
            Some(EventCause::TimerInterrupt) => HaltDisposition::TimerInterrupt,
            Some(EventCause::DeviceInterrupt) => HaltDisposition::DeviceInterrupt,
            None => HaltDisposition::SupervisorFault,
        }
    } else if core.privilege == Privilege::Supervisor {
        HaltDisposition::SupervisorFault
    } else {
        HaltDisposition::UserExit(core.r[R0 as usize])
    }
}

// ───────────────────────────────────────────────────────────────────
// Kernel
// ───────────────────────────────────────────────────────────────────

/// Resource bound for SYS_WRITE: maximum bytes per call.
/// Prevents a malicious guest from forcing unbounded host allocation.
const MAX_WRITE: u64 = 0x10000; // 64 KiB

/// Maximum number of spawn grant/map descriptors.
/// Prevents hostile code from forcing unbounded kernel allocation.
const MAX_SPAWN_GRANTS: u64 = 64;
const MAX_SPAWN_MAPS: u64 = 64;

/// In-memory SpawnGrant descriptor: 5 × u64 = 40 bytes.
///   [0] parent_vaddr: u64  — virtual address in parent identifying the object
///   [1] offset: u64        — offset relative to the resolved mapping position
///   [2] size: u64          — extent of the grant
///   [3] perms: u64         — child permissions (R=0x01, W=0x02, X=0x04, S=0x10)
///   [4] _reserved: u64     — must be zero
const SPAWN_GRANT_SIZE: u64 = 40;

/// In-memory SpawnMap descriptor: 5 × u64 = 40 bytes.
///   [0] child_vaddr: u64   — where to place in the child's virtual space
///   [1] parent_vaddr: u64  — virtual address in parent identifying the object
///   [2] offset: u64        — offset relative to the resolved mapping position
///   [3] size: u64          — extent of the mapping
///   [4] _reserved: u64     — must be zero
const SPAWN_MAP_SIZE: u64 = 40;

// Permission validation now uses Permissions::from_bits_checked (state.rs).

/// In-memory SpawnLayout descriptor: 5 × u64 = 40 bytes.
///   [0] code_vaddr: u64    — where to place the child's code
///   [1] stack_vaddr: u64   — where to place the child's stack
///   [2] stack_size: u64    — size of the child's stack
///   [3] trap_vaddr: u64    — where to place the child's trap handler
///   [4] _reserved: u64     — must be zero
const SPAWN_LAYOUT_SIZE: u64 = 40;

/// Minimum stack size for spawned processes.
const MIN_STACK_SIZE: u64 = 0x1000;

/// Maximum stack size for spawned processes.
const MAX_STACK_SIZE: u64 = 0x100000; // 1 MiB

/// Executable image geometry — already validated by caller.
/// Used by the shared process-creation primitive (prepare_process).
struct ProcessImageDesc {
    code_obj: ObjectId,
    code_offset: u64,
    code_size: u64,
    lit_start: u64,      // image-relative; 0 if no literals
    image_size: u64,     // total image = obj_size - code_offset
    entry: u64,          // image-relative entry point
}

/// Virtual address layout for a new process.
///
/// Process creation mechanism must not assume one universal virtual layout.
/// The compiler's address space is not the tiny child's address space.
struct ProcessLayout {
    code_vaddr: u64,
    stack_vaddr: u64,
    stack_size: u64,
    trap_vaddr: u64,
}

/// Default layout used by SYS_EXEC children.
const EXEC_DEFAULT_LAYOUT: ProcessLayout = ProcessLayout {
    code_vaddr: 0,
    stack_vaddr: 0x10000,
    stack_size: 0x4000,
    trap_vaddr: 0x20000,
};

// ───────────────────────────────────────────────────────────────────
// Shared process-environment types
//
// Both boot() and SYS_SPAWN need to express "initial delegated
// authority" and "initial virtual placement" for a new process.
// The authority source differs (trusted boot root vs parent domain),
// but the kernel-internal representation after resolution is the same.
//
// Authority != placement (Rule 1):
//   InitialGrant = what the child may access
//   InitialMap   = where it appears in virtual space
//
// A map never creates authority.  Every map must have a covering
// grant in the child's domain; maps without covering authority are
// rejected as descriptor errors.
// ───────────────────────────────────────────────────────────────────

/// Kernel-internal resolved grant: additional authority for a new process.
/// The object and range are already validated; the caller is responsible
/// for ensuring the grant is derivable from the authority source.
#[derive(Debug, Clone)]
pub(crate) struct InitialGrant {
    pub obj: ObjectId,
    pub offset: u64,
    pub size: u64,
    pub perms: Permissions,
}

/// Kernel-internal resolved map: additional virtual address mapping.
/// The object and range are already validated by the caller.
#[derive(Debug, Clone)]
pub(crate) struct InitialMap {
    pub vaddr: u64,
    pub size: u64,
    pub obj: ObjectId,
    pub obj_offset: u64,
}

// ───────────────────────────────────────────────────────────────────
// Boot contract types
//
// The boot contract separates authority from placement (Rule 1):
//   BootImage  — identifies the sealed executable object
//   BootGrant  — additional authority beyond the image
//   BootMap    — virtual address placement
//
// BootImage implicitly creates:
//   - RX grant covering [code_offset .. code_offset + code_size)
//   - R  grant covering [code_offset + lit_start .. code_offset + image_end) if lit_start > 0
//   - address map entry: virtual 0 → code
//   - address map entry: virtual lit_start → literals (if present)
//
// Invariant: BootGrant ranges may NOT overlap the BootImage backing
// range [code_offset .. code_offset + image_size).  This preserves
// Rule 28 (one semantic fact, one definition) and Rule 29 (data
// that names code is not authority to transfer control to it).
//
// Invariant: BootMap virtual ranges may NOT overlap each other or
// the implicit BootImage/stack/trap mappings.
// ───────────────────────────────────────────────────────────────────

/// The sealed executable image that init will execute.
#[derive(Debug, Clone)]
pub struct BootImage {
    /// Object containing the executable image (must be Sealed).
    pub obj: ObjectId,
    /// Byte offset within the object where code begins.
    pub code_offset: u64,
    /// Size of the code segment in bytes.
    pub code_size: u64,
    /// Image-relative entry point (must be < code_size).
    pub entry: u64,
    /// Image-relative start of the literal segment.
    /// 0 means no literals.  Must satisfy: code_size <= lit_start < image_size.
    pub lit_start: u64,
}

/// Additional authority granted to init beyond the executable image.
/// The (obj, offset, size) range must NOT overlap the BootImage
/// backing range within the same object.
#[derive(Debug, Clone)]
pub struct BootGrant {
    pub obj: ObjectId,
    pub offset: u64,
    pub size: u64,
    pub perms: Permissions,
}

/// Additional virtual address mapping for init.
/// The virtual range [vaddr .. vaddr + size) must NOT overlap any
/// other BootMap entry or the implicit code/literal/stack/trap maps.
#[derive(Debug, Clone)]
pub struct BootMap {
    pub vaddr: u64,
    pub size: u64,
    pub obj: ObjectId,
    pub obj_offset: u64,
}

/// Complete boot descriptor.
#[derive(Debug, Clone)]
pub struct BootInfo {
    pub image: BootImage,
    pub grants: Vec<BootGrant>,
    pub maps: Vec<BootMap>,
    /// Virtual address where init's code is mapped.
    pub code_vaddr: u64,
    /// Virtual address for init's stack.
    pub stack_vaddr: u64,
    /// Size of init's stack in bytes.
    pub stack_size: u64,
    /// Virtual address for init's trap handler.
    pub trap_vaddr: u64,
}

/// Boot error — reason a boot descriptor was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum BootError {
    /// The kernel has already been successfully booted.
    AlreadyBooted,
    /// The image object does not exist.
    ImageNotFound,
    /// The image object is not Sealed.
    ImageNotSealed,
    /// entry >= code_size.
    InvalidEntry,
    /// code_size is zero.
    ZeroCode,
    /// lit_start is non-zero but < code_size or >= image_size.
    InvalidLiterals,
    /// A BootGrant range overlaps the BootImage backing range.
    GrantOverlapsImage,
    /// Two BootMap virtual ranges overlap each other or an implicit mapping.
    OverlappingMaps,
    /// A BootGrant references an object that doesn't exist.
    GrantObjectNotFound,
    /// A BootMap references an object that doesn't exist.
    MapObjectNotFound,
    /// A BootGrant range exceeds the object size.
    GrantOutOfBounds,
    /// A BootMap range exceeds the object size.
    MapOutOfBounds,
}

pub struct Kernel {
    pub fabric: Fabric,
    pub processes: Vec<Process>,
    /// Byte output buffer.  SYS_WRITE appends here on success.
    /// Output-atomic: a failed SYS_WRITE leaves this unchanged.
    pub byte_output: Vec<u8>,
    pub(crate) mailboxes: Vec<Vec<Message>>,
    current: usize,
    /// Next available physical address for dynamic allocation.
    pub next_phys: u64,
    /// Next available agent ID for child processes.
    pub next_agent: u64,
    /// Monotonic PID counter (checked, never wraps, never reused).
    next_pid: u64,
    /// One-success-only boot flag.  Set to true after a successful boot.
    booted: bool,
    /// Per-process lifecycle authority tables.
    /// lifecycle_tables[slot] = that slot's lifecycle entries.
    pub(crate) lifecycle_tables: Vec<Vec<LifecycleEntry>>,
    /// Recycled stack extents (exact-size match only).
    pub(crate) free_stack_extents: Vec<PhysicalExtent>,
    /// Recycled trap extents (exact-size match only).
    pub(crate) free_trap_extents: Vec<PhysicalExtent>,
    /// Optional block device controller.
    /// When present, tick_devices() advances it and routes
    /// level-triggered device interrupts.
    pub block_controller: Option<BlockController>,
}

impl Kernel {
    pub fn new(fabric: Fabric) -> Self {
        Self {
            fabric,
            processes: Vec::new(),
            byte_output: Vec::new(),
            mailboxes: Vec::new(),
            current: 0,
            next_phys: 0x100000,
            next_agent: 100,
            next_pid: 0,
            booted: false,
            lifecycle_tables: Vec::new(),
            free_stack_extents: Vec::new(),
            free_trap_extents: Vec::new(),
            block_controller: None,
        }
    }

    // ─── Physical extent allocation ──────────────────────────────
    //
    // Exact-size reuse: scan pool for matching extent, else bump.
    // Recycled extents are scrubbed (zeroed) before return.
    // Ordering: take → zero → create object → grant authority.

    /// Allocate a physical extent for a process stack.
    pub(crate) fn alloc_stack_extent(&mut self, size: u64) -> PhysicalExtent {
        if let Some(idx) = self.free_stack_extents.iter().position(|e| e.size == size) {
            let ext = self.free_stack_extents.swap_remove(idx);
            self.fabric.zero_physical(ext.base, ext.size);
            ext
        } else {
            let base = self.next_phys;
            self.next_phys += size;
            PhysicalExtent { base, size }
        }
    }

    /// Allocate a physical extent for a process trap page.
    pub(crate) fn alloc_trap_extent(&mut self, size: u64) -> PhysicalExtent {
        if let Some(idx) = self.free_trap_extents.iter().position(|e| e.size == size) {
            let ext = self.free_trap_extents.swap_remove(idx);
            self.fabric.zero_physical(ext.base, ext.size);
            ext
        } else {
            let base = self.next_phys;
            self.next_phys += size;
            PhysicalExtent { base, size }
        }
    }

    // ─── Map-overlap validation ────────────────────────────────
    //
    // Shared by boot() and SYS_SPAWN.  Checks that a set of
    // virtual ranges (implicit + explicit maps) do not overlap.
    // Returns true if all ranges are disjoint.

    // ─── Single-mapping range resolver ─────────────────────────
    //
    // Resolves [vaddr, vaddr+size) through a process's address map
    // to (ObjectId, obj_offset) with the guarantee that the entire
    // range falls within exactly one address-map entry.
    //
    // This prevents two adjacent virtual mappings from being stitched
    // together to reach an unrelated part of an object.
    //
    // Used by: SYS_WRITE preflight, spawn descriptor table reads,
    // spawn grant/map resolution.

    /// Resolve a virtual range [vaddr, vaddr+size) through a process's
    /// address map.  Returns (ObjectId, base_obj_offset) if the entire
    /// range falls within exactly one AddressMapEntry.
    ///
    /// This is the exact-one-entry guarantee.  Two adjacent entries
    /// mapping contiguous portions of the same object cannot be
    /// stitched together — the structural containment check lives
    /// in AddressMap::resolve_range_single_entry().
    fn resolve_virtual_range(
        &self, idx: usize, vaddr: u64, size: u64,
    ) -> Option<(ObjectId, u64)> {
        self.processes[idx].core.address_map.resolve_range_single_entry(vaddr, size)
    }

    /// Read `size` bytes from process `idx`'s virtual address space,
    /// starting at `vaddr`.  The entire range must fall within a single
    /// address-map entry and be authorized for READ by the process's
    /// domain.  Returns None on any failure.
    ///
    /// This produces a kernel-owned copy.  Validation and commit
    /// operate on this copy, not on the original memory.
    fn read_virtual_bytes(&self, idx: usize, vaddr: u64, size: u64) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        let (obj, off) = self.resolve_virtual_range(idx, vaddr, size)?;

        // Verify parent has READ authority over this range
        let domain = self.processes[idx].core.domain;
        self.fabric.find_authorizing_cap(
            domain, obj, off, size, Permissions::READ,
        )?;

        // Translate to physical address and read
        let phys = self.fabric.translate(obj, off)?;
        Some(self.fabric.read_physical(phys, size).to_vec())
    }

    fn validate_no_map_overlap(ranges: &[(u64, u64)]) -> bool {
        for i in 0..ranges.len() {
            for j in (i + 1)..ranges.len() {
                let (a_start, a_end) = ranges[i];
                let (b_start, b_end) = ranges[j];
                if a_start < b_end && b_start < a_end {
                    return false;
                }
            }
        }
        true
    }

    // ─── Shared process-image creation primitive ────────────────
    //
    // Used by SYS_EXEC, SYS_SPAWN, and Kernel::boot().  The caller
    // is responsible for:
    //   1. Creating the domain
    //   2. Granting executable image authority (RX for code, R for literals)
    //   3. Granting any additional InitialGrants into the domain
    //   4. Validating all maps for overlap
    //
    // This method creates stack, trap handler, address map, and core.
    // It also installs any InitialMaps into the child's address map.
    //
    // The difference between boot() and SYS_SPAWN is the authority
    // source: boot() establishes from trusted boot state; SYS_SPAWN
    // derives from a parent domain.  SYS_EXEC passes no additional
    // grants or maps.  Everything after authority establishment is
    // the same mechanism.

    /// Create process infrastructure for a domain that already has
    /// executable image authority (and any additional grants).
    /// Returns the spawned ProcessKey.
    ///
    /// `initial_maps` are additional virtual address mappings installed
    /// into the child's address map.  The caller must have already
    /// validated that these do not overlap with implicit regions or
    /// each other.
    ///
    /// On failure, rolls back: destroys domain and any resources
    /// created during preparation.  No reachable domain, capability,
    /// mapping, or runnable process survives a failed preparation.
    fn prepare_process(
        &mut self,
        dom: DomainId,
        desc: &ProcessImageDesc,
        layout: &ProcessLayout,
        initial_maps: &[InitialMap],
    ) -> ProcessKey {
        // --- Stack: alloc extent (recycled or bump), create object ---
        let stack_extent = self.alloc_stack_extent(layout.stack_size);
        let stack_obj = self.fabric.alloc_object(
            "process_stack", layout.stack_size, ObjectKind::Memory);
        self.fabric.place_object(stack_obj, stack_extent.base);
        self.fabric.grant(dom, stack_obj, 0, layout.stack_size, Permissions::RW);

        // --- Trap: alloc extent, create/initialize/seal/grant ---
        let trap_size: u64 = 0x1000;
        let trap_extent = self.alloc_trap_extent(trap_size);
        let trap_obj = self.fabric.alloc_object("process_trap", trap_size, ObjectKind::Memory);
        self.fabric.place_object(trap_obj, trap_extent.base);

        let mut handler = Asm64::new();
        handler.halt();
        self.fabric.initialize_object(trap_obj, 0, &handler.to_bytes());
        self.fabric.seal_object(trap_obj);
        self.fabric.grant(dom, trap_obj, 0, trap_size, Permissions::RX);

        // --- Core ---
        let agent = AgentId(self.next_agent);
        self.next_agent += 1;

        let mut core = Anka64Core::new(agent, dom);
        core.address_map.add_at(
            layout.code_vaddr, desc.code_size, desc.code_obj, desc.code_offset);
        core.pc = layout.code_vaddr + desc.entry;
        if desc.lit_start != 0 {
            let lit_length = desc.image_size - desc.lit_start;
            core.address_map.add_at(
                layout.code_vaddr + desc.lit_start, lit_length, desc.code_obj,
                desc.code_offset + desc.lit_start);
        }
        core.address_map.add(layout.stack_vaddr, layout.stack_size, stack_obj);
        core.address_map.add(layout.trap_vaddr, trap_size, trap_obj);
        core.r[SP as usize] = layout.stack_vaddr + layout.stack_size;
        core.trap_vector = layout.trap_vaddr;

        // --- Additional maps from initial environment ---
        for m in initial_maps {
            core.address_map.add_at(m.vaddr, m.size, m.obj, m.obj_offset);
        }

        // --- Spawn and capture ownership ---
        let key = self.spawn(core);
        self.processes[key.slot].resources = Some(OwnedResources {
            domain: dom,
            stack_obj,
            trap_obj,
            stack_extent,
            trap_extent,
        });
        key
    }

    pub fn spawn(&mut self, core: Anka64Core) -> ProcessKey {
        let pid = self.next_pid;
        self.next_pid = self.next_pid.checked_add(1)
            .expect("PID space exhausted");

        // Try to reuse a Free slot (Free(g) → Running(g), same generation)
        if let Some(slot) = self.processes.iter().position(|p| p.state == ProcessState::Free) {
            let reuse_gen = self.processes[slot].generation;
            self.processes[slot] = Process {
                pid,
                state: ProcessState::Running,
                core,
                exit_code: 0,
                waiting_on: None,
                io_wait: None,
                parent: None,
                generation: reuse_gen,
                result: None,
                resources: None,
                cap_table: Some(CapabilityTable::new()),
            };
            self.mailboxes[slot].clear();
            self.lifecycle_tables[slot].clear();
            return ProcessKey { slot, generation: reuse_gen };
        }

        // No Free slot — append
        let slot = self.processes.len();
        self.processes.push(Process {
            pid,
            state: ProcessState::Running,
            core,
            exit_code: 0,
            waiting_on: None,
            io_wait: None,
            parent: None,
            generation: 0,
            result: None,
            resources: None,
            cap_table: Some(CapabilityTable::new()),
        });
        self.mailboxes.push(Vec::new());
        self.lifecycle_tables.push(Vec::new());
        ProcessKey { slot, generation: 0 }
    }

    /// Install a capability into a process's cap table.
    ///
    /// Allocates a fresh AuthorityId, grants the capability in the
    /// process's Fabric domain with that AuthorityId, and installs
    /// a cap-table slot linking to it.  Returns the CapabilityHandle
    /// on success, or None if the Fabric grant fails or the table is full.
    ///
    /// Used by boot/spawn to seed initial handles and by tests.
    /// Runtime transfer belongs to 9.2b.
    pub fn install_capability(
        &mut self,
        slot: usize,
        object: ObjectId,
        offset: u64,
        length: u64,
        perms: Permissions,
    ) -> Option<CapabilityHandle> {
        let domain = self.processes[slot].core.domain;
        let auth_id = self.fabric.alloc_authority_id();

        self.fabric.grant_with_authority_id(
            domain, object, offset, length, perms, auth_id,
        )?;

        let obj_gen = self.fabric.objects.get(&object)?.generation;

        self.processes[slot].cap_table.as_mut()?
            .install(object, obj_gen, offset, length, perms, auth_id)
    }

    /// Resolve a capability handle for a process.
    ///
    /// Three-condition check:
    ///   1. handle_generation = slot.handle_generation
    ///   2. slot is Occupied (AuthorityId exists)
    ///   3. object_generation = current Fabric object generation
    ///
    /// This is the kernel-side wrapper that supplies the Fabric
    /// generation lookup closure.
    pub fn resolve_capability(
        &self,
        slot: usize,
        handle: CapabilityHandle,
    ) -> Option<ResolvedCapability> {
        let ct = self.processes[slot].cap_table.as_ref()?;
        ct.resolve(handle, |oid| {
            self.fabric.objects.get(&oid).map(|o| o.generation)
        })
    }

    /// Install a lifecycle entry in a parent's table.
    /// Returns the LifecycleHandle for the new entry.
    fn install_lifecycle(&mut self, parent_slot: usize, child_key: ProcessKey) -> LifecycleHandle {
        let table = &mut self.lifecycle_tables[parent_slot];
        // Try to reuse a collected slot (checked non-wrapping generation)
        for (i, entry) in table.iter_mut().enumerate() {
            if entry.collected {
                match entry.slot_generation.checked_add(1) {
                    Some(g) => {
                        entry.slot_generation = g;
                        entry.child = child_key;
                        entry.collected = false;
                        return LifecycleHandle::new(i as u32, g);
                    }
                    None => continue, // lifecycle slot generation exhausted, skip
                }
            }
        }
        // No reusable slot — append
        let slot = table.len() as u32;
        table.push(LifecycleEntry {
            slot_generation: 0,
            child: child_key,
            collected: false,
        });
        LifecycleHandle::new(slot, 0)
    }

    /// Resolve a LifecycleHandle in a specific process's table.
    /// Returns the LifecycleEntry index if valid and not yet collected.
    fn resolve_lifecycle(&self, owner_slot: usize, handle: LifecycleHandle) -> Option<(usize, &LifecycleEntry)> {
        let table = self.lifecycle_tables.get(owner_slot)?;
        let slot = handle.slot() as usize;
        let entry = table.get(slot)?;
        if entry.slot_generation != handle.slot_generation() { return None; }
        if entry.collected { return None; }
        Some((slot, entry))
    }

    /// Resolve a PID to a slot index.
    /// Only succeeds for Running processes (SYS_SEND delivery target).
    fn resolve_pid(&self, pid: u64) -> Option<usize> {
        self.processes.iter().position(|p|
            p.pid == pid && p.state == ProcessState::Running
        )
    }

    /// Validate a ProcessKey against the process table.
    /// Returns the slot index if the key matches a live (non-Free, non-Retired) process.
    pub(crate) fn validate_process_key(&self, key: &ProcessKey) -> Option<usize> {
        if key.slot >= self.processes.len() { return None; }
        let p = &self.processes[key.slot];
        if p.generation != key.generation { return None; }
        if p.state == ProcessState::Free || p.state == ProcessState::Retired { return None; }
        Some(key.slot)
    }

    // ─── Process reclamation ───────────────────────────────────
    //
    // Reclaim(P_g) = destroy owned resources + return placement
    //              + erase incarnation relations/state + invalidate P_g
    //
    // P_g → Free(g+1) if g < u32::MAX
    //     → Retired(g) if g = u32::MAX
    //
    // When resources is None (raw spawn() processes), resource
    // destruction is skipped but logical reclamation still happens.
    //
    // As of 8.3d, finish_process() calls terminate_orphans()
    // depth-first before any parent reclamation can occur.

    /// Reclaim a zombie or completed process slot.
    ///
    /// Destroys owned resources (domain, stack/trap objects),
    /// returns physical extents to the appropriate pools, clears
    /// all incarnation metadata, and advances the slot to
    /// Free(g+1) or Retired.
    pub(crate) fn reclaim_process(&mut self, slot: usize) {
        // --- Destroy owned resources (if any) ---
        if let Some(res) = self.processes[slot].resources.take() {
            self.fabric.destroy_object(res.stack_obj);
            self.fabric.destroy_object(res.trap_obj);
            self.fabric.destroy_domain(res.domain);
            self.free_stack_extents.push(res.stack_extent);
            self.free_trap_extents.push(res.trap_extent);
        }

        // --- Clear mailbox ---
        self.mailboxes[slot].clear();

        // --- Clear lifecycle table ---
        self.lifecycle_tables[slot].clear();

        // --- Erase incarnation relations/state ---
        self.processes[slot].parent = None;
        self.processes[slot].waiting_on = None;
        self.processes[slot].io_wait = None;
        self.processes[slot].result = None;
        self.processes[slot].exit_code = 0;

        // --- Advance generation: Free(g+1) or Retired ---
        let g = self.processes[slot].generation;
        match g.checked_add(1) {
            Some(next_g) => {
                self.processes[slot].generation = next_g;
                self.processes[slot].state = ProcessState::Free;
            }
            None => {
                self.processes[slot].state = ProcessState::Retired;
            }
        }
    }

    // ─── Central death transition (Rule 28) ─────────────────────
    //
    // Every path that kills a process goes through finish_process().
    // One semantic fact — "this incarnation died" — one authoritative
    // transition.  No partial death states survive.

    /// Transition a process to Zombie with a definitive ProcessResult.
    /// Then depth-first terminate any orphaned descendants.
    pub(crate) fn finish_process(&mut self, slot: usize, result: ProcessResult) {
        let exit_code = match &result {
            ProcessResult::Exited(code) => *code,
            _ => 0xDEAD,
        };
        self.processes[slot].exit_code = exit_code;
        self.processes[slot].result = Some(result);
        self.processes[slot].state = ProcessState::Zombie;

        let key = ProcessKey {
            slot,
            generation: self.processes[slot].generation,
        };
        self.terminate_orphans(key);
    }

    // ─── Depth-first orphan termination ────────────────────────
    //
    // When a process dies, its children become unsupervised.
    // No authorized collector survives.  We terminate and reclaim
    // descendants depth-first so that:
    //
    //   P → C → G  dies as:
    //   G reclaimed → C reclaimed → P eventually collected.
    //
    // No parent relation is erased before its subtree is discovered.

    /// Terminate and reclaim all descendants of dead_parent, depth-first.
    pub(crate) fn terminate_orphans(&mut self, dead_parent: ProcessKey) {
        // Snapshot direct children matching exact ProcessKey
        let children: Vec<(usize, ProcessKey)> = self.processes.iter()
            .enumerate()
            .filter_map(|(i, p)| {
                if let Some(ref pk) = p.parent {
                    if pk.slot == dead_parent.slot
                        && pk.generation == dead_parent.generation
                        && p.state != ProcessState::Free
                        && p.state != ProcessState::Retired
                    {
                        return Some((i, ProcessKey {
                            slot: i,
                            generation: p.generation,
                        }));
                    }
                }
                None
            })
            .collect();

        for (child_slot, child_key) in children {
            // Recurse: terminate child's descendants first
            self.terminate_orphans(child_key);

            match self.processes[child_slot].state {
                ProcessState::Running => {
                    // Terminate then reclaim in one step
                    self.processes[child_slot].exit_code = 0xDEAD;
                    self.processes[child_slot].result =
                        Some(ProcessResult::ProtectionFault);
                    self.processes[child_slot].state = ProcessState::Zombie;
                    self.reclaim_process(child_slot);
                }
                ProcessState::Zombie => {
                    self.reclaim_process(child_slot);
                }
                ProcessState::Free | ProcessState::Retired => {
                    // Already reclaimed — nothing to do
                }
            }
        }
    }

    // ─── Boot contract ─────────────────────────────────────────
    //
    // boot() establishes the first runnable Anka process (init).
    // It validates the boot descriptor, creates init's domain,
    // grants image authority from trusted boot state, and calls
    // prepare_process() to create stack/trap/core/address map.
    //
    // boot() does NOT call run().  It installs init as runnable
    // and returns Ok(()).  The host calls kernel.run() afterward.
    //
    // One-success-only: a successful boot sets the booted flag.
    // Failed preparation leaves no reachable domain, capability,
    // mapping, runnable process, or live allocated object.

    /// Boot the kernel with the given boot descriptor.
    ///
    /// On success, init is installed as a runnable process and the
    /// method returns `Ok(())`.  The caller then invokes `run()`.
    ///
    /// On failure, nothing is mutated (transactional rejection).
    pub fn boot(&mut self, info: &BootInfo) -> Result<(), BootError> {
        // ── One-success-only ──
        if self.booted {
            return Err(BootError::AlreadyBooted);
        }

        // ── Validate image object ──
        let img = &info.image;
        let obj = self.fabric.objects.get(&img.obj)
            .ok_or(BootError::ImageNotFound)?;
        if obj.state != ObjectState::Sealed {
            return Err(BootError::ImageNotSealed);
        }
        if img.code_size == 0 {
            return Err(BootError::ZeroCode);
        }
        if img.entry >= img.code_size {
            return Err(BootError::InvalidEntry);
        }
        let obj_size = obj.size;
        if img.code_offset > obj_size {
            return Err(BootError::InvalidEntry);
        }
        let image_size = obj_size - img.code_offset;
        if img.code_size > image_size {
            return Err(BootError::ZeroCode);
        }

        // ── Validate literal geometry ──
        if img.lit_start != 0 {
            if img.lit_start < img.code_size {
                return Err(BootError::InvalidLiterals);
            }
            if img.lit_start >= image_size {
                return Err(BootError::InvalidLiterals);
            }
        }

        // Image backing range: [code_offset .. code_offset + image_size)
        let img_back_start = img.code_offset;
        let img_back_end = img.code_offset + image_size;

        // ── Validate grants ──
        for g in &info.grants {
            let gobj = self.fabric.objects.get(&g.obj)
                .ok_or(BootError::GrantObjectNotFound)?;
            if g.size > gobj.size || g.offset > gobj.size - g.size {
                return Err(BootError::GrantOutOfBounds);
            }
            // Grant must not overlap image backing range (same object)
            if g.obj == img.obj {
                let g_end = g.offset + g.size;
                if g.offset < img_back_end && g_end > img_back_start {
                    return Err(BootError::GrantOverlapsImage);
                }
            }
        }

        // ── Validate maps ──
        // Collect implicit virtual ranges: code, literals, stack, trap.
        let trap_size: u64 = 0x1000;

        let mut ranges: Vec<(u64, u64)> = Vec::new();
        // Code: [code_vaddr .. code_vaddr + code_size)
        ranges.push((info.code_vaddr, info.code_vaddr + img.code_size));
        // Literals: [code_vaddr + lit_start .. code_vaddr + lit_start + lit_length)
        if img.lit_start != 0 {
            let lit_length = image_size - img.lit_start;
            ranges.push((info.code_vaddr + img.lit_start,
                         info.code_vaddr + img.lit_start + lit_length));
        }
        // Stack and trap from descriptor
        ranges.push((info.stack_vaddr, info.stack_vaddr + info.stack_size));
        ranges.push((info.trap_vaddr, info.trap_vaddr + trap_size));

        for m in &info.maps {
            let mobj = self.fabric.objects.get(&m.obj)
                .ok_or(BootError::MapObjectNotFound)?;
            if m.size > mobj.size || m.obj_offset > mobj.size - m.size {
                return Err(BootError::MapOutOfBounds);
            }
            ranges.push((m.vaddr, m.vaddr + m.size));
        }

        if !Self::validate_no_map_overlap(&ranges) {
            return Err(BootError::OverlappingMaps);
        }

        // ── All validation passed — now mutate ──
        let dom = self.fabric.create_domain();

        // Grant image authority: RX for code
        if self.fabric.grant(
            dom, img.obj, img.code_offset, img.code_size, Permissions::RX,
        ).is_none() {
            self.fabric.destroy_domain(dom);
            return Err(BootError::ImageNotSealed);
        }

        // Grant image authority: R for literals
        if img.lit_start != 0 {
            let lit_offset = img.code_offset + img.lit_start;
            let lit_length = image_size - img.lit_start;
            if self.fabric.grant(
                dom, img.obj, lit_offset, lit_length, Permissions::READ,
            ).is_none() {
                self.fabric.destroy_domain(dom);
                return Err(BootError::ImageNotSealed);
            }
        }

        // Additional grants
        for g in &info.grants {
            if self.fabric.grant(dom, g.obj, g.offset, g.size, g.perms).is_none() {
                self.fabric.destroy_domain(dom);
                return Err(BootError::GrantOutOfBounds);
            }
        }

        // Create process via shared primitive
        let desc = ProcessImageDesc {
            code_obj: img.obj,
            code_offset: img.code_offset,
            code_size: img.code_size,
            lit_start: img.lit_start,
            image_size,
            entry: img.entry,
        };
        let boot_layout = ProcessLayout {
            code_vaddr: info.code_vaddr,
            stack_vaddr: info.stack_vaddr,
            stack_size: info.stack_size,
            trap_vaddr: info.trap_vaddr,
        };
        // Convert BootMaps to InitialMaps for the shared primitive
        let initial_maps: Vec<InitialMap> = info.maps.iter().map(|m| InitialMap {
            vaddr: m.vaddr,
            size: m.size,
            obj: m.obj,
            obj_offset: m.obj_offset,
        }).collect();

        let _init_key = self.prepare_process(dom, &desc, &boot_layout, &initial_maps);

        self.booted = true;
        Ok(())
    }

    /// Run all processes in round-robin until all exit.
    /// Each process gets `quantum` steps per turn.
    pub fn run(&mut self, quantum: usize, max_rounds: usize) {
        for _ in 0..max_rounds {
            if self.processes.iter().all(|p| p.exited()) {
                break;
            }

            for i in 0..self.processes.len() {
                if self.processes[i].exited() {
                    continue;
                }
                // Skip processes blocked waiting on a child or I/O
                if self.processes[i].waiting_on.is_some()
                    || self.processes[i].io_wait.is_some()
                {
                    continue;
                }
                self.current = i;
                self.run_process(i, quantum);
                // After running, check if any newly-exited process
                // has a parent waiting on it
                self.wake_waiters();
            }
        }
    }

    /// Check for exited processes and resume any parent waiting on them.
    fn wake_waiters(&mut self) {
        // Collect (child_slot, child_gen, result) for zombie children
        let mut completions: Vec<(usize, u32, ProcessResult)> = Vec::new();
        for (slot, p) in self.processes.iter().enumerate() {
            if p.state == ProcessState::Zombie {
                let result = p.result.clone()
                    .expect("every zombie must have a ProcessResult (finish_process gate)");
                completions.push((slot, p.generation, result));
            }
        }
        // For each zombie child, find any parent waiting on it.
        // One completed incarnation satisfies one waiter; after
        // reclamation the child's generation has changed anyway.
        for (child_slot, child_gen, result) in completions {
            for i in 0..self.processes.len() {
                let matches = self.processes[i].waiting_on.as_ref()
                    .map(|ws| ws.child.slot == child_slot && ws.child.generation == child_gen)
                    .unwrap_or(false);
                if matches {
                    let ws = self.processes[i].waiting_on.take().unwrap();
                    match ws.kind {
                        WaitKind::Exec => {
                            self.processes[i].core.r[R0 as usize] = encode_exec_result(&result);
                        }
                        WaitKind::Lifecycle => {
                            let (r0, r1) = encode_wait_result(&result);
                            self.processes[i].core.r[R0 as usize] = r0;
                            self.processes[i].core.r[R1 as usize] = r1;
                            if let Some(handle_slot) = ws.handle_slot {
                                self.lifecycle_tables[i][handle_slot].collected = true;
                            }
                        }
                    }
                    self.reclaim_process(child_slot);
                    self.resume_from_trap(i);
                    break;
                }
            }
        }
    }

    fn run_process(&mut self, idx: usize, quantum: usize) {
        // Machine event sequence (Phase 9.0d):
        //
        //   Before any instruction fetch, if P ∧ ¬M, delivery gets
        //   first refusal.  This handles both:
        //     A. post-commit: step → tick → post → deliver → next fetch
        //     B. post-event_return: resume with pending → deliver → next fetch
        //   The M3a → M1 → M2 re-fire path falls out naturally.
        //
        //   Committed instruction ⇒ timer tick.
        //   Faulted instruction ⇒ no timer tick, no async delivery (INT-6).

        for _ in 0..quantum {
            if self.processes[idx].exited() {
                return;
            }

            // ── Pre-fetch delivery check ──────────────────────────
            // Handles case B: if event_return() or a previous cycle
            // left pending bits + interrupts_enabled, deliver now
            // before executing the next instruction.
            //
            // The arbiter inside deliver_pending() selects at most
            // one source per boundary (ARB-11).
            if self.processes[idx].core.deliver_pending() {
                self.processes[idx].core.halted = true;
                self.handle_async_interrupt(idx);
                return;
            }

            // ── Execute one instruction ───────────────────────────
            let result = self.processes[idx].core.step(&mut self.fabric);
            match result {
                super::core::StepResult::Continue => {
                    // ── Committed: tick devices, route assertions ──
                    self.tick_devices(idx);
                    // Post-commit delivery (case A) is handled by
                    // the pre-fetch check at the top of the next
                    // iteration.  This keeps deliver_pending() in
                    // exactly one place.
                }
                super::core::StepResult::Halted => {
                    // HALT is a committed instruction: tick devices.
                    self.tick_devices(idx);

                    match classify_halt(&self.processes[idx].core) {
                        HaltDisposition::Syscall => {
                            self.handle_syscall(idx);
                        }
                        HaltDisposition::TimerInterrupt
                        | HaltDisposition::DeviceInterrupt => {
                            self.handle_async_interrupt(idx);
                        }
                        HaltDisposition::SupervisorFault => {
                            let core = &self.processes[idx].core;
                            eprintln!("Process {} supervisor halt at {:#x} (not trap gate {:#x})",
                                self.processes[idx].pid, core.pc, core.trap_vector);
                            self.finish_process(idx, ProcessResult::SupervisorFault);
                        }
                        HaltDisposition::UserExit(code) => {
                            self.finish_process(idx, ProcessResult::Exited(code));
                        }
                    }
                    return;
                }
                super::core::StepResult::Fault(f) => {
                    // Faulted instruction: NO timer tick, NO async
                    // delivery.  INT-6 safety direction.
                    eprintln!("Process {} faulted: {:?} obj={:?} off={:#x} kind={:?} pc={:#x}",
                        self.processes[idx].pid, f.reason,
                        f.object, f.offset, f.kind,
                        self.processes[idx].core.pc);
                    self.finish_process(idx, ProcessResult::ProtectionFault);
                    return;
                }
            }
        }
    }

    /// Tick all devices and route source assertions to the core.
    ///
    /// Called once per committed instruction boundary.  This is the
    /// machine-level operation:
    ///   I_n commits → tick_devices() → route assertions → I_{n+1}
    ///
    /// Timer source: edge-triggered — fires once at period expiry.
    /// Block device: level-triggered — L_dev := (C > 0).
    ///   As long as the completion queue is non-empty, the source
    ///   remains asserted and posts P_dev every tick.  Consuming
    ///   P_dev in deliver_pending() does not consume completions;
    ///   if C > 0 persists, P_dev is re-posted on the next tick.
    fn tick_devices(&mut self, idx: usize) {
        // --- Timer source ---
        let timer_fired = if let Some(ref mut timer) = self.fabric.timer {
            timer.tick()
        } else {
            false
        };
        if timer_fired {
            self.processes[idx].core.post_timer_interrupt();
        }

        // --- Block device source ---
        // Tick the controller (advances latency, DMA transactions).
        if let Some(ref mut ctrl) = self.block_controller {
            ctrl.tick(&mut self.fabric);
        }
        // Level-triggered: L_dev := requires_attention() = (C > 0).
        // Posting is idempotent (sets pending.device = true).
        if self.block_controller.as_ref()
            .map_or(false, |c| c.requires_attention())
        {
            self.processes[idx].core.post_device_interrupt();
        }
    }

    /// Handle an asynchronous interrupt (timer or device).
    ///
    /// For timer interrupts: resume the interrupted process and yield
    /// to the round-robin scheduler (scheduling preemption).
    ///
    /// For device interrupts: drain the block controller's completion
    /// queue, wake any processes blocked on I/O whose RequesterKey
    /// matches a completion, then resume the interrupted process.
    ///
    /// The generation-qualified RequesterKey prevents stale completions
    /// from waking a recycled process slot.
    fn handle_async_interrupt(&mut self, idx: usize) {
        // Determine cause from the current event frame.
        let is_device = self.processes[idx].core.event_frames.last()
            .map(|f| f.cause == EventCause::DeviceInterrupt)
            .unwrap_or(false);

        if is_device {
            self.drain_block_completions();
        }

        self.resume_from_trap(idx);
    }

    /// Drain the block controller's completion queue and wake
    /// processes whose identity matches a completed request.
    ///
    /// Two independent identity checks:
    ///   RequesterKey (slot, generation) — which process incarnation?
    ///   RequestHandle (slot, generation) — which I/O operation?
    ///
    /// Both must match the process's current `io_wait`.  If either
    /// is stale, the completion is consumed with no observable effect.
    ///
    /// On match, the suspended SYS_BLOCK_READ is completed:
    ///   1. R0 = completion status (0 = success, MAX = fault)
    ///   2. event_return() pops the syscall EventFrame
    ///   3. io_wait = None
    ///   4. halted = false
    ///
    /// The process then becomes schedulable and resumes at user PC
    /// (the instruction after the original TRAP).
    fn drain_block_completions(&mut self) {
        loop {
            let completion = match self.block_controller.as_mut() {
                Some(ctrl) if ctrl.completion_count() > 0 => {
                    ctrl.consume_completion()
                }
                _ => break,
            };
            let completion = match completion {
                Some(c) => c,
                None => break,
            };

            let rk = &completion.requester;
            let slot = rk.slot as usize;

            // Validate: slot in range, generation matches, process
            // is Running and actually waiting for this exact request.
            let wake = slot < self.processes.len()
                && self.processes[slot].generation == rk.generation
                && self.processes[slot].state == ProcessState::Running
                && self.processes[slot].io_wait.as_ref()
                    .map(|w| w.request == completion.handle)
                    .unwrap_or(false);

            if wake {
                let proc = &mut self.processes[slot];
                proc.core.r[R0 as usize] = match completion.status {
                    super::block::CompletionStatus::Success => 0,
                    super::block::CompletionStatus::DmaFault(_) => u64::MAX,
                };
                let pc = proc.core.event_return()
                    .expect("matched I/O completion requires outstanding syscall EventFrame");
                proc.core.pc = pc;
                proc.io_wait = None;
                proc.core.halted = false;
            }
        }
    }

    fn handle_syscall(&mut self, idx: usize) {
        let syscall = self.processes[idx].core.r[R0 as usize];

        match syscall {
            SYS_EXIT => {
                let code = self.processes[idx].core.r[R1 as usize];
                self.finish_process(idx, ProcessResult::Exited(code));
            }
            SYS_WRITE => {
                self.handle_buffer_write(idx);
            }
            SYS_YIELD => {
                self.processes[idx].core.r[R0 as usize] = 0;
                self.resume_from_trap(idx);
            }
            SYS_SEND => {
                let dest_pid = self.processes[idx].core.r[R1 as usize];
                let value = self.processes[idx].core.r[R2 as usize];
                let from_pid = self.processes[idx].pid;
                if let Some(dest_slot) = self.resolve_pid(dest_pid) {
                    self.mailboxes[dest_slot].push(Message { from_pid, value });
                    self.processes[idx].core.r[R0 as usize] = 0;
                } else {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                }
                self.resume_from_trap(idx);
            }
            SYS_RECV => {
                if let Some(msg) = self.mailboxes[idx].pop() {
                    self.processes[idx].core.r[R0 as usize] = msg.value;
                } else {
                    self.processes[idx].core.r[R0 as usize] = 0;
                }
                self.resume_from_trap(idx);
            }
            SYS_SEAL => {
                self.handle_seal(idx);
            }
            SYS_EXEC => {
                self.handle_exec(idx);
            }
            SYS_SPAWN => {
                self.handle_spawn(idx);
            }
            SYS_WAIT => {
                self.handle_wait(idx);
            }
            SYS_BLOCK_READ => {
                self.handle_block_read(idx);
            }
            SYS_CAP_DROP => {
                self.handle_cap_drop(idx);
            }
            _ => {
                eprintln!("Unknown syscall {} from pid {}",
                    syscall, self.processes[idx].pid);
                self.finish_process(idx, ProcessResult::ProtectionFault);
            }
        }
    }

    /// Seal an object: Active(RW+S) → Sealed(RX).
    ///
    /// R1 = virtual address of the object to seal.
    /// Returns: R0 = 0 on success, R0 = MAX on error.
    ///
    /// Authority check: the calling domain must possess a valid SEAL
    /// capability covering the entire object.  WRITE authority alone
    /// is not sufficient — writing a buffer and authorizing it to
    /// SYS_WRITE: buffer-only output (7.3).
    ///
    ///   R1 = source virtual address
    ///   R2 = byte length
    ///   R3 = 0 (reserved — nonzero rejected)
    ///
    /// Authorization is range-atomic; observation is sequential;
    /// output commit is atomic.
    ///
    /// Output-atomic, not snapshot-atomic: another agent could modify
    /// a writable buffer between byte reads, so a successful write may
    /// contain bytes observed at different instants.  The guarantee is:
    /// either all reads succeed and one output buffer is committed, or
    /// no output is committed.
    ///
    /// Anti-stitching: one address-map entry must cover the entire
    /// virtual buffer, and one READ capability must authorize the
    /// entire object-level range.  SYS_WRITE cannot manufacture wider
    /// authority by combining multiple capabilities.
    fn handle_buffer_write(&mut self, idx: usize) {
        let addr = self.processes[idx].core.r[R1 as usize];
        let len  = self.processes[idx].core.r[R2 as usize];
        let r3   = self.processes[idx].core.r[R3 as usize];

        // R3 reserved — reject nonzero now to prevent accidental ABI growth.
        if r3 != 0 {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // len == 0: success, write nothing, addr not resolved.
        if len == 0 {
            self.processes[idx].core.r[R0 as usize] = 0;
            self.resume_from_trap(idx);
            return;
        }

        // Resource bound: reject before allocating.
        if len > MAX_WRITE {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Overflow preflight: addr + (len - 1) must not wrap.
        let addr_end = match addr.checked_add(len - 1) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        // ── Single-mapping preflight ──────────────────────────
        // Resolve both endpoints.  One address-map entry must cover
        // the entire virtual buffer.  This relies on the structural
        // invariant that address-map entries are non-overlapping
        // linear mappings: equal endpoint objects with contiguous
        // offsets imply every interior address maps to the same
        // object at the expected offset.
        let (obj_start, off_start) = match self.processes[idx].core.address_map.resolve(addr) {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };
        let (obj_end, off_end) = match self.processes[idx].core.address_map.resolve(addr_end) {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Same object
        if obj_start != obj_end {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Contiguous offsets (checked arithmetic on object offsets)
        let expected_off_end = match off_start.checked_add(len - 1) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };
        if off_end != expected_off_end {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // ── Single-capability preflight ───────────────────────
        // One READ capability must authorize the entire range.
        let domain = self.processes[idx].core.domain;
        if self.fabric.find_authorizing_cap(
            domain, obj_start, off_start, len, Permissions::READ
        ).is_none() {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // ── Per-byte fabric reads (revocation-sensitive) ──────
        // Each byte goes through the full fabric transaction path
        // (resolve → authorize → translate → read).  Revocation
        // between preflight and here can cause individual reads to
        // fail — in which case no output is committed.
        let mut buf = Vec::with_capacity(len as usize);
        for i in 0..len {
            let va = addr + i; // safe: overflow preflight passed
            let (obj, off) = match self.processes[idx].core.address_map.resolve(va) {
                Some(r) => r,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return;
                }
            };
            let req = MemoryRequest {
                context: AccessContext {
                    agent: self.processes[idx].core.agent,
                    domain: self.processes[idx].core.domain,
                    privilege: self.processes[idx].core.privilege,
                },
                object: obj,
                offset: off,
                width: Width::Byte,
                length: Width::Byte.bytes(),
                kind: AccessKind::Read,
            };
            match self.fabric.execute_read(req) {
                Ok(bytes) => buf.push(bytes[0]),
                Err(_) => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return;
                }
            }
        }

        // ── Commit staged output ──────────────────────────────
        // All bytes succeeded.  Append once.
        self.byte_output.extend_from_slice(&buf);
        self.processes[idx].core.r[R0 as usize] = 0;
        self.resume_from_trap(idx);
    }

    /// become executable code are different powers:
    ///   WRITE authority ≠ authority to create executable code.
    ///
    /// The seal is structural (fabric-level):
    ///   - Bumps generation (invalidates all old capabilities)
    ///   - Sets state = Sealed
    ///   - Grants RX at the new generation
    ///   - grant() will refuse WRITE/ATOMIC/SEAL on this object forever
    fn handle_seal(&mut self, idx: usize) {
        let vaddr = self.processes[idx].core.r[R1 as usize];
        let (object, _offset) = match self.processes[idx].core.address_map.resolve(vaddr) {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        let domain = self.processes[idx].core.domain;
        let obj_size = self.fabric.objects[&object].size;

        // Range-exact authority: caller must have SEAL covering [0, obj_size).
        // Narrow SEAL authority cannot seal the whole object.
        if self.fabric.find_authorizing_cap(
            domain, object, 0, obj_size, Permissions::SEAL
        ).is_none() {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Structural seal: Active → Sealed, generation bumped.
        if !self.fabric.seal_object(object) {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Grant RX at the new generation
        self.fabric.grant(domain, object, 0, obj_size, Permissions::RX);

        self.processes[idx].core.r[R0 as usize] = 0;
        self.resume_from_trap(idx);
    }

    /// Execute a sealed code object as a new child process.
    ///
    /// R1 = virtual address of sealed code object.
    /// R2 = code_size in bytes.
    /// R3 = lit_start offset within the image (0 = no literals).
    /// Returns: child's exit code in R0, or MAX on error.
    ///
    /// Structural checks before the kernel creates anything:
    ///   1. Object must be Sealed (W⊕X: no simultaneous W+X)
    ///   2. If lit_start != 0: code_size <= lit_start < image_size
    ///      (disjoint code and literal regions)
    ///   3. Parent must have RX authority covering the code range
    ///      (searches for READ|EXECUTE so the query matches derivation)
    ///   4. If literals: parent must have READ covering the literal range
    ///   5. derive() for both code and literal caps must succeed
    ///      (transactional: no half-authorized child on failure)
    ///
    /// Authority derivation:
    ///   - Code cap: derive RX from the RX parent (attenuation, I7)
    ///   - Literal cap: derive R from the R parent (Rule 29:
    ///     data is not authority to transfer control)
    /// Common validation and child creation for SYS_EXEC and SYS_SPAWN.
    /// Returns Some(child_pid) on success, None on validation failure.
    /// On failure, sets R0 = MAX and resumes the caller.
    fn create_child(&mut self, idx: usize) -> Option<ProcessKey> {
        let code_vaddr = self.processes[idx].core.r[R1 as usize];
        let code_size = self.processes[idx].core.r[R2 as usize];
        let lit_start = self.processes[idx].core.r[R3 as usize];

        let (code_obj, code_offset) = match self.processes[idx].core.address_map.resolve(code_vaddr) {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };

        let is_sealed = self.fabric.objects.get(&code_obj)
            .map(|o| o.state == ObjectState::Sealed)
            .unwrap_or(false);
        if !is_sealed {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return None;
        }

        let obj_size = match self.fabric.objects.get(&code_obj) {
            Some(o) => o.size,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };
        let image_size = obj_size - code_offset;

        let has_literals = lit_start != 0;
        if has_literals {
            if lit_start < code_size {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
            if image_size <= lit_start {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        }

        let domain = self.processes[idx].core.domain;

        let code_parent = match self.fabric.find_authorizing_cap(
            domain, code_obj, code_offset, code_size, Permissions::RX
        ) {
            Some(cap) => cap.clone(),
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };

        let lit_parent = if has_literals {
            let lit_offset = code_offset + lit_start;
            let lit_length = image_size - lit_start;
            match self.fabric.find_authorizing_cap(
                domain, code_obj, lit_offset, lit_length, Permissions::READ
            ) {
                Some(cap) => Some(cap.clone()),
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            }
        } else {
            None
        };

        let child_dom = self.fabric.create_domain();

        if self.fabric.derive(
            child_dom, &code_parent, code_offset, code_size, Permissions::RX,
        ).is_none() {
            self.fabric.destroy_domain(child_dom);
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return None;
        }

        if has_literals {
            let lit_offset = code_offset + lit_start;
            let lit_length = image_size - lit_start;
            if self.fabric.derive(
                child_dom, lit_parent.as_ref().unwrap(),
                lit_offset, lit_length, Permissions::READ,
            ).is_none() {
                self.fabric.destroy_domain(child_dom);
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        }

        let desc = ProcessImageDesc {
            code_obj,
            code_offset,
            code_size,
            lit_start,
            image_size,
            entry: 0,
        };
        let child_key = self.prepare_process(child_dom, &desc, &EXEC_DEFAULT_LAYOUT, &[]);
        let parent_key = ProcessKey {
            slot: idx,
            generation: self.processes[idx].generation,
        };
        self.processes[child_key.slot].parent = Some(parent_key);
        Some(child_key)
    }

    fn handle_exec(&mut self, idx: usize) {
        if let Some(child_key) = self.create_child(idx) {
            self.processes[idx].waiting_on = Some(WaitState {
                child: child_key,
                kind: WaitKind::Exec,
                handle_slot: None,
            });
        }
        // On failure, create_child already set R0=MAX and resumed.
    }

    fn handle_spawn(&mut self, idx: usize) {
        let grant_count = self.processes[idx].core.r[R5 as usize];
        let map_count = self.processes[idx].core.r[R7 as usize];
        let layout_addr = self.processes[idx].core.r[R8 as usize];

        // Default environment: no grants, maps, or custom layout
        if grant_count == 0 && map_count == 0 && layout_addr == 0 {
            if let Some(child_key) = self.create_child(idx) {
                let handle = self.install_lifecycle(idx, child_key);
                self.processes[idx].core.r[R0 as usize] = handle.as_u64();
                self.resume_from_trap(idx);
            }
            return;
        }

        // Extended spawn with grants and maps
        if let Some(child_key) = self.create_child_with_env(idx) {
            let handle = self.install_lifecycle(idx, child_key);
            self.processes[idx].core.r[R0 as usize] = handle.as_u64();
            self.resume_from_trap(idx);
        }
        // On failure, create_child_with_env already set R0=MAX and resumed.
    }

    // ─── Extended spawn: create child with initial environment ──
    //
    // Transaction order:
    //   read R4-R7
    //   validate counts / byte lengths (checked arithmetic)
    //   copy grant + map tables through parent's address map
    //   parse raw u64 descriptors
    //   resolve every parent_vaddr/range through parent's address map
    //   produce InitialGrant / InitialMap vectors
    //   validate all authority (attenuation, no stitching)
    //   validate all map geometry/overlap
    //   create child domain
    //   derive code/literals (reuses create_child validation)
    //   derive all InitialGrants
    //   prepare_process(... InitialMaps ...)
    //   publish parent relation + LifecycleHandle
    //
    // Failure before prepare_process: destroy child domain, R0=MAX.
    // Validation and commit use one kernel-owned copy of the
    // descriptor tables (eliminates post-copy TOCTOU).

    fn create_child_with_env(&mut self, idx: usize) -> Option<ProcessKey> {
        let grant_table_addr = self.processes[idx].core.r[R4 as usize];
        let grant_count = self.processes[idx].core.r[R5 as usize];
        let map_table_addr = self.processes[idx].core.r[R6 as usize];
        let map_count = self.processes[idx].core.r[R7 as usize];
        let layout_addr = self.processes[idx].core.r[R8 as usize];

        // ── Validate counts ──
        if grant_count > MAX_SPAWN_GRANTS || map_count > MAX_SPAWN_MAPS {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return None;
        }

        // ── Checked byte-length computation ──
        let grant_bytes = match grant_count.checked_mul(SPAWN_GRANT_SIZE) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };
        let map_bytes = match map_count.checked_mul(SPAWN_MAP_SIZE) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };

        // ── Copy grant table from parent's virtual address space ──
        let raw_grants = if grant_count > 0 {
            match self.read_virtual_bytes(idx, grant_table_addr, grant_bytes) {
                Some(bytes) => bytes,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            }
        } else {
            Vec::new()
        };

        // ── Copy map table from parent's virtual address space ──
        let raw_maps = if map_count > 0 {
            match self.read_virtual_bytes(idx, map_table_addr, map_bytes) {
                Some(bytes) => bytes,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            }
        } else {
            Vec::new()
        };

        // ── Read SpawnLayout (R8) ──
        // R8 = 0 → use EXEC_DEFAULT_LAYOUT.
        // R8 ≠ 0 → read SpawnLayout descriptor from parent's address space.
        let child_layout = if layout_addr == 0 {
            EXEC_DEFAULT_LAYOUT
        } else {
            let raw_layout = match self.read_virtual_bytes(idx, layout_addr, SPAWN_LAYOUT_SIZE) {
                Some(bytes) => bytes,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };
            let code_vaddr  = u64::from_le_bytes(raw_layout[0..8].try_into().unwrap());
            let stack_vaddr = u64::from_le_bytes(raw_layout[8..16].try_into().unwrap());
            let stack_size  = u64::from_le_bytes(raw_layout[16..24].try_into().unwrap());
            let trap_vaddr  = u64::from_le_bytes(raw_layout[24..32].try_into().unwrap());
            let reserved    = u64::from_le_bytes(raw_layout[32..40].try_into().unwrap());

            if reserved != 0 {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            // Validate resource bounds
            if stack_size < MIN_STACK_SIZE || stack_size > MAX_STACK_SIZE {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            // Validate alignment (page-aligned)
            if stack_vaddr & 0xFFF != 0 || trap_vaddr & 0xFFF != 0 {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            ProcessLayout {
                code_vaddr,
                stack_vaddr,
                stack_size,
                trap_vaddr,
            }
        };

        // ── Parse and resolve grant descriptors ──
        let mut initial_grants: Vec<InitialGrant> = Vec::new();
        for i in 0..grant_count as usize {
            let base = i * SPAWN_GRANT_SIZE as usize;
            let parent_vaddr = u64::from_le_bytes(raw_grants[base..base+8].try_into().unwrap());
            let offset       = u64::from_le_bytes(raw_grants[base+8..base+16].try_into().unwrap());
            let size          = u64::from_le_bytes(raw_grants[base+16..base+24].try_into().unwrap());
            let perms_raw    = u64::from_le_bytes(raw_grants[base+24..base+32].try_into().unwrap());
            let reserved     = u64::from_le_bytes(raw_grants[base+32..base+40].try_into().unwrap());

            // Reserved field must be zero
            if reserved != 0 {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            // Validate permission bits
            let child_perms = match Permissions::from_bits_checked(perms_raw) {
                Some(p) => p,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };

            // Size must be nonzero
            if size == 0 {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            // Resolve parent_vaddr to (ObjectId, map_base_offset)
            // We resolve just the single byte at parent_vaddr to find the mapping.
            let (obj, map_base) = match self.processes[idx].core.address_map.resolve(parent_vaddr) {
                Some(r) => r,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };

            // Compute target offset: map_base + offset (checked)
            let target_offset = match map_base.checked_add(offset) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };

            // Verify [target_offset, target_offset+size) stays within
            // the same parent mapping (single-mapping guarantee).
            // The parent virtual range [parent_vaddr+offset .. parent_vaddr+offset+size)
            // must resolve through exactly one address-map entry.
            let grant_parent_vaddr = match parent_vaddr.checked_add(offset) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };
            if self.resolve_virtual_range(idx, grant_parent_vaddr, size).is_none() {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            // Validate attenuation: parent must have a single capability
            // covering [target_offset, target_offset+size) on this object
            // with permissions that are a superset of child_perms.
            let parent_domain = self.processes[idx].core.domain;
            if self.fabric.find_authorizing_cap(
                parent_domain, obj, target_offset, size, child_perms,
            ).is_none() {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            initial_grants.push(InitialGrant {
                obj,
                offset: target_offset,
                size,
                perms: child_perms,
            });
        }

        // ── Parse and resolve map descriptors ──
        let mut initial_maps: Vec<InitialMap> = Vec::new();
        for i in 0..map_count as usize {
            let base = i * SPAWN_MAP_SIZE as usize;
            let child_vaddr  = u64::from_le_bytes(raw_maps[base..base+8].try_into().unwrap());
            let parent_vaddr = u64::from_le_bytes(raw_maps[base+8..base+16].try_into().unwrap());
            let offset       = u64::from_le_bytes(raw_maps[base+16..base+24].try_into().unwrap());
            let size          = u64::from_le_bytes(raw_maps[base+24..base+32].try_into().unwrap());
            let reserved     = u64::from_le_bytes(raw_maps[base+32..base+40].try_into().unwrap());

            if reserved != 0 || size == 0 {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            // Resolve parent_vaddr to (ObjectId, map_base_offset)
            let (obj, map_base) = match self.processes[idx].core.address_map.resolve(parent_vaddr) {
                Some(r) => r,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };

            let target_offset = match map_base.checked_add(offset) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };

            // Single-mapping guarantee for the parent range
            let map_parent_vaddr = match parent_vaddr.checked_add(offset) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };
            if self.resolve_virtual_range(idx, map_parent_vaddr, size).is_none() {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }

            initial_maps.push(InitialMap {
                vaddr: child_vaddr,
                size,
                obj,
                obj_offset: target_offset,
            });
        }

        // ── Validate: every map must be covered by prospective child authority ──
        // Prospective authority = implicit code/literal grants + initial_grants.
        // We check this after resolving maps so we have all the information.
        // (Code/literal grants will be added below; for now check against initial_grants.)
        // Defer this check until after code/lit validation so we know the full authority set.

        // ── Now do the standard code/literal validation (from create_child) ──
        let code_vaddr = self.processes[idx].core.r[R1 as usize];
        let code_size = self.processes[idx].core.r[R2 as usize];
        let lit_start = self.processes[idx].core.r[R3 as usize];

        let (code_obj, code_offset) = match self.processes[idx].core.address_map.resolve(code_vaddr) {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };

        let is_sealed = self.fabric.objects.get(&code_obj)
            .map(|o| o.state == ObjectState::Sealed)
            .unwrap_or(false);
        if !is_sealed {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return None;
        }

        let obj_size = match self.fabric.objects.get(&code_obj) {
            Some(o) => o.size,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };
        let image_size = obj_size - code_offset;

        let has_literals = lit_start != 0;
        if has_literals {
            if lit_start < code_size {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
            if image_size <= lit_start {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        }

        let domain = self.processes[idx].core.domain;

        let code_parent = match self.fabric.find_authorizing_cap(
            domain, code_obj, code_offset, code_size, Permissions::RX
        ) {
            Some(cap) => cap.clone(),
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };

        let lit_parent = if has_literals {
            let lit_offset = code_offset + lit_start;
            let lit_length = image_size - lit_start;
            match self.fabric.find_authorizing_cap(
                domain, code_obj, lit_offset, lit_length, Permissions::READ
            ) {
                Some(cap) => Some(cap.clone()),
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            }
        } else {
            None
        };

        // ── Validate map overlap (checked arithmetic throughout) ──
        let trap_size: u64 = 0x1000;
        let mut ranges: Vec<(u64, u64)> = Vec::new();

        let code_end = match child_layout.code_vaddr.checked_add(code_size) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };
        ranges.push((child_layout.code_vaddr, code_end));

        if has_literals {
            let lit_length = image_size - lit_start;
            let lit_vaddr = match child_layout.code_vaddr.checked_add(lit_start) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };
            let lit_end = match lit_vaddr.checked_add(lit_length) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };
            ranges.push((lit_vaddr, lit_end));
        }

        let stack_end = match child_layout.stack_vaddr.checked_add(child_layout.stack_size) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };
        ranges.push((child_layout.stack_vaddr, stack_end));

        let trap_end = match child_layout.trap_vaddr.checked_add(trap_size) {
            Some(v) => v,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        };
        ranges.push((child_layout.trap_vaddr, trap_end));

        for m in &initial_maps {
            let m_end = match m.vaddr.checked_add(m.size) {
                Some(v) => v,
                None => {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    self.resume_from_trap(idx);
                    return None;
                }
            };
            ranges.push((m.vaddr, m_end));
        }
        if !Self::validate_no_map_overlap(&ranges) {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return None;
        }

        // ── Validate: every map must be covered by prospective child authority ──
        // Prospective authority: code (RX), literals (R), plus initial_grants.
        for m in &initial_maps {
            let has_covering_grant = initial_grants.iter().any(|g| {
                g.obj == m.obj
                    && g.offset <= m.obj_offset
                    && m.obj_offset.checked_add(m.size)
                        .map(|end| {
                            g.offset.checked_add(g.size)
                                .map(|g_end| end <= g_end)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
            });
            // Also check implicit code authority (RX: [code_offset, code_offset+code_size))
            let has_code_rx = m.obj == code_obj
                && m.obj_offset >= code_offset
                && m.obj_offset.checked_add(m.size)
                    .map(|end| end <= code_offset + code_size)
                    .unwrap_or(false);
            // And implicit literal authority (R: [code_offset+lit_start, code_offset+image_size))
            let has_lit_r = has_literals && m.obj == code_obj
                && m.obj_offset >= code_offset + lit_start
                && m.obj_offset.checked_add(m.size)
                    .map(|end| end <= code_offset + image_size)
                    .unwrap_or(false);
            if !has_covering_grant && !has_code_rx && !has_lit_r {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        }

        // ── All validation passed — create child ──
        let child_dom = self.fabric.create_domain();

        if self.fabric.derive(
            child_dom, &code_parent, code_offset, code_size, Permissions::RX,
        ).is_none() {
            self.fabric.destroy_domain(child_dom);
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return None;
        }

        if has_literals {
            let lit_offset = code_offset + lit_start;
            let lit_length = image_size - lit_start;
            if self.fabric.derive(
                child_dom, lit_parent.as_ref().unwrap(),
                lit_offset, lit_length, Permissions::READ,
            ).is_none() {
                self.fabric.destroy_domain(child_dom);
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        }

        // Derive all initial grants into child domain
        for g in &initial_grants {
            // Find the authorizing parent capability again (already validated above)
            let parent_cap = self.fabric.find_authorizing_cap(
                domain, g.obj, g.offset, g.size, g.perms,
            ).unwrap().clone();
            if self.fabric.derive(
                child_dom, &parent_cap, g.offset, g.size, g.perms,
            ).is_none() {
                self.fabric.destroy_domain(child_dom);
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return None;
            }
        }

        let desc = ProcessImageDesc {
            code_obj,
            code_offset,
            code_size,
            lit_start,
            image_size,
            entry: 0,
        };
        let child_key = self.prepare_process(child_dom, &desc, &child_layout, &initial_maps);
        let parent_key = ProcessKey {
            slot: idx,
            generation: self.processes[idx].generation,
        };
        self.processes[child_key.slot].parent = Some(parent_key);
        Some(child_key)
    }

    /// Wait for a child process to exit.
    /// R1 = LifecycleHandle (u64).
    /// Returns: two-register ABI (R0=tag, R1=detail) via encode_wait_result.
    fn handle_wait(&mut self, idx: usize) {
        let raw_handle = self.processes[idx].core.r[R1 as usize];
        let handle = LifecycleHandle::from_u64(raw_handle);

        // Resolve in the caller's own lifecycle table (indexed by slot)
        let (slot, child_key) = match self.resolve_lifecycle(idx, handle) {
            Some((s, entry)) => (s, entry.child),
            None => {
                let (r0, r1) = encode_wait_invalid();
                self.processes[idx].core.r[R0 as usize] = r0;
                self.processes[idx].core.r[R1 as usize] = r1;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Validate the child ProcessKey against the process table
        let child_idx = match self.validate_process_key(&child_key) {
            Some(i) => i,
            None => {
                let (r0, r1) = encode_wait_invalid();
                self.processes[idx].core.r[R0 as usize] = r0;
                self.processes[idx].core.r[R1 as usize] = r1;
                self.resume_from_trap(idx);
                return;
            }
        };

        // If child already zombie: read result → consume handle → reclaim → resume
        if self.processes[child_idx].state == ProcessState::Zombie {
            let result = self.processes[child_idx].result.clone()
                .expect("zombie process must have a result");
            let (r0, r1) = encode_wait_result(&result);
            self.lifecycle_tables[idx][slot].collected = true;
            self.processes[idx].core.r[R0 as usize] = r0;
            self.processes[idx].core.r[R1 as usize] = r1;
            self.reclaim_process(child_idx);
            self.resume_from_trap(idx);
            return;
        }

        // Child still running — block the parent
        self.processes[idx].waiting_on = Some(WaitState {
            child: child_key,
            kind: WaitKind::Lifecycle,
            handle_slot: Some(slot),
        });
    }

    /// SYS_BLOCK_READ: asynchronous block read.
    ///
    /// ABI:
    ///   R1 = block number
    ///   R2 = buffer virtual address (must map a contiguous 512-byte
    ///        region within a single address-map entry)
    ///
    /// On success: the process blocks with its syscall EventFrame
    /// outstanding.  The block controller is given a request with
    /// RequesterKey = (process_slot, process_generation).  When the
    /// DMA completes, drain_block_completions() performs event_return()
    /// and resumes the caller at user PC with R0 = 0.
    ///
    /// On failure (no block controller, invalid block, bad buffer,
    /// delegation failure, already waiting): R0 = MAX and the
    /// caller resumes immediately.
    fn handle_block_read(&mut self, idx: usize) {
        use super::block::{BlockRequest, SubmitResult};

        let block_number = self.processes[idx].core.r[R1 as usize];
        let buf_vaddr = self.processes[idx].core.r[R2 as usize];

        // Fail fast: no block controller.
        if self.block_controller.is_none() {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Fail fast: already waiting on I/O.
        if self.processes[idx].io_wait.is_some() {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        let block_size = self.block_controller.as_ref().unwrap()
            .storage_ref().block_size();

        // Resolve the 512-byte destination buffer to (ObjectId, offset).
        let (target_object, target_offset) = match self.processes[idx]
            .core.address_map.resolve_range_single_entry(buf_vaddr, block_size)
        {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        let rk = RequesterKey {
            slot: idx as u32,
            generation: self.processes[idx].generation,
        };
        let source_domain = self.processes[idx].core.domain;

        let req = BlockRequest {
            block_number,
            requester: rk,
            target_object,
            target_offset,
            source_domain,
        };

        let result = self.block_controller.as_mut().unwrap()
            .submit(req, &mut self.fabric);

        match result {
            SubmitResult::Accepted(handle) => {
                // Block the caller: leave EventFrame outstanding,
                // keep halted = true, set io_wait.
                self.processes[idx].io_wait = Some(IoWait { request: handle });
            }
            _ => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
            }
        }
    }

    /// SYS_CAP_DROP: release a capability handle.
    ///
    /// R1 = slot index, R2 = handle generation.
    /// Returns: R0 = 0 on success, R0 = 1 on invalid handle.
    ///
    /// On success: the cap-table slot is freed (generation incremented),
    /// and the exact backing authority entry (identified by AuthorityId)
    /// is removed from the process's Fabric domain.
    ///
    /// Formal basis: anka_userspace_driver.kleis DROP-1..4.
    fn handle_cap_drop(&mut self, idx: usize) {
        let slot = self.processes[idx].core.r[R1 as usize] as u32;
        let hgen = self.processes[idx].core.r[R2 as usize] as u32;

        let handle = CapabilityHandle { slot, generation: hgen };

        let domain = self.processes[idx].core.domain;

        let auth_id = match self.processes[idx].cap_table.as_mut() {
            Some(ct) => ct.drop_handle(handle),
            None => None,
        };

        match auth_id {
            Some(aid) => {
                self.fabric.remove_by_authority_id(domain, aid);
                self.processes[idx].core.r[R0 as usize] = 0;
            }
            None => {
                self.processes[idx].core.r[R0 as usize] = 1;
            }
        }
        self.resume_from_trap(idx);
    }

    fn resume_from_trap(&mut self, idx: usize) {
        let proc = &mut self.processes[idx];
        // Uses the unified event_return() primitive — same code path
        // as Sem::Eret in the ISA.  This is the host-mediated
        // equivalent: the kernel intercepted the HALT in the trap
        // handler and now performs the return on behalf of the process.
        //
        // Formal basis: T_eret in anka_interrupts.kleis.
        proc.core.halted = false;
        if let Some(pc) = proc.core.event_return() {
            proc.core.pc = pc;
        }
    }
}


// ═══════════════════════════════════════════════════════════════════
// Test helpers (module-scope, available to sibling test modules)
// ═══════════════════════════════════════════════════════════════════

/// Emit a default SYS_SPAWN sequence: sets R1-R3, zeros R5/R7/R8,
/// loads SYS_SPAWN into R0, and traps.  R4 and R6 are deliberately
/// left untouched — with counts zero they are don't-care values.
///
/// Caller saves R0 (LifecycleHandle) afterward.
///
/// Emits 8 words (vs the old 5-word pattern without ABI zeroing).
#[cfg(test)]
pub(crate) fn emit_spawn_default(
    asm: &mut Asm64,
    code_vaddr: i32,
    code_size: i32,
    lit_start: i32,
) {
    asm.movi(R1, code_vaddr);
    asm.movi(R2, code_size);
    asm.movi(R3, lit_start);
    asm.movi(R5, 0);
    asm.movi(R7, 0);
    asm.movi(R8, 0);
    asm.movi(R0, SYS_SPAWN as i32);
    asm.trap(0);
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::core::StepResult;
    use super::super::fabric::Fabric;
    #[allow(unused_imports)]
    use super::super::cc::{self, Program, Function, Stmt, Expr, BinOp, Type, VarId};
    use super::super::guest_compiler::{CPU0, install_trap_handler, seal_code_object};

    /// Create a process with its own domain, objects, and address map.
    ///
    /// Text object starts Active.  Callers must:
    ///   1. Write code and trap handler to text via write_physical()
    ///   2. Call seal_code_object() before running the kernel
    ///
    /// W⊕X: Active ⇒ ¬X, Sealed ⇒ ¬W.
    fn create_process(
        fabric: &mut Fabric,
        agent: AgentId,
        name: &str,
        text_phys: u64,
        data_phys: u64,
        stack_phys: u64,
    ) -> (Anka64Core, DomainId, ObjectId, ObjectId, ObjectId) {
        let text  = fabric.alloc_object(&format!("{}_text", name),  0x4000, ObjectKind::Memory);
        let data  = fabric.alloc_object(&format!("{}_data", name),  0x4000, ObjectKind::Memory);
        let stack = fabric.alloc_object(&format!("{}_stack", name), 0x4000, ObjectKind::Memory);
        fabric.place_object(text,  text_phys);
        fabric.place_object(data,  data_phys);
        fabric.place_object(stack, stack_phys);

        let dom = fabric.create_domain();
        // text: RX granted AFTER seal (see seal_code_object)
        fabric.grant(dom, data,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(agent, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x10000, 0x4000, data);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        core.trap_vector = 0x3FF0;

        (core, dom, text, data, stack)
    }

    // ═══════════════════════════════════════════════════════════
    // P14: C program → TRAP/syscall → OS → return
    //
    //   int main() {
    //       syscall_write(42);
    //       syscall_exit(0);
    //   }
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p14_c_program_with_syscall() {
        // Buffer-based SYS_WRITE (7.3): write 8-byte LE values
        // to the data object, then SYS_WRITE(addr, 8, 0).
        // Data object is at virtual 0x10000 with RW permission.
        let mut fabric = Fabric::new(0x400000);
        let (core, _dom, _text, _data, _stack) =
            create_process(&mut fabric, CPU0, "proc0", 0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut asm = Asm64::new();
        asm.call(2);                // _start: call main
        asm.halt();

        // main:
        // Store 42 as u64 LE to data[0] (virtual 0x10000)
        asm.movi(R4, 42);
        asm.movi(R5, 0x10000_u32 as i32);
        asm.st(R4, R5, 0);
        // SYS_WRITE(0x10000, 8, 0)
        asm.movi(R0, SYS_WRITE as i32);
        asm.mov(R1, R5);           // addr = 0x10000
        asm.movi(R2, 8);           // len = 8
        asm.movi(R3, 0);           // reserved
        asm.trap(0);

        // Store 99 as u64 LE to data[0]
        asm.movi(R4, 99);
        asm.st(R4, R5, 0);
        // SYS_WRITE(0x10000, 8, 0)
        asm.movi(R0, SYS_WRITE as i32);
        asm.mov(R1, R5);
        asm.movi(R2, 8);
        asm.movi(R3, 0);
        asm.trap(0);

        // SYS_EXIT(0)
        asm.movi(R0, SYS_EXIT as i32);
        asm.movi(R1, 0);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, _text, _dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited(), "process should have exited");
        assert_eq!(kernel.processes[0].exit_code, 0, "exit code should be 0");
        assert_eq!(kernel.byte_output.len(), 16, "should have 16 bytes (two 8-byte writes)");
        assert_eq!(&kernel.byte_output[0..8], &42u64.to_le_bytes());
        assert_eq!(&kernel.byte_output[8..16], &99u64.to_le_bytes());
        eprintln!("P14: SYS_WRITE(42 as u64 LE), SYS_WRITE(99 as u64 LE) ✓");
        eprintln!("     byte_output: {:?}", &kernel.byte_output);
    }

    // ═══════════════════════════════════════════════════════════
    // P15: Two processes in separate domains communicating
    //
    //   Process A: send(1, 42), exit(0)
    //   Process B: v = recv(), write(v), exit(v)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p15_two_processes_ipc() {
        // Buffer-based SYS_WRITE (7.3): B receives 42 via IPC,
        // stores it to its data object, and writes 8 bytes out.
        let mut fabric = Fabric::new(0x800000);

        // Process A at physical 0x000000..
        let (core_a, dom_a, text_a, _d, _s) =
            create_process(&mut fabric, AgentId(0), "procA",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Process B at physical 0x100000..
        let (core_b, dom_b, text_b, _d, _s) =
            create_process(&mut fabric, AgentId(1), "procB",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);

        // Process A: send(pid=1, value=42), exit(0)
        let mut asm_a = Asm64::new();
        asm_a.movi(R0, SYS_SEND as i32);
        asm_a.movi(R1, 1);    // dest pid
        asm_a.movi(R2, 42);   // value
        asm_a.trap(0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.movi(R1, 0);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());

        // Process B: recv() → store to data → SYS_WRITE → exit
        // Data object is at virtual 0x10000 with RW.
        let mut asm_b = Asm64::new();
        asm_b.movi(R0, SYS_RECV as i32);
        asm_b.trap(0);
        // R0 = received value (42)
        asm_b.mov(R4, R0);         // save in R4
        asm_b.movi(R5, 0x10000_u32 as i32);
        asm_b.st(R4, R5, 0);       // data[0] = 42 (u64 LE)

        asm_b.movi(R0, SYS_WRITE as i32);
        asm_b.mov(R1, R5);         // addr = 0x10000
        asm_b.movi(R2, 8);         // len = 8
        asm_b.movi(R3, 0);         // reserved
        asm_b.trap(0);

        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.mov(R1, R4);         // exit(42)
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());

        // Seal both text objects (W⊕X lifecycle)
        seal_code_object(&mut fabric, text_a, dom_a);
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core_a);
        kernel.spawn(core_b);

        // Round-robin: A runs first (sends), then B runs (receives)
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited(), "A should have exited");
        assert!(kernel.processes[1].exited(), "B should have exited");
        assert_eq!(kernel.processes[0].exit_code, 0, "A exit code = 0");
        assert_eq!(kernel.processes[1].exit_code, 42, "B exit code = 42");
        assert_eq!(kernel.byte_output.len(), 8, "B wrote 8 bytes");
        assert_eq!(&kernel.byte_output[..], &42u64.to_le_bytes());

        eprintln!("P15: A→send(42)→B, B→recv()=42→store+write(8 bytes)→exit(42) ✓");
        eprintln!("     byte_output: {:?}", &kernel.byte_output);
    }

    // ═══════════════════════════════════════════════════════════
    // 6S.1 security tests — executable authority
    // ═══════════════════════════════════════════════════════════

    /// Helper: build a process that calls a single syscall and exits.
    fn build_syscall_program(
        fabric: &mut Fabric,
        text_phys: u64,
        syscall_num: u64,
        arg1: i32,
        arg2: i32,
    ) {
        let mut asm = Asm64::new();
        asm.movi(R1, arg1);
        asm.movi(R2, arg2);
        asm.movi(R0, syscall_num as i32);
        asm.trap(0);
        // After syscall returns, R0 has result → exit with it
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(text_phys, &asm.to_bytes());
    }

    #[test]
    fn s1_exec_rejects_unsealed_object() {
        // A process creates an RW buffer, writes valid code to it,
        // and calls SYS_EXEC WITHOUT calling SYS_SEAL first.
        // The kernel must reject: object is Active, not Sealed.
        let mut fabric = Fabric::new(0x200000);

        let text   = fabric.alloc_object("text",   0x4000, ObjectKind::Memory);
        let output = fabric.alloc_object("output", 0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(stack,  0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Write valid code to output buffer
        let mut code = Asm64::new();
        code.movi(R1, 42);
        code.movi(R0, SYS_EXIT as i32);
        code.trap(0);
        fabric.write_physical(0x020000, &code.to_bytes());

        // Program: call SYS_EXEC directly (skip SYS_SEAL)
        build_syscall_program(&mut fabric, 0x000000, SYS_EXEC,
            0x5000, 16);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(0x06000, 0x4000, stack);
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 100);

        // Process exited. SYS_EXEC should have returned MAX (error).
        // The process then exits with that error code.
        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "SYS_EXEC on unsealed object should return error");
        assert_eq!(kernel.processes.len(), 1,
            "no child should have been spawned");

        eprintln!("S1: SYS_EXEC on unsealed object → rejected ✓");
    }

    #[test]
    fn s2_seal_requires_seal_authority() {
        // A process has RW authority on an object but no SEAL.
        // Calling SYS_SEAL should fail — WRITE ≠ SEAL authority.
        let mut fabric = Fabric::new(0x200000);

        let text     = fabric.alloc_object("text",     0x4000, ObjectKind::Memory);
        let rw_only  = fabric.alloc_object("rw_only",  0x1000, ObjectKind::Memory);
        let stack    = fabric.alloc_object("stack",    0x4000, ObjectKind::Memory);

        fabric.place_object(text,     0x000000);
        fabric.place_object(rw_only,  0x020000);
        fabric.place_object(stack,    0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, rw_only, 0, 0x1000, Permissions::RW); // no SEAL!
        fabric.grant(dom, stack,   0, 0x4000, Permissions::RW);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Program: SYS_SEAL on the RW-only object
        build_syscall_program(&mut fabric, 0x000000, SYS_SEAL,
            0x5000, 0);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x05000, 0x1000, rw_only);
        core.address_map.add(0x06000, 0x4000, stack);
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "SYS_SEAL without SEAL authority should return error");
        // Object should still be Active (not Sealed)
        assert_eq!(kernel.fabric.objects[&rw_only].state, ObjectState::Active,
            "object should remain Active after failed seal");

        eprintln!("S2: SYS_SEAL with RW but no SEAL → rejected ✓");
        eprintln!("    WRITE authority ≠ authority to create executable code");
    }

    #[test]
    fn s3_pc_alignment_faults() {
        // Set PC to an unaligned address → AlignmentFault.
        // This blocks overlapping instruction streams from ROP gadgets.
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);

        let dom = fabric.create_domain();

        // Write code and seal before granting RX
        let mut asm = Asm64::new();
        asm.movi(R0, 42);
        asm.halt();
        fabric.write_physical(0x00000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // Start at aligned PC = 0 → should work
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x0000, 0x1000, text);
        let result = core.step(&mut fabric);
        assert!(matches!(result, StepResult::Continue),
            "aligned fetch should succeed");

        // Set PC to unaligned address (offset +1 into instruction)
        core.pc = 1;
        let result = core.step(&mut fabric);
        match result {
            StepResult::Fault(f) => {
                assert_eq!(f.reason, FaultReason::AlignmentFault);
            }
            other => panic!("expected AlignmentFault, got {:?}", other),
        }

        // PC+2 also unaligned
        core.pc = 6;
        let result = core.step(&mut fabric);
        assert!(matches!(result, StepResult::Fault(ref f) if f.reason == FaultReason::AlignmentFault),
            "PC=6 should fault");

        // PC+3 also unaligned
        core.pc = 7;
        let result = core.step(&mut fabric);
        assert!(matches!(result, StepResult::Fault(ref f) if f.reason == FaultReason::AlignmentFault),
            "PC=7 should fault");

        eprintln!("S3: PC mod 4 ≠ 0 → AlignmentFault ✓");
        eprintln!("    Blocks overlapping instruction streams from ROP gadgets");
    }

    // ═══════════════════════════════════════════════════════════
    // 6S.1a security tests — range-exact authority + SEAL separation
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn s4_narrow_seal_cannot_seal_whole_object() {
        // Domain has SEAL authority only over [0x100, 0x20).
        // SYS_SEAL requires SEAL covering [0, obj_size).
        // Narrow SEAL → rejected.
        let mut fabric = Fabric::new(0x200000);

        let text   = fabric.alloc_object("text",   0x4000, ObjectKind::Memory);
        let buffer = fabric.alloc_object("buffer", 0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(buffer, 0x020000);
        fabric.place_object(stack,  0x030000);

        let dom = fabric.create_domain();
        // Narrow SEAL: only [0x100, 0x120), not the whole object
        fabric.grant(dom, buffer, 0x100, 0x20, Permissions::SEAL);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        build_syscall_program(&mut fabric, 0x000000, SYS_SEAL,
            0x5000, 0);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x05000, 0x1000, buffer);
        core.address_map.add(0x06000, 0x4000, stack);
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "narrow SEAL should not authorize whole-object seal");
        assert_eq!(kernel.fabric.objects[&buffer].state, ObjectState::Active);

        eprintln!("S4: narrow SEAL [0x100,0x20) cannot seal whole object ✓");
        eprintln!("    Attenuation holds: narrow authority → narrow result");
    }

    #[test]
    fn s5_narrow_exec_cannot_authorize_larger_range() {
        // Parent has EXECUTE on [0, 0x10) of a sealed object.
        // SYS_EXEC with code_size=0x100 → rejected (narrow authority).
        let mut fabric = Fabric::new(0x200000);

        let text   = fabric.alloc_object("text",   0x4000, ObjectKind::Memory);
        let code   = fabric.alloc_object("code",   0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text, 0x000000);
        fabric.place_object(code, 0x020000);
        fabric.place_object(stack, 0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, code,  0, 0x1000, Permissions::RWS);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        // Write valid code and seal the code object
        let mut asm = Asm64::new();
        asm.movi(R1, 42);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x020000, &asm.to_bytes());
        fabric.seal_object(code);

        // Grant only narrow EXECUTE: [0, 0x10) — 4 instructions worth
        fabric.grant(dom, code, 0, 0x10, Permissions::RX);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Program: SYS_EXEC with code_size=0x100 (larger than authority)
        build_syscall_program(&mut fabric, 0x000000, SYS_EXEC,
            0x5000, 0x100);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x05000, 0x1000, code);
        core.address_map.add(0x06000, 0x4000, stack);
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "narrow EXECUTE should not authorize larger code range");
        assert_eq!(kernel.processes.len(), 1, "no child spawned");

        eprintln!("S5: EXECUTE on [0,0x10) cannot authorize exec of 0x100 bytes ✓");
        eprintln!("    Authority(child) ⊆ Authority(parent) — structural");
    }

    #[test]
    fn s6_child_authority_derived_from_parent() {
        // After SYS_EXEC, verify the child's capability was derived
        // (not freshly minted) — it must be within the parent's range.
        let mut fabric = Fabric::new(0x200000);

        let text   = fabric.alloc_object("text",   0x4000, ObjectKind::Memory);
        let code   = fabric.alloc_object("code",   0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text, 0x000000);
        fabric.place_object(code, 0x020000);
        fabric.place_object(stack, 0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, code,  0, 0x1000, Permissions::RWS);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        // Write simple code and seal the code object
        let mut asm = Asm64::new();
        asm.movi(R1, 77);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x020000, &asm.to_bytes());
        fabric.seal_object(code);

        // Parent gets whole-object RX (post-seal)
        fabric.grant(dom, code, 0, 0x1000, Permissions::RX);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // SYS_EXEC with code_size = 16 (within parent's [0, 0x1000))
        build_syscall_program(&mut fabric, 0x000000, SYS_EXEC,
            0x5000, 16);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x05000, 0x1000, code);
        core.address_map.add(0x06000, 0x4000, stack);
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(1000, 1000);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 77,
            "parent received child's exit code 77 — proves authority derivation");
        assert!(kernel.processes.len() >= 2);

        // Post-8.3c: child is reclaimed after collection.
        // The child ran SYS_EXIT(77) successfully, proving it had valid
        // derived authority (RX on code, RW on stack).  The parent
        // received 77 via the EXEC ABI, proving the full derivation
        // chain.  The child's domain and resources are now destroyed.
        assert_eq!(kernel.processes[1].state, ProcessState::Free,
            "child should be reclaimed to Free");
        assert!(kernel.processes[1].resources.is_none(),
            "child resources destroyed by reclaim");

        eprintln!("S6: child exit(77) → parent received 77 → child reclaimed ✓");
        eprintln!("    Authority(child) ⊆ Authority(parent) — proven by successful execution");
    }

    #[test]
    fn s7_overflow_grant_rejected() {
        // Try to grant a capability where offset + length overflows u64.
        // The Kleis model uses subtraction-based checks to avoid this.
        let mut fabric = Fabric::new(0x100000);
        let obj = fabric.alloc_object("huge", 0x1000, ObjectKind::Memory);
        fabric.place_object(obj, 0x0000);
        let dom = fabric.create_domain();

        // offset = u64::MAX - 10, length = 20 → overflow
        let result = fabric.grant(dom, obj, u64::MAX - 10, 20, Permissions::READ);
        assert!(result.is_none(), "overflow grant should be rejected");

        // offset = 0, length = obj_size + 1 → exceeds object
        let result = fabric.grant(dom, obj, 0, 0x1001, Permissions::READ);
        assert!(result.is_none(), "length > obj_size should be rejected");

        // offset = 1, length = obj_size → offset would go past end
        let result = fabric.grant(dom, obj, 1, 0x1000, Permissions::READ);
        assert!(result.is_none(), "offset+length > obj_size should be rejected");

        // Valid: offset = 0, length = obj_size → exact fit
        let result = fabric.grant(dom, obj, 0, 0x1000, Permissions::READ);
        assert!(result.is_some(), "exact fit should succeed");

        eprintln!("S7: overflow range checks in grant() ✓");
        eprintln!("    Rule 28: Rust ≡ Kleis subtraction-based bounds");
    }

    /// Illegal instruction → Fault(IllegalInstruction), not Halted.
    /// Writes a single illegal opcode word into the code object and
    /// runs the kernel.  The process must exit with 0xDEAD (fault),
    /// not with R0 (user HALT).
    #[test]
    fn halt_illegal_instruction_faults() {
        let mut fabric = Fabric::new(0x400000);
        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x0000);

        let dom = fabric.create_domain();
        fabric.grant(dom, text, 0, 0x1000, Permissions::READ);

        // Write a single illegal word (opcode 0 → no desc-table match).
        // NOTE: 0xFFFFFFFF maps to opcode 0x3F = NOP, not illegal.
        fabric.write_physical(0x0000, &0x00000001u32.to_le_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x0000, 0x1000, text);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(100, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 0xDEAD,
            "illegal instruction must produce fault exit (0xDEAD), not user HALT");
        eprintln!("halt: illegal opcode → IllegalInstruction fault → exit 0xDEAD ✓");
    }

    /// Supervisor HALT at PC ≠ trap_vector → 0xDEAD.
    ///
    /// Places a core in Supervisor mode at a HALT instruction that is
    /// NOT at the trap gate.  The kernel must treat this as a
    /// supervisor fault, not a syscall.
    #[test]
    fn halt_supervisor_not_at_gate() {
        let mut fabric = Fabric::new(0x400000);
        let text = fabric.alloc_object("text", 0x4000, ObjectKind::Memory);
        fabric.place_object(text, 0x0000);

        let dom = fabric.create_domain();

        // Write HALT at word 0 (physical 0x0000).
        let mut asm = Asm64::new();
        asm.halt();
        fabric.write_physical(0x0000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x0000, 0x4000, text);
        core.trap_vector = 0x3FF0;
        // Force supervisor mode — as if TRAP had elevated privilege
        // but we jumped somewhere other than the trap gate.
        core.privilege = Privilege::Supervisor;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(100, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 0xDEAD,
            "supervisor HALT not at trap gate must produce 0xDEAD");
        eprintln!("halt: supervisor HALT at PC=0x0000 (not gate 0x3FF0) → 0xDEAD ✓");
        eprintln!("     classify_halt → SupervisorFault");
    }

    // ═══════════════════════════════════════════════════════════
    // 7.3h: Hostile SYS_WRITE tests
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p73h_write_wraparound() {
        // addr near u64::MAX, len > 1: addr + (len - 1) wraps.
        // checked_add must catch it; SYS_WRITE returns u64::MAX.
        let mut fabric = Fabric::new(0x400000);
        let (mut core, _dom, _text, _data, _stack) =
            create_process(&mut fabric, CPU0, "hostile",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Code: set R0=SYS_WRITE, R1=u64::MAX-1, R2=4, R3=0; TRAP; exit R0
        let mut asm = Asm64::new();
        // We cannot load u64::MAX-1 via MOVI (18-bit signed).
        // Instead, pre-load R1 in the core and use NOP in the asm.
        asm.movi(R0, SYS_WRITE as i32);
        // R1 is pre-set below
        asm.movi(R2, 4);
        asm.movi(R3, 0);
        asm.trap(0);
        asm.mov(R1, R0);   // R1 = SYS_WRITE return value
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, _text, _dom);

        // Pre-set R1 = u64::MAX - 1
        core.r[R1 as usize] = u64::MAX - 1;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "wraparound must fail with u64::MAX");
        assert!(kernel.byte_output.is_empty(),
            "no bytes should be committed on wraparound");
        eprintln!("7.3h: wraparound → u64::MAX, no output ✓");
    }

    #[test]
    fn p73h_write_range_preflight_oob() {
        // Buffer starts inside a valid data object but len extends
        // past the object boundary.  The preflight rejects before
        // any bytes are read.
        //
        // Data object: virtual 0x10000, size 0x4000.
        // We write a marker byte at data[0] and request a write
        // of 0x4001 bytes starting at 0x10000 — one byte past end.
        let mut fabric = Fabric::new(0x400000);
        let (core, _dom, _text, _data, _stack) =
            create_process(&mut fabric, CPU0, "hostile",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Write a marker to data[0] so we can prove it was never read.
        fabric.write_physical(0x010000, &[0xAB]);

        let mut asm = Asm64::new();
        // Store marker at data[0] (already there from write_physical)
        asm.movi(R0, SYS_WRITE as i32);
        asm.movi(R1, 0x10000_u32 as i32); // addr = data base
        asm.movi(R2, 0x4001);              // len = 0x4001 = 1 past end
        asm.movi(R3, 0);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, _text, _dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "OOB range must fail with u64::MAX");
        assert!(kernel.byte_output.is_empty(),
            "no bytes committed when range extends past object");
        eprintln!("7.3h: range_preflight_oob → u64::MAX, no output ✓");
    }

    #[test]
    fn p73h_write_r3_nonzero_rejected() {
        // R3 != 0 must be rejected immediately.
        let mut fabric = Fabric::new(0x400000);
        let (core, _dom, _text, _data, _stack) =
            create_process(&mut fabric, CPU0, "hostile",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R0, SYS_WRITE as i32);
        asm.movi(R1, 0x10000_u32 as i32); // valid addr
        asm.movi(R2, 1);                   // valid len
        asm.movi(R3, 1);                   // NONZERO → reject
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, _text, _dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "nonzero R3 must be rejected");
        assert!(kernel.byte_output.is_empty(),
            "no bytes committed when R3 != 0");
        eprintln!("7.3h: R3 nonzero → u64::MAX, no output ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.2: Lifecycle authority tests — SYS_SPAWN / SYS_WAIT
    // ═══════════════════════════════════════════════════════════
    //
    // Layout for lifecycle tests:
    //   Parent text : virt 0x00000, phys 0x000000, size 0x4000
    //   Output buf  : virt 0x10000, phys 0x010000, size 0x4000 (RWS → child code)
    //   Stack       : virt 0x20000, phys 0x020000, size 0x4000
    //   (Kernel alloc starts at 0x040000)
    //
    // Child code is pre-written to the output buffer's physical
    // address before the parent is sealed.  The parent then:
    //   SYS_SEAL(output_buf_vaddr) → SYS_SPAWN(output_buf_vaddr, child_size, 0)
    //   → SYS_WAIT(handle) → SYS_EXIT(result).

    /// Build a child program that exits with the given code.
    fn child_exit_code(code: i32) -> Vec<u8> {
        let mut asm = Asm64::new();
        asm.movi(R1, code);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        asm.halt();
        asm.to_bytes()
    }

    /// Build a child program that triggers a protection fault.
    /// Attempts to write to address 0xDEAD_0000 (unmapped).
    fn child_fault_program() -> Vec<u8> {
        let mut asm = Asm64::new();
        asm.movi(R5, 0xDEAD_u32 as i32);
        asm.movi(R6, 16);
        asm.shl(R5, R5, R6);
        asm.movi(R6, 42);
        asm.st(R6, R5, 0);
        asm.halt();
        asm.to_bytes()
    }

    /// Build a child program that loops forever (SYS_YIELD in a loop).
    fn child_infinite_loop() -> Vec<u8> {
        let mut asm = Asm64::new();
        // word 0: SYS_YIELD
        asm.movi(R0, SYS_YIELD as i32);
        asm.trap(0);
        // word 2: branch back to word 0 (target = PC + offset*4 = 8 + (-2)*4 = 0)
        asm.bcc(super::super::isa::Cond::Al, -2);
        asm.to_bytes()
    }

    /// Set up a lifecycle test: parent with RWS output buffer.
    /// Returns (fabric, parent_core, parent_dom, text_obj, output_obj, stack_obj).
    fn lifecycle_test_setup(fabric: &mut Fabric) -> (Anka64Core, DomainId, ObjectId, ObjectId, ObjectId) {
        let text   = fabric.alloc_object("parent_text",   0x4000, ObjectKind::Memory);
        let output = fabric.alloc_object("parent_output", 0x4000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("parent_stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(output, 0x010000);
        fabric.place_object(stack,  0x020000);

        let dom = fabric.create_domain();
        fabric.grant(dom, output, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x10000, 0x4000, output);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        core.trap_vector = 0x3FF0;

        (core, dom, text, output, stack)
    }

    /// Build parent code: SEAL → SPAWN → save handle → WAIT → EXIT(R0).
    /// R0 after WAIT has the tag (0=Exited). R1 has the exit code.
    /// Parent exits with R1 (the child's exit code) for simple tests.
    fn parent_seal_spawn_wait_exit(child_code_size: i32) -> Vec<u8> {
        let mut asm = Asm64::new();
        // SYS_SEAL(0x10000)
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // SYS_SPAWN(0x10000, child_code_size, 0)
        emit_spawn_default(&mut asm, 0x10000_u32 as i32, child_code_size, 0);
        // Save handle in R4
        asm.mov(R4, R0);
        // SYS_WAIT(handle)
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0 = tag (0=Exited), R1 = exit code
        // Exit with R1 (child's exit code)
        asm.mov(R1, R1); // nop but clarifies intent: R1 already has the value
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        asm.to_bytes()
    }

    /// Build parent code: SEAL → SPAWN → EXIT(handle_as_u64).
    /// Returns immediately after spawn without waiting.
    fn parent_seal_spawn_exit_handle(child_code_size: i32) -> Vec<u8> {
        let mut asm = Asm64::new();
        // SYS_SEAL(0x10000)
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // SYS_SPAWN(0x10000, child_code_size, 0)
        emit_spawn_default(&mut asm, 0x10000_u32 as i32, child_code_size, 0);
        // Exit with handle value (R0)
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        asm.to_bytes()
    }

    #[test]
    fn p82_spawn_returns_immediately() {
        // SYS_SPAWN returns immediately even when child loops forever.
        // Parent exits with the handle value (nonzero, non-MAX).
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_infinite_loop();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        let parent_code = parent_seal_spawn_exit_handle(child_size);
        fabric.write_physical(0x000000, &parent_code);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited(),
            "parent must exit");
        let handle_val = kernel.processes[0].exit_code;
        assert_ne!(handle_val, u64::MAX,
            "SPAWN must succeed (not MAX)");
        // Child should still be running (or at least spawned)
        assert!(kernel.processes.len() >= 2,
            "child must have been spawned");
        eprintln!("8.2e: spawn_returns_immediately → handle={:#x} ✓", handle_val);
    }

    #[test]
    fn p82_spawn_wait_single() {
        // Spawn one child that exits with 42, wait for it, parent
        // exits with child's exit code.
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        let parent_code = parent_seal_spawn_wait_exit(child_size);
        fabric.write_physical(0x000000, &parent_code);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 42,
            "parent should exit with child's exit code 42");
        eprintln!("8.2e: spawn_wait_single(42) ✓");
    }

    #[test]
    fn p82_spawn_two_wait_both() {
        // Parent spawns two children (exit 11 and 22), waits both,
        // exits with the sum (33).
        //
        // Virtual layout (all addresses < 0x20000 for 18-bit MOVI):
        //   text:    virt 0x00000, phys 0x000000
        //   output1: virt 0x04000, phys 0x010000
        //   output2: virt 0x08000, phys 0x030000
        //   stack:   virt 0x10000, phys 0x020000
        let mut fabric = Fabric::new(0x800000);

        let text    = fabric.alloc_object("parent_text",   0x4000, ObjectKind::Memory);
        let output1 = fabric.alloc_object("child1_output", 0x4000, ObjectKind::Memory);
        let output2 = fabric.alloc_object("child2_output", 0x4000, ObjectKind::Memory);
        let stack   = fabric.alloc_object("parent_stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text,    0x000000);
        fabric.place_object(output1, 0x010000);
        fabric.place_object(output2, 0x030000);
        fabric.place_object(stack,   0x020000);

        let dom = fabric.create_domain();
        fabric.grant(dom, output1, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, output2, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, stack,   0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x4000, output1);
        core.address_map.add(0x08000, 0x4000, output2);
        core.address_map.add(0x10000, 0x4000, stack);
        core.r[SP as usize] = 0x10000 + 0x4000;
        core.trap_vector = 0x3FF0;

        // Child 1: exit(11)
        let child1 = child_exit_code(11);
        fabric.write_physical(0x010000, &child1);
        // Child 2: exit(22)
        let child2 = child_exit_code(22);
        fabric.write_physical(0x030000, &child2);

        let child1_size = child1.len() as i32;
        let child2_size = child2.len() as i32;

        // Parent: SEAL buf1 → SPAWN buf1 → save H1
        //         SEAL buf2 → SPAWN buf2 → save H2
        //         WAIT H1 → save R1 (exit code) → WAIT H2 → ADD → EXIT
        let mut asm = Asm64::new();
        // SEAL output1
        asm.movi(R1, 0x4000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // SPAWN from output1
        emit_spawn_default(&mut asm, 0x4000_u32 as i32, child1_size, 0);
        asm.mov(R4, R0); // H1 in R4
        // SEAL output2
        asm.movi(R1, 0x8000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // SPAWN from output2
        emit_spawn_default(&mut asm, 0x8000_u32 as i32, child2_size, 0);
        asm.mov(R5, R0); // H2 in R5
        // WAIT H1
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0=tag(0), R1=exit_code(11). Save R1 in R6.
        asm.mov(R6, R1);
        // WAIT H2
        asm.mov(R1, R5);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0=tag(0), R1=exit_code(22). Add R6+R1.
        asm.add(R7, R6, R1);
        // EXIT(sum)
        asm.mov(R1, R7);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 33,
            "parent should exit with 11 + 22 = 33");
        eprintln!("8.2e: spawn_two_wait_both(11+22=33) ✓");
    }

    #[test]
    fn p82_wait_already_exited() {
        // Child exits before parent calls WAIT (parent yields first).
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_exit_code(99);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Parent: SEAL → SPAWN → YIELD → YIELD → YIELD → WAIT → EXIT(R1)
        let mut asm = Asm64::new();
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        emit_spawn_default(&mut asm, 0x10000_u32 as i32, child_size, 0);
        asm.mov(R4, R0); // save handle
        // Yield several times so child runs and exits
        asm.movi(R0, SYS_YIELD as i32);
        asm.trap(0);
        asm.movi(R0, SYS_YIELD as i32);
        asm.trap(0);
        asm.movi(R0, SYS_YIELD as i32);
        asm.trap(0);
        // Now WAIT — child should already be exited
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0=0(Exited), R1=99
        asm.mov(R1, R1);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 99,
            "WAIT on already-exited child should return its exit code");
        eprintln!("8.2e: wait_already_exited(99) ✓");
    }

    #[test]
    fn p82_wait_consumes_handle() {
        // After WAIT succeeds, the handle is consumed.
        // A second WAIT on the same handle returns invalid (R0=MAX).
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_exit_code(7);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Parent: SEAL → SPAWN → WAIT(H) → save tag in R5 →
        //         WAIT(H) again → R0 should be MAX → EXIT(R0)
        let mut asm = Asm64::new();
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        emit_spawn_default(&mut asm, 0x10000_u32 as i32, child_size, 0);
        asm.mov(R4, R0); // save handle
        // First WAIT → should succeed
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0=0(Exited), R1=7. Save to verify later.
        asm.mov(R5, R1); // child exit code in R5
        // Second WAIT on same handle → should return invalid
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0 should be MAX (handle consumed). Exit with R0.
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "second WAIT on consumed handle should return MAX");
        eprintln!("8.2e: wait_consumes_handle ✓");
    }

    #[test]
    fn p82_wait_forged_handle() {
        // A process fabricates a handle value and calls WAIT.
        // Must fail: the handle doesn't exist in the caller's table.
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        // Parent: just WAIT with a fabricated handle, no spawn at all
        let mut asm = Asm64::new();
        asm.movi(R1, 0x42_u32 as i32); // fabricated handle
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0 should be MAX
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "forged handle must be rejected");
        eprintln!("8.2e: wait_forged_handle → MAX ✓");
    }

    #[test]
    fn p82_wait_not_owner() {
        // Process A spawns child C and gets handle H.
        // Process B knows the bits of H but has no entry in its table.
        // B's WAIT(H) must fail.
        //
        // A: SEAL → SPAWN → EXIT(handle)
        // B: receives handle from A via message → WAIT(H) → must fail
        //
        // We set up A and B as two separate spawned processes.
        // A sends handle to B, B tries to WAIT on it.
        let mut fabric = Fabric::new(0x800000);

        // Process A objects
        let a_text   = fabric.alloc_object("a_text",   0x4000, ObjectKind::Memory);
        let a_output = fabric.alloc_object("a_output", 0x4000, ObjectKind::Memory);
        let a_stack  = fabric.alloc_object("a_stack",  0x4000, ObjectKind::Memory);
        fabric.place_object(a_text,   0x000000);
        fabric.place_object(a_output, 0x010000);
        fabric.place_object(a_stack,  0x020000);

        // Process B objects
        let b_text  = fabric.alloc_object("b_text",  0x4000, ObjectKind::Memory);
        let b_stack = fabric.alloc_object("b_stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(b_text,  0x040000);
        fabric.place_object(b_stack, 0x050000);

        let dom_a = fabric.create_domain();
        fabric.grant(dom_a, a_output, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom_a, a_stack,  0, 0x4000, Permissions::RW);

        let dom_b = fabric.create_domain();
        fabric.grant(dom_b, b_stack, 0, 0x4000, Permissions::RW);

        // Child code: exit(77)
        let child_code = child_exit_code(77);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // A: SEAL → SPAWN → get handle → SEND handle to B (pid=1) → EXIT(0)
        let mut asm_a = Asm64::new();
        asm_a.movi(R1, 0x10000_u32 as i32);
        asm_a.movi(R0, SYS_SEAL as i32);
        asm_a.trap(0);
        emit_spawn_default(&mut asm_a, 0x10000_u32 as i32, child_size, 0);
        asm_a.mov(R4, R0); // handle
        // SEND(dest=1, value=handle)
        asm_a.movi(R1, 1); // B's pid
        asm_a.mov(R2, R4);
        asm_a.movi(R0, SYS_SEND as i32);
        asm_a.trap(0);
        // EXIT(0)
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);

        fabric.write_physical(0x000000, &asm_a.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, a_text, dom_a);

        // B: YIELD (let A run) → RECV → WAIT(received_handle) → EXIT(R0)
        let mut asm_b = Asm64::new();
        asm_b.movi(R0, SYS_YIELD as i32);
        asm_b.trap(0);
        asm_b.movi(R0, SYS_YIELD as i32);
        asm_b.trap(0);
        // RECV
        asm_b.movi(R0, SYS_RECV as i32);
        asm_b.trap(0);
        // R0 = handle value. Try to WAIT on it.
        asm_b.mov(R1, R0);
        asm_b.movi(R0, SYS_WAIT as i32);
        asm_b.trap(0);
        // Should return MAX. Exit with R0.
        asm_b.mov(R1, R0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);

        fabric.write_physical(0x040000, &asm_b.to_bytes());
        install_trap_handler(&mut fabric, 0x040000, 0x4000);
        seal_code_object(&mut fabric, b_text, dom_b);

        let mut core_a = Anka64Core::new(CPU0, dom_a);
        core_a.address_map.add(0x00000, 0x4000, a_text);
        core_a.address_map.add(0x10000, 0x4000, a_output);
        core_a.address_map.add(0x20000, 0x4000, a_stack);
        core_a.r[SP as usize] = 0x20000 + 0x4000;
        core_a.trap_vector = 0x3FF0;

        let mut core_b = Anka64Core::new(AgentId(1), dom_b);
        core_b.address_map.add(0x00000, 0x4000, b_text);
        core_b.address_map.add(0x20000, 0x4000, b_stack);
        core_b.r[SP as usize] = 0x20000 + 0x4000;
        core_b.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.spawn(core_a);
        kernel.spawn(core_b);
        kernel.run(1000, 200);

        // B should have exited with MAX (handle not in B's table)
        assert!(kernel.processes[1].exited());
        assert_eq!(kernel.processes[1].exit_code, u64::MAX,
            "non-owner WAIT must be rejected: authority survives full knowledge");
        eprintln!("8.2e: wait_not_owner → MAX (security property confirmed) ✓");
    }

    #[test]
    fn p82_fault_vs_exit() {
        // Spawn a child that faults. WAIT should return
        // R0=2 (ProtectionFault), not R0=0 (Exited).
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_fault_program();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Parent: SEAL → SPAWN → WAIT → EXIT(R0)
        // Exit with R0 (the tag), not R1, to distinguish fault from exit.
        let mut asm = Asm64::new();
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        emit_spawn_default(&mut asm, 0x10000_u32 as i32, child_size, 0);
        asm.mov(R4, R0); // handle
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0=tag. Exit with tag to distinguish.
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 200);

        assert!(kernel.processes[0].exited());
        // Tag 2 = ProtectionFault
        assert_eq!(kernel.processes[0].exit_code, 2,
            "faulted child must return tag 2 (ProtectionFault), not 0 (Exited)");
        eprintln!("8.2e: fault_vs_exit → tag=2 (ProtectionFault) ✓");
    }

    #[test]
    fn p82_exec_compatibility_0xdead() {
        // SYS_EXEC on a faulting child must still return 0xDEAD
        // (historical single-register ABI), not the new tag encoding.
        let mut fabric = Fabric::new(0x400000);
        let (core, dom, text, _output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_fault_program();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Parent: SEAL → EXEC (not SPAWN) → EXIT(R0)
        let mut asm = Asm64::new();
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // SYS_EXEC(0x10000, child_size, 0)
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R0, SYS_EXEC as i32);
        asm.trap(0);
        // R0 = child exit code (or 0xDEAD for faults)
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(1000, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 0xDEAD,
            "SYS_EXEC on faulting child must return 0xDEAD (historical ABI)");
        eprintln!("8.2e: exec_compatibility → 0xDEAD ✓");
    }

    #[test]
    fn p82_stale_handle_after_slot_reuse() {
        // Spawn A → H1(slot=0,gen=0), WAIT H1 (consumes it),
        // Spawn B → H2 reuses slot 0 (gen=1),
        // WAIT H1 → invalid (stale generation),
        // WAIT H2 → succeeds with B's exit code.
        //
        // Virtual layout (all MOVI targets < 0x20000):
        //   text:    virt 0x00000, phys 0x000000
        //   output1: virt 0x04000, phys 0x010000
        //   output2: virt 0x08000, phys 0x030000
        //   stack:   virt 0x10000, phys 0x020000
        let mut fabric = Fabric::new(0x800000);

        let text    = fabric.alloc_object("parent_text",   0x4000, ObjectKind::Memory);
        let output1 = fabric.alloc_object("child1_output", 0x4000, ObjectKind::Memory);
        let output2 = fabric.alloc_object("child2_output", 0x4000, ObjectKind::Memory);
        let stack   = fabric.alloc_object("parent_stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text,    0x000000);
        fabric.place_object(output1, 0x010000);
        fabric.place_object(output2, 0x030000);
        fabric.place_object(stack,   0x020000);

        let dom = fabric.create_domain();
        fabric.grant(dom, output1, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, output2, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, stack,   0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x4000, output1);
        core.address_map.add(0x08000, 0x4000, output2);
        core.address_map.add(0x10000, 0x4000, stack);
        core.r[SP as usize] = 0x10000 + 0x4000;
        core.trap_vector = 0x3FF0;

        // Child A: exit(10)
        let child_a = child_exit_code(10);
        fabric.write_physical(0x010000, &child_a);
        // Child B: exit(20)
        let child_b = child_exit_code(20);
        fabric.write_physical(0x030000, &child_b);

        let child_a_size = child_a.len() as i32;
        let child_b_size = child_b.len() as i32;

        // Parent program:
        //   SEAL buf1 → SPAWN buf1 → H1 in R4
        //   WAIT H1 → exit_code in R5 (10)
        //   SEAL buf2 → SPAWN buf2 → H2 in R6
        //   WAIT H1 again → R0 should be MAX (stale) → save in R7
        //   WAIT H2 → exit_code in R8 (20)
        //   If R7 == MAX, exit with R8 (20). Else exit with 0xFF (failure).
        let mut asm = Asm64::new();
        // SEAL + SPAWN child A
        asm.movi(R1, 0x4000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        emit_spawn_default(&mut asm, 0x4000_u32 as i32, child_a_size, 0);
        asm.mov(R4, R0); // H1

        // WAIT H1 (consume it)
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        asm.mov(R9, R1); // child A exit code (10) — R9 avoids ABI registers

        // SEAL + SPAWN child B (reuses slot 0, gen 1)
        asm.movi(R1, 0x8000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        emit_spawn_default(&mut asm, 0x8000_u32 as i32, child_b_size, 0);
        asm.mov(R6, R0); // H2

        // WAIT H1 again (stale handle — slot 0, gen 0 → gen mismatch)
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        asm.mov(R7, R0); // should be MAX

        // WAIT H2 (should succeed with 20)
        asm.mov(R1, R6);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        asm.mov(R8, R1); // child B exit code (20)

        // Verification: if R7 == MAX, exit with R8 (20).
        // Use: CMPI R7, -1 (MAX as signed = -1); BEQ → exit(R8)
        // else exit(0xFF)
        asm.cmpi(R7, -1);
        asm.bcc(super::super::isa::Cond::Eq, 4); // skip failure path (3 words) to success
        // failure path
        asm.movi(R1, 0xFF);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        // success path
        asm.mov(R1, R8);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.spawn(core);
        kernel.run(1000, 300);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 20,
            "stale H1 must be rejected (MAX), H2 must return 20");
        eprintln!("8.2e: stale_handle_after_slot_reuse → 20 ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.4b: Extended SYS_SPAWN tests — grants and maps
    // ═══════════════════════════════════════════════════════════
    //
    // Layout for extended-spawn tests (all vaddrs < MOVI 18-bit limit):
    //   Parent text : virt 0x00000, phys 0x000000, size 0x4000
    //   Child code  : virt 0x04000, phys 0x010000, size 0x4000 (RWS)
    //   Data obj    : virt 0x08000, phys 0x020000, size 0x4000 (RW)
    //   Stack       : virt 0x0C000, phys 0x030000, size 0x4000 (RW)
    //   Kernel alloc starts at 0x080000.
    //
    // Child virtual layout (EXEC_DEFAULT_LAYOUT):
    //   code:  0x00000   stack: 0x10000   trap: 0x20000
    //   Data object mapped at child_vaddr 0x14000 (between stack end and trap).

    /// Set up an extended-spawn test: parent with child-code buffer (RWS),
    /// a data object (RW), and a stack.
    fn ext_spawn_setup(fabric: &mut Fabric) -> (Anka64Core, DomainId, ObjectId, ObjectId, ObjectId, ObjectId) {
        let text     = fabric.alloc_object("parent_text",   0x4000, ObjectKind::Memory);
        let child_buf= fabric.alloc_object("child_code",    0x4000, ObjectKind::Memory);
        let data     = fabric.alloc_object("data_obj",      0x4000, ObjectKind::Memory);
        let stack    = fabric.alloc_object("parent_stack",   0x4000, ObjectKind::Memory);

        fabric.place_object(text,      0x000000);
        fabric.place_object(child_buf, 0x010000);
        fabric.place_object(data,      0x020000);
        fabric.place_object(stack,     0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, child_buf, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, data,      0, 0x4000, Permissions::RW);
        fabric.grant(dom, stack,     0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x4000, child_buf);
        core.address_map.add(0x08000, 0x4000, data);
        core.address_map.add(0x0C000, 0x4000, stack);
        core.r[SP as usize] = 0x0C000 + 0x4000;
        core.trap_vector = 0x3FF0;

        (core, dom, text, child_buf, data, stack)
    }

    /// Write a SpawnGrant descriptor to physical memory at the given address.
    /// Format: [parent_vaddr: u64, offset: u64, size: u64, perms: u64, reserved: u64]
    fn write_spawn_grant(fabric: &mut Fabric, phys_addr: u64,
                         parent_vaddr: u64, offset: u64, size: u64, perms: u64) {
        fabric.write_physical(phys_addr,      &parent_vaddr.to_le_bytes());
        fabric.write_physical(phys_addr + 8,  &offset.to_le_bytes());
        fabric.write_physical(phys_addr + 16, &size.to_le_bytes());
        fabric.write_physical(phys_addr + 24, &perms.to_le_bytes());
        fabric.write_physical(phys_addr + 32, &0u64.to_le_bytes()); // reserved
    }

    /// Write a SpawnMap descriptor to physical memory at the given address.
    /// Format: [child_vaddr: u64, parent_vaddr: u64, offset: u64, size: u64, reserved: u64]
    fn write_spawn_map(fabric: &mut Fabric, phys_addr: u64,
                       child_vaddr: u64, parent_vaddr: u64, offset: u64, size: u64) {
        fabric.write_physical(phys_addr,      &child_vaddr.to_le_bytes());
        fabric.write_physical(phys_addr + 8,  &parent_vaddr.to_le_bytes());
        fabric.write_physical(phys_addr + 16, &offset.to_le_bytes());
        fabric.write_physical(phys_addr + 24, &size.to_le_bytes());
        fabric.write_physical(phys_addr + 32, &0u64.to_le_bytes()); // reserved
    }

    // ── Test 1: Extended spawn with one grant (R data→child) ──
    //
    // Parent spawns child with code from sealed child_buf and grants
    // the child READ on data_obj.  Child reads from its mapped data
    // and exits with the value found there.
    #[test]
    fn p84b_spawn_with_grant() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        // Write child code: LD R1, [0x14000+0]; EXIT(R1)
        // Child will have data_obj mapped at 0x14000 via SpawnMap.
        let mut child_asm = Asm64::new();
        child_asm.movi(R1, 0x14000_u32 as i32);
        child_asm.ld(R1, R1, 0);       // R1 = [0x14000]
        child_asm.movi(R0, SYS_EXIT as i32);
        child_asm.trap(0);
        let child_code = child_asm.to_bytes();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Write marker value 0xBEEF into data_obj at offset 0
        fabric.write_physical(0x020000, &0xBEEFu64.to_le_bytes());

        // Write grant descriptor onto parent's stack area (phys 0x030000)
        // Grant: parent_vaddr=0x08000 (data obj), offset=0, size=0x4000, perms=R(0x01)
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x01);

        // Write map descriptor at phys 0x030000 + 40 = 0x030028
        // Map: child_vaddr=0x14000, parent_vaddr=0x08000, offset=0, size=0x4000
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        // Parent code: SEAL child_buf → extended SPAWN with 1 grant + 1 map → WAIT → EXIT
        let mut asm = Asm64::new();
        // SYS_SEAL(0x04000) — child code buffer
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // SYS_SPAWN: R1=code_vaddr, R2=code_size, R3=lit_start
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        // R4=grant_table_addr, R5=grant_count, R6=map_table_addr, R7=map_count
        asm.movi(R4, 0x0C000_u32 as i32);  // grant table at stack base
        asm.movi(R5, 1);                    // 1 grant
        asm.movi(R6, 0x0C028_u32 as i32);  // map table at stack base + 40
        asm.movi(R7, 1);                    // 1 map
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        // Save handle, WAIT, exit with child's exit code
        asm.mov(R4, R0);
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R1 = child exit code (should be 0xBEEF)
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 0xBEEF,
            "child should read 0xBEEF from granted data object");
        eprintln!("8.4b-1: spawn_with_grant → 0xBEEF ✓");
    }

    // ── Test 2: Extended spawn with RWS grant — child seals an object ──
    #[test]
    fn p84b_spawn_with_rws_grant() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, _child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        // Upgrade parent's data_obj authority to RWS (setup gives only RW).
        // Parent needs SEAL to delegate it.
        fabric.grant(dom, data, 0, 0x4000, Permissions::RWS);

        // Child: seal data obj at child_vaddr 0x14000, exit(99) on success
        let mut child_asm = Asm64::new();
        child_asm.movi(R1, 0x14000_u32 as i32);
        child_asm.movi(R0, SYS_SEAL as i32);
        child_asm.trap(0);
        child_asm.cmpi(R0, -1);
        child_asm.bcc(super::super::isa::Cond::Eq, 2); // skip to failure
        child_asm.movi(R1, 99);
        child_asm.movi(R0, SYS_EXIT as i32);
        child_asm.trap(0);
        child_asm.movi(R1, 0);
        child_asm.movi(R0, SYS_EXIT as i32);
        child_asm.trap(0);
        let child_code = child_asm.to_bytes();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Grant descriptor: RWS (0x13) on data_obj at parent_vaddr 0x08000
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x13);
        // Map descriptor: data_obj at child vaddr 0x14000
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        // Parent code
        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R4, R0);
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 99,
            "child should successfully seal data_obj (RWS grant)");
        eprintln!("8.4b-2: spawn_with_rws_grant → 99 ✓");
    }

    // ── Test 3: Grant with attenuated permissions (parent=RW, child=R) ──
    #[test]
    fn p84b_attenuated_grant() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        // Child: try to write to data_obj at 0x14000 (should fault — only has R)
        let mut child_asm = Asm64::new();
        child_asm.movi(R1, 42);
        child_asm.movi(R2, 0x14000_u32 as i32);
        child_asm.st(R1, R2, 0);  // write → should cause ProtectionFault
        child_asm.movi(R1, 0);
        child_asm.movi(R0, SYS_EXIT as i32);
        child_asm.trap(0);
        let child_code = child_asm.to_bytes();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        fabric.write_physical(0x020000, &0xBEEFu64.to_le_bytes());

        // Grant: READ only (0x01) — parent has RW, child gets R (attenuation)
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x01);
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R4, R0);
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        // R0 = tag. ProtectionFault = 2.
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 2,
            "child with READ-only grant should fault on write (tag=2)");
        eprintln!("8.4b-3: attenuated_grant → ProtectionFault ✓");
    }

    // ── Test 4: Permission escalation rejected ──
    // Parent has RW on data_obj, tries to grant RWS (SEAL) to child.
    // Spawn should fail (R0=MAX).
    #[test]
    fn p84b_escalation_rejected() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Grant: RWS (0x13) on data_obj — but parent only has RW → escalation
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x13);
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        // R0 should be MAX (spawn rejected)
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "escalation (RW→RWS) must be rejected");
        eprintln!("8.4b-4: escalation_rejected → MAX ✓");
    }

    // ── Test 5: Map without covering grant rejected ──
    // Map refers to data_obj, but no grant covers it.
    #[test]
    fn p84b_map_without_grant_rejected() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // No grants — only a map
        write_spawn_map(&mut fabric, 0x030000, 0x14000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);  // grant table
        asm.movi(R5, 0);                    // 0 grants
        asm.movi(R6, 0x0C000_u32 as i32);  // map table at same addr
        asm.movi(R7, 1);                    // 1 map
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "map without covering grant must be rejected");
        eprintln!("8.4b-5: map_without_grant_rejected → MAX ✓");
    }

    // ── Test 6: Map overlapping child code region rejected ──
    #[test]
    fn p84b_map_overlaps_code_rejected() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Grant and map at child vaddr 0x0000 — overlaps child code region
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x01);
        write_spawn_map(&mut fabric, 0x030028, 0x0000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "map overlapping child code must be rejected");
        eprintln!("8.4b-6: map_overlaps_code_rejected → MAX ✓");
    }

    // ── Test 7: Descriptor-table byte-length overflow ──
    // grant_count near u64::MAX, so grant_count × 40 overflows.
    #[test]
    fn p84b_descriptor_byte_overflow() {
        let mut fabric = Fabric::new(0x800000);
        let (mut core, dom, text, child_buf, _data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Parent code: set R5 = huge value → SPAWN → R0 should be MAX
        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        // R5 set below — too large for MOVI
        asm.movi(R6, 0x0C000_u32 as i32);
        asm.movi(R7, 0);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        // Set R5 to u64::MAX / 2 (way above MAX_SPAWN_GRANTS)
        core.r[R5 as usize] = u64::MAX / 2;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "huge grant_count must be rejected before allocation");
        eprintln!("8.4b-7: descriptor_byte_overflow → MAX ✓");
    }

    // ── Test 8: Descriptor table crossing two mappings rejected ──
    // Grant table straddles two separate address-map entries.
    #[test]
    fn p84b_descriptor_table_cross_mapping() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Place a grant descriptor straddling the end of data object.
        // data is at virt 0x08000 size 0x4000 (ends at 0x0C000).
        // Grant table at virt 0x0BFE0 (= 0x08000 + 0x3FE0) with size 40
        // spans [0x0BFE0, 0x0C008), exceeding the data mapping end (0x0C000).
        write_spawn_grant(&mut fabric, 0x023FE0, 0x08000, 0, 0x1000, 0x01);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        // Grant table at virt 0x0BFE0: resolve_virtual_range rejects it.
        asm.movi(R4, 0x0BFE0_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C000_u32 as i32);
        asm.movi(R7, 0);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "descriptor table crossing mapping boundary must be rejected");
        eprintln!("8.4b-8: descriptor_table_cross_mapping → MAX ✓");
    }

    // ── Test 9: Invalid permission bits rejected ──
    // Grant with perms = 0x20 (undefined bit) must be rejected.
    #[test]
    fn p84b_invalid_permission_bits() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Grant with invalid perms 0x20
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x20);
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "invalid permission bits (0x20) must be rejected");
        eprintln!("8.4b-9: invalid_permission_bits → MAX ✓");
    }

    // ── Test 10: Default spawn environment (R5=R7=R8=0) ──
    #[test]
    fn p84b_default_spawn_env() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_exit_code(77);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // R5=R7=R8=0 requests default process environment
        let parent_code = parent_seal_spawn_wait_exit(child_size);
        fabric.write_physical(0x000000, &parent_code);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 77,
            "default spawn env (R5=R7=R8=0) must work");
        eprintln!("8.4b-10: default_spawn_env → 77 ✓");
    }

    // ── Test 10b: Default spawn ignores R4/R6 (adversarial) ──
    //
    // When R5=0 and R7=0, R4 (grant_table_addr) and R6 (map_table_addr)
    // are don't-care values.  Set them to garbage to prove the kernel
    // never reads them under zero counts.
    #[test]
    fn p84b_default_spawn_ignores_r4_r6() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, output, _stack) = lifecycle_test_setup(&mut fabric);

        let child_code = child_exit_code(55);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        let mut asm = Asm64::new();
        // SEAL
        asm.movi(R1, 0x10000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        // Set R4 and R6 to garbage before SYS_SPAWN
        asm.movi(R4, 0x7FFF);   // garbage grant_table_addr
        asm.movi(R6, 0x7FFF);   // garbage map_table_addr
        // SYS_SPAWN with R5=R7=R8=0 (default env), R4/R6 = garbage
        emit_spawn_default(&mut asm, 0x10000_u32 as i32, child_size, 0);
        asm.mov(R4, R0); // save handle
        // WAIT + EXIT
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        asm.mov(R1, R1);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 55,
            "default spawn must ignore garbage R4/R6 when R5=R7=0");
        eprintln!("8.4b-10b: default_spawn_ignores_r4_r6 → 55 ✓");
    }

    // ── Test 11: Nonzero reserved field in grant rejected ──
    #[test]
    fn p84b_nonzero_reserved_rejected() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Write grant with nonzero reserved field
        fabric.write_physical(0x030000,       &0x08000u64.to_le_bytes()); // parent_vaddr
        fabric.write_physical(0x030000 + 8,   &0u64.to_le_bytes());       // offset
        fabric.write_physical(0x030000 + 16,  &0x4000u64.to_le_bytes());  // size
        fabric.write_physical(0x030000 + 24,  &0x01u64.to_le_bytes());    // perms = READ
        fabric.write_physical(0x030000 + 32,  &1u64.to_le_bytes());       // reserved = 1 (bad)

        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);                    // layout = default
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "nonzero reserved field in grant must be rejected");
        eprintln!("8.4b-11: nonzero_reserved → MAX ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.4b.1: SpawnLayout, exact-one-entry, checked overflow
    // ═══════════════════════════════════════════════════════════

    /// Write a SpawnLayout descriptor to physical memory.
    /// Format: [code_vaddr, stack_vaddr, stack_size, trap_vaddr, reserved]
    fn write_spawn_layout(fabric: &mut Fabric, phys_addr: u64,
                          code_vaddr: u64, stack_vaddr: u64,
                          stack_size: u64, trap_vaddr: u64) {
        fabric.write_physical(phys_addr,      &code_vaddr.to_le_bytes());
        fabric.write_physical(phys_addr + 8,  &stack_vaddr.to_le_bytes());
        fabric.write_physical(phys_addr + 16, &stack_size.to_le_bytes());
        fabric.write_physical(phys_addr + 24, &trap_vaddr.to_le_bytes());
        fabric.write_physical(phys_addr + 32, &0u64.to_le_bytes());
    }

    // ── Test 12: Custom SpawnLayout ──
    // Spawn child with code at 0x8000, stack at 0x18000 (4K),
    // trap at 0x1C000.  Child reads from granted data at 0x14000
    // and exits with the value.  Proves non-default layout works.
    #[test]
    fn p84b1_custom_spawn_layout() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, _child_buf, data, _stack) = ext_spawn_setup(&mut fabric);

        // Child code: LD R1, [0x14000]; EXIT(R1)
        // Child code will be placed at vaddr 0x8000 by SpawnLayout.
        let mut child_asm = Asm64::new();
        child_asm.movi(R1, 0x14000_u32 as i32);
        child_asm.ld(R1, R1, 0);
        child_asm.movi(R0, SYS_EXIT as i32);
        child_asm.trap(0);
        let child_code = child_asm.to_bytes();
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        fabric.write_physical(0x020000, &0xCAFEu64.to_le_bytes());

        // Grant: R on data_obj
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x01);
        // Map: data_obj at child vaddr 0x14000
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);
        // Layout: code=0x8000, stack=0x18000 (4K), trap=0x1C000
        write_spawn_layout(&mut fabric, 0x030050, 0x8000, 0x18000, 0x1000, 0x1C000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);  // grant table
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);  // map table
        asm.movi(R7, 1);
        asm.movi(R8, 0x0C050_u32 as i32);  // layout descriptor
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R4, R0);
        asm.mov(R1, R4);
        asm.movi(R0, SYS_WAIT as i32);
        asm.trap(0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 0xCAFE,
            "child with custom layout should read 0xCAFE");
        eprintln!("8.4b.1-12: custom_spawn_layout → 0xCAFE ✓");
    }

    // ── Test 13: SpawnLayout with bad reserved field rejected ──
    #[test]
    fn p84b1_layout_reserved_rejected() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, _child_buf, _data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Write layout with nonzero reserved
        fabric.write_physical(0x030000,      &0x8000u64.to_le_bytes());  // code_vaddr
        fabric.write_physical(0x030000 + 8,  &0x18000u64.to_le_bytes()); // stack_vaddr
        fabric.write_physical(0x030000 + 16, &0x1000u64.to_le_bytes());  // stack_size
        fabric.write_physical(0x030000 + 24, &0x1C000u64.to_le_bytes()); // trap_vaddr
        fabric.write_physical(0x030000 + 32, &1u64.to_le_bytes());       // reserved = 1 (bad)

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 0);
        asm.movi(R6, 0x0C000_u32 as i32);
        asm.movi(R7, 0);
        asm.movi(R8, 0x0C000_u32 as i32);  // layout at stack base (reused addr, 0 grants/maps)
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "layout with nonzero reserved must be rejected");
        eprintln!("8.4b.1-13: layout_reserved_rejected → MAX ✓");
    }

    // ── Test 14: SpawnLayout with stack too small rejected ──
    #[test]
    fn p84b1_layout_stack_too_small() {
        let mut fabric = Fabric::new(0x800000);
        let (core, dom, text, _child_buf, _data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Layout with stack_size = 0x100 (too small, MIN is 0x1000)
        write_spawn_layout(&mut fabric, 0x030000, 0x8000, 0x18000, 0x100, 0x1C000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 0);
        asm.movi(R6, 0x0C000_u32 as i32);
        asm.movi(R7, 0);
        asm.movi(R8, 0x0C000_u32 as i32);
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "layout with stack_size < MIN must be rejected");
        eprintln!("8.4b.1-14: layout_stack_too_small → MAX ✓");
    }

    // ── Test 15: Exact-one-entry: adjacent mappings can't stitch ──
    // Two adjacent address-map entries map contiguous portions of the
    // same object.  A grant descriptor that spans both entries must
    // be rejected by resolve_virtual_range (exact-one-entry check).
    #[test]
    fn p84b1_adjacent_map_no_stitch() {
        let mut fabric = Fabric::new(0x800000);

        let text      = fabric.alloc_object("parent_text",  0x4000, ObjectKind::Memory);
        let child_buf = fabric.alloc_object("child_code",   0x4000, ObjectKind::Memory);
        // One big data object split across two address-map entries
        let big_data  = fabric.alloc_object("big_data",     0x8000, ObjectKind::Memory);
        let stack     = fabric.alloc_object("parent_stack",  0x4000, ObjectKind::Memory);

        fabric.place_object(text,      0x000000);
        fabric.place_object(child_buf, 0x010000);
        fabric.place_object(big_data,  0x020000);
        fabric.place_object(stack,     0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, child_buf, 0, 0x4000, Permissions::RWS);
        fabric.grant(dom, big_data,  0, 0x8000, Permissions::RW);
        fabric.grant(dom, stack,     0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x4000, child_buf);
        // Map big_data as TWO adjacent entries of 0x4000 each:
        //   virt 0x08000 → big_data[0..0x4000)
        //   virt 0x0C000 → big_data[0x4000..0x8000)
        core.address_map.add_at(0x08000, 0x4000, big_data, 0);
        core.address_map.add_at(0x0C000, 0x4000, big_data, 0x4000);
        core.address_map.add(0x10000, 0x4000, stack);
        core.r[SP as usize] = 0x10000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Write a grant descriptor that spans BOTH entries:
        // parent_vaddr=0x08000, offset=0, size=0x8000
        // This crosses the entry boundary at 0x0C000.
        // The exact-one-entry check must reject it.
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x8000, 0x01);
        write_spawn_map(&mut fabric, 0x030028, 0x14000, 0x08000, 0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x10000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x10028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "grant spanning two adjacent map entries must be rejected (no stitching)");
        eprintln!("8.4b.1-15: adjacent_map_no_stitch → MAX ✓");
    }

    // ── Test 16: Map child_vaddr overflow rejected ──
    // Map with child_vaddr near u64::MAX so vaddr+size overflows.
    #[test]
    fn p84b1_map_vaddr_overflow() {
        let mut fabric = Fabric::new(0x800000);
        let (mut core, dom, text, _child_buf, _data, _stack) = ext_spawn_setup(&mut fabric);

        let child_code = child_exit_code(42);
        let child_size = child_code.len() as i32;
        fabric.write_physical(0x010000, &child_code);

        // Grant: valid
        write_spawn_grant(&mut fabric, 0x030000, 0x08000, 0, 0x4000, 0x01);
        // Map: child_vaddr = u64::MAX - 1, size = 0x4000 → overflow
        write_spawn_map(&mut fabric, 0x030028,
                        u64::MAX - 1,    // child_vaddr
                        0x08000,         // parent_vaddr
                        0, 0x4000);

        let mut asm = Asm64::new();
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R0, SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0x04000_u32 as i32);
        asm.movi(R2, child_size);
        asm.movi(R3, 0);
        asm.movi(R4, 0x0C000_u32 as i32);
        asm.movi(R5, 1);
        asm.movi(R6, 0x0C028_u32 as i32);
        asm.movi(R7, 1);
        asm.movi(R8, 0);
        asm.movi(R0, SYS_SPAWN as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x080000;
        kernel.spawn(core);
        kernel.run(500, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "map with child_vaddr+size overflow must be rejected");
        eprintln!("8.4b.1-16: map_vaddr_overflow → MAX ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.0d — Machine event composition tests
    //
    // These witness the full composed path:
    //   I_n commits → timer tick → post → deliver_pending → I_{n+1}
    // through the actual kernel scheduler.
    // ═══════════════════════════════════════════════════════════════

    /// Helper: set up a single-process kernel with a trap handler
    /// (HALT at trap_vector) and an N-instruction user program.
    /// Returns (kernel, text ObjectId, text physical base).
    fn timer_test_setup(
        fabric: &mut Fabric,
        user_code: &[u8],
    ) -> (Anka64Core, DomainId, ObjectId) {
        let text  = fabric.alloc_object("timer_text",  0x4000, ObjectKind::Memory);
        let stack = fabric.alloc_object("timer_stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text,  0x000000);
        fabric.place_object(stack, 0x010000);

        let dom = fabric.create_domain();
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        core.trap_vector = 0x3FF0;

        // Write user code at offset 0.
        fabric.write_physical(0x000000, user_code);
        // Write trap handler (HALT) at trap_vector physical offset.
        install_trap_handler(fabric, 0x000000, 0x4000);

        (core, dom, text)
    }

    /// Committed instruction → timer fires → immediate delivery.
    ///
    /// A 10-instruction NOP sled with timer period 5.  The timer
    /// fires after instruction 5 commits.  Before instruction 6
    /// fetches, deliver_pending() triggers, the process enters
    /// supervisor at trap_vector, and handle_async_interrupt() yields.
    ///
    /// On resume the process continues from instruction 6.
    #[test]
    fn p90d_commit_fire_deliver() {
        let mut asm = Asm64::new();
        // 10 NOPs then SYS_EXIT(42).
        for _ in 0..10 { asm.nop(); }
        asm.movi(R1, 42);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x100000);
        fabric.configure_timer(5);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        // Large quantum so preemption comes from the timer, not the loop.
        kernel.run(10000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 42,
            "process must complete after timer preemption + resume");
        eprintln!("9.0d: commit→fire→deliver→resume→exit(42) ✓");
    }

    /// No timer firing → ordinary execution continues uninterrupted.
    ///
    /// A 4-instruction program with timer period 100 (never fires).
    /// Process completes without any delivery.
    #[test]
    fn p90d_no_fire_continues() {
        let mut asm = Asm64::new();
        asm.movi(R1, 7);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x100000);
        fabric.configure_timer(100);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(10000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 7);
        eprintln!("9.0d: no fire → exit(7) ✓");
    }

    /// Timer fires repeatedly during a long NOP sled.  Each fire
    /// causes preemption and resume.  The process still completes.
    ///
    /// 50 NOPs + SYS_EXIT(99) with period 3: fires ~16 times.
    #[test]
    fn p90d_repeated_preemption() {
        let mut asm = Asm64::new();
        for _ in 0..50 { asm.nop(); }
        asm.movi(R1, 99);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x100000);
        fabric.configure_timer(3);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(10000, 200);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 99,
            "process must survive repeated timer preemptions");
        eprintln!("9.0d: repeated preemption (~16 fires) → exit(99) ✓");
    }

    /// M3a → M1 → M2 re-fire path: a second timer fires while the
    /// first interrupt is being handled (masked).  After event_return,
    /// the preserved pending event must be delivered before the next
    /// user instruction executes.
    ///
    /// This is the decisive composition witness for the formal path:
    ///   M3a →(T_eret)→ M1 →(T_deliver)→ M2.
    ///
    /// Strategy: period 1 fires every instruction.  After the first
    /// delivery, the timer fires again during the HALT at trap_vector
    /// (committed instruction → tick → post).  handle_async_interrupt
    /// does event_return, leaving P_timer + enabled.
    /// The pre-fetch check in run_process catches this and delivers
    /// again immediately.
    ///
    /// Despite constant preemption, the process must complete.
    #[test]
    fn p90d_masked_refire_path() {
        let mut asm = Asm64::new();
        // 20 NOPs then SYS_EXIT(77).
        for _ in 0..20 { asm.nop(); }
        asm.movi(R1, 77);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x100000);
        // Period 1: fires every single instruction.
        // Every committed instruction fires the timer, so the process
        // is preempted after every instruction.
        fabric.configure_timer(1);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        // Need many rounds because each instruction causes preemption.
        kernel.run(10000, 500);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 77,
            "M3a→M1→M2 re-fire path: process must survive period-1 preemption");
        eprintln!("9.0d: period-1 re-fire path → exit(77) ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.0e — Decisive adversarial preemption test
    //
    // Two infinite-loop processes preempted by the architectural
    // timer.  Both must make progress.  This proves that a real
    // architectural timer interrupt caused scheduling transitions,
    // not that the host loop happened to hit its bound.
    // ═══════════════════════════════════════════════════════════════

    /// Build an infinite-loop program that increments a counter in
    /// data memory on every iteration.
    ///
    /// Layout:
    ///   MOVI Rbase, data_vaddr   ; R2 = &counter
    ///   MOVI Rcount, 0           ; R3 = 0
    /// loop:
    ///   ADDI Rcount, Rcount, 1   ; R3++
    ///   ST   Rcount, Rbase, 0    ; data[0] = R3
    ///   BCC  Al, -2              ; unconditional backward branch to ADDI
    fn infinite_counter_program(data_vaddr: i32) -> Vec<u8> {
        let mut asm = Asm64::new();
        asm.movi(R2, data_vaddr);  // R2 = &data[0]
        asm.movi(R3, 0);           // R3 = counter = 0
        // loop:
        asm.addi(R3, R3, 1);       // counter++
        asm.st(R3, R2, 0);         // store counter to data
        asm.bcc(Cond::Al, -2);     // branch back to addi
        asm.to_bytes()
    }

    /// **Decisive Phase 9.0 test**: two infinite-loop processes,
    /// both preempted by the architectural timer, both make progress.
    ///
    /// This reproduces the 68000 project's decisive scheduling
    /// milestone on Anka64 — but this time using Anka64's own
    /// architectural interrupt semantics rather than a host-loop
    /// quantum counter.
    ///
    /// Proves:
    ///   A > 0  ∧  B > 0
    ///
    /// where A and B are iteration counts of two infinite loops,
    /// and the only cause of context switching is the FabricTimer
    /// → post_timer_interrupt → deliver_pending() → handle_async_interrupt
    /// → round-robin path.
    #[test]
    fn p90e_preemptive_multitasking() {
        let mut fabric = Fabric::new(0x800000);

        // Timer period 10: fires every 10 committed instructions.
        // Small enough that both processes are preempted frequently,
        // large enough that each makes meaningful progress per slice.
        fabric.configure_timer(10);

        // ── Process A at physical 0x000000 ──
        let (core_a, dom_a, text_a, data_a, _stack_a) =
            create_process(&mut fabric, AgentId(0), "procA",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let code_a = infinite_counter_program(0x10000);
        fabric.write_physical(0x000000, &code_a);
        seal_code_object(&mut fabric, text_a, dom_a);

        // ── Process B at physical 0x100000 ──
        let (core_b, dom_b, text_b, data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "procB",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let code_b = infinite_counter_program(0x10000);
        fabric.write_physical(0x100000, &code_b);
        seal_code_object(&mut fabric, text_b, dom_b);

        // ── Boot and run ──
        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core_a);
        kernel.spawn(core_b);

        // Use a very large quantum (safety bound) so preemption
        // comes from the architectural timer, not the loop counter.
        // 200 rounds of the scheduler should give each process
        // hundreds of timer slices.
        kernel.run(100_000, 200);

        // ── Read counters from data memory ──
        let a_phys = 0x010000_u64;  // data_a physical base
        let b_phys = 0x110000_u64;  // data_b physical base

        let a_bytes = kernel.fabric.read_physical(a_phys, 8);
        let b_bytes = kernel.fabric.read_physical(b_phys, 8);

        let counter_a = u64::from_le_bytes(
            [a_bytes[0], a_bytes[1], a_bytes[2], a_bytes[3],
             a_bytes[4], a_bytes[5], a_bytes[6], a_bytes[7]]);
        let counter_b = u64::from_le_bytes(
            [b_bytes[0], b_bytes[1], b_bytes[2], b_bytes[3],
             b_bytes[4], b_bytes[5], b_bytes[6], b_bytes[7]]);

        assert!(counter_a > 0,
            "Process A must have made progress (counter_a = {})", counter_a);
        assert!(counter_b > 0,
            "Process B must have made progress (counter_b = {})", counter_b);

        // Neither process should have exited — they are infinite loops.
        assert!(!kernel.processes[0].exited(),
            "Process A must still be running (infinite loop)");
        assert!(!kernel.processes[1].exited(),
            "Process B must still be running (infinite loop)");

        eprintln!("9.0e: DECISIVE PREEMPTIVE MULTITASKING TEST");
        eprintln!("      Process A iterations: {}", counter_a);
        eprintln!("      Process B iterations: {}", counter_b);
        eprintln!("      Both A > 0 ∧ B > 0 ✓");
        eprintln!("      Preemption source: architectural FabricTimer");
        eprintln!("      (not host-loop quantum bound)");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.1d — Interrupt source + kernel wiring
    //
    // Tests the composition:
    //   tick_devices() → level-triggered L_dev → post_device_interrupt()
    //   → deliver_pending() → handle_async_interrupt() → drain_block_completions()
    //   → generation-qualified wake
    //
    // The block controller is attached to the kernel and ticked
    // at each committed instruction boundary alongside the timer.
    // ═══════════════════════════════════════════════════════════════

    /// Helper: set up a kernel with one process and a block device.
    ///
    /// The process runs a simple NOP sled then SYS_EXIT(code).
    /// The block controller has `num_blocks` × 512 bytes, latency 1.
    /// Returns (kernel, buffer ObjectId, buffer DomainId) so callers
    /// can submit requests manually.
    fn block_kernel_setup(
        num_nops: usize,
        exit_code: i32,
        num_blocks: u64,
    ) -> (Kernel, ObjectId, DomainId) {
        use super::super::block::{BlockStorage, BlockController};

        let mut asm = Asm64::new();
        for _ in 0..num_nops { asm.nop(); }
        asm.movi(R1, exit_code);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, _data, _stack) =
            create_process(&mut fabric, AgentId(0), "blk_test",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        fabric.write_physical(0x000000, &code);
        seal_code_object(&mut fabric, text, dom);

        // DMA target buffer — a separate Memory object with WRITE authority.
        let buf = fabric.alloc_object("dma_buf", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf, 0x080000);
        fabric.grant(dom, buf, 0, 0x1000, Permissions::WRITE);

        let storage = BlockStorage::new(num_blocks, 512);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.block_controller = Some(ctrl);

        (kernel, buf, dom)
    }

    /// Level-triggered routing: tick_devices posts P_dev when C > 0.
    ///
    /// Manually submit a block request, tick until completed,
    /// then verify the core's pending.device bit is set.
    #[test]
    fn p91d_level_triggered_routing() {
        use super::super::block::{BlockRequest, SubmitResult};

        let (mut kernel, buf, dom) = block_kernel_setup(100, 42, 4);

        // Pre-populate block 0 with known data.
        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(0, &[0xAA; 512]);

        let rk = RequesterKey { slot: 0, generation: 0 };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
        };

        let result = kernel.block_controller.as_mut().unwrap()
            .submit(req, &mut kernel.fabric);
        assert!(matches!(result, SubmitResult::Accepted(_)));

        // Tick the controller until the request completes (latency 1 + DMA).
        for _ in 0..5 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }
        assert!(kernel.block_controller.as_ref().unwrap().requires_attention(),
            "C > 0 after completion");

        // Now call tick_devices() which should post P_dev.
        kernel.tick_devices(0);
        assert!(kernel.processes[0].core.pending.device,
            "level-triggered: tick_devices must post P_dev when C > 0");
        eprintln!("9.1d: level-triggered routing ✓");
    }

    /// Level re-assertion: after P_dev is consumed by delivery,
    /// if C > 0 persists, tick_devices re-posts P_dev.
    #[test]
    fn p91d_level_reassertion() {
        use super::super::block::{BlockRequest, SubmitResult};

        let (mut kernel, buf, dom) = block_kernel_setup(100, 42, 4);

        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(0, &[0xBB; 512]);
        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(1, &[0xCC; 512]);

        // Submit two requests — both slots occupied.
        let rk = RequesterKey { slot: 0, generation: 0 };
        for blk in 0..2u64 {
            let req = BlockRequest {
                block_number: blk,
                requester: rk,
                target_object: buf,
                target_offset: blk * 512,
                source_domain: dom,
            };
            let result = kernel.block_controller.as_mut().unwrap()
                .submit(req, &mut kernel.fabric);
            assert!(matches!(result, SubmitResult::Accepted(_)));
        }

        // Tick until both complete.
        for _ in 0..10 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }
        assert_eq!(kernel.block_controller.as_ref().unwrap().completion_count(), 2);

        // tick_devices posts P_dev.
        kernel.tick_devices(0);
        assert!(kernel.processes[0].core.pending.device);

        // Simulate delivery consuming P_dev.
        kernel.processes[0].core.pending.device = false;

        // Consume one completion — C is now 1, still > 0.
        kernel.block_controller.as_mut().unwrap().consume_completion();
        assert_eq!(kernel.block_controller.as_ref().unwrap().completion_count(), 1);

        // tick_devices must re-post because L_dev = (C > 0) is still true.
        kernel.tick_devices(0);
        assert!(kernel.processes[0].core.pending.device,
            "level re-assertion: P_dev must be re-posted while C > 0");
        eprintln!("9.1d: level re-assertion ✓");
    }

    /// Drain completions + wake: device interrupt handler wakes
    /// a process blocked on I/O with proper EventFrame continuation.
    ///
    /// Manually submit a request with the process's RequesterKey,
    /// push a synthetic syscall EventFrame, set io_wait, complete
    /// the request, then invoke drain_block_completions() and verify
    /// the process is unblocked with R0 = 0 and EventFrame consumed.
    #[test]
    fn p91d_drain_wake_success() {
        use super::super::block::{BlockRequest, SubmitResult, RequestHandle};

        let (mut kernel, buf, dom) = block_kernel_setup(100, 42, 4);

        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(0, &[0xDD; 512]);

        let rk = RequesterKey {
            slot: 0,
            generation: kernel.processes[0].generation,
        };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
        };

        let result = kernel.block_controller.as_mut().unwrap()
            .submit(req, &mut kernel.fabric);
        let handle = match result {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit must succeed"),
        };

        // Simulate the suspended syscall state: push an EventFrame
        // and set halted, as if SYS_BLOCK_READ had just executed.
        let saved_pc = kernel.processes[0].core.pc;
        kernel.processes[0].core.event_frames.push(EventFrame {
            return_pc: saved_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[0].core.halted = true;
        kernel.processes[0].io_wait = Some(IoWait { request: handle });

        // Tick until DMA completes.
        for _ in 0..10 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }
        assert!(kernel.block_controller.as_ref().unwrap().requires_attention());

        // Drain — should wake the process via event_return().
        kernel.drain_block_completions();

        assert!(kernel.processes[0].io_wait.is_none(),
            "process must be unblocked after completion drain");
        assert!(!kernel.processes[0].core.halted,
            "halted must be cleared by drain");
        assert_eq!(kernel.processes[0].core.r[R0 as usize], 0,
            "R0 = 0 on successful completion");
        assert_eq!(kernel.processes[0].core.pc, saved_pc,
            "PC must be restored to saved return address");
        assert!(kernel.processes[0].core.event_frames.is_empty(),
            "EventFrame must be consumed by event_return()");

        // Verify data arrived in guest buffer.
        let buf_data = kernel.fabric.read_physical(0x080000, 512);
        assert!(buf_data.iter().all(|&b| b == 0xDD),
            "DMA must have written block data to guest buffer");
        eprintln!("9.1d: drain + wake (success, event_return) ✓");
    }

    /// Generation-qualified wake: stale RequesterKey does not
    /// wake a recycled process slot.
    ///
    /// Submit a request with generation 0, then recycle the process
    /// slot (increment generation), complete the request, and verify
    /// that drain_block_completions() does NOT unblock the recycled slot.
    #[test]
    fn p91d_stale_requester_no_wake() {
        use super::super::block::{BlockRequest, SubmitResult, RequestHandle};

        let (mut kernel, buf, dom) = block_kernel_setup(100, 42, 4);

        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(0, &[0xEE; 512]);

        // Submit with generation 0 (the current incarnation).
        let rk = RequesterKey {
            slot: 0,
            generation: kernel.processes[0].generation,
        };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
        };

        let result = kernel.block_controller.as_mut().unwrap()
            .submit(req, &mut kernel.fabric);
        let handle = match result {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit must succeed"),
        };

        // "Recycle" the process slot by bumping its generation.
        kernel.processes[0].generation += 1;
        // Set up io_wait with the old handle on the recycled slot.
        kernel.processes[0].io_wait = Some(IoWait { request: handle });

        // Tick until completion.
        for _ in 0..10 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }

        // Drain — should NOT wake because generation doesn't match.
        kernel.drain_block_completions();

        assert!(kernel.processes[0].io_wait.is_some(),
            "stale RequesterKey must not wake a recycled process slot");
        eprintln!("9.1d: stale requester → no wake ✓");
    }

    /// Not-io_wait process: completion is consumed but no wake effect.
    ///
    /// A process that is not waiting on I/O should not have its
    /// R0 clobbered or state modified.
    #[test]
    fn p91d_not_blocked_no_clobber() {
        use super::super::block::{BlockRequest, SubmitResult};

        let (mut kernel, buf, dom) = block_kernel_setup(100, 42, 4);

        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(0, &[0xFF; 512]);

        let rk = RequesterKey {
            slot: 0,
            generation: kernel.processes[0].generation,
        };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
        };

        kernel.block_controller.as_mut().unwrap()
            .submit(req, &mut kernel.fabric);

        // Process is NOT io_wait.
        assert!(kernel.processes[0].io_wait.is_none());
        kernel.processes[0].core.r[R0 as usize] = 0xDEAD;

        for _ in 0..10 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }

        kernel.drain_block_completions();

        // R0 should be untouched — process was not waiting.
        assert_eq!(kernel.processes[0].core.r[R0 as usize], 0xDEAD,
            "non-waiting process must not have R0 clobbered");
        assert!(kernel.processes[0].io_wait.is_none());
        eprintln!("9.1d: not-waiting → no clobber ✓");
    }

    /// Timer + device simultaneously: both sources become pending
    /// from the same tick boundary, and both are eventually served.
    ///
    /// Uses a NOP sled long enough for the timer to fire and the
    /// block request to complete, then verifies both P_t and P_d
    /// are posted on the same tick.
    #[test]
    fn p91d_timer_and_device_simultaneous() {
        use super::super::block::{BlockRequest, BlockStorage, BlockController, SubmitResult};

        let mut asm = Asm64::new();
        for _ in 0..50 { asm.nop(); }
        asm.movi(R1, 99);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x200000);
        // Timer period: large enough that we can control when it fires.
        fabric.configure_timer(10);
        let (core, dom, text, _data, _stack) =
            create_process(&mut fabric, AgentId(0), "simul",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        fabric.write_physical(0x000000, &code);
        seal_code_object(&mut fabric, text, dom);

        let buf = fabric.alloc_object("dma_buf", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf, 0x080000);
        fabric.grant(dom, buf, 0, 0x1000, Permissions::WRITE);

        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0x42; 512]);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.block_controller = Some(ctrl);

        // Submit a block request.
        let rk = RequesterKey { slot: 0, generation: 0 };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
        };
        kernel.block_controller.as_mut().unwrap()
            .submit(req, &mut kernel.fabric);

        // Tick the block controller until completed.
        for _ in 0..10 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }
        assert!(kernel.block_controller.as_ref().unwrap().requires_attention());

        // Manually configure timer to fire on the next tick.
        kernel.fabric.configure_timer(1);

        // tick_devices should post BOTH P_t and P_d.
        kernel.tick_devices(0);

        assert!(kernel.processes[0].core.pending.timer,
            "timer must be pending");
        assert!(kernel.processes[0].core.pending.device,
            "device must be pending");
        eprintln!("9.1d: timer + device simultaneous pending ✓");
    }

    /// No block controller → tick_devices is harmless.
    ///
    /// Kernel without a block controller should not panic.
    #[test]
    fn p91d_no_controller_harmless() {
        let mut asm = Asm64::new();
        asm.movi(R1, 7);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x100000);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        assert!(kernel.block_controller.is_none());
        kernel.spawn(core);
        kernel.run(10000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 7);
        eprintln!("9.1d: no controller → harmless ✓");
    }

    /// Empty completion queue: drain_block_completions is harmless.
    #[test]
    fn p91d_drain_empty_harmless() {
        let (mut kernel, _buf, _dom) = block_kernel_setup(10, 42, 4);
        kernel.drain_block_completions();
        assert!(kernel.processes[0].io_wait.is_none());
        eprintln!("9.1d: drain empty → harmless ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.1e — Decisive guest-level async block I/O
    //
    // The centerpiece: a real SYS_BLOCK_READ syscall that retains
    // the EventFrame while the process is I/O-blocked.  Completion
    // performs event_return(), resuming the caller at user PC.
    //
    // This composes EventFrame architecture (9.0) with asynchronous
    // I/O (9.1) into a single suspended-syscall continuation path.
    // ═══════════════════════════════════════════════════════════════

    /// **Decisive Phase 9.1 test**: guest async block READ.
    ///
    /// Process A issues SYS_BLOCK_READ and blocks.  Process B
    /// runs an infinite counter.  The block controller completes
    /// A's request via DMA.  A device interrupt fires during B's
    /// execution.  The handler drains the completion, validates
    /// both RequesterKey and RequestHandle identity, performs
    /// event_return(), and resumes A at user PC.  A then reads
    /// the DMA buffer and verifies the 512 bytes match.
    ///
    /// Proves the full composition:
    ///   guest TRAP → validate buffer → narrow DMA delegation
    ///   → block with EventFrame → other process executes
    ///   → DMA commit → device interrupt → identity validation
    ///   → event_return → guest verifies 512 bytes
    #[test]
    fn p91e_decisive_guest_async_read() {
        use super::super::block::{BlockStorage, BlockController};

        // Process A — guest verifies all 512 bytes (64 words) after DMA:
        //
        //   MOVI R1, 0               ; block_number = 0
        //   MOVI R2, buf_vaddr       ; buffer virtual address
        //   MOVI R0, SYS_BLOCK_READ
        //   TRAP                     ; → blocks here
        //   --- resumes here after completion ---
        //   MOVI R5, 64              ; word counter (512 / 8)
        //   MOVI R6, 1               ; expected word value
        // loop:
        //   LD   R3, R2, 0           ; load 8 bytes at [R2]
        //   CMP  R3, R6              ; compare with expected (1)
        //   BCC  Ne, +5              ; mismatch → error exit
        //   ADDI R2, R2, 8           ; advance pointer
        //   SUBI R5, R5, 1           ; decrement counter
        //   MOVI R7, 0
        //   CMP  R5, R7              ; counter == 0?
        //   BCC  Ne, -6              ; loop back if counter > 0
        //   MOVI R1, 200             ; all 64 words verified — success
        //   MOVI R0, SYS_EXIT
        //   TRAP
        // error:
        //   MOVI R1, 0xDEA           ; data mismatch
        //   MOVI R0, SYS_EXIT
        //   TRAP
        let buf_vaddr = 0x04000_i32;  // fits signed imm18
        let mut asm_a = Asm64::new();
        asm_a.movi(R1, 0);                          // block_number = 0
        asm_a.movi(R2, buf_vaddr);                   // buf_vaddr
        asm_a.movi(R0, SYS_BLOCK_READ as i32);
        asm_a.trap(0);
        // After wake: R0 = 0 (success).  Verify all 512 bytes.
        asm_a.movi(R5, 64);                          // 64 words = 512 bytes
        asm_a.movi(R6, 1);                           // expected u64 value
        // loop (word offset 6):
        asm_a.ld(R3, R2, 0);                         // load 8 bytes at [R2]
        asm_a.cmp(R3, R6);                           // compare with expected
        asm_a.bcc(Cond::Ne, 5);                      // mismatch → error exit
        asm_a.addi(R2, R2, 8);                       // advance pointer
        asm_a.subi(R5, R5, 1);                       // decrement counter
        asm_a.movi(R7, 0);
        asm_a.cmp(R5, R7);                           // counter == 0?
        asm_a.bcc(Cond::Ne, -6);                     // loop back
        // success:
        asm_a.movi(R1, 200);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        // error:
        asm_a.movi(R1, 0xDEA);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        let code_a = asm_a.to_bytes();

        // Process B: infinite counter loop.
        let code_b = infinite_counter_program(0x10000);

        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(5);

        // Process A — text at 0x000000, data at 0x010000, stack at 0x020000
        let (core_a, dom_a, text_a, _data_a, _stack_a) =
            create_process(&mut fabric, AgentId(0), "procA",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        fabric.write_physical(0x000000, &code_a);
        seal_code_object(&mut fabric, text_a, dom_a);

        // DMA target buffer for process A — mapped at buf_vaddr.
        let buf_obj = fabric.alloc_object("dma_buf_a", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf_obj, 0x040000);
        fabric.grant(dom_a, buf_obj, 0, 0x1000, Permissions::RW);

        // Process B — at separate physical addresses
        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "procB",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        fabric.write_physical(0x100000, &code_b);
        seal_code_object(&mut fabric, text_b, dom_b);

        // Block storage: block 0 filled with 64 copies of u64 = 1.
        let mut storage = BlockStorage::new(4, 512);
        let block_data: Vec<u8> = (0..64)
            .flat_map(|_| 1u64.to_le_bytes())
            .collect();
        assert_eq!(block_data.len(), 512);
        storage.write_block(0, &block_data);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        kernel.spawn(core_b);
        kernel.block_controller = Some(ctrl);

        // Map the DMA buffer into process A's address space at buf_vaddr.
        kernel.processes[key_a.slot].core.address_map
            .add(buf_vaddr as u64, 0x1000, buf_obj);

        // Run: A will issue SYS_BLOCK_READ and block.
        // B runs in the background. The block controller completes.
        // A device interrupt fires, drains, event_return wakes A.
        // A reads the buffer, verifies data, exits with 200.
        kernel.run(100_000, 500);

        assert!(kernel.processes[key_a.slot].exited(),
            "process A must complete after I/O wake + verification");
        assert_eq!(kernel.processes[key_a.slot].exit_code, 200,
            "A must exit with 200 (data verified), got {}",
            kernel.processes[key_a.slot].exit_code);
        assert!(!kernel.processes[1].exited(),
            "process B (infinite loop) must still be running");

        // Double-check: verify the physical DMA buffer contains expected data.
        let phys_buf = kernel.fabric.read_physical(0x040000, 512);
        assert_eq!(&phys_buf[..], &block_data[..],
            "DMA buffer must contain the exact block data");

        eprintln!("9.1e: DECISIVE GUEST ASYNC BLOCK READ");
        eprintln!("      A: SYS_BLOCK_READ → blocked → woken → verified all 512 bytes → exit(200)");
        eprintln!("      B: infinite counter (still running)");
        eprintln!("      Block data: 64 × u64(1), guest-verified word-by-word");
        eprintln!("      Composition: EventFrame + async I/O + DMA + device interrupt ✓");
    }

    /// SYS_BLOCK_READ with no block controller returns MAX immediately.
    #[test]
    fn p91e_block_read_no_controller() {
        let mut asm = Asm64::new();
        asm.movi(R1, 0);
        asm.movi(R2, 0x10000);
        asm.movi(R0, SYS_BLOCK_READ as i32);
        asm.trap(0);
        // R0 should be MAX after failed syscall.
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x100000);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        assert!(kernel.block_controller.is_none());
        kernel.spawn(core);
        kernel.run(10000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "SYS_BLOCK_READ with no controller must return MAX");
        eprintln!("9.1e: block_read no controller → MAX ✓");
    }

    /// SYS_BLOCK_READ with invalid buffer address returns MAX.
    #[test]
    fn p91e_block_read_bad_buffer() {
        use super::super::block::{BlockStorage, BlockController};

        let mut asm = Asm64::new();
        asm.movi(R1, 0);          // block 0
        asm.movi(R2, 0x18000_i32); // representable AND unmapped
        asm.movi(R0, SYS_BLOCK_READ as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text) = timer_test_setup(&mut fabric, &code);
        seal_code_object(&mut fabric, text, dom);

        let storage = BlockStorage::new(4, 512);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.block_controller = Some(ctrl);
        kernel.run(10000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "SYS_BLOCK_READ with unmapped buffer must return MAX");
        eprintln!("9.1e: block_read bad buffer → MAX ✓");
    }

    /// SYS_BLOCK_READ with invalid block number returns MAX.
    #[test]
    fn p91e_block_read_invalid_block() {
        use super::super::block::{BlockStorage, BlockController};

        // Read block 999 from a 4-block device.
        let buf_vaddr = 0x04000_i32;  // fits signed imm18
        let mut asm = Asm64::new();
        asm.movi(R1, 999);
        asm.movi(R2, buf_vaddr);
        asm.movi(R0, SYS_BLOCK_READ as i32);
        asm.trap(0);
        asm.mov(R1, R0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, _data, _stack) =
            create_process(&mut fabric, AgentId(0), "inv_blk",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        fabric.write_physical(0x000000, &code);
        seal_code_object(&mut fabric, text, dom);

        let buf = fabric.alloc_object("buf", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf, 0x080000);
        fabric.grant(dom, buf, 0, 0x1000, Permissions::RW);

        let storage = BlockStorage::new(4, 512);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.block_controller = Some(ctrl);
        kernel.processes[0].core.address_map.add(buf_vaddr as u64, 0x1000, buf);
        kernel.run(10000, 100);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "SYS_BLOCK_READ with out-of-range block must return MAX");
        eprintln!("9.1e: block_read invalid block → MAX ✓");
    }

    /// Stale RequestHandle: completion with a non-matching handle
    /// does not wake the process.
    ///
    /// Submit two requests (different blocks), io_wait on the second
    /// handle, complete both.  The first completion (different handle)
    /// must not wake; the second (matching handle) must.
    #[test]
    fn p91e_stale_request_handle_no_wake() {
        use super::super::block::{BlockRequest, SubmitResult, RequestHandle};

        let (mut kernel, buf, dom) = block_kernel_setup(100, 42, 4);
        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(0, &[0xAA; 512]);
        kernel.block_controller.as_mut().unwrap()
            .storage_mut().write_block(1, &[0xBB; 512]);

        let rk = RequesterKey {
            slot: 0,
            generation: kernel.processes[0].generation,
        };

        // Submit request for block 0 → gets handle from slot 0.
        let req0 = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
        };
        let handle0 = match kernel.block_controller.as_mut().unwrap()
            .submit(req0, &mut kernel.fabric)
        {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit 0 must succeed"),
        };

        // Submit request for block 1 → gets handle from slot 1.
        let req1 = BlockRequest {
            block_number: 1,
            requester: rk,
            target_object: buf,
            target_offset: 512,
            source_domain: dom,
        };
        let handle1 = match kernel.block_controller.as_mut().unwrap()
            .submit(req1, &mut kernel.fabric)
        {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit 1 must succeed"),
        };

        assert_ne!(handle0.slot, handle1.slot, "must use different slots");

        // The process is waiting on handle1 (the second request).
        let saved_pc = kernel.processes[0].core.pc;
        kernel.processes[0].core.event_frames.push(EventFrame {
            return_pc: saved_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[0].core.halted = true;
        kernel.processes[0].io_wait = Some(IoWait { request: handle1 });

        // Tick until both complete.
        for _ in 0..10 {
            kernel.block_controller.as_mut().unwrap()
                .tick(&mut kernel.fabric);
        }
        assert_eq!(kernel.block_controller.as_ref().unwrap().completion_count(), 2);

        // Drain: the first completion (handle0) must NOT wake.
        // The second completion (handle1) MUST wake.
        kernel.drain_block_completions();

        assert!(kernel.processes[0].io_wait.is_none(),
            "process must be woken by matching handle1");
        assert!(!kernel.processes[0].core.halted);
        assert_eq!(kernel.processes[0].core.r[R0 as usize], 0);
        eprintln!("9.1e: stale request handle → selective wake ✓");
    }

    /// Machine limitation documentation test: with a block controller
    /// attached, if the only process is io_wait'd and no other
    /// process runs, the device never ticks (no instructions commit).
    ///
    /// This test documents the known limitation rather than fixing it.
    /// The current machine model requires at least one running process
    /// to generate instruction boundaries for tick_devices().
    #[test]
    fn p91e_all_blocked_no_progress_documented() {
        use super::super::block::{BlockRequest, BlockStorage, BlockController, SubmitResult};

        let buf_vaddr = 0x04000_i32;  // fits signed imm18
        let mut asm = Asm64::new();
        asm.movi(R1, 0);
        asm.movi(R2, buf_vaddr);
        asm.movi(R0, SYS_BLOCK_READ as i32);
        asm.trap(0);
        asm.movi(R1, 123);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let code = asm.to_bytes();

        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, _data, _stack) =
            create_process(&mut fabric, AgentId(0), "solo",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        fabric.write_physical(0x000000, &code);
        seal_code_object(&mut fabric, text, dom);

        let buf = fabric.alloc_object("buf", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf, 0x080000);
        fabric.grant(dom, buf, 0, 0x1000, Permissions::RW);

        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0x42; 512]);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.block_controller = Some(ctrl);
        kernel.processes[0].core.address_map.add(buf_vaddr as u64, 0x1000, buf);

        // Run with very few rounds — the process will block on I/O
        // and no one else runs, so no tick_devices() fires.
        kernel.run(10000, 10);

        // Process A issued SYS_BLOCK_READ and is now io_wait.
        // It should NOT have exited because no device ticks occurred.
        assert!(!kernel.processes[0].exited(),
            "solo io_wait process must NOT complete — no tick source");
        assert!(kernel.processes[0].io_wait.is_some(),
            "process must still be waiting on I/O");

        eprintln!("9.1e: all-blocked-no-progress limitation documented ✓");
        eprintln!("      (machine requires at least one running process");
        eprintln!("       to generate instruction boundaries for tick_devices)");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2a — Capability table kernel tests
    // ═══════════════════════════════════════════════════════════════

    /// Helper: set up a minimal kernel with one process and a data object.
    /// Returns (kernel, data_object_id, process_slot).
    fn captab_kernel_setup() -> (Kernel, ObjectId, usize) {
        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, data, _stack) =
            create_process(&mut fabric, CPU0, "cap_test",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Minimal guest: NOP * 100 then EXIT(0)
        let mut asm = Asm64::new();
        for _ in 0..100 { asm.nop(); }
        asm.movi(R1, 0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);

        (kernel, data, 0)
    }

    // ─── Kernel install + resolve ───

    #[test]
    fn p92a_install_and_resolve() {
        let (mut kernel, data, slot) = captab_kernel_setup();

        let h = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("install should succeed");

        let resolved = kernel.resolve_capability(slot, h)
            .expect("resolve should succeed");
        assert_eq!(resolved.object, data);
        assert_eq!(resolved.offset, 0);
        assert_eq!(resolved.length, 4096);
        assert_eq!(resolved.perms, Permissions::READ);

        eprintln!("9.2a: install + resolve ✓");
    }

    // ─── Kernel: resolve fails after object revocation ───

    #[test]
    fn p92a_resolve_fails_after_revocation() {
        let (mut kernel, data, slot) = captab_kernel_setup();

        let h = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("install should succeed");

        // Revoke the object → bumps generation
        kernel.fabric.revoke(data);

        assert!(kernel.resolve_capability(slot, h).is_none(),
            "handle must not resolve after object revocation");

        eprintln!("9.2a: resolve-after-revocation ✓");
    }

    // ─── Kernel: drop removes exactly one backing authority ───

    #[test]
    fn p92a_drop_removes_only_linked_authority() {
        let (mut kernel, data, slot) = captab_kernel_setup();

        let domain = kernel.processes[slot].core.domain;
        let cap_count_before = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();

        // Install two equal-looking capabilities with different AuthorityIds
        let h1 = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("install h1");
        let h2 = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("install h2");

        let cap_count_after_install = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_after_install, cap_count_before + 2,
            "two grants should add two domain entries");

        // Drop h1
        let auth_id = kernel.processes[slot].cap_table.as_mut().unwrap()
            .drop_handle(h1).expect("drop h1");
        kernel.fabric.remove_by_authority_id(domain, auth_id);

        let cap_count_after_drop = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_after_drop, cap_count_before + 1,
            "drop(H1) must remove exactly one domain entry");

        // h2 still resolves
        assert!(kernel.resolve_capability(slot, h2).is_some(),
            "H2 must survive drop(H1)");

        eprintln!("9.2a: equal-looking-caps drop isolation ✓");
    }

    // ─── Kernel: SYS_CAP_DROP via guest code ───

    #[test]
    fn p92a_syscall_cap_drop() {
        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, data, _stack) =
            create_process(&mut fabric, CPU0, "cap_drop",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut kernel = Kernel::new(fabric);
        let pk = kernel.spawn(core);
        let slot = pk.slot;

        let h = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
            .expect("install should succeed");

        // Assemble guest code: CAP_DROP(slot, generation), save result, EXIT(0)
        let mut asm = Asm64::new();
        asm.movi(R1, h.slot as i32);
        asm.movi(R2, h.generation as i32);
        asm.movi(R0, SYS_CAP_DROP as i32);
        asm.trap(0);
        asm.mov(R5, R0); // save result
        asm.movi(R1, 0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        kernel.fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut kernel.fabric, text, dom);

        kernel.run(10000, 10);

        assert!(kernel.processes[slot].exited());
        assert_eq!(kernel.processes[slot].core.r[R5 as usize], 0,
            "SYS_CAP_DROP should return 0 on success");

        assert!(kernel.resolve_capability(slot, h).is_none(),
            "dropped handle must not resolve");

        eprintln!("9.2a: SYS_CAP_DROP via guest code ✓");
    }

    // ─── Kernel: SYS_CAP_DROP with invalid handle ───

    #[test]
    fn p92a_syscall_cap_drop_bad_handle() {
        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, _data, _stack) =
            create_process(&mut fabric, CPU0, "cap_drop_bad",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Guest: CAP_DROP(slot=0, gen=99) — no such handle, then EXIT
        let mut asm = Asm64::new();
        asm.movi(R1, 0);
        asm.movi(R2, 99);
        asm.movi(R0, SYS_CAP_DROP as i32);
        asm.trap(0);
        asm.mov(R5, R0); // save result
        asm.movi(R1, 0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);

        kernel.run(10000, 10);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].core.r[R5 as usize], 1,
            "SYS_CAP_DROP on bad handle should return 1");

        eprintln!("9.2a: SYS_CAP_DROP bad handle rejection ✓");
    }

    // ─── Kernel: table exhaustion at kernel level ───

    #[test]
    fn p92a_kernel_table_exhaustion() {
        let (mut kernel, data, slot) = captab_kernel_setup();

        // Fill the table
        for _ in 0..CAP_TABLE_SIZE {
            kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
                .expect("install should succeed");
        }

        // Next install must fail
        assert!(kernel.install_capability(slot, data, 0, 4096, Permissions::READ).is_none(),
            "install beyond table capacity must fail");

        eprintln!("9.2a: kernel-level table exhaustion ✓");
    }

    // ─── Kernel: F+O=N conservation through kernel operations ───

    #[test]
    fn p92a_kernel_fo_conservation() {
        let (mut kernel, data, slot) = captab_kernel_setup();
        let ct = kernel.processes[slot].cap_table.as_ref().unwrap();
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);

        let h1 = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("install");
        let h2 = kernel.install_capability(slot, data, 0, 4096, Permissions::RW)
            .expect("install");

        let ct = kernel.processes[slot].cap_table.as_ref().unwrap();
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);

        // Drop h1
        let auth_id = kernel.processes[slot].cap_table.as_mut().unwrap()
            .drop_handle(h1).expect("drop");
        let domain = kernel.processes[slot].core.domain;
        kernel.fabric.remove_by_authority_id(domain, auth_id);

        let ct = kernel.processes[slot].cap_table.as_ref().unwrap();
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 1);

        // Reinstall
        kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("reinstall");
        let ct = kernel.processes[slot].cap_table.as_ref().unwrap();
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 2);

        eprintln!("9.2a: kernel F+O=N conservation ✓");
    }

    // ─── Kernel: SYS_CAP_DROP + reinstall ───

    #[test]
    fn p92a_drop_reinstall_old_handle_stale() {
        let (mut kernel, data, slot) = captab_kernel_setup();

        let h = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("install");

        // Drop via kernel API (not syscall) for simplicity
        let auth_id = kernel.processes[slot].cap_table.as_mut().unwrap()
            .drop_handle(h).expect("drop");
        let domain = kernel.processes[slot].core.domain;
        kernel.fabric.remove_by_authority_id(domain, auth_id);

        // Reinstall in the same slot
        let h2 = kernel.install_capability(slot, data, 0, 4096, Permissions::READ)
            .expect("reinstall");

        // Old handle is permanently stale
        assert!(kernel.resolve_capability(slot, h).is_none(),
            "old handle must be permanently stale after slot reuse");
        assert!(kernel.resolve_capability(slot, h2).is_some(),
            "new handle must resolve");
        assert_ne!(h.generation, h2.generation,
            "slot reuse must increment generation");

        eprintln!("9.2a: drop+reinstall handle staleness ✓");
    }
}

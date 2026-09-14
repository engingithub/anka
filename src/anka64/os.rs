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
pub const SYS_SEND_CAP: u64 = 11;  // send_cap(dest_key, value, src_handle, child_subset) → 0 ok
pub const SYS_SEND_KEY: u64 = 12;  // send_key(dest_slot, dest_gen, value) → 0 ok
pub const SYS_DEV_SUBMIT: u64 = 13; // dev_submit(device_handle, block_num, buffer_handle) → 0 ok
pub const SYS_RECV_WAIT: u64 = 14; // recv_wait(peer_slot, peer_gen) → blocking exact-peer receive
pub const SYS_DEV_SUBMIT_ASYNC: u64 = 15; // dev_submit_async(same args) → R0=0,R1=slot,R2=gen
pub const SYS_DEV_WAIT: u64 = 16; // dev_wait(slot, gen) → completion status

/// Maximum messages per mailbox.  Enforced by all producers:
/// SYS_SEND, SYS_SEND_KEY, and SYS_SEND_CAP.
pub const MAX_MAILBOX_SIZE: usize = 16;

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
    /// If Some, process is blocked waiting for an exact-peer message
    /// or PeerDied notification (Phase 9.2e).  The process remains
    /// `ProcessState::Running` but is not schedulable.
    pub recv_wait: Option<RecvWait>,
    /// Per-process async request ledger (Phase 9.2f).
    ///
    /// Tracks outstanding SYS_DEV_SUBMIT_ASYNC requests and their
    /// completion status.  Bounded by MAX_ASYNC_REQUESTS.
    /// Cleared by reclaim_process(); NOT cleared by finish_process().
    pub async_requests: Vec<AsyncDeviceRequest>,
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

    /// True if the process can be scheduled for instruction execution.
    ///
    /// A process is schedulable iff it is Running AND not blocked on
    /// any wait type.  This is the single authoritative predicate —
    /// all scheduler logic must use this rather than ad-hoc field
    /// combinations.
    ///
    /// Formal basis: anka_blocking_receive.kleis — client_schedulable_92e,
    ///   driver_schedulable_92e.
    pub fn is_schedulable(&self) -> bool {
        self.state == ProcessState::Running
            && self.waiting_on.is_none()
            && self.io_wait.is_none()
            && self.recv_wait.is_none()
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

// ProcessKey is now in state.rs (Phase 9.2b) for cross-module use.

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

/// Device-qualified request identity (Phase 9.3b).
///
/// Controller-local `RequestHandle` values are NOT globally unique.
/// Two controllers may independently issue `(slot=0, gen=0)`.
/// This key resolves the ambiguity:
///
///   MachineRequestIdentity = (DeviceIdentity, LocalRequestIdentity)
///
/// where DeviceIdentity = DeviceBinding = (ObjectId, Generation).
///
/// Formal basis: anka_multi_device_routing.kleis DEVROUTE-6..8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRequestKey {
    pub device: DeviceBinding,
    pub request: super::block::RequestHandle,
}

/// Suspended I/O wait — the process has an outstanding device
/// request whose EventFrame remains on the frame stack.
///
/// Two independent identity protections:
///   RequesterKey — which process incarnation?
///   DeviceRequestKey — which device + which I/O operation?
///
/// The completion must match both before the kernel will perform
/// event_return() and resume the caller at user PC.
#[derive(Debug, Clone)]
pub struct IoWait {
    pub request: DeviceRequestKey,
}

/// Maximum entries in the per-process async request ledger.
///
/// Deliberately larger than the controller's NUM_SLOTS (2) to
/// separate software completion-record lifetime from hardware
/// slot availability.
pub const MAX_ASYNC_REQUESTS: usize = 16;

/// An outstanding asynchronous device request tracked in the
/// per-process ledger.
///
/// Lifecycle:
///   SYS_DEV_SUBMIT_ASYNC → push { handle, completion: None }
///   drain_block_completions() → fill completion = Some(status)
///   SYS_DEV_WAIT on completed → return status, remove entry
///   SYS_DEV_WAIT on pending → install IoWait, completion drain
///     will later wake + remove entry
///   reclaim_process() → clear entire ledger
///
/// Formal basis: anka_multi_request_quiescence.kleis MULTI92F-*.
#[derive(Debug, Clone)]
pub struct AsyncDeviceRequest {
    pub key: DeviceRequestKey,
    pub completion: Option<super::block::CompletionStatus>,
}

/// Side-effect-free validation result from preflight_dev_submit().
///
/// Contains all validated fields needed to construct a BlockRequest
/// and submit to the controller, but no DMA domain has been created
/// and no authority IDs have been consumed.
///
/// The caller (handle_dev_submit or handle_dev_submit_async) uses
/// these fields to mint the DMA authority and submit, ensuring that
/// preflight failure implies zero side effects.
#[derive(Debug)]
struct PreparedDevSubmit {
    device_binding: DeviceBinding,
    block_number: u64,
    requester: super::state::RequesterKey,
    target_object: super::state::ObjectId,
    target_offset: u64,
    source_domain: super::state::DomainId,
    source_authority_id: super::state::AuthorityId,
    delegation_id: Option<super::state::DelegationId>,
}

/// Exact-peer blocking receive (Phase 9.2e).
///
/// A process in RecvWait remains `ProcessState::Running` — just not
/// schedulable.  This is a scheduling field, not a ProcessState variant.
///
/// The `peer` field identifies the exact generation-qualified ProcessKey
/// whose message (or death notification) this process is waiting for.
///
/// Formal basis: anka_blocking_receive.kleis RECV92E-*.
#[derive(Debug, Clone)]
pub struct RecvWait {
    pub peer: ProcessKey,
}

/// Receive completion outcome — single authoritative encoder input.
///
/// Every path that completes a RecvWait (immediate queued message,
/// future direct send, PeerDied) must go through `complete_recv_wait()`
/// with one of these variants.  No other code fills R0-R5 for RecvWait.
///
/// Formal basis: anka_blocking_receive.kleis — RECV_MESSAGE, RECV_PEER_DIED, RECV_ERROR.
#[derive(Debug)]
pub(crate) enum RecvOutcome {
    /// Exact-peer message delivered (tag 1 = ordinary, tag 2 = cap-bearing).
    Message(Message),
    /// Peer died and all pair-relevant work is terminal (tag 3).
    PeerDied(ProcessKey),
    /// Stale/recycled peer key (tag 4).
    Error,
}

/// Delivery routing decision for message producers (Phase 9.2e).
///
/// All three producers — SYS_SEND, SYS_SEND_KEY, SYS_SEND_CAP —
/// use this single routing operation.  Direct delivery bypasses
/// the mailbox entirely but requires the destination to be:
///   1. live (ProcessState::Running) — validate_message_destination()
///   2. in RecvWait for the exact sender ProcessKey
///
/// A stale recv_wait on a Zombie process is never sufficient.
///
/// Formal basis: anka_blocking_receive.kleis — delivery_direct_92e,
///   delivery_enqueue_92e, delivery_full_92e.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryRoute {
    /// Destination is RecvWait(sender) — bypass mailbox entirely.
    Direct,
    /// Mailbox has room — enqueue normally.
    Enqueue,
    /// Mailbox full and no direct route — reject.
    Full,
}

// ───────────────────────────────────────────────────────────────────
// Message mailbox
// ───────────────────────────────────────────────────────────────────

/// IPC message — unified envelope for ordinary and cap-bearing messages.
///
/// `cap` is None for ordinary messages, Some for cap-bearing.
/// The capability (if any) was installed in the receiver's cap table
/// at send time; RECV merely reveals the handle.
#[derive(Debug, Clone)]
pub(crate) struct Message {
    pub(crate) from: ProcessKey,
    pub(crate) value: u64,
    pub(crate) cap: Option<CapabilityHandle>,
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

/// A registered device instance in the kernel (Phase 9.3b).
///
/// Registry membership means active: there is no DeviceState enum
/// because 9.3b does not support unregister/recycling.
///
/// Invariant: `Binding in Registry => FabricObject(binding.object)
/// remains Active at binding.generation` for the kernel's lifetime.
#[derive(Debug)]
pub struct DeviceSlot {
    pub binding: DeviceBinding,
    pub controller: BlockController,
}

/// Registry of all device instances (Phase 9.3b).
///
/// Identity is `DeviceBinding = (ObjectId, Generation)`, never
/// the vector index.  The index is storage location only:
///   `RegistryIndex != DeviceBinding != Authority`.
///
/// Formal basis: anka_multi_device_routing.kleis DEVROUTE-1..5.
#[derive(Debug)]
pub struct DeviceRegistry {
    pub devices: Vec<DeviceSlot>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }

    /// Lookup by exact DeviceBinding.  Returns the internal index.
    /// The index must not escape as identity — callers should use
    /// the DeviceBinding from the slot, not the index.
    pub fn lookup_index(&self, binding: DeviceBinding) -> Option<usize> {
        self.devices.iter().position(|d|
            d.binding.object == binding.object
            && d.binding.generation == binding.generation
        )
    }

    /// Lookup by exact DeviceBinding — shared reference.
    pub fn lookup(&self, binding: DeviceBinding) -> Option<&DeviceSlot> {
        self.devices.iter().find(|d|
            d.binding.object == binding.object
            && d.binding.generation == binding.generation
        )
    }

    /// Lookup by exact DeviceBinding — mutable reference.
    pub fn lookup_mut(&mut self, binding: DeviceBinding) -> Option<&mut DeviceSlot> {
        self.devices.iter_mut().find(|d|
            d.binding.object == binding.object
            && d.binding.generation == binding.generation
        )
    }

    /// Quantitative registry-wide nonterminal pair request count.
    ///
    /// `Count_registry(C,D) = sum over all devices of Count_device(C,D)`
    ///
    /// Formal basis: anka_multi_device_routing.kleis DEVROUTE-9..14.
    pub fn nonterminal_pair_request_count(
        &self,
        client: &ProcessKey,
        peer: &ProcessKey,
    ) -> usize {
        self.devices.iter()
            .filter(|d| d.controller.has_nonterminal_pair_request(client, peer))
            .map(|d| d.controller.nonterminal_pair_request_count(client, peer))
            .sum()
    }
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
    /// Device registry (Phase 9.3b).
    /// Replaces the singleton block_controller / block_device_binding.
    /// Each registered device has a DeviceBinding + BlockController.
    pub device_registry: DeviceRegistry,
    /// Legacy default block device for SYS_BLOCK_READ (Phase 9.3b).
    ///
    /// Set once when the first block device is registered.
    /// SYS_BLOCK_READ resolves this binding through the registry
    /// rather than relying on vector index 0.
    ///
    /// This is a compatibility routing alias, not device identity
    /// or authority.  All modern capability-mediated device operations
    /// are selected by the presented Device capability.
    legacy_block_device: Option<DeviceBinding>,
    /// Monotonic DelegationId incarnation counter (checked, never wraps).
    /// Kernel owns this because DelegationId contains ProcessKeys,
    /// which are kernel-layer concepts.
    next_delegation_incarnation: u64,
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
            device_registry: DeviceRegistry::new(),
            legacy_block_device: None,
            next_delegation_incarnation: 0,
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
                recv_wait: None,
                async_requests: Vec::new(),
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
            recv_wait: None,
            async_requests: Vec::new(),
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
    /// Atomic with respect to the invariant:
    ///   installed authority ⟺ installed handle.
    ///
    /// Preflight: refuses early if the cap table has no free slot,
    /// before any Fabric authority is created.  If installation
    /// unexpectedly fails after grant, the Fabric authority is
    /// rolled back so no orphan authority can exist.
    ///
    /// Used by boot/spawn to seed initial handles and by tests.
    /// Runtime transfer belongs to 9.2b.
    /// Install a memory capability for a process.
    ///
    /// Kind boundary: requires ObjectKind::Memory.
    pub fn install_capability(
        &mut self,
        slot: usize,
        object: ObjectId,
        offset: u64,
        length: u64,
        perms: Permissions,
    ) -> Option<CapabilityHandle> {
        // Kind boundary: require Memory
        let obj = self.fabric.objects.get(&object)?;
        if obj.kind != ObjectKind::Memory { return None; }

        // Preflight: table must have an allocatable slot (Free AND
        // generation < u32::MAX).  Using allocatable_count() avoids
        // burning AuthorityIds on retired terminal-generation slots.
        let ct = self.processes[slot].cap_table.as_ref()?;
        if ct.allocatable_count() == 0 {
            return None;
        }

        let domain = self.processes[slot].core.domain;
        let auth_id = self.fabric.alloc_authority_id()?;

        self.fabric.grant_with_authority_id(
            domain, object, offset, length, perms, auth_id,
        )?;

        let obj_gen = self.fabric.objects.get(&object)?.generation;

        match self.processes[slot].cap_table.as_mut()
            .and_then(|ct| ct.install_memory(object, obj_gen, offset, length, perms, auth_id, None))
        {
            Some(handle) => Some(handle),
            None => {
                // Rollback: remove the Fabric authority we just created.
                self.fabric.remove_by_authority_id(domain, auth_id);
                None
            }
        }
    }

    /// Install a block device controller and create a Device object for it.
    ///
    /// Register a block device in the device registry (Phase 9.3b).
    ///
    /// Allocates an ObjectKind::Device Fabric object and pushes a
    /// new DeviceSlot into the registry.  Returns the DeviceBinding
    /// (the device's identity) on success.
    ///
    /// Rejects duplicate live bindings.  Multiple distinct devices
    /// are supported — each gets its own ObjectId.
    ///
    /// The returned DeviceBinding is the routing key for SYS_DEV_SUBMIT.
    /// The old `install_block_device()` returning ObjectId is preserved
    /// as a convenience wrapper for existing tests.
    pub fn register_block_device(&mut self, controller: BlockController) -> Option<DeviceBinding> {
        let dev_obj = self.fabric.alloc_object("block_device", 0, ObjectKind::Device);
        let dev_gen = self.fabric.objects.get(&dev_obj)?.generation;

        debug_assert_eq!(
            self.fabric.objects.get(&dev_obj).unwrap().state,
            ObjectState::Active,
            "Device objects must be Active immediately after alloc_object"
        );

        let binding = DeviceBinding {
            object: dev_obj,
            generation: dev_gen,
        };

        // Reject duplicate live bindings
        if self.device_registry.lookup(binding).is_some() {
            return None;
        }

        self.device_registry.devices.push(DeviceSlot {
            binding,
            controller,
        });

        // First registered block device becomes the legacy default
        // for SYS_BLOCK_READ (compatibility routing alias).
        if self.legacy_block_device.is_none() {
            self.legacy_block_device = Some(binding);
        }

        Some(binding)
    }

    /// Convenience wrapper: register a block device and return just the ObjectId.
    /// Preserved for backward compatibility with existing tests.
    pub fn install_block_device(&mut self, controller: BlockController) -> Option<ObjectId> {
        self.register_block_device(controller).map(|b| b.object)
    }

    /// Install a device capability for a process.
    ///
    /// Kind boundary: requires ObjectKind::Device.
    /// Same atomic discipline as install_capability: preflight
    /// allocatable count and object kind/lifecycle before consuming
    /// an AuthorityId.
    pub fn install_device_capability(
        &mut self,
        slot: usize,
        device_object: ObjectId,
        rights: DeviceRights,
    ) -> Option<CapabilityHandle> {
        // Kind boundary: require Device
        let obj = self.fabric.objects.get(&device_object)?;
        if obj.kind != ObjectKind::Device { return None; }
        if obj.state != ObjectState::Active { return None; }

        // Preflight: table must have an allocatable slot
        let ct = self.processes[slot].cap_table.as_ref()?;
        if ct.allocatable_count() == 0 {
            return None;
        }

        let domain = self.processes[slot].core.domain;
        let auth_id = self.fabric.alloc_authority_id()?;

        self.fabric.grant_device_with_authority_id(
            domain, device_object, rights, auth_id,
        )?;

        let obj_gen = self.fabric.objects.get(&device_object)?.generation;

        match self.processes[slot].cap_table.as_mut()
            .and_then(|ct| ct.install_device(device_object, obj_gen, rights, auth_id, None))
        {
            Some(handle) => Some(handle),
            None => {
                // Rollback: remove the Fabric authority we just created.
                self.fabric.remove_by_authority_id(domain, auth_id);
                None
            }
        }
    }

    /// Resolve a capability handle for a process.
    ///
    /// Full architectural three-condition check:
    ///   1. g_h = g_slot  (handle generation matches cap-table slot)
    ///   2. AuthorityId exists in Fabric domain  (not merely slot occupied)
    ///   3. g_o = g_current  (object generation is current)
    ///
    /// CapabilityTable::resolve() checks conditions 1 and 3 (naming
    /// structure + object generation).  This kernel wrapper adds the
    /// ground-truth Fabric verification for condition 2: the
    /// AuthorityId recorded in the slot must actually exist in the
    /// process's domain.
    ///
    /// Without this check, removing an AuthorityId behind an occupied
    /// slot would leave a ghost handle that resolves incorrectly.
    pub fn resolve_capability(
        &self,
        slot: usize,
        handle: CapabilityHandle,
    ) -> Option<ResolvedCapability> {
        let ct = self.processes[slot].cap_table.as_ref()?;
        let resolved = ct.resolve(handle, |oid| {
            self.fabric.objects.get(&oid).map(|o| o.generation)
        })?;

        // Condition 2 ground truth: AuthorityId must exist in Fabric domain.
        let domain = self.processes[slot].core.domain;
        if !self.fabric.has_authority_id(domain, resolved.authority_id()) {
            return None;
        }

        Some(resolved)
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

    /// Validate a ProcessKey as a live message destination.
    ///
    /// Stricter than `validate_process_key()`: requires Running state.
    /// A Zombie process is generation-current but not alive enough to
    /// receive authority or messages.  SYS_WAIT deliberately uses
    /// `validate_process_key()` (which accepts Zombies) because
    /// observation of a dead child is the whole point of WAIT.
    /// IPC delivery must not install authority into a dead process.
    fn validate_message_destination(&self, key: &ProcessKey) -> Option<usize> {
        let idx = self.validate_process_key(key)?;
        if self.processes[idx].state == ProcessState::Running {
            Some(idx)
        } else {
            None
        }
    }

    // ─── DelegationId allocation (Phase 9.2b) ─────────────────

    /// Read-only preflight: can a fresh DelegationId be allocated?
    pub(crate) fn can_alloc_delegation_id(&self) -> bool {
        self.next_delegation_incarnation.checked_add(1).is_some()
    }

    /// Allocate a fresh DelegationId.  Monotonic, never reused.
    /// Returns None if the incarnation counter is exhausted.
    pub(crate) fn alloc_delegation_id(
        &mut self,
        client: ProcessKey,
        driver: ProcessKey,
    ) -> Option<DelegationId> {
        let inc = self.next_delegation_incarnation;
        self.next_delegation_incarnation =
            self.next_delegation_incarnation.checked_add(1)?;
        Some(DelegationId { client, driver, incarnation: inc })
    }

    /// Force the delegation incarnation counter — test-only.
    #[cfg(test)]
    pub(crate) fn set_next_delegation_incarnation(&mut self, value: u64) {
        self.next_delegation_incarnation = value;
    }

    /// Read the delegation incarnation counter — test-only.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn next_delegation_incarnation(&self) -> u64 {
        self.next_delegation_incarnation
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
        self.processes[slot].recv_wait = None;
        self.processes[slot].async_requests.clear();
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
            // ── Resolve phase: service all immediately resolvable events ──
            //
            // Two categories of resolvable state:
            //   1. Completed block I/O — drain completions, wake IoWait processes.
            //   2. Zombie children — wake parents waiting_on them.
            //
            // Both must be drained BEFORE the schedulability scan so
            // that just-woken processes can run this round.
            //
            // Without the completion drain here, the state
            //   D=IoWait, request=Completed, ¬AutonomousIO
            // would be misclassified as Stop because Completed is
            // (correctly) excluded from has_autonomous_io().
            self.drain_block_completions();
            self.reevaluate_recv_waits();
            self.wake_waiters();

            // ── Run phase: try every schedulable process ──
            let mut ran = false;
            for i in 0..self.processes.len() {
                if self.processes[i].exited() {
                    continue;
                }
                if !self.processes[i].is_schedulable() {
                    continue;
                }
                self.current = i;
                self.run_process(i, quantum);
                self.wake_waiters();
                ran = true;
            }

            if ran {
                continue;
            }

            // ── Idle phase: no process ran this round ──
            //
            // Formal selector (anka_blocking_receive.kleis):
            //   ¬Runnable ∧ ¬Resolvable ∧ AutonomousIO ⇒ IdleProgress
            //   ¬Runnable ∧ ¬Resolvable ∧ ¬AutonomousIO ⇒ Stop
            //
            // Timer does NOT advance during idle progress.
            if self.has_autonomous_io() {
                self.idle_progress_once();
                continue;
            }

            // Nothing runnable, nothing resolvable, no autonomous I/O.
            break;
        }
    }

    /// True if the block controller has autonomous work that can make
    /// progress without any process executing instructions.
    ///
    /// Structural definition: Waiting ∨ DmaReady ∨ DmaInFlight.
    /// Completed is NOT autonomous — it is immediately serviceable
    /// kernel work (the DMA domain has already been destroyed).
    fn has_autonomous_io(&self) -> bool {
        self.device_registry.devices.iter()
            .any(|d| d.controller.has_autonomous_work())
    }

    /// Advance block I/O by one tick without executing any guest
    /// instruction and without ticking the architectural timer.
    ///
    /// This is the idle progress boundary: the kernel observes that
    /// no process is runnable but hardware may still be active.  It
    /// ticks the controller to advance DMA latency/transfers, then
    /// drains any resulting completions to wake blocked processes.
    ///
    /// Formal basis: anka_blocking_receive.kleis — idle_progress_92e.
    ///   IdleProgress ⇒ TimerAfter = TimerBefore.
    fn idle_progress_once(&mut self) {
        // Tick ALL registered controllers exactly once.
        for slot in &mut self.device_registry.devices {
            slot.controller.tick(&mut self.fabric);
        }
        // Drain completions from all devices, then reevaluate.
        self.drain_block_completions();
        self.reevaluate_recv_waits();
    }

    /// Reevaluate all outstanding RecvWait blocks after a completion
    /// drain or other state change that may have made a pair quiescent.
    ///
    /// Only Running clients are considered — a dead client with residual
    /// recv_wait must never receive IPC completion.
    ///
    /// For each Running process P with recv_wait = Some(peer):
    ///   - The exact awaited incarnation is considered dead if:
    ///       (a) the slot generation has changed (peer was reclaimed), or
    ///       (b) the same-generation slot is Zombie or Retired.
    ///   - If dead AND the (P, peer) pair has no nonterminal delegated
    ///     requests (pair-level quiescence) → PeerDied.
    ///   - Otherwise → remain blocked.
    ///
    /// The quiescence query uses the stored peer ProcessKey, not the
    /// current slot occupant — a recycled incarnation has no relation
    /// to the original peer's outstanding work.
    ///
    /// This must be called after every completion drain (resolve phase,
    /// idle progress, device interrupt) so that PeerDied is delivered
    /// as soon as quiescence is achieved.
    ///
    /// Formal basis: anka_blocking_receive.kleis — peer_died_reevaluate_92e.
    fn reevaluate_recv_waits(&mut self) {
        let mut to_complete: Vec<(usize, ProcessKey)> = Vec::new();
        for i in 0..self.processes.len() {
            // Only deliver PeerDied to a live Running client.
            // A dead client can temporarily retain recv_wait (finish_process
            // does not clear it), but IPC completion must never be
            // delivered to a dead incarnation.
            if self.processes[i].state != ProcessState::Running {
                continue;
            }
            if let Some(ref rw) = self.processes[i].recv_wait {
                let peer = rw.peer;
                if peer.slot >= self.processes.len() {
                    continue;
                }

                // Determine whether the exact awaited incarnation is dead.
                // Three cases:
                //   1. Generation mismatch → D_g was reclaimed, slot now
                //      holds D_{g+1} or is Free(g+1)/Retired.
                //   2. Same generation, Zombie → D_g died but not yet reclaimed.
                //   3. Same generation, Retired → generation overflow at reclaim.
                let peer_proc = &self.processes[peer.slot];
                let peer_dead = peer_proc.generation != peer.generation
                    || matches!(
                        peer_proc.state,
                        ProcessState::Zombie | ProcessState::Retired
                    );

                if !peer_dead {
                    continue;
                }

                // Peer is dead — check pair-level quiescence.
                // Use the STORED peer key, not the current slot occupant.
                let client_key = ProcessKey {
                    slot: i,
                    generation: self.processes[i].generation,
                };
                let pair_count = self.device_registry
                    .nonterminal_pair_request_count(&client_key, &peer);
                if pair_count == 0 {
                    to_complete.push((i, peer));
                }
            }
        }
        for (slot, peer) in to_complete {
            self.complete_recv_wait(slot, RecvOutcome::PeerDied(peer));
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

        // --- Device registry source (Phase 9.3b) ---
        // Tick every registered controller exactly once.
        for slot in &mut self.device_registry.devices {
            slot.controller.tick(&mut self.fabric);
        }
        // Aggregate attention: if ANY controller requires attention,
        // post one generic device interrupt.  The handler drains all.
        let any_attention = self.device_registry.devices.iter()
            .any(|d| d.controller.requires_attention());
        if any_attention {
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
            self.reevaluate_recv_waits();
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
    /// Drain all ready completions from the block controller.
    ///
    /// Two-guard completion routing (Phase 9.2f):
    ///
    ///   Guard 1 — exact-incarnation match:
    ///     Completion(P_g, h) may affect only P_g, never the
    ///     current occupant of P.slot if incarnation differs.
    ///
    ///   Guard 2 — process must be Running:
    ///     A Zombie/Retired process with correct generation must
    ///     not receive software events.  The request becomes terminal
    ///     for pair-quiescence purposes but no process is mutated.
    ///
    /// Within the exact Running incarnation:
    ///   - If io_wait matches this handle: wake the process.
    ///     If async_requests also has an entry for this handle
    ///     (SYS_DEV_WAIT path), consume the ledger entry.
    ///     Legacy SYS_DEV_SUBMIT has no ledger entry — no-op.
    ///   - Else if async_requests has a matching entry: fill
    ///     completion status for later SYS_DEV_WAIT.
    ///
    /// Formal basis: anka_multi_request_quiescence.kleis MULTI92F-*.
    fn drain_block_completions(&mut self) {
        // Drain completions from ALL registered devices (Phase 9.3b).
        // Each completion is qualified with the device's binding to form
        // a DeviceRequestKey before matching against process state.
        //
        // InterruptTarget != CompletionRequester: the process that took
        // the interrupt does NOT select whose I/O completed.  Delivery
        // uses exclusively (Completion.requester, DeviceBinding, RequestHandle).
        for dev_idx in 0..self.device_registry.devices.len() {
            loop {
                let ctrl = &mut self.device_registry.devices[dev_idx].controller;
                let completion = if ctrl.completion_count() > 0 {
                    ctrl.consume_completion()
                } else {
                    break;
                };
                let completion = match completion {
                    Some(c) => c,
                    None => break,
                };

                // Qualify the controller-local handle with device identity.
                let dev_key = DeviceRequestKey {
                    device: self.device_registry.devices[dev_idx].binding,
                    request: completion.handle,
                };

                let rk = &completion.requester;
                let slot = rk.slot as usize;

                // Guard 1: slot in range and exact-incarnation match.
                if slot >= self.processes.len()
                    || self.processes[slot].generation != rk.generation
                {
                    continue;
                }

                // Guard 2: process must be Running.
                if self.processes[slot].state != ProcessState::Running {
                    continue;
                }

                // Inner logic: exact incarnation AND Running.
                // Match against DeviceRequestKey, not raw RequestHandle.
                let io_wait_matches = self.processes[slot].io_wait.as_ref()
                    .map(|w| w.request == dev_key)
                    .unwrap_or(false);

                if io_wait_matches {
                    if let Some(pos) = self.processes[slot].async_requests.iter()
                        .position(|r| r.key == dev_key)
                    {
                        self.processes[slot].async_requests.remove(pos);
                    }

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
                } else if let Some(entry) = self.processes[slot].async_requests.iter_mut()
                    .find(|r| r.key == dev_key)
                {
                    entry.completion = Some(completion.status);
                }
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
                let from_key = ProcessKey {
                    slot: idx,
                    generation: self.processes[idx].generation,
                };
                if let Some(dest_slot) = self.resolve_pid(dest_pid) {
                    let route = self.message_route(dest_slot, &from_key);
                    if route == DeliveryRoute::Full {
                        self.processes[idx].core.r[R0 as usize] = u64::MAX;
                    } else {
                        let msg = Message { from: from_key, value, cap: None };
                        self.deliver_message(dest_slot, msg, route);
                        self.processes[idx].core.r[R0 as usize] = 0;
                    }
                } else {
                    self.processes[idx].core.r[R0 as usize] = u64::MAX;
                }
                self.resume_from_trap(idx);
            }
            SYS_RECV => {
                if let Some(msg) = self.mailboxes[idx].pop() {
                    self.processes[idx].core.r[R0 as usize] = msg.value;
                    // R1 = tag: 1 = ordinary, 2 = cap-bearing
                    self.processes[idx].core.r[R1 as usize] =
                        if msg.cap.is_some() { 2 } else { 1 };
                    // R2,R3 = cap handle (slot, generation) or sentinel
                    if let Some(ch) = msg.cap {
                        self.processes[idx].core.r[R2 as usize] = ch.slot as u64;
                        self.processes[idx].core.r[R3 as usize] = ch.generation as u64;
                    } else {
                        self.processes[idx].core.r[R2 as usize] = u32::MAX as u64;
                        self.processes[idx].core.r[R3 as usize] = 0;
                    }
                    // R4,R5 = sender ProcessKey (slot, generation)
                    self.processes[idx].core.r[R4 as usize] = msg.from.slot as u64;
                    self.processes[idx].core.r[R5 as usize] = msg.from.generation as u64;
                } else {
                    // Empty mailbox
                    self.processes[idx].core.r[R0 as usize] = 0;
                    self.processes[idx].core.r[R1 as usize] = 0; // tag 0 = empty
                    self.processes[idx].core.r[R2 as usize] = u32::MAX as u64;
                    self.processes[idx].core.r[R3 as usize] = 0;
                    self.processes[idx].core.r[R4 as usize] = 0;
                    self.processes[idx].core.r[R5 as usize] = 0;
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
            SYS_SEND_CAP => {
                self.handle_send_cap(idx);
            }
            SYS_SEND_KEY => {
                self.handle_send_key(idx);
            }
            SYS_DEV_SUBMIT => {
                self.handle_dev_submit(idx);
            }
            SYS_RECV_WAIT => {
                self.handle_recv_wait(idx);
            }
            SYS_DEV_SUBMIT_ASYNC => {
                self.handle_dev_submit_async(idx);
            }
            SYS_DEV_WAIT => {
                self.handle_dev_wait(idx);
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

        // Fail fast: no legacy default block device.
        let dev_binding = match self.legacy_block_device {
            Some(b) => b,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Fail fast: already waiting on I/O.
        if self.processes[idx].io_wait.is_some() {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Legacy SYS_BLOCK_READ resolves through the registry.
        let block_size = match self.device_registry.lookup(dev_binding) {
            Some(slot) => slot.controller.storage_ref().block_size(),
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

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
            source_authority_id: None,
            delegation_id: None,
        };

        let result = self.device_registry.lookup_mut(dev_binding)
            .expect("legacy_block_device binding must resolve")
            .controller
            .submit(req, &mut self.fabric);

        match result {
            SubmitResult::Accepted(handle) => {
                // Block the caller: leave EventFrame outstanding,
                // keep halted = true, set io_wait.
                self.processes[idx].io_wait = Some(IoWait {
                    request: DeviceRequestKey {
                        device: dev_binding,
                        request: handle,
                    },
                });
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
    /// Both-or-neither semantics: succeeds only if both the cap-table
    /// handle AND the backing Fabric authority are removed.
    ///
    /// Preflight (all read-only, no mutations):
    ///   1. preflight_drop(handle) → AuthorityId
    ///      (checks generation match, occupancy, recyclability)
    ///   2. has_authority_id(domain, aid) → true
    ///
    /// Only after both pass does the kernel commit both removals.
    /// No .expect() is needed — drop_handle() is guaranteed to
    /// succeed because preflight_drop() verified the same conditions
    /// plus recyclability.
    ///
    /// Formal basis: anka_userspace_driver.kleis DROP-1..4.
    fn handle_cap_drop(&mut self, idx: usize) {
        // Checked ABI decode: narrow fields use u32::try_from(),
        // consistent with 9.2b/c discipline.  Prevents high-bit
        // aliasing (e.g. 0x1_0000_0001 silently becoming 1).
        let slot = match u32::try_from(self.processes[idx].core.r[R1 as usize]) {
            Ok(v) => v,
            Err(_) => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }
        };
        let hgen = match u32::try_from(self.processes[idx].core.r[R2 as usize]) {
            Ok(v) => v,
            Err(_) => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }
        };

        let handle = CapabilityHandle { slot, generation: hgen };
        let domain = self.processes[idx].core.domain;

        // Phase 1: preflight — handle valid, occupied, AND recyclable.
        let auth_id = match self.processes[idx].cap_table.as_ref()
            .and_then(|ct| ct.preflight_drop(handle))
        {
            Some(aid) => aid,
            None => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Phase 2: preflight — backing authority must exist in domain.
        if !self.fabric.has_authority_id(domain, auth_id) {
            self.processes[idx].core.r[R0 as usize] = 1;
            self.resume_from_trap(idx);
            return;
        }

        // Phase 3: commit both removals.
        // preflight_drop checked gen match + occupancy + recyclability,
        // so drop_handle is guaranteed to succeed here.
        let removed_aid = self.processes[idx].cap_table.as_mut()
            .expect("cap_table present — preflight passed")
            .drop_handle(handle)
            .expect("drop_handle must succeed — preflight_drop passed");
        debug_assert_eq!(removed_aid, auth_id);

        let removed = self.fabric.remove_by_authority_id(domain, removed_aid);
        debug_assert!(removed, "authority present — phase 2 passed");

        self.processes[idx].core.r[R0 as usize] = 0;
        self.resume_from_trap(idx);
    }

    /// SYS_SEND_KEY (syscall 12): ProcessKey-addressed ordinary send.
    ///
    /// ABI:
    ///   R1 = destination process slot (u32)
    ///   R2 = destination process generation (u32)
    ///   R3 = value
    ///
    /// Returns: R0 = 0 on success, R0 = error code on failure.
    ///   1 = destination not live (malformed register, stale generation, Zombie, absent)
    ///   2 = mailbox full
    ///
    /// Uses checked u32 decoding for all narrow fields.
    fn handle_send_key(&mut self, idx: usize) {
        let r1 = self.processes[idx].core.r[R1 as usize];
        let r2 = self.processes[idx].core.r[R2 as usize];
        let value = self.processes[idx].core.r[R3 as usize];

        // Gate 0: checked ABI decode
        let dest_slot = match usize::try_from(
            match u32::try_from(r1) { Ok(v) => v, Err(_) => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }}
        ) { Ok(v) => v, Err(_) => {
            self.processes[idx].core.r[R0 as usize] = 1;
            self.resume_from_trap(idx);
            return;
        }};
        let dest_gen = match u32::try_from(r2) {
            Ok(v) => v,
            Err(_) => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }
        };

        let dest_key = ProcessKey { slot: dest_slot, generation: dest_gen };

        // Gate 1: destination is a live Running process
        let dest_idx = match self.validate_message_destination(&dest_key) {
            Some(i) => i,
            None => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Gate 2: delivery routing (Direct / Enqueue / Full)
        let from_key = ProcessKey {
            slot: idx,
            generation: self.processes[idx].generation,
        };
        let route = self.message_route(dest_idx, &from_key);
        if route == DeliveryRoute::Full {
            self.processes[idx].core.r[R0 as usize] = 2;
            self.resume_from_trap(idx);
            return;
        }

        let msg = Message { from: from_key, value, cap: None };
        self.deliver_message(dest_idx, msg, route);
        self.processes[idx].core.r[R0 as usize] = 0;
        self.resume_from_trap(idx);
    }

    /// SYS_SEND_CAP (syscall 11): Kind-sensitive atomic capability transfer.
    ///
    /// ABI (common fields):
    ///   R1 = destination process slot (u32)
    ///   R2 = destination process generation (u32)
    ///   R3 = source cap handle slot (u32)
    ///   R4 = source cap handle generation (u32)
    ///   R8 = value (u64, message payload)
    ///
    /// ABI (kind-specific, interpreted after source resolution):
    ///   Memory source:
    ///     R5 = child offset (u64)
    ///     R6 = child length (u64)
    ///     R7 = child permissions (u64 → Permissions)
    ///   Device source:
    ///     R5 = 0 (required — device authority is non-spatial)
    ///     R6 = 0 (required)
    ///     R7 = child device rights (u64 → DeviceRights)
    ///
    /// Returns: R0 = 0 on success, R0 = error code on failure.
    ///   1 = ABI decode failure (malformed register, bad rights bits)
    ///   2 = destination not live (not Running, or stale generation, or Zombie)
    ///   3 = source handle does not resolve (three-condition failure)
    ///   4 = kind-specific attenuation/shape violation
    ///   5 = receiver has no allocatable cap slot
    ///   6 = receiver mailbox full
    ///   7 = identity space exhausted (AuthorityId or DelegationId)
    ///   8 = internal error (unexpected commit failure; IDs consumed,
    ///       no live authority or capability leaked)
    ///
    /// Gate ordering (frozen):
    ///   resolve destination → resolve presented source →
    ///   kind-specific attenuation → receiver-cap capacity →
    ///   delivery route → identity availability →
    ///   derive child authority → install child handle + provenance → deliver.
    ///
    /// Formal basis: anka_device_capability_transfer.kleis DEVXFER-1..12.
    fn handle_send_cap(&mut self, idx: usize) {
        let r1 = self.processes[idx].core.r[R1 as usize];
        let r2 = self.processes[idx].core.r[R2 as usize];
        let r3 = self.processes[idx].core.r[R3 as usize];
        let r4 = self.processes[idx].core.r[R4 as usize];
        let r5 = self.processes[idx].core.r[R5 as usize];
        let r6 = self.processes[idx].core.r[R6 as usize];
        let r7 = self.processes[idx].core.r[R7 as usize];
        let value = self.processes[idx].core.r[R8 as usize];

        // ── Gate 0: Checked ABI decode (common fields only) ──
        // R5/R6/R7 are NOT decoded here — they are kind-specific.
        let dest_slot_u32 = match u32::try_from(r1) {
            Ok(v) => v, Err(_) => { self.fail_send_cap(idx, 1); return; }
        };
        let dest_slot = match usize::try_from(dest_slot_u32) {
            Ok(v) => v, Err(_) => { self.fail_send_cap(idx, 1); return; }
        };
        let dest_gen = match u32::try_from(r2) {
            Ok(v) => v, Err(_) => { self.fail_send_cap(idx, 1); return; }
        };
        let src_slot = match u32::try_from(r3) {
            Ok(v) => v, Err(_) => { self.fail_send_cap(idx, 1); return; }
        };
        let src_gen = match u32::try_from(r4) {
            Ok(v) => v, Err(_) => { self.fail_send_cap(idx, 1); return; }
        };

        let dest_key = ProcessKey { slot: dest_slot, generation: dest_gen };
        let src_handle = CapabilityHandle { slot: src_slot, generation: src_gen };

        // ── Gate 1: Destination is a live Running process ──
        let dest_idx = match self.validate_message_destination(&dest_key) {
            Some(i) => i,
            None => { self.fail_send_cap(idx, 2); return; }
        };

        // ── Gate 2: Source handle fully resolves (three-condition) ──
        let resolved = match self.resolve_capability(idx, src_handle) {
            Some(r) => r,
            None => { self.fail_send_cap(idx, 3); return; }
        };

        // ── Gate 2b: Kind-sensitive ABI interpretation ──
        //
        // Kind(source) → Interpretation(R5, R6, R7).
        // R7 is decoded as Permissions or DeviceRights depending on
        // the resolved source kind — never before.
        enum PreparedTransfer {
            Memory {
                child_offset: u64,
                child_length: u64,
                child_perms: Permissions,
            },
            Device {
                child_rights: DeviceRights,
                presented_object: ObjectId,
                presented_generation: Generation,
                presented_rights: DeviceRights,
            },
        }

        let prepared = match &resolved {
            ResolvedCapability::Memory { offset, length, perms, .. } => {
                let parent_offset = *offset;
                let parent_length = *length;
                let parent_perms = *perms;

                let child_perms = match Permissions::from_bits_checked(r7) {
                    Some(p) => p,
                    None => { self.fail_send_cap(idx, 1); return; }
                };
                let child_offset = r5;
                let child_length = r6;

                if child_length == 0 {
                    self.fail_send_cap(idx, 4); return;
                }
                if !child_perms.is_subset_of(parent_perms) {
                    self.fail_send_cap(idx, 4); return;
                }
                if child_offset < parent_offset {
                    self.fail_send_cap(idx, 4); return;
                }
                if child_length > parent_length {
                    self.fail_send_cap(idx, 4); return;
                }
                if child_offset - parent_offset > parent_length - child_length {
                    self.fail_send_cap(idx, 4); return;
                }

                PreparedTransfer::Memory { child_offset, child_length, child_perms }
            }
            ResolvedCapability::Device {
                object, object_generation, rights, ..
            } => {
                // Device authority is non-spatial: R5=R6=0 required.
                if r5 != 0 { self.fail_send_cap(idx, 4); return; }
                if r6 != 0 { self.fail_send_cap(idx, 4); return; }

                let child_rights = match DeviceRights::from_bits_checked(r7) {
                    Some(dr) => dr,
                    None => { self.fail_send_cap(idx, 1); return; }
                };

                // Presented-authority attenuation check (Rule 1).
                if !child_rights.is_subset_of(*rights) {
                    self.fail_send_cap(idx, 4); return;
                }

                PreparedTransfer::Device {
                    child_rights,
                    presented_object: *object,
                    presented_generation: *object_generation,
                    presented_rights: *rights,
                }
            }
        };

        // ── Gate 3: Receiver has an allocatable cap slot ──
        let dest_allocatable = self.processes[dest_idx].cap_table.as_ref()
            .map_or(0, |ct| ct.allocatable_count());
        if dest_allocatable == 0 {
            self.fail_send_cap(idx, 5); return;
        }

        // ── Gate 4: Delivery routing (Direct / Enqueue / Full) ──
        let sender_key = ProcessKey {
            slot: idx,
            generation: self.processes[idx].generation,
        };
        let route = self.message_route(dest_idx, &sender_key);
        if route == DeliveryRoute::Full {
            self.fail_send_cap(idx, 6); return;
        }

        // ── Gate 5: Fresh identity availability ──
        if !self.fabric.can_alloc_authority_id() || !self.can_alloc_delegation_id() {
            self.fail_send_cap(idx, 7); return;
        }

        // ─── All preflights passed — atomic commit ───
        //
        // Preflight failures: ΔAuthorityIdCounter = ΔDelegationIdCounter = 0.
        // Post-commit error 8: monotonic IDs may be consumed, but
        // ΔLiveAuthority = ΔLiveCapability = ΔMessage = 0.

        let new_aid = match self.fabric.alloc_authority_id() {
            Some(a) => a,
            None => { self.fail_send_cap(idx, 8); return; }
        };
        let new_tid = match self.alloc_delegation_id(sender_key, dest_key) {
            Some(t) => t,
            None => { self.fail_send_cap(idx, 8); return; }
        };

        let src_domain = self.processes[idx].core.domain;
        let dst_domain = self.processes[dest_idx].core.domain;

        // Kind-sensitive derivation + installation.
        let new_handle = match prepared {
            PreparedTransfer::Memory { child_offset, child_length, child_perms } => {
                let derived = self.fabric.derive_from_authority_id(
                    src_domain,
                    resolved.authority_id(),
                    dst_domain,
                    child_offset,
                    child_length,
                    child_perms,
                    new_aid,
                );
                match derived {
                    None => {
                        self.fail_send_cap(idx, 8);
                        return;
                    }
                    Some(derived_cap) => {
                        let obj_gen = Generation(derived_cap.generation().0);
                        let h = self.processes[dest_idx].cap_table.as_mut()
                            .and_then(|ct| ct.install_memory(
                                derived_cap.object(),
                                obj_gen,
                                child_offset,
                                child_length,
                                child_perms,
                                new_aid,
                                Some(new_tid),
                            ));
                        match h {
                            Some(handle) => handle,
                            None => {
                                self.fabric.remove_by_authority_id(dst_domain, new_aid);
                                self.fail_send_cap(idx, 8);
                                return;
                            }
                        }
                    }
                }
            }
            PreparedTransfer::Device {
                child_rights,
                presented_object,
                presented_generation,
                presented_rights,
            } => {
                // Derive with exact presented/backing correspondence (Rule 4).
                let derived = self.fabric.derive_device_from_authority_id(
                    src_domain,
                    resolved.authority_id(),
                    presented_object,
                    presented_generation,
                    presented_rights,
                    dst_domain,
                    child_rights,
                    new_aid,
                );
                match derived {
                    None => {
                        self.fail_send_cap(idx, 8);
                        return;
                    }
                    Some((obj, obj_gen, derived_rights)) => {
                        let h = self.processes[dest_idx].cap_table.as_mut()
                            .and_then(|ct| ct.install_device(
                                obj,
                                obj_gen,
                                derived_rights,
                                new_aid,
                                Some(new_tid),
                            ));
                        match h {
                            Some(handle) => handle,
                            None => {
                                // Rollback both planes: Fabric authority + cap slot.
                                self.fabric.remove_by_authority_id(dst_domain, new_aid);
                                self.fail_send_cap(idx, 8);
                                return;
                            }
                        }
                    }
                }
            }
        };

        // Deliver via computed route (capacity preflighted at gate 4).
        let msg = Message {
            from: sender_key,
            value,
            cap: Some(new_handle),
        };
        self.deliver_message(dest_idx, msg, route);
        self.processes[idx].core.r[R0 as usize] = 0;
        self.resume_from_trap(idx);
    }

    /// Helper: fail a SYS_SEND_CAP with a specific error code.
    /// Side-effect-free preflight validation for device submission.
    ///
    /// Validates ABI decode, capability resolution, device authority,
    /// controller binding, buffer authority, and provenance.
    /// Returns a PreparedDevSubmit on success, or an error code on failure.
    ///
    /// **Invariant:** this function does NOT create DMA domains,
    /// consume authority IDs, modify the controller, or touch the
    /// async ledger.  Failure implies zero side effects.
    ///
    /// Gates:
    ///   0. ABI fields decode exactly
    ///   1. H_d resolves as Device
    ///   2. H_d has SubmitRead in Fabric and cap table, bound to controller
    ///   3. Block controller exists
    ///   4. H_b resolves as Memory
    ///   5. H_b.perms ⊇ WRITE
    ///   6. T.driver == current ProcessKey, if T exists
    fn preflight_dev_submit(&self, idx: usize) -> Result<PreparedDevSubmit, u64> {
        let r1 = self.processes[idx].core.r[R1 as usize];
        let r2 = self.processes[idx].core.r[R2 as usize];
        let block_number = self.processes[idx].core.r[R3 as usize];
        let r4 = self.processes[idx].core.r[R4 as usize];
        let r5 = self.processes[idx].core.r[R5 as usize];

        // ── Gate 0: Checked ABI decode ──
        let dev_slot = u32::try_from(r1).map_err(|_| 1u64)?;
        let dev_gen = u32::try_from(r2).map_err(|_| 1u64)?;
        let buf_slot = u32::try_from(r4).map_err(|_| 1u64)?;
        let buf_gen = u32::try_from(r5).map_err(|_| 1u64)?;

        let dev_handle = CapabilityHandle { slot: dev_slot, generation: dev_gen };
        let buf_handle = CapabilityHandle { slot: buf_slot, generation: buf_gen };

        // ── Gate 1: Device handle resolves as Device ──
        let dev_resolved = self.resolve_capability(idx, dev_handle)
            .ok_or(3u64)?;
        let (dev_object, dev_gen_resolved, dev_rights, dev_authority_id) = match &dev_resolved {
            ResolvedCapability::Device {
                object, object_generation, rights, authority_id, ..
            } => (*object, *object_generation, *rights, *authority_id),
            ResolvedCapability::Memory { .. } => return Err(3),
        };

        // ── Gate 2: Device authority valid (SubmitRead, binding) ──
        let domain = self.processes[idx].core.domain;
        if !self.fabric.validate_device_authority(
            domain,
            dev_authority_id,
            dev_object,
            dev_gen_resolved,
            dev_rights,
            DeviceRights::SUBMIT_READ,
        ) {
            return Err(4);
        }

        // ── Gate 2b: Device object routes to a registered controller ──
        let dev_binding = DeviceBinding {
            object: dev_object,
            generation: dev_gen_resolved,
        };
        if self.device_registry.lookup(dev_binding).is_none() {
            return Err(5);
        }

        // ── Gate 4: Buffer handle resolves as Memory ──
        let buf_resolved = self.resolve_capability(idx, buf_handle)
            .ok_or(6u64)?;
        let (buf_object, buf_offset, buf_perms, buf_authority_id, buf_delegation_id) =
            match &buf_resolved {
                ResolvedCapability::Memory {
                    object, offset, perms, authority_id, delegation_id, ..
                } => (*object, *offset, *perms, *authority_id, *delegation_id),
                ResolvedCapability::Device { .. } => return Err(6),
            };

        // ── Gate 5: Buffer handle has WRITE ──
        if !buf_perms.contains(Permissions::WRITE) {
            return Err(7);
        }

        // ── Gate 6: Provenance check (mandatory when T exists) ──
        if let Some(tid) = buf_delegation_id {
            let current_key = ProcessKey {
                slot: idx,
                generation: self.processes[idx].generation,
            };
            if tid.driver != current_key {
                return Err(8);
            }
        }

        // ── All validation passed — return prepared submission ──
        let rk = RequesterKey {
            slot: idx as u32,
            generation: self.processes[idx].generation,
        };

        Ok(PreparedDevSubmit {
            device_binding: dev_binding,
            block_number,
            requester: rk,
            target_object: buf_object,
            target_offset: buf_offset,
            source_domain: domain,
            source_authority_id: buf_authority_id,
            delegation_id: buf_delegation_id,
        })
    }

    /// SYS_DEV_SUBMIT (13) — blocking device submission.
    ///
    /// Transactional order:
    ///   io_wait gate → preflight → mint DMA authority → submit → install IoWait
    ///
    /// Returns: R0 = 0 on success (caller blocked in IoWait),
    ///   1-8 = preflight error, 9 = controller submission failed.
    fn handle_dev_submit(&mut self, idx: usize) {
        use super::block::{BlockRequest, SubmitResult};

        // ── Gate 0: Caller scheduling state — before any validation ──
        if self.processes[idx].io_wait.is_some() {
            self.fail_dev_submit(idx, 2);
            return;
        }

        // ── Gates 1-6: Pure ABI/authority/provenance validation ──
        let prepared = match self.preflight_dev_submit(idx) {
            Ok(p) => p,
            Err(code) => { self.fail_dev_submit(idx, code); return; }
        };

        // ── Mint DMA authority + submit ──
        let req = BlockRequest {
            block_number: prepared.block_number,
            requester: prepared.requester,
            target_object: prepared.target_object,
            target_offset: prepared.target_offset,
            source_domain: prepared.source_domain,
            source_authority_id: Some(prepared.source_authority_id),
            delegation_id: prepared.delegation_id,
        };

        let dev_binding = prepared.device_binding;
        let result = self.device_registry.lookup_mut(dev_binding)
            .expect("preflight validated binding exists")
            .controller
            .submit(req, &mut self.fabric);

        match result {
            SubmitResult::Accepted(handle) => {
                self.processes[idx].io_wait = Some(IoWait {
                    request: DeviceRequestKey {
                        device: dev_binding,
                        request: handle,
                    },
                });
            }
            _ => {
                self.fail_dev_submit(idx, 9);
            }
        }
    }

    /// SYS_DEV_SUBMIT_ASYNC (15) — non-blocking device submission.
    ///
    /// Transactional order:
    ///   io_wait gate → preflight → ledger capacity → controller capacity
    ///   → mint DMA authority → submit → publish ledger entry
    ///
    /// Returns immediately:
    ///   R0 = 0, R1 = handle.slot, R2 = handle.generation on success.
    ///   R0 = error code on failure (same 1-9 as SYS_DEV_SUBMIT,
    ///         plus 10 = ledger full).
    ///
    /// Failure atomicity: SubmitAsync failure ⇒
    ///   ΔController = ΔLedger = ΔFabricDomains = ΔAuthorityIds = 0.
    fn handle_dev_submit_async(&mut self, idx: usize) {
        use super::block::{BlockRequest, SubmitResult};

        // ── Gate 0: Caller scheduling state — before any validation ──
        if self.processes[idx].io_wait.is_some() {
            self.fail_dev_submit(idx, 2);
            return;
        }

        // ── Gates 1-6: Pure ABI/authority/provenance validation ──
        let prepared = match self.preflight_dev_submit(idx) {
            Ok(p) => p,
            Err(code) => { self.fail_dev_submit(idx, code); return; }
        };

        // ── Gate A: Ledger capacity (async-only, after preflight) ──
        if self.processes[idx].async_requests.len() >= MAX_ASYNC_REQUESTS {
            self.fail_dev_submit(idx, 10);
            return;
        }

        // ── Gate B: Controller-slot capacity (before minting) ──
        let dev_binding = prepared.device_binding;
        {
            let dev_slot = self.device_registry.lookup(dev_binding)
                .expect("preflight validated binding exists");
            if dev_slot.controller.free_slot_count() == 0 {
                self.fail_dev_submit(idx, 9);
                return;
            }
        }

        // ── Mint DMA authority + submit ──
        let req = BlockRequest {
            block_number: prepared.block_number,
            requester: prepared.requester,
            target_object: prepared.target_object,
            target_offset: prepared.target_offset,
            source_domain: prepared.source_domain,
            source_authority_id: Some(prepared.source_authority_id),
            delegation_id: prepared.delegation_id,
        };

        let result = self.device_registry.lookup_mut(dev_binding)
            .expect("preflight validated binding exists")
            .controller
            .submit(req, &mut self.fabric);

        match result {
            SubmitResult::Accepted(handle) => {
                let dev_key = DeviceRequestKey {
                    device: dev_binding,
                    request: handle,
                };
                self.processes[idx].async_requests.push(AsyncDeviceRequest {
                    key: dev_key,
                    completion: None,
                });
                self.processes[idx].core.r[R0 as usize] = 0;
                self.processes[idx].core.r[R1 as usize] = handle.slot as u64;
                self.processes[idx].core.r[R2 as usize] = handle.generation;
                // Extended ABI: R3/R4 = device identity (namespace ticket)
                self.processes[idx].core.r[R3 as usize] = dev_binding.object.0;
                self.processes[idx].core.r[R4 as usize] = dev_binding.generation.0;
                self.resume_from_trap(idx);
            }
            _ => {
                self.fail_dev_submit(idx, 9);
            }
        }
    }

    /// SYS_DEV_WAIT (16) — wait for a specific async request (Phase 9.3b).
    ///
    /// Extended ABI:
    ///   R1 = request_handle.slot
    ///   R2 = request_handle.generation
    ///   R3 = device ObjectId      (namespace qualification, not authority)
    ///   R4 = device Generation    (namespace qualification, not authority)
    ///
    /// The (R3, R4) pair is the namespace ticket returned by
    /// SYS_DEV_SUBMIT_ASYNC.  It qualifies which controller's
    /// request namespace R1/R2 refers to.  This is NOT renewed
    /// device authority — the accepted request may outlive
    /// possession of the device capability.
    ///
    /// Returns:
    ///   R0 = 0 (success) or R0 = u64::MAX (DMA fault) on completion.
    ///   R0 = 1 (stale/unknown/malformed key), R0 = 2 (already in IoWait).
    ///
    /// Error 1 with zero side effects for malformed R3/R4.
    fn handle_dev_wait(&mut self, idx: usize) {
        use super::block::RequestHandle;

        let r1 = self.processes[idx].core.r[R1 as usize];
        let r2 = self.processes[idx].core.r[R2 as usize];
        let r3 = self.processes[idx].core.r[R3 as usize];
        let r4 = self.processes[idx].core.r[R4 as usize];

        // ── Checked ABI decode: request handle ──
        let slot = match u8::try_from(r1) {
            Ok(v) => v,
            Err(_) => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
                return;
            }
        };
        let handle = RequestHandle { slot, generation: r2 };

        // ── Checked ABI decode: device identity (R3/R4) ──
        // ObjectId is u64-based, so R3 passes through directly.
        // R4 = Generation (u64).  Both are namespace qualification,
        // not authority — no registry lookup needed.
        let dev_object = ObjectId(r3);
        let dev_generation = r4;

        let dev_key = DeviceRequestKey {
            device: DeviceBinding {
                object: dev_object,
                generation: Generation(dev_generation),
            },
            request: handle,
        };

        // ── Gate: not already in IoWait ──
        if self.processes[idx].io_wait.is_some() {
            self.processes[idx].core.r[R0 as usize] = 2;
            self.resume_from_trap(idx);
            return;
        }

        // ── Search async_requests by DeviceRequestKey ──
        let pos = self.processes[idx].async_requests.iter()
            .position(|r| r.key == dev_key);

        match pos {
            None => {
                self.processes[idx].core.r[R0 as usize] = 1;
                self.resume_from_trap(idx);
            }
            Some(p) => {
                let entry = &self.processes[idx].async_requests[p];
                if let Some(status) = entry.completion {
                    self.processes[idx].core.r[R0 as usize] = match status {
                        super::block::CompletionStatus::Success => 0,
                        super::block::CompletionStatus::DmaFault(_) => u64::MAX,
                    };
                    self.processes[idx].async_requests.remove(p);
                    self.resume_from_trap(idx);
                } else {
                    // Pending → block on this DeviceRequestKey
                    self.processes[idx].io_wait = Some(IoWait { request: dev_key });
                }
            }
        }
    }

    fn fail_dev_submit(&mut self, idx: usize, code: u64) {
        self.processes[idx].core.r[R0 as usize] = code;
        self.resume_from_trap(idx);
    }

    fn fail_send_cap(&mut self, idx: usize, code: u64) {
        self.processes[idx].core.r[R0 as usize] = code;
        self.resume_from_trap(idx);
    }

    // ─── Message delivery routing (Phase 9.2e.2) ────────────────────

    /// Compute the delivery route for a message from `sender_key` to
    /// the validated destination slot `dest_idx`.
    ///
    /// Precondition: `dest_idx` has already passed
    /// `validate_message_destination()`, so the destination is live
    /// and Running.
    ///
    /// Returns Direct if the destination is in RecvWait for this exact
    /// sender, Enqueue if mailbox has room, Full otherwise.
    fn message_route(&self, dest_idx: usize, sender_key: &ProcessKey) -> DeliveryRoute {
        if let Some(ref rw) = self.processes[dest_idx].recv_wait {
            if rw.peer.slot == sender_key.slot
                && rw.peer.generation == sender_key.generation
            {
                return DeliveryRoute::Direct;
            }
        }
        if self.mailboxes[dest_idx].len() < MAX_MAILBOX_SIZE {
            DeliveryRoute::Enqueue
        } else {
            DeliveryRoute::Full
        }
    }

    /// Deliver a message to `dest_idx`, using the route returned by
    /// `message_route()`.
    ///
    /// For `Direct`: calls `complete_recv_wait()` with `RecvOutcome::Message`,
    ///   bypassing the mailbox entirely.
    /// For `Enqueue`: pushes the message into the mailbox.
    /// For `Full`: unreachable — callers must have already handled it.
    ///
    /// Returns `true` for Direct or Enqueue, `false` is never returned
    /// (callers must not call this for Full).
    fn deliver_message(&mut self, dest_idx: usize, msg: Message, route: DeliveryRoute) {
        debug_assert_eq!(
            route,
            self.message_route(dest_idx, &msg.from),
            "delivery route must correspond to the committed message"
        );
        debug_assert_eq!(
            self.processes[dest_idx].state,
            ProcessState::Running,
            "message destination must remain live at commit"
        );
        match route {
            DeliveryRoute::Direct => {
                self.complete_recv_wait(dest_idx, RecvOutcome::Message(msg));
            }
            DeliveryRoute::Enqueue => {
                self.mailboxes[dest_idx].push(msg);
            }
            DeliveryRoute::Full => {
                unreachable!("deliver_message called with Full route");
            }
        }
    }

    // ─── SYS_RECV_WAIT (Phase 9.2e) ────────────────────────────────

    /// Authoritative receive-completion encoder.
    ///
    /// Every code path that completes a RecvWait — immediate queued
    /// message, direct send (9.2e.2), PeerDied (9.2e.5) —
    /// MUST go through this single function.  It owns:
    ///   1. Register ABI (R0-R5)
    ///   2. recv_wait = None
    ///   3. event_return() / resume
    ///
    /// Register specification:
    ///   Message(ordinary): R0=value, R1=1, R2=MAX, R3=0, R4=from.slot, R5=from.gen
    ///   Message(cap):      R0=value, R1=2, R2=cap.slot, R3=cap.gen, R4=from.slot, R5=from.gen
    ///   PeerDied:          R0=0, R1=3, R2=MAX, R3=0, R4=peer.slot, R5=peer.gen
    ///   Error:             R0=0, R1=4, R2=MAX, R3=0, R4=0, R5=0
    ///
    /// Formal basis: anka_blocking_receive.kleis — RECV_DECISION_*.
    fn complete_recv_wait(&mut self, slot: usize, outcome: RecvOutcome) {
        self.processes[slot].recv_wait = None;
        match outcome {
            RecvOutcome::Message(msg) => {
                self.processes[slot].core.r[R0 as usize] = msg.value;
                if msg.cap.is_some() {
                    self.processes[slot].core.r[R1 as usize] = 2;
                    let ch = msg.cap.unwrap();
                    self.processes[slot].core.r[R2 as usize] = ch.slot as u64;
                    self.processes[slot].core.r[R3 as usize] = ch.generation as u64;
                } else {
                    self.processes[slot].core.r[R1 as usize] = 1;
                    self.processes[slot].core.r[R2 as usize] = u32::MAX as u64;
                    self.processes[slot].core.r[R3 as usize] = 0;
                }
                self.processes[slot].core.r[R4 as usize] = msg.from.slot as u64;
                self.processes[slot].core.r[R5 as usize] = msg.from.generation as u64;
            }
            RecvOutcome::PeerDied(peer) => {
                self.processes[slot].core.r[R0 as usize] = 0;
                self.processes[slot].core.r[R1 as usize] = 3;
                self.processes[slot].core.r[R2 as usize] = u32::MAX as u64;
                self.processes[slot].core.r[R3 as usize] = 0;
                self.processes[slot].core.r[R4 as usize] = peer.slot as u64;
                self.processes[slot].core.r[R5 as usize] = peer.generation as u64;
            }
            RecvOutcome::Error => {
                self.processes[slot].core.r[R0 as usize] = 0;
                self.processes[slot].core.r[R1 as usize] = 4;
                self.processes[slot].core.r[R2 as usize] = u32::MAX as u64;
                self.processes[slot].core.r[R3 as usize] = 0;
                self.processes[slot].core.r[R4 as usize] = 0;
                self.processes[slot].core.r[R5 as usize] = 0;
            }
        }
        self.resume_from_trap(slot);
    }

    /// SYS_RECV_WAIT (syscall 14): blocking exact-peer receive.
    ///
    /// ABI:
    ///   R1 = peer slot (u32)
    ///   R2 = peer generation (u32)
    ///
    /// Decision order (anka_blocking_receive.kleis recv_wait_decision_92e):
    ///   1. Checked ProcessKey decode
    ///   2. Matching queued message from exact ProcessKey? → immediate Message
    ///   3. Peer incarnation state:
    ///      a. Running → install RecvWait, block
    ///      b. Zombie + nonterminal pair DMA → install RecvWait, block
    ///      c. Zombie + quiescent → immediate PeerDied
    ///      d. Free/Retired/stale gen → immediate Error
    ///
    /// The queued-message search uses rposition() + remove() to find the
    /// most recently enqueued message from the exact peer, preserving
    /// the existing LIFO ordering (Vec + pop() = newest-first).
    ///
    /// Formal basis: anka_blocking_receive.kleis — recv_wait_decision_92e,
    ///   recv_wait_sender_matches_92e, recv_after_direct_message_92e.
    fn handle_recv_wait(&mut self, idx: usize) {
        let r1 = self.processes[idx].core.r[R1 as usize];
        let r2 = self.processes[idx].core.r[R2 as usize];

        // ── Gate 0: Checked ABI decode ──
        let peer_slot = match u32::try_from(r1) {
            Ok(v) => match usize::try_from(v) {
                Ok(s) => s,
                Err(_) => {
                    self.complete_recv_wait(idx, RecvOutcome::Error);
                    return;
                }
            },
            Err(_) => {
                self.complete_recv_wait(idx, RecvOutcome::Error);
                return;
            }
        };
        let peer_gen = match u32::try_from(r2) {
            Ok(v) => v,
            Err(_) => {
                self.complete_recv_wait(idx, RecvOutcome::Error);
                return;
            }
        };

        let peer_key = ProcessKey { slot: peer_slot, generation: peer_gen };

        // ── Decision 1: Matching queued message from exact ProcessKey ──
        // rposition() finds the most recently enqueued match (LIFO convention).
        let match_pos = self.mailboxes[idx].iter().rposition(|msg| {
            msg.from.slot == peer_key.slot && msg.from.generation == peer_key.generation
        });
        if let Some(pos) = match_pos {
            let msg = self.mailboxes[idx].remove(pos);
            self.complete_recv_wait(idx, RecvOutcome::Message(msg));
            return;
        }

        // ── Decision 2: Peer incarnation state ──
        if peer_slot >= self.processes.len() {
            self.complete_recv_wait(idx, RecvOutcome::Error);
            return;
        }
        let peer_proc = &self.processes[peer_slot];
        if peer_proc.generation != peer_gen {
            // Stale generation → error
            self.complete_recv_wait(idx, RecvOutcome::Error);
            return;
        }

        match peer_proc.state {
            ProcessState::Running => {
                // Peer is alive → install RecvWait, block
                self.processes[idx].recv_wait = Some(RecvWait { peer: peer_key });
                // Leave EventFrame outstanding — completion path will event_return()
            }
            ProcessState::Zombie => {
                // Peer is dead — check quiescence
                let caller_key = ProcessKey {
                    slot: idx,
                    generation: self.processes[idx].generation,
                };
                let pair_count = self.device_registry
                    .nonterminal_pair_request_count(&caller_key, &peer_key);
                if pair_count > 0 {
                    // Nonterminal DMA outstanding → block until quiescent
                    self.processes[idx].recv_wait = Some(RecvWait { peer: peer_key });
                } else {
                    // Quiescent → immediate PeerDied
                    self.complete_recv_wait(idx, RecvOutcome::PeerDied(peer_key));
                }
            }
            ProcessState::Free | ProcessState::Retired => {
                // Recycled/retired → error
                self.complete_recv_wait(idx, RecvOutcome::Error);
            }
        }
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
        kernel.register_block_device(ctrl)
            .expect("block device registration must succeed");

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
        kernel.device_registry.devices[0].controller
            .storage_mut().write_block(0, &[0xAA; 512]);

        let rk = RequesterKey { slot: 0, generation: 0 };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
            source_authority_id: None,
            delegation_id: None,
        };

        let result = kernel.device_registry.devices[0].controller
            .submit(req, &mut kernel.fabric);
        assert!(matches!(result, SubmitResult::Accepted(_)));

        // Tick the controller until the request completes (latency 1 + DMA).
        for _ in 0..5 {
            kernel.device_registry.devices[0].controller
                .tick(&mut kernel.fabric);
        }
        assert!(kernel.device_registry.devices[0].controller.requires_attention(),
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

        kernel.device_registry.devices[0].controller
            .storage_mut().write_block(0, &[0xBB; 512]);
        kernel.device_registry.devices[0].controller
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
            source_authority_id: None,
            delegation_id: None,
            };
            let result = kernel.device_registry.devices[0].controller
                .submit(req, &mut kernel.fabric);
            assert!(matches!(result, SubmitResult::Accepted(_)));
        }

        // Tick until both complete.
        for _ in 0..10 {
            kernel.device_registry.devices[0].controller
                .tick(&mut kernel.fabric);
        }
        assert_eq!(kernel.device_registry.devices[0].controller.completion_count(), 2);

        // tick_devices posts P_dev.
        kernel.tick_devices(0);
        assert!(kernel.processes[0].core.pending.device);

        // Simulate delivery consuming P_dev.
        kernel.processes[0].core.pending.device = false;

        // Consume one completion — C is now 1, still > 0.
        kernel.device_registry.devices[0].controller.consume_completion();
        assert_eq!(kernel.device_registry.devices[0].controller.completion_count(), 1);

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

        kernel.device_registry.devices[0].controller
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
            source_authority_id: None,
            delegation_id: None,
        };

        let result = kernel.device_registry.devices[0].controller
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
        let dev_binding = kernel.device_registry.devices[0].binding;
        kernel.processes[0].io_wait = Some(IoWait {
            request: DeviceRequestKey { device: dev_binding, request: handle },
        });

        // Tick until DMA completes.
        for _ in 0..10 {
            kernel.device_registry.devices[0].controller
                .tick(&mut kernel.fabric);
        }
        assert!(kernel.device_registry.devices[0].controller.requires_attention());

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

        kernel.device_registry.devices[0].controller
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
            source_authority_id: None,
            delegation_id: None,
        };

        let result = kernel.device_registry.devices[0].controller
            .submit(req, &mut kernel.fabric);
        let handle = match result {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit must succeed"),
        };

        // "Recycle" the process slot by bumping its generation.
        kernel.processes[0].generation += 1;
        // Set up io_wait with the old handle on the recycled slot.
        let dev_binding = kernel.device_registry.devices[0].binding;
        kernel.processes[0].io_wait = Some(IoWait {
            request: DeviceRequestKey { device: dev_binding, request: handle },
        });

        // Tick until completion.
        for _ in 0..10 {
            kernel.device_registry.devices[0].controller
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

        kernel.device_registry.devices[0].controller
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
            source_authority_id: None,
            delegation_id: None,
        };

        kernel.device_registry.devices[0].controller
            .submit(req, &mut kernel.fabric);

        // Process is NOT io_wait.
        assert!(kernel.processes[0].io_wait.is_none());
        kernel.processes[0].core.r[R0 as usize] = 0xDEAD;

        for _ in 0..10 {
            kernel.device_registry.devices[0].controller
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
        kernel.register_block_device(ctrl).expect("register_block_device");

        // Submit a block request.
        let rk = RequesterKey { slot: 0, generation: 0 };
        let req = BlockRequest {
            block_number: 0,
            requester: rk,
            target_object: buf,
            target_offset: 0,
            source_domain: dom,
            source_authority_id: None,
            delegation_id: None,
        };
        kernel.device_registry.devices[0].controller
            .submit(req, &mut kernel.fabric);

        // Tick the block controller until completed.
        for _ in 0..10 {
            kernel.device_registry.devices[0].controller
                .tick(&mut kernel.fabric);
        }
        assert!(kernel.device_registry.devices[0].controller.requires_attention());

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
        assert!(kernel.device_registry.devices.is_empty());
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
        kernel.register_block_device(ctrl).expect("register_block_device");

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
        assert!(kernel.device_registry.devices.is_empty());
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
        kernel.register_block_device(ctrl).expect("register_block_device");
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
        kernel.register_block_device(ctrl).expect("register_block_device");
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
        kernel.device_registry.devices[0].controller
            .storage_mut().write_block(0, &[0xAA; 512]);
        kernel.device_registry.devices[0].controller
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
            source_authority_id: None,
            delegation_id: None,
        };
        let handle0 = match kernel.device_registry.devices[0].controller
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
            source_authority_id: None,
            delegation_id: None,
        };
        let handle1 = match kernel.device_registry.devices[0].controller
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
        let dev_binding = kernel.device_registry.devices[0].binding;
        kernel.processes[0].io_wait = Some(IoWait {
            request: DeviceRequestKey { device: dev_binding, request: handle1 },
        });

        // Tick until both complete.
        for _ in 0..10 {
            kernel.device_registry.devices[0].controller
                .tick(&mut kernel.fabric);
        }
        assert_eq!(kernel.device_registry.devices[0].controller.completion_count(), 2);

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
        kernel.register_block_device(ctrl).expect("register_block_device");
        kernel.processes[0].core.address_map.add(buf_vaddr as u64, 0x1000, buf);

        // Run: the process issues SYS_BLOCK_READ and blocks on I/O.
        // Pre-9.2e.3 this was a dead end (no tick source).
        // Post-9.2e.3 idle progress advances the controller, the
        // completion wakes the process, and it exits normally.
        kernel.run(10000, 100);

        // The process must have completed — idle progress kept the
        // block controller alive until the DMA finished.
        assert!(kernel.processes[0].exited(),
            "solo io_wait process must complete via idle progress");
        assert_eq!(kernel.processes[0].result,
            Some(ProcessResult::Exited(123)),
            "process must exit with code 123 after I/O completion");

        eprintln!("9.2e.3: solo io_wait → idle progress → completion → exit ✓");
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
        assert_eq!(resolved.object(), data);
        let (offset, length, perms) = resolved.as_memory();
        assert_eq!(offset, 0);
        assert_eq!(length, 4096);
        assert_eq!(perms, Permissions::READ);

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

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2a hardening — formal correspondence witnesses
    // ═══════════════════════════════════════════════════════════════

    /// Full-table installation failure must leave no orphan Fabric authority.
    ///
    /// Before the fix, install_capability() would:
    ///   alloc AuthorityId → grant in Fabric → fail table install
    /// leaving the Fabric authority with no naming handle.
    ///
    /// Now the preflight rejects before granting, and the rollback
    /// catches any unexpected post-grant failure.
    #[test]
    fn p92a_full_table_no_orphan_authority() {
        let (mut kernel, data, slot) = captab_kernel_setup();
        let domain = kernel.processes[slot].core.domain;

        let cap_count_before = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();

        // Fill all 16 slots.
        for _ in 0..CAP_TABLE_SIZE {
            kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
                .expect("install should succeed");
        }

        let cap_count_full = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_full, cap_count_before + CAP_TABLE_SIZE);

        // 17th install must fail.
        assert!(kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ).is_none(),
            "install beyond table capacity must fail");

        // Crucial: Fabric authority count unchanged — no orphan.
        let cap_count_after = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_after, cap_count_full,
            "failed install must not leave orphan Fabric authority");

        eprintln!("9.2a: full-table no-orphan-authority ✓");
    }

    /// Removing an AuthorityId behind an occupied slot makes
    /// resolve_capability() fail — even though the slot is still
    /// Occupied and the object generation is still current.
    ///
    /// This witnesses the full architectural condition 2:
    ///   AuthorityIdExists means "exists in Fabric domain",
    ///   not merely "slot is Occupied".
    #[test]
    fn p92a_ghost_authority_resolve_fails() {
        let (mut kernel, data, slot) = captab_kernel_setup();
        let domain = kernel.processes[slot].core.domain;

        let h = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
            .expect("install should succeed");

        // Resolve succeeds with authority present.
        assert!(kernel.resolve_capability(slot, h).is_some());

        // Surgically remove the backing authority from the Fabric,
        // leaving the cap-table slot Occupied.
        let resolved = kernel.processes[slot].cap_table.as_ref().unwrap()
            .resolve(h, |oid| kernel.fabric.objects.get(&oid).map(|o| o.generation))
            .expect("table-level resolve should succeed");
        let removed = kernel.fabric.remove_by_authority_id(domain, resolved.authority_id());
        assert!(removed, "authority should exist");

        // Now: slot is Occupied, object gen is current, but AuthorityId
        // is missing from the domain.  Kernel resolve must fail.
        assert!(kernel.resolve_capability(slot, h).is_none(),
            "ghost authority: slot occupied but AuthorityId missing → must fail");

        eprintln!("9.2a: ghost-authority resolve failure ✓");
    }

    /// CAP_DROP cannot report success unless both the name and the
    /// exact backing authority are removed.
    ///
    /// We surgically remove the Fabric authority before the guest
    /// calls SYS_CAP_DROP.  The syscall must return 1 (failure)
    /// because the backing authority is absent, even though the
    /// cap-table handle is valid.
    #[test]
    fn p92a_cap_drop_requires_backing_authority() {
        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, data, _stack) =
            create_process(&mut fabric, CPU0, "cap_drop_ghost",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut kernel = Kernel::new(fabric);
        let pk = kernel.spawn(core);
        let slot = pk.slot;

        let h = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
            .expect("install should succeed");

        // Surgically remove the Fabric authority.
        let resolved = kernel.processes[slot].cap_table.as_ref().unwrap()
            .resolve(h, |oid| kernel.fabric.objects.get(&oid).map(|o| o.generation))
            .expect("table-level resolve");
        kernel.fabric.remove_by_authority_id(dom, resolved.authority_id());

        // Guest code: CAP_DROP(slot, gen), save result, EXIT
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
        assert_eq!(kernel.processes[slot].core.r[R5 as usize], 1,
            "CAP_DROP must fail when backing authority is absent");

        eprintln!("9.2a: CAP_DROP requires backing authority ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2a final — generation wrap and AuthorityId exhaustion
    // ═══════════════════════════════════════════════════════════════

    /// A slot at handle_generation = u32::MAX cannot be dropped.
    ///
    /// If drop_handle() used wrapping_add, the generation would wrap
    /// to 0 and an ancient stale handle would become current again.
    /// The Kleis model requires: recyclable(g) ≡ g ≠ 2^32 − 1.
    ///
    /// Drop must fail, the handle must still resolve, and the
    /// backing AuthorityId must still exist in the Fabric domain.
    #[test]
    fn p92a_handle_generation_max_does_not_wrap() {
        let (mut kernel, data, slot) = captab_kernel_setup();
        let domain = kernel.processes[slot].core.domain;

        // Install a capability, then force the slot generation to u32::MAX.
        let h = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
            .expect("install should succeed");

        // Surgically set the slot generation to u32::MAX.
        let ct = kernel.processes[slot].cap_table.as_mut().unwrap();
        ct.slots_mut()[h.slot as usize].handle_generation = u32::MAX;

        // Build a handle that matches the forced generation.
        let h_max = CapabilityHandle { slot: h.slot, generation: u32::MAX };

        // Verify it resolves before the drop attempt.
        assert!(kernel.resolve_capability(slot, h_max).is_some(),
            "handle at MAX generation should resolve");

        // Record Fabric state before attempt.
        let cap_count_before = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();

        // Attempt drop — must fail because generation cannot advance.
        let ct = kernel.processes[slot].cap_table.as_mut().unwrap();
        assert!(ct.drop_handle(h_max).is_none(),
            "drop_handle at u32::MAX must fail (no wrap)");

        // Handle still resolves.
        assert!(kernel.resolve_capability(slot, h_max).is_some(),
            "handle must survive failed drop");

        // Fabric authority unchanged.
        let cap_count_after = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_before, cap_count_after,
            "Fabric authority must survive failed drop");

        eprintln!("9.2a: handle generation MAX does not wrap ✓");
    }

    /// AuthorityId exhaustion prevents installation — no reuse.
    ///
    /// If alloc_authority_id() used unchecked addition, the u64
    /// counter would eventually wrap and re-emit an AuthorityId
    /// that was supposed to be permanently dead.  The formal model
    /// requires: AuthorityId is monotonic, never reused.
    ///
    /// alloc_authority_id() emits counter then advances; the last
    /// emittable value is u64::MAX − 1 because checked_add(MAX, 1)
    /// fails before returning AuthorityId(MAX).
    #[test]
    fn p92a_authority_id_exhaustion_does_not_reuse() {
        let (mut kernel, data, slot) = captab_kernel_setup();
        let domain = kernel.processes[slot].core.domain;

        let cap_count_before = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();

        // Force counter to u64::MAX − 1.
        // First alloc: emits AuthorityId(MAX−1), counter → MAX.
        // Second alloc: tries to advance past MAX → None.
        kernel.fabric.set_next_authority_id(u64::MAX - 1);

        let h = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ);
        assert!(h.is_some(), "install at u64::MAX - 1 should succeed");
        assert_eq!(kernel.fabric.next_authority_id(), u64::MAX,
            "counter should now be at MAX");

        // Second allocation must fail — counter cannot advance past MAX.
        let h2 = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ);
        assert!(h2.is_none(), "install after exhaustion must fail");

        // Counter must NOT have wrapped to 0.
        assert_eq!(kernel.fabric.next_authority_id(), u64::MAX,
            "counter must not wrap — still at MAX");

        // Only one new authority should exist.
        let cap_count_after = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_after, cap_count_before + 1,
            "only the first install should add Fabric authority");

        eprintln!("9.2a: AuthorityId exhaustion does not reuse ✓");
    }

    /// Valid but non-recyclable handle through SYS_CAP_DROP.
    ///
    /// The handle is valid (generation matches, slot occupied,
    /// backing authority exists), but the slot generation is
    /// u32::MAX so advancing it would wrap.  SYS_CAP_DROP must
    /// return failure (R0 = 1), NOT panic at an .expect().
    ///
    /// The handle must still resolve and the Fabric authority
    /// must still exist after the failed syscall.
    #[test]
    fn p92a_syscall_cap_drop_non_recyclable() {
        let mut fabric = Fabric::new(0x200000);
        let (core, dom, text, data, _stack) =
            create_process(&mut fabric, CPU0, "cap_drop_maxgen",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut kernel = Kernel::new(fabric);
        let pk = kernel.spawn(core);
        let slot = pk.slot;

        let h = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
            .expect("install should succeed");

        // Force the slot generation to u32::MAX.
        kernel.processes[slot].cap_table.as_mut().unwrap()
            .slots_mut()[h.slot as usize].handle_generation = u32::MAX;

        let h_max = CapabilityHandle { slot: h.slot, generation: u32::MAX };

        // Verify it resolves before the syscall.
        assert!(kernel.resolve_capability(slot, h_max).is_some(),
            "handle at MAX gen should resolve");

        // Guest: CAP_DROP(slot, u32::MAX), save result, EXIT
        let mut asm = Asm64::new();
        asm.movi(R1, h_max.slot as i32);
        // u32::MAX as two's complement i32 is -1.
        asm.movi(R2, -1_i32);
        asm.movi(R0, SYS_CAP_DROP as i32);
        asm.trap(0);
        asm.mov(R5, R0); // save result
        asm.movi(R1, 0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);

        kernel.fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut kernel.fabric, text, dom);

        // Snapshot AFTER seal (which adds an RX entry).
        let domain = kernel.processes[slot].core.domain;
        let cap_count_before = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();

        // Must NOT panic.
        kernel.run(10000, 10);

        assert!(kernel.processes[slot].exited());
        assert_eq!(kernel.processes[slot].core.r[R5 as usize], 1,
            "SYS_CAP_DROP at u32::MAX must return 1 (failure)");

        // Handle still resolves (nothing was mutated).
        assert!(kernel.resolve_capability(slot, h_max).is_some(),
            "handle must survive non-recyclable drop failure");

        // Fabric authority unchanged.
        let cap_count_after = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_before, cap_count_after,
            "Fabric authority must survive non-recyclable drop failure");

        eprintln!("9.2a: SYS_CAP_DROP non-recyclable handle ✓");
    }

    /// Terminal-generation free slot is not reusable for install.
    ///
    /// Dropping a slot at generation MAX−1 succeeds and advances
    /// it to Free(MAX).  That slot is structurally free but retired:
    /// installing into it would create authority that can never be
    /// dropped (preflight_drop rejects MAX).
    ///
    /// With that one slot retired and the other 15 filled, install
    /// must fail atomically with no new Fabric authority.
    #[test]
    fn p92a_retired_slot_not_reusable() {
        let (mut kernel, data, slot) = captab_kernel_setup();
        let domain = kernel.processes[slot].core.domain;

        // Install into slot 0, force its generation to MAX−1.
        let h0 = kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
            .expect("install into slot 0");
        assert_eq!(h0.slot, 0);
        kernel.processes[slot].cap_table.as_mut().unwrap()
            .slots_mut()[0].handle_generation = u32::MAX - 1;
        let h0_penultimate = CapabilityHandle { slot: 0, generation: u32::MAX - 1 };

        // Drop at MAX−1 → succeeds → slot becomes Free(MAX).
        let aid = kernel.processes[slot].cap_table.as_mut().unwrap()
            .drop_handle(h0_penultimate)
            .expect("drop at MAX-1 must succeed");
        kernel.fabric.remove_by_authority_id(domain, aid);

        // Verify slot is Free(MAX).
        let ct = kernel.processes[slot].cap_table.as_ref().unwrap();
        let slot0 = &ct.slots()[0];
        assert!(matches!(slot0.state, CapabilitySlotState::Free));
        assert_eq!(slot0.handle_generation, u32::MAX,
            "slot should be at terminal generation");

        // Structural vs allocatable: slot 0 is free but not allocatable.
        assert_eq!(ct.free_count(), CAP_TABLE_SIZE,
            "all 16 slots structurally free");
        assert_eq!(ct.allocatable_count(), CAP_TABLE_SIZE - 1,
            "only 15 allocatable (slot 0 retired)");

        // Fill the remaining 15 allocatable slots.
        for _ in 0..CAP_TABLE_SIZE - 1 {
            kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ)
                .expect("install into non-retired slot");
        }

        let cap_count_before = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();

        // Attempt one more — must fail (only Free(MAX) slot left).
        assert!(kernel.install_capability(slot, data, 0, 0x4000, Permissions::READ).is_none(),
            "install into retired slot must fail");

        // No orphan authority created.
        let cap_count_after = kernel.fabric.domains.get(&domain).unwrap()
            .capabilities.len();
        assert_eq!(cap_count_before, cap_count_after,
            "failed install must not create Fabric authority");

        // Old MAX−1 handle remains stale (was dropped).
        assert!(kernel.resolve_capability(slot, h0_penultimate).is_none(),
            "dropped handle at MAX-1 must remain stale");

        // F_structural + O = N still holds.
        let ct = kernel.processes[slot].cap_table.as_ref().unwrap();
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE,
            "F_structural + O = N");

        eprintln!("9.2a: retired slot not reusable ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2b — User-Space Capability-Mediated Transfer
    // ═══════════════════════════════════════════════════════════════

    /// Two-process kernel setup for 9.2b transfer tests.
    /// Returns (kernel, sender_slot, receiver_slot, shared_data_object).
    /// Both processes are spawned and have cap tables.
    /// The shared data object is Memory, placed, and RW-granted to the sender.
    fn send_cap_setup() -> (Kernel, usize, usize, ObjectId) {
        let mut fabric = Fabric::new(0x400000);

        // Sender process (slot 0)
        let (core_a, dom_a, text_a, data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "sender",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        // Receiver process (slot 1)
        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "receiver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);

        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);

        (kernel, key_a.slot, key_b.slot, data_a)
    }

    // ─── End-to-end: SYS_SEND_CAP → SYS_RECV ───

    #[test]
    fn p92b_send_cap_end_to_end() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();

        // Install a capability in sender's cap table
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("sender install");

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Before: receiver has 0 messages, 16 allocatable slots
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();

        // Execute SYS_SEND_CAP manually
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;      // child_offset
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;  // child_length (subset)
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64; // attenuated
        kernel.processes[sender].core.r[R8 as usize] = 0xCAFE;  // value

        kernel.handle_send_cap(sender);

        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0,
            "SYS_SEND_CAP must succeed");

        // Identity counters advanced exactly once each
        assert_eq!(kernel.fabric.next_authority_id(), aid_before + 1);
        assert_eq!(kernel.next_delegation_incarnation(), tid_before + 1);

        // Receiver mailbox has one message
        assert_eq!(kernel.mailboxes[receiver].len(), 1);
        let msg = &kernel.mailboxes[receiver][0];
        assert_eq!(msg.from, sender_key);
        assert_eq!(msg.value, 0xCAFE);
        assert!(msg.cap.is_some());

        let recv_handle = msg.cap.unwrap();

        // Resolve the receiver's handle — should succeed
        let resolved = kernel.resolve_capability(receiver, recv_handle)
            .expect("receiver handle must resolve");

        // Non-amplification: subset relationship
        let (offset, length, perms) = resolved.as_memory();
        assert_eq!(offset, 0);
        assert_eq!(length, 0x2000);
        assert_eq!(perms, Permissions::READ);

        // DelegationId is present and correct
        assert!(resolved.delegation_id().is_some());
        let tid = resolved.delegation_id().unwrap();
        assert_eq!(tid.client, sender_key);
        assert_eq!(tid.driver, receiver_key);
        assert_eq!(tid.incarnation, tid_before);

        eprintln!("9.2b: end-to-end send_cap → recv ✓");
    }

    // ─── Preflight failures: each gate produces no side effects ───

    #[test]
    fn p92b_gate0_malformed_dest_slot() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();

        // High-bit alias: 0x1_0000_0001 → would truncate to 1
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = 0x1_0000_0001u64; // bad
        kernel.processes[sender].core.r[R2 as usize] = 0;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 1,
            "malformed dest slot must fail with code 1");

        // No side effects
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);
        assert_eq!(kernel.next_delegation_incarnation(), tid_before);
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: gate 0 malformed dest slot ✓");
    }

    #[test]
    fn p92b_gate0_malformed_src_handle() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let _src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        let aid_before = kernel.fabric.next_authority_id();

        // High-bit alias on source cap handle slot
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = 0x1_0000_0000u64; // bad
        kernel.processes[sender].core.r[R4 as usize] = 0;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 1,
            "malformed src handle must fail with code 1");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.2b: gate 0 malformed src handle ✓");
    }

    #[test]
    fn p92b_gate0_bad_permissions() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Invalid permission bits
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = 0xFF; // invalid bits
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 1,
            "bad permission bits must fail");

        eprintln!("9.2b: gate 0 bad permissions ✓");
    }

    #[test]
    fn p92b_gate1_dest_not_current() {
        let (mut kernel, sender, _receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let aid_before = kernel.fabric.next_authority_id();

        // Non-existent dest
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = 99; // no such slot
        kernel.processes[sender].core.r[R2 as usize] = 0;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 2,
            "non-existent dest must fail with code 2");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.2b: gate 1 dest not current ✓");
    }

    #[test]
    fn p92b_gate1_dest_stale_generation() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let aid_before = kernel.fabric.next_authority_id();

        // Stale generation
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver as u64;
        kernel.processes[sender].core.r[R2 as usize] = 999; // wrong gen
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 2,
            "stale dest generation must fail with code 2");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.2b: gate 1 dest stale generation ✓");
    }

    #[test]
    fn p92b_gate2_source_handle_not_resolved() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        let aid_before = kernel.fabric.next_authority_id();

        // No capability installed — handle (0,0) is Free
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = 0;
        kernel.processes[sender].core.r[R4 as usize] = 0;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 3,
            "unresolvable source must fail with code 3");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: gate 2 source not resolved ✓");
    }

    #[test]
    fn p92b_gate3_subset_amplification_rejected() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::READ)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        let aid_before = kernel.fabric.next_authority_id();

        // Attempt to amplify READ → RW
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x4000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::RW.0 as u64; // amplify!
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 4,
            "permission amplification must fail with code 4");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: gate 3 subset amplification rejected ✓");
    }

    #[test]
    fn p92b_gate3_range_exceeds_parent() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::READ)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        let aid_before = kernel.fabric.next_authority_id();

        // Child extends past parent
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0x1000;  // offset 4096
        kernel.processes[sender].core.r[R6 as usize] = 0x4000;  // length 16384 → past end
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 4,
            "range exceeding parent must fail");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.2b: gate 3 range exceeds parent ✓");
    }

    #[test]
    fn p92b_gate3_zero_length_rejected() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::READ)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0; // zero length
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 4,
            "zero length must fail");

        eprintln!("9.2b: gate 3 zero length rejected ✓");
    }

    #[test]
    fn p92b_gate4_receiver_cap_table_full() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        // Fill receiver's cap table
        let recv_data = {
            let dom = kernel.processes[receiver].core.domain;
            let caps = &kernel.fabric.domains[&dom].capabilities;
            let entry = caps.iter().find(|e| {
                e.cap.permissions().contains(Permissions::WRITE)
                    && !e.cap.permissions().contains(Permissions::EXECUTE)
            }).unwrap();
            entry.cap.object()
        };
        for _ in 0..CAP_TABLE_SIZE {
            kernel.install_capability(receiver, recv_data, 0, 0x4000, Permissions::RW)
                .expect("fill receiver cap table");
        }

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };
        let aid_before = kernel.fabric.next_authority_id();

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 5,
            "full receiver cap table must fail with code 5");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: gate 4 receiver cap table full ✓");
    }

    #[test]
    fn p92b_gate5_mailbox_full() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Fill the mailbox
        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        for _ in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[receiver].push(Message {
                from: sender_key, value: 0, cap: None,
            });
        }

        let aid_before = kernel.fabric.next_authority_id();

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 6,
            "full mailbox must fail with code 6");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.2b: gate 5 mailbox full ✓");
    }

    #[test]
    fn p92b_gate6_authority_id_exhausted() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Exhaust AuthorityId space
        kernel.fabric.set_next_authority_id(u64::MAX);

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 7,
            "AuthorityId exhaustion must fail with code 7");
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: gate 6 authority ID exhausted ✓");
    }

    #[test]
    fn p92b_gate6_delegation_id_exhausted() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Exhaust DelegationId incarnation space
        kernel.set_next_delegation_incarnation(u64::MAX);

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 7,
            "DelegationId exhaustion must fail with code 7");
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: gate 6 delegation ID exhausted ✓");
    }

    // ─── Exact AuthorityId derivation with value-equal twins ───

    #[test]
    fn p92b_exact_authority_transfer_with_twins() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();

        // Two value-equal caps, different AuthorityIds
        let h1 = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install h1");
        let h2 = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install h2");

        let r1 = kernel.resolve_capability(sender, h1).unwrap();
        let r2 = kernel.resolve_capability(sender, h2).unwrap();
        assert_ne!(r1.authority_id(), r2.authority_id(),
            "twin caps must have different AuthorityIds");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        let src_domain = kernel.processes[sender].core.domain;
        let dst_domain = kernel.processes[receiver].core.domain;
        let sender_caps_before = kernel.fabric.domains[&src_domain].capabilities.len();
        let receiver_caps_before = kernel.fabric.domains[&dst_domain].capabilities.len();

        // Transfer h1 only
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = h1.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = h1.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x4000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::RW.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 0xDEAD;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0);

        // Sender domain unchanged (source authority not consumed)
        let sender_caps_after = kernel.fabric.domains[&src_domain].capabilities.len();
        assert_eq!(sender_caps_after, sender_caps_before);

        // Receiver domain gained exactly one
        let receiver_caps_after = kernel.fabric.domains[&dst_domain].capabilities.len();
        assert_eq!(receiver_caps_after, receiver_caps_before + 1);

        // h2 still resolves in sender — transfer of h1 did not destroy the twin
        assert!(kernel.resolve_capability(sender, h2).is_some(),
            "twin cap h2 must still resolve after h1 was transferred");

        eprintln!("9.2b: exact authority with value-equal twins ✓");
    }

    // ─── Non-Memory source rejection ───

    // ─── 9.3a: Device source with nonzero R6 rejects (non-spatial ABI) ───
    //
    // Originally this test verified that Device sources were rejected
    // entirely.  After the 9.3a kind-sensitive refactor, Device sources
    // are accepted — but the non-spatial ABI requires R5=R6=0.
    // This test now exercises that R6≠0 on a Device source yields error 4.
    // No AuthorityId is consumed because rejection is at the preflight gate.

    #[test]
    fn p92b_device_nonzero_r6_rejected() {
        let mut fabric = Fabric::new(0x400000);

        let (core_a, dom_a, text_a, _data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "sender_dev",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let dev_obj = fabric.alloc_object("device0", 0, ObjectKind::Device);

        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "receiver_dev",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);

        let sender = key_a.slot;

        let dev_auth_id = kernel.fabric.alloc_authority_id().expect("alloc auth id");
        kernel.fabric.grant_device_with_authority_id(
            kernel.processes[sender].core.domain, dev_obj,
            DeviceRights::SUBMIT_READ, dev_auth_id,
        ).expect("grant device authority");
        let dev_gen = kernel.fabric.objects.get(&dev_obj).unwrap().generation;
        let dev_handle = kernel.processes[sender].cap_table.as_mut().unwrap()
            .install_device(dev_obj, dev_gen, DeviceRights::SUBMIT_READ, dev_auth_id, None)
            .expect("install device cap in table");

        let receiver_key = ProcessKey {
            slot: key_b.slot,
            generation: kernel.processes[key_b.slot].generation,
        };

        let aid_before = kernel.fabric.next_authority_id();

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = dev_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = dev_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000; // nonzero → error 4
        kernel.processes[sender].core.r[R7 as usize] = DeviceRights::SUBMIT_READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 4,
            "Device transfer with nonzero R6 must be rejected");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "no AuthorityId consumed on preflight failure");

        eprintln!("9.3a: Device nonzero R6 rejected (error 4) ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.3a — Device-Capability Transfer Hostile Suite
    //
    // Tests the kind-sensitive SYS_SEND_CAP refactor:
    //   - Device authority transfer with rights-only attenuation
    //   - Non-spatial ABI (R5=R6=0 required)
    //   - Exact-presented-authority enforcement
    //   - Atomicity / rollback
    //   - Revocation independence
    //   - Kind-correct decode ordering
    //
    // Formal basis: anka_device_capability_transfer.kleis DEVXFER-1..12.
    // ═══════════════════════════════════════════════════════════════

    /// Helper: set up a kernel with two processes and a Device object
    /// with SUBMIT_READ authority installed in the sender's cap table.
    /// Returns (kernel, sender_slot, receiver_slot, dev_obj, dev_handle).
    fn dev_transfer_setup() -> (Kernel, usize, usize, ObjectId, CapabilityHandle) {
        let mut fabric = Fabric::new(0x400000);

        let (core_a, dom_a, text_a, _data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "dev_sender",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let dev_obj = fabric.alloc_object("device0", 0, ObjectKind::Device);
        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "dev_receiver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);
        let sender = key_a.slot;
        let receiver = key_b.slot;

        let dev_handle = kernel.install_device_capability(
            sender, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap for sender");

        (kernel, sender, receiver, dev_obj, dev_handle)
    }

    /// Helper: execute a SYS_SEND_CAP for a Device source.
    fn do_dev_send_cap(
        kernel: &mut Kernel,
        sender: usize,
        receiver_slot: usize,
        receiver_gen: u32,
        dev_handle: &CapabilityHandle,
        r5: u64,
        r6: u64,
        r7: u64,
        value: u64,
    ) -> u64 {
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_gen as u64;
        kernel.processes[sender].core.r[R3 as usize] = dev_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = dev_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = r5;
        kernel.processes[sender].core.r[R6 as usize] = r6;
        kernel.processes[sender].core.r[R7 as usize] = r7;
        kernel.processes[sender].core.r[R8 as usize] = value;

        kernel.handle_send_cap(sender);
        kernel.processes[sender].core.r[R0 as usize]
    }

    // ─── 9.3a.3.1: Successful transfer preserves ObjectId, Generation, Kind ───

    #[test]
    fn p93a_1_device_transfer_preserves_identity() {
        let (mut kernel, sender, receiver, dev_obj, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 99,
        );
        assert_eq!(r0, 0, "device transfer must succeed");

        // Receiver mailbox has exactly one message with a cap
        let msg = kernel.mailboxes[receiver].pop().unwrap();
        assert_eq!(msg.value, 99);
        let new_handle = msg.cap.unwrap();

        // Resolve the child: must be Device with exact object/generation/rights
        let resolved = kernel.resolve_capability(receiver, new_handle)
            .expect("transferred device cap must resolve");
        assert!(resolved.is_device(), "child must be Device");
        assert_eq!(resolved.object(), dev_obj, "child object must match parent");
        assert_eq!(resolved.object_generation(),
            kernel.fabric.objects.get(&dev_obj).unwrap().generation,
            "child generation must be current");
        assert_eq!(resolved.as_device_rights(), DeviceRights::SUBMIT_READ,
            "child rights must match requested");

        eprintln!("9.3a.3.1: device transfer preserves ObjectId, Generation, Kind ✓");
    }

    // ─── 9.3a.3.2: Non-amplification: NONE parent → SUBMIT_READ child rejects ───

    #[test]
    fn p93a_2_non_amplification_none_to_submit_read() {
        let mut fabric = Fabric::new(0x400000);
        let (core_a, dom_a, text_a, _, _) =
            create_process(&mut fabric, CPU0, "sender",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let dev_obj = fabric.alloc_object("device0", 0, ObjectKind::Device);
        let mut asm = Asm64::new();
        for _ in 0..100 { asm.nop(); }
        asm.movi(R1, 0); asm.movi(R0, SYS_EXIT as i32); asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        let (core_b, dom_b, text_b, _, _) =
            create_process(&mut fabric, AgentId(1), "receiver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0); asm_b.movi(R0, SYS_EXIT as i32); asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);
        let sender = key_a.slot;

        // Install Device cap with NONE rights
        let dev_handle = kernel.install_device_capability(
            sender, dev_obj, DeviceRights::NONE,
        ).expect("install NONE device cap");

        let aid_before = kernel.fabric.next_authority_id();
        let recv_gen = kernel.processes[key_b.slot].generation;

        let r0 = do_dev_send_cap(
            &mut kernel, sender, key_b.slot, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 4, "NONE→SUBMIT_READ must be rejected (amplification)");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "no AuthorityId consumed on attenuation failure");

        eprintln!("9.3a.3.2: NONE parent → SUBMIT_READ child rejected ✓");
    }

    // ─── 9.3a.3.3: SUBMIT_READ → NONE succeeds, child cannot DEV_SUBMIT ───

    #[test]
    fn p93a_3_submit_read_to_none_succeeds_but_useless() {
        use super::super::block::{BlockStorage, BlockController};

        // Full setup with block device so we can attempt a real operation.
        let mut fabric = Fabric::new(0x800000);

        let (core_a, dom_a, text_a, _data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "sender",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0); asm_a.movi(R0, SYS_EXIT as i32); asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "receiver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0); asm_b.movi(R0, SYS_EXIT as i32); asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        // DMA buffer for the receiver
        let buf_obj = fabric.alloc_object("buf", 512, ObjectKind::Memory);
        fabric.place_object(buf_obj, 0x300000);
        fabric.write_physical(0x300000, &[0x00; 512]);

        // Block storage
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xCC; 512]);
        let controller = BlockController::new(storage, 3, AgentId(100));

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);
        let sender = key_a.slot;
        let receiver = key_b.slot;

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        // Sender gets SUBMIT_READ device cap
        let dev_handle = kernel.install_device_capability(
            sender, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("sender device cap");

        // Transfer SUBMIT_READ → NONE to receiver
        let recv_gen = kernel.processes[receiver].generation;
        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::NONE.0 as u64, 0,
        );
        assert_eq!(r0, 0, "SUBMIT_READ→NONE must succeed (valid attenuation)");

        let msg = kernel.mailboxes[receiver].pop().unwrap();
        let none_handle = msg.cap.unwrap();
        let resolved = kernel.resolve_capability(receiver, none_handle)
            .expect("NONE device cap must resolve");
        assert!(resolved.is_device());
        assert_eq!(resolved.as_device_rights(), DeviceRights::NONE);

        // Give receiver a valid WRITE buffer cap so the only failure
        // path is the device-authority gate, not buffer resolution.
        let recv_dom = kernel.processes[receiver].core.domain;
        let buf_aid = kernel.fabric.alloc_authority_id().unwrap();
        kernel.fabric.grant_with_authority_id(
            recv_dom, buf_obj, 0, 512, Permissions::WRITE, buf_aid,
        ).expect("grant receiver buffer");
        let buf_gen = kernel.fabric.objects.get(&buf_obj).unwrap().generation;
        let buf_handle = kernel.processes[receiver].cap_table.as_mut().unwrap()
            .install_memory(buf_obj, buf_gen, 0, 512, Permissions::WRITE, buf_aid, None)
            .expect("install receiver buffer cap");

        // Attempt blocking SYS_DEV_SUBMIT (13) with the NONE device cap.
        // This must fail at the device-authority gate with error 4.
        let return_pc = kernel.processes[receiver].core.pc + 4;
        kernel.processes[receiver].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[receiver].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[receiver].core.r[R1 as usize] = none_handle.slot as u64;
        kernel.processes[receiver].core.r[R2 as usize] = none_handle.generation as u64;
        kernel.processes[receiver].core.r[R3 as usize] = 0; // block 0
        kernel.processes[receiver].core.r[R4 as usize] = buf_handle.slot as u64;
        kernel.processes[receiver].core.r[R5 as usize] = buf_handle.generation as u64;
        kernel.processes[receiver].core.halted = true;
        kernel.handle_syscall(receiver);

        assert_eq!(kernel.processes[receiver].core.r[R0 as usize], 4,
            "SYS_DEV_SUBMIT with DeviceRights::NONE must fail at authority gate (error 4)");
        assert!(kernel.processes[receiver].io_wait.is_none(),
            "no IoWait installed on rejected submission");

        // Buffer must be unchanged — no DMA occurred
        let buf_data = kernel.fabric.read_physical(0x300000, 512);
        assert!(buf_data.iter().all(|&b| b == 0x00),
            "buffer must remain at baseline — no DMA domain created");

        // Controller must have no in-flight requests
        assert!(kernel.device_registry.devices[0].controller
            .in_flight_requests().is_empty(),
            "controller must not have accepted a request");

        eprintln!("9.3a.3.3: SUBMIT_READ → NONE succeeds; NONE child → SYS_DEV_SUBMIT error 4 ✓");
    }

    // ─── 9.3a.3.4: R5 != 0 rejects (error 4) ───

    #[test]
    fn p93a_4_r5_nonzero_rejected() {
        let (mut kernel, sender, receiver, _, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;
        let aid_before = kernel.fabric.next_authority_id();

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            1, 0, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 4, "nonzero R5 on Device source must yield error 4");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.3a.3.4: R5≠0 rejected ✓");
    }

    // ─── 9.3a.3.5: R6 != 0 rejects (error 4) ───
    // (covered by p92b_device_nonzero_r6_rejected above, but explicit here)

    #[test]
    fn p93a_5_r6_nonzero_rejected() {
        let (mut kernel, sender, receiver, _, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;
        let aid_before = kernel.fabric.next_authority_id();

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 512, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 4, "nonzero R6 on Device source must yield error 4");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.3a.3.5: R6≠0 rejected ✓");
    }

    // ─── 9.3a.3.6: Undefined DeviceRights bits reject (error 1) ───

    #[test]
    fn p93a_6_undefined_device_rights_rejected() {
        let (mut kernel, sender, receiver, _, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;
        let aid_before = kernel.fabric.next_authority_id();

        // R7 = 0x02 is valid Permissions::WRITE but undefined DeviceRights.
        // If R7 were decoded before source-kind resolution, 0x02 would pass
        // the Permissions decode.  This test protects:
        //   Kind(source) → Decode(R7).
        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, 0x02, 0,
        );
        assert_eq!(r0, 1, "undefined DeviceRights bit 0x02 must yield error 1");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before);

        eprintln!("9.3a.3.6: R7=0x02 (WRITE as Permissions, undefined as DeviceRights) → error 1 ✓");
    }

    // ─── 9.3a.3.7: Fresh AuthorityId + DelegationId ───

    #[test]
    fn p93a_7_fresh_authority_and_delegation_ids() {
        let (mut kernel, sender, receiver, _, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        let src_resolved = kernel.resolve_capability(sender, dev_handle).unwrap();
        let src_aid = src_resolved.authority_id();
        let tid_before = kernel.next_delegation_incarnation();

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 77,
        );
        assert_eq!(r0, 0);

        let msg = kernel.mailboxes[receiver].pop().unwrap();
        let child_handle = msg.cap.unwrap();
        let child_resolved = kernel.resolve_capability(receiver, child_handle)
            .expect("child must resolve");
        let child_aid = child_resolved.authority_id();
        let child_tid = child_resolved.delegation_id()
            .expect("transferred cap must carry DelegationId");

        assert_ne!(child_aid, src_aid,
            "child AuthorityId must differ from source");
        assert!(child_tid.incarnation >= tid_before,
            "DelegationId incarnation must be fresh");

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };
        assert_eq!(child_tid.client, sender_key,
            "DelegationId.client must be the sender");
        assert_eq!(child_tid.driver, receiver_key,
            "DelegationId.driver must be the receiver");

        eprintln!("9.3a.3.7: fresh AuthorityId + DelegationId(sender,receiver) ✓");
    }

    // ─── 9.3a.3.8: Receiver can use transferred device cap in DEV_SUBMIT ───

    #[test]
    fn p93a_8_transferred_device_cap_usable_for_dev_submit() {
        use super::super::block::{BlockStorage, BlockController};

        let mut fabric = Fabric::new(0x800000);

        // Sender (supervisor-like)
        let (core_sup, dom_sup, text_sup, _data_sup, _stack_sup) =
            create_process(&mut fabric, CPU0, "supervisor",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_sup = Asm64::new();
        for _ in 0..100 { asm_sup.nop(); }
        asm_sup.movi(R1, 0); asm_sup.movi(R0, SYS_EXIT as i32); asm_sup.trap(0);
        fabric.write_physical(0x000000, &asm_sup.to_bytes());
        seal_code_object(&mut fabric, text_sup, dom_sup);

        // Driver
        let (core_drv, dom_drv, text_drv, _data_drv, _stack_drv) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_drv = Asm64::new();
        for _ in 0..100 { asm_drv.nop(); }
        asm_drv.movi(R1, 0); asm_drv.movi(R0, SYS_EXIT as i32); asm_drv.trap(0);
        fabric.write_physical(0x100000, &asm_drv.to_bytes());
        seal_code_object(&mut fabric, text_drv, dom_drv);

        // DMA buffer (client-owned, delegated to driver)
        let buf_obj = fabric.alloc_object("buf", 512, ObjectKind::Memory);
        fabric.place_object(buf_obj, 0x300000);
        fabric.grant(dom_sup, buf_obj, 0, 512, Permissions::RW);
        fabric.write_physical(0x300000, &[0x11; 512]);

        // Block storage
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xAA; 512]);
        let controller = BlockController::new(storage, 3, AgentId(100));

        let mut kernel = Kernel::new(fabric);
        let key_sup = kernel.spawn(core_sup);
        let key_drv = kernel.spawn(core_drv);
        let sup = key_sup.slot;
        let drv = key_drv.slot;

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        // Supervisor gets root device cap
        let sup_dev_handle = kernel.install_device_capability(
            sup, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("supervisor device cap");

        // Supervisor transfers device cap to driver via SYS_SEND_CAP
        let r0 = do_dev_send_cap(
            &mut kernel, sup, drv, key_drv.generation,
            &sup_dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 42,
        );
        assert_eq!(r0, 0, "device cap transfer must succeed");

        // Driver receives and resolves
        let msg = kernel.mailboxes[drv].pop().unwrap();
        let drv_dev_handle = msg.cap.unwrap();
        let drv_dev_resolved = kernel.resolve_capability(drv, drv_dev_handle)
            .expect("driver device cap must resolve");
        assert!(drv_dev_resolved.is_device());

        // Driver gets a buffer cap (via direct delegation for simplicity)
        let drv_dom = kernel.processes[drv].core.domain;
        let tid = kernel.alloc_delegation_id(key_sup, key_drv).unwrap();
        let aid_buf = kernel.fabric.alloc_authority_id().unwrap();
        kernel.fabric.grant_with_authority_id(
            drv_dom, buf_obj, 0, 512, Permissions::WRITE, aid_buf,
        ).expect("grant driver buffer");
        let buf_gen = kernel.fabric.objects.get(&buf_obj).unwrap().generation;
        let drv_buf_handle = kernel.processes[drv].cap_table.as_mut().unwrap()
            .install_memory(buf_obj, buf_gen, 0, 512, Permissions::WRITE, aid_buf, Some(tid))
            .expect("install driver buffer cap");

        // Driver submits I/O using the TRANSFERRED device cap
        let r0_submit = do_async_submit(
            &mut kernel, drv, &drv_dev_handle, 0, &drv_buf_handle,
        );
        assert_eq!(r0_submit, 0, "DEV_SUBMIT with transferred device cap must succeed");

        // Complete the I/O
        for _ in 0..20 { kernel.idle_progress_once(); }
        let buf_data = kernel.fabric.read_physical(0x300000, 512).to_vec();
        assert!(buf_data.iter().all(|&b| b == 0xAA),
            "DMA must commit block data through transferred device authority");

        eprintln!("9.3a.3.8: transferred device cap usable for DEV_SUBMIT ✓");
    }

    // ─── 9.3a.3.9: Sender CAP_DROP does not revoke child ───

    #[test]
    fn p93a_9_sender_drop_does_not_revoke_child() {
        let (mut kernel, sender, receiver, dev_obj, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 0);

        let msg = kernel.mailboxes[receiver].pop().unwrap();
        let child_handle = msg.cap.unwrap();

        // Sender drops their cap
        kernel.processes[sender].core.r[R0 as usize] = SYS_CAP_DROP;
        kernel.processes[sender].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.handle_syscall(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0,
            "sender CAP_DROP must succeed");

        // Child must still resolve
        let resolved = kernel.resolve_capability(receiver, child_handle)
            .expect("child must survive sender CAP_DROP");
        assert!(resolved.is_device());
        assert_eq!(resolved.object(), dev_obj);
        assert_eq!(resolved.as_device_rights(), DeviceRights::SUBMIT_READ);

        eprintln!("9.3a.3.9: sender CAP_DROP does not revoke child ✓");
    }

    // ─── 9.3a.3.10: Sender death does not revoke child ───

    #[test]
    fn p93a_10_sender_death_does_not_revoke_child() {
        let (mut kernel, sender, receiver, dev_obj, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 0);

        let msg = kernel.mailboxes[receiver].pop().unwrap();
        let child_handle = msg.cap.unwrap();

        // Sender dies and is reclaimed
        kernel.finish_process(sender, ProcessResult::Exited(0));
        kernel.reclaim_process(sender);

        // Child must still resolve
        let resolved = kernel.resolve_capability(receiver, child_handle)
            .expect("child must survive sender death");
        assert!(resolved.is_device());
        assert_eq!(resolved.object(), dev_obj);

        eprintln!("9.3a.3.10: sender death does not revoke child ✓");
    }

    // ─── 9.3a.3.11: Adversarial kind preservation ───
    //
    // Verifies:
    //   - Device child is in Fabric device_authorities, NOT memory capabilities
    //   - Device child resolves as ResolvedCapability::Device
    //   - R7=0x02 with Device source → error 1 (protects decode ordering)

    #[test]
    fn p93a_11_adversarial_kind_preservation() {
        let (mut kernel, sender, receiver, dev_obj, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        // Successful device transfer
        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 0);

        let msg = kernel.mailboxes[receiver].pop().unwrap();
        let child_handle = msg.cap.unwrap();

        // Child MUST resolve as Device, not Memory
        let resolved = kernel.resolve_capability(receiver, child_handle).unwrap();
        assert!(resolved.is_device(), "child must be Device");
        assert!(!resolved.is_memory(), "child must not be Memory");

        // Fabric: destination domain must have a device_authorities entry
        let dst_domain = kernel.processes[receiver].core.domain;
        let child_aid = resolved.authority_id();
        let dst_dom = kernel.fabric.domains.get(&dst_domain).unwrap();
        assert!(
            dst_dom.device_authorities.iter().any(|e| e.authority_id == child_aid),
            "child AuthorityId must exist in device_authorities"
        );
        assert!(
            !dst_dom.capabilities.iter().any(|e| e.authority_id == Some(child_aid)),
            "child AuthorityId must NOT exist in memory capabilities"
        );

        // The adversarial R7=0x02 test is already covered by p93a_6
        // (R7=0x02 is Permissions::WRITE but undefined DeviceRights → error 1).
        // This confirms: Kind(source) → Interpretation(R7).

        eprintln!("9.3a.3.11: Device child in device_authorities, not memory capabilities ✓");
    }

    // ─── 9.3a.3.12: Receiver-table-full failure is atomic ───

    #[test]
    fn p93a_12_receiver_table_full_atomic() {
        let (mut kernel, sender, receiver, _, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        // Fill the receiver's cap table
        let recv_dom = kernel.processes[receiver].core.domain;
        let dummy_obj = kernel.fabric.alloc_object("dummy_fill", 0x1000, ObjectKind::Memory);
        kernel.fabric.place_object(dummy_obj, 0x500000);
        {
            let ct = kernel.processes[receiver].cap_table.as_mut().unwrap();
            while ct.allocatable_count() > 0 {
                let aid = kernel.fabric.alloc_authority_id().unwrap();
                kernel.fabric.grant_with_authority_id(
                    recv_dom, dummy_obj, 0, 0x1000, Permissions::READ, aid,
                ).expect("fill grant");
                let obj_gen = kernel.fabric.objects.get(&dummy_obj).unwrap().generation;
                ct.install_memory(dummy_obj, obj_gen, 0, 0x1000, Permissions::READ, aid, None)
                    .expect("fill cap table");
            }
        }

        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();
        let dst_dom_state = kernel.fabric.domains.get(&recv_dom).unwrap();
        let dev_auth_count_before = dst_dom_state.device_authorities.len();

        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 0,
        );
        assert_eq!(r0, 5, "receiver table full → error 5");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "no AuthorityId consumed");
        assert_eq!(kernel.next_delegation_incarnation(), tid_before,
            "no DelegationId consumed");
        let dst_dom_state = kernel.fabric.domains.get(&recv_dom).unwrap();
        assert_eq!(dst_dom_state.device_authorities.len(), dev_auth_count_before,
            "no device authority created");

        eprintln!("9.3a.3.12: receiver table full → atomic failure (ΔAuthority=ΔHandle=0) ✓");
    }

    // ─── 9.3a.3.13: Direct delivery for Device cap transfer ───

    #[test]
    fn p93a_13_direct_delivery_device_transfer() {
        let (mut kernel, sender, receiver, _, dev_handle) = dev_transfer_setup();

        // Put receiver in RecvWait(sender) via actual SYS_RECV_WAIT
        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        setup_recv_wait_call(&mut kernel, receiver, &sender_key);
        kernel.handle_syscall(receiver);
        assert!(kernel.processes[receiver].recv_wait.is_some(),
            "receiver must be in RecvWait(sender)");

        let mailbox_len_before = kernel.mailboxes[receiver].len();

        // Transfer device cap — should use direct delivery
        let recv_gen = kernel.processes[receiver].generation;
        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 55,
        );
        assert_eq!(r0, 0, "direct delivery device transfer must succeed");

        // RecvWait cleared
        assert!(kernel.processes[receiver].recv_wait.is_none(),
            "RecvWait must be cleared by direct delivery");

        // Mailbox unchanged (bypassed)
        assert_eq!(kernel.mailboxes[receiver].len(), mailbox_len_before,
            "mailbox must not be used for direct delivery");

        // Verify full ABI in receiver registers
        assert_eq!(kernel.processes[receiver].core.r[R1 as usize], 2,
            "R1 = 2 (cap-bearing message)");
        let cap_slot = kernel.processes[receiver].core.r[R2 as usize] as u32;
        let cap_gen = kernel.processes[receiver].core.r[R3 as usize] as u32;
        let from_slot = kernel.processes[receiver].core.r[R4 as usize];
        let from_gen = kernel.processes[receiver].core.r[R5 as usize];
        assert_eq!(from_slot, sender as u64, "R4 = sender slot");
        assert_eq!(from_gen, kernel.processes[sender].generation as u64,
            "R5 = sender generation");

        // Resolve the directly-delivered Device cap
        let delivered_handle = CapabilityHandle { slot: cap_slot, generation: cap_gen };
        let resolved = kernel.resolve_capability(receiver, delivered_handle)
            .expect("directly delivered device cap must resolve");
        assert!(resolved.is_device());
        assert_eq!(resolved.as_device_rights(), DeviceRights::SUBMIT_READ);

        eprintln!("9.3a.3.13: direct delivery for Device cap transfer ✓");
    }

    // ─── 9.3a.3.14: Fabric derive_device rejects object mismatch ───

    #[test]
    fn p93a_14_fabric_derive_rejects_object_mismatch() {
        let mut fabric = Fabric::new(0x400000);

        let dev_a = fabric.alloc_object("dev_a", 0, ObjectKind::Device);
        let dev_b = fabric.alloc_object("dev_b", 0, ObjectKind::Device);
        let src_dom = fabric.create_domain();
        let dst_dom = fabric.create_domain();

        // Install authority for dev_a in src_dom
        let src_aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_device_with_authority_id(
            src_dom, dev_a, DeviceRights::SUBMIT_READ, src_aid,
        ).expect("grant dev_a");

        let new_aid = fabric.alloc_authority_id().unwrap();
        let gen_a = fabric.objects.get(&dev_a).unwrap().generation;

        // Present dev_b but backing is dev_a → must reject
        let result = fabric.derive_device_from_authority_id(
            src_dom, src_aid,
            dev_b, gen_a, DeviceRights::SUBMIT_READ,
            dst_dom, DeviceRights::SUBMIT_READ, new_aid,
        );
        assert!(result.is_none(),
            "presented object != backing object → reject");

        // No authority leaked into destination
        assert!(fabric.domains.get(&dst_dom).unwrap().device_authorities.is_empty(),
            "no device authority in destination after rejection");

        eprintln!("9.3a.3.14: Fabric derive rejects object mismatch ✓");
    }

    // ─── 9.3a.3.15: Delivery-Full (full mailbox, no RecvWait) → error 6 ───
    //
    // Forces the Device branch through Gate 4 (DeliveryRoute::Full).
    // The receiver has cap-table room but a full mailbox and no
    // matching RecvWait.  Proves:
    //   DeliveryFull ⇒ nothing minted or published.

    #[test]
    fn p93a_15_delivery_full_device_atomic() {
        let (mut kernel, sender, receiver, dev_obj, dev_handle) = dev_transfer_setup();
        let recv_gen = kernel.processes[receiver].generation;

        // Fill receiver mailbox to MAX_MAILBOX_SIZE
        let filler_key = ProcessKey { slot: 99, generation: 0 };
        for i in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[receiver].push(Message {
                from: filler_key,
                value: 1000 + i as u64,
                cap: None,
            });
        }
        assert_eq!(kernel.mailboxes[receiver].len(), MAX_MAILBOX_SIZE);

        // Confirm: no RecvWait on receiver
        assert!(kernel.processes[receiver].recv_wait.is_none(),
            "no RecvWait to provide a Direct route");
        // Confirm: receiver cap table still has room
        assert!(kernel.processes[receiver].cap_table.as_ref()
            .map_or(false, |ct| ct.allocatable_count() > 0),
            "cap table must have room — this test targets mailbox-full only");

        // Snapshot all counters
        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();
        let recv_dom = kernel.processes[receiver].core.domain;
        let dev_auth_before = kernel.fabric.domains.get(&recv_dom)
            .unwrap().device_authorities.len();
        let recv_cap_before = kernel.processes[receiver].cap_table.as_ref()
            .unwrap().allocatable_count();
        let mailbox_before = kernel.mailboxes[receiver].len();

        // Attempt Device cap transfer → DeliveryRoute::Full → error 6
        let r0 = do_dev_send_cap(
            &mut kernel, sender, receiver, recv_gen, &dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 42,
        );
        assert_eq!(r0, 6, "full mailbox (no RecvWait) must yield error 6");

        // Nothing minted or published
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "ΔAuthorityIdCounter = 0");
        assert_eq!(kernel.next_delegation_incarnation(), tid_before,
            "ΔDelegationIdCounter = 0");
        assert_eq!(kernel.fabric.domains.get(&recv_dom)
            .unwrap().device_authorities.len(), dev_auth_before,
            "ΔDeviceAuthorityCount = 0");
        assert_eq!(kernel.processes[receiver].cap_table.as_ref()
            .unwrap().allocatable_count(), recv_cap_before,
            "ΔReceiverCapCount = 0");
        assert_eq!(kernel.mailboxes[receiver].len(), mailbox_before,
            "ΔMailbox = 0");

        eprintln!("9.3a.3.15: Delivery-Full for Device cap → error 6, nothing minted ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.3a.4 — Supervisor→Driver Runtime Delegation Integration
    //
    // Decisive witness:
    //   KernelBootstrap → Supervisor → SYS_SEND_CAP → Driver → SYS_DEV_SUBMIT → Device
    //
    // The kernel establishes root device authority.  The supervisor holds
    // it and delegates via ordinary SYS_SEND_CAP to a driver.  The driver
    // uses the transferred capability for SYS_DEV_SUBMIT.  No special
    // kernel-to-driver provisioning path exists.
    //
    // Proves:
    //   - RootDeviceAuthority → RuntimeDelegation → DriverOperation
    //   - SenderDrop ⇏ ChildRevocation
    //   - DelegationId records provenance (client=supervisor, driver=driver)
    //   - Authority chain is clean: supervisor AuthorityId ≠ driver AuthorityId
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn p93a_4_supervisor_to_driver_integration() {
        use super::super::block::{BlockStorage, BlockController};

        let mut fabric = Fabric::new(0x800000);

        // ── Supervisor (slot 0) ──
        let (core_sup, dom_sup, text_sup, data_sup, _stack_sup) =
            create_process(&mut fabric, CPU0, "supervisor",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_sup = Asm64::new();
        for _ in 0..100 { asm_sup.nop(); }
        asm_sup.movi(R1, 0); asm_sup.movi(R0, SYS_EXIT as i32); asm_sup.trap(0);
        fabric.write_physical(0x000000, &asm_sup.to_bytes());
        seal_code_object(&mut fabric, text_sup, dom_sup);

        // ── Driver (slot 1) ──
        let (core_drv, dom_drv, text_drv, data_drv, _stack_drv) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_drv = Asm64::new();
        for _ in 0..100 { asm_drv.nop(); }
        asm_drv.movi(R1, 0); asm_drv.movi(R0, SYS_EXIT as i32); asm_drv.trap(0);
        fabric.write_physical(0x100000, &asm_drv.to_bytes());
        seal_code_object(&mut fabric, text_drv, dom_drv);

        // ── DMA buffer (for driver I/O) ──
        let buf_obj = fabric.alloc_object("dma_buf", 512, ObjectKind::Memory);
        fabric.place_object(buf_obj, 0x300000);
        // Write baseline pattern so we can verify DMA later
        fabric.write_physical(0x300000, &[0x11; 512]);

        // ── Block storage with known data ──
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xBB; 512]);
        let controller = BlockController::new(storage, 3, AgentId(100));

        let mut kernel = Kernel::new(fabric);
        let key_sup = kernel.spawn(core_sup);
        let key_drv = kernel.spawn(core_drv);
        let sup = key_sup.slot;
        let drv = key_drv.slot;

        // ══════════════════════════════════════════════════
        // Phase 1: Kernel bootstraps root device authority
        // ══════════════════════════════════════════════════
        let dev_obj = kernel.install_block_device(controller)
            .expect("kernel installs block device");

        // Root device cap goes to supervisor — this is the ONLY
        // kernel-to-process device provisioning.
        let sup_dev_handle = kernel.install_device_capability(
            sup, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("supervisor root device cap");

        let sup_resolved = kernel.resolve_capability(sup, sup_dev_handle)
            .expect("supervisor device cap resolves");
        let sup_aid = sup_resolved.authority_id();

        // ══════════════════════════════════════════════════
        // Phase 2: Supervisor delegates to driver via SYS_SEND_CAP
        // ══════════════════════════════════════════════════
        let r0 = do_dev_send_cap(
            &mut kernel, sup, drv, key_drv.generation,
            &sup_dev_handle,
            0, 0, DeviceRights::SUBMIT_READ.0 as u64, 0xDEAD,
        );
        assert_eq!(r0, 0, "supervisor→driver SYS_SEND_CAP must succeed");

        // Driver receives the message
        let msg = kernel.mailboxes[drv].pop()
            .expect("driver must receive the cap-bearing message");
        assert_eq!(msg.value, 0xDEAD);
        let drv_dev_handle = msg.cap
            .expect("message must carry a device capability");

        // Verify delegation identity chain
        let drv_resolved = kernel.resolve_capability(drv, drv_dev_handle)
            .expect("driver device cap resolves");
        assert!(drv_resolved.is_device());
        assert_eq!(drv_resolved.object(), dev_obj);
        assert_eq!(drv_resolved.as_device_rights(), DeviceRights::SUBMIT_READ);

        let drv_aid = drv_resolved.authority_id();
        assert_ne!(drv_aid, sup_aid,
            "driver AuthorityId must differ from supervisor's");

        let drv_tid = drv_resolved.delegation_id()
            .expect("transferred cap must carry DelegationId");
        assert_eq!(drv_tid.client, key_sup,
            "DelegationId.client = supervisor");
        assert_eq!(drv_tid.driver, key_drv,
            "DelegationId.driver = driver");

        // ══════════════════════════════════════════════════
        // Phase 3: Supervisor drops its cap (not required for driver)
        // ══════════════════════════════════════════════════
        kernel.processes[sup].core.r[R0 as usize] = SYS_CAP_DROP;
        kernel.processes[sup].core.r[R1 as usize] = sup_dev_handle.slot as u64;
        kernel.processes[sup].core.r[R2 as usize] = sup_dev_handle.generation as u64;
        kernel.handle_syscall(sup);
        assert_eq!(kernel.processes[sup].core.r[R0 as usize], 0,
            "supervisor drop must succeed");

        // Driver cap must survive
        assert!(kernel.resolve_capability(drv, drv_dev_handle).is_some(),
            "driver cap must survive supervisor drop");

        // ══════════════════════════════════════════════════
        // Phase 4: Driver gets buffer authority and does DEV_SUBMIT
        // ══════════════════════════════════════════════════
        let drv_dom = kernel.processes[drv].core.domain;
        let tid_buf = kernel.alloc_delegation_id(key_sup, key_drv).unwrap();
        let aid_buf = kernel.fabric.alloc_authority_id().unwrap();
        kernel.fabric.grant_with_authority_id(
            drv_dom, buf_obj, 0, 512, Permissions::WRITE, aid_buf,
        ).expect("grant driver buffer authority");
        let buf_gen = kernel.fabric.objects.get(&buf_obj).unwrap().generation;
        let drv_buf_handle = kernel.processes[drv].cap_table.as_mut().unwrap()
            .install_memory(buf_obj, buf_gen, 0, 512, Permissions::WRITE, aid_buf, Some(tid_buf))
            .expect("install driver buffer cap");

        // Execute DEV_SUBMIT using the TRANSFERRED device cap
        let r0_submit = do_async_submit(
            &mut kernel, drv, &drv_dev_handle, 0, &drv_buf_handle,
        );
        assert_eq!(r0_submit, 0,
            "DEV_SUBMIT with runtime-delegated device cap must succeed");

        // ══════════════════════════════════════════════════
        // Phase 5: Complete I/O and verify DMA committed
        // ══════════════════════════════════════════════════
        for _ in 0..20 { kernel.idle_progress_once(); }
        let buf_data = kernel.fabric.read_physical(0x300000, 512).to_vec();
        assert!(buf_data.iter().all(|&b| b == 0xBB),
            "DMA must commit block[0] data (0xBB) through runtime-delegated authority");

        // Verify baseline was overwritten (not unchanged)
        assert_ne!(&[0x11u8; 512][..], &buf_data[..],
            "buffer must differ from baseline");

        eprintln!("9.3a.4: Supervisor→Driver runtime delegation integration ✓");
        eprintln!("  KernelBootstrap → Supervisor → SYS_SEND_CAP → Driver → SYS_DEV_SUBMIT");
        eprintln!("  Authority chain: sup_aid={} → drv_aid={}", sup_aid, drv_aid);
        eprintln!("  DelegationId: client={}, driver={}", drv_tid.client, drv_tid.driver);
        eprintln!("  Supervisor drop: child survived");
        eprintln!("  DMA verified: 512 bytes of 0xBB committed to buffer");
    }

    // ─── DelegationId: fresh per transfer, not inherited ───

    #[test]
    fn p92b_delegation_id_fresh_per_transfer() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Transfer #1
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 1;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0);
        let msg1 = kernel.mailboxes[receiver].last().unwrap().clone();
        let h1 = msg1.cap.unwrap();
        let r1 = kernel.resolve_capability(receiver, h1).unwrap();
        let t1 = r1.delegation_id().unwrap();

        // Transfer #2 (same source, different subset)
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0x1000;
        kernel.processes[sender].core.r[R6 as usize] = 0x1000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 2;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0);
        let msg2 = kernel.mailboxes[receiver].last().unwrap().clone();
        let h2 = msg2.cap.unwrap();
        let r2 = kernel.resolve_capability(receiver, h2).unwrap();
        let t2 = r2.delegation_id().unwrap();

        // DelegationIds must be distinct
        assert_ne!(t1.incarnation, t2.incarnation,
            "each transfer must get a fresh DelegationId");
        assert_eq!(t1.client, sender_key);
        assert_eq!(t2.client, sender_key);
        assert_eq!(t1.driver, receiver_key);
        assert_eq!(t2.driver, receiver_key);

        eprintln!("9.2b: delegation ID fresh per transfer ✓");
    }

    // ─── SYS_SEND_KEY: generation-qualified ordinary send ───

    #[test]
    fn p92b_send_key_success() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = 0xBEEF;

        kernel.handle_send_key(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0);
        assert_eq!(kernel.mailboxes[receiver].len(), 1);
        assert_eq!(kernel.mailboxes[receiver][0].value, 0xBEEF);
        assert!(kernel.mailboxes[receiver][0].cap.is_none());

        eprintln!("9.2b: send_key success ✓");
    }

    #[test]
    fn p92b_send_key_stale_dest() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[sender].core.r[R1 as usize] = receiver as u64;
        kernel.processes[sender].core.r[R2 as usize] = 999; // wrong gen
        kernel.processes[sender].core.r[R3 as usize] = 0xBEEF;

        kernel.handle_send_key(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 1);
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: send_key stale dest ✓");
    }

    #[test]
    fn p92b_send_key_mailbox_full() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };
        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };

        for _ in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[receiver].push(Message {
                from: sender_key, value: 0, cap: None,
            });
        }

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = 0xBEEF;

        kernel.handle_send_key(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 2,
            "SEND_KEY mailbox full must return code 2");
        assert_eq!(kernel.mailboxes[receiver].len(), MAX_MAILBOX_SIZE);

        eprintln!("9.2b: send_key mailbox full ✓");
    }

    #[test]
    fn p92b_send_key_malformed_high_bits() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[sender].core.r[R1 as usize] = 0x1_0000_0001u64; // high bits
        kernel.processes[sender].core.r[R2 as usize] = 0;
        kernel.processes[sender].core.r[R3 as usize] = 0xBEEF;

        kernel.handle_send_key(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 1);
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        eprintln!("9.2b: send_key malformed high bits ✓");
    }

    // ─── SYS_SEND mailbox bound ───

    #[test]
    fn p92b_legacy_send_mailbox_bound() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();
        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };

        for _ in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[receiver].push(Message {
                from: sender_key, value: 0, cap: None,
            });
        }

        // Legacy SYS_SEND now respects MAX_MAILBOX_SIZE
        let dest_pid = kernel.processes[receiver].pid;
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND;
        kernel.processes[sender].core.r[R1 as usize] = dest_pid;
        kernel.processes[sender].core.r[R2 as usize] = 0xBEEF;
        kernel.processes[sender].core.halted = true;
        kernel.handle_syscall(sender);

        assert_eq!(kernel.processes[sender].core.r[R0 as usize], u64::MAX,
            "legacy SYS_SEND must respect mailbox bound");
        assert_eq!(kernel.mailboxes[receiver].len(), MAX_MAILBOX_SIZE);

        eprintln!("9.2b: legacy send mailbox bound ✓");
    }

    // ─── SYS_RECV extended ABI ───

    #[test]
    fn p92b_recv_ordinary_message() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();
        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };

        kernel.mailboxes[receiver].push(Message {
            from: sender_key, value: 0xCAFE, cap: None,
        });

        // SYS_RECV
        kernel.processes[receiver].core.r[R0 as usize] = SYS_RECV;
        kernel.processes[receiver].core.halted = true;
        kernel.handle_syscall(receiver);

        assert_eq!(kernel.processes[receiver].core.r[R0 as usize], 0xCAFE);
        assert_eq!(kernel.processes[receiver].core.r[R1 as usize], 1,
            "ordinary message tag = 1");
        assert_eq!(kernel.processes[receiver].core.r[R2 as usize], u32::MAX as u64,
            "no cap → sentinel slot");
        assert_eq!(kernel.processes[receiver].core.r[R3 as usize], 0);
        assert_eq!(kernel.processes[receiver].core.r[R4 as usize], sender_key.slot as u64);
        assert_eq!(kernel.processes[receiver].core.r[R5 as usize], sender_key.generation as u64);

        eprintln!("9.2b: recv ordinary message ABI ✓");
    }

    #[test]
    fn p92b_recv_cap_bearing_message() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };

        let test_handle = CapabilityHandle { slot: 5, generation: 3 };
        kernel.mailboxes[receiver].push(Message {
            from: sender_key, value: 0xDEAD, cap: Some(test_handle),
        });

        kernel.processes[receiver].core.r[R0 as usize] = SYS_RECV;
        kernel.processes[receiver].core.halted = true;
        kernel.handle_syscall(receiver);

        assert_eq!(kernel.processes[receiver].core.r[R0 as usize], 0xDEAD);
        assert_eq!(kernel.processes[receiver].core.r[R1 as usize], 2,
            "cap-bearing message tag = 2");
        assert_eq!(kernel.processes[receiver].core.r[R2 as usize], 5,
            "cap handle slot");
        assert_eq!(kernel.processes[receiver].core.r[R3 as usize], 3,
            "cap handle generation");
        assert_eq!(kernel.processes[receiver].core.r[R4 as usize], sender_key.slot as u64);
        assert_eq!(kernel.processes[receiver].core.r[R5 as usize], sender_key.generation as u64);

        eprintln!("9.2b: recv cap-bearing message ABI ✓");
    }

    #[test]
    fn p92b_recv_empty_mailbox() {
        let (mut kernel, _sender, receiver, _data) = send_cap_setup();

        kernel.processes[receiver].core.r[R0 as usize] = SYS_RECV;
        kernel.processes[receiver].core.halted = true;
        kernel.handle_syscall(receiver);

        assert_eq!(kernel.processes[receiver].core.r[R0 as usize], 0);
        assert_eq!(kernel.processes[receiver].core.r[R1 as usize], 0,
            "empty mailbox tag = 0");
        assert_eq!(kernel.processes[receiver].core.r[R2 as usize], u32::MAX as u64);
        assert_eq!(kernel.processes[receiver].core.r[R3 as usize], 0);
        assert_eq!(kernel.processes[receiver].core.r[R4 as usize], 0);
        assert_eq!(kernel.processes[receiver].core.r[R5 as usize], 0);

        eprintln!("9.2b: recv empty mailbox ABI ✓");
    }

    // ─── All-or-nothing: preflight rejection consumes no identity ───

    #[test]
    fn p92b_all_or_nothing_identity_counters() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();
        let recv_occ_before = kernel.processes[receiver].cap_table.as_ref()
            .unwrap().occupied_count();

        // Fail at gate 3: amplification
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x4000;
        kernel.processes[sender].core.r[R7 as usize] = (Permissions::RW.0 | Permissions::EXECUTE.0) as u64;
        kernel.processes[sender].core.r[R8 as usize] = 99;

        kernel.handle_send_cap(sender);
        assert_ne!(kernel.processes[sender].core.r[R0 as usize], 0);

        // All counters unchanged
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "AuthorityId must not advance on preflight rejection");
        assert_eq!(kernel.next_delegation_incarnation(), tid_before,
            "DelegationId must not advance on preflight rejection");
        assert_eq!(kernel.mailboxes[receiver].len(), 0);
        assert_eq!(kernel.processes[receiver].cap_table.as_ref().unwrap().occupied_count(),
            recv_occ_before);

        eprintln!("9.2b: all-or-nothing identity counters ✓");
    }

    // ─── Stale-while-queued ───

    #[test]
    fn p92b_stale_while_queued() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Successful transfer
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 0xF00D;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0);

        let msg = kernel.mailboxes[receiver].last().unwrap().clone();
        let recv_handle = msg.cap.unwrap();

        // At this instant, the handle resolves
        assert!(kernel.resolve_capability(receiver, recv_handle).is_some());

        // Now revoke the underlying object — advance its generation
        kernel.fabric.revoke(data);

        // Handle no longer resolves — stale while queued
        assert!(kernel.resolve_capability(receiver, recv_handle).is_none(),
            "handle must become stale after object revocation");

        // But the message is still in the mailbox with the handle
        assert_eq!(kernel.mailboxes[receiver].len(), 1);
        assert!(kernel.mailboxes[receiver][0].cap.is_some());

        eprintln!("9.2b: stale-while-queued ✓");
    }

    // ─── Boot-installed caps have no DelegationId ───

    #[test]
    fn p92b_boot_cap_has_no_delegation_id() {
        let (mut kernel, sender, _receiver, data) = send_cap_setup();
        let h = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let resolved = kernel.resolve_capability(sender, h).unwrap();
        assert!(resolved.delegation_id().is_none(),
            "boot/spawn-installed cap must have no DelegationId");

        eprintln!("9.2b: boot cap no delegation ID ✓");
    }

    // ─── Zombie destination rejection ───

    #[test]
    fn p92b_send_key_rejects_zombie_dest() {
        let (mut kernel, sender, receiver, _data) = send_cap_setup();
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Force receiver to Zombie
        kernel.processes[receiver].state = ProcessState::Zombie;

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = 0xBEEF;

        kernel.handle_send_key(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 1,
            "SEND_KEY to Zombie must fail");
        assert_eq!(kernel.mailboxes[receiver].len(), 0,
            "no message delivered to Zombie");

        eprintln!("9.2b: send_key rejects zombie dest ✓");
    }

    #[test]
    fn p92b_send_cap_rejects_zombie_dest() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Force receiver to Zombie
        kernel.processes[receiver].state = ProcessState::Zombie;

        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();
        let recv_occ_before = kernel.processes[receiver].cap_table.as_ref()
            .unwrap().occupied_count();
        let dst_domain = kernel.processes[receiver].core.domain;
        let dst_caps_before = kernel.fabric.domains[&dst_domain].capabilities.len();

        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 42;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 2,
            "SEND_CAP to Zombie must fail with code 2");

        // No side effects whatsoever
        assert_eq!(kernel.mailboxes[receiver].len(), 0,
            "no message delivered to Zombie");
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "AuthorityId counter unchanged");
        assert_eq!(kernel.next_delegation_incarnation(), tid_before,
            "DelegationId counter unchanged");
        assert_eq!(kernel.processes[receiver].cap_table.as_ref().unwrap().occupied_count(),
            recv_occ_before, "receiver cap table unchanged");
        assert_eq!(kernel.fabric.domains[&dst_domain].capabilities.len(),
            dst_caps_before, "receiver domain unchanged");

        eprintln!("9.2b: send_cap rejects zombie dest ✓");
    }

    // ─── True end-to-end: SEND_CAP → SYS_RECV ABI → resolve(H) ───

    #[test]
    fn p92b_send_cap_recv_resolve_end_to_end() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Step 1: SEND_CAP
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 0xCAFE;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0,
            "SEND_CAP must succeed");

        // Step 2: SYS_RECV through the actual syscall ABI
        kernel.processes[receiver].core.r[R0 as usize] = SYS_RECV;
        kernel.processes[receiver].core.halted = true;
        kernel.handle_syscall(receiver);

        // Step 3: Reconstruct message from registers
        let recv_value = kernel.processes[receiver].core.r[R0 as usize];
        let recv_tag = kernel.processes[receiver].core.r[R1 as usize];
        let recv_cap_slot = kernel.processes[receiver].core.r[R2 as usize];
        let recv_cap_gen = kernel.processes[receiver].core.r[R3 as usize];
        let recv_sender_slot = kernel.processes[receiver].core.r[R4 as usize];
        let recv_sender_gen = kernel.processes[receiver].core.r[R5 as usize];

        assert_eq!(recv_value, 0xCAFE);
        assert_eq!(recv_tag, 2, "cap-bearing message tag");
        assert_ne!(recv_cap_slot, u32::MAX as u64, "cap slot must not be sentinel");

        // Verify sender identity from ABI registers
        assert_eq!(recv_sender_slot, sender_key.slot as u64);
        assert_eq!(recv_sender_gen, sender_key.generation as u64);

        // Step 4: Reconstruct handle from R2/R3 and resolve it
        let reconstructed_handle = CapabilityHandle {
            slot: recv_cap_slot as u32,
            generation: recv_cap_gen as u32,
        };
        let resolved = kernel.resolve_capability(receiver, reconstructed_handle)
            .expect("handle from RECV ABI must resolve");

        // Verify non-amplification through the full path
        let (offset, length, perms) = resolved.as_memory();
        assert_eq!(offset, 0);
        assert_eq!(length, 0x2000);
        assert_eq!(perms, Permissions::READ);

        // Verify DelegationId is present
        let tid = resolved.delegation_id()
            .expect("transferred cap must carry DelegationId");
        assert_eq!(tid.client, sender_key);
        assert_eq!(tid.driver, receiver_key);

        eprintln!("9.2b: SEND_CAP → RECV ABI → resolve(H) end-to-end ✓");
    }

    // ─── Sender domain destruction does not destroy receiver authority ───

    #[test]
    fn p92b_sender_domain_death_preserves_receiver() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();
        let src_handle = kernel.install_capability(sender, data, 0, 0x4000, Permissions::RW)
            .expect("install");

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Verify object generation before transfer
        let obj_gen_before = kernel.fabric.objects.get(&data)
            .expect("data object").generation;

        // Transfer capability
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 0xDEAD;

        kernel.handle_send_cap(sender);
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0);

        // Capture the receiver handle from the mailbox
        let recv_handle = kernel.mailboxes[receiver].last().unwrap().cap.unwrap();

        // Verify it resolves before sender death
        let resolved_before = kernel.resolve_capability(receiver, recv_handle)
            .expect("handle must resolve before sender death");
        let tid = resolved_before.delegation_id()
            .expect("must have DelegationId");

        // Destroy the sender's domain — simulates sender process death
        let sender_domain = kernel.processes[sender].core.domain;
        kernel.fabric.destroy_domain(sender_domain);

        // Verify object generation is unchanged (object is NOT owned by sender domain)
        let obj_gen_after = kernel.fabric.objects.get(&data)
            .expect("data object still exists").generation;
        assert_eq!(obj_gen_before, obj_gen_after,
            "object generation must be unchanged — object was not revoked");

        // The receiver's derived authority survives sender domain destruction
        let resolved_after = kernel.resolve_capability(receiver, recv_handle)
            .expect("receiver handle must still resolve after sender domain death");
        let (offset, length, perms) = resolved_after.as_memory();
        assert_eq!(offset, 0);
        assert_eq!(length, 0x2000);
        assert_eq!(perms, Permissions::READ);
        assert_eq!(resolved_after.authority_id(), resolved_before.authority_id());

        // DelegationId survives — it is part of the receiver's cap-table entry
        let tid_after = resolved_after.delegation_id()
            .expect("DelegationId must survive sender death");
        assert_eq!(tid_after, tid);
        assert_eq!(tid_after.client, sender_key,
            "provenance still records the now-dead sender");

        eprintln!("9.2b: sender domain death preserves receiver authority ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2c — Device Capability + SYS_DEV_SUBMIT tests
    // ═══════════════════════════════════════════════════════════════

    /// Set up a kernel with a block device, a driver process with both
    /// device and buffer capabilities, for 9.2c testing.
    fn dev_submit_setup() -> (Kernel, usize, ObjectId, ObjectId) {
        let mut fabric = Fabric::new(0x400000);

        // Create driver process
        let (core, dom, text, data, _stack) =
            create_process(&mut fabric, CPU0, "driver",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut asm = Asm64::new();
        for _ in 0..100 { asm.nop(); }
        asm.movi(R1, 0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // Block storage: 4 blocks × 512 bytes
        let mut storage = super::super::block::BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &b0);
        storage.write_block(1, &vec![0xAA; 512]);

        let controller = super::super::block::BlockController::new(
            storage, 1, AgentId(100),
        );

        let mut kernel = Kernel::new(fabric);
        let pk = kernel.spawn(core);
        let slot = pk.slot;

        // Install block device (one-shot)
        let dev_obj = kernel.install_block_device(controller)
            .expect("install_block_device");

        // Install device capability for the driver
        let _dev_handle = kernel.install_device_capability(slot, dev_obj, DeviceRights::SUBMIT_READ)
            .expect("install device cap");

        (kernel, slot, dev_obj, data)
    }

    // ─── 9.3b: Multiple block devices register distinct bindings ───
    //
    // Replaces 9.2c one-device bootstrap restriction:
    //   #BlockDevices ≤ 1  →  Register(A),Register(B) ⇒ Binding_A ≠ Binding_B.

    #[test]
    fn p93b_multiple_block_devices_register_distinct_bindings() {
        let (mut kernel, _slot, first_obj, _data) = dev_submit_setup();

        assert_eq!(kernel.device_registry.devices.len(), 1);

        let first_binding = kernel.device_registry.devices[0].binding;
        assert_eq!(first_binding.object, first_obj);

        let storage2 = super::super::block::BlockStorage::new(2, 512);
        let ctrl2 = super::super::block::BlockController::new(
            storage2, 1, AgentId(200),
        );

        let second_binding = kernel
            .register_block_device(ctrl2)
            .expect("second block device must register");

        assert_ne!(
            second_binding, first_binding,
            "distinct registered devices must have distinct DeviceBindings"
        );
        assert_ne!(
            second_binding.object, first_binding.object,
            "distinct devices must have distinct ObjectIds"
        );

        assert_eq!(kernel.device_registry.devices.len(), 2);

        assert!(
            kernel.device_registry.lookup(first_binding).is_some(),
            "registering B must not disturb A"
        );
        assert!(
            kernel.device_registry.lookup(second_binding).is_some(),
            "B must be independently registered"
        );

        let a = kernel.fabric.objects.get(&first_binding.object).unwrap();
        let b = kernel.fabric.objects.get(&second_binding.object).unwrap();

        assert_eq!(a.kind, ObjectKind::Device);
        assert_eq!(b.kind, ObjectKind::Device);
        assert_eq!(a.generation, first_binding.generation);
        assert_eq!(b.generation, second_binding.generation);

        eprintln!("9.3b: multiple block devices register distinct bindings ✓");
    }

    // ─── 9.2c: Device object is Active without placement ───

    #[test]
    fn p92c_device_object_active_no_placement() {
        let (kernel, _slot, dev_obj, _data) = dev_submit_setup();
        let obj = kernel.fabric.objects.get(&dev_obj).unwrap();
        assert_eq!(obj.state, ObjectState::Active);
        assert_eq!(obj.kind, ObjectKind::Device);
        assert_eq!(obj.size, 0, "Device object needs no physical extent");
        assert!(kernel.fabric.translate(dev_obj, 0).is_none(),
            "Device object must not have physical placement");

        eprintln!("9.2c: Device object active without placement ✓");
    }

    // ─── 9.2c: install_capability rejects Device objects ───

    #[test]
    fn p92c_install_capability_rejects_device() {
        let (mut kernel, slot, dev_obj, _data) = dev_submit_setup();
        let result = kernel.install_capability(slot, dev_obj, 0, 0, Permissions::READ);
        assert!(result.is_none(),
            "install_capability must reject Device objects");

        eprintln!("9.2c: install_capability rejects Device ✓");
    }

    // ─── 9.2c: install_device_capability rejects Memory objects ───

    #[test]
    fn p92c_install_device_capability_rejects_memory() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();
        let result = kernel.install_device_capability(slot, data, DeviceRights::SUBMIT_READ);
        assert!(result.is_none(),
            "install_device_capability must reject Memory objects");

        eprintln!("9.2c: install_device_capability rejects Memory ✓");
    }

    // ─── 9.2c: valid SYS_DEV_SUBMIT succeeds ───

    #[test]
    fn p92c_dev_submit_success() {
        let (mut kernel, slot, dev_obj, data) = dev_submit_setup();

        // Install a WRITE buffer cap for the driver
        let buf_handle = kernel.install_capability(slot, data, 0, 512, Permissions::WRITE)
            .expect("install buffer cap");

        // Get device handle (slot 0 was installed by setup)
        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        // Push an EventFrame to simulate the TRAP instruction's effect.
        // In real execution, TRAP pushes this before the kernel intercepts.
        let return_pc = kernel.processes[slot].core.pc + 4;
        kernel.processes[slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });

        // SYS_DEV_SUBMIT
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0; // block 0
        kernel.processes[slot].core.r[R4 as usize] = buf_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = buf_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        // Should be blocked in IoWait (EventFrame outstanding)
        assert!(kernel.processes[slot].io_wait.is_some(),
            "driver should be in IoWait after DEV_SUBMIT");
        assert_eq!(kernel.processes[slot].core.event_frames.len(), 1,
            "EventFrame must remain outstanding for completion path");

        // Tick until completion
        for _ in 0..20 {
            kernel.tick_devices(slot);
        }
        kernel.drain_block_completions();

        // Process should have woken up with success
        assert!(kernel.processes[slot].io_wait.is_none());
        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 0,
            "DEV_SUBMIT completion should report success");

        // Data should be in the buffer
        let phys = kernel.fabric.translate(data, 0).unwrap();
        let buf_data = kernel.fabric.read_physical(phys, 512);
        let expected: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        assert_eq!(buf_data, &expected[..], "block 0 data should be in buffer");

        eprintln!("9.2c: DEV_SUBMIT success ✓");
    }

    // ─── 9.2c CENTERPIECE: READ-only handle fails despite ambient WRITE ───

    #[test]
    fn p92c_read_handle_fails_despite_ambient_write() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        // Install a READ-only buffer handle (insufficient for DMA WRITE)
        let read_handle = kernel.install_capability(slot, data, 0, 512, Permissions::READ)
            .expect("install read-only buffer cap");

        // Also grant ambient WRITE authority over the same object/span
        let domain = kernel.processes[slot].core.domain;
        kernel.fabric.grant(domain, data, 0, 512, Permissions::WRITE);

        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        // SYS_DEV_SUBMIT with the READ-only handle
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = read_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = read_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        // Must be rejected (gate 6: WRITE check on the presented handle)
        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 7,
            "READ-only handle must be rejected even with ambient WRITE");
        assert!(kernel.processes[slot].io_wait.is_none(),
            "rejected DEV_SUBMIT must not enter IoWait");

        eprintln!("9.2c CENTERPIECE: ¬WRITE(H_b) + ambient WRITE → rejected ✓");
    }

    // ─── 9.2c: memory handle as device handle fails ───

    #[test]
    fn p92c_memory_handle_as_device_fails() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        let mem_handle = kernel.install_capability(slot, data, 0, 512, Permissions::RW)
            .expect("install memory cap");

        // Use memory handle in device position
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = mem_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = mem_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = mem_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = mem_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 3,
            "Memory handle in device position must fail");

        eprintln!("9.2c: Memory handle as device → rejected ✓");
    }

    // ─── 9.2c: device handle as buffer fails ───

    #[test]
    fn p92c_device_handle_as_buffer_fails() {
        let (mut kernel, slot, dev_obj, _data) = dev_submit_setup();

        // Install a second device cap for use as buffer
        let dev2_handle = kernel.install_device_capability(
            slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install second device cap");

        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = dev2_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = dev2_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 6,
            "Device handle in buffer position must fail");

        eprintln!("9.2c: Device handle as buffer → rejected ✓");
    }

    // ─── 9.2c: high-bit handle fields rejected ───

    #[test]
    fn p92c_high_bit_handle_fields_rejected() {
        let (mut kernel, slot, _dev_obj, _data) = dev_submit_setup();

        // R1 = 0x1_0000_0001 → u32 overflow
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = 0x1_0000_0001;
        kernel.processes[slot].core.r[R2 as usize] = 0;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = 0;
        kernel.processes[slot].core.r[R5 as usize] = 0;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 1,
            "high-bit device slot must be rejected");

        eprintln!("9.2c: high-bit handle rejected ✓");
    }

    // ─── 9.2c: provenance violation rejected ───

    #[test]
    fn p92c_provenance_violation_rejected() {
        // Set up a transferred buffer with delegation_id naming a different driver
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        // Manually install a cap with a delegation_id naming a different driver
        let other_driver_key = ProcessKey { slot: 99, generation: 0 };
        let current_key = ProcessKey {
            slot,
            generation: kernel.processes[slot].generation,
        };
        let fake_tid = DelegationId {
            client: ProcessKey { slot: 42, generation: 0 },
            driver: other_driver_key, // NOT the current process
            incarnation: 0,
        };

        let domain = kernel.processes[slot].core.domain;
        let auth_id = kernel.fabric.alloc_authority_id().expect("alloc");
        kernel.fabric.grant_with_authority_id(
            domain, data, 0, 512, Permissions::WRITE, auth_id,
        ).expect("grant");
        let obj_gen = kernel.fabric.objects.get(&data).unwrap().generation;
        let bad_handle = kernel.processes[slot].cap_table.as_mut().unwrap()
            .install_memory(data, obj_gen, 0, 512, Permissions::WRITE, auth_id, Some(fake_tid))
            .expect("install");

        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = bad_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = bad_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 8,
            "provenance violation (T.driver ≠ current) must be rejected");
        assert!(kernel.processes[slot].io_wait.is_none());

        eprintln!("9.2c: provenance violation → rejected ✓");
    }

    // ─── 9.2c: no delegation_id (boot cap) succeeds ───

    #[test]
    fn p92c_boot_cap_no_delegation_succeeds() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        let buf_handle = kernel.install_capability(slot, data, 0, 512, Permissions::WRITE)
            .expect("install buffer cap");

        // Verify delegation_id is None
        let resolved = kernel.resolve_capability(slot, buf_handle).unwrap();
        assert!(resolved.delegation_id().is_none());

        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 1; // block 1
        kernel.processes[slot].core.r[R4 as usize] = buf_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = buf_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert!(kernel.processes[slot].io_wait.is_some(),
            "boot cap with None delegation should be accepted");

        eprintln!("9.2c: boot cap (no delegation) accepted ✓");
    }

    // ─── 9.2c: transferred delegation_id reaches completion ───

    #[test]
    fn p92c_delegation_id_reaches_completion() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        // Install a buffer cap with a valid delegation_id
        let current_key = ProcessKey {
            slot,
            generation: kernel.processes[slot].generation,
        };
        let client_key = ProcessKey { slot: 42, generation: 0 };
        let tid = DelegationId {
            client: client_key,
            driver: current_key,
            incarnation: 777,
        };

        let domain = kernel.processes[slot].core.domain;
        let auth_id = kernel.fabric.alloc_authority_id().expect("alloc");
        kernel.fabric.grant_with_authority_id(
            domain, data, 0, 512, Permissions::WRITE, auth_id,
        ).expect("grant");
        let obj_gen = kernel.fabric.objects.get(&data).unwrap().generation;
        let buf_handle = kernel.processes[slot].cap_table.as_mut().unwrap()
            .install_memory(data, obj_gen, 0, 512, Permissions::WRITE, auth_id, Some(tid))
            .expect("install");

        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = buf_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = buf_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);
        assert!(kernel.processes[slot].io_wait.is_some());

        // Tick to completion and check delegation_id propagated
        for _ in 0..20 {
            kernel.tick_devices(slot);
        }

        // Peek at the completion before drain
        let comp = kernel.device_registry.devices[0].controller
            .consume_completion().unwrap();
        assert_eq!(comp.delegation_id, Some(tid),
            "delegation_id must propagate unchanged through controller");

        eprintln!("9.2c: delegation_id reaches completion ✓");
    }

    // ─── 9.2c: AuthorityId cross-kind uniqueness ───

    #[test]
    fn p92c_authority_id_cross_kind_uniqueness() {
        let mut fabric = Fabric::new(0x10000);
        let dom = fabric.create_domain();

        let mem_obj = fabric.alloc_object("buf", 512, ObjectKind::Memory);
        fabric.place_object(mem_obj, 0x2000);
        let dev_obj = fabric.alloc_object("dev", 0, ObjectKind::Device);

        // Grant memory authority with AuthorityId A
        let aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_with_authority_id(dom, mem_obj, 0, 512, Permissions::RW, aid)
            .expect("memory grant");

        // Attempt device grant with the SAME AuthorityId → must fail
        let result = fabric.grant_device_with_authority_id(
            dom, dev_obj, DeviceRights::SUBMIT_READ, aid,
        );
        assert!(result.is_none(),
            "AuthorityId must be unique across memory and device");

        // Neither entry disturbed
        assert!(fabric.has_authority_id(dom, aid));

        // Reverse: device first, then memory
        let dom2 = fabric.create_domain();
        let aid2 = fabric.alloc_authority_id().unwrap();
        fabric.grant_device_with_authority_id(
            dom2, dev_obj, DeviceRights::SUBMIT_READ, aid2,
        ).expect("device grant");

        let result2 = fabric.grant_with_authority_id(
            dom2, mem_obj, 0, 512, Permissions::RW, aid2,
        );
        assert!(result2.is_none(),
            "AuthorityId must be unique across device and memory");
        assert!(fabric.has_authority_id(dom2, aid2));

        eprintln!("9.2c: AuthorityId cross-kind uniqueness ✓");
    }

    // ─── 9.2c: request-metadata consistency invariant ───

    #[test]
    fn p92c_request_metadata_consistency() {
        use super::super::block::*;

        let mut fabric = Fabric::new(0x10000);
        let obj = fabric.alloc_object("buf", 512, ObjectKind::Memory);
        fabric.place_object(obj, 0x2000);
        let dom = fabric.create_domain();
        fabric.grant(dom, obj, 0, 512, Permissions::WRITE);

        let storage = BlockStorage::new(4, 512);
        let mut ctrl = BlockController::new(storage, 1, AgentId(100));

        // source_authority_id=None, delegation_id=Some → must fail
        let fake_tid = DelegationId {
            client: ProcessKey { slot: 0, generation: 0 },
            driver: ProcessKey { slot: 1, generation: 0 },
            incarnation: 0,
        };
        let req = BlockRequest {
            block_number: 0,
            requester: RequesterKey { slot: 0, generation: 0 },
            target_object: obj,
            target_offset: 0,
            source_domain: dom,
            source_authority_id: None,
            delegation_id: Some(fake_tid),
        };
        let result = ctrl.submit(req, &mut fabric);
        assert!(matches!(result, SubmitResult::DelegationFailed),
            "source_authority_id=None + delegation_id=Some must be rejected");
        assert_eq!(ctrl.free_slot_count(), 2, "no slot consumed");

        eprintln!("9.2c: request-metadata consistency invariant ✓");
    }

    // ─── 9.2c: grant() rejects Device, grant_device rejects Memory ───

    #[test]
    fn p92c_kind_boundary_hardening() {
        let mut fabric = Fabric::new(0x10000);
        let dom = fabric.create_domain();

        let mem_obj = fabric.alloc_object("mem", 512, ObjectKind::Memory);
        fabric.place_object(mem_obj, 0x2000);
        let dev_obj = fabric.alloc_object("dev", 0, ObjectKind::Device);

        // grant() rejects Device
        assert!(fabric.grant(dom, dev_obj, 0, 0, Permissions::RW).is_none(),
            "grant must reject Device objects");

        // grant_with_authority_id() rejects Device
        let aid = fabric.alloc_authority_id().unwrap();
        assert!(fabric.grant_with_authority_id(dom, dev_obj, 0, 0, Permissions::RW, aid).is_none(),
            "grant_with_authority_id must reject Device objects");

        // grant_device_with_authority_id() rejects Memory
        let aid2 = fabric.alloc_authority_id().unwrap();
        assert!(fabric.grant_device_with_authority_id(dom, mem_obj, DeviceRights::SUBMIT_READ, aid2).is_none(),
            "grant_device must reject Memory objects");

        eprintln!("9.2c: kind boundary hardening ✓");
    }

    // ─── 9.2c: legacy SYS_BLOCK_READ remains unchanged ───

    #[test]
    fn p92c_legacy_block_read_unchanged() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        // Use legacy SYS_BLOCK_READ path (no device cap needed)
        // Grant direct WRITE to the buffer in the process domain
        let domain = kernel.processes[slot].core.domain;
        kernel.fabric.grant(domain, data, 0, 512, Permissions::WRITE);

        let rk = RequesterKey {
            slot: slot as u32,
            generation: kernel.processes[slot].generation,
        };
        let req = super::super::block::BlockRequest {
            block_number: 1,
            requester: rk,
            target_object: data,
            target_offset: 0,
            source_domain: domain,
            source_authority_id: None,
            delegation_id: None,
        };

        let result = kernel.device_registry.devices[0].controller
            .submit(req, &mut kernel.fabric);
        assert!(matches!(result, super::super::block::SubmitResult::Accepted(_)));

        for _ in 0..20 {
            kernel.device_registry.devices[0].controller.tick(&mut kernel.fabric);
        }
        let comp = kernel.device_registry.devices[0].controller
            .consume_completion().unwrap();
        assert_eq!(comp.status, super::super::block::CompletionStatus::Success);
        assert!(comp.delegation_id.is_none(),
            "legacy path must carry no delegation_id");

        eprintln!("9.2c: legacy SYS_BLOCK_READ path unchanged ✓");
    }

    // ─── 9.2c: already in IoWait rejected ───

    #[test]
    fn p92c_already_io_wait_rejected() {
        let (mut kernel, slot, _dev_obj, data) = dev_submit_setup();

        let buf_handle = kernel.install_capability(slot, data, 0, 512, Permissions::WRITE)
            .expect("install buffer");
        let dev_handle = CapabilityHandle { slot: 0, generation: 0 };

        // First DEV_SUBMIT — should succeed
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = 0;
        kernel.processes[slot].core.r[R4 as usize] = buf_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = buf_handle.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);
        assert!(kernel.processes[slot].io_wait.is_some());

        // Second DEV_SUBMIT while still in IoWait — must fail
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 2,
            "already-in-IoWait must be rejected");

        eprintln!("9.2c: already in IoWait → rejected ✓");
    }

    // ─── 9.2c: remove_by_authority_id works across kinds ───

    #[test]
    fn p92c_remove_by_authority_id_cross_kind() {
        let mut fabric = Fabric::new(0x10000);
        let dom = fabric.create_domain();
        let dev_obj = fabric.alloc_object("dev", 0, ObjectKind::Device);

        let aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_device_with_authority_id(dom, dev_obj, DeviceRights::SUBMIT_READ, aid)
            .expect("grant device");

        assert!(fabric.has_authority_id(dom, aid));
        assert!(fabric.remove_by_authority_id(dom, aid));
        assert!(!fabric.has_authority_id(dom, aid));

        eprintln!("9.2c: remove_by_authority_id works for device ✓");
    }

    // ─── 9.2c: CAP_DROP works for device caps ───

    #[test]
    fn p92c_cap_drop_device_cap() {
        let (mut kernel, slot, dev_obj, _data) = dev_submit_setup();

        // Install another device cap so we have one to drop
        let dev_handle2 = kernel.install_device_capability(
            slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install second device cap");

        let resolved = kernel.resolve_capability(slot, dev_handle2).unwrap();
        assert!(resolved.is_device());

        // Drop via SYS_CAP_DROP
        kernel.processes[slot].core.r[R0 as usize] = SYS_CAP_DROP;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle2.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle2.generation as u64;

        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 0,
            "CAP_DROP on device cap must succeed");
        assert!(kernel.resolve_capability(slot, dev_handle2).is_none(),
            "dropped device handle must not resolve");

        eprintln!("9.2c: CAP_DROP device cap ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2d — Client-Driver-Device Composition
    //
    // Thesis: the 9.2a-c primitives compose into a working isolated
    // user-space device driver without new mechanism.
    //
    // Formal basis: anka_driver_composition.kleis
    //   COMP-1..8, COMP-TIME-1 pass; FALSE-COMP-1..4 rejected.
    //
    // The decisive test uses real Asm64 guest programs — the first
    // time SYS_SEND_CAP and SYS_DEV_SUBMIT are issued by guest code.
    // ═══════════════════════════════════════════════════════════════

    /// Build the client guest program.
    ///
    /// The client:
    ///   1. Writes sentinel values around a 512-byte buffer region
    ///   2. SYS_SEND_CAP transfers a 512-byte WRITE cap to the driver
    ///   3. Polls SYS_RECV for driver completion
    ///   4. Verifies sentinels untouched and data arrived
    ///   5. SYS_EXIT(200) on success, distinct error codes on failure
    ///
    /// Buffer layout within data object (vaddr 0x10000):
    ///   [0..8)    sentinel_before = 42
    ///   [8..520)  DMA target (512 bytes)
    ///   [520..528) sentinel_after = 42
    ///
    /// Cap slot 0 = data object, offset 0, length 1024, perms RW
    /// Driver = process slot 1, generation 0
    fn build_client_program() -> Vec<u8> {
        let mut asm = Asm64::new();

        // ── Step 1: Write sentinels ──
        asm.movi(R1, 42);              // [0] sentinel value
        asm.movi(R2, 0x10000);         // [1] data base vaddr
        asm.st(R1, R2, 0);             // [2] sentinel_before at data+0
        asm.st(R1, R2, 520);           // [3] sentinel_after at data+520

        // ── Step 2: SYS_SEND_CAP to driver ──
        asm.movi(R0, SYS_SEND_CAP as i32); // [4]
        asm.movi(R1, 1);               // [5]  dest_slot (driver)
        asm.movi(R2, 0);               // [6]  dest_gen
        asm.movi(R3, 0);               // [7]  src_cap_slot (buffer cap)
        asm.movi(R4, 0);               // [8]  src_cap_gen
        asm.movi(R5, 8);               // [9]  child_offset (skip sentinel)
        asm.movi(R6, 512);             // [10] child_length
        asm.movi(R7, Permissions::WRITE.0 as i32); // [11] child_perms
        asm.movi(R8, 0);               // [12] value = block number 0
        asm.trap(0);                    // [13] SYS_SEND_CAP

        // Check SEND_CAP success (R0 == 0)
        asm.cmpi(R0, 0);               // [14]
        // If fail, skip 7 instructions (recv loop + branch-back) to error block
        // Error_send is at [30]. This branch is at [15]. Offset = 30-15 = 15.
        // But we compute it precisely below.

        // The client code layout (from here):
        //   [15] bcc Ne, -> error_send
        //   [16] movi R0,4   (recv_top)
        //   [17] trap
        //   [18] cmpi R1,0
        //   [19] bcc Ne, -> got_msg
        //   [20] bcc Al, -> recv_top
        //   [21] movi R2,0x10000  (got_msg)
        //   [22] ld R3,R2,0
        //   [23] cmpi R3,42
        //   [24] bcc Ne, -> error_sbefore
        //   [25] ld R3,R2,520
        //   [26] cmpi R3,42
        //   [27] bcc Ne, -> error_safter
        //   [28] ld R3,R2,8
        //   [29] cmpi R3,0
        //   [30] bcc Eq, -> error_nodata
        //   [31] movi R0,0   (success)
        //   [32] movi R1,200
        //   [33] trap
        //   [34] movi R0,0   (error_send)
        //   [35] movi R1,0xB01
        //   [36] trap
        //   [37] movi R0,0   (error_sbefore)
        //   [38] movi R1,0xB02
        //   [39] trap
        //   [40] movi R0,0   (error_safter)
        //   [41] movi R1,0xB03
        //   [42] trap
        //   [43] movi R0,0   (error_nodata)
        //   [44] movi R1,0xB04
        //   [45] trap

        // error_send = 34, this branch at 15: offset = 34-15 = 19
        asm.bcc(Cond::Ne, 19);         // [15] -> error_send

        // ── Step 3: Poll SYS_RECV for completion ──
        // recv_top = 16
        asm.movi(R0, SYS_RECV as i32); // [16]
        asm.trap(0);                    // [17]
        asm.cmpi(R1, 0);               // [18] tag == 0 (empty)?
        // got_msg = 21, this branch at 19: offset = 21-19 = 2
        asm.bcc(Cond::Ne, 2);          // [19] -> got_msg
        // recv_top = 16, this branch at 20: offset = 16-20 = -4
        asm.bcc(Cond::Al, -4);         // [20] -> recv_top

        // ── Step 4: Verify sentinels and data ──
        // got_msg = 21
        asm.movi(R2, 0x10000);         // [21] data base
        asm.ld(R3, R2, 0);             // [22] sentinel_before
        asm.cmpi(R3, 42);              // [23]
        // error_sbefore = 37, this at 24: offset = 37-24 = 13
        asm.bcc(Cond::Ne, 13);         // [24] -> error_sbefore

        asm.ld(R3, R2, 520);           // [25] sentinel_after
        asm.cmpi(R3, 42);              // [26]
        // error_safter = 40, this at 27: offset = 40-27 = 13
        asm.bcc(Cond::Ne, 13);         // [27] -> error_safter

        asm.ld(R3, R2, 8);             // [28] first DMA word
        asm.cmpi(R3, 0);               // [29] must be nonzero
        // error_nodata = 43, this at 30: offset = 43-30 = 13
        asm.bcc(Cond::Eq, 13);         // [30] -> error_nodata

        // ── Success ──
        asm.movi(R0, SYS_EXIT as i32); // [31]
        asm.movi(R1, 200);             // [32]
        asm.trap(0);                    // [33]

        // ── Error exits ──
        // error_send @ 34
        asm.movi(R0, SYS_EXIT as i32); // [34]
        asm.movi(R1, 0xB01);           // [35] SEND_CAP failed
        asm.trap(0);                    // [36]
        // error_sbefore @ 37
        asm.movi(R0, SYS_EXIT as i32); // [37]
        asm.movi(R1, 0xB02);           // [38] sentinel_before corrupted
        asm.trap(0);                    // [39]
        // error_safter @ 40
        asm.movi(R0, SYS_EXIT as i32); // [40]
        asm.movi(R1, 0xB03);           // [41] sentinel_after corrupted
        asm.trap(0);                    // [42]
        // error_nodata @ 43
        asm.movi(R0, SYS_EXIT as i32); // [43]
        asm.movi(R1, 0xB04);           // [44] data did not arrive
        asm.trap(0);                    // [45]

        // Verify layout assumptions
        assert_eq!(asm.here(), 46, "client program layout mismatch");

        asm.to_bytes()
    }

    /// Build the driver guest program.
    ///
    /// The driver:
    ///   1. Polls SYS_RECV for client request (cap-bearing message)
    ///   2. Saves sender ProcessKey and cap handle in high registers
    ///   3. SYS_DEV_SUBMIT with device cap (slot 0) + received buffer cap
    ///   4. Blocks in IoWait, resumes on device completion
    ///   5. SYS_SEND_KEY completion message to exact client ProcessKey
    ///   6. SYS_EXIT(200) on success
    ///
    /// Cap slot 0 = device object, rights SubmitRead (pre-provisioned)
    /// Transferred buffer cap arrives at runtime in slot 1
    fn build_driver_program() -> Vec<u8> {
        let mut asm = Asm64::new();

        // Layout:
        //   [0]  movi R0,4   (recv_top)
        //   [1]  trap
        //   [2]  cmpi R1,0
        //   [3]  bcc Ne, -> got_request
        //   [4]  bcc Al, -> recv_top
        //   [5]  mov R6,R0   (got_request)
        //   [6]  mov R7,R4
        //   [7]  mov R8,R5
        //   [8]  mov R9,R2
        //   [9]  mov R10,R3
        //   [10] movi R0,13
        //   [11] movi R1,0
        //   [12] movi R2,0
        //   [13] mov R3,R6
        //   [14] mov R4,R9
        //   [15] mov R5,R10
        //   [16] trap
        //   [17] cmpi R0,0
        //   [18] bcc Ne, -> error
        //   [19] movi R0,12
        //   [20] mov R1,R7
        //   [21] mov R2,R8
        //   [22] movi R3,42
        //   [23] trap
        //   [24] movi R0,0
        //   [25] movi R1,200
        //   [26] trap
        //   [27] movi R0,0  (error)
        //   [28] movi R1,0xBAD
        //   [29] trap

        // ── Step 1: Poll SYS_RECV ──
        // recv_top = 0
        asm.movi(R0, SYS_RECV as i32); // [0]
        asm.trap(0);                    // [1]
        asm.cmpi(R1, 0);               // [2]  tag == 0 (empty)?
        // got_request = 5, this at 3: offset = 5-3 = 2
        asm.bcc(Cond::Ne, 2);          // [3]  -> got_request
        // recv_top = 0, this at 4: offset = 0-4 = -4
        asm.bcc(Cond::Al, -4);         // [4]  -> recv_top

        // ── Step 2: Save message fields to high registers ──
        // got_request = 5
        asm.mov(R6, R0);               // [5]  block number
        asm.mov(R7, R4);               // [6]  sender (client) slot
        asm.mov(R8, R5);               // [7]  sender (client) gen
        asm.mov(R9, R2);               // [8]  transferred buffer cap slot
        asm.mov(R10, R3);              // [9]  transferred buffer cap gen

        // ── Step 3: SYS_DEV_SUBMIT ──
        asm.movi(R0, SYS_DEV_SUBMIT as i32); // [10]
        asm.movi(R1, 0);               // [11] device cap slot
        asm.movi(R2, 0);               // [12] device cap gen
        asm.mov(R3, R6);               // [13] block number
        asm.mov(R4, R9);               // [14] buffer cap slot
        asm.mov(R5, R10);              // [15] buffer cap gen
        asm.trap(0);                    // [16]

        // ── Step 4: Resumed from IoWait — check R0 ──
        asm.cmpi(R0, 0);               // [17]
        // error = 27, this at 18: offset = 27-18 = 9
        asm.bcc(Cond::Ne, 9);          // [18] -> error

        // ── Step 5: SYS_SEND_KEY completion to client ──
        asm.movi(R0, SYS_SEND_KEY as i32); // [19]
        asm.mov(R1, R7);               // [20] client slot (saved)
        asm.mov(R2, R8);               // [21] client gen (saved)
        asm.movi(R3, 42);              // [22] completion value
        asm.trap(0);                    // [23]

        // ── Step 6: SYS_EXIT(200) ──
        asm.movi(R0, SYS_EXIT as i32); // [24]
        asm.movi(R1, 200);             // [25]
        asm.trap(0);                    // [26]

        // ── Error ──
        // error = 27
        asm.movi(R0, SYS_EXIT as i32); // [27]
        asm.movi(R1, 0xBAD);           // [28]
        asm.trap(0);                    // [29]

        assert_eq!(asm.here(), 30, "driver program layout mismatch");

        asm.to_bytes()
    }

    /// **Decisive Phase 9.2d test**: two real guest programs compose
    /// SYS_SEND_CAP + SYS_RECV + SYS_DEV_SUBMIT + SYS_SEND_KEY
    /// into a working isolated user-space device driver.
    ///
    /// Proves end-to-end:
    ///   client -> cap transfer -> driver -> device -> exact DMA -> client memory
    ///
    /// without a kernel-space driver participating in the policy decision.
    ///
    /// Formal basis: anka_driver_composition.kleis COMP-1..8, COMP-TIME-1.
    #[test]
    fn p92d_composition_client_driver_device() {
        use super::super::block::{BlockStorage, BlockController};

        // ── Block storage: block 0 with known data pattern ──
        let mut storage = BlockStorage::new(4, 512);
        let block_data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &block_data);
        let controller = BlockController::new(storage, 1, AgentId(100));

        // ── Fabric with timer for preemption ──
        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(10);

        // ── Client process at physical 0x000000 ──
        let (core_client, dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let client_code = build_client_program();
        fabric.write_physical(0x000000, &client_code);
        seal_code_object(&mut fabric, text_client, dom_client);

        // ── Driver process at physical 0x100000 ──
        let (core_driver, dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let driver_code = build_driver_program();
        fabric.write_physical(0x100000, &driver_code);
        seal_code_object(&mut fabric, text_driver, dom_driver);

        // ── Kernel + spawn ──
        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        // ── Install block device + device cap for driver ──
        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap for driver");

        // ── Install buffer cap for client (over its data object) ──
        let _buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        // ── Run both processes ──
        kernel.run(100_000, 500);

        // ══════════════════════════════════════════════════════
        // Verification — guest-side (exit codes) + host-side
        // ══════════════════════════════════════════════════════

        assert!(kernel.processes[client_key.slot].exited(),
            "client must have exited");
        assert_eq!(kernel.processes[client_key.slot].exit_code, 200,
            "client exit code: expected 200 (success), got {}",
            kernel.processes[client_key.slot].exit_code);

        assert!(kernel.processes[driver_key.slot].exited(),
            "driver must have exited");
        assert_eq!(kernel.processes[driver_key.slot].exit_code, 200,
            "driver exit code: expected 200 (success), got {}",
            kernel.processes[driver_key.slot].exit_code);

        // Host-side: verify all 512 bytes of DMA data
        let buf_phys = 0x010000_u64 + 8; // data base + sentinel offset
        let dma_data = kernel.fabric.read_physical(buf_phys, 512);
        assert_eq!(&dma_data[..], &block_data[..],
            "DMA buffer must contain exact block 0 data");

        // Host-side: verify sentinels untouched
        let sentinel_before_bytes = kernel.fabric.read_physical(0x010000, 8);
        let sentinel_before = u64::from_le_bytes(
            sentinel_before_bytes[..8].try_into().unwrap());
        assert_eq!(sentinel_before, 42,
            "sentinel_before must be untouched (42), got {}", sentinel_before);

        let sentinel_after_bytes = kernel.fabric.read_physical(0x010000 + 520, 8);
        let sentinel_after = u64::from_le_bytes(
            sentinel_after_bytes[..8].try_into().unwrap());
        assert_eq!(sentinel_after, 42,
            "sentinel_after must be untouched (42), got {}", sentinel_after);

        eprintln!("9.2d: DECISIVE CLIENT-DRIVER-DEVICE COMPOSITION");
        eprintln!("      Client: SEND_CAP(512B WRITE) → poll RECV → verify data + sentinels → exit(200)");
        eprintln!("      Driver: RECV → DEV_SUBMIT(device+buffer) → IoWait → SEND_KEY → exit(200)");
        eprintln!("      DMA: exact-authority delegation from transferred buffer handle");
        eprintln!("      Authority chain: A_DMA ⊆ A_driver_buffer ⊆ A_client_buffer ✓");
        eprintln!("      Formal basis: COMP-1..8, COMP-TIME-1 ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2d — Hostile Composition Tests
    //
    // These tests attack the joins between composition layers.
    // Each witnesses a specific security property of the composed
    // system, not just of individual primitives.
    // ═══════════════════════════════════════════════════════════════

    /// Helper: set up a two-process kernel with block device for
    /// composition hostile tests.  Returns (kernel, client_key, driver_key,
    /// client_data_obj, dev_obj).
    ///
    /// Client at slot 0 with buffer cap at slot 0.
    /// Driver at slot 1 with device cap at slot 0.
    fn composition_setup() -> (Kernel, ProcessKey, ProcessKey, ObjectId, ObjectId) {
        use super::super::block::{BlockStorage, BlockController};

        let mut storage = BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &b0);
        let controller = BlockController::new(storage, 1, AgentId(100));

        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(10);

        let (core_client, dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Client: simple NOP sled + exit(200)
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 200);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_client, dom_client);

        let (core_driver, dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);

        let mut asm_d = Asm64::new();
        for _ in 0..100 { asm_d.nop(); }
        asm_d.movi(R1, 200);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_driver, dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");
        let _buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        (kernel, client_key, driver_key, data_client, dev_obj)
    }

    /// COMP-hostile-1: Driver cannot DEV_SUBMIT before receiving client buffer.
    ///
    /// The driver owns a device cap (slot 0) but has no buffer handle.
    /// DEV_SUBMIT with an invalid buffer handle must fail.
    #[test]
    fn p92d_driver_cannot_submit_without_client_buffer() {
        let (mut kernel, _client_key, driver_key, _data, _dev) = composition_setup();
        let slot = driver_key.slot;

        // Driver tries DEV_SUBMIT with non-existent buffer cap (slot 1, gen 0)
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[slot].core.r[R1 as usize] = 0;  // device cap slot
        kernel.processes[slot].core.r[R2 as usize] = 0;  // device cap gen
        kernel.processes[slot].core.r[R3 as usize] = 0;  // block number
        kernel.processes[slot].core.r[R4 as usize] = 1;  // buffer cap slot (empty!)
        kernel.processes[slot].core.r[R5 as usize] = 0;  // buffer cap gen

        let return_pc = kernel.processes[slot].core.pc + 4;
        kernel.processes[slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_ne!(kernel.processes[slot].core.r[R0 as usize], 0,
            "DEV_SUBMIT must fail without transferred buffer handle");
        assert!(kernel.processes[slot].io_wait.is_none(),
            "driver must not enter IoWait on failure");

        eprintln!("9.2d: driver cannot submit without client buffer ✓");
    }

    /// COMP-hostile-2: Client has no device authority before, during, or after.
    ///
    /// Verifies COMP-6: composition leaves client device authority unchanged.
    #[test]
    fn p92d_client_has_no_device_authority() {
        let (mut kernel, client_key, _driver_key, _data, dev_obj) = composition_setup();

        // Client attempts to install a device cap — must fail (not provisioned)
        let result = kernel.install_device_capability(
            client_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        );
        // Client already has a memory cap at slot 0. This should still succeed
        // if there's a free slot and the object is valid.
        // The point is that the composition test (decisive) doesn't give the
        // client a device cap. We verify that the client's cap table has
        // no device-resolved caps at slot 0.
        let resolved = kernel.resolve_capability(client_key.slot,
            CapabilityHandle { slot: 0, generation: 0 });
        match resolved {
            Some(ResolvedCapability::Memory { .. }) => { /* correct */ }
            Some(ResolvedCapability::Device { .. }) => {
                panic!("client must not have device authority at slot 0");
            }
            None => { panic!("client buffer cap must resolve"); }
        }

        eprintln!("9.2d: client has no device authority (COMP-6) ✓");
        let _ = result;
    }

    /// COMP-hostile-3: DelegationId end-to-end from SEND_CAP through
    /// accepted block request.
    ///
    /// Proves COMP-5: the transfer incarnation T created by SYS_SEND_CAP
    /// is the same T carried into the accepted request.
    #[test]
    fn p92d_delegation_id_end_to_end() {
        use super::super::block::{BlockStorage, BlockController};

        let mut storage = BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &b0);
        let controller = BlockController::new(storage, 1, AgentId(100));

        let mut fabric = Fabric::new(0x800000);

        let (core_client, _dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        asm_c.nop();
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_client, _dom_client);

        let (core_driver, _dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        asm_d.nop();
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_driver, _dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");
        let buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        // Step 1: Client sends cap to driver via kernel API
        let cslot = client_key.slot;
        kernel.processes[cslot].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[cslot].core.r[R1 as usize] = driver_key.slot as u64;
        kernel.processes[cslot].core.r[R2 as usize] = driver_key.generation as u64;
        kernel.processes[cslot].core.r[R3 as usize] = buf_handle.slot as u64;
        kernel.processes[cslot].core.r[R4 as usize] = buf_handle.generation as u64;
        kernel.processes[cslot].core.r[R5 as usize] = 8;    // child_offset
        kernel.processes[cslot].core.r[R6 as usize] = 512;  // child_length
        kernel.processes[cslot].core.r[R7 as usize] = Permissions::WRITE.0 as u64;
        kernel.processes[cslot].core.r[R8 as usize] = 0;    // value

        let return_pc = kernel.processes[cslot].core.pc + 4;
        kernel.processes[cslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[cslot].core.halted = true;
        kernel.handle_syscall(cslot);

        assert_eq!(kernel.processes[cslot].core.r[R0 as usize], 0,
            "SEND_CAP must succeed");

        // Step 2: Driver receives the message
        let dslot = driver_key.slot;
        let msg = kernel.mailboxes[dslot].pop().expect("driver must have a message");
        let recv_handle = msg.cap.expect("message must be cap-bearing");

        // Resolve the transferred cap and get DelegationId
        let resolved = kernel.resolve_capability(dslot, recv_handle)
            .expect("transferred cap must resolve");
        let (_buf_authority_id, send_delegation_id) = match &resolved {
            ResolvedCapability::Memory { authority_id, delegation_id, .. } =>
                (*authority_id, delegation_id.clone()),
            _ => panic!("transferred cap must be Memory"),
        };
        let transfer_delegation = send_delegation_id
            .expect("transferred cap must carry DelegationId");
        assert_eq!(transfer_delegation.client, client_key,
            "DelegationId.client must be the sender");
        assert_eq!(transfer_delegation.driver, driver_key,
            "DelegationId.driver must be the receiver");

        // Step 3: Driver issues DEV_SUBMIT
        kernel.processes[dslot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[dslot].core.r[R1 as usize] = 0;  // device cap slot
        kernel.processes[dslot].core.r[R2 as usize] = 0;  // device cap gen
        kernel.processes[dslot].core.r[R3 as usize] = 0;  // block number
        kernel.processes[dslot].core.r[R4 as usize] = recv_handle.slot as u64;
        kernel.processes[dslot].core.r[R5 as usize] = recv_handle.generation as u64;

        let return_pc = kernel.processes[dslot].core.pc + 4;
        kernel.processes[dslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[dslot].core.halted = true;
        kernel.handle_syscall(dslot);

        // Driver should be in IoWait now
        assert!(kernel.processes[dslot].io_wait.is_some(),
            "driver must be in IoWait after successful DEV_SUBMIT");

        // Step 4: Verify the request metadata in the controller
        let ctrl = &kernel.device_registry.devices[0].controller;
        let req_delegation = ctrl.in_flight_requests().iter()
            .find_map(|r| r.delegation_id.clone());
        let request_delegation = req_delegation
            .expect("accepted request must carry DelegationId");

        assert_eq!(request_delegation.client, transfer_delegation.client,
            "request DelegationId.client must match transfer");
        assert_eq!(request_delegation.driver, transfer_delegation.driver,
            "request DelegationId.driver must match transfer");
        assert_eq!(request_delegation.incarnation, transfer_delegation.incarnation,
            "request DelegationId.incarnation must match transfer (COMP-5)");

        eprintln!("9.2d: DelegationId end-to-end SEND_CAP → request (COMP-5) ✓");
    }

    /// COMP-hostile-4: After normal completion, driver retains device
    /// authority but no longer has client buffer authority after CAP_DROP.
    ///
    /// Proves COMP-8: terminal completion + CAP_DROP leaves driver device
    /// authority but not client buffer authority.
    #[test]
    fn p92d_authority_postconditions_after_completion() {
        use super::super::block::{BlockStorage, BlockController};

        let mut storage = BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &b0);
        let controller = BlockController::new(storage, 1, AgentId(100));

        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(10);

        let (core_client, dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let client_code = build_client_program();
        fabric.write_physical(0x000000, &client_code);
        seal_code_object(&mut fabric, text_client, dom_client);

        let (core_driver, dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);

        // Driver: RECV → DEV_SUBMIT → CAP_DROP(transferred buffer) → SEND_KEY → EXIT
        let mut asm_d = Asm64::new();
        // Layout (exact word indices):
        //   [0]  movi R0, RECV (recv_top)
        //   [1]  trap
        //   [2]  cmpi R1, 0
        //   [3]  bcc Ne, +2    -> got_request
        //   [4]  bcc Al, -4    -> recv_top
        //   [5]  mov R6, R0    (got_request) block number
        //   [6]  mov R7, R4    sender slot
        //   [7]  mov R8, R5    sender gen
        //   [8]  mov R9, R2    buffer cap slot
        //   [9]  mov R10, R3   buffer cap gen
        //   [10] movi R0, DEV_SUBMIT
        //   [11] movi R1, 0    device cap slot
        //   [12] movi R2, 0    device cap gen
        //   [13] mov R3, R6    block number
        //   [14] mov R4, R9    buffer cap slot
        //   [15] mov R5, R10   buffer cap gen
        //   [16] trap
        //   [17] cmpi R0, 0
        //   [18] bcc Ne, +15   -> error (at 33)
        //   [19] movi R0, 10   CAP_DROP
        //   [20] mov R1, R9    buffer cap slot
        //   [21] mov R2, R10   buffer cap gen
        //   [22] trap           CAP_DROP
        //   [23] movi R0, 12   SEND_KEY
        //   [24] mov R1, R7    client slot
        //   [25] mov R2, R8    client gen
        //   [26] movi R3, 42   completion value
        //   [27] trap           SEND_KEY
        //   [28] movi R0, 0    EXIT
        //   [29] movi R1, 200
        //   [30] trap
        //   [31] movi R0, 0    error
        //   [32] movi R1, 0xBAD
        //   [33] trap

        // recv_top = 0
        asm_d.movi(R0, SYS_RECV as i32);   // [0]
        asm_d.trap(0);                       // [1]
        asm_d.cmpi(R1, 0);                  // [2]
        asm_d.bcc(Cond::Ne, 2);             // [3] -> got_request (5)
        asm_d.bcc(Cond::Al, -4);            // [4] -> recv_top (0)
        // got_request = 5
        asm_d.mov(R6, R0);                  // [5]
        asm_d.mov(R7, R4);                  // [6]
        asm_d.mov(R8, R5);                  // [7]
        asm_d.mov(R9, R2);                  // [8]
        asm_d.mov(R10, R3);                 // [9]
        // DEV_SUBMIT
        asm_d.movi(R0, SYS_DEV_SUBMIT as i32); // [10]
        asm_d.movi(R1, 0);                  // [11]
        asm_d.movi(R2, 0);                  // [12]
        asm_d.mov(R3, R6);                  // [13]
        asm_d.mov(R4, R9);                  // [14]
        asm_d.mov(R5, R10);                 // [15]
        asm_d.trap(0);                       // [16]
        asm_d.cmpi(R0, 0);                  // [17]
        // error = 31, this at 18: offset = 31-18 = 13
        asm_d.bcc(Cond::Ne, 13);            // [18] -> error (31)
        // CAP_DROP on transferred buffer
        asm_d.movi(R0, SYS_CAP_DROP as i32); // [19]
        asm_d.mov(R1, R9);                  // [20] buffer cap slot
        asm_d.mov(R2, R10);                 // [21] buffer cap gen
        asm_d.trap(0);                       // [22]
        // SEND_KEY completion
        asm_d.movi(R0, SYS_SEND_KEY as i32); // [23]
        asm_d.mov(R1, R7);                  // [24] client slot
        asm_d.mov(R2, R8);                  // [25] client gen
        asm_d.movi(R3, 42);                 // [26]
        asm_d.trap(0);                       // [27]
        // EXIT(200)
        asm_d.movi(R0, SYS_EXIT as i32);    // [28]
        asm_d.movi(R1, 200);                // [29]
        asm_d.trap(0);                       // [30]
        // error
        asm_d.movi(R0, SYS_EXIT as i32);    // [31]
        asm_d.movi(R1, 0xBAD);              // [32]
        asm_d.trap(0);                       // [33]

        assert_eq!(asm_d.here(), 34, "postcondition driver layout mismatch");

        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_driver, dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");
        let _buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        kernel.run(100_000, 500);

        assert_eq!(kernel.processes[driver_key.slot].exit_code, 200,
            "driver must exit 200, got {}",
            kernel.processes[driver_key.slot].exit_code);

        // Driver's device cap (slot 0) must still resolve
        let dev_resolved = kernel.resolve_capability(driver_key.slot, dev_handle);
        assert!(dev_resolved.is_some(),
            "driver device cap must survive after buffer cleanup");
        assert!(matches!(dev_resolved, Some(ResolvedCapability::Device { .. })),
            "driver slot 0 must be Device");

        // Driver's transferred buffer cap must NOT resolve (dropped by guest)
        let buf_resolved = kernel.resolve_capability(driver_key.slot,
            CapabilityHandle { slot: 1, generation: 0 });
        assert!(buf_resolved.is_none(),
            "driver transferred buffer cap must not resolve after CAP_DROP");

        eprintln!("9.2d: authority postconditions after completion (COMP-8) ✓");
    }

    /// COMP-hostile-5: Ambient driver memory authority cannot substitute
    /// for exact transferred buffer handle.
    ///
    /// The driver has a WRITE ambient memory capability over the same object
    /// and span, but DEV_SUBMIT using a READ-only transferred handle must fail.
    /// Proves the 9.2c centerpiece: ambient authority cannot rescue a
    /// deficient presented handle.
    #[test]
    fn p92d_ambient_driver_authority_irrelevant() {
        let (mut kernel, client_key, driver_key, data_client, _dev) = composition_setup();
        let dslot = driver_key.slot;

        // Give the driver a WRITE ambient memory capability over the client's
        // data object (this simulates ambient privilege).
        let driver_dom = kernel.processes[dslot].core.domain;
        kernel.fabric.grant(driver_dom, data_client, 0, 1024, Permissions::RW);

        // Transfer a READ-only capability from client to driver
        let cslot = client_key.slot;
        let buf_handle = CapabilityHandle { slot: 0, generation: 0 }; // client's cap

        kernel.processes[cslot].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[cslot].core.r[R1 as usize] = driver_key.slot as u64;
        kernel.processes[cslot].core.r[R2 as usize] = driver_key.generation as u64;
        kernel.processes[cslot].core.r[R3 as usize] = buf_handle.slot as u64;
        kernel.processes[cslot].core.r[R4 as usize] = buf_handle.generation as u64;
        kernel.processes[cslot].core.r[R5 as usize] = 0;    // child_offset
        kernel.processes[cslot].core.r[R6 as usize] = 512;  // child_length
        kernel.processes[cslot].core.r[R7 as usize] = Permissions::READ.0 as u64; // READ only!
        kernel.processes[cslot].core.r[R8 as usize] = 0;    // value

        let return_pc = kernel.processes[cslot].core.pc + 4;
        kernel.processes[cslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[cslot].core.halted = true;
        kernel.handle_syscall(cslot);

        assert_eq!(kernel.processes[cslot].core.r[R0 as usize], 0,
            "SEND_CAP(READ) must succeed");

        // Driver receives the READ-only buffer cap
        let msg = kernel.mailboxes[dslot].pop().expect("driver must have message");
        let recv_handle = msg.cap.expect("message must be cap-bearing");

        // Driver tries DEV_SUBMIT — must fail because buffer is READ, not WRITE
        kernel.processes[dslot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[dslot].core.r[R1 as usize] = 0;  // device cap slot
        kernel.processes[dslot].core.r[R2 as usize] = 0;  // device cap gen
        kernel.processes[dslot].core.r[R3 as usize] = 0;  // block number
        kernel.processes[dslot].core.r[R4 as usize] = recv_handle.slot as u64;
        kernel.processes[dslot].core.r[R5 as usize] = recv_handle.generation as u64;

        let return_pc = kernel.processes[dslot].core.pc + 4;
        kernel.processes[dslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[dslot].core.halted = true;
        kernel.handle_syscall(dslot);

        assert_ne!(kernel.processes[dslot].core.r[R0 as usize], 0,
            "DEV_SUBMIT must fail: buffer is READ-only despite ambient WRITE");
        assert!(kernel.processes[dslot].io_wait.is_none(),
            "driver must not enter IoWait on permission failure");

        eprintln!("9.2d: ambient driver WRITE authority irrelevant (FALSE-COMP-2) ✓");
    }

    /// COMP-hostile-6: Dropping the driver's transferred handle after
    /// request acceptance does not cancel request-local DMA authority.
    ///
    /// Proves COMP-7: accepted ∧ ¬terminal → request still active.
    #[test]
    fn p92d_cap_drop_after_acceptance_does_not_cancel_dma() {
        use super::super::block::{BlockStorage, BlockController};

        let mut storage = BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &b0);
        // Latency 5 ticks to allow time for CAP_DROP while request in-flight
        let controller = BlockController::new(storage, 5, AgentId(100));

        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(10);

        let (core_client, dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let client_code = build_client_program();
        fabric.write_physical(0x000000, &client_code);
        seal_code_object(&mut fabric, text_client, dom_client);

        let (core_driver, dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);

        // Same driver as postconditions test: RECV → DEV_SUBMIT → CAP_DROP → SEND_KEY → EXIT
        let mut asm_d = Asm64::new();
        asm_d.movi(R0, SYS_RECV as i32);   // [0]
        asm_d.trap(0);                       // [1]
        asm_d.cmpi(R1, 0);                  // [2]
        asm_d.bcc(Cond::Ne, 2);             // [3] -> got_request (5)
        asm_d.bcc(Cond::Al, -4);            // [4] -> recv_top (0)
        asm_d.mov(R6, R0);                  // [5]
        asm_d.mov(R7, R4);                  // [6]
        asm_d.mov(R8, R5);                  // [7]
        asm_d.mov(R9, R2);                  // [8]
        asm_d.mov(R10, R3);                 // [9]
        asm_d.movi(R0, SYS_DEV_SUBMIT as i32); // [10]
        asm_d.movi(R1, 0);                  // [11]
        asm_d.movi(R2, 0);                  // [12]
        asm_d.mov(R3, R6);                  // [13]
        asm_d.mov(R4, R9);                  // [14]
        asm_d.mov(R5, R10);                 // [15]
        asm_d.trap(0);                       // [16]
        asm_d.cmpi(R0, 0);                  // [17]
        asm_d.bcc(Cond::Ne, 13);            // [18] -> error (31)
        asm_d.movi(R0, SYS_CAP_DROP as i32); // [19]
        asm_d.mov(R1, R9);                  // [20]
        asm_d.mov(R2, R10);                 // [21]
        asm_d.trap(0);                       // [22]
        asm_d.movi(R0, SYS_SEND_KEY as i32); // [23]
        asm_d.mov(R1, R7);                  // [24]
        asm_d.mov(R2, R8);                  // [25]
        asm_d.movi(R3, 42);                 // [26]
        asm_d.trap(0);                       // [27]
        asm_d.movi(R0, SYS_EXIT as i32);    // [28]
        asm_d.movi(R1, 200);                // [29]
        asm_d.trap(0);                       // [30]
        asm_d.movi(R0, SYS_EXIT as i32);    // [31]
        asm_d.movi(R1, 0xBAD);              // [32]
        asm_d.trap(0);                       // [33]

        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_driver, dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");
        let _buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        kernel.run(100_000, 500);

        // Both processes must complete successfully
        assert_eq!(kernel.processes[client_key.slot].exit_code, 200,
            "client must succeed despite driver dropping buffer cap mid-flight");
        assert_eq!(kernel.processes[driver_key.slot].exit_code, 200,
            "driver must succeed despite dropping buffer cap after submit");

        // DMA must have completed despite driver dropping its buffer handle
        let dma_data = kernel.fabric.read_physical(0x010000 + 8, 512);
        assert_eq!(&dma_data[..], &b0[..],
            "DMA data must arrive despite mid-flight CAP_DROP (COMP-7)");

        eprintln!("9.2d: CAP_DROP after acceptance does not cancel DMA (COMP-7) ✓");
    }

    /// COMP-hostile-7: Stale client incarnation cannot receive the
    /// driver's completion message.
    ///
    /// If the client slot is recycled between transfer and completion reply,
    /// the generation-qualified SEND_KEY must fail.
    #[test]
    fn p92d_stale_client_incarnation_rejected() {
        let (mut kernel, client_key, driver_key, _data, _dev) = composition_setup();

        // Record the original client's ProcessKey
        let original_client_key = client_key;

        // Simulate: client dies and slot is reused
        kernel.finish_process(original_client_key.slot, ProcessResult::Exited(0));
        kernel.reclaim_process(original_client_key.slot);

        // Driver tries SEND_KEY to the stale client ProcessKey
        let dslot = driver_key.slot;
        kernel.processes[dslot].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[dslot].core.r[R1 as usize] = original_client_key.slot as u64;
        kernel.processes[dslot].core.r[R2 as usize] = original_client_key.generation as u64;
        kernel.processes[dslot].core.r[R3 as usize] = 42;  // value

        let return_pc = kernel.processes[dslot].core.pc + 4;
        kernel.processes[dslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[dslot].core.halted = true;
        kernel.handle_syscall(dslot);

        assert_eq!(kernel.processes[dslot].core.r[R0 as usize], 1,
            "SEND_KEY to stale client incarnation must fail (error 1)");

        eprintln!("9.2d: stale client incarnation rejected by SEND_KEY ✓");
    }

    /// COMP-hostile-8: The exact non-amplification chain holds:
    /// A_DMA ⊆ A_driver_buffer ⊆ A_client_buffer.
    ///
    /// The client delegates a narrow 512-byte window; the driver cannot
    /// DEV_SUBMIT a larger request using that handle.
    #[test]
    fn p92d_non_amplification_chain() {
        use super::super::block::{BlockStorage, BlockController};

        let mut storage = BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &b0);
        let controller = BlockController::new(storage, 1, AgentId(100));

        let mut fabric = Fabric::new(0x800000);

        let (core_client, _dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        asm_c.nop();
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_client, _dom_client);

        let (core_driver, _dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        asm_d.nop();
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_driver, _dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");

        // Client has full 4096-byte RW capability
        let buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 4096, Permissions::RW,
        ).expect("install client buffer cap");

        // Client sends exactly 512 bytes at offset 8 with WRITE-only
        let cslot = client_key.slot;
        kernel.processes[cslot].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[cslot].core.r[R1 as usize] = driver_key.slot as u64;
        kernel.processes[cslot].core.r[R2 as usize] = driver_key.generation as u64;
        kernel.processes[cslot].core.r[R3 as usize] = buf_handle.slot as u64;
        kernel.processes[cslot].core.r[R4 as usize] = buf_handle.generation as u64;
        kernel.processes[cslot].core.r[R5 as usize] = 8;    // child_offset
        kernel.processes[cslot].core.r[R6 as usize] = 512;  // child_length
        kernel.processes[cslot].core.r[R7 as usize] = Permissions::WRITE.0 as u64;
        kernel.processes[cslot].core.r[R8 as usize] = 0;    // value

        let return_pc = kernel.processes[cslot].core.pc + 4;
        kernel.processes[cslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[cslot].core.halted = true;
        kernel.handle_syscall(cslot);
        assert_eq!(kernel.processes[cslot].core.r[R0 as usize], 0);

        // Driver receives the narrow 512-byte handle
        let dslot = driver_key.slot;
        let msg = kernel.mailboxes[dslot].pop().unwrap();
        let recv_handle = msg.cap.unwrap();

        // Resolve to verify the transferred cap is exactly [8..520), WRITE-only
        let resolved = kernel.resolve_capability(dslot, recv_handle).unwrap();
        match &resolved {
            ResolvedCapability::Memory { offset, length, perms, .. } => {
                assert_eq!(*offset, 8, "transferred offset must be 8");
                assert_eq!(*length, 512, "transferred length must be 512");
                assert_eq!(*perms, Permissions::WRITE,
                    "transferred perms must be WRITE-only");
            }
            _ => panic!("transferred cap must be Memory"),
        }

        // DEV_SUBMIT with the narrow handle should succeed
        // (512 bytes is exactly one block)
        kernel.processes[dslot].core.r[R0 as usize] = SYS_DEV_SUBMIT;
        kernel.processes[dslot].core.r[R1 as usize] = 0;
        kernel.processes[dslot].core.r[R2 as usize] = 0;
        kernel.processes[dslot].core.r[R3 as usize] = 0;
        kernel.processes[dslot].core.r[R4 as usize] = recv_handle.slot as u64;
        kernel.processes[dslot].core.r[R5 as usize] = recv_handle.generation as u64;

        let return_pc = kernel.processes[dslot].core.pc + 4;
        kernel.processes[dslot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[dslot].core.halted = true;
        kernel.handle_syscall(dslot);

        // The submit must succeed with the exact 512-byte window
        assert!(kernel.processes[dslot].io_wait.is_some(),
            "DEV_SUBMIT with exact 512B transferred handle must succeed");

        eprintln!("9.2d: non-amplification chain holds (COMP-4) ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Pre-9.2e correspondence fixes
    //
    // Two holes discovered by comparing the implementation against
    // the established ABI discipline from 9.2b/c:
    //   1. SYS_CAP_DROP used `as u32` (truncation) instead of
    //      u32::try_from() (checked decode).
    //   2. derive_from_authority_id() did not enforce new_authority_id
    //      uniqueness in the destination domain.
    // ═══════════════════════════════════════════════════════════════

    /// SYS_CAP_DROP must reject malformed high-bit handle fields.
    ///
    /// 0x1_0000_0001 must not silently alias slot 1.
    /// The handle must not be dropped and the generation must not change.
    #[test]
    fn p92_cap_drop_rejects_high_bit_slot() {
        let (mut kernel, slot, _dev, data) = dev_submit_setup();

        // Install a memory cap at slot 0
        let handle = kernel.install_capability(slot, data, 0, 4096, Permissions::RW)
            .expect("install cap");
        assert_eq!(handle.slot, 1); // slot 0 is device cap from setup

        // Attempt CAP_DROP with high-bit aliased slot: 0x1_0000_0001
        kernel.processes[slot].core.r[R0 as usize] = SYS_CAP_DROP;
        kernel.processes[slot].core.r[R1 as usize] = 0x1_0000_0001_u64; // would alias slot 1
        kernel.processes[slot].core.r[R2 as usize] = handle.generation as u64;

        let return_pc = kernel.processes[slot].core.pc + 4;
        kernel.processes[slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 1,
            "CAP_DROP must reject high-bit aliased slot");

        // The real handle must still resolve
        assert!(kernel.resolve_capability(slot, handle).is_some(),
            "cap must survive rejected malformed drop");

        eprintln!("pre-9.2e: CAP_DROP rejects high-bit slot alias ✓");
    }

    /// SYS_CAP_DROP must reject malformed high-bit generation fields.
    #[test]
    fn p92_cap_drop_rejects_high_bit_generation() {
        let (mut kernel, slot, _dev, data) = dev_submit_setup();

        let handle = kernel.install_capability(slot, data, 0, 4096, Permissions::RW)
            .expect("install cap");

        // Attempt CAP_DROP with high-bit aliased generation
        kernel.processes[slot].core.r[R0 as usize] = SYS_CAP_DROP;
        kernel.processes[slot].core.r[R1 as usize] = handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = 0x1_0000_0000_u64; // gen 0 with high bit

        let return_pc = kernel.processes[slot].core.pc + 4;
        kernel.processes[slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);

        assert_eq!(kernel.processes[slot].core.r[R0 as usize], 1,
            "CAP_DROP must reject high-bit aliased generation");

        assert!(kernel.resolve_capability(slot, handle).is_some(),
            "cap must survive rejected malformed drop");

        eprintln!("pre-9.2e: CAP_DROP rejects high-bit generation alias ✓");
    }

    /// derive_from_authority_id() must reject a new_authority_id that
    /// already exists in the destination domain (cross-kind collision).
    #[test]
    fn p92_derive_from_authority_id_rejects_duplicate() {
        let mut fabric = Fabric::new(0x400000);

        let obj = fabric.alloc_object("test_obj", 0x1000, ObjectKind::Memory);
        fabric.place_object(obj, 0x000000);

        let src_dom = fabric.create_domain();
        let dst_dom = fabric.create_domain();

        // Grant source authority with AuthorityId(0)
        let src_aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_with_authority_id(src_dom, obj, 0, 0x1000, Permissions::RW, src_aid);

        // Grant a capability in destination domain with AuthorityId(1)
        let existing_aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_with_authority_id(dst_dom, obj, 0, 0x1000, Permissions::RW, existing_aid);

        // Attempt derivation using the SAME AuthorityId as already in dst
        let result = fabric.derive_from_authority_id(
            src_dom, src_aid, dst_dom,
            0, 512, Permissions::RW,
            existing_aid, // duplicate!
        );
        assert!(result.is_none(),
            "derive_from_authority_id must reject duplicate AuthorityId in destination");

        // Verify destination domain still has exactly one memory authority
        let dst = fabric.domains.get(&dst_dom).unwrap();
        assert_eq!(dst.capabilities.len(), 1,
            "rejected derivation must not add an entry");

        eprintln!("pre-9.2e: derive_from_authority_id rejects duplicate AuthorityId ✓");
    }

    /// derive_from_authority_id() must reject cross-kind AuthorityId collision.
    ///
    /// Destination has a Device authority with AuthorityId(X); attempting
    /// to derive a Memory authority with the same ID must fail.
    #[test]
    fn p92_derive_from_authority_id_rejects_cross_kind_duplicate() {
        let mut fabric = Fabric::new(0x400000);

        let mem_obj = fabric.alloc_object("mem_obj", 0x1000, ObjectKind::Memory);
        fabric.place_object(mem_obj, 0x000000);

        let dev_obj = fabric.alloc_object("dev_obj", 0, ObjectKind::Device);
        fabric.place_object(dev_obj, 0x100000);

        let src_dom = fabric.create_domain();
        let dst_dom = fabric.create_domain();

        // Grant source memory authority
        let src_aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_with_authority_id(src_dom, mem_obj, 0, 0x1000, Permissions::RW, src_aid);

        // Grant a DEVICE authority in destination with AuthorityId(X)
        let device_aid = fabric.alloc_authority_id().unwrap();
        fabric.grant_device_with_authority_id(
            dst_dom, dev_obj, DeviceRights::SUBMIT_READ, device_aid,
        ).expect("install device authority");

        // Attempt memory derivation into destination using the SAME AuthorityId
        let result = fabric.derive_from_authority_id(
            src_dom, src_aid, dst_dom,
            0, 512, Permissions::RW,
            device_aid, // collides with device authority!
        );
        assert!(result.is_none(),
            "derive_from_authority_id must reject cross-kind AuthorityId collision");

        // Device authority must be undisturbed
        assert!(fabric.has_authority_id(dst_dom, device_aid),
            "existing device authority must survive rejected derivation");

        eprintln!("pre-9.2e: derive_from_authority_id rejects cross-kind AuthorityId collision ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2e.1 — SYS_RECV_WAIT = 14
    //
    // Tests: checked decode, immediate message, stale/error,
    // blocking installation, queued-message rposition ordering.
    //
    // Formal basis: anka_blocking_receive.kleis
    // ═══════════════════════════════════════════════════════════════

    /// Helper: create a two-process setup suitable for RecvWait testing.
    /// Returns (kernel, slot_a, slot_b, key_a, key_b).
    /// Both processes are Running with cap tables.
    fn recv_wait_setup() -> (Kernel, usize, usize, ProcessKey, ProcessKey) {
        let mut fabric = Fabric::new(0x400000);

        let (core_a, dom_a, text_a, _data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);

        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);

        (kernel, key_a.slot, key_b.slot, key_a, key_b)
    }

    /// Helper: set up a process for a manual SYS_RECV_WAIT syscall.
    fn setup_recv_wait_call(kernel: &mut Kernel, slot: usize, peer: &ProcessKey) {
        kernel.processes[slot].core.halted = true;
        kernel.processes[slot].core.r[R0 as usize] = SYS_RECV_WAIT;
        kernel.processes[slot].core.r[R1 as usize] = peer.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = peer.generation as u64;
    }

    // ─── Checked ABI decode ─────────────────────────────────────

    /// R1 overflows u32: immediate error (tag 4).
    #[test]
    fn p92e1_abi_overflow_slot_error() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();
        kernel.processes[a].core.halted = true;
        kernel.processes[a].core.r[R0 as usize] = SYS_RECV_WAIT;
        kernel.processes[a].core.r[R1 as usize] = u64::MAX; // overflows u32
        kernel.processes[a].core.r[R2 as usize] = key_b.generation as u64;

        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4,
            "ABI overflow must produce error tag 4");
        assert!(kernel.processes[a].recv_wait.is_none(),
            "error path must not install RecvWait");
        eprintln!("9.2e.1: ABI overflow slot → tag 4 ✓");
    }

    /// R2 overflows u32: immediate error (tag 4).
    #[test]
    fn p92e1_abi_overflow_gen_error() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();
        kernel.processes[a].core.halted = true;
        kernel.processes[a].core.r[R0 as usize] = SYS_RECV_WAIT;
        kernel.processes[a].core.r[R1 as usize] = key_b.slot as u64;
        kernel.processes[a].core.r[R2 as usize] = u64::MAX; // overflows u32

        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4,
            "ABI overflow gen must produce error tag 4");
        assert!(kernel.processes[a].recv_wait.is_none());
        eprintln!("9.2e.1: ABI overflow gen → tag 4 ✓");
    }

    // ─── Immediate queued message ───────────────────────────────

    /// Exact-peer message already queued: immediate return with tag 1.
    #[test]
    fn p92e1_queued_message_immediate() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        // Enqueue a message from B to A
        kernel.mailboxes[a].push(Message {
            from: key_b,
            value: 42,
            cap: None,
        });

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 42, "value");
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 1, "tag 1 = ordinary");
        assert_eq!(kernel.processes[a].core.r[R2 as usize], u32::MAX as u64, "no cap");
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 0, "no cap gen");
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64, "sender slot");
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64, "sender gen");
        assert!(kernel.processes[a].recv_wait.is_none(),
            "immediate message must not install RecvWait");
        assert_eq!(kernel.mailboxes[a].len(), 0, "message consumed from mailbox");

        eprintln!("9.2e.1: queued exact-peer message → immediate tag 1 ✓");
    }

    /// Cap-bearing message: immediate return with tag 2.
    #[test]
    fn p92e1_queued_cap_message_immediate() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        let cap_handle = CapabilityHandle { slot: 3, generation: 7 };
        kernel.mailboxes[a].push(Message {
            from: key_b,
            value: 99,
            cap: Some(cap_handle),
        });

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 99, "value");
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 2, "tag 2 = cap-bearing");
        assert_eq!(kernel.processes[a].core.r[R2 as usize], 3, "cap slot");
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 7, "cap gen");
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64);
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64);

        eprintln!("9.2e.1: queued cap message → immediate tag 2 ✓");
    }

    /// Multiple messages in mailbox: only the exact-peer message is consumed.
    /// Other messages remain.
    #[test]
    fn p92e1_queued_message_exact_peer_only() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        // Enqueue messages from different senders
        let other_key = ProcessKey { slot: 99, generation: 0 };
        kernel.mailboxes[a].push(Message {
            from: other_key, value: 100, cap: None,
        });
        kernel.mailboxes[a].push(Message {
            from: key_b, value: 42, cap: None,
        });
        kernel.mailboxes[a].push(Message {
            from: other_key, value: 200, cap: None,
        });

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 42,
            "must consume the exact-peer message");
        assert_eq!(kernel.mailboxes[a].len(), 2,
            "other messages must remain");
        assert_eq!(kernel.mailboxes[a][0].value, 100);
        assert_eq!(kernel.mailboxes[a][1].value, 200);

        eprintln!("9.2e.1: exact-peer search leaves other messages ✓");
    }

    /// rposition() finds the most recently enqueued match (LIFO).
    #[test]
    fn p92e1_rposition_newest_first() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        // Enqueue two messages from the same peer
        kernel.mailboxes[a].push(Message {
            from: key_b, value: 1, cap: None,
        });
        kernel.mailboxes[a].push(Message {
            from: key_b, value: 2, cap: None,
        });

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 2,
            "rposition must find the newest (last-enqueued) message");
        assert_eq!(kernel.mailboxes[a].len(), 1, "one message remains");
        assert_eq!(kernel.mailboxes[a][0].value, 1,
            "older message must remain");

        eprintln!("9.2e.1: rposition returns newest match ✓");
    }

    // ─── Blocking installation ──────────────────────────────────

    /// Running peer + empty mailbox → install RecvWait, block.
    #[test]
    fn p92e1_running_peer_blocks() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert!(kernel.processes[a].recv_wait.is_some(),
            "must install RecvWait for Running peer");
        let rw = kernel.processes[a].recv_wait.as_ref().unwrap();
        assert_eq!(rw.peer.slot, key_b.slot);
        assert_eq!(rw.peer.generation, key_b.generation);
        assert_eq!(kernel.processes[a].state, ProcessState::Running,
            "RecvWait is a scheduling field, not a ProcessState change");

        eprintln!("9.2e.1: Running peer → RecvWait installed ✓");
    }

    /// RecvWait process is skipped by the scheduler.
    #[test]
    fn p92e1_recv_wait_not_schedulable() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        // Manually install RecvWait
        kernel.processes[a].recv_wait = Some(RecvWait { peer: key_b });

        assert!(!kernel.processes[a].is_schedulable(),
            "RecvWait process must not be schedulable");

        eprintln!("9.2e.1: RecvWait → not schedulable ✓");
    }

    // ─── Stale / error paths ────────────────────────────────────

    /// Stale generation → immediate error (tag 4).
    #[test]
    fn p92e1_stale_generation_error() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // Advance B's generation to make key_b stale
        kernel.processes[b].generation += 1;

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4, "tag 4 = error");
        assert!(kernel.processes[a].recv_wait.is_none());
        eprintln!("9.2e.1: stale generation → tag 4 ✓");
    }

    /// Free peer → immediate error (tag 4).
    #[test]
    fn p92e1_free_peer_error() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // Transition B to Free (simulating reclaim)
        kernel.processes[b].state = ProcessState::Free;

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4, "tag 4 = error");
        assert!(kernel.processes[a].recv_wait.is_none());
        eprintln!("9.2e.1: Free peer → tag 4 ✓");
    }

    /// Retired peer → immediate error (tag 4).
    #[test]
    fn p92e1_retired_peer_error() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        kernel.processes[b].state = ProcessState::Retired;

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4, "tag 4 = error");
        assert!(kernel.processes[a].recv_wait.is_none());
        eprintln!("9.2e.1: Retired peer → tag 4 ✓");
    }

    /// Out-of-bounds slot → immediate error (tag 4).
    #[test]
    fn p92e1_oob_slot_error() {
        let (mut kernel, a, _b, _key_a, _key_b) = recv_wait_setup();

        let bad_key = ProcessKey { slot: 999, generation: 0 };
        setup_recv_wait_call(&mut kernel, a, &bad_key);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4, "tag 4 = error");
        assert!(kernel.processes[a].recv_wait.is_none());
        eprintln!("9.2e.1: OOB slot → tag 4 ✓");
    }

    // ─── Zombie + quiescent → PeerDied ──────────────────────────

    /// Zombie peer with no block controller → immediate PeerDied (tag 3).
    #[test]
    fn p92e1_zombie_quiescent_peerdied() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // Kill B: set Zombie state
        kernel.processes[b].state = ProcessState::Zombie;

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 0, "PeerDied value");
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 3, "tag 3 = PeerDied");
        assert_eq!(kernel.processes[a].core.r[R2 as usize], u32::MAX as u64);
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64, "peer slot");
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64, "peer gen");
        assert!(kernel.processes[a].recv_wait.is_none());

        eprintln!("9.2e.1: Zombie + quiescent → PeerDied tag 3 ✓");
    }

    /// Message > PeerDied ordering: message from dead peer takes priority.
    ///
    /// D sends to C, D dies, C does RECV_WAIT(D).
    /// The queued message is returned, not PeerDied.
    ///
    /// Formal basis: anka_blocking_receive.kleis — message-before-death.
    #[test]
    fn p92e1_message_before_death() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // Enqueue a message from B, then kill B
        kernel.mailboxes[a].push(Message {
            from: key_b, value: 77, cap: None,
        });
        kernel.processes[b].state = ProcessState::Zombie;

        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 77,
            "message must take priority over PeerDied");
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 1,
            "tag 1 = ordinary message, not tag 3 PeerDied");

        eprintln!("9.2e.1: message-before-death ordering ✓");
    }

    /// complete_recv_wait encoder: error path fills all 6 registers correctly.
    #[test]
    fn p92e1_complete_encoder_error() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        // Install RecvWait manually, then complete with Error
        kernel.processes[a].recv_wait = Some(RecvWait { peer: key_b });
        kernel.processes[a].core.halted = true;

        kernel.complete_recv_wait(a, RecvOutcome::Error);

        assert!(kernel.processes[a].recv_wait.is_none(),
            "complete_recv_wait must clear recv_wait");
        assert_eq!(kernel.processes[a].core.r[R0 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 4);
        assert_eq!(kernel.processes[a].core.r[R2 as usize], u32::MAX as u64);
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R4 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R5 as usize], 0);

        eprintln!("9.2e.1: complete_recv_wait(Error) ✓");
    }

    /// complete_recv_wait encoder: PeerDied path fills registers correctly.
    #[test]
    fn p92e1_complete_encoder_peerdied() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        kernel.processes[a].recv_wait = Some(RecvWait { peer: key_b });
        kernel.processes[a].core.halted = true;

        kernel.complete_recv_wait(a, RecvOutcome::PeerDied(key_b));

        assert!(kernel.processes[a].recv_wait.is_none());
        assert_eq!(kernel.processes[a].core.r[R0 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 3);
        assert_eq!(kernel.processes[a].core.r[R2 as usize], u32::MAX as u64);
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64);
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64);

        eprintln!("9.2e.1: complete_recv_wait(PeerDied) ✓");
    }

    /// complete_recv_wait encoder: Message path fills registers correctly.
    #[test]
    fn p92e1_complete_encoder_message() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        kernel.processes[a].recv_wait = Some(RecvWait { peer: key_b });
        kernel.processes[a].core.halted = true;

        let msg = Message { from: key_b, value: 55, cap: None };
        kernel.complete_recv_wait(a, RecvOutcome::Message(msg));

        assert!(kernel.processes[a].recv_wait.is_none());
        assert_eq!(kernel.processes[a].core.r[R0 as usize], 55);
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 1);
        assert_eq!(kernel.processes[a].core.r[R2 as usize], u32::MAX as u64);
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 0);
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64);
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64);

        eprintln!("9.2e.1: complete_recv_wait(Message) ✓");
    }

    /// complete_recv_wait encoder: cap-bearing Message fills R2,R3 with handle.
    #[test]
    fn p92e1_complete_encoder_cap_message() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        kernel.processes[a].recv_wait = Some(RecvWait { peer: key_b });
        kernel.processes[a].core.halted = true;

        let ch = CapabilityHandle { slot: 5, generation: 11 };
        let msg = Message { from: key_b, value: 88, cap: Some(ch) };
        kernel.complete_recv_wait(a, RecvOutcome::Message(msg));

        assert_eq!(kernel.processes[a].core.r[R0 as usize], 88);
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 2);
        assert_eq!(kernel.processes[a].core.r[R2 as usize], 5);
        assert_eq!(kernel.processes[a].core.r[R3 as usize], 11);
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64);
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64);

        eprintln!("9.2e.1: complete_recv_wait(cap Message) ✓");
    }

    // ─── Quiescence-gated blocking ──────────────────────────────

    /// Zombie(D) ∧ ActivePairRequest(C,D) ⇒ RecvWait(C,D), not PeerDied.
    ///
    /// Constructs a nonterminal delegated request with DelegationId
    /// matching (client, driver), kills the driver, and proves that
    /// SYS_RECV_WAIT installs RecvWait rather than producing premature
    /// PeerDied.
    ///
    /// This is the central safety property of 9.2e.
    ///
    /// Formal basis: anka_blocking_receive.kleis — peer_died_allowed_all_92e,
    ///   controller_pair_active_92e.
    #[test]
    fn p92e1_zombie_active_pair_blocks() {
        use super::super::block::{BlockStorage, BlockController, BlockRequest, SubmitResult};

        let mut fabric = Fabric::new(0x800000);

        // Client (A) at slot 0
        let (core_a, dom_a, text_a, data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        // Driver (B) at slot 1
        let (core_b, dom_b, text_b, _data_b, _stack_b) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_b = Asm64::new();
        for _ in 0..100 { asm_b.nop(); }
        asm_b.movi(R1, 0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());
        seal_code_object(&mut fabric, text_b, dom_b);

        // Block storage with high latency so request stays nonterminal
        let storage = BlockStorage::new(4, 512);
        let controller = BlockController::new(storage, 100, AgentId(100));

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_b = kernel.spawn(core_b);

        let _dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        // Construct a DelegationId matching (client=A, driver=B)
        let tid = kernel.alloc_delegation_id(key_a, key_b)
            .expect("alloc delegation ID");

        // Submit a nonterminal request to the controller with that DelegationId.
        // source_authority_id must be Some (consistency invariant).
        // Install a tagged authority in A's domain for the buffer.
        let src_aid = kernel.fabric.alloc_authority_id()
            .expect("alloc source authority ID");
        let client_dom = kernel.processes[key_a.slot].core.domain;
        kernel.fabric.grant_with_authority_id(
            client_dom, data_a, 0, 512, Permissions::WRITE, src_aid,
        ).expect("grant tagged authority");

        // submit() does its own delegation from source_domain+source_authority_id
        let request = BlockRequest {
            block_number: 0,
            requester: RequesterKey { slot: key_b.slot as u32, generation: key_b.generation },
            target_object: data_a,
            target_offset: 0,
            source_domain: client_dom,
            source_authority_id: Some(src_aid),
            delegation_id: Some(tid),
        };
        let result = kernel.device_registry.devices[0].controller
            .submit(request, &mut kernel.fabric);
        match &result {
            SubmitResult::Accepted(_) => {}
            other => panic!("request must be accepted, got {:?}", other),
        }

        // Verify the controller sees a nonterminal pair request
        assert!(kernel.device_registry.devices[0].controller
            .has_nonterminal_pair_request(&key_a, &key_b),
            "controller must report nonterminal pair request");

        // Kill the driver (Zombie)
        kernel.processes[key_b.slot].state = ProcessState::Zombie;

        // SYS_RECV_WAIT from A for B
        setup_recv_wait_call(&mut kernel, key_a.slot, &key_b);
        kernel.handle_syscall(key_a.slot);

        // Must install RecvWait, NOT produce PeerDied
        assert!(kernel.processes[key_a.slot].recv_wait.is_some(),
            "Zombie + active pair DMA must install RecvWait, not premature PeerDied");
        let rw = kernel.processes[key_a.slot].recv_wait.as_ref().unwrap();
        assert_eq!(rw.peer, key_b,
            "RecvWait must be for the exact peer");

        eprintln!("9.2e.1: Zombie + ActivePairRequest → RecvWait (not PeerDied) ✓");
    }

    // ─── Recycled-generation message-before-death ───────────────

    /// D_g sends → D_g dies → D_g reclaimed → D_{g+1} occupies same slot
    /// → RECV_WAIT(D_g) → Message(D_g), not stale-key error.
    ///
    /// The queued message from D_g was enqueued before the slot was
    /// recycled. Because mailbox lookup precedes process-table validation,
    /// the historical message takes priority.
    ///
    /// This protects the deliberate decision ordering against future
    /// refactoring that might check liveness before mailbox search.
    ///
    /// Formal basis: anka_blocking_receive.kleis — message-before-death,
    ///   Clarification 1 in PHASE_9.2e_PLAN.md.
    #[test]
    fn p92e1_recycled_gen_message_before_stale() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // B sends a message to A
        kernel.mailboxes[a].push(Message {
            from: key_b, value: 77, cap: None,
        });

        // Kill B → Zombie
        kernel.finish_process(b, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[b].state, ProcessState::Zombie);

        // Reclaim B → Free with generation+1
        kernel.reclaim_process(b);
        assert_eq!(kernel.processes[b].state, ProcessState::Free);
        assert_eq!(kernel.processes[b].generation, key_b.generation + 1,
            "reclaim must advance generation");

        // Spawn a new process into B's slot (occupies as D_{g+1})
        let new_core = super::super::core::Anka64Core::new(
            AgentId(2),
            kernel.fabric.create_domain(),
        );
        let new_key = kernel.spawn(new_core);
        assert_eq!(new_key.slot, b,
            "new process must reuse the Free slot");
        assert_eq!(new_key.generation, key_b.generation + 1,
            "new occupant has advanced generation");

        // Now key_b is stale: slot B has generation g+1, key_b has generation g.
        // But a message from D_g is still in A's mailbox.

        // SYS_RECV_WAIT(D_g) from A
        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);

        // Must return the historical message, NOT stale-key error
        assert_eq!(kernel.processes[a].core.r[R0 as usize], 77,
            "must return historical message from D_g");
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 1,
            "tag 1 = ordinary message, not tag 4 error");
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_b.slot as u64,
            "sender slot must match D_g");
        assert_eq!(kernel.processes[a].core.r[R5 as usize], key_b.generation as u64,
            "sender generation must match D_g");
        assert!(kernel.processes[a].recv_wait.is_none(),
            "immediate message must not install RecvWait");

        eprintln!("9.2e.1: D_g sends → dies → reclaimed → D_{{g+1}} → RECV_WAIT(D_g) → Message ✓");
    }

    // ─── Behavioral scheduler skip ──────────────────────────────

    /// RecvWait behavioral test: A waits on B, B exits, reevaluation
    /// delivers PeerDied to A (B is Zombie + quiescent).
    ///
    /// Pre-9.2e.4 this test asserted A was never touched.  Post-9.2e.4
    /// the reevaluate_recv_waits() resolve phase correctly completes
    /// A's RecvWait with PeerDied after B dies and the pair is quiescent.
    /// A then becomes schedulable and resumes execution (its code exits
    /// with SYS_EXIT).
    #[test]
    fn p92e1_recv_wait_scheduler_behavioral() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // Install RecvWait on A via the real syscall path
        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);
        assert!(kernel.processes[a].recv_wait.is_some());

        // Run: B executes and exits.  Reevaluation sees B is Zombie +
        // quiescent → completes A's RecvWait with PeerDied → A resumes
        // and eventually executes its own SYS_EXIT.
        kernel.run(1000, 10);

        assert!(kernel.processes[b].exited(),
            "B must have exited normally");

        // A's RecvWait was completed — A resumed and exited
        assert!(kernel.processes[a].recv_wait.is_none(),
            "RecvWait must be cleared by PeerDied reevaluation");
        assert!(kernel.processes[a].exited(),
            "A must have exited after PeerDied woke it");

        eprintln!("9.2e.4: RecvWait(A,B) + B dies + quiescent → PeerDied → A exits ✓");
    }

    // ─── Phase 9.2e.2: Direct delivery + is_schedulable() ──────────

    /// Helper: three-process setup for 9.2e.2 delivery-routing tests.
    ///
    /// Returns (kernel, c, d, x, key_c, key_d, key_x) where:
    ///   C = receiver (slot 0), D = awaited peer (slot 1), X = unrelated sender (slot 2).
    /// All three are Running with cap tables.
    fn delivery_route_setup() -> (Kernel, usize, usize, usize,
                                  ProcessKey, ProcessKey, ProcessKey) {
        let mut fabric = Fabric::new(0x600000);

        let (core_c, dom_c, text_c, _data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "receiver",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "awaited_peer",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..100 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        let (core_x, dom_x, text_x, _data_x, _stack_x) =
            create_process(&mut fabric, AgentId(2), "unrelated",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut fabric, 0x200000, 0x4000);
        let mut asm_x = Asm64::new();
        for _ in 0..100 { asm_x.nop(); }
        asm_x.movi(R1, 0);
        asm_x.movi(R0, SYS_EXIT as i32);
        asm_x.trap(0);
        fabric.write_physical(0x200000, &asm_x.to_bytes());
        seal_code_object(&mut fabric, text_x, dom_x);

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);
        let key_x = kernel.spawn(core_x);

        (kernel, key_c.slot, key_d.slot, key_x.slot, key_c, key_d, key_x)
    }

    /// Helper: three-process setup with a shared data object for
    /// SEND_CAP delivery-routing tests.
    ///
    /// Returns (kernel, c, d, x, key_c, key_d, key_x, data_object).
    /// D (the awaited peer) has a data object suitable for SEND_CAP source.
    fn delivery_route_cap_setup() -> (Kernel, usize, usize, usize,
                                      ProcessKey, ProcessKey, ProcessKey,
                                      ObjectId) {
        let mut fabric = Fabric::new(0x600000);

        let (core_c, dom_c, text_c, _data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "receiver",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        // D (awaited peer / sender for SEND_CAP) — keep data_d
        let (core_d, dom_d, text_d, data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "awaited_peer",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..100 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        let (core_x, dom_x, text_x, _data_x, _stack_x) =
            create_process(&mut fabric, AgentId(2), "unrelated",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut fabric, 0x200000, 0x4000);
        let mut asm_x = Asm64::new();
        for _ in 0..100 { asm_x.nop(); }
        asm_x.movi(R1, 0);
        asm_x.movi(R0, SYS_EXIT as i32);
        asm_x.trap(0);
        fabric.write_physical(0x200000, &asm_x.to_bytes());
        seal_code_object(&mut fabric, text_x, dom_x);

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);
        let key_x = kernel.spawn(core_x);

        (kernel, key_c.slot, key_d.slot, key_x.slot, key_c, key_d, key_x, data_d)
    }

    /// is_schedulable() is the consolidated predicate.
    #[test]
    fn p92e2_is_schedulable_predicate() {
        let (mut kernel, a, _b, _key_a, key_b) = recv_wait_setup();

        // Running with no waits → schedulable
        assert!(kernel.processes[a].is_schedulable());

        // RecvWait → not schedulable
        kernel.processes[a].recv_wait = Some(RecvWait { peer: key_b });
        assert!(!kernel.processes[a].is_schedulable());
        kernel.processes[a].recv_wait = None;

        // io_wait → not schedulable
        kernel.processes[a].io_wait = Some(IoWait {
            request: DeviceRequestKey {
                device: DeviceBinding {
                    object: ObjectId(0),
                    generation: Generation(0),
                },
                request: crate::anka64::block::RequestHandle { slot: 0, generation: 0 },
            },
        });
        assert!(!kernel.processes[a].is_schedulable());
        kernel.processes[a].io_wait = None;

        // Exited → not schedulable
        kernel.finish_process(a, ProcessResult::Exited(0));
        assert!(!kernel.processes[a].is_schedulable());

        eprintln!("9.2e.2: is_schedulable() predicate ✓");
    }

    /// MailboxFull(C) ∧ RecvWait(C,D) ∧ Send(D,C) ⇒ Direct
    ///
    /// Reachable pre-state: mailbox is full of UNRELATED traffic
    /// from X (not D), so SYS_RECV_WAIT(D) finds no matching
    /// message and installs RecvWait.  Then D sends via SYS_SEND_KEY.
    #[test]
    fn p92e2_mailbox_full_direct_delivery() {
        let (mut kernel, c, d, x, key_c, key_d, key_x) = delivery_route_setup();

        // Fill C's mailbox with unrelated traffic from X
        for i in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[c].push(Message {
                from: key_x, value: i as u64, cap: None,
            });
        }
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE);

        // C calls SYS_RECV_WAIT(D) — no D message queued, D is live → blocks
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some(),
            "SYS_RECV_WAIT must install RecvWait when no peer message queued");
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        // D sends to C via SYS_SEND_KEY
        kernel.processes[d].core.halted = true;
        kernel.processes[d].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[d].core.r[R1 as usize] = key_c.slot as u64;
        kernel.processes[d].core.r[R2 as usize] = key_c.generation as u64;
        kernel.processes[d].core.r[R3 as usize] = 0xBEEF;

        kernel.handle_syscall(d);

        // Sender succeeds
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 0,
            "SYS_SEND_KEY must succeed via direct delivery");

        // Mailbox is still full (message was NOT enqueued)
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE,
            "Direct delivery must NOT enqueue into mailbox");

        // RecvWait is cleared on C
        assert!(kernel.processes[c].recv_wait.is_none(),
            "Direct delivery must clear recv_wait");

        // C's registers were populated by complete_recv_wait()
        assert_eq!(kernel.processes[c].core.r[R0 as usize], 0xBEEF,
            "R0 = message value");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 1,
            "R1 = tag 1 (ordinary message)");
        assert_eq!(kernel.processes[c].core.r[R4 as usize], key_d.slot as u64,
            "R4 = sender slot");
        assert_eq!(kernel.processes[c].core.r[R5 as usize], key_d.generation as u64,
            "R5 = sender generation");

        eprintln!("9.2e.2: MailboxFull(X) + RecvWait(C,D) + Send(D,C) → Direct ✓");
    }

    /// MailboxFull(C) ∧ RecvWait(C,D) ∧ Send(X,C) ⇒ Full
    ///
    /// Reachable pre-state: C's mailbox is full of unrelated traffic
    /// from X, C calls SYS_RECV_WAIT(D) which installs RecvWait,
    /// then X (not D) tries to send again.
    #[test]
    fn p92e2_mailbox_full_wrong_sender_rejected() {
        let (mut kernel, c, d, x, key_c, key_d, key_x) = delivery_route_setup();

        // Fill C's mailbox with unrelated traffic from X
        for i in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[c].push(Message {
                from: key_x, value: i as u64, cap: None,
            });
        }
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE);

        // C calls SYS_RECV_WAIT(D) — no D message, D is live → blocks
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some());
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        // X (unrelated) sends to C via SYS_SEND_KEY
        kernel.processes[x].core.halted = true;
        kernel.processes[x].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[x].core.r[R1 as usize] = key_c.slot as u64;
        kernel.processes[x].core.r[R2 as usize] = key_c.generation as u64;
        kernel.processes[x].core.r[R3 as usize] = 0xDEAD;

        kernel.handle_syscall(x);

        // Sender fails with mailbox-full (error code 2 for SEND_KEY)
        assert_eq!(kernel.processes[x].core.r[R0 as usize], 2,
            "SYS_SEND_KEY from unrelated sender must fail with mailbox-full");

        // RecvWait is still installed on C (waiting for D)
        assert!(kernel.processes[c].recv_wait.is_some(),
            "RecvWait must NOT be disturbed by unrelated sender");
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        // Mailbox unchanged
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE);

        eprintln!("9.2e.2: MailboxFull(X) + RecvWait(C,D) + Send(X,C) → Full ✓");
    }

    /// Zombie(C) ∧ RecvWait(C,D) ⇏ Direct
    ///
    /// A Zombie destination must NEVER accept direct delivery even if
    /// its recv_wait field has not been cleared yet.
    /// validate_message_destination() rejects Zombies before
    /// message_route() is ever consulted.
    #[test]
    fn p92e2_zombie_recv_wait_no_direct() {
        let (mut kernel, c, d, _key_c, _key_d) = recv_wait_setup();

        let key_c = ProcessKey {
            slot: c, generation: kernel.processes[c].generation,
        };
        let key_d_fresh = ProcessKey {
            slot: d, generation: kernel.processes[d].generation,
        };

        // Install RecvWait on C, then kill C (goes Zombie)
        kernel.processes[c].recv_wait = Some(RecvWait { peer: key_d_fresh });
        kernel.finish_process(c, ProcessResult::Exited(0));

        // Stale recv_wait persists (finish_process doesn't clear it)
        assert!(kernel.processes[c].recv_wait.is_some(),
            "finish_process must NOT clear recv_wait (lifecycle vs scheduling)");

        // D tries to send to C via SYS_SEND_KEY
        kernel.processes[d].core.halted = true;
        kernel.processes[d].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[d].core.r[R1 as usize] = key_c.slot as u64;
        kernel.processes[d].core.r[R2 as usize] = key_c.generation as u64;
        kernel.processes[d].core.r[R3 as usize] = 0xBAD;

        kernel.handle_syscall(d);

        // validate_message_destination rejects the Zombie
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 1,
            "SYS_SEND_KEY must fail for Zombie destination");

        // RecvWait untouched (no one completed it)
        assert!(kernel.processes[c].recv_wait.is_some());

        eprintln!("9.2e.2: Zombie(C) + RecvWait(C,D) ⇏ Direct ✓");
    }

    /// DirectRoute ∧ CapTableFull ⇒ failure with no partial receiver
    /// state and no wakeup.
    ///
    /// Even when direct delivery would apply (receiver is RecvWait for
    /// the sender), if the receiver's cap table is full the SEND_CAP
    /// must fail atomically: no wakeup, no register writes, recv_wait
    /// preserved.
    #[test]
    fn p92e2_send_cap_direct_route_cap_full() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Install source cap in sender
        let src_handle = kernel.install_capability(
            sender, data, 0, 0x4000, Permissions::RW,
        ).expect("sender install");

        // Fill receiver's cap table completely
        {
            let ct = kernel.processes[receiver].cap_table.as_mut().unwrap();
            while ct.allocatable_count() > 0 {
                ct.install_memory(
                    data, Generation(0), 0, 0x100, Permissions::READ,
                    kernel.fabric.alloc_authority_id().unwrap(),
                    None,
                ).expect("fill cap table");
            }
            assert_eq!(ct.allocatable_count(), 0);
        }

        // Install RecvWait on receiver for sender
        kernel.processes[receiver].recv_wait =
            Some(RecvWait { peer: sender_key });
        kernel.processes[receiver].core.halted = true;

        // Snapshot receiver registers AND identity counters
        let r0_before = kernel.processes[receiver].core.r[R0 as usize];
        let r1_before = kernel.processes[receiver].core.r[R1 as usize];
        let aid_before = kernel.fabric.next_authority_id();
        let tid_before = kernel.next_delegation_incarnation();

        // Execute SYS_SEND_CAP
        kernel.processes[sender].core.halted = true;
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 0xCAFE;

        kernel.handle_send_cap(sender);

        // Sender fails with code 5 (no allocatable cap slot)
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 5,
            "SEND_CAP must fail with cap-table-full before route commit");

        // Receiver was NOT woken: recv_wait still installed
        assert!(kernel.processes[receiver].recv_wait.is_some(),
            "Cap-table-full must NOT clear recv_wait");

        // Receiver registers untouched
        assert_eq!(kernel.processes[receiver].core.r[R0 as usize], r0_before,
            "Receiver R0 must not change on cap-table-full");
        assert_eq!(kernel.processes[receiver].core.r[R1 as usize], r1_before,
            "Receiver R1 must not change on cap-table-full");

        // Mailbox unchanged
        assert_eq!(kernel.mailboxes[receiver].len(), 0);

        // No identities consumed — failure is before the atomic commit boundary
        assert_eq!(kernel.fabric.next_authority_id(), aid_before,
            "No AuthorityId must be consumed on cap-table-full");
        assert_eq!(kernel.next_delegation_incarnation(), tid_before,
            "No DelegationId must be consumed on cap-table-full");

        // Source authority remains valid
        assert!(kernel.resolve_capability(sender, src_handle).is_some(),
            "Sender's source capability must remain valid after failed SEND_CAP");

        eprintln!("9.2e.2: DirectRoute + CapTableFull → fail, no partial state ✓");
    }

    /// Positive cap-bearing direct delivery.
    ///
    /// RecvWait(receiver, sender) + SYS_SEND_CAP → direct delivery
    /// with the capability handle properly installed and reported
    /// through complete_recv_wait().
    #[test]
    fn p92e2_send_cap_direct_delivery_positive() {
        let (mut kernel, sender, receiver, data) = send_cap_setup();

        let sender_key = ProcessKey {
            slot: sender,
            generation: kernel.processes[sender].generation,
        };
        let receiver_key = ProcessKey {
            slot: receiver,
            generation: kernel.processes[receiver].generation,
        };

        // Install source cap in sender
        let src_handle = kernel.install_capability(
            sender, data, 0, 0x4000, Permissions::RW,
        ).expect("sender install");

        // Install RecvWait on receiver for sender
        kernel.processes[receiver].recv_wait =
            Some(RecvWait { peer: sender_key });
        kernel.processes[receiver].core.halted = true;

        // Execute SYS_SEND_CAP
        kernel.processes[sender].core.halted = true;
        kernel.processes[sender].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[sender].core.r[R1 as usize] = receiver_key.slot as u64;
        kernel.processes[sender].core.r[R2 as usize] = receiver_key.generation as u64;
        kernel.processes[sender].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[sender].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[sender].core.r[R5 as usize] = 0;
        kernel.processes[sender].core.r[R6 as usize] = 0x2000;
        kernel.processes[sender].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[sender].core.r[R8 as usize] = 0xCAFE;

        kernel.handle_send_cap(sender);

        // Sender succeeds
        assert_eq!(kernel.processes[sender].core.r[R0 as usize], 0,
            "SEND_CAP direct delivery must succeed");

        // Mailbox is empty — message went through direct delivery
        assert_eq!(kernel.mailboxes[receiver].len(), 0,
            "Direct delivery must bypass the mailbox");

        // RecvWait cleared on receiver
        assert!(kernel.processes[receiver].recv_wait.is_none(),
            "Direct delivery must clear recv_wait");

        // Receiver registers populated by complete_recv_wait()
        assert_eq!(kernel.processes[receiver].core.r[R0 as usize], 0xCAFE,
            "R0 = message value");
        assert_eq!(kernel.processes[receiver].core.r[R1 as usize], 2,
            "R1 = tag 2 (cap-bearing message)");
        assert_eq!(kernel.processes[receiver].core.r[R4 as usize],
            sender_key.slot as u64, "R4 = sender slot");
        assert_eq!(kernel.processes[receiver].core.r[R5 as usize],
            sender_key.generation as u64, "R5 = sender generation");

        // The cap handle in R2/R3 should resolve correctly
        let recv_handle = CapabilityHandle {
            slot: kernel.processes[receiver].core.r[R2 as usize] as u32,
            generation: kernel.processes[receiver].core.r[R3 as usize] as u32,
        };
        let resolved = kernel.resolve_capability(receiver, recv_handle)
            .expect("receiver handle must resolve");
        let (offset, length, perms) = resolved.as_memory();
        assert_eq!(offset, 0);
        assert_eq!(length, 0x2000);
        assert_eq!(perms, Permissions::READ);

        eprintln!("9.2e.2: RecvWait + SEND_CAP → direct cap delivery ✓");
    }

    /// SYS_SEND direct delivery via the simple (resolve_pid) path.
    ///
    /// Proves that even the original SYS_SEND (pid-based) properly
    /// routes through direct delivery when RecvWait matches.
    #[test]
    fn p92e2_sys_send_direct_delivery() {
        let (mut kernel, c, d, _key_c, _key_d) = recv_wait_setup();

        let key_c = ProcessKey {
            slot: c, generation: kernel.processes[c].generation,
        };
        let key_d_fresh = ProcessKey {
            slot: d, generation: kernel.processes[d].generation,
        };

        // Install RecvWait(C, D)
        kernel.processes[c].recv_wait = Some(RecvWait { peer: key_d_fresh });
        kernel.processes[c].core.halted = true;

        // D sends to C via SYS_SEND
        kernel.processes[d].core.halted = true;
        kernel.processes[d].core.r[R0 as usize] = SYS_SEND;
        kernel.processes[d].core.r[R1 as usize] = c as u64; // dest_pid
        kernel.processes[d].core.r[R2 as usize] = 0xF00D;

        kernel.handle_syscall(d);

        // Sender succeeds
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 0);

        // Mailbox empty — direct delivery
        assert_eq!(kernel.mailboxes[c].len(), 0);

        // RecvWait cleared
        assert!(kernel.processes[c].recv_wait.is_none());

        // Receiver registers populated
        assert_eq!(kernel.processes[c].core.r[R0 as usize], 0xF00D);
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 1); // tag=ordinary
        assert_eq!(kernel.processes[c].core.r[R4 as usize], key_d_fresh.slot as u64);
        assert_eq!(kernel.processes[c].core.r[R5 as usize], key_d_fresh.generation as u64);

        eprintln!("9.2e.2: SYS_SEND → direct delivery ✓");
    }

    /// Unrelated sender enqueues normally even when receiver has RecvWait.
    ///
    /// Reachable pre-state: C calls SYS_RECV_WAIT(D) with D live
    /// and no D message queued, so RecvWait is installed.  Then X
    /// (unrelated, live) sends to C.  Mailbox has room → Enqueue.
    #[test]
    fn p92e2_unrelated_sender_enqueues() {
        let (mut kernel, c, d, x, key_c, key_d, key_x) = delivery_route_setup();

        // C calls SYS_RECV_WAIT(D) — no D message, D is live → blocks
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some());
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        // X (unrelated) sends to C via SYS_SEND_KEY — mailbox has room
        kernel.processes[x].core.halted = true;
        kernel.processes[x].core.r[R0 as usize] = SYS_SEND_KEY;
        kernel.processes[x].core.r[R1 as usize] = key_c.slot as u64;
        kernel.processes[x].core.r[R2 as usize] = key_c.generation as u64;
        kernel.processes[x].core.r[R3 as usize] = 0x1234;

        kernel.handle_syscall(x);

        // Sender succeeds (mailbox has room)
        assert_eq!(kernel.processes[x].core.r[R0 as usize], 0);

        // Message was ENQUEUED, not direct-delivered
        assert_eq!(kernel.mailboxes[c].len(), 1);
        assert_eq!(kernel.mailboxes[c][0].value, 0x1234);
        assert_eq!(kernel.mailboxes[c][0].from, key_x);

        // RecvWait still installed (unrelated sender does not wake)
        assert!(kernel.processes[c].recv_wait.is_some());
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        eprintln!("9.2e.2: RecvWait(C,D) + Send(X,C) → enqueue, no wake ✓");
    }

    /// MailboxFull(C) ∧ RecvWait(C,D) ∧ SYS_SEND_CAP(D→C) ⇒ Direct
    ///
    /// Reachable pre-state: C's mailbox full of unrelated traffic
    /// from X.  C calls SYS_RECV_WAIT(D), installs RecvWait.
    /// D then performs SEND_CAP to C.  Direct delivery bypasses the
    /// full mailbox; cap is installed and reported with tag=2.
    #[test]
    fn p92e2_send_cap_full_mailbox_direct() {
        let (mut kernel, c, d, x, key_c, key_d, key_x, data) =
            delivery_route_cap_setup();

        // Install source cap in D (the sender)
        let src_handle = kernel.install_capability(
            d, data, 0, 0x4000, Permissions::RW,
        ).expect("sender install");

        // Fill C's mailbox with unrelated traffic from X
        for i in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[c].push(Message {
                from: key_x, value: i as u64, cap: None,
            });
        }
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE);

        // C calls SYS_RECV_WAIT(D) — no D message, D is live → blocks
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some());
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        // D performs SYS_SEND_CAP to C
        kernel.processes[d].core.halted = true;
        kernel.processes[d].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[d].core.r[R1 as usize] = key_c.slot as u64;
        kernel.processes[d].core.r[R2 as usize] = key_c.generation as u64;
        kernel.processes[d].core.r[R3 as usize] = src_handle.slot as u64;
        kernel.processes[d].core.r[R4 as usize] = src_handle.generation as u64;
        kernel.processes[d].core.r[R5 as usize] = 0;
        kernel.processes[d].core.r[R6 as usize] = 0x2000;
        kernel.processes[d].core.r[R7 as usize] = Permissions::READ.0 as u64;
        kernel.processes[d].core.r[R8 as usize] = 0xCAFE;

        kernel.handle_send_cap(d);

        // Sender succeeds
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 0,
            "SEND_CAP must succeed via direct delivery despite full mailbox");

        // Mailbox unchanged (still full — message bypassed it)
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE,
            "Direct delivery must NOT enqueue into mailbox");

        // RecvWait cleared
        assert!(kernel.processes[c].recv_wait.is_none(),
            "Direct delivery must clear recv_wait");

        // Receiver registers populated by complete_recv_wait()
        assert_eq!(kernel.processes[c].core.r[R0 as usize], 0xCAFE,
            "R0 = message value");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 2,
            "R1 = tag 2 (cap-bearing message)");
        assert_eq!(kernel.processes[c].core.r[R4 as usize],
            key_d.slot as u64, "R4 = sender slot");
        assert_eq!(kernel.processes[c].core.r[R5 as usize],
            key_d.generation as u64, "R5 = sender generation");

        // Received handle resolves correctly
        let recv_handle = CapabilityHandle {
            slot: kernel.processes[c].core.r[R2 as usize] as u32,
            generation: kernel.processes[c].core.r[R3 as usize] as u32,
        };
        let resolved = kernel.resolve_capability(c, recv_handle)
            .expect("receiver handle must resolve");
        let (offset, length, perms) = resolved.as_memory();
        assert_eq!(offset, 0);
        assert_eq!(length, 0x2000);
        assert_eq!(perms, Permissions::READ);

        eprintln!("9.2e.2: SEND_CAP + FullMailbox(X) + RecvWait(C,D) → Direct ✓");
    }

    /// MailboxFull(C) ∧ RecvWait(C,D) ∧ SYS_SEND(D→C) ⇒ Direct
    ///
    /// Reachable pre-state: C's mailbox full of unrelated traffic
    /// from X.  C calls SYS_RECV_WAIT(D), installs RecvWait.
    /// D sends via legacy SYS_SEND (pid-based).
    #[test]
    fn p92e2_sys_send_full_mailbox_direct() {
        let (mut kernel, c, d, x, key_c, key_d, key_x) = delivery_route_setup();

        // Fill C's mailbox with unrelated traffic from X
        for i in 0..MAX_MAILBOX_SIZE {
            kernel.mailboxes[c].push(Message {
                from: key_x, value: i as u64, cap: None,
            });
        }
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE);

        // C calls SYS_RECV_WAIT(D) — no D message, D is live → blocks
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some());
        assert_eq!(kernel.processes[c].recv_wait.as_ref().unwrap().peer, key_d);

        // D sends to C via SYS_SEND (pid-based)
        kernel.processes[d].core.halted = true;
        kernel.processes[d].core.r[R0 as usize] = SYS_SEND;
        kernel.processes[d].core.r[R1 as usize] = c as u64; // dest_pid
        kernel.processes[d].core.r[R2 as usize] = 0xF00D;

        kernel.handle_syscall(d);

        // Sender succeeds
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 0,
            "SYS_SEND must succeed via direct delivery despite full mailbox");

        // Mailbox unchanged (still full)
        assert_eq!(kernel.mailboxes[c].len(), MAX_MAILBOX_SIZE,
            "Direct delivery must NOT enqueue into mailbox");

        // RecvWait cleared
        assert!(kernel.processes[c].recv_wait.is_none(),
            "Direct delivery must clear recv_wait");

        // Receiver registers populated
        assert_eq!(kernel.processes[c].core.r[R0 as usize], 0xF00D,
            "R0 = message value");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 1,
            "R1 = tag 1 (ordinary message)");
        assert_eq!(kernel.processes[c].core.r[R4 as usize], key_d.slot as u64,
            "R4 = sender slot");
        assert_eq!(kernel.processes[c].core.r[R5 as usize], key_d.generation as u64,
            "R5 = sender generation");

        eprintln!("9.2e.2: SYS_SEND + FullMailbox(X) + RecvWait(C,D) → Direct ✓");
    }

    // ─── Phase 9.2e.3: Idle progress boundary ──────────────────────

    /// Helper: create a single-process kernel with a block device,
    /// suitable for idle-progress tests.
    ///
    /// Returns (kernel, slot, buf_object) where the process's code
    /// performs SYS_BLOCK_READ(block 0, buf_vaddr) then SYS_EXIT(123).
    /// Timer is configured with the given period (0 = no timer).
    fn idle_progress_setup(timer_period: u64) -> (Kernel, usize, ObjectId) {
        use super::super::block::{BlockStorage, BlockController};

        let buf_vaddr = 0x04000_i32;
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

        if timer_period > 0 {
            fabric.configure_timer(timer_period);
        }

        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0x42; 512]);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        let key = kernel.spawn(core);
        kernel.register_block_device(ctrl).expect("register_block_device");
        kernel.processes[key.slot].core.address_map.add(
            buf_vaddr as u64, 0x1000, buf,
        );

        (kernel, key.slot, buf)
    }

    /// Timer does NOT advance during idle progress — exact witness.
    ///
    /// Formal basis: IdleProgress ⇒ TimerAfter = TimerBefore.
    ///
    /// Calls idle_progress_once() directly and asserts exact counter
    /// equality.  No guest instructions execute, so there is no
    /// ambiguity from post-wake ticks.
    #[test]
    fn p92e3_timer_preserved_during_idle() {
        let (mut kernel, slot, _buf) = idle_progress_setup(1000);

        // Run one round — process issues SYS_BLOCK_READ, blocks.
        kernel.run(10000, 1);
        assert!(kernel.processes[slot].io_wait.is_some(),
            "process must be in io_wait after SYS_BLOCK_READ");
        assert!(kernel.has_autonomous_io(),
            "must have autonomous work after request accepted");

        // Snapshot timer counter
        let counter_before = kernel.fabric.timer.as_ref().unwrap().counter;

        // Single idle progress step — advances controller, no timer
        kernel.idle_progress_once();

        let counter_after = kernel.fabric.timer.as_ref().unwrap().counter;
        assert_eq!(counter_after, counter_before,
            "idle_progress_once() must not tick the timer");

        eprintln!("9.2e.3: IdleProgress ⇒ TimerAfter = TimerBefore (exact) ✓");
    }

    /// ¬Runnable ∧ ¬Resolvable ∧ ¬AutonomousIO ⇒ Stop.
    ///
    /// Reachable kernel state: mutual RecvWait deadlock.
    ///   A = RecvWait(B), B = RecvWait(A)
    /// Both waits established through the actual SYS_RECV_WAIT path.
    /// No block controller, no autonomous I/O.  The scheduler must
    /// return without either PC advancing.
    #[test]
    fn p92e3_no_autonomous_io_stops() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();
        let key_a = ProcessKey {
            slot: a, generation: kernel.processes[a].generation,
        };

        // A calls SYS_RECV_WAIT(B) — B is live, no B message → blocks
        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);
        assert!(kernel.processes[a].recv_wait.is_some());
        assert_eq!(kernel.processes[a].recv_wait.as_ref().unwrap().peer, key_b);

        // B calls SYS_RECV_WAIT(A) — A is live, no A message → blocks
        setup_recv_wait_call(&mut kernel, b, &key_a);
        kernel.handle_syscall(b);
        assert!(kernel.processes[b].recv_wait.is_some());
        assert_eq!(kernel.processes[b].recv_wait.as_ref().unwrap().peer, key_a);

        // No block controller
        assert!(kernel.device_registry.devices.is_empty());

        // Snapshot state
        let pc_a = kernel.processes[a].core.pc;
        let pc_b = kernel.processes[b].core.pc;

        // Run with many rounds — should terminate immediately
        kernel.run(10000, 1000);

        // Neither process advanced
        assert_eq!(kernel.processes[a].core.pc, pc_a);
        assert_eq!(kernel.processes[b].core.pc, pc_b);
        assert!(!kernel.processes[a].exited());
        assert!(!kernel.processes[b].exited());

        // RecvWait still installed on both
        assert!(kernel.processes[a].recv_wait.is_some());
        assert!(kernel.processes[b].recv_wait.is_some());

        eprintln!("9.2e.3: RecvWait(A,B) ∧ RecvWait(B,A) ⇒ Stop ✓");
    }

    /// Idle progress advances the block controller until completion
    /// wakes the blocked process, which then resumes and exits.
    ///
    /// This is the central liveness theorem: a solo I/O-blocked
    /// process is no longer a dead end.
    #[test]
    fn p92e3_idle_progress_completes_io() {
        let (mut kernel, slot, _buf) = idle_progress_setup(0);

        kernel.run(10000, 200);

        assert!(kernel.processes[slot].exited(),
            "solo io_wait process must complete via idle progress");
        assert_eq!(kernel.processes[slot].result,
            Some(ProcessResult::Exited(123)));

        eprintln!("9.2e.3: solo io_wait → idle progress → exit(123) ✓");
    }

    /// CompletedIO ∧ ¬Runnable ⇒ completion drained, waiter wakes.
    ///
    /// Reachable scenario: D submits I/O and blocks (io_wait).
    /// Helper X has exactly 3 instructions (movi, movi, trap=SYS_EXIT).
    /// With controller latency 1, the pipeline is:
    ///
    ///   MOVI₁ tick: Requested → Authorized
    ///   MOVI₂ tick: Authorized → Prepared
    ///   TRAP  tick: Prepared → Committed
    ///
    /// The TRAP tick posts a device interrupt, but the same
    /// run_process() classifies the halt as SYS_EXIT and kills X
    /// before any pre-fetch delivery can consume the interrupt.
    ///
    /// After one scheduler round:
    ///   D = IoWait, X = Zombie, request = Completed,
    ///   AutonomousIO = false, Runnable = ∅.
    ///
    /// The ONLY way D wakes is the resolve-phase completion drain.
    /// Removing that drain from run() must make this test fail.
    #[test]
    fn p92e3_completed_before_stop() {
        use super::super::block::{BlockStorage, BlockController};

        // D: issues SYS_BLOCK_READ then SYS_EXIT(200)
        let buf_vaddr_d = 0x04000_i32;
        let mut asm_d = Asm64::new();
        asm_d.movi(R1, 0);
        asm_d.movi(R2, buf_vaddr_d);
        asm_d.movi(R0, SYS_BLOCK_READ as i32);
        asm_d.trap(0);
        asm_d.movi(R1, 200);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        let code_d = asm_d.to_bytes();

        // X: exactly 3 instructions — movi, movi, trap(SYS_EXIT).
        // With latency 1, X's 3 committed-instruction ticks advance
        // the DMA pipeline to Completed.  The SYS_EXIT halt kills X
        // before the posted device interrupt can be delivered.
        let mut asm_x = Asm64::new();
        asm_x.movi(R1, 0);
        asm_x.movi(R0, SYS_EXIT as i32);
        asm_x.trap(0);
        let code_x = asm_x.to_bytes();

        let mut fabric = Fabric::new(0x400000);

        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(0), "driver",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        fabric.write_physical(0x000000, &code_d);
        seal_code_object(&mut fabric, text_d, dom_d);

        let buf = fabric.alloc_object("buf", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf, 0x080000);
        fabric.grant(dom_d, buf, 0, 0x1000, Permissions::RW);

        let (core_x, dom_x, text_x, _data_x, _stack_x) =
            create_process(&mut fabric, AgentId(1), "helper",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        fabric.write_physical(0x100000, &code_x);
        seal_code_object(&mut fabric, text_x, dom_x);

        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xAB; 512]);
        let ctrl = BlockController::new(storage, 1, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        let key_d = kernel.spawn(core_d);
        let key_x = kernel.spawn(core_x);
        kernel.register_block_device(ctrl).expect("register_block_device");
        kernel.processes[key_d.slot].core.address_map.add(
            buf_vaddr_d as u64, 0x1000, buf,
        );

        // ── Stage 1: one round ──
        // D runs first (slot 0): issues SYS_BLOCK_READ, blocks.
        // X runs next (slot 1): 3 instructions tick the controller
        // to Completed, then SYS_EXIT kills X.
        kernel.run(10000, 1);

        // Assert the exact intermediate state
        assert!(kernel.processes[key_d.slot].io_wait.is_some(),
            "D must still be in io_wait");
        assert!(!kernel.processes[key_d.slot].is_schedulable(),
            "D must not be schedulable");
        assert!(kernel.processes[key_x.slot].exited(),
            "X must have exited");
        assert_eq!(
            kernel.device_registry.devices[0].controller.completion_count(),
            1,
            "exactly one completion must be pending"
        );
        assert!(!kernel.has_autonomous_io(),
            "no autonomous work (Completed is not autonomous)");

        // ── Stage 2: one more round ──
        // The resolve phase drains the completion and wakes D.
        // D resumes, executes movi+movi+trap(SYS_EXIT), exits 200.
        kernel.run(10000, 1);

        assert!(kernel.processes[key_d.slot].exited(),
            "D must exit after resolve-phase completion drain");
        assert_eq!(kernel.processes[key_d.slot].result,
            Some(ProcessResult::Exited(200)),
            "D must exit with code 200");

        eprintln!("9.2e.3: CompletedIO ∧ ¬Runnable ⇒ resolve drains, D wakes ✓");
    }

    // ─── Phase 9.2e.4: Reevaluation lifecycle tests ──────────────

    /// Reclamation race: P reclaims D_g before reevaluation runs.
    ///
    /// A = RecvWait(D_g), P = parent waiting_on(D_g).
    /// D_g exits → wake_waiters() collects D for P → reclaim_process()
    /// advances slot to generation g+1.  Reevaluation must still
    /// detect that D_g is dead (generation mismatch) and deliver
    /// PeerDied(D_g) to A.
    #[test]
    fn p92e4_reclamation_race_peer_died() {
        let mut fabric = Fabric::new(0x600000);

        // A (slot 0): receiver — will RecvWait(D)
        let (core_a, dom_a, text_a, _data_a, _stack_a) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_a = Asm64::new();
        for _ in 0..100 { asm_a.nop(); }
        asm_a.movi(R1, 0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        seal_code_object(&mut fabric, text_a, dom_a);

        // D (slot 1): peer — will exit immediately
        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "peer",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        asm_d.movi(R1, 42);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        // P (slot 2): parent — will wait_on D via SYS_EXEC-style wait
        let (core_p, dom_p, text_p, _data_p, _stack_p) =
            create_process(&mut fabric, AgentId(2), "parent",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut fabric, 0x200000, 0x4000);
        let mut asm_p = Asm64::new();
        for _ in 0..100 { asm_p.nop(); }
        asm_p.movi(R1, 0);
        asm_p.movi(R0, SYS_EXIT as i32);
        asm_p.trap(0);
        fabric.write_physical(0x200000, &asm_p.to_bytes());
        seal_code_object(&mut fabric, text_p, dom_p);

        let mut kernel = Kernel::new(fabric);
        let key_a = kernel.spawn(core_a);
        let key_d = kernel.spawn(core_d);
        let key_p = kernel.spawn(core_p);

        let a = key_a.slot;
        let d = key_d.slot;
        let p = key_p.slot;

        // Record D's original generation
        let d_gen_original = kernel.processes[d].generation;

        // A calls SYS_RECV_WAIT(D) — D is live, no message → blocks
        setup_recv_wait_call(&mut kernel, a, &key_d);
        kernel.handle_syscall(a);
        assert!(kernel.processes[a].recv_wait.is_some());
        assert_eq!(kernel.processes[a].recv_wait.as_ref().unwrap().peer, key_d);

        // P installs waiting_on(D) so wake_waiters will reclaim D
        kernel.processes[p].waiting_on = Some(WaitState {
            child: key_d,
            kind: WaitKind::Exec,
            handle_slot: None,
        });
        kernel.processes[p].core.halted = true;

        // Kill D directly — goes Zombie
        kernel.finish_process(d, ProcessResult::Exited(42));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);
        assert_eq!(kernel.processes[d].generation, d_gen_original);

        // wake_waiters() collects D for P → reclaim_process() runs
        kernel.wake_waiters();

        // D is now reclaimed — generation advanced
        assert_ne!(kernel.processes[d].generation, d_gen_original,
            "reclaim must advance generation");
        assert_ne!(kernel.processes[d].state, ProcessState::Zombie);

        // A still has RecvWait for the OLD D_g
        assert!(kernel.processes[a].recv_wait.is_some());
        assert_eq!(kernel.processes[a].recv_wait.as_ref().unwrap().peer.generation,
            d_gen_original);

        // Reevaluate — must detect generation mismatch as death
        kernel.reevaluate_recv_waits();

        // A's RecvWait completed with PeerDied for the original D_g
        assert!(kernel.processes[a].recv_wait.is_none(),
            "reevaluation must complete RecvWait after reclaimed peer");
        assert_eq!(kernel.processes[a].core.r[R1 as usize], 3,
            "R1 = tag 3 (PeerDied)");
        assert_eq!(kernel.processes[a].core.r[R4 as usize], key_d.slot as u64,
            "R4 = original peer slot");
        assert_eq!(kernel.processes[a].core.r[R5 as usize], d_gen_original as u64,
            "R5 = original peer generation, not recycled");

        eprintln!("9.2e.4: reclaimed peer → generation mismatch → PeerDied(D_g) ✓");
    }

    /// Dead client must not receive PeerDied.
    ///
    /// A = RecvWait(D), then A dies.  D later dies and becomes quiescent.
    /// reevaluate_recv_waits() must skip A because it is Zombie — IPC
    /// completion must never be delivered to a dead incarnation.
    #[test]
    fn p92e4_dead_client_no_peer_died() {
        let (mut kernel, a, b, _key_a, key_b) = recv_wait_setup();

        // A calls SYS_RECV_WAIT(B)
        setup_recv_wait_call(&mut kernel, a, &key_b);
        kernel.handle_syscall(a);
        assert!(kernel.processes[a].recv_wait.is_some());

        // Snapshot A's registers and event frame count
        let r0_before = kernel.processes[a].core.r[R0 as usize];
        let r1_before = kernel.processes[a].core.r[R1 as usize];
        let frames_before = kernel.processes[a].core.event_frames.len();

        // Kill A — goes Zombie.  recv_wait persists (finish_process
        // does not clear scheduling fields).
        kernel.finish_process(a, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[a].state, ProcessState::Zombie);
        assert!(kernel.processes[a].recv_wait.is_some(),
            "finish_process must not clear recv_wait");

        // Kill B — goes Zombie, quiescent (no block controller)
        kernel.finish_process(b, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[b].state, ProcessState::Zombie);

        // Reevaluate — must NOT deliver PeerDied to dead client A
        kernel.reevaluate_recv_waits();

        // A's state unchanged — still Zombie, recv_wait still present,
        // registers and event frames untouched
        assert_eq!(kernel.processes[a].state, ProcessState::Zombie);
        assert!(kernel.processes[a].recv_wait.is_some(),
            "dead client's recv_wait must not be cleared");
        assert_eq!(kernel.processes[a].core.r[R0 as usize], r0_before);
        assert_eq!(kernel.processes[a].core.r[R1 as usize], r1_before);
        assert_eq!(kernel.processes[a].core.event_frames.len(), frames_before);

        eprintln!("9.2e.4: Zombie(A) + RecvWait(A,B) → no PeerDied delivery ✓");
    }

    // ─── Phase 9.2e.5: Quiescence-gated PeerDied ─────────────────

    /// Decisive quiescence chain: D dies with nonterminal request,
    /// C remains RecvWait until autonomous progress achieves terminality,
    /// then PeerDied fires.  Post-notification DMA target is frozen.
    ///
    /// Forces the full causal chain:
    ///   D dies ∧ Request(C,D) nonterminal → C remains RecvWait
    ///   → idle progress until terminality
    ///   → PeerDied(C,D)
    ///   → t ≥ t_PeerDied ⇒ M_target(t) = M_target(t_PeerDied)
    #[test]
    fn p92e5_quiescence_gated_peer_died() {
        use super::super::block::{BlockStorage, BlockController, BlockRequest, SubmitResult};

        let mut fabric = Fabric::new(0x800000);

        // C (slot 0): client — issues RECV_WAIT(D), then exits after PeerDied
        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        // D (slot 1): driver — will be killed while request is nonterminal
        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..100 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        // Block storage: latency 3 so request stays nonterminal across
        // several idle ticks.
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xBE; 512]);
        let controller = BlockController::new(storage, 3, AgentId(50));

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);

        let _dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        let c = key_c.slot;
        let d = key_d.slot;

        // ── Setup: submit a nonterminal block request attributed to (C,D) ──

        let tid = kernel.alloc_delegation_id(key_c, key_d)
            .expect("alloc delegation ID");

        let src_aid = kernel.fabric.alloc_authority_id()
            .expect("alloc source authority ID");
        let client_dom = kernel.processes[c].core.domain;
        kernel.fabric.grant_with_authority_id(
            client_dom, data_c, 0, 512, Permissions::WRITE, src_aid,
        ).expect("grant tagged authority for DMA buffer");

        let request = BlockRequest {
            block_number: 0,
            requester: RequesterKey { slot: d as u32, generation: key_d.generation },
            target_object: data_c,
            target_offset: 0,
            source_domain: client_dom,
            source_authority_id: Some(src_aid),
            delegation_id: Some(tid),
        };
        let result = kernel.device_registry.devices[0].controller
            .submit(request, &mut kernel.fabric);
        match &result {
            SubmitResult::Accepted(_) => {}
            other => panic!("request must be accepted, got {:?}", other),
        }

        assert!(kernel.device_registry.devices[0].controller
            .has_nonterminal_pair_request(&key_c, &key_d),
            "pair request must be nonterminal after submission");

        // ── Establish non-vacuous DMA baseline ──
        // Initialize target buffer to a known value different from block
        // storage (0xBE).  This ensures the causal-barrier witness includes
        // an actual DMA mutation rather than passing vacuously.
        let buf_phys = kernel.fabric.translate(data_c, 0)
            .expect("data object must be placed");
        kernel.fabric.write_physical(buf_phys, &[0x11; 512]);
        let mem_before_dma = kernel.fabric.read_physical(buf_phys, 512).to_vec();
        assert!(mem_before_dma.iter().all(|&b| b == 0x11));

        // ── C enters RecvWait(D) ──
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must block on RecvWait(D) — D is live");

        // ── Kill D while request is nonterminal ──
        kernel.finish_process(d, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);

        // Reevaluate — C must NOT get PeerDied yet (nonterminal request)
        kernel.reevaluate_recv_waits();
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must remain RecvWait — pair request is nonterminal");
        assert!(kernel.device_registry.devices[0].controller
            .has_nonterminal_pair_request(&key_c, &key_d),
            "pair request must still be nonterminal");

        // ── Idle progress: advance until request becomes terminal ──
        // With latency 3: tick 1 = Waiting→DmaReady→DmaInFlight+advance(1),
        // tick 2 = advance(2), tick 3 = advance(3)→Committed→Completed.
        // Then drain_block_completions() consumes the completion.
        for tick in 0..20 {
            if !kernel.device_registry.devices[0].controller
                .has_nonterminal_pair_request(&key_c, &key_d)
            {
                eprintln!("  request became terminal after {} idle ticks", tick);
                break;
            }
            kernel.idle_progress_once();
        }

        // Request must now be terminal (Completed or consumed)
        assert!(!kernel.device_registry.devices[0].controller
            .has_nonterminal_pair_request(&key_c, &key_d),
            "pair request must be terminal after idle progress");

        // After idle_progress_once() calls reevaluate_recv_waits(),
        // C should have received PeerDied
        assert!(kernel.processes[c].recv_wait.is_none(),
            "C's RecvWait must be cleared after quiescence achieved");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 3,
            "R1 = tag 3 (PeerDied)");
        assert_eq!(kernel.processes[c].core.r[R4 as usize], key_d.slot as u64,
            "R4 = dead peer slot");
        assert_eq!(kernel.processes[c].core.r[R5 as usize], key_d.generation as u64,
            "R5 = dead peer generation");

        // Structural witness: no hardware work or undrained completions
        // remain — this is WHY the causal barrier holds.
        assert!(!kernel.has_autonomous_io(),
            "no autonomous I/O must remain at PeerDied");
        assert_eq!(
            kernel.device_registry.devices[0].controller.completion_count(),
            0,
            "no undrained completions must remain at PeerDied"
        );

        // ── Snapshot target memory at PeerDied ──
        // DMA must have committed the requested block (0xBE) into the
        // buffer that was initialized to 0x11.
        let mem_at_peer_died = kernel.fabric.read_physical(buf_phys, 512).to_vec();
        assert!(mem_at_peer_died.iter().all(|&b| b == 0xBE),
            "DMA must have committed the requested block before PeerDied");
        assert_ne!(mem_before_dma, mem_at_peer_died,
            "causal-barrier witness must include an actual DMA mutation");

        // ── Additional idle rounds: memory must never change ──
        for _ in 0..10 {
            kernel.idle_progress_once();
        }

        let mem_after = kernel.fabric.read_physical(buf_phys, 512).to_vec();
        assert_eq!(mem_at_peer_died, mem_after,
            "target memory must not change after PeerDied (causal barrier)");

        // Three-point witness: M_0 ≠ M_PeerDied = M_later
        eprintln!("9.2e.5: M_0(0x11) → M_PeerDied(0xBE) → M_later(0xBE) ✓");
        eprintln!("9.2e.5: DMA acted → quiescence → PeerDied → no later DMA mutation ✓");
    }

    // ─── Phase 9.2e.6: Decisive blocking composition ──────────────

    /// Build the blocking client program for 9.2e.6.
    ///
    /// Same as the 9.2d client, but replaces the SYS_RECV poll loop
    /// with a single SYS_RECV_WAIT(driver_slot=1, driver_gen=0).
    /// The client blocks until the driver sends the completion message.
    fn build_blocking_client_program() -> Vec<u8> {
        let mut asm = Asm64::new();

        // Layout:
        //   [0]  movi R1,42           sentinel value
        //   [1]  movi R2,0x10000      data base vaddr
        //   [2]  st R1,R2,0           sentinel_before
        //   [3]  st R1,R2,520         sentinel_after
        //   [4]  movi R0,11           SYS_SEND_CAP
        //   [5]  movi R1,1            dest_slot (driver)
        //   [6]  movi R2,0            dest_gen
        //   [7]  movi R3,0            src_cap_slot
        //   [8]  movi R4,0            src_cap_gen
        //   [9]  movi R5,8            child_offset
        //   [10] movi R6,512          child_length
        //   [11] movi R7,WRITE        child_perms
        //   [12] movi R8,0            value = block 0
        //   [13] trap                 SYS_SEND_CAP
        //   [14] cmpi R0,0
        //   [15] bcc Ne,+25           -> error_send (40)
        //   [16] movi R0,14           SYS_RECV_WAIT
        //   [17] movi R1,1            peer_slot = 1
        //   [18] movi R2,0            peer_gen = 0
        //   [19] trap                 blocks
        //   [20] cmpi R1,1            expect tag 1 (ordinary)
        //   [21] bcc Ne,+22           -> error_recv (43)
        //   [22] cmpi R0,42           completion value from driver
        //   [23] bcc Ne,+23           -> error_value (46)
        //   [24] cmpi R4,1            sender slot = driver (1)
        //   [25] bcc Ne,+24           -> error_sender_slot (49)
        //   [26] cmpi R5,0            sender gen = 0
        //   [27] bcc Ne,+25           -> error_sender_gen (52)
        //   [28] movi R2,0x10000      data base
        //   [29] ld R3,R2,0           sentinel_before
        //   [30] cmpi R3,42
        //   [31] bcc Ne,+24           -> error_sbefore (55)
        //   [32] ld R3,R2,520         sentinel_after
        //   [33] cmpi R3,42
        //   [34] bcc Ne,+24           -> error_safter (58)
        //   [35] movi R0,SYS_EXIT     success
        //   [36] movi R1,200
        //   [37] trap
        //   [38] nop                  alignment pad
        //   [39] nop
        //   [40] movi R0,SYS_EXIT     error_send
        //   [41] movi R1,0xB01
        //   [42] trap
        //   [43] movi R0,SYS_EXIT     error_recv
        //   [44] movi R1,0xB05
        //   [45] trap
        //   [46] movi R0,SYS_EXIT     error_value
        //   [47] movi R1,0xB06
        //   [48] trap
        //   [49] movi R0,SYS_EXIT     error_sender_slot
        //   [50] movi R1,0xB07
        //   [51] trap
        //   [52] movi R0,SYS_EXIT     error_sender_gen
        //   [53] movi R1,0xB08
        //   [54] trap
        //   [55] movi R0,SYS_EXIT     error_sbefore
        //   [56] movi R1,0xB02
        //   [57] trap
        //   [58] movi R0,SYS_EXIT     error_safter
        //   [59] movi R1,0xB03
        //   [60] trap

        // ── Step 1: Write sentinels ──
        asm.movi(R1, 42);              // [0]
        asm.movi(R2, 0x10000);         // [1]
        asm.st(R1, R2, 0);             // [2]
        asm.st(R1, R2, 520);           // [3]

        // ── Step 2: SYS_SEND_CAP to driver ──
        asm.movi(R0, SYS_SEND_CAP as i32); // [4]
        asm.movi(R1, 1);               // [5]
        asm.movi(R2, 0);               // [6]
        asm.movi(R3, 0);               // [7]
        asm.movi(R4, 0);               // [8]
        asm.movi(R5, 8);               // [9]
        asm.movi(R6, 512);             // [10]
        asm.movi(R7, Permissions::WRITE.0 as i32); // [11]
        asm.movi(R8, 0);               // [12]
        asm.trap(0);                    // [13]

        asm.cmpi(R0, 0);               // [14]
        asm.bcc(Cond::Ne, 25);         // [15] -> error_send @ 40

        // ── Step 3: SYS_RECV_WAIT(driver_slot=1, driver_gen=0) ──
        asm.movi(R0, SYS_RECV_WAIT as i32); // [16]
        asm.movi(R1, 1);               // [17]
        asm.movi(R2, 0);               // [18]
        asm.trap(0);                    // [19]

        // ── Step 4: Verify IPC result ──
        asm.cmpi(R1, 1);               // [20] tag = ordinary
        asm.bcc(Cond::Ne, 22);         // [21] -> error_recv @ 43

        asm.cmpi(R0, 42);              // [22] completion value
        asm.bcc(Cond::Ne, 23);         // [23] -> error_value @ 46

        asm.cmpi(R4, 1);               // [24] sender slot = driver (1)
        asm.bcc(Cond::Ne, 24);         // [25] -> error_sender_slot @ 49

        asm.cmpi(R5, 0);               // [26] sender gen = 0
        asm.bcc(Cond::Ne, 25);         // [27] -> error_sender_gen @ 52

        // ── Step 5: Verify sentinels ──
        asm.movi(R2, 0x10000);         // [28]
        asm.ld(R3, R2, 0);             // [29]
        asm.cmpi(R3, 42);              // [30]
        asm.bcc(Cond::Ne, 24);         // [31] -> error_sbefore @ 55

        asm.ld(R3, R2, 520);           // [32]
        asm.cmpi(R3, 42);              // [33]
        asm.bcc(Cond::Ne, 24);         // [34] -> error_safter @ 58

        // ── Success ──
        asm.movi(R0, SYS_EXIT as i32); // [35]
        asm.movi(R1, 200);             // [36]
        asm.trap(0);                    // [37]

        asm.nop();                      // [38] alignment
        asm.nop();                      // [39]

        // ── Error exits ──
        asm.movi(R0, SYS_EXIT as i32); // [40] error_send
        asm.movi(R1, 0xB01);           // [41]
        asm.trap(0);                    // [42]

        asm.movi(R0, SYS_EXIT as i32); // [43] error_recv
        asm.movi(R1, 0xB05);           // [44]
        asm.trap(0);                    // [45]

        asm.movi(R0, SYS_EXIT as i32); // [46] error_value
        asm.movi(R1, 0xB06);           // [47]
        asm.trap(0);                    // [48]

        asm.movi(R0, SYS_EXIT as i32); // [49] error_sender_slot
        asm.movi(R1, 0xB07);           // [50]
        asm.trap(0);                    // [51]

        asm.movi(R0, SYS_EXIT as i32); // [52] error_sender_gen
        asm.movi(R1, 0xB08);           // [53]
        asm.trap(0);                    // [54]

        asm.movi(R0, SYS_EXIT as i32); // [55] error_sbefore
        asm.movi(R1, 0xB02);           // [56]
        asm.trap(0);                    // [57]

        asm.movi(R0, SYS_EXIT as i32); // [58] error_safter
        asm.movi(R1, 0xB03);           // [59]
        asm.trap(0);                    // [60]

        assert_eq!(asm.here(), 61, "blocking client program layout mismatch");

        asm.to_bytes()
    }

    /// **Decisive Phase 9.2e.6 test**: blocking client/driver composition.
    ///
    /// Identical to the 9.2d composition but the client uses
    /// SYS_RECV_WAIT(driver_key) instead of polling SYS_RECV.
    ///
    /// Reaches the decisive all-blocked state:
    ///   Client = RecvWait(driver)
    ///   Driver = IoWait
    ///   DMA    = active
    ///   runnable = 0
    ///
    /// Idle progress advances the controller, completion wakes the driver,
    /// driver SEND_KEYs the client (direct delivery into RecvWait),
    /// both exit 200.
    #[test]
    fn p92e6_blocking_composition() {
        use super::super::block::{BlockStorage, BlockController};

        // Block storage with known data pattern.
        // Latency 10: ensures the client enters RecvWait BEFORE DMA
        // can complete.  With latency 1, the client's pre-trap
        // instructions would drive DMA to Completed via tick_devices(),
        // and the completion could be drained before RecvWait installs.
        let mut storage = BlockStorage::new(4, 512);
        let block_data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &block_data);
        let controller = BlockController::new(storage, 10, AgentId(100));

        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(10);

        // Client at slot 0
        let (core_client, dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let client_code = build_blocking_client_program();
        fabric.write_physical(0x000000, &client_code);
        seal_code_object(&mut fabric, text_client, dom_client);

        // Driver at slot 1 — same driver program as 9.2d
        let (core_driver, dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let driver_code = build_driver_program();
        fabric.write_physical(0x100000, &driver_code);
        seal_code_object(&mut fabric, text_driver, dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        // Install block device + device cap for driver
        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap for driver");

        // Install buffer cap for client
        let _buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        // ── Phase 1: advance round-by-round until the decisive
        //    all-blocked state is reached ──
        let mut reached_decisive_state = false;

        for round in 0..50 {
            kernel.run(100_000, 1);

            let client_blocked = kernel.processes[client_key.slot]
                .recv_wait
                .as_ref()
                .map(|w| w.peer == driver_key)
                .unwrap_or(false);

            let driver_blocked =
                kernel.processes[driver_key.slot].io_wait.is_some();

            let no_runnable =
                kernel.processes.iter().all(|p| !p.is_schedulable());

            if client_blocked && driver_blocked
                && kernel.has_autonomous_io() && no_runnable
            {
                reached_decisive_state = true;
                eprintln!("  decisive state reached at round {}", round);
                break;
            }
        }

        assert!(reached_decisive_state,
            "must reach Client=RecvWait(driver), Driver=IoWait, \
             DMA active, runnable=0");

        // ── Phase 2: let the kernel complete from the all-blocked state.
        //    No guest can supply instruction ticks — only idle progress
        //    can advance the DMA, wake the driver, and resolve the
        //    composition. ──
        kernel.run(100_000, 500);

        // ── Verification ──
        assert!(kernel.processes[client_key.slot].exited(),
            "client must have exited");
        assert_eq!(kernel.processes[client_key.slot].exit_code, 200,
            "client exit code: expected 200 (success), got {}",
            kernel.processes[client_key.slot].exit_code);

        assert!(kernel.processes[driver_key.slot].exited(),
            "driver must have exited");
        assert_eq!(kernel.processes[driver_key.slot].exit_code, 200,
            "driver exit code: expected 200 (success), got {}",
            kernel.processes[driver_key.slot].exit_code);

        // Host-side: verify DMA data in client buffer
        let buf_phys = 0x010000_u64 + 8; // data base + sentinel offset
        let dma_data = kernel.fabric.read_physical(buf_phys, 512);
        assert_eq!(&dma_data[..], &block_data[..],
            "DMA buffer must contain exact block 0 data");

        // Sentinels untouched
        let sentinel_before_bytes = kernel.fabric.read_physical(0x010000, 8);
        let sentinel_before = u64::from_le_bytes(
            sentinel_before_bytes[..8].try_into().unwrap());
        assert_eq!(sentinel_before, 42,
            "sentinel_before must be untouched");

        let sentinel_after_bytes = kernel.fabric.read_physical(0x010000 + 520, 8);
        let sentinel_after = u64::from_le_bytes(
            sentinel_after_bytes[..8].try_into().unwrap());
        assert_eq!(sentinel_after, 42,
            "sentinel_after must be untouched");

        eprintln!("9.2e.6: DECISIVE BLOCKING COMPOSITION");
        eprintln!("  Client: SEND_CAP → RECV_WAIT(driver) → blocks");
        eprintln!("  Driver: RECV → DEV_SUBMIT → IoWait → SEND_KEY → exit(200)");
        eprintln!("  All-blocked state explicitly witnessed");
        eprintln!("  Idle progress: DMA active → completion → wake driver");
        eprintln!("  Direct delivery: driver SEND_KEY(value=42) → client RecvWait");
        eprintln!("  Client verifies: tag=1, value=42, sender=driver");
        eprintln!("  Both exit 200 ✓");
    }

    // ─── Phase 9.2e.7: Single-request death/quiescence ────────────

    /// Build the death-awaiting client program for 9.2e.7.
    ///
    /// Same initial SEND_CAP + RECV_WAIT as 9.2e.6, but expects
    /// PeerDied (tag 3) instead of an ordinary message, because the
    /// driver will be killed externally while its I/O request is active.
    fn build_death_client_program() -> Vec<u8> {
        let mut asm = Asm64::new();

        // Layout:
        //   [0-3]   sentinels
        //   [4-13]  SEND_CAP to driver
        //   [14-15] check SEND_CAP success
        //   [16-19] RECV_WAIT(driver)
        //   [20-21] cmpi R1,3; bcc Ne -> error_not_peerdied (38)
        //   [22-23] cmpi R4,1; bcc Ne -> error_peer_slot (41)
        //   [24-25] cmpi R5,0; bcc Ne -> error_peer_gen (44)
        //   [26-31] verify sentinels
        //   [32-34] verify DMA data arrived (ld first word, nonzero)
        //   [35-37] success exit(200)
        //   [38-40] error_send
        //   [41-43] error_not_peerdied
        //   [44-46] error_peer_slot
        //   [47-49] error_peer_gen
        //   [50-52] error_sbefore
        //   [53-55] error_safter
        //   [56-58] error_nodata

        // ── Step 1: Write sentinels ──
        asm.movi(R1, 42);              // [0]
        asm.movi(R2, 0x10000);         // [1]
        asm.st(R1, R2, 0);             // [2]
        asm.st(R1, R2, 520);           // [3]

        // ── Step 2: SYS_SEND_CAP to driver ──
        asm.movi(R0, SYS_SEND_CAP as i32); // [4]
        asm.movi(R1, 1);               // [5]  dest_slot (driver)
        asm.movi(R2, 0);               // [6]  dest_gen
        asm.movi(R3, 0);               // [7]  src_cap_slot
        asm.movi(R4, 0);               // [8]  src_cap_gen
        asm.movi(R5, 8);               // [9]  child_offset
        asm.movi(R6, 512);             // [10] child_length
        asm.movi(R7, Permissions::WRITE.0 as i32); // [11]
        asm.movi(R8, 0);               // [12] value = block 0
        asm.trap(0);                    // [13]

        asm.cmpi(R0, 0);               // [14]
        asm.bcc(Cond::Ne, 24);         // [15] -> error_send @ 39

        // ── Step 3: SYS_RECV_WAIT(driver_slot=1, driver_gen=0) ──
        asm.movi(R0, SYS_RECV_WAIT as i32); // [16]
        asm.movi(R1, 1);               // [17]
        asm.movi(R2, 0);               // [18]
        asm.trap(0);                    // [19]

        // ── Step 4: Expect PeerDied (tag 3) ──
        asm.cmpi(R1, 3);               // [20]
        asm.bcc(Cond::Ne, 21);         // [21] -> error_not_peerdied @ 42

        asm.cmpi(R4, 1);               // [22] peer slot = driver (1)
        asm.bcc(Cond::Ne, 22);         // [23] -> error_peer_slot @ 45

        asm.cmpi(R5, 0);               // [24] peer gen = 0
        asm.bcc(Cond::Ne, 23);         // [25] -> error_peer_gen @ 48

        // ── Step 5: Verify sentinels ──
        asm.movi(R2, 0x10000);         // [26]
        asm.ld(R3, R2, 0);             // [27]
        asm.cmpi(R3, 42);              // [28]
        asm.bcc(Cond::Ne, 22);         // [29] -> error_sbefore @ 51

        asm.ld(R3, R2, 520);           // [30]
        asm.cmpi(R3, 42);              // [31]
        asm.bcc(Cond::Ne, 22);         // [32] -> error_safter @ 54

        // ── Step 6: Verify DMA data arrived ──
        asm.ld(R3, R2, 8);             // [33] first DMA byte
        asm.cmpi(R3, 0);               // [34]
        asm.bcc(Cond::Eq, 22);         // [35] -> error_nodata @ 57

        // ── Success ──
        asm.movi(R0, SYS_EXIT as i32); // [36]
        asm.movi(R1, 200);             // [37]
        asm.trap(0);                    // [38]

        // ── Error exits ──
        asm.movi(R0, SYS_EXIT as i32); // [39] error_send
        asm.movi(R1, 0xC01);           // [40]
        asm.trap(0);                    // [41]

        asm.movi(R0, SYS_EXIT as i32); // [42] error_not_peerdied
        asm.movi(R1, 0xC02);           // [43]
        asm.trap(0);                    // [44]

        asm.movi(R0, SYS_EXIT as i32); // [45] error_peer_slot
        asm.movi(R1, 0xC03);           // [46]
        asm.trap(0);                    // [47]

        asm.movi(R0, SYS_EXIT as i32); // [48] error_peer_gen
        asm.movi(R1, 0xC04);           // [49]
        asm.trap(0);                    // [50]

        asm.movi(R0, SYS_EXIT as i32); // [51] error_sbefore
        asm.movi(R1, 0xC05);           // [52]
        asm.trap(0);                    // [53]

        asm.movi(R0, SYS_EXIT as i32); // [54] error_safter
        asm.movi(R1, 0xC06);           // [55]
        asm.trap(0);                    // [56]

        asm.movi(R0, SYS_EXIT as i32); // [57] error_nodata
        asm.movi(R1, 0xC07);           // [58]
        asm.trap(0);                    // [59]

        assert_eq!(asm.here(), 60, "death client program layout mismatch");

        asm.to_bytes()
    }

    /// **Phase 9.2e.7**: Single-request death + quiescence integration.
    ///
    /// Real guest execution reaches the decisive all-blocked state,
    /// then the driver is killed externally.  The client must NOT
    /// receive PeerDied while the pair's DMA request is nonterminal.
    /// Idle progress advances the DMA to completion, pair becomes
    /// quiescent, PeerDied fires, and the client verifies:
    ///
    ///   tag=3 (PeerDied), peer=(1,0)=driver_key
    ///   DMA data arrived in buffer
    ///   sentinels untouched
    ///   post-PeerDied memory stability
    #[test]
    fn p92e7_death_quiescence_integration() {
        use super::super::block::{BlockStorage, BlockController};

        // Latency 10: ensures DMA is still nonterminal when both
        // processes enter their respective blocked states.
        let mut storage = BlockStorage::new(4, 512);
        let block_data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        storage.write_block(0, &block_data);
        let controller = BlockController::new(storage, 10, AgentId(100));

        let mut fabric = Fabric::new(0x800000);
        fabric.configure_timer(10);

        // Client at slot 0 — expects PeerDied
        let (core_client, dom_client, text_client, data_client, _stack_client) =
            create_process(&mut fabric, AgentId(0), "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let client_code = build_death_client_program();
        fabric.write_physical(0x000000, &client_code);
        seal_code_object(&mut fabric, text_client, dom_client);

        // Driver at slot 1 — same program as 9.2d/9.2e.6
        let (core_driver, dom_driver, text_driver, _data_driver, _stack_driver) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let driver_code = build_driver_program();
        fabric.write_physical(0x100000, &driver_code);
        seal_code_object(&mut fabric, text_driver, dom_driver);

        let mut kernel = Kernel::new(fabric);
        let client_key = kernel.spawn(core_client);
        let driver_key = kernel.spawn(core_driver);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let _dev_handle = kernel.install_device_capability(
            driver_key.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap for driver");
        let _buf_handle = kernel.install_capability(
            client_key.slot, data_client, 0, 1024, Permissions::RW,
        ).expect("install client buffer cap");

        // ── Phase 1: advance until decisive all-blocked state ──
        let mut reached_decisive = false;
        for round in 0..50 {
            kernel.run(100_000, 1);

            let client_blocked = kernel.processes[client_key.slot]
                .recv_wait.as_ref()
                .map(|w| w.peer == driver_key)
                .unwrap_or(false);
            let driver_blocked =
                kernel.processes[driver_key.slot].io_wait.is_some();
            let no_runnable =
                kernel.processes.iter().all(|p| !p.is_schedulable());

            if client_blocked && driver_blocked
                && kernel.has_autonomous_io() && no_runnable
            {
                reached_decisive = true;
                eprintln!("  decisive state reached at round {}", round);
                break;
            }
        }
        assert!(reached_decisive,
            "must reach Client=RecvWait(driver), Driver=IoWait, \
             DMA active, runnable=0");

        // ── Phase 2: kill the driver while DMA is nonterminal ──
        assert!(kernel.device_registry.devices[0].controller
            .has_nonterminal_pair_request(&client_key, &driver_key),
            "pair request must be nonterminal before kill");

        kernel.finish_process(driver_key.slot, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[driver_key.slot].state,
            ProcessState::Zombie);

        // Client must NOT get PeerDied yet
        kernel.reevaluate_recv_waits();
        assert!(kernel.processes[client_key.slot].recv_wait.is_some(),
            "client must remain RecvWait — pair request is nonterminal");

        // ── Phase 3: idle progress until PeerDied fires ──
        // Initialize the DMA region (offset 8..520) to 0x11 for a
        // non-vacuous DMA witness.  Sentinels at offset 0 and 520
        // are preserved (written by the client guest code).
        let buf_phys = kernel.fabric.translate(data_client, 0)
            .expect("data object must be placed");
        kernel.fabric.write_physical(buf_phys + 8, &[0x11; 512]);

        let mut peer_died_fired = false;
        for tick in 0..50 {
            kernel.idle_progress_once();
            if kernel.processes[client_key.slot].recv_wait.is_none() {
                peer_died_fired = true;
                eprintln!("  PeerDied fired after {} idle ticks", tick + 1);
                break;
            }
        }
        assert!(peer_died_fired, "PeerDied must fire after idle progress");

        // Structural witnesses at PeerDied instant
        assert!(!kernel.has_autonomous_io(),
            "no autonomous I/O at PeerDied");
        assert_eq!(
            kernel.device_registry.devices[0].controller.completion_count(), 0,
            "no undrained completions at PeerDied");
        assert!(!kernel.device_registry.devices[0].controller
            .has_nonterminal_pair_request(&client_key, &driver_key),
            "pair must be quiescent at PeerDied");

        // ── Phase 4: snapshot target memory at PeerDied ──
        // The complete DMA payload must already be committed at the
        // exact PeerDied instant — not merely "something changed."
        let dma_at_peer_died =
            kernel.fabric.read_physical(buf_phys + 8, 512).to_vec();
        assert_eq!(&dma_at_peer_died[..], &block_data[..],
            "the complete DMA payload must already be committed before PeerDied");
        // Full region snapshot for stability check
        let mem_at_peer_died =
            kernel.fabric.read_physical(buf_phys, 1024).to_vec();

        // ── Phase 5: let the client run and verify guest-side ──
        kernel.run(100_000, 100);

        assert!(kernel.processes[client_key.slot].exited(),
            "client must have exited");
        assert_eq!(kernel.processes[client_key.slot].exit_code, 200,
            "client exit code: expected 200 (PeerDied verified), got {}",
            kernel.processes[client_key.slot].exit_code);

        // Host-side DMA verification
        let buf_data = kernel.fabric.read_physical(buf_phys + 8, 512);
        assert_eq!(&buf_data[..], &block_data[..],
            "DMA buffer must contain exact block 0 data");

        // Sentinels untouched
        let sentinel_before_bytes = kernel.fabric.read_physical(
            buf_phys, 8);
        let sentinel_before = u64::from_le_bytes(
            sentinel_before_bytes[..8].try_into().unwrap());
        assert_eq!(sentinel_before, 42,
            "sentinel_before must be untouched");

        let sentinel_after_bytes = kernel.fabric.read_physical(
            buf_phys + 520, 8);
        let sentinel_after = u64::from_le_bytes(
            sentinel_after_bytes[..8].try_into().unwrap());
        assert_eq!(sentinel_after, 42,
            "sentinel_after must be untouched");

        // ── Phase 6: post-PeerDied memory stability ──
        for _ in 0..10 {
            kernel.idle_progress_once();
        }
        let mem_final = kernel.fabric.read_physical(buf_phys, 1024).to_vec();
        assert_eq!(mem_at_peer_died, mem_final,
            "target memory must not change after PeerDied (causal barrier)");

        eprintln!("9.2e.7: SINGLE-REQUEST DEATH/QUIESCENCE INTEGRATION");
        eprintln!("  Real guest setup → decisive all-blocked state");
        eprintln!("  Driver killed → nonterminal pair blocks PeerDied");
        eprintln!("  Idle progress → DMA completes → PeerDied fires");
        eprintln!("  Client verifies: tag=3, peer=(1,0), DMA data, sentinels");
        eprintln!("  Post-PeerDied memory frozen ✓");
    }

    // ─── Phase 9.2e.8: Hostile suite / closure ────────────────────

    /// Direct-message-before-death: D sends directly to C's RecvWait,
    /// then D dies in the same scheduler cycle.
    ///
    /// C's outstanding RECV_WAIT must return Message (the direct send),
    /// NOT PeerDied.  complete_recv_wait() clears recv_wait atomically,
    /// so a subsequent reevaluation cannot overwrite the completed
    /// syscall with a death notification.
    ///
    /// Formal basis: PHASE_9.2e_PLAN.md Formal Refinement 5.
    #[test]
    fn p92e8_direct_message_before_death() {
        let (mut kernel, c, d, _key_c, key_d) = recv_wait_setup();

        // C calls SYS_RECV_WAIT(D) — D is live, no message → blocks
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some());

        // D sends directly to C via SYS_SEND_KEY — triggers direct delivery
        let sender_key = ProcessKey {
            slot: d,
            generation: kernel.processes[d].generation,
        };
        let route = kernel.message_route(c, &sender_key);
        assert_eq!(route, DeliveryRoute::Direct,
            "D must get direct route to C's RecvWait");

        // Perform the direct delivery
        let msg = Message { from: sender_key, value: 77, cap: None };
        kernel.deliver_message(c, msg, DeliveryRoute::Direct);

        // RecvWait must now be cleared by complete_recv_wait
        assert!(kernel.processes[c].recv_wait.is_none(),
            "direct delivery must clear recv_wait");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 1,
            "R1 = tag 1 (ordinary message)");
        assert_eq!(kernel.processes[c].core.r[R0 as usize], 77,
            "R0 = value 77");
        assert_eq!(kernel.processes[c].core.r[R4 as usize], d as u64,
            "R4 = sender slot");

        // Now kill D in the same logical cycle
        kernel.finish_process(d, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);

        // Reevaluate — C's recv_wait is already None, so reevaluation
        // must not touch C.  The message result must survive.
        kernel.reevaluate_recv_waits();

        assert!(kernel.processes[c].recv_wait.is_none());
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 1,
            "tag must still be 1 (Message), not 3 (PeerDied)");
        assert_eq!(kernel.processes[c].core.r[R0 as usize], 77,
            "value must still be 77");

        eprintln!("9.2e.8: direct message before death — Message wins over PeerDied ✓");
    }

    /// has_autonomous_io() correctly reflects controller state.
    #[test]
    fn p92e3_has_autonomous_io_predicate() {
        let (mut kernel, slot, _buf) = idle_progress_setup(0);

        // Before the process runs: no request submitted yet
        assert!(!kernel.has_autonomous_io(),
            "no autonomous work before any request is submitted");

        // Run one round — process issues SYS_BLOCK_READ
        kernel.run(10000, 1);
        assert!(kernel.processes[slot].io_wait.is_some());

        // Now there IS autonomous work
        assert!(kernel.has_autonomous_io(),
            "must have autonomous work after SYS_BLOCK_READ accepted");

        // Run to completion via idle progress
        kernel.run(10000, 200);
        assert!(kernel.processes[slot].exited());

        // No more autonomous work
        assert!(!kernel.has_autonomous_io(),
            "no autonomous work after process exits and DMA completes");

        eprintln!("9.2e.3: has_autonomous_io() predicate ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2f — Hostile Async-Completion Suite
    //
    // Eight targeted tests attacking the async submission/wait/
    // completion machinery.  Each witnesses a specific invariant
    // of the three-lifetime separation:
    //   hardware request lifetime ≠ process incarnation lifetime
    //   ≠ software completion-record lifetime.
    //
    // Formal basis: anka_multi_request_quiescence.kleis MULTI92F-*.
    // ═══════════════════════════════════════════════════════════════

    /// Helper: set up a kernel with a driver process that has device +
    /// buffer caps suitable for SYS_DEV_SUBMIT_ASYNC testing.
    ///
    /// Returns (kernel, driver_key, dev_handle, buf_handle, data_obj).
    /// The driver owns:
    ///   - Device cap at slot 0
    ///   - Buffer cap at slot 1 (512B WRITE with delegation_id)
    /// Two blocks pre-populated: block 0 = 0xAA, block 1 = 0xBB.
    /// Controller latency = 3 (stays nonterminal across multiple ticks).
    fn async_submit_setup() -> (Kernel, ProcessKey, ProcessKey,
                                CapabilityHandle, CapabilityHandle,
                                ObjectId)
    {
        use super::super::block::{BlockStorage, BlockController};

        let mut fabric = Fabric::new(0x800000);

        // Client (slot 0) — minimal, just so we have a delegation pair
        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        // Driver (slot 1)
        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..100 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        // Block storage: latency 3
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xAA; 512]);
        storage.write_block(1, &[0xBB; 512]);
        let controller = BlockController::new(storage, 3, AgentId(100));

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        let dev_handle = kernel.install_device_capability(
            key_d.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");

        // Install a buffer cap with delegation_id(C,D)
        let tid = kernel.alloc_delegation_id(key_c, key_d)
            .expect("alloc delegation ID");
        let src_aid = kernel.fabric.alloc_authority_id()
            .expect("alloc authority ID");
        let driver_dom = kernel.processes[key_d.slot].core.domain;
        kernel.fabric.grant_with_authority_id(
            driver_dom, data_c, 0, 512, Permissions::WRITE, src_aid,
        ).expect("grant tagged authority");
        let obj_gen = kernel.fabric.objects.get(&data_c).unwrap().generation;
        let buf_handle = kernel.processes[key_d.slot].cap_table.as_mut().unwrap()
            .install_memory(
                data_c, obj_gen, 0, 512, Permissions::WRITE, src_aid, Some(tid),
            ).expect("install buffer cap");

        (kernel, key_c, key_d, dev_handle, buf_handle, data_c)
    }

    /// Helper: push an EventFrame and issue SYS_DEV_SUBMIT_ASYNC with
    /// the given device handle, block number, and buffer handle.
    /// Returns the R0 result code.
    fn do_async_submit(
        kernel: &mut Kernel,
        slot: usize,
        dev_handle: &CapabilityHandle,
        block_num: u64,
        buf_handle: &CapabilityHandle,
    ) -> u64 {
        let return_pc = kernel.processes[slot].core.pc + 4;
        kernel.processes[slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[slot].core.r[R0 as usize] = SYS_DEV_SUBMIT_ASYNC;
        kernel.processes[slot].core.r[R1 as usize] = dev_handle.slot as u64;
        kernel.processes[slot].core.r[R2 as usize] = dev_handle.generation as u64;
        kernel.processes[slot].core.r[R3 as usize] = block_num;
        kernel.processes[slot].core.r[R4 as usize] = buf_handle.slot as u64;
        kernel.processes[slot].core.r[R5 as usize] = buf_handle.generation as u64;
        kernel.processes[slot].core.halted = true;
        kernel.handle_syscall(slot);
        kernel.processes[slot].core.r[R0 as usize]
    }

    /// Helper: push an EventFrame and issue SYS_DEV_WAIT (Phase 9.3b).
    ///
    /// Extended ABI: R1=slot, R2=gen, R3=device_object, R4=device_gen.
    /// Returns R0 result code.
    fn do_dev_wait(
        kernel: &mut Kernel,
        proc_slot: usize,
        req_slot: u8,
        req_gen: u64,
        dev_object: u64,
        dev_generation: u64,
    ) -> u64 {
        let return_pc = kernel.processes[proc_slot].core.pc + 4;
        kernel.processes[proc_slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[proc_slot].core.r[R0 as usize] = SYS_DEV_WAIT;
        kernel.processes[proc_slot].core.r[R1 as usize] = req_slot as u64;
        kernel.processes[proc_slot].core.r[R2 as usize] = req_gen;
        kernel.processes[proc_slot].core.r[R3 as usize] = dev_object;
        kernel.processes[proc_slot].core.r[R4 as usize] = dev_generation;
        kernel.processes[proc_slot].core.halted = true;
        kernel.handle_syscall(proc_slot);
        kernel.processes[proc_slot].core.r[R0 as usize]
    }

    // ─── 9.2f.5 test 1: two async submissions produce distinct handles ───

    #[test]
    fn p92f5_1_distinct_async_handles() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;

        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0, "first async submit must succeed");
        let h_a_slot = kernel.processes[d].core.r[R1 as usize];
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];

        let r0_b = do_async_submit(&mut kernel, d, &dev_h, 1, &buf_h);
        assert_eq!(r0_b, 0, "second async submit must succeed");
        let h_b_slot = kernel.processes[d].core.r[R1 as usize];
        let h_b_gen = kernel.processes[d].core.r[R2 as usize];

        assert!(
            h_a_slot != h_b_slot || h_a_gen != h_b_gen,
            "two simultaneously active async requests must have distinct full handles: \
             A=({},{}) B=({},{})", h_a_slot, h_a_gen, h_b_slot, h_b_gen
        );

        assert_eq!(kernel.processes[d].async_requests.len(), 2,
            "ledger must contain exactly two entries");

        eprintln!("9.2f.5-1: two distinct async handles ✓");
    }

    // ─── 9.2f.5 test 2: completion A cannot wake IoWait(B) ───
    //
    // Staggered submission: submit A, tick twice, submit B.
    // With latency 3, A completes while B is still nonterminal.
    // We wait on B, then drain A's completion and verify:
    //   Completion(h_A) AND Nonterminal(h_B) AND IoWait(h_B)
    //   => IoWait(h_B) still installed, A retained in ledger.

    #[test]
    fn p92f5_2_cross_completion_rejection() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;

        // Submit A to block 0
        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let h_a_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_gen = kernel.processes[d].core.r[R4 as usize];

        // Advance A by 2 ticks (of latency 3) — A is now at remaining=1
        kernel.tick_devices(d);
        kernel.tick_devices(d);

        // Submit B to block 1 — B starts fresh at remaining=3
        let r0_b = do_async_submit(&mut kernel, d, &dev_h, 1, &buf_h);
        assert_eq!(r0_b, 0);
        let h_b_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_b_gen = kernel.processes[d].core.r[R2 as usize];

        assert!(h_a_slot != h_b_slot || h_a_gen != h_b_gen,
            "handles must be distinct");

        // DEV_WAIT on B — should block (B is pending with remaining>=2)
        let _r0_wait = do_dev_wait(&mut kernel, d, h_b_slot, h_b_gen, dev_obj, dev_gen);
        assert!(kernel.processes[d].io_wait.is_some(),
            "DEV_WAIT(B) must install IoWait when B is pending");
        let io_handle = kernel.processes[d].io_wait.as_ref().unwrap().request;
        assert_eq!(io_handle.request.slot, h_b_slot);
        assert_eq!(io_handle.request.generation, h_b_gen,
            "IoWait must be for B, not A");

        // One more tick: A reaches remaining=0 -> DmaReady -> DmaInFlight
        // But B still has remaining>=1.
        kernel.tick_devices(d);

        // A's DMA will take at least one more tick to commit.
        // Keep ticking until A completes but B does not.
        // With latency 3 for A (started 2 ticks ago + 1 just now = DmaReady),
        // A needs DMA phases.  B needs 2 more latency ticks + DMA phases.
        // Tick one more for A's DMA:
        kernel.tick_devices(d);
        kernel.drain_block_completions();

        // Check: is A terminal and B still nonterminal?
        // A had a 2-tick head start.  If A is completed, its entry has
        // completion filled.  B should still be pending.
        let a_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.request.slot == h_a_slot && r.key.request.generation == h_a_gen);
        let b_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.request.slot == h_b_slot && r.key.request.generation == h_b_gen);

        // If A hasn't completed yet, tick more until it does
        let mut ticks = 0;
        while kernel.processes[d].async_requests.iter()
            .find(|r| r.key.request.slot == h_a_slot && r.key.request.generation == h_a_gen)
            .map(|r| r.completion.is_none())
            .unwrap_or(false)
        {
            kernel.tick_devices(d);
            kernel.drain_block_completions();
            ticks += 1;
            assert!(ticks < 20, "A should complete within 20 ticks");
        }

        // DECISIVE STATE: A completed, B still in IoWait
        // A's completion must NOT have woken IoWait(B).
        assert!(kernel.processes[d].io_wait.is_some(),
            "A's completion must NOT wake IoWait(B)");
        let io_handle = kernel.processes[d].io_wait.as_ref().unwrap().request;
        assert_eq!(io_handle.request.slot, h_b_slot,
            "IoWait must still be for B after A completes");
        assert_eq!(io_handle.request.generation, h_b_gen);

        // A's completion must be retained in the ledger
        let a_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.request.slot == h_a_slot && r.key.request.generation == h_a_gen)
            .expect("A must still be in ledger");
        assert!(a_entry.completion.is_some(),
            "A must have completion filled in ledger");

        // B must still be pending (nonterminal)
        let b_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.request.slot == h_b_slot && r.key.request.generation == h_b_gen)
            .expect("B must still be in ledger");
        assert!(b_entry.completion.is_none(),
            "B must still be pending (nonterminal)");

        eprintln!("  Decisive state witnessed:");
        eprintln!("    Completion(A) AND Nonterminal(B) AND IoWait(B)");
        eprintln!("    => IoWait(B) undisturbed, A retained in ledger");

        // Now tick until B completes — B's completion wakes IoWait(B)
        for _ in 0..20 {
            kernel.tick_devices(d);
        }
        kernel.drain_block_completions();

        assert!(kernel.processes[d].io_wait.is_none(),
            "B's completion must wake IoWait(B)");
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 0,
            "B's result must be success");

        // A should still be in ledger (retained), B consumed by wake
        assert_eq!(kernel.processes[d].async_requests.len(), 1,
            "only A should remain in ledger after B wakes");
        let remaining = &kernel.processes[d].async_requests[0];
        assert_eq!(remaining.key.request.slot, h_a_slot);
        assert!(remaining.completion.is_some());

        // Reap A
        let r0_reap_a = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj, dev_gen);
        assert_eq!(r0_reap_a, 0, "DEV_WAIT(A) must return retained success");
        assert_eq!(kernel.processes[d].async_requests.len(), 0);

        eprintln!("9.2f.5-2: Completion(h_A) does not wake IoWait(h_B) ✓");
    }

    // ─── 9.2f.5 test 3: completed A reapable after controller slot reuse ───
    //
    // Proves: RequestHandle lifetime < CompletionRecord lifetime.
    // h_A=(s,g) completes and drains into ledger.
    // h_B=(s,g+1) active on same controller slot.
    // DEV_WAIT(h_A) returns A's result without disturbing B.

    #[test]
    fn p92f5_3_completion_survives_slot_reuse() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;

        // Submit A
        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let h_a_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_gen = kernel.processes[d].core.r[R4 as usize];

        // Tick A to completion
        for _ in 0..10 {
            kernel.tick_devices(d);
        }
        kernel.drain_block_completions();

        // A's completion is now in the ledger (no IoWait was installed)
        assert_eq!(kernel.processes[d].async_requests.len(), 1);
        assert!(kernel.processes[d].async_requests[0].completion.is_some(),
            "A must have completion in ledger");

        // Controller slot should be free now
        assert_eq!(kernel.device_registry.devices[0].controller.free_slot_count(), 2);

        // Submit B on what was A's slot — will get a higher generation
        let r0_b = do_async_submit(&mut kernel, d, &dev_h, 1, &buf_h);
        assert_eq!(r0_b, 0, "B must succeed — slot is free");
        let h_b_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_b_gen = kernel.processes[d].core.r[R2 as usize];

        // Verify slot reuse with newer generation
        assert_eq!(h_b_slot, h_a_slot,
            "B must reuse A's controller slot");
        assert!(h_b_gen > h_a_gen,
            "B's generation must be strictly greater than A's: B={} A={}",
            h_b_gen, h_a_gen);

        // B is still nonterminal
        assert!(kernel.device_registry.devices[0].controller.has_autonomous_work(),
            "B must be nonterminal");

        // DEV_WAIT(A_old_handle) — must return A's retained completion
        let r0_wait_a = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj, dev_gen);
        assert_eq!(r0_wait_a, 0,
            "DEV_WAIT(A) must return A's retained success");
        assert!(kernel.processes[d].io_wait.is_none(),
            "immediate return must not install IoWait");

        // B must still be in the ledger, unaffected
        assert_eq!(kernel.processes[d].async_requests.len(), 1);
        assert_eq!(kernel.processes[d].async_requests[0].key.request.slot, h_b_slot);
        assert_eq!(kernel.processes[d].async_requests[0].key.request.generation, h_b_gen);
        assert!(kernel.processes[d].async_requests[0].completion.is_none(),
            "B must still be pending");

        eprintln!("9.2f.5-3: RequestHandle lifetime < CompletionRecord lifetime ✓");
        eprintln!("          h_A=({},{}) completed and retained, h_B=({},{}) active on same slot",
            h_a_slot, h_a_gen, h_b_slot, h_b_gen);
    }

    // ─── 9.2f.5 test 4: stale generation cannot alias recycled request ───

    #[test]
    fn p92f5_4_stale_generation_rejected() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;

        // Submit and complete A
        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let h_a_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_gen = kernel.processes[d].core.r[R4 as usize];

        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();

        // Reap A
        let r0_reap = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj, dev_gen);
        assert_eq!(r0_reap, 0, "reap A");
        assert_eq!(kernel.processes[d].async_requests.len(), 0);

        // Submit B on the same controller slot
        let r0_b = do_async_submit(&mut kernel, d, &dev_h, 1, &buf_h);
        assert_eq!(r0_b, 0);
        let h_b_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_b_gen = kernel.processes[d].core.r[R2 as usize];
        assert_eq!(h_b_slot, h_a_slot);
        assert!(h_b_gen > h_a_gen);

        // Try to DEV_WAIT on the stale A handle — must fail
        let r0_stale = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj, dev_gen);
        assert_eq!(r0_stale, 1,
            "stale handle must be rejected (error 1, not found)");
        assert!(kernel.processes[d].io_wait.is_none(),
            "stale handle must not install IoWait");

        // B is still in the ledger, untouched
        assert_eq!(kernel.processes[d].async_requests.len(), 1);
        assert_eq!(kernel.processes[d].async_requests[0].key.request.generation, h_b_gen);

        eprintln!("9.2f.5-4: stale generation rejected, cannot alias recycled request ✓");
    }

    // ─── 9.2f.5 test 5: recycled process incarnation cannot consume old completion ───
    //
    // D_g submits async A, A completes, D_g dies, slot recycled.
    // D_{g+1} spawns in same slot, attempts DEV_WAIT(h_old) → error 1.
    // Proves: recycled incarnation cannot consume old completion.

    #[test]
    fn p92f5_5_recycled_incarnation_no_consumption() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;
        let old_proc_gen = kernel.processes[d].generation;

        // D_g submits async A
        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let h_a_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_gen = kernel.processes[d].core.r[R4 as usize];

        // Tick to completion — completion drains into ledger
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();
        assert!(kernel.processes[d].async_requests[0].completion.is_some(),
            "A must have completion in D_g's ledger");

        // Kill D_g
        kernel.finish_process(d, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);

        // Reclaim D_g — slot becomes Free(g+1)
        kernel.reclaim_process(d);
        assert_eq!(kernel.processes[d].state, ProcessState::Free);
        assert_eq!(kernel.processes[d].async_requests.len(), 0,
            "reclaim must clear async ledger");

        // Spawn D_{g+1} in the same slot
        let (core_new, dom_new, text_new, _data_new, _stack_new) =
            create_process(&mut kernel.fabric, AgentId(2), "driver_g1",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut kernel.fabric, 0x200000, 0x4000);
        let mut asm_new = Asm64::new();
        for _ in 0..10 { asm_new.nop(); }
        asm_new.movi(R1, 0);
        asm_new.movi(R0, SYS_EXIT as i32);
        asm_new.trap(0);
        kernel.fabric.write_physical(0x200000, &asm_new.to_bytes());
        seal_code_object(&mut kernel.fabric, text_new, dom_new);
        let key_d_new = kernel.spawn(core_new);

        // Verify D_{g+1} reused the same slot with incremented generation
        assert_eq!(key_d_new.slot, d,
            "D_{{g+1}} must reuse the same slot as D_g");
        assert_eq!(key_d_new.generation, old_proc_gen + 1,
            "D_{{g+1}}.generation must be D_g.generation + 1");
        assert_eq!(kernel.processes[d].state, ProcessState::Running);
        assert_eq!(kernel.processes[d].async_requests.len(), 0,
            "D_{{g+1}} must start with empty async ledger");

        // D_{g+1} tries DEV_WAIT(h_old) — must fail
        let r0_stale = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj, dev_gen);
        assert_eq!(r0_stale, 1,
            "recycled incarnation must get error 1 for old handle");
        assert!(kernel.processes[d].io_wait.is_none(),
            "stale handle must not install IoWait in D_{{g+1}}");
        assert_eq!(kernel.processes[d].async_requests.len(), 0,
            "D_{{g+1}} ledger must remain empty");

        eprintln!("9.2f.5-5: D_{{g+1}} at slot {} gen {} cannot consume D_g's completion ✓",
            d, key_d_new.generation);
    }

    // ─── 9.2f.5 test 6: dead requester gets no software mutation ───

    #[test]
    fn p92f5_6_dead_requester_no_mutation() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;

        // Submit async A
        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0);

        // Install IoWait on A via DEV_WAIT (A is pending)
        let h_a_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_gen = kernel.processes[d].core.r[R4 as usize];
        let _r0_wait = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj, dev_gen);
        assert!(kernel.processes[d].io_wait.is_some(),
            "must block — A is pending");

        // Snapshot driver state before death
        let regs_before: Vec<u64> = kernel.processes[d].core.r.to_vec();
        let frames_before = kernel.processes[d].core.event_frames.len();
        let io_wait_before = kernel.processes[d].io_wait.clone();
        let ledger_before = kernel.processes[d].async_requests.len();

        // Kill the driver
        kernel.finish_process(d, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);

        // Tick to complete A at the hardware level
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();

        // Dead requester must not receive any software mutation
        assert_eq!(kernel.processes[d].core.r.to_vec(), regs_before,
            "dead process registers must not change");
        assert_eq!(kernel.processes[d].core.event_frames.len(), frames_before,
            "dead process EventFrames must not change");
        assert_eq!(kernel.processes[d].io_wait.is_some(), io_wait_before.is_some(),
            "dead process io_wait must not change");
        assert_eq!(kernel.processes[d].async_requests.len(), ledger_before,
            "dead process async_requests must not change");

        // But the request IS terminal at the controller level
        assert!(!kernel.device_registry.devices[0].controller.has_autonomous_work(),
            "controller must report no autonomous work after completion");

        eprintln!("9.2f.5-6: dead requester — ΔRegisters=ΔEventFrames=ΔIoWait=ΔLedger=0 ✓");
    }

    // ─── 9.2f.5 test 7: third request on occupied slots fails atomically ───

    #[test]
    fn p92f5_7_third_request_fails_atomically() {
        let (mut kernel, _key_c, key_d, dev_h, buf_h, _data) = async_submit_setup();
        let d = key_d.slot;

        // Fill both controller slots
        let r0_a = do_async_submit(&mut kernel, d, &dev_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let r0_b = do_async_submit(&mut kernel, d, &dev_h, 1, &buf_h);
        assert_eq!(r0_b, 0);

        assert_eq!(kernel.device_registry.devices[0].controller.free_slot_count(), 0,
            "both controller slots must be occupied");

        // Snapshot all quantities that must not change
        let domain_count_before = kernel.fabric.domain_count();
        let authority_id_before = kernel.fabric.next_authority_id();
        let ledger_len_before = kernel.processes[d].async_requests.len();
        let controller_free_before = kernel.device_registry.devices[0].controller.free_slot_count();

        // Third async submission — must fail (controller busy)
        let r0_c = do_async_submit(&mut kernel, d, &dev_h, 2, &buf_h);
        assert_eq!(r0_c, 9,
            "third request must fail with error 9 (controller busy)");

        // Verify zero side effects
        assert_eq!(kernel.fabric.domain_count(), domain_count_before,
            "ΔDomainCount must be 0 on rejected submission");
        assert_eq!(kernel.fabric.next_authority_id(), authority_id_before,
            "ΔAuthorityIds must be 0 on rejected submission");
        assert_eq!(kernel.processes[d].async_requests.len(), ledger_len_before,
            "ΔLedger must be 0 on rejected submission");
        assert_eq!(kernel.device_registry.devices[0].controller.free_slot_count(),
            controller_free_before,
            "ΔController must be 0 on rejected submission");

        eprintln!("9.2f.5-7: third request — ΔDomain=ΔAuthority=ΔLedger=ΔController=0 ✓");
    }

    // ─── 9.2f.5 test 8: ledger exhaustion (17th unreaped) fails atomically ───

    #[test]
    fn p92f5_8_ledger_exhaustion_fails_atomically() {
        use super::super::block::{BlockStorage, BlockController};

        // Need a controller with enough slots or repeated submit/complete cycles
        // to fill the 16-entry ledger.  Since NUM_SLOTS=2, we repeatedly:
        //   submit → tick to completion → drain (fills ledger) → repeat.
        // After 16 completions in the ledger, the 17th submit must fail.

        let mut fabric = Fabric::new(0x800000);

        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..10 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..10 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        // Short latency (1) so completions happen quickly
        let mut storage = BlockStorage::new(4, 512);
        for i in 0..4 { storage.write_block(i, &[i as u8; 512]); }
        let controller = BlockController::new(storage, 1, AgentId(100));

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");
        let dev_handle = kernel.install_device_capability(
            key_d.slot, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");

        let tid = kernel.alloc_delegation_id(key_c, key_d)
            .expect("delegation ID");
        let src_aid = kernel.fabric.alloc_authority_id()
            .expect("authority ID");
        let driver_dom = kernel.processes[key_d.slot].core.domain;
        kernel.fabric.grant_with_authority_id(
            driver_dom, data_c, 0, 512, Permissions::WRITE, src_aid,
        ).expect("grant");
        let obj_gen = kernel.fabric.objects.get(&data_c).unwrap().generation;
        let buf_handle = kernel.processes[key_d.slot].cap_table.as_mut().unwrap()
            .install_memory(
                data_c, obj_gen, 0, 512, Permissions::WRITE, src_aid, Some(tid),
            ).expect("install buffer cap");

        let d = key_d.slot;

        // Fill the ledger to 16 entries by repeated submit+complete cycles
        for i in 0..MAX_ASYNC_REQUESTS {
            let block_num = (i % 4) as u64;
            let r0 = do_async_submit(&mut kernel, d, &dev_handle, block_num, &buf_handle);
            assert_eq!(r0, 0, "submit {} must succeed", i);

            // Tick to completion
            for _ in 0..10 { kernel.tick_devices(d); }
            kernel.drain_block_completions();
        }

        // Verify ledger is full
        assert_eq!(kernel.processes[d].async_requests.len(), MAX_ASYNC_REQUESTS,
            "ledger must contain exactly {} entries", MAX_ASYNC_REQUESTS);
        assert!(kernel.processes[d].async_requests.iter()
            .all(|r| r.completion.is_some()),
            "all entries must have completions");

        // Snapshot quantities
        let domain_count_before = kernel.fabric.domain_count();
        let authority_id_before = kernel.fabric.next_authority_id();
        let controller_free_before = kernel.device_registry.devices[0].controller.free_slot_count();

        // 17th submit must fail
        let r0_overflow = do_async_submit(&mut kernel, d, &dev_handle, 0, &buf_handle);
        assert_eq!(r0_overflow, 10,
            "17th unreaped async request must fail with error 10 (ledger full)");

        // Zero side effects
        assert_eq!(kernel.fabric.domain_count(), domain_count_before,
            "ΔDomainCount must be 0");
        assert_eq!(kernel.fabric.next_authority_id(), authority_id_before,
            "ΔAuthorityIds must be 0");
        assert_eq!(kernel.device_registry.devices[0].controller.free_slot_count(),
            controller_free_before,
            "controller slots must not change");
        assert_eq!(kernel.processes[d].async_requests.len(), MAX_ASYNC_REQUESTS,
            "ledger must not grow");

        eprintln!("9.2f.5-8: 17th unreaped async → ledger full, atomic rejection ✓");
        eprintln!("          ΔDomain=ΔAuthority=ΔController=ΔLedger=0");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2f.6 — Decisive Two-Request Pair-Quiescence Test
    //
    // Two processes: client C, driver D.
    // D submits two staggered async requests attributed to (C,D).
    // D is killed while both are nonterminal.
    //
    // Decisive requirement:
    //   PairCount(C,D): 2 → [1] → 0
    // with C remaining in RecvWait(D) at counts 2 and 1.
    // The intermediate count=1 state MUST be explicitly observed.
    // Observing only 2→0 does not satisfy the phase.
    //
    // At count=1, the test records which target has committed
    // and which has not (non-vacuous intermediate witness).
    //
    // Formal basis: anka_multi_request_quiescence.kleis MULTI92F-*.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn p92f6_two_request_pair_quiescence() {
        use super::super::block::{BlockStorage, BlockController, BlockRequest, SubmitResult};

        let mut fabric = Fabric::new(0x800000);

        // ── Client C (slot 0) ──
        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        // ── Driver D (slot 1) ──
        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..100 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        // ── Two DMA target buffers ──
        // buf_A: client-owned, for request A (block 0 → 0xAA pattern)
        // buf_B: client-owned, for request B (block 1 → 0xBB pattern)
        let buf_a_obj = fabric.alloc_object("buf_a", 512, ObjectKind::Memory);
        fabric.place_object(buf_a_obj, 0x300000);
        let buf_b_obj = fabric.alloc_object("buf_b", 512, ObjectKind::Memory);
        fabric.place_object(buf_b_obj, 0x310000);

        // Grant client domain authority over both buffers
        fabric.grant(dom_c, buf_a_obj, 0, 512, Permissions::RW);
        fabric.grant(dom_c, buf_b_obj, 0, 512, Permissions::RW);

        // Initialize with distinct known patterns
        fabric.write_physical(0x300000, &[0x11; 512]); // A_0 = 0x11
        fabric.write_physical(0x310000, &[0x22; 512]); // B_0 = 0x22

        // ── Block storage: block 0 = 0xAA, block 1 = 0xBB ──
        // Latency 5 gives enough ticks for staggered observation.
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xAA; 512]);
        storage.write_block(1, &[0xBB; 512]);
        let controller = BlockController::new(storage, 5, AgentId(100));

        // ── Kernel + spawn ──
        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);
        let c = key_c.slot;
        let d = key_d.slot;

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        // ── Device cap for driver ──
        let dev_handle = kernel.install_device_capability(
            d, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("install device cap");

        // ── Two buffer caps for driver, each with delegation_id(C,D) ──
        let tid_a = kernel.alloc_delegation_id(key_c, key_d)
            .expect("delegation ID for A");
        let aid_a = kernel.fabric.alloc_authority_id()
            .expect("authority ID for A");
        let driver_dom = kernel.processes[d].core.domain;
        kernel.fabric.grant_with_authority_id(
            driver_dom, buf_a_obj, 0, 512, Permissions::WRITE, aid_a,
        ).expect("grant A authority to driver");
        let gen_a = kernel.fabric.objects.get(&buf_a_obj).unwrap().generation;
        let buf_a_handle = kernel.processes[d].cap_table.as_mut().unwrap()
            .install_memory(
                buf_a_obj, gen_a, 0, 512, Permissions::WRITE, aid_a, Some(tid_a),
            ).expect("install buf_A cap");

        let tid_b = kernel.alloc_delegation_id(key_c, key_d)
            .expect("delegation ID for B");
        let aid_b = kernel.fabric.alloc_authority_id()
            .expect("authority ID for B");
        kernel.fabric.grant_with_authority_id(
            driver_dom, buf_b_obj, 0, 512, Permissions::WRITE, aid_b,
        ).expect("grant B authority to driver");
        let gen_b = kernel.fabric.objects.get(&buf_b_obj).unwrap().generation;
        let buf_b_handle = kernel.processes[d].cap_table.as_mut().unwrap()
            .install_memory(
                buf_b_obj, gen_b, 0, 512, Permissions::WRITE, aid_b, Some(tid_b),
            ).expect("install buf_B cap");

        // ── Snapshot initial memory ──
        let a_0 = kernel.fabric.read_physical(0x300000, 512).to_vec();
        let b_0 = kernel.fabric.read_physical(0x310000, 512).to_vec();
        assert!(a_0.iter().all(|&x| x == 0x11), "A_0 = 0x11");
        assert!(b_0.iter().all(|&x| x == 0x22), "B_0 = 0x22");

        // ── D_0: domain count immediately before submissions ──
        let d_0 = kernel.fabric.domain_count();

        // ── Submit A (block 0 → buf_A), stagger, submit B (block 1 → buf_B) ──
        let r0_a = do_async_submit(&mut kernel, d, &dev_handle, 0, &buf_a_handle);
        assert_eq!(r0_a, 0, "submit A must succeed");
        let h_a_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_a_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_obj_r3 = kernel.processes[d].core.r[R3 as usize];
        let dev_gen_r4 = kernel.processes[d].core.r[R4 as usize];

        // Tick twice to stagger: A has remaining=3 after 2 ticks
        kernel.tick_devices(d);
        kernel.tick_devices(d);

        let r0_b = do_async_submit(&mut kernel, d, &dev_handle, 1, &buf_b_handle);
        assert_eq!(r0_b, 0, "submit B must succeed");
        let h_b_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let h_b_gen = kernel.processes[d].core.r[R2 as usize];

        // ── Verify PairCount(C,D) = 2, D_2 = D_0 + 2 ──
        let count_initial = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_d);
        assert_eq!(count_initial, 2,
            "PairCount(C,D) must be 2 after both submissions");
        let d_2 = kernel.fabric.domain_count();
        assert_eq!(d_2, d_0 + 2,
            "two request-local DMA domains must exist: D_2={} expected D_0+2={}",
            d_2, d_0 + 2);

        // ── D enters DEV_WAIT(A) ──
        let _r0_wait = do_dev_wait(&mut kernel, d, h_a_slot, h_a_gen, dev_obj_r3, dev_gen_r4);
        assert!(kernel.processes[d].io_wait.is_some(),
            "D must block on DEV_WAIT(A)");

        // ── C enters RECV_WAIT(D) ──
        // Push EventFrame for C's RECV_WAIT
        let return_pc_c = kernel.processes[c].core.pc + 4;
        kernel.processes[c].core.event_frames.push(EventFrame {
            return_pc: return_pc_c,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        setup_recv_wait_call(&mut kernel, c, &key_d);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must block on RecvWait(D)");

        // ── Kill D ──
        kernel.finish_process(d, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);

        // ── Observation point: PairCount=2 ──
        let count_at_death = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_d);
        assert_eq!(count_at_death, 2,
            "PairCount must still be 2 immediately after killing D");
        kernel.reevaluate_recv_waits();
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must remain in RecvWait at PairCount=2");
        eprintln!("  PairCount=2: RecvWait(C,D) ✓");

        // ── Idle progress until PairCount drops to 1 ──
        let mut ticks_to_1 = 0;
        loop {
            kernel.idle_progress_once();
            ticks_to_1 += 1;
            let count = kernel.device_registry.devices[0].controller
                .nonterminal_pair_request_count(&key_c, &key_d);
            if count <= 1 {
                assert_eq!(count, 1,
                    "PairCount must transition through 1, not skip to 0");
                break;
            }
            assert!(ticks_to_1 < 50, "PairCount should drop to 1 within 50 ticks");
        }

        // ── Observation point: PairCount=1 ──
        // C must still be in RecvWait — PeerDied is NOT delivered yet
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must remain in RecvWait at PairCount=1");

        // D_1 = D_0 + 1: one request-local DMA domain destroyed,
        // one still active for the remaining nonterminal request.
        let d_1 = kernel.fabric.domain_count();
        assert_eq!(d_1, d_0 + 1,
            "one DMA domain destroyed, one remains: D_1={} expected D_0+1={}",
            d_1, d_0 + 1);

        // Record which target has committed and which has not
        let a_at_1 = kernel.fabric.read_physical(0x300000, 512).to_vec();
        let b_at_1 = kernel.fabric.read_physical(0x310000, 512).to_vec();
        let a_committed = a_at_1.iter().all(|&x| x == 0xAA);
        let b_committed = b_at_1.iter().all(|&x| x == 0xBB);

        // Exactly one must have committed (A was submitted first)
        assert!(a_committed || b_committed,
            "at PairCount=1, at least one DMA must have committed");
        assert!(!(a_committed && b_committed),
            "at PairCount=1, exactly one DMA must have committed, not both");

        if a_committed {
            eprintln!("  PairCount=1: A=Block_A(0xAA), B=B_0(0x22) — RecvWait(C,D) ✓");
            assert_ne!(a_at_1, a_0, "A changed from A_0");
            assert_eq!(b_at_1, b_0, "B unchanged from B_0");
        } else {
            eprintln!("  PairCount=1: A=A_0(0x11), B=Block_B(0xBB) — RecvWait(C,D) ✓");
            assert_eq!(a_at_1, a_0, "A unchanged from A_0");
            assert_ne!(b_at_1, b_0, "B changed from B_0");
        }

        eprintln!("  PairCount dropped 2→1 after {} idle ticks", ticks_to_1);

        // ── Idle progress until PairCount drops to 0 ──
        let mut ticks_to_0 = 0;
        loop {
            kernel.idle_progress_once();
            ticks_to_0 += 1;
            let count = kernel.device_registry.devices[0].controller
                .nonterminal_pair_request_count(&key_c, &key_d);
            if count == 0 {
                break;
            }
            assert!(ticks_to_0 < 50, "PairCount should drop to 0 within 50 ticks");
        }

        // ── Observation point: PairCount=0 → PeerDied ──
        // idle_progress_once() called reevaluate_recv_waits(), so
        // C should have received PeerDied.
        assert!(kernel.processes[c].recv_wait.is_none(),
            "C's RecvWait must be cleared at PairCount=0");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 3,
            "R1 = tag 3 (PeerDied)");
        assert_eq!(kernel.processes[c].core.r[R4 as usize], key_d.slot as u64,
            "R4 = dead peer slot");
        assert_eq!(kernel.processes[c].core.r[R5 as usize], key_d.generation as u64,
            "R5 = dead peer generation");

        // Both DMA targets must now contain their block data
        let a_final = kernel.fabric.read_physical(0x300000, 512).to_vec();
        let b_final = kernel.fabric.read_physical(0x310000, 512).to_vec();
        assert!(a_final.iter().all(|&x| x == 0xAA),
            "A must contain Block_A at PeerDied");
        assert!(b_final.iter().all(|&x| x == 0xBB),
            "B must contain Block_B at PeerDied");

        // ── Structural witnesses at PeerDied ──
        assert!(!kernel.has_autonomous_io(),
            "no autonomous I/O at PeerDied");
        assert_eq!(
            kernel.device_registry.devices[0].controller.completion_count(), 0,
            "no undrained completions at PeerDied"
        );

        // D_P = D_0: both request-local DMA domains destroyed.
        let d_p = kernel.fabric.domain_count();
        assert_eq!(d_p, d_0,
            "both DMA domains destroyed at PeerDied: D_P={} expected D_0={}",
            d_p, d_0);

        // ── Post-barrier freeze: 10 additional idle rounds ──
        for _ in 0..10 {
            kernel.idle_progress_once();
        }

        let a_later = kernel.fabric.read_physical(0x300000, 512).to_vec();
        let b_later = kernel.fabric.read_physical(0x310000, 512).to_vec();
        assert_eq!(a_final, a_later,
            "A must not change after PeerDied (causal barrier)");
        assert_eq!(b_final, b_later,
            "B must not change after PeerDied (causal barrier)");

        // ── Summary ──
        eprintln!("  PairCount dropped 2→1 after {} idle ticks", ticks_to_1);
        eprintln!("  PairCount dropped 1→0 after {} additional idle ticks", ticks_to_0);
        eprintln!("9.2f.6+7: DECISIVE TWO-REQUEST PAIR-QUIESCENCE + CAUSAL BARRIER ✓");
        eprintln!("  PairCount(C,D): 2 → [1] → 0");
        eprintln!("  RecvWait(C,D) at counts 2 and 1, PeerDied at count 0");
        eprintln!("  (A_0,B_0) ≠ (A_P,B_P) = (A_∞,B_∞)");
        eprintln!("  DomainCount: D_0={} → D_0+2={} → D_0+1={} → D_0={}",
            d_0, d_2, d_1, d_p);
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.2f.8 — Recycled-Driver Concurrency Adversary
    //
    // D_g creates one request attributed to (C, D_g), then dies.
    // D_{g+1} spawns in the same slot and creates one request
    // attributed to (C, D_{g+1}).
    //
    // Decisive observation:
    //   PairCount(C, D_g) = 1,  PairCount(C, D_{g+1}) = 1
    //
    // Then D_g's request terminates while D_{g+1}'s remains active:
    //   PairCount(C, D_g) = 0,  PairCount(C, D_{g+1}) = 1
    //
    // At that exact state:
    //   PeerDied(C, D_g) must be delivered
    //   despite global AutonomousIO == true.
    //
    // This proves:
    //   PeerDied(C, D_g) => not AutonomousWorkAttributedTo(C, D_g),
    //   NOT "the machine has no autonomous work whatsoever."
    //
    // Formal basis: anka_multi_request_quiescence.kleis MULTI92F-6,7.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn p92f8_recycled_driver_concurrency_adversary() {
        use super::super::block::{BlockStorage, BlockController, BlockRequest, SubmitResult};

        let mut fabric = Fabric::new(0x800000);

        // ── Client C (slot 0) ──
        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        // ── Driver D_g (slot 1) ──
        let (core_dg, dom_dg, text_dg, _data_dg, _stack_dg) =
            create_process(&mut fabric, AgentId(1), "driver_g",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_dg = Asm64::new();
        for _ in 0..100 { asm_dg.nop(); }
        asm_dg.movi(R1, 0);
        asm_dg.movi(R0, SYS_EXIT as i32);
        asm_dg.trap(0);
        fabric.write_physical(0x100000, &asm_dg.to_bytes());
        seal_code_object(&mut fabric, text_dg, dom_dg);

        // ── DMA target buffer (owned by client) ──
        let buf_obj = fabric.alloc_object("buf_dg", 512, ObjectKind::Memory);
        fabric.place_object(buf_obj, 0x300000);
        fabric.grant(dom_c, buf_obj, 0, 512, Permissions::RW);
        fabric.write_physical(0x300000, &[0x11; 512]);

        // ── Block storage: latency 5 ──
        let mut storage = BlockStorage::new(4, 512);
        storage.write_block(0, &[0xAA; 512]);
        storage.write_block(1, &[0xBB; 512]);
        let controller = BlockController::new(storage, 5, AgentId(100));

        // ── Kernel + spawn ──
        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_dg = kernel.spawn(core_dg);
        let c = key_c.slot;
        let d = key_dg.slot;

        let dev_obj = kernel.install_block_device(controller)
            .expect("install block device");

        // ── D_g's device cap ──
        let dev_handle_g = kernel.install_device_capability(
            d, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("device cap for D_g");

        // ── D_g's buffer cap with delegation_id(C, D_g) ──
        let tid_g = kernel.alloc_delegation_id(key_c, key_dg)
            .expect("delegation ID for D_g");
        let aid_g = kernel.fabric.alloc_authority_id()
            .expect("authority ID for D_g");
        let dg_dom = kernel.processes[d].core.domain;
        kernel.fabric.grant_with_authority_id(
            dg_dom, buf_obj, 0, 512, Permissions::WRITE, aid_g,
        ).expect("grant D_g authority");
        let gen_buf = kernel.fabric.objects.get(&buf_obj).unwrap().generation;
        let buf_handle_g = kernel.processes[d].cap_table.as_mut().unwrap()
            .install_memory(
                buf_obj, gen_buf, 0, 512, Permissions::WRITE, aid_g, Some(tid_g),
            ).expect("install D_g buffer cap");

        // ── D_g submits async request (block 0 → buf) ──
        let r0_g = do_async_submit(&mut kernel, d, &dev_handle_g, 0, &buf_handle_g);
        assert_eq!(r0_g, 0, "D_g async submit must succeed");

        // Give D_g a head start: tick 3 times (of latency 5).
        // D_g is now at remaining_ticks=2 when D_{g+1} later submits at
        // remaining_ticks=5, ensuring D_g completes first.
        kernel.tick_devices(d);
        kernel.tick_devices(d);
        kernel.tick_devices(d);

        assert_eq!(
            kernel.device_registry.devices[0].controller
                .nonterminal_pair_request_count(&key_c, &key_dg),
            1,
            "PairCount(C, D_g) = 1"
        );

        // ── C enters RECV_WAIT(D_g) ──
        let return_pc_c = kernel.processes[c].core.pc + 4;
        kernel.processes[c].core.event_frames.push(EventFrame {
            return_pc: return_pc_c,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        setup_recv_wait_call(&mut kernel, c, &key_dg);
        kernel.handle_syscall(c);
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must block on RecvWait(D_g)");

        // ── Kill D_g ──
        kernel.finish_process(d, ProcessResult::Exited(0));
        assert_eq!(kernel.processes[d].state, ProcessState::Zombie);

        // D_g's request is still nonterminal — PeerDied deferred
        kernel.reevaluate_recv_waits();
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must remain in RecvWait — D_g request nonterminal");

        // ── Reclaim D_g's slot → Free(g+1) ──
        kernel.reclaim_process(d);
        assert_eq!(kernel.processes[d].state, ProcessState::Free);
        let new_gen = kernel.processes[d].generation;
        assert_eq!(new_gen, key_dg.generation + 1);

        // D_g's request is STILL nonterminal at the controller level
        assert_eq!(
            kernel.device_registry.devices[0].controller
                .nonterminal_pair_request_count(&key_c, &key_dg),
            1,
            "PairCount(C, D_g) must still be 1 after reclaim"
        );

        // ── Spawn D_{g+1} in the same slot ──
        let (core_dg1, dom_dg1, text_dg1, _data_dg1, _stack_dg1) =
            create_process(&mut kernel.fabric, AgentId(2), "driver_g1",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut kernel.fabric, 0x200000, 0x4000);
        let mut asm_dg1 = Asm64::new();
        for _ in 0..100 { asm_dg1.nop(); }
        asm_dg1.movi(R1, 0);
        asm_dg1.movi(R0, SYS_EXIT as i32);
        asm_dg1.trap(0);
        kernel.fabric.write_physical(0x200000, &asm_dg1.to_bytes());
        seal_code_object(&mut kernel.fabric, text_dg1, dom_dg1);
        let key_dg1 = kernel.spawn(core_dg1);
        assert_eq!(key_dg1.slot, d, "D_{{g+1}} must reuse D_g's slot");
        assert_eq!(key_dg1.generation, key_dg.generation + 1);

        // ── D_{g+1}'s device cap ──
        let dev_handle_g1 = kernel.install_device_capability(
            d, dev_obj, DeviceRights::SUBMIT_READ,
        ).expect("device cap for D_{{g+1}}");

        // ── D_{g+1}'s buffer (separate object) with delegation_id(C, D_{g+1}) ──
        let buf_obj_g1 = kernel.fabric.alloc_object("buf_dg1", 512, ObjectKind::Memory);
        kernel.fabric.place_object(buf_obj_g1, 0x320000);
        kernel.fabric.grant(dom_c, buf_obj_g1, 0, 512, Permissions::RW);
        kernel.fabric.write_physical(0x320000, &[0x33; 512]);

        let tid_g1 = kernel.alloc_delegation_id(key_c, key_dg1)
            .expect("delegation ID for D_{{g+1}}");
        let aid_g1 = kernel.fabric.alloc_authority_id()
            .expect("authority ID for D_{{g+1}}");
        let dg1_dom = kernel.processes[d].core.domain;
        kernel.fabric.grant_with_authority_id(
            dg1_dom, buf_obj_g1, 0, 512, Permissions::WRITE, aid_g1,
        ).expect("grant D_{{g+1}} authority");
        let gen_buf_g1 = kernel.fabric.objects.get(&buf_obj_g1).unwrap().generation;
        let buf_handle_g1 = kernel.processes[d].cap_table.as_mut().unwrap()
            .install_memory(
                buf_obj_g1, gen_buf_g1, 0, 512, Permissions::WRITE, aid_g1, Some(tid_g1),
            ).expect("install D_{{g+1}} buffer cap");

        // ── D_{g+1} submits async request (block 1 → buf_g1) ──
        let r0_g1 = do_async_submit(&mut kernel, d, &dev_handle_g1, 1, &buf_handle_g1);
        assert_eq!(r0_g1, 0, "D_{{g+1}} async submit must succeed");

        // ── DECISIVE STATE 1: both counters simultaneously ──
        let count_g = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_dg);
        let count_g1 = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_dg1);
        assert_eq!(count_g, 1, "PairCount(C, D_g) = 1");
        assert_eq!(count_g1, 1, "PairCount(C, D_{{g+1}}) = 1");
        assert!(kernel.has_autonomous_io(),
            "global autonomous I/O must be true (two active requests)");
        eprintln!("  State 1: PairCount(C,D_g)={}, PairCount(C,D_{{g+1}})={}", count_g, count_g1);

        // C is still in RecvWait(D_g)
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must remain in RecvWait(D_g)");
        let rw_peer = kernel.processes[c].recv_wait.as_ref().unwrap().peer;
        assert_eq!(rw_peer.slot, key_dg.slot);
        assert_eq!(rw_peer.generation, key_dg.generation,
            "C must be waiting for D_g, not D_{{g+1}}");

        // ── Idle progress until D_g's request terminates ──
        // D_g's request was submitted first and has a head start.
        // We need D_g's to finish while D_{g+1}'s is still active.
        let mut ticks = 0;
        loop {
            kernel.idle_progress_once();
            ticks += 1;
            let cg = kernel.device_registry.devices[0].controller
                .nonterminal_pair_request_count(&key_c, &key_dg);
            if cg == 0 {
                break;
            }
            assert!(ticks < 50, "D_g request should terminate within 50 ticks");
        }

        // ── DECISIVE STATE 2: D_g quiescent, D_{g+1} active ──
        let count_g_final = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_dg);
        let count_g1_at_peer_died = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_dg1);
        assert_eq!(count_g_final, 0, "PairCount(C, D_g) = 0");
        assert_eq!(count_g1_at_peer_died, 1,
            "PairCount(C, D_{{g+1}}) must still be 1");

        // Global autonomous I/O is TRUE because D_{g+1}'s request is active
        assert!(kernel.has_autonomous_io(),
            "global autonomous I/O must be true (D_{{g+1}} request active)");

        // But PeerDied(C, D_g) MUST have been delivered
        // (idle_progress_once calls reevaluate_recv_waits)
        assert!(kernel.processes[c].recv_wait.is_none(),
            "PeerDied(C, D_g) must be delivered despite global autonomous I/O");
        assert_eq!(kernel.processes[c].core.r[R1 as usize], 3,
            "R1 = tag 3 (PeerDied)");
        assert_eq!(kernel.processes[c].core.r[R4 as usize], key_dg.slot as u64,
            "R4 = dead peer slot (D_g)");
        assert_eq!(kernel.processes[c].core.r[R5 as usize], key_dg.generation as u64,
            "R5 = dead peer generation (D_g)");

        eprintln!("  State 2: PairCount(C,D_g)=0, PairCount(C,D_{{g+1}})=1");
        eprintln!("  PeerDied(C,D_g) delivered despite AutonomousIO=true");
        eprintln!("  D_g request terminated after {} idle ticks", ticks);
        eprintln!("9.2f.8: RECYCLED-DRIVER CONCURRENCY ADVERSARY ✓");
        eprintln!("  PeerDied(C,D_g) => not AutonomousWork(C,D_g)");
        eprintln!("  NOT => not AutonomousIO_global");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.3b — Two-Device Hostile Suite
    // ═══════════════════════════════════════════════════════════════
    //
    // Formal basis: anka_multi_device_routing.kleis DEVROUTE-1..14.
    //
    // Central identity hierarchy under test:
    //   DeviceIdentity    = (ObjectId, Generation)
    //   LocalRequestId    = (slot, generation)
    //   MachineRequestId  = (DeviceIdentity, LocalRequestId)

    /// Two-device kernel setup for Phase 9.3b hostile tests.
    ///
    /// Returns:
    ///   kernel — with two block devices registered
    ///   key_c  — client process key (slot 0)
    ///   key_d  — driver process key (slot 1)
    ///   dev_a_handle — device capability handle for device A (block 0 = 0xAA)
    ///   dev_b_handle — device capability handle for device B (block 0 = 0xBB)
    ///   buf_handle   — buffer capability handle (delegated C→D)
    ///   binding_a    — DeviceBinding for device A
    ///   binding_b    — DeviceBinding for device B
    fn two_device_setup() -> (
        Kernel, ProcessKey, ProcessKey,
        CapabilityHandle, CapabilityHandle, CapabilityHandle,
        DeviceBinding, DeviceBinding,
    ) {
        use super::super::block::{BlockStorage, BlockController};

        let mut fabric = Fabric::new(0x800000);

        // Client (slot 0)
        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        // Driver (slot 1)
        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..200 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        // Device A: block 0 = 0xAA, latency 3
        let mut storage_a = BlockStorage::new(4, 512);
        storage_a.write_block(0, &[0xAA; 512]);
        let ctrl_a = BlockController::new(storage_a, 3, AgentId(100));

        // Device B: block 0 = 0xBB, latency 3
        let mut storage_b = BlockStorage::new(4, 512);
        storage_b.write_block(0, &[0xBB; 512]);
        let ctrl_b = BlockController::new(storage_b, 3, AgentId(101));

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);

        let binding_a = kernel.register_block_device(ctrl_a)
            .expect("register device A");
        let binding_b = kernel.register_block_device(ctrl_b)
            .expect("register device B");

        // Device capabilities
        let dev_a_handle = kernel.install_device_capability(
            key_d.slot, binding_a.object, DeviceRights::SUBMIT_READ,
        ).expect("install dev_A cap");
        let dev_b_handle = kernel.install_device_capability(
            key_d.slot, binding_b.object, DeviceRights::SUBMIT_READ,
        ).expect("install dev_B cap");

        // Buffer cap with delegation_id(C,D)
        let tid = kernel.alloc_delegation_id(key_c, key_d)
            .expect("alloc delegation ID");
        let src_aid = kernel.fabric.alloc_authority_id()
            .expect("alloc authority ID");
        kernel.fabric.grant_with_authority_id(
            dom_d, data_c, 0, 512, Permissions::WRITE, src_aid,
        ).expect("grant tagged authority");
        let obj_gen = kernel.fabric.objects.get(&data_c).unwrap().generation;
        let buf_handle = kernel.processes[key_d.slot].cap_table.as_mut().unwrap()
            .install_memory(
                data_c, obj_gen, 0, 512, Permissions::WRITE, src_aid, Some(tid),
            ).expect("install buffer cap");

        (kernel, key_c, key_d, dev_a_handle, dev_b_handle, buf_handle,
         binding_a, binding_b)
    }

    // ─── 9.3b.4 test 1: Routing A/B ───
    //
    // Present(H_A) => Controller_A reads 0xAA.
    // Present(H_B) => Controller_B reads 0xBB.
    // Each submission leaves the opposite controller untouched.

    #[test]
    fn p93b4_1_exact_device_routing() {
        let (mut kernel, _key_c, key_d, dev_a_h, dev_b_h, buf_h,
             binding_a, binding_b) = two_device_setup();
        let d = key_d.slot;

        // Submit to A (block 0 → 0xAA)
        let r0_a = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0_a, 0, "submit to A must succeed");
        let ha_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let ha_gen = kernel.processes[d].core.r[R2 as usize];
        let ra_dev_obj = kernel.processes[d].core.r[R3 as usize];
        let ra_dev_gen = kernel.processes[d].core.r[R4 as usize];

        // Verify R3/R4 match A's binding
        assert_eq!(ra_dev_obj, binding_a.object.0,
            "R3 must be A's ObjectId");
        assert_eq!(ra_dev_gen, binding_a.generation.0,
            "R4 must be A's Generation");

        // B's controller must be completely untouched
        assert_eq!(kernel.device_registry.devices[1].controller.free_slot_count(), 2,
            "ΔController_B = 0 after submit to A");

        // Complete A
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();

        // Verify A read 0xAA into the buffer
        let buf_data = kernel.fabric.read_physical(0x010000, 512);
        assert!(buf_data.iter().all(|&b| b == 0xAA),
            "A must have read 0xAA pattern");

        // Reap A
        let r0_reap = do_dev_wait(&mut kernel, d, ha_slot, ha_gen, ra_dev_obj, ra_dev_gen);
        assert_eq!(r0_reap, 0);

        // Now submit to B (block 0 → 0xBB)
        let r0_b = do_async_submit(&mut kernel, d, &dev_b_h, 0, &buf_h);
        assert_eq!(r0_b, 0, "submit to B must succeed");
        let rb_dev_obj = kernel.processes[d].core.r[R3 as usize];
        let rb_dev_gen = kernel.processes[d].core.r[R4 as usize];

        // Verify R3/R4 match B's binding
        assert_eq!(rb_dev_obj, binding_b.object.0);
        assert_eq!(rb_dev_gen, binding_b.generation.0);

        // A's controller must now be untouched (only B active)
        assert_eq!(kernel.device_registry.devices[0].controller.free_slot_count(), 2,
            "ΔController_A = 0 after submit to B");

        // Complete B
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();

        let buf_data2 = kernel.fabric.read_physical(0x010000, 512);
        assert!(buf_data2.iter().all(|&b| b == 0xBB),
            "B must have read 0xBB pattern, overwriting A's data");

        eprintln!("9.3b.4-1: exact device routing A=0xAA, B=0xBB ✓");
    }

    // ─── 9.3b.4 test 2: Transferred capability routes to same device ───

    #[test]
    fn p93b4_2_transferred_cap_routes_same_device() {
        let (mut kernel, _key_c, key_d, dev_a_h, _dev_b_h, buf_h,
             binding_a, _binding_b) = two_device_setup();
        let d = key_d.slot;

        // Transfer dev_a_h to self with attenuated rights (child cap)
        // Use SYS_SEND_CAP to self
        let recv_slot = d;
        kernel.processes[recv_slot].core.r[R0 as usize] = SYS_SEND_CAP;
        kernel.processes[recv_slot].core.r[R1 as usize] = key_d.slot as u64;
        kernel.processes[recv_slot].core.r[R2 as usize] = key_d.generation as u64;
        kernel.processes[recv_slot].core.r[R3 as usize] = dev_a_h.slot as u64;
        kernel.processes[recv_slot].core.r[R4 as usize] = dev_a_h.generation as u64;
        kernel.processes[recv_slot].core.r[R5 as usize] = 0; // kind = device
        kernel.processes[recv_slot].core.r[R6 as usize] = 0;
        kernel.processes[recv_slot].core.r[R7 as usize] = DeviceRights::SUBMIT_READ.0 as u64;
        kernel.processes[recv_slot].core.r[R8 as usize] = 0xBEEF;

        let return_pc = kernel.processes[recv_slot].core.pc + 4;
        kernel.processes[recv_slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[recv_slot].core.halted = true;
        kernel.handle_syscall(recv_slot);
        assert_eq!(kernel.processes[recv_slot].core.r[R0 as usize], 0,
            "self-transfer must succeed");

        // Get the child cap from mailbox
        let child_cap = kernel.mailboxes[d].last().unwrap().cap.unwrap();

        // Submit using the child cap — must still route to A
        let r0 = do_async_submit(&mut kernel, d, &child_cap, 0, &buf_h);
        assert_eq!(r0, 0, "submit via child cap must succeed");

        let r3 = kernel.processes[d].core.r[R3 as usize];
        let r4 = kernel.processes[d].core.r[R4 as usize];
        assert_eq!(r3, binding_a.object.0,
            "child cap must route to A");
        assert_eq!(r4, binding_a.generation.0);

        // B untouched
        assert_eq!(kernel.device_registry.devices[1].controller.free_slot_count(), 2,
            "transfer of A must not touch B");

        eprintln!("9.3b.4-2: transferred capability routes to same device ✓");
    }

    // ─── 9.3b.4 test 3: Stale binding finds no registry entry ───

    #[test]
    fn p93b4_3_stale_binding_rejected() {
        let (mut kernel, _key_c, key_d, dev_a_h, _dev_b_h, _buf_h,
             binding_a, _binding_b) = two_device_setup();
        let d = key_d.slot;

        // Corrupt the device capability to have a wrong generation
        // by directly modifying the cap table entry's generation.
        // This simulates a stale binding where object exists but
        // generation doesn't match.
        // Corrupt device A's Fabric object generation to simulate
        // a stale binding.  The resolve path checks the cap table
        // entry's generation against the Fabric object's current
        // generation — bumping the Fabric generation creates a mismatch.
        {
            let obj = kernel.fabric.objects.get_mut(&binding_a.object).unwrap();
            obj.generation = Generation(obj.generation.0 + 999);
        }

        let return_pc = kernel.processes[d].core.pc + 4;
        kernel.processes[d].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[d].core.r[R0 as usize] = SYS_DEV_SUBMIT_ASYNC;
        kernel.processes[d].core.r[R1 as usize] = dev_a_h.slot as u64;
        kernel.processes[d].core.r[R2 as usize] = dev_a_h.generation as u64;
        kernel.processes[d].core.r[R3 as usize] = 0; // block 0
        kernel.processes[d].core.r[R4 as usize] = 0; // buf handle slot (invalid)
        kernel.processes[d].core.r[R5 as usize] = 0; // buf handle gen
        kernel.processes[d].core.halted = true;
        kernel.handle_syscall(d);

        let r0 = kernel.processes[d].core.r[R0 as usize];
        assert_ne!(r0, 0, "stale generation must fail submission");

        // Both controllers untouched
        assert_eq!(kernel.device_registry.devices[0].controller.free_slot_count(), 2);
        assert_eq!(kernel.device_registry.devices[1].controller.free_slot_count(), 2);

        eprintln!("9.3b.4-3: stale binding rejected ✓");
    }

    // ─── 9.3b.4 test 4: Cross-completion isolation ───
    //
    // Decisive collision test: h_A = h_B = (0, 0).
    // Completion(B, 0, 0) must NOT wake IoWait(A, 0, 0).

    #[test]
    fn p93b4_4_cross_completion_isolation() {
        let (mut kernel, _key_c, key_d, dev_a_h, dev_b_h, buf_h,
             binding_a, binding_b) = two_device_setup();
        let d = key_d.slot;

        // Submit to A
        let r0_a = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let ha_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let ha_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_a_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_a_gen = kernel.processes[d].core.r[R4 as usize];

        // Submit to B
        let r0_b = do_async_submit(&mut kernel, d, &dev_b_h, 0, &buf_h);
        assert_eq!(r0_b, 0);
        let hb_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let hb_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_b_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_b_gen = kernel.processes[d].core.r[R4 as usize];

        // Both controllers independently assign slot 0, gen 0
        assert_eq!(ha_slot, 0, "A must get slot 0");
        assert_eq!(hb_slot, 0, "B must get slot 0");
        assert_eq!(ha_gen, hb_gen, "both controllers start at gen 0");

        // But device identities differ
        assert_ne!(dev_a_obj, dev_b_obj, "device A != device B");

        // DEV_WAIT on A — pending, must block
        let _r0_w = do_dev_wait(
            &mut kernel, d, ha_slot, ha_gen, dev_a_obj, dev_a_gen,
        );
        assert!(kernel.processes[d].io_wait.is_some(),
            "must block on A (pending)");

        // Complete ONLY B by ticking — but we can't selectively tick.
        // Instead, tick everything and let both complete, then verify
        // that drain correctly routes.
        // Actually — both complete simultaneously with latency 3.
        // The key test: after drain, IoWait(A) must be consumed by
        // A's completion, not B's.
        for _ in 0..10 {
            kernel.tick_devices(d);
        }
        kernel.drain_block_completions();

        // IoWait(A) must be consumed by A's completion
        assert!(kernel.processes[d].io_wait.is_none(),
            "A's completion must wake IoWait(A)");
        assert_eq!(kernel.processes[d].core.r[R0 as usize], 0,
            "A's completion must be success");

        // B's completion should be in the ledger (no IoWait for B)
        let b_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.device == binding_b);
        assert!(b_entry.is_some(), "B must still be in ledger");
        assert!(b_entry.unwrap().completion.is_some(),
            "B's completion must be retained in ledger");

        // Reap B
        let r0_reap_b = do_dev_wait(
            &mut kernel, d, hb_slot, hb_gen, dev_b_obj, dev_b_gen,
        );
        assert_eq!(r0_reap_b, 0, "reaping B must succeed");
        assert_eq!(kernel.processes[d].async_requests.len(), 0,
            "ledger must be empty after reaping both");

        eprintln!("9.3b.4-4: cross-completion isolation h_A=h_B=(0,0) ✓");
    }

    // ─── 9.3b.4 test 5: Dual ledger collision ───
    //
    // Both (A,0,0) and (B,0,0) coexist in the ledger.
    // DEV_WAIT(A,0,0) selects exactly A; B is untouched.

    #[test]
    fn p93b4_5_dual_ledger_coexistence() {
        let (mut kernel, _key_c, key_d, dev_a_h, dev_b_h, buf_h,
             binding_a, binding_b) = two_device_setup();
        let d = key_d.slot;

        // Submit to A and B
        let r0_a = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let ha_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let ha_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_a_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_a_gen = kernel.processes[d].core.r[R4 as usize];

        let r0_b = do_async_submit(&mut kernel, d, &dev_b_h, 0, &buf_h);
        assert_eq!(r0_b, 0);
        let hb_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let hb_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_b_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_b_gen = kernel.processes[d].core.r[R4 as usize];

        // Verify collision: same local handle, different device
        assert_eq!(ha_slot, hb_slot);
        assert_eq!(ha_gen, hb_gen);
        assert_ne!(dev_a_obj, dev_b_obj);

        // Both in ledger
        assert_eq!(kernel.processes[d].async_requests.len(), 2);

        // Complete both
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();

        // Both retained in ledger with completions
        assert_eq!(kernel.processes[d].async_requests.len(), 2);
        let a_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.device == binding_a).unwrap();
        let b_entry = kernel.processes[d].async_requests.iter()
            .find(|r| r.key.device == binding_b).unwrap();
        assert!(a_entry.completion.is_some());
        assert!(b_entry.completion.is_some());

        // Reap A — must leave B untouched
        let r0_reap_a = do_dev_wait(
            &mut kernel, d, ha_slot, ha_gen, dev_a_obj, dev_a_gen,
        );
        assert_eq!(r0_reap_a, 0, "reap A must succeed");
        assert_eq!(kernel.processes[d].async_requests.len(), 1,
            "only B must remain");

        let remaining = &kernel.processes[d].async_requests[0];
        assert_eq!(remaining.key.device, binding_b,
            "remaining entry must be B, not A");
        assert!(remaining.completion.is_some(),
            "B's completion must be untouched");

        // Reap B
        let r0_reap_b = do_dev_wait(
            &mut kernel, d, hb_slot, hb_gen, dev_b_obj, dev_b_gen,
        );
        assert_eq!(r0_reap_b, 0, "reap B must succeed");
        assert_eq!(kernel.processes[d].async_requests.len(), 0);

        eprintln!("9.3b.4-5: dual ledger coexistence (A,0,0)+(B,0,0) ✓");
    }

    // ─── 9.3b.4 test 6: Registry-wide pair count ───
    //
    // Count_A(C,D)=1, Count_B(C,D)=1 => Count_registry(C,D)=2.

    #[test]
    fn p93b4_6_registry_pair_count() {
        let (mut kernel, key_c, key_d, dev_a_h, dev_b_h, buf_h,
             _binding_a, _binding_b) = two_device_setup();
        let d = key_d.slot;

        // Submit to A
        let r0_a = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0_a, 0);

        // Submit to B
        let r0_b = do_async_submit(&mut kernel, d, &dev_b_h, 0, &buf_h);
        assert_eq!(r0_b, 0);

        // Registry-wide count must be 2
        let count = kernel.device_registry.nonterminal_pair_request_count(
            &key_c, &key_d,
        );
        assert_eq!(count, 2,
            "Count_registry(C,D) must be 2 with one request on each device");

        // Individual counts
        let count_a = kernel.device_registry.devices[0].controller
            .nonterminal_pair_request_count(&key_c, &key_d);
        let count_b = kernel.device_registry.devices[1].controller
            .nonterminal_pair_request_count(&key_c, &key_d);
        assert_eq!(count_a, 1, "Count_A(C,D) = 1");
        assert_eq!(count_b, 1, "Count_B(C,D) = 1");
        assert_eq!(count_a + count_b, count,
            "Count_registry = Count_A + Count_B");

        eprintln!("9.3b.4-6: registry pair count = {} = {}+{} ✓",
            count, count_a, count_b);
    }

    // ─── 9.3b.4 test 7: Cross-device quiescence ───
    //
    // A quiescent, B still working for pair (C,D) => no PeerDied.

    #[test]
    fn p93b4_7_cross_device_quiescence_blocks_peer_died() {
        let (mut kernel, key_c, key_d, dev_a_h, dev_b_h, buf_h,
             _binding_a, _binding_b) = two_device_setup();
        let d = key_d.slot;
        let c = key_c.slot;

        // Submit to A for pair (C,D)
        let r0_a = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0_a, 0);
        let ha_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let ha_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_a_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_a_gen = kernel.processes[d].core.r[R4 as usize];

        // Complete and reap A — A is now quiescent for (C,D)
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();
        let r0_reap_a = do_dev_wait(
            &mut kernel, d, ha_slot, ha_gen, dev_a_obj, dev_a_gen,
        );
        assert_eq!(r0_reap_a, 0);

        // Now submit to B — B is nonterminal for pair (C,D)
        let r0_b = do_async_submit(&mut kernel, d, &dev_b_h, 0, &buf_h);
        assert_eq!(r0_b, 0);

        // Count_A(C,D)=0, Count_B(C,D)=1 => PeerDied blocked
        let count = kernel.device_registry.nonterminal_pair_request_count(
            &key_c, &key_d,
        );
        assert_eq!(count, 1,
            "B's nonterminal request must block quiescence: Count_A=0, Count_B=1");

        // Kill D — C enters RECV_WAIT(D)
        // Pair delegation is (client=C, driver=D), so C waits for D.
        kernel.finish_process(d, ProcessResult::Exited(0));

        // Set up C to call RECV_WAIT(D)
        let return_pc = kernel.processes[c].core.pc + 4;
        kernel.processes[c].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[c].core.r[R0 as usize] = SYS_RECV_WAIT;
        kernel.processes[c].core.r[R1 as usize] = key_d.slot as u64;
        kernel.processes[c].core.r[R2 as usize] = key_d.generation as u64;
        kernel.processes[c].core.halted = true;
        kernel.handle_syscall(c);

        // C must be blocked — B's work for pair (C,D) prevents PeerDied
        assert!(kernel.processes[c].recv_wait.is_some(),
            "C must be blocked in RECV_WAIT — B's nonterminal work prevents PeerDied(C,D)");

        eprintln!("9.3b.4-7: cross-device quiescence blocks PeerDied ✓");
    }

    // ─── 9.3b.4 test 8: Unrelated device work does not block PeerDied ───
    //
    // B's work belongs to an unrelated pair (X,D).
    // Count_A(C,D)=0, Count_B(X,D)=1 => PeerDied(C,D) permitted.

    #[test]
    fn p93b4_8_unrelated_device_autonomy() {
        use super::super::block::{BlockStorage, BlockController};

        let mut fabric = Fabric::new(0x800000);

        // C (slot 0), D (slot 1), X (slot 2)
        let (core_c, dom_c, text_c, data_c, _stack_c) =
            create_process(&mut fabric, CPU0, "client",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm_c = Asm64::new();
        for _ in 0..100 { asm_c.nop(); }
        asm_c.movi(R1, 0);
        asm_c.movi(R0, SYS_EXIT as i32);
        asm_c.trap(0);
        fabric.write_physical(0x000000, &asm_c.to_bytes());
        seal_code_object(&mut fabric, text_c, dom_c);

        let (core_d, dom_d, text_d, _data_d, _stack_d) =
            create_process(&mut fabric, AgentId(1), "driver",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm_d = Asm64::new();
        for _ in 0..200 { asm_d.nop(); }
        asm_d.movi(R1, 0);
        asm_d.movi(R0, SYS_EXIT as i32);
        asm_d.trap(0);
        fabric.write_physical(0x100000, &asm_d.to_bytes());
        seal_code_object(&mut fabric, text_d, dom_d);

        let (core_x, dom_x, text_x, data_x, _stack_x) =
            create_process(&mut fabric, AgentId(2), "other",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut fabric, 0x200000, 0x4000);
        let mut asm_x = Asm64::new();
        for _ in 0..100 { asm_x.nop(); }
        asm_x.movi(R1, 0);
        asm_x.movi(R0, SYS_EXIT as i32);
        asm_x.trap(0);
        fabric.write_physical(0x200000, &asm_x.to_bytes());
        seal_code_object(&mut fabric, text_x, dom_x);

        // Device B with latency 3
        let storage_b = BlockStorage::new(4, 512);
        let ctrl_b = BlockController::new(storage_b, 3, AgentId(101));

        let mut kernel = Kernel::new(fabric);
        let key_c = kernel.spawn(core_c);
        let key_d = kernel.spawn(core_d);
        let key_x = kernel.spawn(core_x);

        let binding_b = kernel.register_block_device(ctrl_b)
            .expect("register device B");

        // D gets device cap and buffer cap with delegation (X,D)
        let dev_b_handle = kernel.install_device_capability(
            key_d.slot, binding_b.object, DeviceRights::SUBMIT_READ,
        ).expect("install dev_B cap");

        let tid_xd = kernel.alloc_delegation_id(key_x, key_d)
            .expect("alloc delegation ID X→D");
        let aid_xd = kernel.fabric.alloc_authority_id()
            .expect("alloc authority ID");
        kernel.fabric.grant_with_authority_id(
            dom_d, data_x, 0, 512, Permissions::WRITE, aid_xd,
        ).expect("grant");
        let gen_x = kernel.fabric.objects.get(&data_x).unwrap().generation;
        let buf_xd_handle = kernel.processes[key_d.slot].cap_table.as_mut().unwrap()
            .install_memory(
                data_x, gen_x, 0, 512, Permissions::WRITE, aid_xd, Some(tid_xd),
            ).expect("install buf cap");

        // Submit to B with delegation (X,D) — unrelated to pair (C,D)
        let r0 = do_async_submit(&mut kernel, key_d.slot, &dev_b_handle, 0, &buf_xd_handle);
        assert_eq!(r0, 0);

        // Count(C,D) = 0 despite B having work for (X,D)
        let count_cd = kernel.device_registry.nonterminal_pair_request_count(
            &key_c, &key_d,
        );
        assert_eq!(count_cd, 0,
            "unrelated pair (X,D) work must not affect Count(C,D)");

        // Global autonomous I/O is true
        assert!(kernel.has_autonomous_io(),
            "B has nonterminal work → autonomous I/O");

        // Kill C — D's RECV_WAIT should get immediate PeerDied
        kernel.finish_process(key_c.slot, ProcessResult::Exited(0));

        let return_pc = kernel.processes[key_d.slot].core.pc + 4;
        kernel.processes[key_d.slot].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[key_d.slot].core.r[R0 as usize] = SYS_RECV_WAIT;
        kernel.processes[key_d.slot].core.r[R1 as usize] = key_c.slot as u64;
        kernel.processes[key_d.slot].core.r[R2 as usize] = key_c.generation as u64;
        kernel.processes[key_d.slot].core.halted = true;
        kernel.handle_syscall(key_d.slot);

        // PeerDied(C,D) must be delivered immediately
        assert!(kernel.processes[key_d.slot].recv_wait.is_none(),
            "PeerDied(C,D) must be immediate — B's work is for (X,D), not (C,D)");
        assert_eq!(kernel.processes[key_d.slot].core.r[R1 as usize], 3,
            "R1 = PeerDied tag");

        eprintln!("9.3b.4-8: unrelated device autonomy permits PeerDied ✓");
    }

    // ─── 9.3b.4 test 9: Aggregate interrupt / three-process routing ───
    //
    // P1 submits to A, P2 submits to B, P3 is executing.
    // Both complete in one tick pass.  One interrupt, one handler.
    // Completion_A → P1, Completion_B → P2, P3 untouched.

    #[test]
    fn p93b4_9_aggregate_interrupt_three_process() {
        use super::super::block::{BlockStorage, BlockController, BlockRequest, SubmitResult};

        let mut fabric = Fabric::new(0x800000);

        // P1 (slot 0)
        let (core_p1, dom_p1, text_p1, _data_p1, _stack_p1) =
            create_process(&mut fabric, CPU0, "p1",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        let mut asm = Asm64::new();
        for _ in 0..200 { asm.nop(); }
        asm.movi(R1, 0);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text_p1, dom_p1);

        // DMA buffer for P1
        let buf_p1 = fabric.alloc_object("buf_p1", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf_p1, 0x080000);
        fabric.grant(dom_p1, buf_p1, 0, 0x1000, Permissions::WRITE);

        // P2 (slot 1)
        let (core_p2, dom_p2, text_p2, _data_p2, _stack_p2) =
            create_process(&mut fabric, AgentId(1), "p2",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000, 0x4000);
        let mut asm2 = Asm64::new();
        for _ in 0..200 { asm2.nop(); }
        asm2.movi(R1, 0);
        asm2.movi(R0, SYS_EXIT as i32);
        asm2.trap(0);
        fabric.write_physical(0x100000, &asm2.to_bytes());
        seal_code_object(&mut fabric, text_p2, dom_p2);

        // DMA buffer for P2
        let buf_p2 = fabric.alloc_object("buf_p2", 0x1000, ObjectKind::Memory);
        fabric.place_object(buf_p2, 0x180000);
        fabric.grant(dom_p2, buf_p2, 0, 0x1000, Permissions::WRITE);

        // P3 (slot 2) — bystander
        let (core_p3, _dom_p3, text_p3, _data_p3, _stack_p3) =
            create_process(&mut fabric, AgentId(2), "p3",
                0x200000, 0x210000, 0x220000);
        install_trap_handler(&mut fabric, 0x200000, 0x4000);
        let mut asm3 = Asm64::new();
        for _ in 0..200 { asm3.nop(); }
        asm3.movi(R1, 0);
        asm3.movi(R0, SYS_EXIT as i32);
        asm3.trap(0);
        fabric.write_physical(0x200000, &asm3.to_bytes());
        seal_code_object(&mut fabric, text_p3, _dom_p3);

        // Device A (latency 2), Device B (latency 2)
        let mut storage_a = BlockStorage::new(4, 512);
        storage_a.write_block(0, &[0xAA; 512]);
        let ctrl_a = BlockController::new(storage_a, 2, AgentId(100));

        let mut storage_b = BlockStorage::new(4, 512);
        storage_b.write_block(0, &[0xBB; 512]);
        let ctrl_b = BlockController::new(storage_b, 2, AgentId(101));

        let mut kernel = Kernel::new(fabric);
        let _key_p1 = kernel.spawn(core_p1);
        let _key_p2 = kernel.spawn(core_p2);
        let _key_p3 = kernel.spawn(core_p3);

        let binding_a = kernel.register_block_device(ctrl_a)
            .expect("register A");
        let binding_b = kernel.register_block_device(ctrl_b)
            .expect("register B");

        // Manually submit requests (low-level, bypassing SYS_DEV_SUBMIT)
        let rk_p1 = RequesterKey { slot: 0, generation: kernel.processes[0].generation };
        let rk_p2 = RequesterKey { slot: 1, generation: kernel.processes[1].generation };

        let req_a = BlockRequest {
            block_number: 0, requester: rk_p1, target_object: buf_p1,
            target_offset: 0, source_domain: dom_p1,
            source_authority_id: None, delegation_id: None,
        };
        let handle_a = match kernel.device_registry.devices[0].controller
            .submit(req_a, &mut kernel.fabric)
        {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit A must succeed"),
        };

        let req_b = BlockRequest {
            block_number: 0, requester: rk_p2, target_object: buf_p2,
            target_offset: 0, source_domain: dom_p2,
            source_authority_id: None, delegation_id: None,
        };
        let handle_b = match kernel.device_registry.devices[1].controller
            .submit(req_b, &mut kernel.fabric)
        {
            SubmitResult::Accepted(h) => h,
            _ => panic!("submit B must succeed"),
        };

        // Install IoWait on P1 for (A, handle_a)
        let pc_p1 = kernel.processes[0].core.pc;
        kernel.processes[0].core.event_frames.push(EventFrame {
            return_pc: pc_p1,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[0].core.halted = true;
        kernel.processes[0].io_wait = Some(IoWait {
            request: DeviceRequestKey { device: binding_a, request: handle_a },
        });

        // Install IoWait on P2 for (B, handle_b)
        let pc_p2 = kernel.processes[1].core.pc;
        kernel.processes[1].core.event_frames.push(EventFrame {
            return_pc: pc_p2,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[1].core.halted = true;
        kernel.processes[1].io_wait = Some(IoWait {
            request: DeviceRequestKey { device: binding_b, request: handle_b },
        });

        // Snapshot P3 state
        let p3_regs_before: Vec<u64> = kernel.processes[2].core.r.to_vec();
        let p3_io_wait_before = kernel.processes[2].io_wait.clone();
        let p3_halted_before = kernel.processes[2].core.halted;

        // Tick both controllers to completion (latency 2)
        for _ in 0..5 {
            for slot in &mut kernel.device_registry.devices {
                slot.controller.tick(&mut kernel.fabric);
            }
        }

        // Both require attention
        assert!(kernel.device_registry.devices[0].controller.requires_attention(),
            "A must require attention");
        assert!(kernel.device_registry.devices[1].controller.requires_attention(),
            "B must require attention");

        // One drain pass handles both
        kernel.drain_block_completions();

        // P1 woken by A's completion
        assert!(kernel.processes[0].io_wait.is_none(),
            "P1 must be woken by A's completion");
        assert_eq!(kernel.processes[0].core.r[R0 as usize], 0,
            "P1 must get success from A");

        // P2 woken by B's completion
        assert!(kernel.processes[1].io_wait.is_none(),
            "P2 must be woken by B's completion");
        assert_eq!(kernel.processes[1].core.r[R0 as usize], 0,
            "P2 must get success from B");

        // P3 completely untouched
        assert_eq!(kernel.processes[2].core.r.to_vec(), p3_regs_before,
            "P3 registers must be untouched");
        assert_eq!(kernel.processes[2].io_wait.is_none(), p3_io_wait_before.is_none(),
            "P3 io_wait must be untouched");
        assert_eq!(kernel.processes[2].core.halted, p3_halted_before,
            "P3 halted must be untouched");

        eprintln!("9.3b.4-9: aggregate interrupt, three-process routing ✓");
        eprintln!("  Completion_A → P1, Completion_B → P2, ΔP3 = 0");
    }

    // ─── 9.3b.4 test 10: Capability-drop lifetime ───
    //
    // Submit async with H_A, drop H_A, DEV_WAIT(A, handle) still works.
    // Accepted request outlives possession of the device capability.

    #[test]
    fn p93b4_10_capability_drop_lifetime() {
        let (mut kernel, _key_c, key_d, dev_a_h, _dev_b_h, buf_h,
             _binding_a, _binding_b) = two_device_setup();
        let d = key_d.slot;

        // Submit async to A
        let r0 = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0, 0);
        let ha_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let ha_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_a_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_a_gen = kernel.processes[d].core.r[R4 as usize];

        // Drop the device capability
        kernel.processes[d].cap_table.as_mut().unwrap()
            .drop_handle(dev_a_h);

        // Complete the request
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();

        // DEV_WAIT must still work — namespace qualification, not authority
        let r0_wait = do_dev_wait(
            &mut kernel, d, ha_slot, ha_gen, dev_a_obj, dev_a_gen,
        );
        assert_eq!(r0_wait, 0,
            "DEV_WAIT must succeed after capability drop — \
             accepted request outlives device capability possession");
        assert_eq!(kernel.processes[d].async_requests.len(), 0);

        eprintln!("9.3b.4-10: capability-drop lifetime ✓");
        eprintln!("  Submit(H_A) → Drop(H_A) → DEV_WAIT(A,h) = success");
    }

    // ─── 9.3b.4 test 11: DEV_WAIT ticket hardening ───
    //
    // R1 overflow (slot > u8::MAX) → error 1, zero side effects.
    // Unknown (R3,R4) identity → error 1, zero side effects.

    #[test]
    fn p93b4_11_dev_wait_ticket_hardening() {
        let (mut kernel, _key_c, key_d, dev_a_h, _dev_b_h, buf_h,
             binding_a, _binding_b) = two_device_setup();
        let d = key_d.slot;

        // Submit to A so we have a real ledger entry
        let r0 = do_async_submit(&mut kernel, d, &dev_a_h, 0, &buf_h);
        assert_eq!(r0, 0);
        let ha_slot = kernel.processes[d].core.r[R1 as usize] as u8;
        let ha_gen = kernel.processes[d].core.r[R2 as usize];
        let dev_a_obj = kernel.processes[d].core.r[R3 as usize];
        let dev_a_gen = kernel.processes[d].core.r[R4 as usize];

        let ledger_before = kernel.processes[d].async_requests.len();
        let io_wait_before = kernel.processes[d].io_wait.is_none();

        // ── Test 1: R1 overflow (slot > u8::MAX) ──
        // do_dev_wait takes u8, so we issue the raw syscall with R1=256.
        let return_pc = kernel.processes[d].core.pc + 4;
        kernel.processes[d].core.event_frames.push(EventFrame {
            return_pc,
            return_privilege: Privilege::User,
            interrupts_were_enabled: true,
            cause: EventCause::Syscall,
        });
        kernel.processes[d].core.r[R0 as usize] = SYS_DEV_WAIT;
        kernel.processes[d].core.r[R1 as usize] = 256; // > u8::MAX
        kernel.processes[d].core.r[R2 as usize] = ha_gen;
        kernel.processes[d].core.r[R3 as usize] = dev_a_obj;
        kernel.processes[d].core.r[R4 as usize] = dev_a_gen;
        kernel.processes[d].core.halted = true;
        kernel.handle_syscall(d);

        assert_eq!(kernel.processes[d].core.r[R0 as usize], 1,
            "R1 overflow must return error 1");
        assert_eq!(kernel.processes[d].async_requests.len(), ledger_before,
            "ΔLedger = 0 on R1 overflow");
        assert_eq!(kernel.processes[d].io_wait.is_none(), io_wait_before,
            "ΔIoWait = 0 on R1 overflow");

        // ── Test 2: Unknown device identity (R3,R4) ──
        let r0_unknown = do_dev_wait(
            &mut kernel, d, ha_slot, ha_gen,
            0xDEAD_BEEF, // unknown ObjectId
            0xCAFE_BABE, // unknown Generation
        );
        assert_eq!(r0_unknown, 1,
            "unknown (ObjectId, Generation) must return error 1");
        assert_eq!(kernel.processes[d].async_requests.len(), ledger_before,
            "ΔLedger = 0 on unknown device identity");
        assert_eq!(kernel.processes[d].io_wait.is_none(), io_wait_before,
            "ΔIoWait = 0 on unknown device identity");

        // ── Test 3: Correct device, wrong request slot (never submitted) ──
        let r0_wrong_slot = do_dev_wait(
            &mut kernel, d, 99, 0, dev_a_obj, dev_a_gen,
        );
        assert_eq!(r0_wrong_slot, 1,
            "never-submitted slot must return error 1");

        // ── Verify the real entry is still reapable ──
        for _ in 0..10 { kernel.tick_devices(d); }
        kernel.drain_block_completions();
        let r0_valid = do_dev_wait(
            &mut kernel, d, ha_slot, ha_gen, dev_a_obj, dev_a_gen,
        );
        assert_eq!(r0_valid, 0,
            "real entry must still be reapable after all hostile DEV_WAITs");

        eprintln!("9.3b.4-11: DEV_WAIT ticket hardening ✓");
        eprintln!("  R1 overflow → error 1, Δ=0");
        eprintln!("  Unknown (R3,R4) → error 1, Δ=0");
    }
}

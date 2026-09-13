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

// ───────────────────────────────────────────────────────────────────
// Process descriptor
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u64,
    pub core: Anka64Core,
    pub exited: bool,
    pub exit_code: u64,
    /// If Some(child_pid), this process is blocked waiting for child_pid to exit.
    pub waiting_on: Option<u64>,
    /// PID of the parent process (None for init).
    pub parent: Option<u64>,
}

/// Process lifecycle result — distinguishes normal exit from fault.
/// program returned 7 != program died with ExecuteDenied.
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
// Message mailbox
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Message {
    #[allow(dead_code)]
    from_pid: u64,
    value: u64,
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
    /// R0 = syscall number.
    Syscall,
    /// Supervisor HALT not at the trap gate: kernel halt/panic.
    SupervisorFault,
}

fn classify_halt(core: &Anka64Core) -> HaltDisposition {
    if core.privilege == Privilege::Supervisor && core.pc == core.trap_vector {
        HaltDisposition::Syscall
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
    mailboxes: Vec<Vec<Message>>,
    current: usize,
    /// Next available physical address for dynamic allocation.
    pub next_phys: u64,
    /// Next available agent ID for child processes.
    pub next_agent: u64,
    /// One-success-only boot flag.  Set to true after a successful boot.
    booted: bool,
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
            booted: false,
        }
    }

    // ─── Shared process-image creation primitive ────────────────
    //
    // Used by both SYS_EXEC and Kernel::boot().  The caller is
    // responsible for creating the domain and granting executable
    // image authority (RX for code, R for literals).  This method
    // creates stack, trap handler, address map, and core.
    //
    // The difference between SYS_EXEC and boot() is the source of
    // authority: SYS_EXEC derives it from a caller's domain;
    // boot() establishes it from trusted boot state.  Everything
    // after authority establishment is the same mechanism.

    /// Create process infrastructure for a domain that already has
    /// executable image authority.  Returns the spawned PID.
    ///
    /// On failure, rolls back: destroys domain and any resources
    /// created during preparation.  No reachable domain, capability,
    /// mapping, or runnable process survives a failed preparation.
    fn prepare_process(
        &mut self, dom: DomainId, desc: &ProcessImageDesc, layout: &ProcessLayout,
    ) -> u64 {
        // --- Stack ---
        let stack_obj = self.fabric.alloc_object(
            "process_stack", layout.stack_size, ObjectKind::Memory);
        let stack_phys = self.next_phys;
        self.next_phys += layout.stack_size;
        self.fabric.place_object(stack_obj, stack_phys);
        self.fabric.grant(dom, stack_obj, 0, layout.stack_size, Permissions::RW);

        // --- Trap handler: alloc → initialize → seal → grant RX ---
        // W⊕X: no exceptional executable-object creation path.
        let trap_size: u64 = 0x1000;
        let trap_obj = self.fabric.alloc_object("process_trap", trap_size, ObjectKind::Memory);
        let trap_phys = self.next_phys;
        self.next_phys += trap_size;
        self.fabric.place_object(trap_obj, trap_phys);

        let mut handler = Asm64::new();
        handler.halt();
        self.fabric.initialize_object(trap_obj, 0, &handler.to_bytes());
        self.fabric.seal_object(trap_obj);
        self.fabric.grant(dom, trap_obj, 0, trap_size, Permissions::RX);

        // --- Core ---
        let agent = AgentId(self.next_agent);
        self.next_agent += 1;

        let mut core = Anka64Core::new(agent, dom);
        // Map code at code_vaddr → object at code_offset
        core.address_map.add_at(
            layout.code_vaddr, desc.code_size, desc.code_obj, desc.code_offset);
        core.pc = layout.code_vaddr + desc.entry;
        // Map literal segment at its natural image-relative offset
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

        self.spawn(core)
    }

    pub fn spawn(&mut self, core: Anka64Core) -> u64 {
        let pid = self.processes.len() as u64;
        self.processes.push(Process {
            pid,
            core,
            exited: false,
            exit_code: 0,
            waiting_on: None,
            parent: None,
        });
        self.mailboxes.push(Vec::new());
        pid
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
            let m_end = m.vaddr + m.size;
            // Check against all existing ranges
            for &(rs, re) in &ranges {
                if m.vaddr < re && m_end > rs {
                    return Err(BootError::OverlappingMaps);
                }
            }
            ranges.push((m.vaddr, m_end));
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
        let _init_pid = self.prepare_process(dom, &desc, &boot_layout);

        // Additional address maps
        for m in &info.maps {
            let init_idx = _init_pid as usize;
            self.processes[init_idx].core.address_map.add_at(
                m.vaddr, m.size, m.obj, m.obj_offset,
            );
        }

        self.booted = true;
        Ok(())
    }

    /// Run all processes in round-robin until all exit.
    /// Each process gets `quantum` steps per turn.
    pub fn run(&mut self, quantum: usize, max_rounds: usize) {
        for _ in 0..max_rounds {
            if self.processes.iter().all(|p| p.exited) {
                break;
            }

            for i in 0..self.processes.len() {
                if self.processes[i].exited {
                    continue;
                }
                // Skip processes blocked waiting on a child
                if self.processes[i].waiting_on.is_some() {
                    continue;
                }
                self.current = i;
                self.run_process(i, quantum);
                // After running, check if any newly-exited process
                // has a parent waiting on it
                self.reap_exited();
            }
        }
    }

    /// Check for exited processes and resume any parent waiting on them.
    fn reap_exited(&mut self) {
        // Collect (child_pid, exit_code) for exited children
        let mut completions: Vec<(u64, u64)> = Vec::new();
        for p in &self.processes {
            if p.exited {
                completions.push((p.pid, p.exit_code));
            }
        }
        // For each exited child, find any parent waiting on it
        for (child_pid, child_exit) in completions {
            for i in 0..self.processes.len() {
                if self.processes[i].waiting_on == Some(child_pid) {
                    self.processes[i].waiting_on = None;
                    self.processes[i].core.r[R0 as usize] = child_exit;
                    self.resume_from_trap(i);
                }
            }
        }
    }

    fn run_process(&mut self, idx: usize, quantum: usize) {
        for _ in 0..quantum {
            if self.processes[idx].exited {
                return;
            }

            let result = self.processes[idx].core.step(&mut self.fabric);
            match result {
                super::core::StepResult::Continue => {}
                super::core::StepResult::Halted => {
                    match classify_halt(&self.processes[idx].core) {
                        HaltDisposition::Syscall => {
                            self.handle_syscall(idx);
                        }
                        HaltDisposition::SupervisorFault => {
                            let core = &self.processes[idx].core;
                            eprintln!("Process {} supervisor halt at {:#x} (not trap gate {:#x})",
                                self.processes[idx].pid, core.pc, core.trap_vector);
                            self.processes[idx].exited = true;
                            self.processes[idx].exit_code = 0xDEAD;
                        }
                        HaltDisposition::UserExit(code) => {
                            self.processes[idx].exit_code = code;
                            self.processes[idx].exited = true;
                        }
                    }
                    return;
                }
                super::core::StepResult::Fault(f) => {
                    eprintln!("Process {} faulted: {:?} obj={:?} off={:#x} kind={:?} pc={:#x}",
                        self.processes[idx].pid, f.reason,
                        f.object, f.offset, f.kind,
                        self.processes[idx].core.pc);
                    self.processes[idx].exited = true;
                    self.processes[idx].exit_code = 0xDEAD;
                    return;
                }
            }
        }
    }

    fn handle_syscall(&mut self, idx: usize) {
        let proc = &mut self.processes[idx];
        let syscall = proc.core.r[R0 as usize];

        match syscall {
            SYS_EXIT => {
                proc.exit_code = proc.core.r[R1 as usize];
                proc.exited = true;
            }
            SYS_WRITE => {
                self.handle_buffer_write(idx);
            }
            SYS_YIELD => {
                proc.core.r[R0 as usize] = 0;
                self.resume_from_trap(idx);
            }
            SYS_SEND => {
                let dest_pid = proc.core.r[R1 as usize];
                let value = proc.core.r[R2 as usize];
                let from_pid = proc.pid;
                if (dest_pid as usize) < self.mailboxes.len() {
                    self.mailboxes[dest_pid as usize].push(Message { from_pid, value });
                    proc.core.r[R0 as usize] = 0;
                } else {
                    proc.core.r[R0 as usize] = u64::MAX; // error
                }
                self.resume_from_trap(idx);
            }
            SYS_RECV => {
                let pid = proc.pid as usize;
                if let Some(msg) = self.mailboxes[pid].pop() {
                    proc.core.r[R0 as usize] = msg.value;
                } else {
                    proc.core.r[R0 as usize] = 0; // no message
                }
                self.resume_from_trap(idx);
            }
            SYS_SEAL => {
                self.handle_seal(idx);
            }
            SYS_EXEC => {
                self.handle_exec(idx);
            }
            _ => {
                eprintln!("Unknown syscall {} from pid {}", syscall, proc.pid);
                proc.exited = true;
                proc.exit_code = 0xBAD;
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
    fn handle_exec(&mut self, idx: usize) {
        let code_vaddr = self.processes[idx].core.r[R1 as usize];
        let code_size = self.processes[idx].core.r[R2 as usize];
        let lit_start = self.processes[idx].core.r[R3 as usize];

        let (code_obj, code_offset) = match self.processes[idx].core.address_map.resolve(code_vaddr) {
            Some(r) => r,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Check 1: object must be Sealed
        let is_sealed = self.fabric.objects.get(&code_obj)
            .map(|o| o.state == ObjectState::Sealed)
            .unwrap_or(false);
        if !is_sealed {
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // Compute image_size = obj_size - code_offset
        let obj_size = match self.fabric.objects.get(&code_obj) {
            Some(o) => o.size,
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };
        let image_size = obj_size - code_offset;

        // Check 2: validate literal segment geometry (if present)
        let has_literals = lit_start != 0;
        if has_literals {
            // code_size <= lit_start (disjoint regions, empty gap is OK)
            if lit_start < code_size {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
            // lit_start < image_size (strict: zero-width literal is meaningless)
            if image_size <= lit_start {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        }

        let domain = self.processes[idx].core.domain;

        // Check 3: range-exact RX authority covering the code range.
        // Search for READ|EXECUTE (RX) so the query matches what we derive.
        let code_parent = match self.fabric.find_authorizing_cap(
            domain, code_obj, code_offset, code_size, Permissions::RX
        ) {
            Some(cap) => cap.clone(),
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        // Check 4: if literals, find READ parent covering literal range
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
                    return;
                }
            }
        } else {
            None
        };

        // --- Preflight complete: now create child domain ---
        // Transactional: all checks passed before any domain/object creation.
        let child_dom = self.fabric.create_domain();

        // Derive child's RX from code parent (I7).
        if self.fabric.derive(
            child_dom, &code_parent, code_offset, code_size, Permissions::RX,
        ).is_none() {
            self.fabric.destroy_domain(child_dom);
            self.processes[idx].core.r[R0 as usize] = u64::MAX;
            self.resume_from_trap(idx);
            return;
        }

        // If literals, derive child's R from literal parent.
        // Rule 29: data is not authority to transfer control.
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
                return;
            }
        }

        // --- Create child process using shared primitive ---
        let desc = ProcessImageDesc {
            code_obj,
            code_offset,
            code_size,
            lit_start,
            image_size,
            entry: 0,
        };
        let child_pid = self.prepare_process(child_dom, &desc, &EXEC_DEFAULT_LAYOUT);
        self.processes[child_pid as usize].parent = Some(self.processes[idx].pid);

        // Block the parent until the child exits.
        // The scheduler will resume the parent when it reaps the child.
        self.processes[idx].waiting_on = Some(child_pid);
        // Do NOT call resume_from_trap here — the parent stays suspended.
        // When the child exits, complete_wait() will set R0 and resume.
    }

    fn resume_from_trap(&mut self, idx: usize) {
        let proc = &mut self.processes[idx];
        // TRAP set saved_pc and privilege. ERET restores them.
        // But since we intercepted the HALT in the trap handler,
        // we need to manually restore and advance.
        // The trap saved PC+4 (instruction after TRAP).
        // We restore privilege and jump to saved_pc.
        proc.core.privilege = Privilege::User;
        proc.core.halted = false;
        // PC is at the HALT in the trap handler. We need to go to
        // the saved return address. The trap handler is:
        //   HALT  (we intercepted here)
        // So saved_pc points to the instruction after the TRAP.
        if let Some(pc) = proc.core.saved_pc.take() {
            proc.core.pc = pc;
        }
        if let Some(priv_) = proc.core.saved_privilege.take() {
            proc.core.privilege = priv_;
        }
    }
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

        assert!(kernel.processes[0].exited, "process should have exited");
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

        assert!(kernel.processes[0].exited, "A should have exited");
        assert!(kernel.processes[1].exited, "B should have exited");
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
        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
        assert_eq!(kernel.processes[0].exit_code, 77,
            "child should return 77");
        assert!(kernel.processes.len() >= 2);

        // Verify child's code capability was derived (subset of parent's)
        let child_dom = kernel.processes[1].core.domain;
        let child_caps: Vec<_> = kernel.fabric.domains[&child_dom]
            .capabilities.iter()
            .filter(|c| c.object() == code)
            .collect();
        assert!(!child_caps.is_empty(), "child should have code capability");
        let child_code_cap = child_caps[0];
        // Child's range [offset, offset+length) must be within parent's [0, 0x1000)
        assert_eq!(child_code_cap.offset(), 0);
        assert_eq!(child_code_cap.length(), 16);
        assert!(child_code_cap.permissions().is_subset_of(Permissions::RX),
            "child permissions must be subset of parent's RX");

        eprintln!("S6: child code cap = ({}, {}, {:?}) ⊆ parent (0, 0x1000, RX) ✓",
            child_code_cap.offset(), child_code_cap.length(),
            child_code_cap.permissions());
        eprintln!("    Authority(child) ⊆ Authority(parent) — I7 structural");
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
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

        assert!(kernel.processes[0].exited);
        assert_eq!(kernel.processes[0].exit_code, u64::MAX,
            "nonzero R3 must be rejected");
        assert!(kernel.byte_output.is_empty(),
            "no bytes committed when R3 != 0");
        eprintln!("7.3h: R3 nonzero → u64::MAX, no output ✓");
    }

}

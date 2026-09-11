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
pub const SYS_WRITE: u64 = 1;  // write(value) — log output
pub const SYS_YIELD: u64 = 2;  // yield to other process
pub const SYS_SEND: u64 = 3;   // send(dest_pid, value)
pub const SYS_RECV: u64 = 4;   // recv() → value
pub const SYS_SEAL: u64 = 5;   // seal(addr) — RW→RX, W⊕X enforcement
pub const SYS_EXEC: u64 = 6;   // exec(code_addr, code_size) → child exit code

// ───────────────────────────────────────────────────────────────────
// Process descriptor
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u64,
    pub core: Anka64Core,
    pub exited: bool,
    pub exit_code: u64,
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
// Kernel
// ───────────────────────────────────────────────────────────────────

pub struct Kernel {
    pub fabric: Fabric,
    pub processes: Vec<Process>,
    pub output: Vec<(u64, u64)>,  // (pid, value) log
    mailboxes: Vec<Vec<Message>>,
    current: usize,
    /// Next available physical address for dynamic allocation.
    pub next_phys: u64,
    /// Next available agent ID for child processes.
    pub next_agent: u64,
}

impl Kernel {
    pub fn new(fabric: Fabric) -> Self {
        Self {
            fabric,
            processes: Vec::new(),
            output: Vec::new(),
            mailboxes: Vec::new(),
            current: 0,
            next_phys: 0x100000,
            next_agent: 100,
        }
    }

    pub fn spawn(&mut self, core: Anka64Core) -> u64 {
        let pid = self.processes.len() as u64;
        self.processes.push(Process {
            pid,
            core,
            exited: false,
            exit_code: 0,
        });
        self.mailboxes.push(Vec::new());
        pid
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
                self.current = i;
                self.run_process(i, quantum);
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
                    // Check if we're in the trap vector (syscall)
                    self.handle_syscall(idx);
                    return;
                }
                super::core::StepResult::Fault(f) => {
                    eprintln!("Process {} faulted: {:?}", self.processes[idx].pid, f.reason);
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
                let value = proc.core.r[R1 as usize];
                self.output.push((proc.pid, value));
                // Return 0 (success)
                proc.core.r[R0 as usize] = 0;
                self.resume_from_trap(idx);
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
    /// R2 = code size in bytes.
    /// Returns: child's exit code in R0, or MAX on error.
    ///
    /// Three structural checks before the kernel creates anything:
    ///   1. Object must be Sealed (W⊕X: no simultaneous W+X)
    ///   2. Caller must have EXECUTE authority covering the range
    ///      (range-exact, not object-level)
    ///   3. Child's authority is derived from parent's capability,
    ///      not freshly minted — attenuation (I7) applies structurally:
    ///        Authority(C_child) ⊆ Authority(C_parent)
    fn handle_exec(&mut self, idx: usize) {
        let code_vaddr = self.processes[idx].core.r[R1 as usize];
        let code_size = self.processes[idx].core.r[R2 as usize];

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

        let domain = self.processes[idx].core.domain;

        // Check 2: range-exact EXECUTE authority.
        // Narrow execute capability cannot authorize a larger range.
        let parent_cap = match self.fabric.find_authorizing_cap(
            domain, code_obj, code_offset, code_size, Permissions::EXECUTE
        ) {
            Some(cap) => cap.clone(),
            None => {
                self.processes[idx].core.r[R0 as usize] = u64::MAX;
                self.resume_from_trap(idx);
                return;
            }
        };

        // --- Child domain: isolated authority container ---
        // Check 3: derive child's RX from parent's capability (I7).
        // Authority(C_child) ⊆ Authority(C_parent).
        let child_dom = self.fabric.create_domain();
        let child_perms = Permissions(
            parent_cap.permissions().0 & Permissions::RX.0
        );
        self.fabric.derive(
            child_dom, &parent_cap, code_offset, code_size, child_perms,
        );

        // --- Child stack ---
        let stack_size: u64 = 0x4000;
        let stack_obj = self.fabric.alloc_object("child_stack", stack_size, ObjectKind::Memory);
        let stack_phys = self.next_phys;
        self.next_phys += stack_size;
        self.fabric.place_object(stack_obj, stack_phys);
        self.fabric.grant(child_dom, stack_obj, 0, stack_size, Permissions::RW);

        // --- Child trap handler: alloc → initialize → seal → grant RX ---
        // W⊕X: no exceptional executable-object creation path.
        let trap_size: u64 = 0x1000;
        let trap_obj = self.fabric.alloc_object("child_trap", trap_size, ObjectKind::Memory);
        let trap_phys = self.next_phys;
        self.next_phys += trap_size;
        self.fabric.place_object(trap_obj, trap_phys);

        let mut handler = Asm64::new();
        handler.halt();
        self.fabric.initialize_object(trap_obj, 0, &handler.to_bytes());
        self.fabric.seal_object(trap_obj);
        self.fabric.grant(child_dom, trap_obj, 0, trap_size, Permissions::RX);

        // --- Child core ---
        let child_agent = AgentId(self.next_agent);
        self.next_agent += 1;

        let mut child = Anka64Core::new(child_agent, child_dom);
        child.address_map.add(0x00000, code_size, code_obj);
        child.address_map.add(0x10000, stack_size, stack_obj);
        child.address_map.add(0x20000, trap_size, trap_obj);
        child.r[SP as usize] = 0x10000 + stack_size;
        child.trap_vector = 0x20000;

        // --- Spawn and run synchronously ---
        let child_pid = self.spawn(child);
        let child_idx = child_pid as usize;
        self.run_to_completion(child_idx, 100_000);

        // Return child's exit code to the parent
        self.processes[idx].core.r[R0 as usize] = self.processes[child_idx].exit_code;
        self.resume_from_trap(idx);
    }

    /// Run a process to completion (used by SYS_EXEC).
    fn run_to_completion(&mut self, idx: usize, max_steps: usize) {
        for _ in 0..max_steps {
            if self.processes[idx].exited { return; }

            let result = self.processes[idx].core.step(&mut self.fabric);
            match result {
                super::core::StepResult::Continue => {}
                super::core::StepResult::Halted => {
                    self.handle_syscall(idx);
                }
                super::core::StepResult::Fault(f) => {
                    eprintln!("Process {} faulted: {:?}", self.processes[idx].pid, f.reason);
                    self.processes[idx].exited = true;
                    self.processes[idx].exit_code = 0xDEAD;
                    return;
                }
            }
        }
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
    use super::super::cc::{self, Program, Function, Stmt, Expr, BinOp, Type, VarId};

    const CPU0: AgentId = AgentId(0);

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

    fn install_trap_handler(fabric: &mut Fabric, text_phys: u64) {
        let mut handler = Asm64::new();
        handler.halt();
        fabric.write_physical(text_phys + 0x3FF0, &handler.to_bytes());
    }

    /// Seal an object and grant RX to a domain.
    /// W⊕X lifecycle: Active(write) → Sealed(fetch).
    fn seal_code_object(fabric: &mut Fabric, obj: ObjectId, dom: DomainId) {
        fabric.seal_object(obj);
        let size = fabric.objects[&obj].size;
        fabric.grant(dom, obj, 0, size, Permissions::RX);
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
        let mut fabric = Fabric::new(0x400000);
        let (core, _dom, _text, _data, _stack) =
            create_process(&mut fabric, CPU0, "proc0", 0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000);

        // Build program — must be written before sealing text object
        //   syscall_write(42): R0=SYS_WRITE, R1=42, TRAP #0
        //   syscall_exit(0):   R0=SYS_EXIT,  R1=0,  TRAP #0
        // Build the program manually via Asm64
        // since the compiler doesn't have syscall intrinsics yet.
        let mut asm = Asm64::new();
        // _start: call main
        asm.call(2);                // word 0 → jump to word 2
        asm.halt();                 // word 1

        // main:
        // syscall_write(42)
        asm.movi(R0, SYS_WRITE as i32);  // R0 = 1 (SYS_WRITE)
        asm.movi(R1, 42);                 // R1 = 42
        asm.trap(0);                       // TRAP → kernel intercepts

        // syscall_write(99)
        asm.movi(R0, SYS_WRITE as i32);
        asm.movi(R1, 99);
        asm.trap(0);

        // syscall_exit(0)
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
        assert_eq!(kernel.output.len(), 2, "should have 2 write outputs");
        assert_eq!(kernel.output[0], (0, 42), "first write should be 42");
        assert_eq!(kernel.output[1], (0, 99), "second write should be 99");
        eprintln!("P14: syscall_write(42), syscall_write(99), syscall_exit(0) ✓");
        eprintln!("     output: {:?}", kernel.output);
    }

    // ═══════════════════════════════════════════════════════════
    // P15: Two processes in separate domains communicating
    //
    //   Process A: send(1, 42), exit(0)
    //   Process B: v = recv(), write(v), exit(v)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p15_two_processes_ipc() {
        let mut fabric = Fabric::new(0x800000);

        // Process A at physical 0x000000..
        let (core_a, dom_a, text_a, _d, _s) =
            create_process(&mut fabric, AgentId(0), "procA",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000);

        // Process B at physical 0x100000..
        let (core_b, dom_b, text_b, _d, _s) =
            create_process(&mut fabric, AgentId(1), "procB",
                0x100000, 0x110000, 0x120000);
        install_trap_handler(&mut fabric, 0x100000);

        // Process A code: send(pid=1, value=42), exit(0)
        let mut asm_a = Asm64::new();
        asm_a.movi(R0, SYS_SEND as i32);
        asm_a.movi(R1, 1);    // dest pid
        asm_a.movi(R2, 42);   // value
        asm_a.trap(0);
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.movi(R1, 0);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());

        // Process B code: v = recv(), write(v), exit(v)
        let mut asm_b = Asm64::new();
        asm_b.movi(R0, SYS_RECV as i32);
        asm_b.trap(0);
        // R0 now has received value
        asm_b.mov(R1, R0);     // save value
        asm_b.movi(R0, SYS_WRITE as i32);
        asm_b.trap(0);          // write(v)
        asm_b.mov(R1, R0);     // Hmm, R0 was clobbered by write return
        // Let's fix: save received value first
        asm_b.movi(R0, SYS_EXIT as i32);
        // We need the received value for exit code. Let's restructure.
        asm_b.trap(0);
        fabric.write_physical(0x100000, &asm_b.to_bytes());

        // Actually, let me rewrite B more carefully:
        let mut asm_b = Asm64::new();
        asm_b.movi(R0, SYS_RECV as i32);
        asm_b.trap(0);
        // R0 = received value (42)
        asm_b.mov(R4, R0);     // save in R4

        asm_b.movi(R0, SYS_WRITE as i32);
        asm_b.mov(R1, R4);     // write(42)
        asm_b.trap(0);

        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.mov(R1, R4);     // exit(42)
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
        assert_eq!(kernel.output.len(), 1);
        assert_eq!(kernel.output[0], (1, 42), "B wrote 42");

        eprintln!("P15: A→send(42)→B, B→recv()=42→write(42)→exit(42) ✓");
        eprintln!("     Process A domain ≠ Process B domain");
        eprintln!("     Both domains protected by the fabric");
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

        install_trap_handler(&mut fabric, 0x000000);

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

        install_trap_handler(&mut fabric, 0x000000);

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

        install_trap_handler(&mut fabric, 0x000000);

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

        install_trap_handler(&mut fabric, 0x000000);

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

        install_trap_handler(&mut fabric, 0x000000);

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

    // ═══════════════════════════════════════════════════════════
    // P20: Guest-hosted compilation — int main() { return 42; }
    //
    //   Phase 6A: the machine creates software for itself.
    //
    //   1. Host AnkaCC₆₄ compiles a tiny C "compiler" to Anka64 code
    //   2. The compiler runs as a user process:
    //      - reads return value (42) from source object
    //      - encodes Anka64 instructions into output buffer
    //      - calls SYS_SEAL → kernel enforces W⊕X (RW → RX)
    //      - calls SYS_EXEC → kernel spawns child from sealed code
    //   3. Child process executes the compiled code → exits with 42
    //   4. Parent receives child's exit code → exits with 42
    //
    //   Security properties proven:
    //     - No special compiler privilege (ordinary user process)
    //     - W⊕X: mutable data → kernel seal → executable code
    //     - Child runs in its own domain (authority isolation)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p20_guest_compiler_return_42() {
        // ─── Physical memory layout ───────────────────────────
        //   0x000000 : compiler text    (0x4000)
        //   0x010000 : source data      (0x1000)
        //   0x020000 : output buffer    (0x1000)
        //   0x030000 : compiler stack   (0x4000)
        //   0x040000+: dynamic (kernel allocs child stack, trap)
        let mut fabric = Fabric::new(0x200000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(stack,  0x030000);

        let dom = fabric.create_domain();
        // text: RX granted after seal (below)
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS); // RW+Seal: code emission buffer
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Source: the number 42 as a 64-bit little-endian value
        fabric.write_physical(0x010000, &42u64.to_le_bytes());

        // Trap handler at offset 0x3FF0 in text object
        install_trap_handler(&mut fabric, 0x000000);

        // ─── The guest compiler: a C program ──────────────────
        //
        //   Virtual address map:
        //     0x00000 : text (RX)   — compiler code
        //     0x04000 : source (R)  — contains return value
        //     0x05000 : output (RW) — code emission target
        //     0x06000 : stack (RW)  — grows downward from 0x0A000
        //
        //   The compiler reads the return value from source,
        //   encodes three Anka64 instructions, stores them to
        //   the output buffer, seals it (RW→RX), and execs it.
        //
        //   Anka64 encoding constants:
        //     MOVI opcode = 22 (0x16), I-format: [op(6)|rd(4)|rs1(4)|imm(18)]
        //     TRAP opcode = 57 (0x39), S-format: [op(6)|imm(26)]
        //     NOP  opcode = 63 (0x3F), S-format
        //
        //   Emitted code for `int main() { return 42; }`:
        //     word 0: MOVI R1, 42     ; exit code
        //     word 1: MOVI R0, 0      ; SYS_EXIT
        //     word 2: TRAP #0         ; syscall
        //     word 3: NOP             ; padding

        let compiler_prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![
                    (0, Type::Int),  // retval
                    (1, Type::Int),  // movi_r1
                    (2, Type::Int),  // movi_r0
                    (3, Type::Int),  // trap_insn
                    (4, Type::Int),  // nop_insn
                    (5, Type::Int),  // pair0
                    (6, Type::Int),  // pair1
                    (7, Type::Int),  // child_exit
                ],
                body: vec![
                    // retval = *(int*)0x4000
                    Stmt::VarDecl(0, Type::Int, Some(
                        Expr::Deref(Box::new(Expr::IntLit(0x4000)))
                    )),

                    // movi_r1 = (22 << 26) | (1 << 22) | retval
                    Stmt::VarDecl(1, Type::Int, Some(
                        Expr::BinOp(BinOp::Or,
                            Box::new(Expr::BinOp(BinOp::Or,
                                Box::new(Expr::BinOp(BinOp::Shl,
                                    Box::new(Expr::IntLit(22)),
                                    Box::new(Expr::IntLit(26)),
                                )),
                                Box::new(Expr::BinOp(BinOp::Shl,
                                    Box::new(Expr::IntLit(1)),
                                    Box::new(Expr::IntLit(22)),
                                )),
                            )),
                            Box::new(Expr::Var(0)),
                        )
                    )),

                    // movi_r0 = 22 << 26
                    Stmt::VarDecl(2, Type::Int, Some(
                        Expr::BinOp(BinOp::Shl,
                            Box::new(Expr::IntLit(22)),
                            Box::new(Expr::IntLit(26)),
                        )
                    )),

                    // trap_insn = 57 << 26
                    Stmt::VarDecl(3, Type::Int, Some(
                        Expr::BinOp(BinOp::Shl,
                            Box::new(Expr::IntLit(57)),
                            Box::new(Expr::IntLit(26)),
                        )
                    )),

                    // nop_insn = 63 << 26
                    Stmt::VarDecl(4, Type::Int, Some(
                        Expr::BinOp(BinOp::Shl,
                            Box::new(Expr::IntLit(63)),
                            Box::new(Expr::IntLit(26)),
                        )
                    )),

                    // pair0 = movi_r1 | (movi_r0 << 32)
                    // Packs two 32-bit instructions into one 64-bit store:
                    //   low  word (offset +0): MOVI R1, retval
                    //   high word (offset +4): MOVI R0, 0
                    Stmt::VarDecl(5, Type::Int, Some(
                        Expr::BinOp(BinOp::Or,
                            Box::new(Expr::Var(1)),
                            Box::new(Expr::BinOp(BinOp::Shl,
                                Box::new(Expr::Var(2)),
                                Box::new(Expr::IntLit(32)),
                            )),
                        )
                    )),

                    // *(int*)0x5000 = pair0
                    Stmt::Expr(Expr::DerefAssign(
                        Box::new(Expr::IntLit(0x5000)),
                        Box::new(Expr::Var(5)),
                    )),

                    // pair1 = trap_insn | (nop_insn << 32)
                    //   low  word (offset +8): TRAP #0
                    //   high word (offset +C): NOP
                    Stmt::VarDecl(6, Type::Int, Some(
                        Expr::BinOp(BinOp::Or,
                            Box::new(Expr::Var(3)),
                            Box::new(Expr::BinOp(BinOp::Shl,
                                Box::new(Expr::Var(4)),
                                Box::new(Expr::IntLit(32)),
                            )),
                        )
                    )),

                    // *(int*)0x5008 = pair1
                    Stmt::Expr(Expr::DerefAssign(
                        Box::new(Expr::IntLit(0x5008)),
                        Box::new(Expr::Var(6)),
                    )),

                    // SYS_SEAL: seal output buffer (RW → RX)
                    Stmt::Expr(Expr::Syscall(SYS_SEAL as u8, vec![
                        Expr::IntLit(0x5000),
                    ])),

                    // SYS_EXEC: spawn child from sealed code
                    Stmt::VarDecl(7, Type::Int, Some(
                        Expr::Syscall(SYS_EXEC as u8, vec![
                            Expr::IntLit(0x5000),
                            Expr::IntLit(16),   // 4 words × 4 bytes
                        ])
                    )),

                    // SYS_EXIT with child's result
                    Stmt::Expr(Expr::Syscall(SYS_EXIT as u8, vec![
                        Expr::Var(7),
                    ])),
                ],
            }],
        };

        // ─── Compile with host AnkaCC₆₄ ──────────────────────
        let asm = cc::compile(&compiler_prog);
        eprintln!("--- Guest compiler listing ---");
        eprintln!("{}", asm.listing());
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // ─── Set up compiler process ──────────────────────────
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);    // code
        core.address_map.add(0x04000, 0x1000, source);  // source data
        core.address_map.add(0x05000, 0x1000, output);  // output buffer
        core.address_map.add(0x06000, 0x4000, stack);   // stack
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        // ─── Run ──────────────────────────────────────────────
        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(1000, 1000);

        // ─── Verify ───────────────────────────────────────────

        // Compiler process exited with child's result
        assert!(kernel.processes[0].exited,
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, 42,
            "compiler should exit with child's result (42)");

        // Child process was spawned and exited with 42
        assert!(kernel.processes.len() >= 2,
            "child process should have been spawned");
        assert!(kernel.processes[1].exited,
            "child process should have exited");
        assert_eq!(kernel.processes[1].exit_code, 42,
            "child should have returned 42");

        // ─── The three 42s ────────────────────────────────────
        //   First 42:  emulator executes code
        //   Second 42: Anka64 executes its own ISA
        //   Third 42:  Anka64 creates the program that returns 42
        eprintln!();
        eprintln!("P20: int main() {{ return 42; }} ✓");
        eprintln!("     Guest compiler → sealed executable → child → R0 = 42");
        eprintln!("     W⊕X lifecycle: source(R) → compiler → output(RW) → seal → code(RX) → execute");
        eprintln!("     No special compiler privilege — ordinary user process");
        eprintln!("     Child domain ≠ parent domain (authority isolation)");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 6B.0 / 6B.0a: text source → guest lexer → code → seal → exec
    //
    // Exit criterion: an ordinary protected Anka64 user process
    // consumes an R-only text object, derives its meaning without
    // host assistance, produces an executable object, seals it,
    // executes it, and obtains the source-specified result.
    //
    //   text bytes "42" → guest lexer → MOVI R1,42; ... → seal → exec → 42
    //
    // The guest reads individual bytes via load-word + shift/mask.
    // No byte-width load instruction exists — the client struggles.
    //
    // 6B.0a additions:
    //   - Integer overflow detected during parsing, not after masking.
    //     value ≥ 131072 → compile error.  Silent truncation is forbidden.
    //   - Source scanning is length-bounded, not NUL-bounded.
    //     Source layout: [u64 length][text bytes...].
    //     Loop guard: pos < src_len.
    //     Memory authority does not imply object-role semantics.
    //   - Loop-scoped variables declared outside loop, assigned inside.
    //     No VarDecl stack leak per iteration.
    // ═══════════════════════════════════════════════════════════════

    /// Build the 6B.0 guest compiler program.
    ///
    /// Virtual address map:
    ///   0x00000 : text (RX)      — compiler code
    ///   0x04000 : source (R)     — [u64 length][text bytes...]
    ///   0x05000 : output (RWS)   — code emission target
    ///   0x06000 : workspace (RW) — scratch (reserved for future use)
    ///   0x07000 : stack (RW)     — grows downward from 0x0B000
    ///
    /// Algorithm:
    ///   1. Read source length from *(src_base), text starts at src_base+8
    ///   2. Scan source bytes with pos < src_len guard
    ///      byte access: LD word at (text_base + (pos & ~7)),
    ///                   shift right by (pos & 7) * 8, mask 0xFF
    ///   3. Accumulate: value = value * 10 + (byte - '0')
    ///   4. After each accumulation: if value ≥ 131072, overflow error
    ///   5. On non-digit: stop scanning
    ///   6. If no digits or overflow: exit(MAX)
    ///   7. Emit MOVI R1,value; MOVI R0,0; TRAP #0; NOP to output
    ///   8. SYS_SEAL output, SYS_EXEC, exit with child result
    fn build_6b0_compiler() -> Program {
        // Variable IDs — all declared once at function scope
        const SRC_BASE: VarId   = 0;
        const OUT_BASE: VarId   = 1;
        const POS: VarId        = 2;
        const VALUE: VarId      = 3;
        const HAS_DIGIT: VarId  = 4;
        const RUNNING: VarId    = 5;
        const WORD: VarId       = 6;
        const BYTE_SHIFT: VarId = 7;
        const CH: VarId         = 8;
        const IS_DIGIT: VarId   = 9;
        const MOVI_R1: VarId    = 10;
        const MOVI_R0: VarId    = 11;
        const TRAP_INSN: VarId  = 12;
        const NOP_INSN: VarId   = 13;
        const PAIR0: VarId      = 14;
        const PAIR1: VarId      = 15;
        const CHILD: VarId      = 16;
        const ALIGNED: VarId    = 17;
        const OVERFLOW: VarId   = 18;
        const SRC_LEN: VarId    = 19;
        const TEXT_BASE: VarId  = 20;

        // Helpers for common expression patterns
        fn lit(v: i64) -> Expr { Expr::IntLit(v) }
        fn var(id: VarId) -> Expr { Expr::Var(id) }
        fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
            Expr::BinOp(op, Box::new(a), Box::new(b))
        }
        fn assign(id: VarId, e: Expr) -> Stmt {
            Stmt::Expr(Expr::Assign(id, Box::new(e)))
        }
        fn deref(addr: Expr) -> Expr { Expr::Deref(Box::new(addr)) }
        fn deref_assign(addr: Expr, val: Expr) -> Stmt {
            Stmt::Expr(Expr::DerefAssign(Box::new(addr), Box::new(val)))
        }
        fn syscall(num: u8, args: Vec<Expr>) -> Expr {
            Expr::Syscall(num, args)
        }

        Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![
                    (SRC_BASE, Type::Int),
                    (OUT_BASE, Type::Int),
                    (POS, Type::Int),
                    (VALUE, Type::Int),
                    (HAS_DIGIT, Type::Int),
                    (RUNNING, Type::Int),
                    (WORD, Type::Int),
                    (BYTE_SHIFT, Type::Int),
                    (CH, Type::Int),
                    (IS_DIGIT, Type::Int),
                    (MOVI_R1, Type::Int),
                    (MOVI_R0, Type::Int),
                    (TRAP_INSN, Type::Int),
                    (NOP_INSN, Type::Int),
                    (PAIR0, Type::Int),
                    (PAIR1, Type::Int),
                    (CHILD, Type::Int),
                    (ALIGNED, Type::Int),
                    (OVERFLOW, Type::Int),
                    (SRC_LEN, Type::Int),
                    (TEXT_BASE, Type::Int),
                ],
                body: vec![
                    // ─── Initialize ─────────────────────────────
                    Stmt::VarDecl(SRC_BASE, Type::Int, Some(lit(0x4000))),
                    Stmt::VarDecl(OUT_BASE, Type::Int, Some(lit(0x5000))),
                    Stmt::VarDecl(POS, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(VALUE, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(HAS_DIGIT, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(RUNNING, Type::Int, Some(lit(1))),
                    Stmt::VarDecl(OVERFLOW, Type::Int, Some(lit(0))),

                    // Source layout: [u64 length][text bytes...]
                    // src_len = *src_base
                    Stmt::VarDecl(SRC_LEN, Type::Int, Some(
                        deref(var(SRC_BASE))
                    )),
                    // text_base = src_base + 8
                    Stmt::VarDecl(TEXT_BASE, Type::Int, Some(
                        binop(BinOp::Add, var(SRC_BASE), lit(8))
                    )),

                    // ─── Source metadata guard ──────────────────
                    // Source object = 0x1000 bytes. Header = 8 bytes.
                    // Max valid text payload = 0x1000 - 8 = 0xFF8 = 4088.
                    // A malformed header claiming more would cause reads
                    // beyond the source object into adjacent capabilities.
                    // Memory authority ≠ source-role authority.
                    Stmt::If(
                        binop(BinOp::Lt, lit(0xFF8), var(SRC_LEN)),
                        vec![
                            Stmt::Expr(syscall(SYS_EXIT as u8, vec![lit(-1)])),
                        ],
                        vec![],
                    ),

                    // Declare loop-scoped variables once (no VarDecl in loop)
                    Stmt::VarDecl(ALIGNED, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(WORD, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(BYTE_SHIFT, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(CH, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(IS_DIGIT, Type::Int, Some(lit(0))),

                    // ─── Lexer loop: length-bounded digit scan ──
                    //
                    // while (running) {
                    //   if (pos >= src_len) { running = 0; }
                    //   else {
                    //     aligned = text_base + (pos & ~7)
                    //     word = *aligned
                    //     byte_shift = (pos & 7) * 8
                    //     ch = (word >> byte_shift) & 0xFF
                    //     is_digit = (48 ≤ ch) & (ch ≤ 57)
                    //     if (is_digit) {
                    //       value = value * 10 + (ch - 48)
                    //       if (value ≥ 131072) { overflow = 1; running = 0; }
                    //       else { has_digit = 1; pos++; }
                    //     } else { running = 0; }
                    //   }
                    // }
                    Stmt::While(
                        var(RUNNING),
                        vec![
                            // Bounds check: Le(SRC_LEN, POS) = src_len ≤ pos
                            Stmt::If(
                                binop(BinOp::Le, var(SRC_LEN), var(POS)),
                                vec![
                                    // pos ≥ src_len → end of source
                                    assign(RUNNING, lit(0)),
                                ],
                                vec![
                                    // In bounds → extract byte
                                    // aligned = text_base + (pos & ~7)
                                    assign(ALIGNED,
                                        binop(BinOp::Add,
                                            var(TEXT_BASE),
                                            binop(BinOp::And, var(POS), lit(-8)),
                                        )
                                    ),
                                    assign(WORD, deref(var(ALIGNED))),
                                    // byte_shift = (pos & 7) * 8
                                    assign(BYTE_SHIFT,
                                        binop(BinOp::Mul,
                                            binop(BinOp::And, var(POS), lit(7)),
                                            lit(8),
                                        )
                                    ),
                                    // ch = (word >> byte_shift) & 0xFF
                                    assign(CH,
                                        binop(BinOp::And,
                                            binop(BinOp::Shr, var(WORD), var(BYTE_SHIFT)),
                                            lit(0xFF),
                                        )
                                    ),
                                    // is_digit = (48 ≤ ch) & (ch ≤ 57)
                                    assign(IS_DIGIT,
                                        binop(BinOp::And,
                                            binop(BinOp::Le, lit(48), var(CH)),
                                            binop(BinOp::Le, var(CH), lit(57)),
                                        )
                                    ),
                                    Stmt::If(
                                        var(IS_DIGIT),
                                        vec![
                                            // value = value * 10 + (ch - 48)
                                            assign(VALUE,
                                                binop(BinOp::Add,
                                                    binop(BinOp::Mul, var(VALUE), lit(10)),
                                                    binop(BinOp::Sub, var(CH), lit(48)),
                                                )
                                            ),
                                            // Overflow check: value > 131071
                                            // Lt(131071, VALUE) = 131071 < value
                                            // (131072 is not representable as
                                            //  18-bit signed MOVI immediate)
                                            Stmt::If(
                                                binop(BinOp::Lt, lit(131071), var(VALUE)),
                                                vec![
                                                    assign(OVERFLOW, lit(1)),
                                                    assign(RUNNING, lit(0)),
                                                ],
                                                vec![
                                                    assign(HAS_DIGIT, lit(1)),
                                                    assign(POS,
                                                        binop(BinOp::Add, var(POS), lit(1))
                                                    ),
                                                ],
                                            ),
                                        ],
                                        vec![
                                            // non-digit → stop
                                            assign(RUNNING, lit(0)),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),

                    // ─── Error check: no digits or overflow ─────
                    // if (!has_digit || overflow) exit(MAX)
                    Stmt::If(
                        binop(BinOp::Eq, var(HAS_DIGIT), lit(0)),
                        vec![
                            Stmt::Expr(syscall(SYS_EXIT as u8, vec![lit(-1)])),
                        ],
                        vec![],
                    ),
                    Stmt::If(
                        var(OVERFLOW),
                        vec![
                            Stmt::Expr(syscall(SYS_EXIT as u8, vec![lit(-1)])),
                        ],
                        vec![],
                    ),

                    // ─── Code emission ──────────────────────────
                    // Encode: MOVI R1, value; MOVI R0, 0; TRAP #0; NOP
                    //
                    // MOVI opcode = 22, I-format: [op(6)|rd(4)|rs1(4)|imm(18)]
                    // movi_r1 = (22 << 26) | (1 << 22) | value
                    // (value is guaranteed ≤ 131071 = 0x1FFFF, fits in 18 bits)
                    Stmt::VarDecl(MOVI_R1, Type::Int, Some(
                        binop(BinOp::Or,
                            binop(BinOp::Or,
                                binop(BinOp::Shl, lit(22), lit(26)),
                                binop(BinOp::Shl, lit(1), lit(22)),
                            ),
                            var(VALUE),
                        )
                    )),
                    // movi_r0 = 22 << 26
                    Stmt::VarDecl(MOVI_R0, Type::Int, Some(
                        binop(BinOp::Shl, lit(22), lit(26))
                    )),
                    // trap = 57 << 26
                    Stmt::VarDecl(TRAP_INSN, Type::Int, Some(
                        binop(BinOp::Shl, lit(57), lit(26))
                    )),
                    // nop = 63 << 26
                    Stmt::VarDecl(NOP_INSN, Type::Int, Some(
                        binop(BinOp::Shl, lit(63), lit(26))
                    )),

                    // Pack two 32-bit instructions per 64-bit store
                    // pair0 = movi_r1 | (movi_r0 << 32)
                    Stmt::VarDecl(PAIR0, Type::Int, Some(
                        binop(BinOp::Or,
                            var(MOVI_R1),
                            binop(BinOp::Shl, var(MOVI_R0), lit(32)),
                        )
                    )),
                    // pair1 = trap | (nop << 32)
                    Stmt::VarDecl(PAIR1, Type::Int, Some(
                        binop(BinOp::Or,
                            var(TRAP_INSN),
                            binop(BinOp::Shl, var(NOP_INSN), lit(32)),
                        )
                    )),

                    // Write to output buffer
                    deref_assign(var(OUT_BASE), var(PAIR0)),
                    deref_assign(
                        binop(BinOp::Add, var(OUT_BASE), lit(8)),
                        var(PAIR1),
                    ),

                    // ─── Seal → Exec ────────────────────────────
                    Stmt::Expr(syscall(SYS_SEAL as u8, vec![
                        var(OUT_BASE),
                    ])),
                    Stmt::VarDecl(CHILD, Type::Int, Some(
                        syscall(SYS_EXEC as u8, vec![
                            var(OUT_BASE),
                            lit(16),
                        ])
                    )),
                    Stmt::Expr(syscall(SYS_EXIT as u8, vec![var(CHILD)])),
                ],
            }],
        }
    }

    /// Run a 6B.0 test case: source text → guest compiler → expected result.
    ///
    /// Source object layout: [u64 length][text bytes...]
    /// The harness writes the length header automatically.
    fn run_6b0_test(
        source_text: &[u8],
        expected_exit: u64,
        expect_child: bool,
    ) -> (bool, u64) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Write source: [u64 length][text bytes]
        let src_len = source_text.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, source_text);

        // Trap handler
        install_trap_handler(&mut fabric, 0x000000);

        // Compile the guest compiler from AST
        let compiler_prog = build_6b0_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // Set up process
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);    // code (RX)
        core.address_map.add(0x04000, 0x1000, source);  // source (R)
        core.address_map.add(0x05000, 0x1000, output);  // output (RWS)
        core.address_map.add(0x06000, 0x1000, work);    // workspace (RW)
        core.address_map.add(0x07000, 0x4000, stack);   // stack (RW)
        core.r[SP as usize] = 0x07000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(10000, 10000);

        let exited = kernel.processes[0].exited;
        let exit_code = kernel.processes[0].exit_code;
        let child_spawned = kernel.processes.len() >= 2;

        assert!(exited, "compiler process should have exited");
        assert_eq!(exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, exit_code);

        if expect_child {
            assert!(child_spawned,
                "source {:?}: expected child process",
                std::str::from_utf8(source_text).unwrap_or("<invalid>"));
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
        }

        (child_spawned, exit_code)
    }

    /// Raw 6B.0 test: explicit (declared_length, payload) control.
    ///
    /// Unlike run_6b0_test, the caller controls the length header
    /// independently of the actual payload bytes.  This exercises
    /// the distinction between memory authority and source-role
    /// semantics.
    fn run_6b0_test_raw(
        declared_len: u64,
        payload: &[u8],
        expected_exit: u64,
        expect_child: bool,
    ) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Write source with explicit length header
        fabric.write_physical(0x010000, &declared_len.to_le_bytes());
        let write_len = payload.len().min(0xFF8); // don't overflow object
        fabric.write_physical(0x010008, &payload[..write_len]);

        install_trap_handler(&mut fabric, 0x000000);

        let compiler_prog = build_6b0_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x1000, source);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(0x06000, 0x1000, work);
        core.address_map.add(0x07000, 0x4000, stack);
        core.r[SP as usize] = 0x07000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(10000, 10000);

        assert!(kernel.processes[0].exited,
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "declared_len={}, payload {:?}: expected exit {}, got {}",
            declared_len,
            std::str::from_utf8(payload).unwrap_or("<binary>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 6B.0 / 6B.0a test corpus
    // ═══════════════════════════════════════════════════════════════

    // ─── Core path ──────────────────────────────────────────────

    #[test]
    fn b0_text_integer_42() {
        run_6b0_test(b"42", 42, true);
        eprintln!("6B.0: \"42\" → guest lexer → code → seal → exec → 42 ✓");
        eprintln!("      text bytes → meaning → executable → result");
    }

    #[test]
    fn b0_text_integer_0() {
        run_6b0_test(b"0", 0, true);
        eprintln!("6B.0: \"0\" → 0 ✓");
    }

    #[test]
    fn b0_text_integer_255() {
        run_6b0_test(b"255", 255, true);
        eprintln!("6B.0: \"255\" → 255 ✓");
    }

    #[test]
    fn b0_text_integer_leading_zeros() {
        run_6b0_test(b"0042", 42, true);
        eprintln!("6B.0: \"0042\" → 42 (leading zeros accepted) ✓");
    }

    // ─── Error: no digits ───────────────────────────────────────

    #[test]
    fn b0_text_empty_source() {
        run_6b0_test(b"", u64::MAX, false);
        eprintln!("6B.0a: empty source → error (no digits, length=0) ✓");
    }

    #[test]
    fn b0_text_non_digit() {
        run_6b0_test(b"42x", 42, true);
        eprintln!("6B.0: \"42x\" → 42 (stops at non-digit) ✓");
    }

    #[test]
    fn b0_text_only_non_digit() {
        run_6b0_test(b"x", u64::MAX, false);
        eprintln!("6B.0: \"x\" → error (no digits) ✓");
    }

    // ─── Overflow boundary ──────────────────────────────────────

    #[test]
    fn b0a_movi_max() {
        // 131071 = 0x1FFFF = maximum positive 18-bit signed value
        run_6b0_test(b"131071", 131071, true);
        eprintln!("6B.0a: \"131071\" → 131071 (MOVI 18-bit max) ✓");
    }

    #[test]
    fn b0a_movi_overflow() {
        // 131072 = 0x20000 → bit 17 set → signed MOVI would be -131072
        // Compiler must reject, not silently truncate
        run_6b0_test(b"131072", u64::MAX, false);
        eprintln!("6B.0a: \"131072\" → error (overflow, not truncation) ✓");
    }

    #[test]
    fn b0a_large_decimal_overflow() {
        // Many digits → overflow during accumulation
        run_6b0_test(b"999999999999999999999", u64::MAX, false);
        eprintln!("6B.0a: \"999...\" → error (decimal overflow) ✓");
    }

    #[test]
    fn b0a_just_above_boundary() {
        // 131073: clearly above MOVI max
        run_6b0_test(b"131073", u64::MAX, false);
        eprintln!("6B.0a: \"131073\" → error (overflow) ✓");
    }

    // ─── Source length-bounded scanning ─────────────────────────

    #[test]
    fn b0a_length_bounded_no_terminator() {
        // Source is exactly "42" with length=2, no NUL terminator.
        // Scanner must stop at pos=2 because of length bound,
        // not because of a NUL byte.
        run_6b0_test(b"42", 42, true);
        eprintln!("6B.0a: \"42\" (no NUL) → 42 (length-bounded scan) ✓");
    }

    #[test]
    fn b0a_length_bounded_trailing_digits() {
        // Declared length = 2, but stored payload = "429999999".
        // The lexer must stop after 2 bytes ("42") because of the
        // length bound, ignoring the trailing "9999999".
        // Without the length guard, this would parse 429999999.
        run_6b0_test_raw(2, b"429999999", 42, true);
        eprintln!("6B.0a: declared_len=2, payload=\"429999999\" → 42 ✓");
        eprintln!("       length bound prevents reading beyond source role");
    }

    // ─── Source metadata guard ──────────────────────────────────

    #[test]
    fn b0a_hostile_metadata_overlength() {
        // Declared length = 0x1000 (4096), but source object capacity
        // after 8-byte header = 0xFF8 (4088).  The guest must reject
        // the malformed metadata before any out-of-role read.
        //
        // Memory authority ≠ source-role authority.
        run_6b0_test_raw(0x1000, b"42", u64::MAX, false);
        eprintln!("6B.0a: declared_len=0x1000, capacity=0xFF8 → error ✓");
        eprintln!("       hostile metadata rejected before out-of-role read");
    }

    #[test]
    fn b0a_metadata_exact_capacity() {
        // Declared length = 0xFF8 (4088) = exact max capacity.
        // Should be accepted (no overflow), even though the actual
        // text is just "7".  The guard checks metadata, not content.
        run_6b0_test_raw(0xFF8, b"7", 7, true);
        eprintln!("6B.0a: declared_len=0xFF8 (exact capacity) → 7 ✓");
    }
}

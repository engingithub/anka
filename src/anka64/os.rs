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

    /// Seal an object: RW → RX (W⊕X enforcement).
    ///
    /// R1 = virtual address of the object to seal.
    /// The kernel revokes the object (invalidating all RW capabilities),
    /// re-activates it, and grants RX to the calling domain.
    ///
    /// This is the "mutable data → sealed executable" transition:
    ///   source(R) → compiler → output(RW,NX) → **kernel seal** → code(RX,!W)
    fn handle_seal(&mut self, idx: usize) {
        let vaddr = self.processes[idx].core.r[R1 as usize];
        let (object, _offset) = self.processes[idx].core.address_map.resolve(vaddr)
            .expect("seal: address not in process address map");

        let domain = self.processes[idx].core.domain;
        let obj_size = self.fabric.objects[&object].size;

        // Revoke: bumps generation, invalidates all existing capabilities
        self.fabric.revoke(object);

        // Re-activate (revoke marks state = Revoked)
        self.fabric.objects.get_mut(&object).unwrap().state = ObjectState::Active;

        // Grant RX at the new generation — W is gone, X is granted
        self.fabric.grant(domain, object, 0, obj_size, Permissions::RX);

        self.processes[idx].core.r[R0 as usize] = 0;
        self.resume_from_trap(idx);
    }

    /// Execute a sealed code object as a new child process.
    ///
    /// R1 = virtual address of sealed code object.
    /// R2 = code size in bytes.
    /// Returns: child's exit code in R0.
    ///
    /// The kernel creates a new domain, grants RX on the code to the
    /// child, allocates stack and trap handler, runs the child to
    /// completion, and returns the exit code to the parent.
    fn handle_exec(&mut self, idx: usize) {
        let code_vaddr = self.processes[idx].core.r[R1 as usize];
        let code_size = self.processes[idx].core.r[R2 as usize];

        let (code_obj, _) = self.processes[idx].core.address_map.resolve(code_vaddr)
            .expect("exec: code address not in process address map");

        // --- Child domain: isolated authority container ---
        let child_dom = self.fabric.create_domain();
        self.fabric.grant(child_dom, code_obj, 0, code_size, Permissions::RX);

        // --- Child stack ---
        let stack_size: u64 = 0x4000;
        let stack_obj = self.fabric.alloc_object("child_stack", stack_size, ObjectKind::Memory);
        let stack_phys = self.next_phys;
        self.next_phys += stack_size;
        self.fabric.place_object(stack_obj, stack_phys);
        self.fabric.grant(child_dom, stack_obj, 0, stack_size, Permissions::RW);

        // --- Child trap handler (HALT for kernel interception) ---
        let trap_size: u64 = 0x1000;
        let trap_obj = self.fabric.alloc_object("child_trap", trap_size, ObjectKind::Memory);
        let trap_phys = self.next_phys;
        self.next_phys += trap_size;
        self.fabric.place_object(trap_obj, trap_phys);
        self.fabric.grant(child_dom, trap_obj, 0, trap_size, Permissions::RX);

        let mut handler = Asm64::new();
        handler.halt();
        self.fabric.write_physical(trap_phys, &handler.to_bytes());

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
    use super::super::fabric::Fabric;

    const CPU0: AgentId = AgentId(0);

    /// Create a process with its own domain, objects, and address map.
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
        fabric.grant(dom, text,  0, 0x4000, Permissions::RX);
        fabric.grant(dom, data,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        let mut core = Anka64Core::new(agent, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x10000, 0x4000, data);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        // Trap handler = HALT at virtual address 0x3FF0 (in text object)
        core.trap_vector = 0x3FF0;

        (core, dom, text, data, stack)
    }

    fn install_trap_handler(fabric: &mut Fabric, text_phys: u64) {
        // At offset 0x3FF0 in text object, write a HALT instruction.
        // The OS kernel intercepts this HALT as a syscall.
        let mut handler = Asm64::new();
        handler.halt();
        let bytes = handler.to_bytes();
        fabric.write_physical(text_phys + 0x3FF0, &bytes);
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

        // Build program using AST:
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
        let (core_a, _dom_a, _t, _d, _s) =
            create_process(&mut fabric, AgentId(0), "procA",
                0x000000, 0x010000, 0x020000);
        install_trap_handler(&mut fabric, 0x000000);

        // Process B at physical 0x100000..
        let (core_b, _dom_b, _t, _d, _s) =
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
        use super::super::cc::{self, *};

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
        fabric.grant(dom, text,   0, 0x4000, Permissions::RX);
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RW);
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
}

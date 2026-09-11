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
}

impl Kernel {
    pub fn new(fabric: Fabric) -> Self {
        Self {
            fabric,
            processes: Vec::new(),
            output: Vec::new(),
            mailboxes: Vec::new(),
            current: 0,
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
            _ => {
                eprintln!("Unknown syscall {} from pid {}", syscall, proc.pid);
                proc.exited = true;
                proc.exit_code = 0xBAD;
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
    use super::super::cc;
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
}

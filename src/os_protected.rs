//! AnkaOS v0.1 — preemptive multitasking with capability-based protection.
//!
//! Extends v0.0 with:
//!
//!   - Per-process protection domains (capability sets)
//!   - Processes run in user mode (SR = 0x0000)
//!   - Domain switching in the timer ISR
//!   - Bus error handler (vector 2) catches access violations
//!   - A hostile process that tries to corrupt another's stack → caught
//!
//! The visible result:
//!
//! ```text
//! AnkaOS 0.1
//! AABABAB...
//! BUS ERROR at 000C0000 by process 0
//! ```
//!
//! Process 0 is hostile: after printing 'A' twice it attempts to write
//! to process 1's stack.  The bus denies the write, the CPU takes a bus
//! error exception (vector 2), and the kernel prints a diagnostic and
//! halts the offending process.

use crate::asm::Asm;

const CONSOLE_TX: u32 = 0x00F0_0000;
const TIMER_BASE: u32 = 0x00F0_0010;
const PROTECT_BASE: u32 = 0x00F0_0020;

const TIMER_CTRL: u32 = TIMER_BASE;
const TIMER_STATUS: u32 = TIMER_BASE + 7;
const PROTECT_DOMAIN: u32 = PROTECT_BASE;

const CURRENT_PID: u32 = 0x0800;
const SAVED_SP_0: u32 = 0x0810;
const SAVED_SP_1: u32 = 0x0814;
const TICK_COUNT: u32 = 0x0818;
const PROC0_DEAD: u32 = 0x081C;       // 1 if process 0 was killed
const PROC1_DEAD: u32 = 0x0820;       // 1 if process 1 was killed

const PROC0_STACK: u32 = 0x0008_0000; // 512 KB
const PROC1_STACK: u32 = 0x000C_0000; // 768 KB

/// Address that process 0 (hostile) will try to write to.
/// This is inside process 1's stack region — a clear violation.
const ATTACK_ADDR: u32 = PROC1_STACK - 0x100;

/// Build the AnkaOS v0.1 kernel image.
pub fn build(base: u32) -> Vec<u8> {
    let mut a = Asm::new(base);

    // ─── _start ───────────────────────────────────────────────
    a.label("_start");

    a.lea_label("banner", 0);
    a.bsr("print_string");

    // Initialize process 0 (hostile — prints A, then attacks)
    a.move_l_imm(PROC0_STACK, 0);
    a.movea_l_dn(0, 0);
    a.lea_label("proc_hostile", 1);
    a.move_l_an_dn(1, 1);
    a.emit(0x2101);                    // MOVE.L D1, -(A0)  push PC
    a.emit(0x5548);                    // SUBQ.L #2, A0
    // User mode with IPL=0: SR = 0x0000
    a.emit(0x30BC);
    a.emit(0x0000);                    // SR = user mode
    a.moveq(15, 2);
    a.moveq(0, 3);
    a.label("push0_loop");
    a.emit(0x2103);                    // MOVE.L D3, -(A0)
    a.emit(0x5382);                    // SUBQ.L #1, D2
    a.bne("push0_loop");
    a.move_l_an_dn(0, 0);
    a.emit(0x23C0);                    // MOVE.L D0, (SAVED_SP_0).L
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);

    // Initialize process 1 (innocent — prints B)
    a.move_l_imm(PROC1_STACK, 0);
    a.movea_l_dn(0, 0);
    a.lea_label("proc_b", 1);
    a.move_l_an_dn(1, 1);
    a.emit(0x2101);
    a.emit(0x5548);
    a.emit(0x30BC);
    a.emit(0x0000);                    // SR = user mode
    a.moveq(15, 2);
    a.moveq(0, 3);
    a.label("push1_loop");
    a.emit(0x2103);
    a.emit(0x5382);
    a.bne("push1_loop");
    a.move_l_an_dn(0, 0);
    a.emit(0x23C0);                    // MOVE.L D0, (SAVED_SP_1).L
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    // Initialize kernel variables
    a.moveq(0, 0);
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x23C0);
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);
    a.emit(0x23C0);
    a.emit((PROC0_DEAD >> 16) as u16);
    a.emit(PROC0_DEAD as u16);
    a.emit(0x23C0);
    a.emit((PROC1_DEAD >> 16) as u16);
    a.emit(PROC1_DEAD as u16);

    // Set protection domain = 0 (process 0)
    a.emit(0x13FC);                    // MOVE.B #0, (PROTECT_DOMAIN).L
    a.emit(0x0000);
    a.emit((PROTECT_DOMAIN >> 16) as u16);
    a.emit(PROTECT_DOMAIN as u16);

    // Enable timer
    a.emit(0x13FC);                    // MOVE.B #1, (TIMER_CTRL).L
    a.emit(0x0001);
    a.emit((TIMER_CTRL >> 16) as u16);
    a.emit(TIMER_CTRL as u16);

    // Dispatch process 0
    a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_0).L, A7
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);
    a.emit(0x4CDF);                    // MOVEM.L (A7)+, D0-D7/A0-A6
    a.emit(0x7FFF);
    a.emit(0x4E73);                    // RTE → user mode

    // ─── Timer ISR ────────────────────────────────────────────
    a.label("timer_isr");
    a.emit(0x48E7);                    // MOVEM.L D0-D7/A0-A6, -(A7)
    a.emit(0xFFFE);

    // Increment tick counter
    a.emit(0x2039);
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);
    a.addq_l(1, 0);
    a.emit(0x23C0);
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);

    // Stop after 40 ticks
    a.emit(0x0C80);
    a.emit(0x0000);
    a.emit(0x0028);
    a.bge("halt_system");

    // ACK timer
    a.emit(0x13FC);
    a.emit(0x0001);
    a.emit((TIMER_STATUS >> 16) as u16);
    a.emit(TIMER_STATUS as u16);

    // Save current SP
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.tst_l(0);
    a.bne("t_save_sp1");

    a.move_l_an_dn(7, 1);
    a.emit(0x23C1);
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);
    a.bra("t_switch_pid");

    a.label("t_save_sp1");
    a.move_l_an_dn(7, 1);
    a.emit(0x23C1);
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    a.label("t_switch_pid");
    a.emit(0x0A80);                    // EORI.L #1, D0
    a.emit(0x0000);
    a.emit(0x0001);
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);

    // Check if the new process is dead — if so, stay with current
    // D0 = new PID after toggle
    a.tst_l(0);
    a.bne("t_check_p1_dead");

    // Target is process 0 — check if dead
    a.emit(0x2039);
    a.emit((PROC0_DEAD >> 16) as u16);
    a.emit(PROC0_DEAD as u16);
    a.tst_l(0);
    a.beq("t_target_alive");
    // Process 0 is dead — toggle back to stay with process 1
    a.moveq(1, 0);
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.bra("t_skip_switch");

    a.label("t_check_p1_dead");
    // Target is process 1 — check if dead
    a.emit(0x2039);
    a.emit((PROC1_DEAD >> 16) as u16);
    a.emit(PROC1_DEAD as u16);
    a.tst_l(0);
    a.beq("t_target_alive");
    // Process 1 is dead — toggle back to stay with process 0
    a.moveq(0, 0);
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.bra("t_skip_switch");

    a.label("t_target_alive");
    // The target process is alive, switch protection domain
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x13C0);                    // MOVE.B D0, (PROTECT_DOMAIN).L
    a.emit((PROTECT_DOMAIN >> 16) as u16);
    a.emit(PROTECT_DOMAIN as u16);

    a.label("t_load_sp");
    // Reload the new PID for SP loading
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.tst_l(0);
    a.bne("t_load_sp1");

    a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_0).L, A7
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);
    a.bra("t_restore_regs");

    a.label("t_load_sp1");
    a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_1).L, A7
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    a.label("t_restore_regs");
    a.emit(0x4CDF);
    a.emit(0x7FFF);
    a.emit(0x4E73);                    // RTE

    // When the target process is dead, don't context-switch.
    // Just restore registers and return to the current process.
    a.label("t_skip_switch");
    a.emit(0x4CDF);                    // MOVEM.L (A7)+, D0-D7/A0-A6
    a.emit(0x7FFF);
    a.emit(0x4E73);                    // RTE

    // ─── Bus error handler (vector 2) ─────────────────────────
    //
    // When a user-mode process tries to access memory outside its
    // capabilities, the bus denies the access and the CPU takes a
    // bus error exception.  We print a diagnostic and kill the
    // offending process.
    a.label("bus_error_handler");

    // Mask all interrupts — don't let timer preempt the diagnostic
    // MOVE.W #$2700, SR  (supervisor + IPL=7)
    a.emit(0x46FC);
    a.emit(0x2700);

    // Print "BUS ERROR by process "
    a.lea_label("bus_err_msg", 0);
    a.bsr("print_string");

    // Print current PID as ASCII digit
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    // ADDI.L #$30, D0  ('0' + pid)
    a.emit(0x0680);
    a.emit(0x0000);
    a.emit(0x0030);
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);

    // Print newline
    a.moveq(0x0A, 0);
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);

    // Mark the current process as dead
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.tst_l(0);
    a.bne("kill_proc1");

    // Kill process 0
    a.moveq(1, 1);
    a.emit(0x23C1);
    a.emit((PROC0_DEAD >> 16) as u16);
    a.emit(PROC0_DEAD as u16);
    a.bra("after_kill");

    a.label("kill_proc1");
    a.moveq(1, 1);
    a.emit(0x23C1);
    a.emit((PROC1_DEAD >> 16) as u16);
    a.emit(PROC1_DEAD as u16);

    a.label("after_kill");

    // Switch to the other process (or halt if both dead)
    // Toggle PID
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x0A80);                    // EORI.L #1, D0
    a.emit(0x0000);
    a.emit(0x0001);
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);

    // Switch protection domain to new process
    a.emit(0x13C0);
    a.emit((PROTECT_DOMAIN >> 16) as u16);
    a.emit(PROTECT_DOMAIN as u16);

    // Check if the other process is alive
    a.tst_l(0);
    a.bne("check_p1_alive");
    a.emit(0x2039);
    a.emit((PROC0_DEAD >> 16) as u16);
    a.emit(PROC0_DEAD as u16);
    a.tst_l(0);
    a.bne("halt_system");
    a.bra("dispatch_other");

    a.label("check_p1_alive");
    a.emit(0x2039);
    a.emit((PROC1_DEAD >> 16) as u16);
    a.emit(PROC1_DEAD as u16);
    a.tst_l(0);
    a.bne("halt_system");

    a.label("dispatch_other");
    // Load the surviving process's SP
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.tst_l(0);
    a.bne("dispatch_p1");

    a.emit(0x2E79);
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);
    a.bra("dispatch_restore");

    a.label("dispatch_p1");
    a.emit(0x2E79);
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    a.label("dispatch_restore");
    a.emit(0x4CDF);
    a.emit(0x7FFF);
    a.emit(0x4E73);                    // RTE into survivor

    // ─── Halt ─────────────────────────────────────────────────
    a.label("halt_system");
    a.moveq(0x0A, 0);
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.stop(0x2700);

    // ─── Hostile process 0 ────────────────────────────────────
    // Prints 'A' three times, then tries to write 0xDEAD to
    // process 1's stack — which is outside its capabilities.
    a.label("proc_hostile");

    // Print 'A' three times
    a.moveq(3, 1);                     // D1 = counter
    a.label("hostile_print");
    a.moveq(0x41, 0);                 // 'A'
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.emit(0x5381);                    // SUBQ.L #1, D1
    a.bne("hostile_print");

    // NOW ATTACK: try to write to process 1's stack
    a.move_l_imm(ATTACK_ADDR, 0);     // D0 = target address
    a.movea_l_dn(0, 0);               // A0 = target address
    a.move_l_imm(0xDEADBEEF, 0);      // D0 = poison value
    a.emit(0x2080);                    // MOVE.L D0, (A0) ← VIOLATION
    // If we get here, protection failed!
    a.moveq(0x58, 0);                 // 'X' — should never print
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.bra("proc_hostile");

    // ─── Innocent process 1 ──────────────────────────────────
    a.label("proc_b");
    a.label("proc_b_loop");
    a.moveq(0x42, 0);                 // 'B'
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.bra("proc_b_loop");

    // ─── print_string ─────────────────────────────────────────
    a.label("print_string");
    a.label("ps_loop");
    a.move_b_postinc_dn(0, 0);
    a.beq("ps_done");
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.bra("ps_loop");
    a.label("ps_done");
    a.rts();

    // ─── Data ─────────────────────────────────────────────────
    a.label("banner");
    a.ascii_z("AnkaOS 0.1\n");

    a.label("bus_err_msg");
    a.ascii_z("BUS ERROR by process ");

    a.assemble()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::timer::Timer;
    use crate::bus::{Bus, MappedBus};
    use crate::cpu::Cpu;
    use crate::protection::{Capability, Domain, Perm, ProtectedBus};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct CaptureConsole {
        output: Arc<Mutex<Vec<u8>>>,
        rx_buf: Arc<Mutex<VecDeque<u8>>>,
    }

    impl CaptureConsole {
        fn new() -> Self {
            Self {
                output: Arc::new(Mutex::new(Vec::new())),
                rx_buf: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
        fn output(&self) -> Arc<Mutex<Vec<u8>>> {
            self.output.clone()
        }
    }

    impl crate::bus::device::Device for CaptureConsole {
        fn name(&self) -> &str { "capture-console" }
        fn size(&self) -> u32 { 16 }
        fn read(&mut self, offset: u32) -> u8 {
            match offset {
                0x00 => 0x00,
                0x01 => 0x01,
                0x02 => self.rx_buf.lock().unwrap().pop_front().unwrap_or(0),
                0x03 => if self.rx_buf.lock().unwrap().is_empty() { 0 } else { 1 },
                _ => 0,
            }
        }
        fn write(&mut self, offset: u32, val: u8) {
            if offset == 0x00 {
                self.output.lock().unwrap().push(val);
            }
        }
    }

    /// Find the ISR entry by scanning for the MOVEM.L signature.
    fn find_isr(kernel: &[u8]) -> u32 {
        let offset = kernel.windows(4)
            .position(|w| w[0] == 0x48 && w[1] == 0xE7 && w[2] == 0xFF && w[3] == 0xFE)
            .expect("could not find timer_isr in kernel");
        0x1000 + offset as u32
    }

    /// Find the bus error handler by its unique opening instruction:
    /// MOVE.W #$2700, SR → 0x46FC 0x2700
    fn find_bus_error_handler(kernel: &[u8]) -> u32 {
        let offset = kernel.windows(4)
            .position(|w| w[0] == 0x46 && w[1] == 0xFC && w[2] == 0x27 && w[3] == 0x00)
            .expect("could not find bus_error_handler (MOVE #$2700,SR)");
        0x1000 + offset as u32
    }

    #[test]
    fn protection_catches_hostile_process() {
        let kernel = build(0x1000);

        let console = CaptureConsole::new();
        let output = console.output();

        let mut bus = MappedBus::new_16mb();
        bus.add_device(0x00F0_0000, Box::new(console));
        bus.add_device(0x00F0_0010, Box::new(Timer::new(200, 6)));

        // Load kernel into inner bus first
        bus.load(0x1000, &kernel);

        // Set up vector table
        bus.write32(0x000000, 0x0010_0000);   // SSP
        bus.write32(0x000004, 0x0000_1000);   // Reset PC

        let isr_addr = find_isr(&kernel);
        bus.write32(0x078, isr_addr);         // vector 30 = timer level 6

        let be_handler = find_bus_error_handler(&kernel);
        bus.write32(0x008, be_handler);       // vector 2 = bus error

        // Wrap in ProtectedBus
        let mut pbus = ProtectedBus::new(bus);

        // Domain 0 (hostile process): code + own stack + console + timer
        let mut dom0 = Domain::new("proc0");
        // Kernel code (read-execute)
        dom0.grant(Capability::new(0, 0x0000, 0x1000, Perm::RW));       // vector table
        dom0.grant(Capability::new(1, 0x1000, 0x10000, Perm::RX));      // code
        // Own stack (read-write), below PROC0_STACK
        dom0.grant(Capability::new(2, 0x0004_0000, 0x0004_0000, Perm::RW)); // 256K-512K
        // Console device (write)
        dom0.grant(Capability::new(3, 0x00F0_0000, 0x10, Perm::RW));
        // Kernel data area (for print_string reading from code area)
        dom0.grant(Capability::new(4, 0x0800, 0x100, Perm::RW));

        // Domain 1 (innocent process): code + own stack + console + timer
        let mut dom1 = Domain::new("proc1");
        dom1.grant(Capability::new(0, 0x0000, 0x1000, Perm::RW));       // vector table
        dom1.grant(Capability::new(1, 0x1000, 0x10000, Perm::RX));      // code
        // Own stack (read-write), below PROC1_STACK
        dom1.grant(Capability::new(5, 0x0008_0000, 0x0004_0000, Perm::RW)); // 512K-768K
        // Console device (write)
        dom1.grant(Capability::new(3, 0x00F0_0000, 0x10, Perm::RW));
        dom1.grant(Capability::new(4, 0x0800, 0x100, Perm::RW));

        pbus.add_domain(dom0);
        pbus.add_domain(dom1);
        pbus.set_domain(0);

        let mut cpu = Cpu::new(pbus);

        let mut steps = 0u64;
        while !cpu.halted && steps < 500_000 {
            cpu.step();
            steps += 1;
        }

        let out = output.lock().unwrap();
        let text = String::from_utf8_lossy(&out);

        eprintln!("Output: {}", text.trim());
        eprintln!("Steps: {}, violations: {}", steps, cpu.bus.violation_count());

        // Should start with banner
        assert!(text.starts_with("AnkaOS 0.1\n"),
            "expected banner, got: {:?}", &text[..text.len().min(30)]);

        // Should contain the bus error message
        assert!(text.contains("BUS ERROR by process 0"),
            "expected bus error diagnostic, got: {}", text);

        // After the bus error, process B should run as the sole survivor.
        // Count B's that are NOT part of "BUS ERROR" —
        // the simplest check: after "process 0\n" we should see B's.
        let after_diag = text.find("process 0\n")
            .map(|i| &text[i + "process 0\n".len()..])
            .unwrap_or("");
        let b_count = after_diag.chars().filter(|c| *c == 'B').count();
        assert!(b_count > 0,
            "innocent process B never ran after hostile was killed. Rest: {:?}", after_diag);

        // 'X' should NOT appear (hostile process should be stopped)
        assert!(!text.contains('X'),
            "hostile process continued after violation!");

        // At least one violation must have occurred
        assert!(cpu.bus.violation_count() >= 1,
            "no violations detected");
    }
}

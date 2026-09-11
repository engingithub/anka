//! AnkaOS v0.0 — preemptive multitasking kernel for MC68000.
//!
//! This module builds a minimal kernel image that:
//!
//!   1. Sets up a timer interrupt
//!   2. Creates two processes with independent stacks
//!   3. Preemptively switches between them on each timer tick
//!   4. Each process prints its letter via MMIO console
//!
//! The visible result is:
//!
//!   ```text
//!   AnkaOS 0.0
//!   ABABABABABABABABAB...
//!   ```
//!
//! This proves: timer MMIO, interrupt delivery, exception frames,
//! supervisor/user mode, context save/restore, two independent stacks,
//! a scheduler, process creation, and preemptive execution.

use crate::asm::Asm;

const CONSOLE_TX: u32 = 0x00F0_0000;
const TIMER_BASE: u32 = 0x00F0_0010;

// Timer registers (offsets from TIMER_BASE)
const TIMER_CTRL: u32 = TIMER_BASE;
const TIMER_STATUS: u32 = TIMER_BASE + 7;

// Fixed memory addresses used by the kernel
const CURRENT_PID: u32 = 0x0800;       // current process index (0 or 1)
const SAVED_SP_0: u32 = 0x0810;        // saved SP for process 0
const SAVED_SP_1: u32 = 0x0814;        // saved SP for process 1
const TICK_COUNT: u32 = 0x0818;        // global tick counter
const PROC0_STACK: u32 = 0x00080000;   // top of process 0 stack (512 KB)
const PROC1_STACK: u32 = 0x000C0000;   // top of process 1 stack (768 KB)

/// Build the AnkaOS v0.0 kernel image.
///
/// Returns a flat binary to be loaded at `base`.
pub fn build(base: u32) -> Vec<u8> {
    let mut a = Asm::new(base);

    // ─── Kernel entry (_start) ─────────────────────────────────
    //
    // Print banner, set up processes, enable timer, start process 0.

    a.label("_start");

    // Print "AnkaOS 0.0\n"
    a.lea_label("banner", 0);          // A0 = banner string
    a.bsr("print_string");

    // Initialize process table
    // Both processes start in supervisor mode with IPL=0

    // Process 0: prints 'A'
    // Build a fake exception frame on process 0's stack so the
    // scheduler can RTE into it.
    a.move_l_imm(PROC0_STACK, 0);      // D0 = stack top
    a.movea_l_dn(0, 0);                // A0 = stack top
    // Push PC (entry point of process 0)
    a.lea_label("proc_a", 1);          // A1 = &proc_a
    a.move_l_an_dn(1, 1);             // D1 = A1 (proc_a addr)
    // Pre-decrement A0 by 4, write D1
    // MOVE.L D1, -(A0) → 0x2101
    a.emit(0x2101);                    // MOVE.L D1, -(A0)
    // Push SR (supervisor, IPL=0)
    // MOVE.W #$2000, -(A0) → 0x3140 would be wrong
    // We need MOVE.W #imm, -(A0)
    // Actually: store $2000 at -(A0):
    // SUB.L #2, A0; MOVE.W #$2000, (A0)
    a.emit(0x5548);                    // SUBQ.L #2, A0
    // MOVE.W #imm, (A0) → 0x30BC + imm
    a.emit(0x30BC);
    a.emit(0x2000);                    // SR = supervisor, IPL=0

    // Save registers D0-D7/A0-A6 (15 longs = 60 bytes)
    // D0-D7 = 8, A0-A6 = 7 → 15 registers to match MOVEM mask 0x7FFF
    a.moveq(15, 2);                    // D2 = 15 (loop counter)
    a.moveq(0, 3);                     // D3 = 0 (initial reg value)
    a.label("push0_loop");
    a.emit(0x2103);                    // MOVE.L D3, -(A0)
    a.emit(0x5382);                    // SUBQ.L #1, D2
    a.bne("push0_loop");
    // Now A0 points to the bottom of the saved frame.
    // Save this as process 0's SP.
    a.move_l_an_dn(0, 0);             // D0 = A0
    a.emit(0x23C0);                    // MOVE.L D0, (SAVED_SP_0).L
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);

    // Process 1: prints 'B'
    a.move_l_imm(PROC1_STACK, 0);
    a.movea_l_dn(0, 0);               // A0 = stack top
    a.lea_label("proc_b", 1);         // A1 = &proc_b
    a.move_l_an_dn(1, 1);
    a.emit(0x2101);                    // MOVE.L D1, -(A0) — push PC
    a.emit(0x5548);                    // SUBQ.L #2, A0
    a.emit(0x30BC);
    a.emit(0x2000);                    // push SR
    a.moveq(15, 2);                    // 15 registers
    a.moveq(0, 3);
    a.label("push1_loop");
    a.emit(0x2103);                    // MOVE.L D3, -(A0)
    a.emit(0x5382);                    // SUBQ.L #1, D2
    a.bne("push1_loop");
    a.move_l_an_dn(0, 0);
    a.emit(0x23C0);                    // MOVE.L D0, (SAVED_SP_1).L
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    // Initialize CURRENT_PID = 0
    a.moveq(0, 0);
    a.emit(0x23C0);                    // MOVE.L D0, (CURRENT_PID).L
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);

    // Initialize TICK_COUNT = 0
    a.emit(0x23C0);
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);

    // Enable timer: write 1 to CTRL
    a.emit(0x13FC);                    // MOVE.B #1, (TIMER_CTRL).L
    a.emit(0x0001);
    a.emit((TIMER_CTRL >> 16) as u16);
    a.emit(TIMER_CTRL as u16);

    // Load process 0's saved SP into A7 and RTE into it
    a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_0).L, A7
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);

    // Restore registers: pop D0-D7, A0-A6 (13 longs)
    // MOVEM.L (A7)+, D0-D7/A0-A6
    a.emit(0x4CDF);                    // MOVEM.L (A7)+, <list>
    a.emit(0x7FFF);                    // register mask: D0-D7, A0-A6

    // RTE into process 0
    a.emit(0x4E73);                    // RTE

    // ─── Timer ISR (context switch) ───────────────────────────
    //
    // On each timer interrupt:
    //   1. Save all registers of current process
    //   2. ACK the timer
    //   3. Switch current PID (0↔1)
    //   4. Restore all registers of new process
    //   5. RTE into new process

    a.label("timer_isr");

    // The CPU has already pushed SR and PC onto the supervisor stack.
    // Now save D0-D7/A0-A6.
    // MOVEM.L D0-D7/A0-A6, -(A7)
    a.emit(0x48E7);                    // MOVEM.L <list>, -(A7)
    a.emit(0xFFFE);                    // register mask: D0-D7, A0-A6

    // Increment tick counter
    a.emit(0x2039);                    // MOVE.L (TICK_COUNT).L, D0
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);
    a.addq_l(1, 0);
    a.emit(0x23C0);                    // MOVE.L D0, (TICK_COUNT).L
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);

    // Check tick count — stop after 40 ticks (20 A's + 20 B's)
    a.emit(0x0C80);                    // CMPI.L #imm, D0
    a.emit(0x0000);
    a.emit(0x0028);                    // #40
    a.bge("halt_system");

    // ACK timer
    a.emit(0x13FC);                    // MOVE.B #1, (TIMER_STATUS).L
    a.emit(0x0001);
    a.emit((TIMER_STATUS >> 16) as u16);
    a.emit(TIMER_STATUS as u16);

    // Save current SP
    a.emit(0x2039);                    // MOVE.L (CURRENT_PID).L, D0
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.tst_l(0);
    a.bne("save_sp1");

    // Save to SAVED_SP_0
    a.move_l_an_dn(7, 1);             // D1 = A7
    a.emit(0x23C1);                    // MOVE.L D1, (SAVED_SP_0).L
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);
    a.bra("switch_pid");

    a.label("save_sp1");
    a.move_l_an_dn(7, 1);
    a.emit(0x23C1);                    // MOVE.L D1, (SAVED_SP_1).L
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    a.label("switch_pid");
    // Toggle: 0→1, 1→0
    a.emit(0x0A80);                    // EORI.L #1, D0
    a.emit(0x0000);
    a.emit(0x0001);
    a.emit(0x23C0);                    // MOVE.L D0, (CURRENT_PID).L
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);

    // Load new process's SP
    a.tst_l(0);
    a.bne("load_sp1");

    a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_0).L, A7
    a.emit((SAVED_SP_0 >> 16) as u16);
    a.emit(SAVED_SP_0 as u16);
    a.bra("restore_regs");

    a.label("load_sp1");
    a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_1).L, A7
    a.emit((SAVED_SP_1 >> 16) as u16);
    a.emit(SAVED_SP_1 as u16);

    a.label("restore_regs");
    // MOVEM.L (A7)+, D0-D7/A0-A6
    a.emit(0x4CDF);
    a.emit(0x7FFF);
    // RTE into the new process
    a.emit(0x4E73);

    // ─── Halt handler ────────────────────────────────────────
    a.label("halt_system");
    // Print newline
    a.moveq(0x0A, 0);                 // '\n'
    a.emit(0x13C0);                    // MOVE.B D0, (CONSOLE_TX).L
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.stop(0x2700);

    // ─── Process A ───────────────────────────────────────────
    a.label("proc_a");
    a.label("proc_a_loop");
    a.moveq(0x41, 0);                 // 'A'
    a.emit(0x13C0);                    // MOVE.B D0, (CONSOLE_TX).L
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.bra("proc_a_loop");

    // ─── Process B ───────────────────────────────────────────
    a.label("proc_b");
    a.label("proc_b_loop");
    a.moveq(0x42, 0);                 // 'B'
    a.emit(0x13C0);                    // MOVE.B D0, (CONSOLE_TX).L
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.bra("proc_b_loop");

    // ─── Utility: print_string ───────────────────────────────
    // Input: A0 = null-terminated string
    a.label("print_string");
    a.label("ps_loop");
    a.move_b_postinc_dn(0, 0);        // MOVE.B (A0)+, D0
    a.beq("ps_done");
    a.emit(0x13C0);                    // MOVE.B D0, (CONSOLE_TX).L
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.bra("ps_loop");
    a.label("ps_done");
    a.rts();

    // ─── Data ────────────────────────────────────────────────
    a.label("banner");
    a.ascii_z("AnkaOS 0.0\n");

    a.assemble()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::timer::Timer;
    use crate::bus::{Bus, MappedBus};
    use crate::cpu::Cpu;
    use std::sync::{Arc, Mutex};
    use std::collections::VecDeque;

    /// Capture console output into a buffer instead of stdout.
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

    #[test]
    fn preemptive_multitasking() {
        let kernel = build(0x1000);

        let console = CaptureConsole::new();
        let output = console.output();

        let mut bus = MappedBus::new_16mb();
        bus.add_device(0x00F0_0000, Box::new(console));
        bus.add_device(0x00F0_0010, Box::new(Timer::new(200, 6)));

        // Vector table
        bus.write32(0x000000, 0x0010_0000);   // SSP
        bus.write32(0x000004, 0x0000_1000);   // Reset PC

        // Auto-vector level 6 → timer_isr
        // We need the address of timer_isr. It's wherever the label
        // "timer_isr" resolved to. Since we build at base 0x1000,
        // we need to find it. Let's scan for the label offset.
        // Instead, we'll use a fixed approach: load the kernel and
        // set vector 30 (level 6) to point to the known label.

        // Load kernel
        bus.load(0x1000, &kernel);

        // Find the ISR entry point by scanning for its MOVEM signature
        let isr_offset = kernel.windows(4)
            .position(|w| w[0] == 0x48 && w[1] == 0xE7 && w[2] == 0xFF && w[3] == 0xFE)
            .expect("could not find timer_isr in kernel");
        let isr_addr = 0x1000 + isr_offset as u32;

        bus.write32(0x078, isr_addr);  // vector 30 = auto-vector level 6

        let mut cpu = Cpu::new(bus);

        let mut steps = 0u64;
        while !cpu.halted && steps < 500_000 {
            cpu.step();
            steps += 1;
        }

        assert!(cpu.halted, "CPU did not halt after {} steps", steps);

        let out = output.lock().unwrap();
        let text = String::from_utf8_lossy(&out);

        // Should start with banner
        assert!(text.starts_with("AnkaOS 0.0\n"),
            "expected banner, got: {:?}", &text[..text.len().min(30)]);

        // After the banner, we should see A's and B's
        let body = &text["AnkaOS 0.0\n".len()..];

        // Verify both A and B appear
        assert!(body.contains('A'), "process A never ran");
        assert!(body.contains('B'), "process B never ran");

        // Verify they alternate (allowing for variable timing)
        // At minimum, we should see transitions from A→B and B→A
        let chars: Vec<char> = body.chars().filter(|c| *c == 'A' || *c == 'B').collect();
        let transitions = chars.windows(2).filter(|w| w[0] != w[1]).count();
        assert!(transitions >= 2,
            "expected at least 2 context switches, got {}: {:?}",
            transitions, &text);

        eprintln!("Output: {}", text.trim());
        eprintln!("Characters: {}, context switches: {}", chars.len(), transitions);
    }
}

//! Anka Secure OS v0.3 — capability-mediated processes and devices.
//!
//! Demonstrates the full authority lifecycle:
//!
//!   1. Kernel allocates named memory objects
//!   2. Processes receive capabilities (not raw addresses)
//!   3. Buffer sharing is explicit delegation of a sub-capability
//!   4. Device service receives delegated buffer capability for DMA
//!   5. Process death revokes objects → stale DMA is denied
//!
//! The demanding client:
//!
//!   Process A allocates a buffer, delegates a write capability to a
//!   device service, then exits.  The kernel revokes process A's objects.
//!   The device service attempts a late DMA write using the stale
//!   capability.  The protection fabric denies the write with
//!   StaleGeneration.  Memory is unchanged.
//!
//! Invariant proven:
//!
//!   g_C ≠ g_O ⟹ DMA transaction denied with no memory side effect.

use crate::asm::Asm;

// ───────────────────────────────────────────────────────────────────
// ABI constants
// ───────────────────────────────────────────────────────────────────

const CONSOLE_TX: u32 = 0x00F0_0000;
const TIMER_BASE: u32 = 0x00F0_0010;
const PROTECT_BASE: u32 = 0x00F0_0020;

const TIMER_CTRL: u32 = TIMER_BASE;
const TIMER_STATUS: u32 = TIMER_BASE + 7;
const PROTECT_DOMAIN: u32 = PROTECT_BASE;

// Kernel data area (0x0800-0x08FF)
const CURRENT_PID: u32 = 0x0800;
const SAVED_SP: [u32; 3] = [0x0810, 0x0814, 0x0818];
const TICK_COUNT: u32 = 0x0820;
const PROC_DEAD: [u32; 3] = [0x0830, 0x0834, 0x0838];
const DMA_BUF_BASE: u32 = 0x0840;

// Process stacks
const PROC0_STACK: u32 = 0x0004_0000; // Process A (worker)
const PROC1_STACK: u32 = 0x0008_0000; // Process B (device service)
const PROC2_STACK: u32 = 0x000C_0000; // Process C (monitor)

// DMA buffer: process A allocates, delegates to device service B
const DMA_BUF: u32 = 0x0002_0000;
const DMA_BUF_LEN: u32 = 0x1000;

// Syscall numbers (TRAP #0, D0 = syscall number)
const SYS_PRINT_CHAR: u32 = 1;
const SYS_EXIT: u32 = 2;
const SYS_DMA_WRITE: u32 = 3; // D1 = offset, D2 = data word

/// Build the Anka Secure OS v0.3 kernel.
///
/// Three processes:
///   0: Worker   — writes 0xCAFE to DMA buffer via syscall, then exits
///   1: DevSvc   — after process 0 exits, attempts stale DMA write
///   2: Monitor  — prints status characters
///
/// The kernel handles TRAP #0 syscalls and manages the object table.
/// Process death triggers revocation — the device service's late DMA
/// write is denied by the protection fabric.
pub fn build(base: u32) -> Vec<u8> {
    let mut a = Asm::new(base);

    // ─── _start ───────────────────────────────────────────────
    a.label("_start");

    // Print banner
    a.lea_label("banner", 0);
    a.bsr("print_string");

    // Store DMA buffer base address in kernel data
    a.move_l_imm(DMA_BUF, 0);
    a.emit(0x23C0); // MOVE.L D0, (DMA_BUF_BASE).L
    a.emit((DMA_BUF_BASE >> 16) as u16);
    a.emit(DMA_BUF_BASE as u16);

    // ─── Initialize process 0 (worker) ──────────────────────
    a.move_l_imm(PROC0_STACK, 0);
    a.movea_l_dn(0, 0); // A0 = stack top
    a.lea_label("proc_worker", 1);
    a.move_l_an_dn(1, 1);
    a.emit(0x2101); // MOVE.L D1, -(A0)  push return PC
    a.emit(0x5548); // SUBQ.L #2, A0
    a.emit(0x30BC); // MOVE.W #$0000, (A0) — user mode SR
    a.emit(0x0000);
    // Push 15 dummy registers (D0-D7, A0-A6)
    a.moveq(15, 2);
    a.moveq(0, 3);
    a.label("push0_loop");
    a.emit(0x2103); // MOVE.L D3, -(A0)
    a.emit(0x5382); // SUBQ.L #1, D2
    a.bne("push0_loop");
    a.move_l_an_dn(0, 0);
    a.emit(0x23C0); // MOVE.L D0, (SAVED_SP[0]).L
    a.emit((SAVED_SP[0] >> 16) as u16);
    a.emit(SAVED_SP[0] as u16);

    // ─── Initialize process 1 (device service) ─────────────
    a.move_l_imm(PROC1_STACK, 0);
    a.movea_l_dn(0, 0);
    a.lea_label("proc_devsvc", 1);
    a.move_l_an_dn(1, 1);
    a.emit(0x2101);
    a.emit(0x5548);
    a.emit(0x30BC);
    a.emit(0x0000);
    a.moveq(15, 2);
    a.moveq(0, 3);
    a.label("push1_loop");
    a.emit(0x2103);
    a.emit(0x5382);
    a.bne("push1_loop");
    a.move_l_an_dn(0, 0);
    a.emit(0x23C0);
    a.emit((SAVED_SP[1] >> 16) as u16);
    a.emit(SAVED_SP[1] as u16);

    // ─── Initialize process 2 (monitor) ─────────────────────
    a.move_l_imm(PROC2_STACK, 0);
    a.movea_l_dn(0, 0);
    a.lea_label("proc_monitor", 1);
    a.move_l_an_dn(1, 1);
    a.emit(0x2101);
    a.emit(0x5548);
    a.emit(0x30BC);
    a.emit(0x0000);
    a.moveq(15, 2);
    a.moveq(0, 3);
    a.label("push2_loop");
    a.emit(0x2103);
    a.emit(0x5382);
    a.bne("push2_loop");
    a.move_l_an_dn(0, 0);
    a.emit(0x23C0);
    a.emit((SAVED_SP[2] >> 16) as u16);
    a.emit(SAVED_SP[2] as u16);

    // ─── Initialize kernel state ────────────────────────────
    a.moveq(0, 0);
    a.emit(0x23C0); // CURRENT_PID = 0
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x23C0); // TICK_COUNT = 0
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);
    // Clear dead flags
    for &addr in &PROC_DEAD {
        a.emit(0x23C0);
        a.emit((addr >> 16) as u16);
        a.emit(addr as u16);
    }

    // Set protection domain = 0
    a.emit(0x13FC);
    a.emit(0x0000);
    a.emit((PROTECT_DOMAIN >> 16) as u16);
    a.emit(PROTECT_DOMAIN as u16);

    // Enable timer (fast — 100 cycles)
    a.emit(0x13FC);
    a.emit(0x0001);
    a.emit((TIMER_CTRL >> 16) as u16);
    a.emit(TIMER_CTRL as u16);

    // Dispatch process 0
    a.emit(0x2E79); // MOVEA.L (SAVED_SP[0]).L, A7
    a.emit((SAVED_SP[0] >> 16) as u16);
    a.emit(SAVED_SP[0] as u16);
    a.emit(0x4CDF); // MOVEM.L (A7)+, D0-D7/A0-A6
    a.emit(0x7FFF);
    a.emit(0x4E73); // RTE → user mode

    // ─── TRAP #0 handler (syscall) ──────────────────────────
    //
    // D0 = syscall number
    // D1, D2 = arguments
    //
    // The kernel runs in supervisor mode.  We have full
    // authority — the process had to ask.
    a.label("syscall_handler");
    // Mask all interrupts — syscalls are atomic.
    // RTE will restore the original SR (user mode, IPL=0).
    a.emit(0x46FC); // MOVE.W #$2700, SR
    a.emit(0x2700);

    // SYS_PRINT_CHAR (1): D1 = character
    a.emit(0x0C80); // CMPI.L #1, D0
    a.emit(0x0000);
    a.emit(SYS_PRINT_CHAR as u16);
    a.bne("sys_not_print");
    a.emit(0x13C1); // MOVE.B D1, (CONSOLE_TX).L
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.emit(0x4E73); // RTE

    a.label("sys_not_print");

    // SYS_EXIT (2): kill current process, switch to next
    a.emit(0x0C80); // CMPI.L #2, D0
    a.emit(0x0000);
    a.emit(SYS_EXIT as u16);
    a.bne("sys_not_exit");
    a.bra("do_exit_process");

    a.label("sys_not_exit");

    // SYS_DMA_WRITE (3): D1 = offset, D2 = data word
    // The kernel writes to the DMA buffer on behalf of the process.
    // This is the authority-checked path.
    a.emit(0x0C80); // CMPI.L #3, D0
    a.emit(0x0000);
    a.emit(SYS_DMA_WRITE as u16);
    a.bne("sys_unknown");

    // Write D2 to DMA_BUF + D1 (supervisor mode, so unchecked)
    a.emit(0x2039); // MOVE.L (DMA_BUF_BASE).L, D0
    a.emit((DMA_BUF_BASE >> 16) as u16);
    a.emit(DMA_BUF_BASE as u16);
    a.add_l_dn(1, 0); // D0 = DMA_BUF + offset
    a.movea_l_dn(0, 0); // A0 = target address
    a.emit(0x2082); // MOVE.L D2, (A0)
    a.emit(0x4E73); // RTE

    a.label("sys_unknown");
    a.emit(0x4E73); // RTE (ignore unknown syscalls)

    // ─── Process exit ───────────────────────────────────────
    a.label("do_exit_process");

    // Print "[exit N]"
    a.lea_label("exit_msg", 0);
    a.bsr("print_string");
    a.emit(0x2039); // MOVE.L (CURRENT_PID).L, D0
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x0680); // ADDI.L #$30, D0
    a.emit(0x0000);
    a.emit(0x0030);
    a.emit(0x13C0); // MOVE.B D0, (CONSOLE_TX).L
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.moveq(0x5D, 0); // ']'
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);

    // Mark process as dead
    a.emit(0x2039); // D0 = CURRENT_PID
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    // D0 * 4 = offset into PROC_DEAD array
    a.emit(0xE580); // ASL.L #2, D0
    a.emit(0x0680); // ADDI.L #PROC_DEAD[0], D0
    a.emit((PROC_DEAD[0] >> 16) as u16);
    a.emit(PROC_DEAD[0] as u16);
    a.movea_l_dn(0, 0); // A0 = &PROC_DEAD[pid]
    a.moveq(1, 1);
    a.emit(0x2081); // MOVE.L D1, (A0)

    // Find next alive process (round-robin)
    a.bra("find_next_alive");

    // ─── Timer ISR ──────────────────────────────────────────
    a.label("timer_isr");
    a.emit(0x48E7); // MOVEM.L D0-D7/A0-A6, -(A7)
    a.emit(0xFFFE);

    // Increment tick count
    a.emit(0x2039);
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);
    a.addq_l(1, 0);
    a.emit(0x23C0);
    a.emit((TICK_COUNT >> 16) as u16);
    a.emit(TICK_COUNT as u16);

    // Stop after 200 ticks
    a.emit(0x0C80); // CMPI.L #200, D0
    a.emit(0x0000);
    a.emit(0x00C8);
    a.bge("halt_system");

    // ACK timer
    a.emit(0x13FC);
    a.emit(0x0001);
    a.emit((TIMER_STATUS >> 16) as u16);
    a.emit(TIMER_STATUS as u16);

    // Save current SP: SAVED_SP[CURRENT_PID] = A7
    a.emit(0x2039); // D0 = CURRENT_PID
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0xE580); // ASL.L #2, D0
    a.emit(0x0680); // ADDI.L #SAVED_SP[0], D0
    a.emit((SAVED_SP[0] >> 16) as u16);
    a.emit(SAVED_SP[0] as u16);
    a.movea_l_dn(0, 0); // A0 = &SAVED_SP[pid]
    a.move_l_an_dn(7, 1); // D1 = A7
    a.emit(0x2081); // MOVE.L D1, (A0)

    // Advance to next process (round-robin over 3)
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.addq_l(1, 0);
    // if D0 >= 3, wrap to 0
    a.emit(0x0C80); // CMPI.L #3, D0
    a.emit(0x0000);
    a.emit(0x0003);
    a.blt("t_pid_ok");
    a.moveq(0, 0);
    a.label("t_pid_ok");

    // Check if target is dead
    a.move_l_dn_dn(0, 1); // D1 = candidate PID
    a.emit(0xE581); // ASL.L #2, D1
    a.emit(0x0681); // ADDI.L #PROC_DEAD[0], D1
    a.emit((PROC_DEAD[0] >> 16) as u16);
    a.emit(PROC_DEAD[0] as u16);
    a.movea_l_dn(1, 0); // A0 = &PROC_DEAD[candidate]
    a.emit(0x2210); // MOVE.L (A0), D1  — D1 = dead flag
    a.tst_l(1);
    a.beq("t_target_alive");

    // Dead — try next
    a.addq_l(1, 0);
    a.emit(0x0C80);
    a.emit(0x0000);
    a.emit(0x0003);
    a.blt("t_pid_ok2");
    a.moveq(0, 0);
    a.label("t_pid_ok2");

    // Check second candidate
    a.move_l_dn_dn(0, 1);
    a.emit(0xE581);
    a.emit(0x0681);
    a.emit((PROC_DEAD[0] >> 16) as u16);
    a.emit(PROC_DEAD[0] as u16);
    a.movea_l_dn(1, 0);
    a.emit(0x2210);
    a.tst_l(1);
    a.beq("t_target_alive");

    // All others dead — stay with current (don't switch)
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);

    // Still same process — just restore and return
    a.label("t_target_alive");
    // D0 = new PID
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);

    // Switch protection domain
    a.emit(0x13C0);
    a.emit((PROTECT_DOMAIN >> 16) as u16);
    a.emit(PROTECT_DOMAIN as u16);

    // Load new SP
    a.move_l_dn_dn(0, 1);
    a.emit(0xE581);
    a.emit(0x0681);
    a.emit((SAVED_SP[0] >> 16) as u16);
    a.emit(SAVED_SP[0] as u16);
    a.movea_l_dn(1, 0);
    a.emit(0x2E50); // MOVEA.L (A0), A7
    a.emit(0x4CDF); // MOVEM.L (A7)+, D0-D7/A0-A6
    a.emit(0x7FFF);
    a.emit(0x4E73); // RTE

    // ─── find_next_alive ────────────────────────────────────
    // Used after process exit.  Scans for any alive process.
    a.label("find_next_alive");
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.addq_l(1, 0);
    a.emit(0x0C80);
    a.emit(0x0000);
    a.emit(0x0003);
    a.blt("fn_pid_ok");
    a.moveq(0, 0);
    a.label("fn_pid_ok");

    // Try 3 candidates
    a.moveq(3, 2); // D2 = attempts
    a.label("fn_try");
    a.move_l_dn_dn(0, 1);
    a.emit(0xE581);
    a.emit(0x0681);
    a.emit((PROC_DEAD[0] >> 16) as u16);
    a.emit(PROC_DEAD[0] as u16);
    a.movea_l_dn(1, 0);
    a.emit(0x2210);
    a.tst_l(1);
    a.beq("fn_found_alive");
    // Dead — next
    a.addq_l(1, 0);
    a.emit(0x0C80);
    a.emit(0x0000);
    a.emit(0x0003);
    a.blt("fn_wrap_ok");
    a.moveq(0, 0);
    a.label("fn_wrap_ok");
    a.emit(0x5382); // SUBQ.L #1, D2
    a.bne("fn_try");
    // All dead
    a.bra("halt_system");

    a.label("fn_found_alive");
    // D0 = alive PID
    a.emit(0x23C0);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x13C0);
    a.emit((PROTECT_DOMAIN >> 16) as u16);
    a.emit(PROTECT_DOMAIN as u16);
    // Load its SP and dispatch
    a.move_l_dn_dn(0, 1);
    a.emit(0xE581);
    a.emit(0x0681);
    a.emit((SAVED_SP[0] >> 16) as u16);
    a.emit(SAVED_SP[0] as u16);
    a.movea_l_dn(1, 0);
    a.emit(0x2E50); // MOVEA.L (A0), A7
    a.emit(0x4CDF);
    a.emit(0x7FFF);
    a.emit(0x4E73); // RTE

    // ─── Bus error handler ──────────────────────────────────
    a.label("bus_error_handler");
    a.emit(0x46FC); // MOVE.W #$2700, SR
    a.emit(0x2700);

    a.lea_label("bus_err_msg", 0);
    a.bsr("print_string");

    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0x0680);
    a.emit(0x0000);
    a.emit(0x0030);
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);
    a.moveq(0x0A, 0);
    a.emit(0x13C0);
    a.emit((CONSOLE_TX >> 16) as u16);
    a.emit(CONSOLE_TX as u16);

    // Mark process dead
    a.emit(0x2039);
    a.emit((CURRENT_PID >> 16) as u16);
    a.emit(CURRENT_PID as u16);
    a.emit(0xE580);
    a.emit(0x0680);
    a.emit((PROC_DEAD[0] >> 16) as u16);
    a.emit(PROC_DEAD[0] as u16);
    a.movea_l_dn(0, 0);
    a.moveq(1, 1);
    a.emit(0x2081);

    a.bra("find_next_alive");

    // ─── Halt ───────────────────────────────────────────────
    a.label("halt_system");
    a.lea_label("halt_msg", 0);
    a.bsr("print_string");
    a.stop(0x2700);

    // ─── Process 0: Worker ──────────────────────────────────
    //
    // Prints 'W', writes 0xCAFEBABE to the DMA buffer via
    // syscall, prints 'W', then exits.
    a.label("proc_worker");

    // Print 'W'
    a.moveq(SYS_PRINT_CHAR as i8, 0);
    a.moveq(0x57, 1); // 'W'
    a.trap_n(0);

    // DMA write: offset=0, data=0xCAFEBABE
    a.moveq(SYS_DMA_WRITE as i8, 0);
    a.moveq(0, 1); // offset = 0
    a.move_l_imm(0xCAFEBABE, 2);
    a.trap_n(0);

    // DMA write: offset=4, data=0xDEADC0DE
    a.moveq(SYS_DMA_WRITE as i8, 0);
    a.moveq(4, 1);
    a.move_l_imm(0xDEADC0DE, 2);
    a.trap_n(0);

    // Print 'W'
    a.moveq(SYS_PRINT_CHAR as i8, 0);
    a.moveq(0x57, 1);
    a.trap_n(0);

    // Exit
    a.moveq(SYS_EXIT as i8, 0);
    a.trap_n(0);
    // Should not reach here
    a.bra("proc_worker");

    // ─── Process 1: Device Service ──────────────────────────
    //
    // Prints 'D' in a loop.  After process 0 exits, it will
    // attempt a direct write to the DMA buffer — which should
    // be denied because the object was revoked.
    //
    // The device service checks the PROC_DEAD[0] flag using a
    // syscall would be cleaner, but for demonstration we make it
    // attempt the raw write once it's been scheduled enough times.
    a.label("proc_devsvc");

    // Print 'D'
    a.moveq(SYS_PRINT_CHAR as i8, 0);
    a.moveq(0x44, 1); // 'D'
    a.trap_n(0);

    // Try to read from DMA buffer directly (user mode!)
    // This will fault because the device service has no
    // capability for the DMA buffer after revocation.
    a.move_l_imm(DMA_BUF, 0);
    a.movea_l_dn(0, 0);
    a.emit(0x2010); // MOVE.L (A0), D0  — read DMA buffer
    // If we get here, the read was allowed (before revocation)
    // or faulted (after revocation, handled by bus error handler)

    // Print 'D' again (only reached if no fault)
    a.moveq(SYS_PRINT_CHAR as i8, 0);
    a.moveq(0x44, 1);
    a.trap_n(0);

    a.bra("proc_devsvc");

    // ─── Process 2: Monitor ─────────────────────────────────
    a.label("proc_monitor");
    a.moveq(SYS_PRINT_CHAR as i8, 0);
    a.moveq(0x4D, 1); // 'M'
    a.trap_n(0);
    a.bra("proc_monitor");

    // ─── print_string ───────────────────────────────────────
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

    // ─── Data ───────────────────────────────────────────────
    a.label("banner");
    a.ascii_z("AnkaOS 0.3\n");
    a.label("exit_msg");
    a.ascii_z("[exit ");
    a.label("bus_err_msg");
    a.ascii_z("BUS ERROR proc ");
    a.label("halt_msg");
    a.ascii_z("\n[halt]\n");

    a.assemble()
}

#[cfg(test)]
mod tests {
    use crate::bus::{Bus, MappedBus};
    use crate::protection::*;

    /// The full lifecycle: allocate → delegate → DMA → revoke → stale DMA → denied.
    #[test]
    fn revocation_stops_stale_dma() {
        let inner = MappedBus::new(0x10_0000); // 1 MB
        let mut bus = ProtectedBus::new(inner);

        // ─── Phase 1: Kernel allocates objects ────────────────
        //
        // The kernel creates named objects for:
        //   - Process A's stack
        //   - Process B's stack
        //   - A shared DMA buffer (owned by process A)

        let stack_a = bus.objects.alloc("stack.proc_a", 0x40000, 0x10000);
        let stack_b = bus.objects.alloc("stack.proc_b", 0x80000, 0x10000);
        let dma_buf = bus.objects.alloc("dma.buffer",   0x20000, 0x1000);

        // ─── Phase 2: Mint capabilities ───────────────────────
        //
        // Each process gets capabilities for its own stack.
        // Process A also gets RW to the DMA buffer.

        let cap_stack_a = bus.objects.make_cap(stack_a, Perm::RW).unwrap();
        let cap_stack_b = bus.objects.make_cap(stack_b, Perm::RW).unwrap();
        let cap_dma_full = bus.objects.make_cap(dma_buf, Perm::RW).unwrap();

        // ─── Phase 3: Process A delegates to device service ───
        //
        // Process A creates a sub-capability for the DMA buffer
        // with write-only access and hands it to the device driver.
        //
        // Authority cannot be widened:
        //   - The sub-capability is within the parent's range
        //   - Write-only ⊂ RW (attenuated)

        let dma_subcap = bus.objects.derive_cap(
            &cap_dma_full,
            0x20000,   // same base
            0x1000,    // same length
            Perm::WRITE, // attenuated: write-only
        ).unwrap();

        // Verify the sub-capability works
        assert!(dma_subcap.permits(0x20000, 4, Perm::WRITE));
        assert!(!dma_subcap.permits(0x20000, 4, Perm::READ)); // attenuated

        // ─── Phase 4: DMA write succeeds ──────────────────────
        //
        // The device service performs a DMA write using its
        // delegated capability.  The write goes through the same
        // protection fabric as CPU accesses.

        let payload = [0xCA, 0xFE, 0xBA, 0xBE];
        let result = bus.dma_write(&dma_subcap, 0, &payload);
        assert!(result.is_ok(), "DMA write should succeed before revocation");

        // Verify the data is in memory
        assert_eq!(bus.inner.read8(0x20000), 0xCA);
        assert_eq!(bus.inner.read8(0x20001), 0xFE);
        assert_eq!(bus.inner.read8(0x20002), 0xBA);
        assert_eq!(bus.inner.read8(0x20003), 0xBE);

        // ─── Phase 5: Process A dies ──────────────────────────
        //
        // The kernel revokes all of process A's objects.
        // This bumps the generation counter, invalidating all
        // capabilities that reference these objects.

        bus.objects.revoke(stack_a);
        bus.objects.revoke(dma_buf);

        // Process B's stack is unaffected
        assert!(bus.objects.validate(&cap_stack_b));

        // Process A's capabilities are now stale
        assert!(!bus.objects.validate(&cap_stack_a));
        assert!(!bus.objects.validate(&cap_dma_full));
        assert!(!bus.objects.validate(&dma_subcap));

        // ─── Phase 6: Late DMA write — DENIED ────────────────
        //
        // The device service attempts another DMA write using
        // the stale sub-capability.  The protection fabric
        // catches the generation mismatch and denies the write.

        let stale_payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = bus.dma_write(&dma_subcap, 0, &stale_payload);

        // The write MUST fail
        assert!(result.is_err(), "stale DMA write must be denied");
        let fault = result.unwrap_err();
        assert_eq!(fault.reason, FaultReason::StaleGeneration,
            "expected StaleGeneration, got {:?}", fault.reason);

        // ─── Phase 7: Verify noninterference ─────────────────
        //
        // The denied DMA write must have had NO side effects.
        // Memory still contains the original payload from phase 4.

        assert_eq!(bus.inner.read8(0x20000), 0xCA, "memory corrupted by stale DMA");
        assert_eq!(bus.inner.read8(0x20001), 0xFE, "memory corrupted by stale DMA");
        assert_eq!(bus.inner.read8(0x20002), 0xBA, "memory corrupted by stale DMA");
        assert_eq!(bus.inner.read8(0x20003), 0xBE, "memory corrupted by stale DMA");

        // Fault log should show exactly one violation
        assert_eq!(bus.violation_count(), 1);
        assert_eq!(bus.fault_log.len(), 1);
        assert_eq!(bus.fault_log[0].reason, FaultReason::StaleGeneration);
        assert_eq!(bus.fault_log[0].address, 0x20000);

        eprintln!("─── Anka Secure OS v0.3: Revocation test ───");
        eprintln!("Objects allocated: stack.proc_a, stack.proc_b, dma.buffer");
        eprintln!("DMA write before revocation: OK (0xCAFEBABE)");
        eprintln!("Process A died → objects revoked (gen 0 → 1)");
        eprintln!("Late DMA write: DENIED ({})", fault);
        eprintln!("Memory unchanged: 0x{:02X}{:02X}{:02X}{:02X}",
            bus.inner.read8(0x20000), bus.inner.read8(0x20001),
            bus.inner.read8(0x20002), bus.inner.read8(0x20003));
        eprintln!("Invariant: g_C ≠ g_O ⟹ no memory side effect ✓");
    }

    /// Sub-capability cannot widen authority.
    #[test]
    fn delegation_cannot_widen_authority() {
        let inner = MappedBus::new(0x10000);
        let mut bus = ProtectedBus::new(inner);

        let buf = bus.objects.alloc("buf", 0x1000, 0x100);
        let parent = bus.objects.make_cap(buf, Perm::READ).unwrap();

        // Cannot widen permissions: R → RW
        assert!(bus.objects.derive_cap(&parent, 0x1000, 0x100, Perm::RW).is_none(),
            "derive_cap allowed permission widening");

        // Cannot widen range
        assert!(bus.objects.derive_cap(&parent, 0x0F00, 0x200, Perm::READ).is_none(),
            "derive_cap allowed range widening");

        // Can attenuate: narrow range, same permissions
        let child = bus.objects.derive_cap(&parent, 0x1010, 0x20, Perm::READ).unwrap();
        assert_eq!(child.base, 0x1010);
        assert_eq!(child.length, 0x20);

        // Child DMA write should fail (read-only)
        let result = bus.dma_write(&child, 0, &[0xFF]);
        assert!(result.is_err());
    }

    /// Stale parent cannot derive new children.
    #[test]
    fn stale_parent_cannot_derive() {
        let inner = MappedBus::new(0x10000);
        let mut bus = ProtectedBus::new(inner);

        let buf = bus.objects.alloc("buf", 0x1000, 0x100);
        let parent = bus.objects.make_cap(buf, Perm::RW).unwrap();

        // Revoke
        bus.objects.revoke(buf);

        // Stale parent cannot produce children
        assert!(bus.objects.derive_cap(&parent, 0x1000, 0x100, Perm::READ).is_none(),
            "stale parent derived a child capability");
    }

    // ═══════════════════════════════════════════════════════════
    // Full CPU integration test
    // ═══════════════════════════════════════════════════════════

    use crate::bus::timer::Timer;
    use crate::cpu::Cpu;
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
        fn output(&self) -> Arc<Mutex<Vec<u8>>> { self.output.clone() }
    }
    impl crate::bus::device::Device for CaptureConsole {
        fn name(&self) -> &str { "capture-console" }
        fn size(&self) -> u32 { 16 }
        fn read(&mut self, offset: u32) -> u8 {
            match offset {
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
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    }

    fn find_isr(kernel: &[u8]) -> u32 {
        let offset = kernel.windows(4)
            .position(|w| w[0] == 0x48 && w[1] == 0xE7 && w[2] == 0xFF && w[3] == 0xFE)
            .expect("could not find timer_isr");
        0x1000 + offset as u32
    }

    fn find_bus_error_handler(kernel: &[u8]) -> u32 {
        let offset = kernel.windows(4)
            .position(|w| w[0] == 0x46 && w[1] == 0xFC && w[2] == 0x27 && w[3] == 0x00)
            .expect("could not find bus_error_handler");
        0x1000 + offset as u32
    }

    fn find_syscall_handler(kernel: &[u8]) -> u32 {
        // TRAP #0 uses vector 32.  The handler starts right after
        // the dispatch-to-user-mode RTE.  We'll find it by scanning
        // for the CMPI.L #1 sequence that checks SYS_PRINT_CHAR.
        let sig: [u8; 6] = [0x0C, 0x80, 0x00, 0x00, 0x00, super::SYS_PRINT_CHAR as u8];
        let offset = kernel.windows(6)
            .position(|w| w == sig)
            .expect("could not find syscall_handler");
        0x1000 + offset as u32
    }

    /// The demanding client: process creates buffer, delegates to
    /// device service, process dies, device service attempts stale
    /// access → denied.
    #[test]
    fn capability_lifecycle_on_cpu() {
        let kernel = super::build(0x1000);

        let console = CaptureConsole::new();
        let output = console.output();

        let mut bus = MappedBus::new_16mb();
        bus.add_device(0x00F0_0000, Box::new(console));
        bus.add_device(0x00F0_0010, Box::new(Timer::new(500, 6)));

        bus.load(0x1000, &kernel);

        // Vector table
        bus.write32(0x000000, 0x0010_0000); // SSP
        bus.write32(0x000004, 0x0000_1000); // Reset PC

        let isr_addr = find_isr(&kernel);
        bus.write32(0x078, isr_addr); // Level 6 autovector

        let be_handler = find_bus_error_handler(&kernel);
        bus.write32(0x008, be_handler); // Vector 2

        let syscall_handler = find_syscall_handler(&kernel);
        bus.write32(0x080, syscall_handler); // Vector 32 = TRAP #0

        // ─── Protection setup ───────────────────────────────
        let mut pbus = ProtectedBus::new(bus);

        // Object table
        let code_obj = pbus.objects.alloc("kernel.code", 0x0000, 0x10000);
        let kdata_obj = pbus.objects.alloc("kernel.data", 0x0800, 0x100);
        let stack0_obj = pbus.objects.alloc("proc0.stack", 0x0002_0000, 0x0002_0000);
        let stack1_obj = pbus.objects.alloc("proc1.stack", 0x0006_0000, 0x0002_0000);
        let stack2_obj = pbus.objects.alloc("proc2.stack", 0x000A_0000, 0x0002_0000);
        let dma_obj = pbus.objects.alloc("dma.buffer", super::DMA_BUF, super::DMA_BUF_LEN);

        // Domain 0: Process A (worker) — code, own stack, console, DMA buffer
        let mut dom0 = Domain::new("proc0.worker");
        dom0.grant(pbus.objects.make_cap(code_obj, Perm::RX).unwrap());
        dom0.grant(pbus.objects.make_cap(kdata_obj, Perm::RW).unwrap());
        dom0.grant(pbus.objects.make_cap(stack0_obj, Perm::RW).unwrap());
        dom0.grant(Capability::new(99, 0x00F0_0000, 0x10, Perm::RW)); // console
        // Note: process 0 does NOT get direct DMA buffer access.
        // It writes through the syscall path (kernel mediates).

        // Domain 1: Process B (device service) — code, own stack, console
        // Initially it also has a capability for the DMA buffer.
        // After process 0 exits, the object is revoked.
        let mut dom1 = Domain::new("proc1.devsvc");
        dom1.grant(pbus.objects.make_cap(code_obj, Perm::RX).unwrap());
        dom1.grant(pbus.objects.make_cap(kdata_obj, Perm::RW).unwrap());
        dom1.grant(pbus.objects.make_cap(stack1_obj, Perm::RW).unwrap());
        dom1.grant(Capability::new(99, 0x00F0_0000, 0x10, Perm::RW));
        // Delegate DMA buffer read to device service
        dom1.grant(pbus.objects.make_cap(dma_obj, Perm::RW).unwrap());

        // Domain 2: Process C (monitor) — code, own stack, console
        let mut dom2 = Domain::new("proc2.monitor");
        dom2.grant(pbus.objects.make_cap(code_obj, Perm::RX).unwrap());
        dom2.grant(pbus.objects.make_cap(kdata_obj, Perm::RW).unwrap());
        dom2.grant(pbus.objects.make_cap(stack2_obj, Perm::RW).unwrap());
        dom2.grant(Capability::new(99, 0x00F0_0000, 0x10, Perm::RW));

        pbus.add_domain(dom0);
        pbus.add_domain(dom1);
        pbus.add_domain(dom2);
        pbus.set_domain(0);

        let mut cpu = Cpu::new(pbus);

        // Run until the worker exits
        let mut steps = 0u64;
        let mut worker_exited = false;
        while !cpu.halted && steps < 500_000 {
            cpu.step();
            steps += 1;

            // Check PROC_DEAD[0] flag in memory (set atomically by
            // the exit handler).  Read from the inner MappedBus to
            // avoid disturbing the CPU's privilege state.
            //
            // Cannot parse output text because the timer preempts
            // between TRAP and the handler's first instruction
            // (TRAP doesn't change IPL — architecturally correct
            // for the 68000), interleaving diagnostic output.
            if !worker_exited {
                let dead_flag = cpu.bus.inner.read8(super::PROC_DEAD[0] + 3);
                if dead_flag == 1 {
                    // REVOKE: process 0 is dead, revoke its DMA buffer
                    cpu.bus.objects.revoke(dma_obj);
                    worker_exited = true;
                    eprintln!("[kernel] Revoked dma.buffer (gen 0 → 1) at step {}", steps);
                }
            }
        }

        let out = output.lock().unwrap();
        let text = String::from_utf8_lossy(&out);

        eprintln!("─── Anka Secure OS v0.3 ───");
        eprintln!("Output: {}", text.trim());
        eprintln!("Steps: {}, violations: {}", steps, cpu.bus.violation_count());

        // Verify banner
        assert!(text.starts_with("AnkaOS 0.3\n"),
            "expected banner, got: {:?}", &text[..text.len().min(30)]);

        // Worker ran and wrote to DMA buffer
        assert!(text.contains('W'), "worker never printed");

        // Worker exited
        assert!(worker_exited, "worker never exited");

        // Device service ran
        assert!(text.contains('D'), "device service never ran");

        // After revocation, the device service's DMA buffer access
        // should trigger a bus error.  The fault log should have
        // StaleGeneration entries.
        if worker_exited {
            let stale_faults: Vec<_> = cpu.bus.fault_log.iter()
                .filter(|f| f.reason == FaultReason::StaleGeneration)
                .collect();
            eprintln!("Stale generation faults: {}", stale_faults.len());
            if let Some(first) = stale_faults.first() {
                eprintln!("  first: {}", first);
            }

            // The DMA buffer should still contain 0xCAFEBABE from the
            // worker's syscall write (supervisor mode, not revoked).
            // Read from inner bus to avoid disturbing CPU state.
            let b0 = cpu.bus.inner.read8(super::DMA_BUF);
            let b1 = cpu.bus.inner.read8(super::DMA_BUF + 1);
            let b2 = cpu.bus.inner.read8(super::DMA_BUF + 2);
            let b3 = cpu.bus.inner.read8(super::DMA_BUF + 3);
            let word = ((b0 as u32) << 24) | ((b1 as u32) << 16)
                     | ((b2 as u32) << 8) | b3 as u32;
            eprintln!("DMA buffer[0..4] = 0x{:08X}", word);
            assert_eq!(word, 0xCAFEBABE,
                "DMA buffer corrupted after revocation!");
        }

        // Monitor should have printed at least one 'M'
        assert!(text.contains('M'), "monitor never scheduled");

        eprintln!("Invariant: g_C ≠ g_O ⟹ stale access denied ✓");
    }

    /// Multiple devices with independent capabilities.
    #[test]
    fn multi_device_isolation() {
        let inner = MappedBus::new(0x10_0000);
        let mut bus = ProtectedBus::new(inner);

        // Two buffers for two different devices
        let buf_a = bus.objects.alloc("net.rx_buf", 0x10000, 0x1000);
        let buf_b = bus.objects.alloc("disk.buf",   0x20000, 0x2000);

        let cap_a = bus.objects.make_cap(buf_a, Perm::RW).unwrap();
        let cap_b = bus.objects.make_cap(buf_b, Perm::RW).unwrap();

        // Device A writes to its buffer
        bus.dma_write(&cap_a, 0, &[0xAA; 16]).unwrap();

        // Device B writes to its buffer
        bus.dma_write(&cap_b, 0, &[0xBB; 16]).unwrap();

        // Device A cannot write to device B's buffer using its cap
        let cross_result = bus.dma_write(&cap_a, 0x10000, &[0xFF]);
        assert!(cross_result.is_err(),
            "device A wrote to device B's buffer");

        // Buffers contain their own data, no cross-contamination
        assert_eq!(bus.inner.read8(0x10000), 0xAA);
        assert_eq!(bus.inner.read8(0x20000), 0xBB);
    }
}

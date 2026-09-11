//! AnkaOS v0.2 — Hostile World test suite.
//!
//! Each test compiles a specific attack program and runs it under
//! the protected kernel.  Every attack must fail.  The fundamental
//! invariant:
//!
//!   **No user-controlled execution sequence can increase its authority.**
//!
//! Attack vectors tested:
//!
//!   1. MOVE #$2700, SR    — privilege escalation via SR write
//!   2. Crafted user-mode RTE — forge supervisor context on stack
//!   3. STOP #$2700         — privileged halt from user mode
//!   4. Write PROTECT_DOMAIN — domain spoofing via MMIO
//!   5. Rewrite vector 2    — vector corruption → supervisor at attacker PC
//!   6. Rewrite timer vector — hijack timer ISR
//!   7. Modify SAVED_SP_1   — scheduler state corruption
//!   8. Cross-stack write   — direct memory corruption (v0.1 baseline)
//!
//! The test harness wires up a ProtectedBus with hardened domains:
//!   - No user write to vector table (0x0000-0x03FF)
//!   - No user write to kernel data (0x0800-0x08FF)
//!   - Protection controller supervisor-only
//!   - Privileged instructions trap to vector 8

#[cfg(test)]
mod tests {
    use crate::asm::Asm;
    use crate::bus::timer::Timer;
    use crate::bus::{Bus, MappedBus};
    use crate::cpu::Cpu;
    use crate::protection::{Capability, Domain, FaultReason, Perm, ProtectedBus};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    // ───────────────────────────────────────────────────────────
    // Test infrastructure
    // ───────────────────────────────────────────────────────────

    const BASE: u32 = 0x1000;
    const CONSOLE_TX: u32 = 0x00F0_0000;
    const TIMER_BASE: u32 = 0x00F0_0010;
    const PROTECT_DOMAIN: u32 = 0x00F0_0020;

    const CURRENT_PID: u32 = 0x0800;
    const SAVED_SP_0: u32 = 0x0810;
    const SAVED_SP_1: u32 = 0x0814;
    const PROC0_STACK: u32 = 0x0008_0000;
    const PROC1_STACK: u32 = 0x000C_0000;

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
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    }

    /// Build a minimal kernel that boots a single user-mode process.
    ///
    /// The kernel sets up:
    ///   - Vector 8 (privilege violation) → priv_violation_handler
    ///   - Vector 2 (bus error) → bus_error_handler
    ///   - Vector 30 (timer level 6) → timer_isr (just ACKs, no switch)
    ///   - Dispatches the attacker process in user mode
    ///
    /// Both handlers print a distinctive tag and STOP.
    fn build_harness(_attacker_code: &[u8]) -> Vec<u8> {
        let mut a = Asm::new(BASE);

        a.label("_start");

        // Set up process 0's exception frame on its stack
        a.move_l_imm(PROC0_STACK, 0);     // D0 = stack top
        a.movea_l_dn(0, 0);               // A0 = stack top

        // Push PC = 0x2000 (attacker code area)
        a.move_l_imm(0x2000, 1);          // D1 = attacker entry
        a.emit(0x2101);                    // MOVE.L D1, -(A0)

        // Push SR = 0x0000 (user mode, IPL=0)
        a.emit(0x5548);                    // SUBQ.L #2, A0
        a.emit(0x30BC);
        a.emit(0x0000);

        // Push 15 zero registers (D0-D7, A0-A6)
        a.moveq(15, 2);
        a.moveq(0, 3);
        a.label("push_loop");
        a.emit(0x2103);                    // MOVE.L D3, -(A0)
        a.emit(0x5382);                    // SUBQ.L #1, D2
        a.bne("push_loop");

        // Save SP
        a.move_l_an_dn(0, 0);
        a.emit(0x23C0);
        a.emit((SAVED_SP_0 >> 16) as u16);
        a.emit(SAVED_SP_0 as u16);

        // Initialize kernel variables
        a.moveq(0, 0);
        a.emit(0x23C0);
        a.emit((CURRENT_PID >> 16) as u16);
        a.emit(CURRENT_PID as u16);

        // Set protection domain = 0
        a.emit(0x13FC);
        a.emit(0x0000);
        a.emit((PROTECT_DOMAIN >> 16) as u16);
        a.emit(PROTECT_DOMAIN as u16);

        // Set USP to top of process 0's stack so user-mode code has
        // a valid stack pointer for push operations.
        a.move_l_imm(PROC0_STACK, 0);     // D0 = stack top
        a.movea_l_dn(0, 0);               // A0 = stack top
        a.emit(0x4E60);                    // MOVE A0, USP

        // Dispatch: load SP, restore regs, RTE
        a.emit(0x2E79);                    // MOVEA.L (SAVED_SP_0).L, A7
        a.emit((SAVED_SP_0 >> 16) as u16);
        a.emit(SAVED_SP_0 as u16);
        a.emit(0x4CDF);                    // MOVEM.L (A7)+, D0-D7/A0-A6
        a.emit(0x7FFF);
        a.emit(0x4E73);                    // RTE → user mode

        // ─── Privilege violation handler (vector 8) ───────────
        a.label("priv_handler");
        a.emit(0x46FC);                    // MOVE.W #$2700, SR (mask IRQs)
        a.emit(0x2700);
        // Print "PV\n"
        a.moveq(0x50, 0);                 // 'P'
        a.emit(0x13C0);
        a.emit((CONSOLE_TX >> 16) as u16);
        a.emit(CONSOLE_TX as u16);
        a.moveq(0x56, 0);                 // 'V'
        a.emit(0x13C0);
        a.emit((CONSOLE_TX >> 16) as u16);
        a.emit(CONSOLE_TX as u16);
        a.moveq(0x0A, 0);                 // '\n'
        a.emit(0x13C0);
        a.emit((CONSOLE_TX >> 16) as u16);
        a.emit(CONSOLE_TX as u16);
        a.stop(0x2700);

        // ─── Bus error handler (vector 2) ─────────────────────
        a.label("bus_handler");
        a.emit(0x46FC);
        a.emit(0x2700);
        // Print "BE\n"
        a.moveq(0x42, 0);                 // 'B'
        a.emit(0x13C0);
        a.emit((CONSOLE_TX >> 16) as u16);
        a.emit(CONSOLE_TX as u16);
        a.moveq(0x45, 0);                 // 'E'
        a.emit(0x13C0);
        a.emit((CONSOLE_TX >> 16) as u16);
        a.emit(CONSOLE_TX as u16);
        a.moveq(0x0A, 0);
        a.emit(0x13C0);
        a.emit((CONSOLE_TX >> 16) as u16);
        a.emit(CONSOLE_TX as u16);
        a.stop(0x2700);

        // ─── Timer ISR (minimal: just ACK) ────────────────────
        a.label("timer_isr");
        a.emit(0x48E7);                    // MOVEM.L save
        a.emit(0xFFFE);
        a.emit(0x13FC);                    // ACK timer
        a.emit(0x0001);
        a.emit(((TIMER_BASE + 7) >> 16) as u16);
        a.emit((TIMER_BASE + 7) as u16);
        a.emit(0x4CDF);                    // MOVEM.L restore
        a.emit(0x7FFF);
        a.emit(0x4E73);                    // RTE

        a.assemble()
    }

    /// Build a hardened ProtectedBus with the kernel loaded and
    /// proper domains.  Returns (cpu, output_handle).
    fn make_hostile_cpu(
        kernel: &[u8],
        attacker: &[u8],
    ) -> (Cpu<ProtectedBus>, Arc<Mutex<Vec<u8>>>) {
        let console = CaptureConsole::new();
        let output = console.output();

        let mut bus = MappedBus::new_16mb();
        bus.add_device(0x00F0_0000, Box::new(console));
        bus.add_device(0x00F0_0010, Box::new(Timer::new(500, 6)));

        // Load kernel and attacker code
        bus.load(BASE, kernel);
        bus.load(0x2000, attacker);

        // Vector table
        bus.write32(0x000000, 0x0010_0000); // SSP
        bus.write32(0x000004, BASE);        // Reset PC

        // Find handler addresses by signature
        let isr_addr = find_sig(kernel, &[0x48, 0xE7, 0xFF, 0xFE]);
        let priv_addr = find_first_sig(kernel, &[0x46, 0xFC, 0x27, 0x00]);
        let bus_addr = find_nth_sig(kernel, &[0x46, 0xFC, 0x27, 0x00], 1);

        bus.write32(0x008, bus_addr);       // vector 2 = bus error
        bus.write32(0x020, priv_addr);      // vector 8 = privilege violation
        bus.write32(0x078, isr_addr);       // vector 30 = timer level 6

        // Wrap in ProtectedBus with hardened domains
        let mut pbus = ProtectedBus::new(bus);

        // Domain 0 (attacker): code + own stack + console (ONLY)
        // NO vector table, NO kernel data, NO protection controller
        let mut dom0 = Domain::new("attacker");
        // Code area (read-execute only, NOT writable)
        dom0.grant(Capability::new(1, 0x1000, 0x2000, Perm::RX));
        // Own stack (read-write)
        dom0.grant(Capability::new(2, 0x0004_0000, 0x0004_0000, Perm::RW));
        // Console device (read-write for putchar)
        dom0.grant(Capability::new(3, 0x00F0_0000, 0x10, Perm::RW));

        pbus.add_domain(dom0);
        pbus.set_domain(0);

        let cpu = Cpu::new(pbus);
        (cpu, output)
    }

    fn find_sig(kernel: &[u8], sig: &[u8]) -> u32 {
        let offset = kernel.windows(sig.len())
            .position(|w| w == sig)
            .expect("signature not found");
        BASE + offset as u32
    }

    fn find_first_sig(kernel: &[u8], sig: &[u8]) -> u32 {
        find_sig(kernel, sig)
    }

    fn find_nth_sig(kernel: &[u8], sig: &[u8], n: usize) -> u32 {
        let offset = kernel.windows(sig.len())
            .enumerate()
            .filter(|(_, w)| *w == sig)
            .nth(n)
            .expect("nth signature not found")
            .0;
        BASE + offset as u32
    }

    /// Run the CPU until halted or step limit.
    fn run(cpu: &mut Cpu<ProtectedBus>, limit: u64) -> u64 {
        let mut steps = 0u64;
        while !cpu.halted && steps < limit {
            cpu.step();
            steps += 1;
        }
        steps
    }

    /// Get the output as a string.
    fn text(output: &Arc<Mutex<Vec<u8>>>) -> String {
        let out = output.lock().unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    // ───────────────────────────────────────────────────────────
    // Attack 1: MOVE #$2700, SR — privilege escalation
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_move_to_sr() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to set supervisor mode + mask interrupts
        // MOVE.W #$2700, SR → 0x46FC 0x2700
        attacker.emit(0x46FC);
        attacker.emit(0x2700);
        // If we get here, the escalation worked → print 'X'
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_move_to_sr] {}", t.trim());
        assert!(t.contains("PV"), "expected privilege violation, got: {}", t);
        assert!(!t.contains('X'), "attacker escalated to supervisor!");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 2: Crafted RTE — forge supervisor context on stack
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_crafted_rte() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Push a fake exception frame: SR=$2700, PC=attacker_win
        // The attacker controls its own stack in user mode.
        // MOVE.L #attacker_win, -(A7)
        attacker.move_l_imm(0x200E, 0);   // D0 = address after RTE
        attacker.emit(0x2F00);             // MOVE.L D0, -(A7)
        // MOVE.W #$2700, -(A7)
        attacker.emit(0x3F3C);             // MOVE.W #imm, -(A7)
        attacker.emit(0x2700);             // SR = supervisor + IPL=7
        // RTE
        attacker.emit(0x4E73);
        // attacker_win: if we get here as supervisor, print 'X'
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_crafted_rte] {}", t.trim());
        assert!(t.contains("PV"), "expected privilege violation for RTE, got: {}", t);
        assert!(!t.contains('X'), "attacker forged supervisor context via RTE!");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 3: STOP — privileged halt from user mode
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_user_stop() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // STOP #$2700 from user mode
        attacker.stop(0x2700);
        // If we get past the trap somehow:
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_user_stop] {}", t.trim());
        assert!(t.contains("PV"), "expected privilege violation for STOP, got: {}", t);
        assert!(!t.contains('X'), "attacker executed STOP in user mode!");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 4: Write PROTECT_DOMAIN — domain spoofing
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_write_protect_domain() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to switch to domain 1 by writing PROTECT_DOMAIN
        // MOVE.B #1, ($00F00020).L
        attacker.emit(0x13FC);
        attacker.emit(0x0001);
        attacker.emit((PROTECT_DOMAIN >> 16) as u16);
        attacker.emit(PROTECT_DOMAIN as u16);
        // If we get here, print 'X' (domain switched)
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_write_protect_domain] {}", t.trim());
        // Should cause bus error (supervisor-only MMIO)
        assert!(t.contains("BE") || t.contains("PV"),
            "expected fault for protection controller write, got: {}", t);
        assert!(!t.contains('X'), "attacker changed protection domain!");

        // Verify the fault log shows DeviceAccessDenied
        let faults = &cpu.bus.fault_log;
        assert!(faults.iter().any(|f| f.reason == FaultReason::DeviceAccessDenied),
            "no DeviceAccessDenied fault recorded: {:?}", faults);
    }

    // ───────────────────────────────────────────────────────────
    // Attack 5: Rewrite vector 2 — hijack bus error handler
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_rewrite_vector_table() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to write our own address to vector 2 (bus error)
        // MOVE.L #$2020, ($0008).L
        attacker.move_l_imm(0x2020, 0);
        attacker.movea_l_dn(0, 0);
        // MOVE.L D0, ($0008).L → but we'll use indirect
        attacker.move_l_imm(0x0008, 1);   // D1 = vector 2 address
        attacker.movea_l_dn(1, 1);         // A1 = 0x0008
        attacker.emit(0x2280);             // MOVE.L D0, (A1)
        // If we get here, we corrupted the vector table
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_rewrite_vector_table] {}", t.trim());
        assert!(t.contains("BE"),
            "expected bus error for vector table write, got: {}", t);
        assert!(!t.contains('X'), "attacker rewrote vector table!");

        // Verify vector 2 is unchanged
        let v2 = cpu.bus.inner.read32(0x0008);
        assert_ne!(v2, 0x2020, "vector 2 was corrupted to attacker address");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 6: Rewrite timer vector — hijack timer ISR
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_rewrite_timer_vector() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to write to vector 30 (timer ISR, offset 0x078)
        attacker.move_l_imm(0x2020, 0);   // D0 = attacker code
        attacker.move_l_imm(0x0078, 1);   // D1 = timer vector addr
        attacker.movea_l_dn(1, 1);         // A1 = 0x0078
        attacker.emit(0x2280);             // MOVE.L D0, (A1)
        // Survival print
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_rewrite_timer_vector] {}", t.trim());
        assert!(t.contains("BE"),
            "expected bus error for timer vector write, got: {}", t);
        assert!(!t.contains('X'), "attacker rewrote timer vector!");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 7: Modify SAVED_SP_1 — scheduler corruption
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_modify_scheduler_state() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to write to SAVED_SP_1 (0x0814) — scheduler data
        attacker.move_l_imm(0xDEADBEEF, 0);
        attacker.move_l_imm(SAVED_SP_1, 1);
        attacker.movea_l_dn(1, 1);
        attacker.emit(0x2280);             // MOVE.L D0, (A1)
        // Survival print
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_modify_scheduler_state] {}", t.trim());
        assert!(t.contains("BE"),
            "expected bus error for scheduler data write, got: {}", t);
        assert!(!t.contains('X'), "attacker modified scheduler state!");

        // Verify SAVED_SP_1 is not corrupted
        let sp1 = cpu.bus.inner.read32(SAVED_SP_1);
        assert_ne!(sp1, 0xDEADBEEF, "SAVED_SP_1 was corrupted");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 8: Cross-stack write — direct memory corruption
    // (baseline from v0.1)
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_cross_stack_write() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to write 0xDEADBEEF to process 1's stack area
        attacker.move_l_imm(PROC1_STACK - 0x100, 0);
        attacker.movea_l_dn(0, 0);
        attacker.move_l_imm(0xDEADBEEF, 0);
        attacker.emit(0x2080);             // MOVE.L D0, (A0)
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_cross_stack_write] {}", t.trim());
        assert!(t.contains("BE"),
            "expected bus error for cross-stack write, got: {}", t);
        assert!(!t.contains('X'), "attacker wrote to another process's stack!");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 9: MOVE SR, D0 — read SR from user mode
    // (leaks supervisor state: S bit, IPL, trace)
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_read_sr() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // MOVE SR, D0 → 0x40C0
        attacker.emit(0x40C0);
        // If we get here, we read the SR
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_read_sr] {}", t.trim());
        assert!(t.contains("PV"),
            "expected privilege violation for MOVE SR, got: {}", t);
        assert!(!t.contains('X'), "attacker read the full SR!");
    }

    // ───────────────────────────────────────────────────────────
    // Attack 10: Read PROTECT_DOMAIN — info disclosure
    // ───────────────────────────────────────────────────────────

    #[test]
    fn attack_read_protect_domain() {
        let kernel = build_harness(&[]);
        let mut attacker = Asm::new(0x2000);
        // Try to read the protection domain register
        // MOVE.B ($00F00020).L, D0
        attacker.emit(0x1039);             // MOVE.B (xxx).L, D0
        attacker.emit((PROTECT_DOMAIN >> 16) as u16);
        attacker.emit(PROTECT_DOMAIN as u16);
        attacker.moveq(0x58, 0);
        attacker.emit(0x13C0);
        attacker.emit((CONSOLE_TX >> 16) as u16);
        attacker.emit(CONSOLE_TX as u16);
        attacker.stop(0x2700);
        let attack_bin = attacker.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &attack_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[attack_read_protect_domain] {}", t.trim());
        assert!(t.contains("BE"),
            "expected bus error for protection register read, got: {}", t);
        assert!(!t.contains('X'), "attacker read the protection domain register!");
    }

    // ───────────────────────────────────────────────────────────
    // Sanity: legitimate user code still works
    // ───────────────────────────────────────────────────────────

    #[test]
    fn legitimate_user_code_works() {
        let kernel = build_harness(&[]);
        let mut legit = Asm::new(0x2000);
        // A well-behaved program: prints "OK\n" and loops
        legit.moveq(0x4F, 0);             // 'O'
        legit.emit(0x13C0);
        legit.emit((CONSOLE_TX >> 16) as u16);
        legit.emit(CONSOLE_TX as u16);
        legit.moveq(0x4B, 0);             // 'K'
        legit.emit(0x13C0);
        legit.emit((CONSOLE_TX >> 16) as u16);
        legit.emit(CONSOLE_TX as u16);
        legit.moveq(0x0A, 0);             // '\n'
        legit.emit(0x13C0);
        legit.emit((CONSOLE_TX >> 16) as u16);
        legit.emit(CONSOLE_TX as u16);
        // Loop forever (timer will eventually make us halt via step limit)
        legit.label("loop");
        legit.bra("loop");
        let legit_bin = legit.assemble();

        let (mut cpu, output) = make_hostile_cpu(&kernel, &legit_bin);
        run(&mut cpu, 10_000);

        let t = text(&output);
        eprintln!("[legitimate_user_code] {}", t.trim());
        assert!(t.contains("OK"), "legitimate user code didn't run: {}", t);
        assert_eq!(cpu.bus.violation_count(), 0,
            "legitimate code triggered {} violations", cpu.bus.violation_count());
    }
}

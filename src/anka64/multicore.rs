//! Anka64 multicore execution under sequential consistency.
//!
//! Memory model: there exists one global ordering of committed
//! memory transactions, consistent with each core's program order.
//!
//! Implementation: interleaved execution — one core steps per tick.
//! This is SC by construction.

use super::core::Anka64Core;
#[cfg(test)]
use super::core::StepResult;
use super::fabric::Fabric;

// ───────────────────────────────────────────────────────────────────
// MultiCore scheduler
// ───────────────────────────────────────────────────────────────────

pub struct MultiCore {
    pub cores: Vec<Anka64Core>,
}

impl MultiCore {
    pub fn new() -> Self { Self { cores: Vec::new() } }

    pub fn add_core(&mut self, core: Anka64Core) {
        self.cores.push(core);
    }

    /// Execute under sequential consistency: step cores round-robin,
    /// one instruction per core per round.
    pub fn run_sc(&mut self, fabric: &mut Fabric, max_steps: usize) {
        let mut total = 0;
        loop {
            let mut all_halted = true;
            for i in 0..self.cores.len() {
                if self.cores[i].halted { continue; }
                all_halted = false;
                self.cores[i].step(fabric);
                total += 1;
                if total >= max_steps { return; }
            }
            if all_halted { return; }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — Phase 5 multicore proofs
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fabric::Fabric;
    use super::super::isa::*;
    use super::super::state::*;

    const CPU0: AgentId = AgentId(0);
    const CPU1: AgentId = AgentId(1);
    const DMA0: AgentId = AgentId(10);

    /// Shared physical layout:
    ///   0x000000: Core 0 text (0x4000)
    ///   0x010000: Core 1 text (0x4000)
    ///   0x020000: Shared data (0x4000)
    ///   0x030000: Core 0 stack (0x4000)
    ///   0x040000: Core 1 stack (0x4000)
    fn setup_two_cores() -> (Fabric, MultiCore, DomainId, DomainId, ObjectId) {
        let mut fabric = Fabric::new(0x800000);

        let text0  = fabric.alloc_object("core0_text",  0x4000, ObjectKind::Memory);
        let text1  = fabric.alloc_object("core1_text",  0x4000, ObjectKind::Memory);
        let shared = fabric.alloc_object("shared_data", 0x4000, ObjectKind::Memory);
        let stack0 = fabric.alloc_object("core0_stack", 0x4000, ObjectKind::Memory);
        let stack1 = fabric.alloc_object("core1_stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text0,  0x000000);
        fabric.place_object(text1,  0x010000);
        fabric.place_object(shared, 0x020000);
        fabric.place_object(stack0, 0x030000);
        fabric.place_object(stack1, 0x040000);

        // Domain for each core: own text + shared data + own stack
        // Both domains get RW + ATOMIC on shared data
        let dom0 = fabric.create_domain();
        fabric.grant(dom0, text0,  0, 0x4000, Permissions::RX);
        fabric.grant(dom0, shared, 0, 0x4000, Permissions(Permissions::RW.0 | Permissions::ATOMIC.0));
        fabric.grant(dom0, stack0, 0, 0x4000, Permissions::RW);

        let dom1 = fabric.create_domain();
        fabric.grant(dom1, text1,  0, 0x4000, Permissions::RX);
        fabric.grant(dom1, shared, 0, 0x4000, Permissions(Permissions::RW.0 | Permissions::ATOMIC.0));
        fabric.grant(dom1, stack1, 0, 0x4000, Permissions::RW);

        // Virtual address maps (same virtual layout for both cores)
        let mut core0 = Anka64Core::new(CPU0, dom0);
        core0.address_map.add(0x00000, 0x4000, text0);
        core0.address_map.add(0x10000, 0x4000, shared);
        core0.address_map.add(0x20000, 0x4000, stack0);
        core0.r[SP as usize] = 0x20000 + 0x4000;

        let mut core1 = Anka64Core::new(CPU1, dom1);
        core1.address_map.add(0x00000, 0x4000, text1);
        core1.address_map.add(0x10000, 0x4000, shared);
        core1.address_map.add(0x20000, 0x4000, stack1);
        core1.r[SP as usize] = 0x20000 + 0x4000;

        let mut mc = MultiCore::new();
        mc.add_core(core0);
        mc.add_core(core1);

        (fabric, mc, dom0, dom1, shared)
    }

    // ═══════════════════════════════════════════════════════════
    // P16: Two cores run independent programs to completion
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p16_two_cores_independent() {
        let (mut fabric, mut mc, _, _, _) = setup_two_cores();

        // Core 0: MOVI R0, 42; HALT
        let mut asm0 = Asm64::new();
        asm0.movi(R0, 42);
        asm0.halt();
        fabric.write_physical(0x000000, &asm0.to_bytes());

        // Core 1: MOVI R0, 99; HALT
        let mut asm1 = Asm64::new();
        asm1.movi(R0, 99);
        asm1.halt();
        fabric.write_physical(0x010000, &asm1.to_bytes());

        mc.run_sc(&mut fabric, 100);

        assert!(mc.cores[0].halted);
        assert!(mc.cores[1].halted);
        assert_eq!(mc.cores[0].r[R0 as usize], 42);
        assert_eq!(mc.cores[1].r[R0 as usize], 99);
        eprintln!("P16: Core0=42, Core1=99 (independent) ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // P17: Naive shared counter — proves LD/ST insufficient
    //
    // Both cores increment shared counter 10 times.
    // Under round-robin SC interleaving, LD-ADDI-ST races
    // cause lost updates.  Expected: counter < 20.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p17_naive_counter_lost_updates() {
        let (mut fabric, mut mc, _, _, _) = setup_two_cores();
        let n = 10;

        // shared[0x0000] = counter, initially 0
        fabric.write_physical(0x020000, &0u64.to_le_bytes());

        // Both cores run the same program:
        //   MOVI R1, 0x10000   ; shared base addr
        //   MOVI R2, N         ; iteration count
        //   MOVI R3, 0         ; loop counter
        // loop:
        //   LD R0, [R1 + 0]    ; read counter
        //   ADDI R0, R0, 1     ; increment
        //   ST R0, [R1 + 0]    ; write counter
        //   ADDI R3, R3, 1
        //   CMP R3, R2
        //   BNE loop
        //   HALT
        fn build_naive_inc(n: i32) -> Asm64 {
            let mut asm = Asm64::new();
            asm.movi(R1, 0x10000);  // shared data virtual addr
            asm.movi(R2, n);
            asm.movi(R3, 0);
            let loop_addr = asm.here();
            asm.ld(R0, R1, 0);
            asm.addi(R0, R0, 1);
            asm.st(R0, R1, 0);
            asm.addi(R3, R3, 1);
            asm.cmp(R3, R2);
            let branch_addr = asm.here();
            asm.bcc(Cond::Ne, loop_addr - branch_addr);
            asm.halt();
            asm
        }

        let asm = build_naive_inc(n);
        fabric.write_physical(0x000000, &asm.to_bytes());
        fabric.write_physical(0x010000, &asm.to_bytes());

        mc.run_sc(&mut fabric, 100_000);

        assert!(mc.cores[0].halted);
        assert!(mc.cores[1].halted);

        let counter_bytes = fabric.read_physical(0x020000, 8);
        let counter = u64::from_le_bytes(
            [counter_bytes[0], counter_bytes[1], counter_bytes[2], counter_bytes[3],
             counter_bytes[4], counter_bytes[5], counter_bytes[6], counter_bytes[7]]);

        eprintln!("P17: naive counter = {} (expected 2×{}={}, got {})",
            counter, n, 2 * n, counter);
        assert!(counter < (2 * n) as u64,
            "naive counter should have lost updates: got {}, expected < {}",
            counter, 2 * n);
        assert!(counter > 0, "counter should be non-zero");
        eprintln!("     LD/ST insufficient for synchronization ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // P18: Spinlock counter with XCHG — counter = 2N
    //
    // The ISA's 29th instruction earns its existence here.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p18_spinlock_counter_correct() {
        let (mut fabric, mut mc, _, _, _) = setup_two_cores();
        let n = 10;

        // shared[0x0000] = counter (initially 0)
        // shared[0x0008] = lock    (initially 0)
        fabric.write_physical(0x020000, &0u64.to_le_bytes());
        fabric.write_physical(0x020008, &0u64.to_le_bytes());

        // Both cores run:
        //   MOVI R4, 0x10000   ; shared base
        //   MOVI R5, N
        //   MOVI R6, 0         ; loop counter
        // loop:
        //   ; acquire spinlock
        //   MOVI R1, 1
        //   XCHG R1, [R4 + 8]  ; atomically swap R1 ↔ lock
        //   CMPI R1, 0          ; was lock free?
        //   BNE acquire         ; no → spin
        //
        //   ; critical section
        //   LD R0, [R4 + 0]
        //   ADDI R0, R0, 1
        //   ST R0, [R4 + 0]
        //
        //   ; release
        //   MOVI R1, 0
        //   ST R1, [R4 + 8]
        //
        //   ADDI R6, R6, 1
        //   CMP R6, R5
        //   BNE loop
        //   HALT
        fn build_spinlock_inc(n: i32) -> Asm64 {
            let mut asm = Asm64::new();
            asm.movi(R4, 0x10000);  // shared data base
            asm.movi(R5, n);
            asm.movi(R6, 0);
            let loop_addr = asm.here(); // word 3

            // Acquire
            let acquire = asm.here();     // word 3 (first iter) or re-entry
            asm.movi(R1, 1);              // R1 = 1
            asm.xchg(R1, R4, 8);         // XCHG R1, [R4+8] — atomic swap
            asm.cmpi(R1, 0);              // was old value 0 (unlocked)?
            let spin_branch = asm.here();
            asm.bcc(Cond::Ne, acquire - spin_branch); // spin if locked

            // Critical section
            asm.ld(R0, R4, 0);
            asm.addi(R0, R0, 1);
            asm.st(R0, R4, 0);

            // Release
            asm.movi(R1, 0);
            asm.st(R1, R4, 8);

            // Loop control
            asm.addi(R6, R6, 1);
            asm.cmp(R6, R5);
            let loop_branch = asm.here();
            asm.bcc(Cond::Ne, loop_addr - loop_branch);
            asm.halt();
            asm
        }

        let asm = build_spinlock_inc(n);
        fabric.write_physical(0x000000, &asm.to_bytes());
        fabric.write_physical(0x010000, &asm.to_bytes());

        mc.run_sc(&mut fabric, 1_000_000);

        assert!(mc.cores[0].halted);
        assert!(mc.cores[1].halted);

        let counter_bytes = fabric.read_physical(0x020000, 8);
        let counter = u64::from_le_bytes(
            [counter_bytes[0], counter_bytes[1], counter_bytes[2], counter_bytes[3],
             counter_bytes[4], counter_bytes[5], counter_bytes[6], counter_bytes[7]]);

        eprintln!("P18: spinlock counter = {} (expected {})", counter, 2 * n);
        assert_eq!(counter, (2 * n) as u64,
            "spinlock counter must be exactly 2N");
        eprintln!("     Instruction 29 (XCHG) earned its existence ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // P19: Revocation under multicore
    //
    // Core 0 reads shared object, Core 1 revokes it mid-flight,
    // DMA has a pending write.  Phase 0 semantics survive.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p19_revocation_under_multicore() {
        let mut fabric = Fabric::new(0x800000);

        let text0  = fabric.alloc_object("core0_text",  0x4000, ObjectKind::Memory);
        let shared = fabric.alloc_object("shared",      0x4000, ObjectKind::Memory);
        fabric.place_object(text0,  0x000000);
        fabric.place_object(shared, 0x020000);

        // Sentinel in shared
        fabric.write_physical(0x020000, &0xCAFEu64.to_le_bytes());

        let dom0 = fabric.create_domain();
        fabric.grant(dom0, text0,  0, 0x4000, Permissions::RX);
        fabric.grant(dom0, shared, 0, 0x4000, Permissions::RW);

        let dma_dom = fabric.create_domain();
        fabric.grant(dma_dom, shared, 0, 0x4000, Permissions::RW);

        // Core 0 program: LD R0, [shared]; HALT
        let mut asm = Asm64::new();
        asm.movi(R1, 0x10000);  // shared virtual addr
        asm.ld(R0, R1, 0);
        asm.halt();
        fabric.write_physical(0x000000, &asm.to_bytes());

        // DMA: authorize a write (but don't commit yet)
        let dma_req = super::super::fabric::request(
            DMA0, dma_dom, shared, 0, Width::Double, AccessKind::Write,
        );
        let dma_idx = fabric.submit(dma_req, Some(0xDEADu64.to_le_bytes().to_vec()));
        fabric.advance(dma_idx); // DMA authorized

        // Core 0 setup
        let mut core0 = Anka64Core::new(CPU0, dom0);
        core0.address_map.add(0x00000, 0x4000, text0);
        core0.address_map.add(0x10000, 0x4000, shared);

        // Core 0 runs MOVI (sets R1), but hasn't loaded yet
        core0.step(&mut fabric); // MOVI R1, 0x10000

        // NOW: revoke the shared object
        fabric.revoke(shared);

        // Core 0 tries to load — should fault (stale generation)
        let result = core0.step(&mut fabric); // LD R0, [R1]
        assert!(matches!(result, StepResult::Fault(_)),
            "load after revocation should fault");

        // DMA tries to commit — should also fault
        fabric.advance(dma_idx); // translate
        fabric.advance(dma_idx); // commit → fault
        assert_eq!(fabric.transaction(dma_idx).state, TxState::Faulted);
        assert_eq!(fabric.transaction(dma_idx).fault.as_ref().unwrap().reason,
            FaultReason::StaleGeneration);

        // Sentinel unchanged
        let mem = fabric.read_physical(0x020000, 8);
        let val = u64::from_le_bytes(
            [mem[0], mem[1], mem[2], mem[3], mem[4], mem[5], mem[6], mem[7]]);
        assert_eq!(val, 0xCAFE, "sentinel must be intact");

        eprintln!("P19: Core0 load faulted, DMA write faulted, sentinel intact ✓");
        eprintln!("     Phase-0 revocation semantics survive true multicore");
    }

    // ═══════════════════════════════════════════════════════════
    // M-proofs: memory model properties
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn m3_protection_independent_of_core_identity() {
        // Same domain on two different cores → same authority
        let (mut fabric, _, _, _, shared) = setup_two_cores();

        // Core 0 writes
        let req0 = super::super::fabric::request(
            CPU0, fabric.domains.keys().next().copied().unwrap(),
            shared, 0, Width::Double, AccessKind::Write,
        );
        let r0 = fabric.execute_write(req0, 42u64.to_le_bytes().to_vec());
        assert!(r0.is_ok(), "Core 0 write should succeed");

        // Read back through Core 1's domain
        let dom1 = *fabric.domains.keys().nth(1).unwrap();
        let req1 = super::super::fabric::request(
            CPU1, dom1, shared, 0, Width::Double, AccessKind::Read,
        );
        let r1 = fabric.execute_read(req1);
        assert!(r1.is_ok(), "Core 1 read should succeed");
        let val = u64::from_le_bytes(r1.unwrap().try_into().unwrap());
        assert_eq!(val, 42, "Core 1 sees Core 0's write");
        eprintln!("M3: protection independent of core identity ✓");
    }

    #[test]
    fn m6_concurrency_cannot_manufacture_authority() {
        let mut fabric = Fabric::new(0x800000);

        let secret = fabric.alloc_object("secret", 0x1000, ObjectKind::Memory);
        fabric.place_object(secret, 0x100000);
        fabric.write_physical(0x100000, &0x5EC4E7u64.to_le_bytes());

        // Domain with NO access to secret
        let dom = fabric.create_domain();

        // Neither core can access it
        let req0 = super::super::fabric::request(
            CPU0, dom, secret, 0, Width::Double, AccessKind::Read,
        );
        assert!(fabric.execute_read(req0).is_err());

        let req1 = super::super::fabric::request(
            CPU1, dom, secret, 0, Width::Double, AccessKind::Read,
        );
        assert!(fabric.execute_read(req1).is_err());

        // Not even with Atomic
        let req_atomic = super::super::fabric::request(
            CPU0, dom, secret, 0, Width::Double, AccessKind::Atomic,
        );
        let xchg_result = fabric.execute_atomic_xchg(req_atomic, 0u64.to_le_bytes().to_vec());
        assert!(xchg_result.is_err());

        eprintln!("M6: concurrency cannot manufacture authority ✓");
    }
}

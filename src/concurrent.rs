//! Concurrent protection fabric — two-agent race model.
//!
//! Sequential Anka treats authorization and commit as one event.
//! With two independent bus masters, they are not:
//!
//!   CPU₀: validate(C) ··· commit(R)
//!   CPU₁: revoke(O)           ← can occur in between
//!
//! This module implements **commit-time generation revalidation**:
//!
//!   request → authorize(g) → prepare → revalidate(g) → commit
//!
//! If the object's generation changed between authorize and commit,
//! the transaction faults with no memory side effects.
//!
//! # Linearization rule
//!
//! Anka64 chooses: revocation wins the race.
//!
//!   Revoke(O, g+1) ≺ Commit(R) ∧ R.object = O ⟹ ¬Effects(R)
//!
//! # Concurrent noninterference (N8c)
//!
//!   stale-at-commit(R) ⟹ S_race = S_revoke-only + fault metadata
//!
//! Object state may differ because the revocation itself happened.
//! The comparison is not state_after = state_before; it is:
//! the denied transaction added nothing beyond the revocation's
//! own legitimate effects.
//!
//! # Deterministic event scheduler
//!
//! Instead of host threads, the fabric uses a deterministic event
//! list.  Tests inject revocation at precise transaction phases,
//! exhaustively covering every interesting interleaving.

use crate::protection::{
    Capability, FaultReason, FaultRecord, ObjectTable, Perm,
};

// ───────────────────────────────────────────────────────────────────
// Transaction state machine
// ───────────────────────────────────────────────────────────────────

/// Transaction phase.
///
/// ```text
/// Requested → Authorized → Prepared → Committed
///     ↓            ↓           ↓
///   Faulted     Faulted     Faulted
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxPhase {
    /// Agent submitted the request.  No checks yet.
    Requested,
    /// Generation was valid at authorization time.
    Authorized,
    /// Translation complete, access ready to commit.
    Prepared,
    /// Data written to memory.  Terminal state.
    Committed,
    /// Transaction denied.  Terminal state.
    Faulted,
}

impl TxPhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, TxPhase::Committed | TxPhase::Faulted)
    }
}

/// A memory transaction with explicit lifecycle phases.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: u32,
    pub agent: u32,
    pub object_id: u32,
    /// Generation captured at authorization time.
    auth_generation: Option<u32>,
    pub offset: u32,
    pub data: Vec<u8>,
    pub phase: TxPhase,
    pub fault: Option<FaultRecord>,
}

impl Transaction {
    pub fn new(id: u32, agent: u32, object_id: u32, offset: u32, data: Vec<u8>) -> Self {
        Self {
            id,
            agent,
            object_id,
            auth_generation: None,
            offset,
            data,
            phase: TxPhase::Requested,
            fault: None,
        }
    }

    pub fn auth_generation(&self) -> Option<u32> {
        self.auth_generation
    }
}

// ───────────────────────────────────────────────────────────────────
// Events
// ───────────────────────────────────────────────────────────────────

/// A deterministic event in the concurrent fabric.
#[derive(Debug, Clone)]
pub enum Event {
    /// Advance the given transaction to its next phase.
    Advance(u32),
    /// Revoke an object (bump generation).
    Revoke(u32),
}

// ───────────────────────────────────────────────────────────────────
// Concurrent fabric
// ───────────────────────────────────────────────────────────────────

/// The concurrent protection fabric.
///
/// Owns the object table and a flat memory region.
/// Transactions proceed through explicit phases.
/// Between any two phases, external events (revocation) can occur.
pub struct ConcurrentFabric {
    pub objects: ObjectTable,
    memory: Vec<u8>,
    pub fault_log: Vec<FaultRecord>,
}

impl ConcurrentFabric {
    pub fn new(mem_size: usize) -> Self {
        Self {
            objects: ObjectTable::new(),
            memory: vec![0u8; mem_size],
            fault_log: Vec::new(),
        }
    }

    /// Read memory directly (for test verification).
    pub fn read(&self, addr: u32, len: u32) -> &[u8] {
        let a = addr as usize;
        let l = len as usize;
        &self.memory[a..a + l]
    }

    /// Advance a transaction to its next phase.
    ///
    /// Returns true if the transaction advanced (or was already terminal).
    pub fn advance(&mut self, tx: &mut Transaction, cap: &Capability) -> bool {
        match tx.phase {
            TxPhase::Requested => self.phase_authorize(tx, cap),
            TxPhase::Authorized => self.phase_prepare(tx),
            TxPhase::Prepared => self.phase_commit(tx, cap),
            TxPhase::Committed | TxPhase::Faulted => true,
        }
    }

    /// Phase 1: Authorize.
    ///
    /// Check that the capability is valid and covers the request.
    /// Capture the generation for commit-time revalidation.
    fn phase_authorize(&mut self, tx: &mut Transaction, cap: &Capability) -> bool {
        let addr = cap.base().wrapping_add(tx.offset);
        let size = tx.data.len() as u32;

        // Validate capability against object table
        if !self.objects.validate(cap) {
            tx.phase = TxPhase::Faulted;
            let record = FaultRecord::new(addr, size, Perm::WRITE, FaultReason::StaleGeneration);
            self.fault_log.push(record.clone());
            tx.fault = Some(record);
            return true;
        }

        // Check range and permissions
        if !cap.permits(addr, size, Perm::WRITE) {
            tx.phase = TxPhase::Faulted;
            let record = FaultRecord::new(addr, size, Perm::WRITE, FaultReason::NoCapability);
            self.fault_log.push(record.clone());
            tx.fault = Some(record);
            return true;
        }

        // Authorized — capture generation
        tx.auth_generation = Some(cap.generation());
        tx.phase = TxPhase::Authorized;
        true
    }

    /// Phase 2: Prepare.
    ///
    /// Translation (trivial in the current model: identity mapping).
    fn phase_prepare(&mut self, tx: &mut Transaction) -> bool {
        tx.phase = TxPhase::Prepared;
        true
    }

    /// Phase 3: Commit.
    ///
    /// **Revalidate generation** before writing to memory.
    /// This is the linearization point: if the object was revoked
    /// between authorization and now, the transaction faults.
    fn phase_commit(&mut self, tx: &mut Transaction, cap: &Capability) -> bool {
        let addr = cap.base().wrapping_add(tx.offset);
        let size = tx.data.len() as u32;

        // COMMIT-TIME REVALIDATION
        //
        // The generation we captured at authorization time must
        // still match the object's current generation.  If someone
        // revoked the object in between, we fault.
        if !self.objects.validate(cap) {
            tx.phase = TxPhase::Faulted;
            let record = FaultRecord::new(addr, size, Perm::WRITE, FaultReason::StaleGeneration);
            self.fault_log.push(record.clone());
            tx.fault = Some(record);
            return true;
        }

        // Generation still valid — commit the write
        let base = addr as usize;
        for (i, &byte) in tx.data.iter().enumerate() {
            self.memory[base + i] = byte;
        }
        tx.phase = TxPhase::Committed;
        true
    }

    /// Run a sequence of events against a set of transactions.
    ///
    /// Each transaction is identified by index into the `txs` slice.
    /// The `caps` slice provides the capability for each transaction
    /// (parallel indexing).
    pub fn run_schedule(
        &mut self,
        txs: &mut [Transaction],
        caps: &[Capability],
        events: &[Event],
    ) {
        for event in events {
            match event {
                Event::Advance(tx_id) => {
                    let idx = *tx_id as usize;
                    let cap = &caps[idx].clone();
                    self.advance(&mut txs[idx], cap);
                }
                Event::Revoke(obj_id) => {
                    self.objects.revoke(*obj_id);
                }
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Tests — exhaustive interleaving suite
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    const SENTINEL: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

    /// Set up a fabric with one object and return (fabric, object_id, capability).
    fn setup() -> (ConcurrentFabric, u32, Capability) {
        let mut fabric = ConcurrentFabric::new(0x10000);

        // Write sentinel so we can detect unauthorized writes
        for (i, &b) in SENTINEL.iter().enumerate() {
            fabric.memory[0x1000 + i] = b;
        }

        let obj = fabric.objects.alloc("buffer", 0x1000, 0x100);
        let cap = fabric.objects.make_cap(obj, Perm::RW).unwrap();
        (fabric, obj, cap)
    }

    fn mem_at(fabric: &ConcurrentFabric, addr: u32) -> [u8; 4] {
        let s = fabric.read(addr, 4);
        [s[0], s[1], s[2], s[3]]
    }

    // ═══════════════════════════════════════════════════════════
    // Sequential baseline
    // ═══════════════════════════════════════════════════════════

    /// No revocation — transaction commits normally.
    #[test]
    fn sequential_commit() {
        let (mut fabric, _obj, cap) = setup();
        let mut tx = Transaction::new(0, 0, 0, 0, PAYLOAD.to_vec());

        fabric.advance(&mut tx, &cap); // Authorize
        assert_eq!(tx.phase, TxPhase::Authorized);

        fabric.advance(&mut tx, &cap); // Prepare
        assert_eq!(tx.phase, TxPhase::Prepared);

        fabric.advance(&mut tx, &cap); // Commit
        assert_eq!(tx.phase, TxPhase::Committed);
        assert_eq!(mem_at(&fabric, 0x1000), PAYLOAD);
    }

    /// Revocation before authorization — transaction never starts.
    #[test]
    fn revoke_before_authorize() {
        let (mut fabric, obj, cap) = setup();
        let mut tx = Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec());

        fabric.objects.revoke(obj);

        fabric.advance(&mut tx, &cap); // Authorize → Faulted
        assert_eq!(tx.phase, TxPhase::Faulted);
        assert_eq!(tx.fault.as_ref().unwrap().reason, FaultReason::StaleGeneration);
        assert_eq!(mem_at(&fabric, 0x1000), SENTINEL, "memory changed on denied tx");
    }

    // ═══════════════════════════════════════════════════════════
    // The critical race: revocation between authorize and commit
    // ═══════════════════════════════════════════════════════════

    /// Revoke after authorize, before commit.
    ///
    /// This is the core concurrent scenario.  The transaction was
    /// authorized at generation g, but the object was revoked to
    /// g+1 before commit.  Commit-time revalidation catches it.
    #[test]
    fn revoke_between_authorize_and_commit() {
        let (mut fabric, obj, cap) = setup();
        let mut tx = Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec());

        fabric.advance(&mut tx, &cap); // Authorize (gen 0 ✓)
        assert_eq!(tx.phase, TxPhase::Authorized);
        assert_eq!(tx.auth_generation(), Some(0));

        // REVOCATION — another agent revokes the object
        fabric.objects.revoke(obj);

        fabric.advance(&mut tx, &cap); // Prepare
        assert_eq!(tx.phase, TxPhase::Prepared);

        fabric.advance(&mut tx, &cap); // Commit → Faulted!
        assert_eq!(tx.phase, TxPhase::Faulted);
        assert_eq!(tx.fault.as_ref().unwrap().reason, FaultReason::StaleGeneration);

        // NONINTERFERENCE: memory is unchanged
        assert_eq!(mem_at(&fabric, 0x1000), SENTINEL,
            "stale-at-commit transaction corrupted memory");
    }

    /// Revoke after authorize, before prepare.
    #[test]
    fn revoke_between_authorize_and_prepare() {
        let (mut fabric, obj, cap) = setup();
        let mut tx = Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec());

        fabric.advance(&mut tx, &cap); // Authorize
        assert_eq!(tx.phase, TxPhase::Authorized);

        fabric.objects.revoke(obj);

        fabric.advance(&mut tx, &cap); // Prepare (translation — no gen check here)
        assert_eq!(tx.phase, TxPhase::Prepared);

        fabric.advance(&mut tx, &cap); // Commit → Faulted
        assert_eq!(tx.phase, TxPhase::Faulted);
        assert_eq!(mem_at(&fabric, 0x1000), SENTINEL);
    }

    // ═══════════════════════════════════════════════════════════
    // Two-agent interleaving
    // ═══════════════════════════════════════════════════════════

    /// Two transactions to the same object.  One authorized before
    /// revocation (stale at commit), one authorized after re-creation
    /// (valid).  Only the valid one commits.
    #[test]
    fn two_agents_one_stale_one_valid() {
        let mut fabric = ConcurrentFabric::new(0x10000);

        // Sentinel
        for (i, &b) in SENTINEL.iter().enumerate() {
            fabric.memory[0x1000 + i] = b;
        }

        let obj = fabric.objects.alloc("buffer", 0x1000, 0x100);
        let cap_old = fabric.objects.make_cap(obj, Perm::RW).unwrap();

        // Agent 0: authorized at gen 0
        let mut tx0 = Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec());
        fabric.advance(&mut tx0, &cap_old);
        assert_eq!(tx0.phase, TxPhase::Authorized);

        // Revoke
        fabric.objects.revoke(obj);

        // Re-create at gen 1 (simulate object recycling)
        fabric.objects.entries[obj as usize].state =
            crate::protection::ObjectState::Active;
        let cap_new = fabric.objects.make_cap(obj, Perm::RW).unwrap();

        // Agent 1: authorized at gen 1
        let new_data = [0x11, 0x22, 0x33, 0x44];
        let mut tx1 = Transaction::new(1, 1, obj, 0, new_data.to_vec());
        fabric.advance(&mut tx1, &cap_new);
        assert_eq!(tx1.phase, TxPhase::Authorized);

        // Both prepare
        fabric.advance(&mut tx0, &cap_old);
        fabric.advance(&mut tx1, &cap_new);

        // Agent 0 tries to commit — stale, denied
        fabric.advance(&mut tx0, &cap_old);
        assert_eq!(tx0.phase, TxPhase::Faulted);

        // Agent 1 commits — valid
        fabric.advance(&mut tx1, &cap_new);
        assert_eq!(tx1.phase, TxPhase::Committed);

        // Memory contains agent 1's data, not agent 0's
        assert_eq!(mem_at(&fabric, 0x1000), new_data);
    }

    // ═══════════════════════════════════════════════════════════
    // Event scheduler interleavings
    // ═══════════════════════════════════════════════════════════

    /// Exercise the event scheduler with the critical race.
    #[test]
    fn scheduler_authorize_revoke_commit() {
        let (mut fabric, obj, cap) = setup();
        let mut txs = [Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec())];
        let caps = [cap];

        let events = [
            Event::Advance(0),  // Authorize
            Event::Revoke(obj), // Revoke!
            Event::Advance(0),  // Prepare
            Event::Advance(0),  // Commit → Faulted
        ];

        fabric.run_schedule(&mut txs, &caps, &events);

        assert_eq!(txs[0].phase, TxPhase::Faulted);
        assert_eq!(mem_at(&fabric, 0x1000), SENTINEL);
    }

    /// No revocation through the scheduler — normal commit.
    #[test]
    fn scheduler_no_revocation() {
        let (mut fabric, obj, cap) = setup();
        let mut txs = [Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec())];
        let caps = [cap];

        let events = [
            Event::Advance(0), // Authorize
            Event::Advance(0), // Prepare
            Event::Advance(0), // Commit
        ];

        fabric.run_schedule(&mut txs, &caps, &events);

        assert_eq!(txs[0].phase, TxPhase::Committed);
        assert_eq!(mem_at(&fabric, 0x1000), PAYLOAD);
    }

    // ═══════════════════════════════════════════════════════════
    // Exhaustive phase × revocation matrix
    // ═══════════════════════════════════════════════════════════

    /// Exhaustively test revocation at every possible phase boundary.
    ///
    /// For a 3-phase transaction (authorize, prepare, commit), there
    /// are 4 possible revocation points:
    ///   - before authorize
    ///   - between authorize and prepare
    ///   - between prepare and commit
    ///   - after commit
    ///
    /// Plus "no revocation" = 5 schedules.
    #[test]
    fn exhaustive_revocation_timing() {
        struct Case {
            name: &'static str,
            revoke_after_step: Option<usize>,
            expect_phase: TxPhase,
            expect_memory: [u8; 4],
        }

        let cases = [
            Case {
                name: "no revocation",
                revoke_after_step: None,
                expect_phase: TxPhase::Committed,
                expect_memory: PAYLOAD,
            },
            Case {
                name: "revoke before authorize",
                revoke_after_step: Some(0),
                expect_phase: TxPhase::Faulted,
                expect_memory: SENTINEL,
            },
            Case {
                name: "revoke between authorize and prepare",
                revoke_after_step: Some(1),
                expect_phase: TxPhase::Faulted,
                expect_memory: SENTINEL,
            },
            Case {
                name: "revoke between prepare and commit",
                revoke_after_step: Some(2),
                expect_phase: TxPhase::Faulted,
                expect_memory: SENTINEL,
            },
            Case {
                name: "revoke after commit",
                revoke_after_step: Some(3),
                expect_phase: TxPhase::Committed,
                expect_memory: PAYLOAD,
            },
        ];

        for case in &cases {
            let (mut fabric, obj, cap) = setup();
            let mut tx = Transaction::new(0, 0, obj, 0, PAYLOAD.to_vec());

            let steps: Vec<Box<dyn Fn(&mut ConcurrentFabric, &mut Transaction, &Capability, u32)>> = vec![
                Box::new(|f, t, c, _| { f.advance(t, c); }),
                Box::new(|f, t, c, _| { f.advance(t, c); }),
                Box::new(|f, t, c, _| { f.advance(t, c); }),
            ];

            for (i, step) in steps.iter().enumerate() {
                if case.revoke_after_step == Some(i) {
                    fabric.objects.revoke(obj);
                }
                step(&mut fabric, &mut tx, &cap, obj);
            }
            if case.revoke_after_step == Some(3) {
                fabric.objects.revoke(obj);
            }

            assert_eq!(tx.phase, case.expect_phase,
                "case '{}': expected {:?}, got {:?}", case.name, case.expect_phase, tx.phase);
            assert_eq!(mem_at(&fabric, 0x1000), case.expect_memory,
                "case '{}': memory mismatch", case.name);

            eprintln!("  ✓ {}: {:?}, mem={:02X?}",
                case.name, tx.phase, mem_at(&fabric, 0x1000));
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Concurrent noninterference (N8c)
    // ═══════════════════════════════════════════════════════════

    /// The concurrent analogue of N8.
    ///
    /// S_race = S_revoke-only + fault metadata.
    ///
    /// Run two scenarios:
    ///   A: revoke only (no transaction attempted)
    ///   B: revoke + stale transaction attempt
    ///
    /// Memory and object state must be identical.
    /// The only difference is the fault log.
    #[test]
    fn concurrent_noninterference_n8c() {
        // Scenario A: revoke only
        let (mut fabric_a, obj_a, _cap_a) = setup();
        fabric_a.objects.revoke(obj_a);
        let mem_a = mem_at(&fabric_a, 0x1000);
        let faults_a = fabric_a.fault_log.len();

        // Scenario B: authorize → revoke → attempt commit
        let (mut fabric_b, obj_b, cap_b) = setup();
        let mut tx = Transaction::new(0, 0, obj_b, 0, PAYLOAD.to_vec());

        fabric_b.advance(&mut tx, &cap_b); // Authorize at gen 0
        fabric_b.objects.revoke(obj_b);     // Revoke → gen 1
        fabric_b.advance(&mut tx, &cap_b); // Prepare
        fabric_b.advance(&mut tx, &cap_b); // Commit → Faulted

        let mem_b = mem_at(&fabric_b, 0x1000);
        let faults_b = fabric_b.fault_log.len();

        // Memory identical (the denied tx added nothing)
        assert_eq!(mem_a, mem_b,
            "N8c: stale transaction altered memory beyond revocation effects");

        // Object generation identical
        assert_eq!(
            fabric_a.objects.entries[obj_a as usize].generation,
            fabric_b.objects.entries[obj_b as usize].generation,
            "N8c: object generation diverged");

        // The only difference: scenario B has one fault record
        assert_eq!(faults_a, 0);
        assert_eq!(faults_b, 1);
        assert_eq!(fabric_b.fault_log[0].reason, FaultReason::StaleGeneration);

        eprintln!("N8c: S_race = S_revoke-only + fault metadata ✓");
        eprintln!("  memory:     {:02X?} == {:02X?}", mem_a, mem_b);
        eprintln!("  generation: {} == {}",
            fabric_a.objects.entries[obj_a as usize].generation,
            fabric_b.objects.entries[obj_b as usize].generation);
        eprintln!("  faults:     {} vs {} (fault metadata only)", faults_a, faults_b);
    }
}

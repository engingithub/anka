//! Phase 9.1b — Block Storage and Controller
//!
//! Asynchronous block device with two request slots, fixed
//! completion latency, and bounded completion queue.  READ-only
//! in this phase.
//!
//! No Fabric DMA, no interrupt posting, no kernel coupling.
//! The controller's universe is:
//!   BlockStorage + two request slots + latency + completion ordering.
//!
//! Formal basis: anka_block_device.kleis
//!   SLOT-1..SLOT-4: F + O_wait + O_dma + C = N_slots
//!   COMP-1..COMP-5: completion ordering and consumption
//!   GEN-1..GEN-4:   generation-qualified request identity
//!   LEVEL-1:        L_dev ≡ (C > 0)
//!
//! Kleis ↔ Rust mapping:
//!   F       ↔ SlotState::Free
//!   O_wait  ↔ SlotState::Waiting
//!   O_dma   ↔ SlotState::DmaReady   (9.1b: no-DMA shortcut)
//!   C       ↔ SlotState::Completed
//!   L_dev   ↔ completion_count() > 0

use std::collections::VecDeque;
use super::state::RequesterKey;

/// Number of request slots.  Matches the formal two-slot model.
const NUM_SLOTS: usize = 2;

// ───────────────────────────────────────────────────────────────────
// Block storage
// ───────────────────────────────────────────────────────────────────

/// Deterministic in-memory backing store.
///
/// A fixed-size array of equal-sized blocks.  No caching, no host
/// filesystem, no scatter/gather.  Pre-populated for testing.
#[derive(Debug)]
pub struct BlockStorage {
    data: Vec<u8>,
    block_size: u64,
    num_blocks: u64,
}

impl BlockStorage {
    pub fn new(num_blocks: u64, block_size: u64) -> Self {
        Self {
            data: vec![0u8; (num_blocks * block_size) as usize],
            block_size,
            num_blocks,
        }
    }

    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    pub fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    /// Read one block.  Returns None if block_number is out of range.
    pub fn read_block(&self, block_number: u64) -> Option<Vec<u8>> {
        if block_number >= self.num_blocks {
            return None;
        }
        let offset = (block_number * self.block_size) as usize;
        let end = offset + self.block_size as usize;
        Some(self.data[offset..end].to_vec())
    }

    /// Write a complete block (for test setup, not guest-accessible).
    pub fn write_block(&mut self, block_number: u64, data: &[u8]) -> bool {
        if block_number >= self.num_blocks || data.len() != self.block_size as usize {
            return false;
        }
        let offset = (block_number * self.block_size) as usize;
        self.data[offset..offset + data.len()].copy_from_slice(data);
        true
    }
}

// ───────────────────────────────────────────────────────────────────
// Request / completion / handle types
// ───────────────────────────────────────────────────────────────────

/// Opaque handle identifying a specific request submission.
///
/// The generation field matches the slot's generation at acceptance
/// time.  After the slot cycles (C → F), the generation increments,
/// making stale handles distinguishable from current ones.
///
/// Formal basis: anka_block_device.kleis GEN-1..GEN-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHandle {
    pub slot: u8,
    pub generation: u32,
}

/// A block read request.
#[derive(Debug, Clone)]
pub struct BlockRequest {
    pub block_number: u64,
    pub requester: RequesterKey,
}

/// A completed block operation.
///
/// Carries generation-qualified identity for both the request slot
/// and the requester, so the kernel can detect stale completions.
#[derive(Debug, Clone)]
pub struct BlockCompletion {
    pub handle: RequestHandle,
    pub requester: RequesterKey,
    pub block_number: u64,
    pub data: Vec<u8>,
}

/// Result of attempting to submit a request.
#[derive(Debug)]
pub enum SubmitResult {
    /// Request accepted; handle identifies this submission.
    Accepted(RequestHandle),
    /// Both slots occupied — no capacity.
    DeviceBusy,
    /// Block number out of range.
    InvalidBlock,
}

// ───────────────────────────────────────────────────────────────────
// Slot lifecycle
// ───────────────────────────────────────────────────────────────────

/// Per-slot lifecycle state — the single source of truth.
///
/// The completion_order queue identifies *which* completed slots
/// to drain and in what order, but does not duplicate completion
/// data.  A queue entry asserts "this slot must be Completed";
/// consuming it performs C → F and increments the slot's generation.
///
/// Conservation: F + O_wait + O_dma + C = NUM_SLOTS.
#[derive(Debug, Clone)]
enum SlotState {
    Free,
    Waiting {
        request: BlockRequest,
        remaining_ticks: u32,
    },
    /// Latency expired, ready for DMA.
    ///
    /// In Phase 9.1b (no DMA), this state is transitional:
    /// tick() immediately advances DmaReady → Completed by reading
    /// from BlockStorage.  Phase 9.1c will give this state a real
    /// DMA transaction to wait for.
    DmaReady {
        request: BlockRequest,
    },
    Completed {
        completion: BlockCompletion,
    },
}

// ───────────────────────────────────────────────────────────────────
// Block controller
// ───────────────────────────────────────────────────────────────────

/// Two-slot block controller with fixed completion latency.
///
/// Manages the request lifecycle and completion queue.
/// Does not perform DMA (Phase 9.1c), does not post interrupts
/// (Phase 9.1d), does not know about processes or kernels.
///
/// Formal basis: anka_block_device.kleis
///   SLOT-1..SLOT-4:  bounded slot conservation
///   COMP-1..COMP-5:  completion queue ordering
///   GEN-1..GEN-4:    generation-qualified handles
///   LEVEL-1:         L_dev ≡ (C > 0), derived
pub struct BlockController {
    slots: [SlotState; NUM_SLOTS],
    slot_generations: [u32; NUM_SLOTS],
    /// Completion ordering — slot indices, not completion data.
    /// An entry asserts "this slot is Completed."
    completion_order: VecDeque<u8>,
    storage: BlockStorage,
    latency: u32,
}

impl BlockController {
    pub fn new(storage: BlockStorage, latency: u32) -> Self {
        Self {
            slots: std::array::from_fn(|_| SlotState::Free),
            slot_generations: [0; NUM_SLOTS],
            completion_order: VecDeque::new(),
            storage,
            latency,
        }
    }

    /// Submit a read request.
    ///
    /// Returns `Accepted(handle)` if a free slot exists,
    /// `DeviceBusy` if both slots are occupied,
    /// `InvalidBlock` if block_number is out of range.
    ///
    /// Formal: F → O_wait.
    pub fn submit(&mut self, request: BlockRequest) -> SubmitResult {
        if request.block_number >= self.storage.num_blocks() {
            return SubmitResult::InvalidBlock;
        }

        let slot_idx = self.slots.iter()
            .position(|s| matches!(s, SlotState::Free));

        match slot_idx {
            None => SubmitResult::DeviceBusy,
            Some(idx) => {
                let handle = RequestHandle {
                    slot: idx as u8,
                    generation: self.slot_generations[idx],
                };
                let remaining = self.latency.max(1);
                self.slots[idx] = SlotState::Waiting {
                    request,
                    remaining_ticks: remaining,
                };
                self.assert_conservation();
                SubmitResult::Accepted(handle)
            }
        }
    }

    /// Advance the controller by one machine tick.
    ///
    /// Latency convention: submit at boundary t → DmaReady on
    /// tick L.  Latency 0 is treated as "next tick" (= latency 1).
    ///
    /// Two-phase processing per tick:
    ///   1. Waiting slots: decrement remaining; if zero → DmaReady.
    ///   2. DmaReady slots: read from storage → Completed.
    ///      (Phase 9.1b: no-DMA shortcut; 9.1c adds real DMA.)
    pub fn tick(&mut self) {
        // Phase 1: Waiting → advance or → DmaReady.
        for i in 0..NUM_SLOTS {
            if let SlotState::Waiting { remaining_ticks, .. } = &mut self.slots[i] {
                *remaining_ticks -= 1;
                if *remaining_ticks == 0 {
                    let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                    if let SlotState::Waiting { request, .. } = state {
                        self.slots[i] = SlotState::DmaReady { request };
                    }
                }
            }
        }

        // Phase 2: DmaReady → Completed (9.1b: no-DMA shortcut).
        for i in 0..NUM_SLOTS {
            if matches!(self.slots[i], SlotState::DmaReady { .. }) {
                let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                if let SlotState::DmaReady { request } = state {
                    let data = self.storage.read_block(request.block_number)
                        .unwrap_or_default();
                    let completion = BlockCompletion {
                        handle: RequestHandle {
                            slot: i as u8,
                            generation: self.slot_generations[i],
                        },
                        requester: request.requester,
                        block_number: request.block_number,
                        data,
                    };
                    self.slots[i] = SlotState::Completed { completion };
                    self.completion_order.push_back(i as u8);
                }
            }
        }

        self.assert_conservation();
    }

    /// Consume the oldest completed request.
    ///
    /// Transitions the slot from Completed → Free and increments
    /// the slot's generation, invalidating any stale handles.
    ///
    /// Formal: C → F, generation++.
    pub fn consume_completion(&mut self) -> Option<BlockCompletion> {
        let slot_idx = self.completion_order.pop_front()? as usize;
        let state = std::mem::replace(&mut self.slots[slot_idx], SlotState::Free);
        match state {
            SlotState::Completed { completion } => {
                self.slot_generations[slot_idx] += 1;
                self.assert_conservation();
                Some(completion)
            }
            _ => {
                self.slots[slot_idx] = state;
                None
            }
        }
    }

    /// True if the completion queue is non-empty.
    ///
    /// This is the level-triggered interrupt source condition:
    ///   L_dev ≡ (C > 0).
    /// Derived from actual slot state, never stored independently.
    ///
    /// Formal basis: anka_block_device.kleis LEVEL-1.
    pub fn requires_attention(&self) -> bool {
        self.completion_count() > 0
    }

    /// Number of slots currently in Completed state.
    pub fn completion_count(&self) -> usize {
        self.slots.iter()
            .filter(|s| matches!(s, SlotState::Completed { .. }))
            .count()
    }

    /// Number of slots currently Free.
    pub fn free_slot_count(&self) -> usize {
        self.slots.iter()
            .filter(|s| matches!(s, SlotState::Free))
            .count()
    }

    /// Current generation for a slot.
    pub fn slot_generation(&self, slot: u8) -> u32 {
        self.slot_generations[slot as usize]
    }

    /// Structural conservation invariant: F + O_wait + O_dma + C = NUM_SLOTS.
    fn assert_conservation(&self) {
        let f = self.slots.iter().filter(|s| matches!(s, SlotState::Free)).count();
        let ow = self.slots.iter().filter(|s| matches!(s, SlotState::Waiting { .. })).count();
        let od = self.slots.iter().filter(|s| matches!(s, SlotState::DmaReady { .. })).count();
        let c = self.slots.iter().filter(|s| matches!(s, SlotState::Completed { .. })).count();
        debug_assert_eq!(
            f + ow + od + c, NUM_SLOTS,
            "SLOT conservation violated: F={} + O_wait={} + O_dma={} + C={} ≠ {}",
            f, ow, od, c, NUM_SLOTS,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 4 blocks × 512 bytes, each with a distinct fill pattern.
    fn test_storage() -> BlockStorage {
        let mut s = BlockStorage::new(4, 512);
        let b0: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        s.write_block(0, &b0);
        s.write_block(1, &vec![0xAA; 512]);
        s.write_block(2, &vec![0xBB; 512]);
        s.write_block(3, &vec![0xCC; 512]);
        s
    }

    fn rk(slot: u32, generation: u32) -> RequesterKey {
        RequesterKey { slot, generation }
    }

    // ─── Capacity / backpressure ──────────────────────────────────

    /// Two accepts exhaust capacity; third returns DeviceBusy.
    ///
    /// Formal: SLOT-1 (F=0 ⇒ no more accepts).
    #[test]
    fn p91b_two_slots_exhausted() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        let r1 = ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        assert!(matches!(r1, SubmitResult::Accepted(_)));
        let r2 = ctrl.submit(BlockRequest { block_number: 1, requester: rk(1, 0) });
        assert!(matches!(r2, SubmitResult::Accepted(_)));
        let r3 = ctrl.submit(BlockRequest { block_number: 2, requester: rk(2, 0) });
        assert!(matches!(r3, SubmitResult::DeviceBusy));
    }

    // ─── Latency ──────────────────────────────────────────────────

    /// Exactly L ticks produce completion for several latency values.
    ///
    /// Formal: O_wait → O_dma on tick L.
    #[test]
    fn p91b_latency_exact() {
        for latency in [1u32, 2, 3, 5] {
            let mut ctrl = BlockController::new(test_storage(), latency);
            ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });

            for tick_num in 1..latency {
                ctrl.tick();
                assert_eq!(ctrl.completion_count(), 0,
                    "latency={}: premature completion on tick {}", latency, tick_num);
            }
            ctrl.tick();
            assert_eq!(ctrl.completion_count(), 1,
                "latency={}: expected completion on tick {}", latency, latency);
        }
    }

    /// Latency 0 means "next tick" (equivalent to latency 1).
    #[test]
    fn p91b_latency_zero_next_tick() {
        let mut ctrl = BlockController::new(test_storage(), 0);
        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        assert_eq!(ctrl.completion_count(), 0, "not completed at submission");
        ctrl.tick();
        assert_eq!(ctrl.completion_count(), 1, "completed on first tick");
    }

    // ─── Slot lifecycle ───────────────────────────────────────────

    /// Completed slots remain unavailable until consumed.
    ///
    /// Formal: C ≠ F — a completed slot does not accept new requests.
    #[test]
    fn p91b_completed_blocks_slot() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        ctrl.submit(BlockRequest { block_number: 1, requester: rk(1, 0) });
        ctrl.tick();

        assert_eq!(ctrl.completion_count(), 2);
        assert!(matches!(
            ctrl.submit(BlockRequest { block_number: 2, requester: rk(2, 0) }),
            SubmitResult::DeviceBusy,
        ), "both slots completed, no free capacity");

        ctrl.consume_completion();
        assert!(matches!(
            ctrl.submit(BlockRequest { block_number: 2, requester: rk(2, 0) }),
            SubmitResult::Accepted(_),
        ), "one slot freed by consume");
    }

    // ─── Generation ───────────────────────────────────────────────

    /// Consuming a completion increments the slot's generation.
    ///
    /// Formal: C → F transitions increment gen (GEN-1).
    #[test]
    fn p91b_consume_increments_generation() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        let gen_before_0 = ctrl.slot_generation(0);

        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        ctrl.tick();
        let comp = ctrl.consume_completion().unwrap();
        let consumed_slot = comp.handle.slot;

        assert_eq!(
            ctrl.slot_generation(consumed_slot),
            gen_before_0 + 1,
            "generation must increment on C→F",
        );
    }

    /// Stale {slot, generation} does not match after slot recycling.
    ///
    /// Formal: GEN-3 — stale request handle ≢ recycled slot.
    #[test]
    fn p91b_stale_handle_no_match() {
        let mut ctrl = BlockController::new(test_storage(), 1);

        let SubmitResult::Accepted(h1) = ctrl.submit(
            BlockRequest { block_number: 0, requester: rk(0, 0) }
        ) else { panic!("first accept must succeed") };
        ctrl.tick();
        ctrl.consume_completion().unwrap();

        let SubmitResult::Accepted(h2) = ctrl.submit(
            BlockRequest { block_number: 1, requester: rk(0, 0) }
        ) else { panic!("second accept must succeed after consume") };

        assert_eq!(h1.slot, h2.slot, "same physical slot reused");
        assert_ne!(h1.generation, h2.generation, "generation must differ");
        assert_eq!(h2.generation, h1.generation + 1);
    }

    // ─── Multiple completions ─────────────────────────────────────

    /// Two completions coexist; requires_attention tracks count.
    ///
    /// Formal: COMP-2 (both slots may be C simultaneously).
    #[test]
    fn p91b_two_completions_coexist() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        ctrl.submit(BlockRequest { block_number: 1, requester: rk(1, 0) });
        ctrl.tick();

        assert_eq!(ctrl.completion_count(), 2);
        assert!(ctrl.requires_attention());

        let c1 = ctrl.consume_completion().unwrap();
        assert_eq!(ctrl.completion_count(), 1);
        assert!(ctrl.requires_attention());

        let c2 = ctrl.consume_completion().unwrap();
        assert_eq!(ctrl.completion_count(), 0);
        assert!(!ctrl.requires_attention());

        assert_ne!(c1.handle.slot, c2.handle.slot);
    }

    // ─── Derived attention ────────────────────────────────────────

    /// requires_attention() is derived from completion state,
    /// not stored independently.
    ///
    /// Formal: LEVEL-1 — L_dev ≡ (C > 0).
    #[test]
    fn p91b_requires_attention_derived() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        assert!(!ctrl.requires_attention(), "empty controller");

        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        assert!(!ctrl.requires_attention(), "waiting, not completed");

        ctrl.tick();
        assert!(ctrl.requires_attention(), "completed");

        ctrl.consume_completion();
        assert!(!ctrl.requires_attention(), "consumed");
    }

    // ─── Conservation ─────────────────────────────────────────────

    /// F + O_wait + O_dma + C = 2 throughout full lifecycle.
    ///
    /// Formal: SLOT-1..SLOT-4 conservation invariant.
    #[test]
    fn p91b_conservation_invariant() {
        let mut ctrl = BlockController::new(test_storage(), 3);

        // [Free, Free]: F=2
        assert_eq!(ctrl.free_slot_count(), 2);

        // Submit one: [Waiting, Free]: F=1, O_wait=1
        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        assert_eq!(ctrl.free_slot_count(), 1);

        // Submit two: [Waiting, Waiting]: O_wait=2
        ctrl.submit(BlockRequest { block_number: 1, requester: rk(1, 0) });
        assert_eq!(ctrl.free_slot_count(), 0);

        // Tick through latency
        for _ in 0..3 {
            ctrl.tick();
        }
        // [Completed, Completed]: C=2
        assert_eq!(ctrl.completion_count(), 2);
        assert_eq!(ctrl.free_slot_count(), 0);

        // Consume both: [Free, Free]: F=2
        ctrl.consume_completion();
        ctrl.consume_completion();
        assert_eq!(ctrl.free_slot_count(), 2);
    }

    // ─── Data correctness ─────────────────────────────────────────

    /// Read data matches storage content.
    #[test]
    fn p91b_read_data_correct() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        ctrl.submit(BlockRequest { block_number: 1, requester: rk(0, 0) });
        ctrl.tick();
        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.data, vec![0xAA; 512]);
        assert_eq!(comp.block_number, 1);
    }

    /// Invalid block number rejected without consuming a slot.
    #[test]
    fn p91b_invalid_block_rejected() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        let r = ctrl.submit(BlockRequest { block_number: 99, requester: rk(0, 0) });
        assert!(matches!(r, SubmitResult::InvalidBlock));
        assert_eq!(ctrl.free_slot_count(), 2, "no slot consumed");
    }

    // ─── Requester identity ───────────────────────────────────────

    /// Completion carries the requester identity from submission.
    ///
    /// Formal: GEN-REQ-1 — completion.requester = submitted requester.
    #[test]
    fn p91b_requester_identity_carried() {
        let key = rk(7, 42);
        let mut ctrl = BlockController::new(test_storage(), 1);
        ctrl.submit(BlockRequest { block_number: 0, requester: key });
        ctrl.tick();
        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.requester, key);
    }

    /// Completion FIFO ordering: first submitted → first completed.
    #[test]
    fn p91b_completion_fifo_order() {
        let mut ctrl = BlockController::new(test_storage(), 1);
        ctrl.submit(BlockRequest { block_number: 0, requester: rk(0, 0) });
        ctrl.submit(BlockRequest { block_number: 1, requester: rk(1, 0) });
        ctrl.tick();

        let c1 = ctrl.consume_completion().unwrap();
        let c2 = ctrl.consume_completion().unwrap();
        assert_eq!(c1.handle.slot, 0, "slot 0 submitted first, completed first");
        assert_eq!(c2.handle.slot, 1);
    }

    /// Full lifecycle: submit → tick → complete → consume → resubmit.
    ///
    /// Exercises every formal transition: F→O_wait→O_dma→C→F.
    #[test]
    fn p91b_full_lifecycle_round_trip() {
        let mut ctrl = BlockController::new(test_storage(), 2);

        // Round 1: submit to both slots
        let SubmitResult::Accepted(h0) = ctrl.submit(
            BlockRequest { block_number: 0, requester: rk(0, 0) }
        ) else { panic!() };
        let SubmitResult::Accepted(h1) = ctrl.submit(
            BlockRequest { block_number: 3, requester: rk(1, 0) }
        ) else { panic!() };
        assert_eq!(h0.generation, 0);
        assert_eq!(h1.generation, 0);

        // Tick through latency
        ctrl.tick();
        assert_eq!(ctrl.completion_count(), 0);
        ctrl.tick();
        assert_eq!(ctrl.completion_count(), 2);

        // Consume both
        let c0 = ctrl.consume_completion().unwrap();
        let c1 = ctrl.consume_completion().unwrap();
        assert_eq!(c0.data, (0..512).map(|i| (i % 256) as u8).collect::<Vec<_>>());
        assert_eq!(c1.data, vec![0xCC; 512]);

        // Generations incremented
        assert_eq!(ctrl.slot_generation(0), 1);
        assert_eq!(ctrl.slot_generation(1), 1);

        // Round 2: resubmit to recycled slots
        let SubmitResult::Accepted(h2) = ctrl.submit(
            BlockRequest { block_number: 2, requester: rk(0, 1) }
        ) else { panic!() };
        assert_eq!(h2.generation, 1, "recycled slot has gen=1");
        ctrl.tick();
        ctrl.tick();
        let c2 = ctrl.consume_completion().unwrap();
        assert_eq!(c2.data, vec![0xBB; 512]);
        assert_eq!(c2.handle.generation, 1);
        assert_eq!(ctrl.slot_generation(h2.slot), 2);
    }
}

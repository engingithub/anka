//! Phase 9.1b/c — Block Storage and Controller
//!
//! Asynchronous block device with two request slots, fixed
//! completion latency, and bounded completion queue.  READ-only.
//!
//! Phase 9.1c adds real Fabric DMA integration:
//!   - Per-request DMA domain (narrow delegation at submission)
//!   - Storage-agent MemoryRequest through full Fabric lifecycle
//!   - CompletionStatus { Success, DmaFault } replaces data payload
//!   - DmaInFlight persists across tick boundaries
//!   - Commit-time generation revalidation (I5) catches revocation
//!
//! Formal basis: anka_block_device.kleis
//!   SLOT-1..SLOT-4: F + O_wait + O_dma + C = N_slots
//!   COMP-1..COMP-5: completion ordering and consumption
//!   GEN-1..GEN-4:   generation-qualified request identity
//!   DMA-1..DMA-4:   narrow delegation, commit-time revalidation
//!   LEVEL-1:        L_dev ≡ (C > 0)
//!
//! Kleis ↔ Rust mapping:
//!   F       ↔ SlotState::Free
//!   O_wait  ↔ SlotState::Waiting
//!   O_dma   ↔ SlotState::DmaReady | SlotState::DmaInFlight
//!   C       ↔ SlotState::Completed
//!   L_dev   ↔ completion_count() > 0

use std::collections::VecDeque;
use super::state::{
    RequesterKey, DomainId, ObjectId, AccessKind,
    Permissions, FaultReason, AgentId, TxState,
};
use super::fabric::Fabric;

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
/// Generation is u64 to match the formal model (anka_block_device.kleis
/// uses BitVec64 for request-slot generations).
///
/// Formal basis: anka_block_device.kleis GEN-1..GEN-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHandle {
    pub slot: u8,
    pub generation: u64,
}

/// A block read request.
///
/// The `target_object`, `target_offset`, and `source_domain` fields
/// identify the guest buffer and the authority to delegate from.
/// The controller delegates a narrow WRITE-only span at submission.
#[derive(Debug, Clone)]
pub struct BlockRequest {
    pub block_number: u64,
    pub requester: RequesterKey,
    /// Guest buffer object to receive the read data.
    pub target_object: ObjectId,
    /// Byte offset within the target object.
    pub target_offset: u64,
    /// Domain with WRITE authority over the target span.
    /// The controller derives a narrow DMA domain from this.
    pub source_domain: DomainId,
}

/// Outcome of a completed block operation.
///
/// The guest buffer contains the data on success;
/// the completion record contains only the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionStatus {
    /// DMA transaction committed — data is in guest buffer.
    Success,
    /// DMA transaction faulted — guest buffer unchanged.
    DmaFault(FaultReason),
}

/// A completed block operation.
///
/// Carries generation-qualified identity for both the request slot
/// and the requester, so the kernel can detect stale completions.
///
/// `status` replaces the old `data: Vec<u8>` — the 512 bytes
/// belong in the guest buffer, not the completion record.
#[derive(Debug, Clone)]
pub struct BlockCompletion {
    pub handle: RequestHandle,
    pub requester: RequesterKey,
    pub block_number: u64,
    pub status: CompletionStatus,
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
    /// Source domain lacks authority to delegate the required span.
    DelegationFailed,
}

// ───────────────────────────────────────────────────────────────────
// Slot lifecycle
// ───────────────────────────────────────────────────────────────────

/// Per-slot lifecycle state — the single source of truth.
///
/// Conservation: F + O_wait + O_dma + C = NUM_SLOTS.
///
/// Both DmaReady and DmaInFlight count as the formal O_dma place.
/// DmaReady is the entry: latency has expired, DMA not yet started.
/// DmaInFlight: a Fabric transaction is in progress.
#[derive(Debug)]
enum SlotState {
    Free,
    Waiting {
        request: BlockRequest,
        remaining_ticks: u32,
        dma_domain: DomainId,
    },
    /// Latency expired, ready to start DMA.
    ///
    /// A Fabric transaction will be created from this state on
    /// the next tick.  Both DmaReady and DmaInFlight are the
    /// formal O_dma place.
    DmaReady {
        request: BlockRequest,
        dma_domain: DomainId,
    },
    /// Fabric transaction in progress.
    ///
    /// The transaction advances through Fabric phases (Requested →
    /// Authorized → Prepared → Committed/Faulted).  Once terminal,
    /// the slot transitions to Completed.
    DmaInFlight {
        request: BlockRequest,
        dma_domain: DomainId,
        tx_idx: usize,
    },
    Completed {
        completion: BlockCompletion,
    },
}

impl SlotState {
    fn is_free(&self) -> bool { matches!(self, SlotState::Free) }
    fn is_completed(&self) -> bool { matches!(self, SlotState::Completed { .. }) }
    fn is_waiting(&self) -> bool { matches!(self, SlotState::Waiting { .. }) }
    fn is_odma(&self) -> bool {
        matches!(self, SlotState::DmaReady { .. } | SlotState::DmaInFlight { .. })
    }
}

// ───────────────────────────────────────────────────────────────────
// Block controller
// ───────────────────────────────────────────────────────────────────

/// Two-slot block controller with fixed completion latency and
/// real Fabric DMA integration.
///
/// Formal basis: anka_block_device.kleis
///   SLOT-1..SLOT-4:  bounded slot conservation
///   COMP-1..COMP-5:  completion queue ordering
///   GEN-1..GEN-4:    generation-qualified handles
///   DMA-1..DMA-4:    narrow delegation, commit-time revalidation
///   LEVEL-1:         L_dev ≡ (C > 0), derived
pub struct BlockController {
    slots: [SlotState; NUM_SLOTS],
    slot_generations: [u64; NUM_SLOTS],
    /// Completion ordering — slot indices, not completion data.
    completion_order: VecDeque<u8>,
    storage: BlockStorage,
    latency: u32,
    /// Stable agent identity for storage DMA transactions.
    pub storage_agent: AgentId,
}

impl BlockController {
    pub fn new(storage: BlockStorage, latency: u32, storage_agent: AgentId) -> Self {
        Self {
            slots: std::array::from_fn(|_| SlotState::Free),
            slot_generations: [0; NUM_SLOTS],
            completion_order: VecDeque::new(),
            storage,
            latency,
            storage_agent,
        }
    }

    /// Submit a read request with narrow DMA delegation.
    ///
    /// At submission time:
    ///   1. Validate block number.
    ///   2. Derive a narrow WRITE-only DMA domain from source_domain
    ///      covering exactly (target_object, target_offset, block_size).
    ///   3. Transition slot: F → O_wait.
    ///
    /// Delegation happens at t₀ (acceptance), not when DMA starts.
    /// This freezes the authority incarnation, allowing later
    /// revocation to produce StaleGeneration at commit time.
    ///
    /// Formal: F → O_wait, DMA-DELEGATION.
    pub fn submit(
        &mut self,
        request: BlockRequest,
        fabric: &mut Fabric,
    ) -> SubmitResult {
        if request.block_number >= self.storage.num_blocks() {
            return SubmitResult::InvalidBlock;
        }

        let slot_idx = self.slots.iter()
            .position(|s| s.is_free());

        let idx = match slot_idx {
            None => return SubmitResult::DeviceBusy,
            Some(i) => i,
        };

        let block_size = self.storage.block_size();
        let dma_domain = match fabric.delegate_dma_span(
            request.source_domain,
            request.target_object,
            request.target_offset,
            block_size,
            Permissions::WRITE,
        ) {
            Some(d) => d,
            None => return SubmitResult::DelegationFailed,
        };

        let handle = RequestHandle {
            slot: idx as u8,
            generation: self.slot_generations[idx],
        };
        let remaining = self.latency.max(1);
        self.slots[idx] = SlotState::Waiting {
            request,
            remaining_ticks: remaining,
            dma_domain,
        };
        self.assert_conservation();
        SubmitResult::Accepted(handle)
    }

    /// Advance the controller by one machine tick.
    ///
    /// Three-phase processing:
    ///   1. Waiting → advance remaining; if zero → DmaReady
    ///   2. DmaReady → start Fabric transaction → DmaInFlight
    ///   3. DmaInFlight → advance Fabric transaction; if terminal → Completed
    ///
    /// Latency convention: submit at t → DmaReady on tick L.
    pub fn tick(&mut self, fabric: &mut Fabric) {
        // Phase 1: Waiting → advance or → DmaReady
        for i in 0..NUM_SLOTS {
            if let SlotState::Waiting { remaining_ticks, .. } = &mut self.slots[i] {
                *remaining_ticks -= 1;
                if *remaining_ticks == 0 {
                    let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                    if let SlotState::Waiting { request, dma_domain, .. } = state {
                        self.slots[i] = SlotState::DmaReady { request, dma_domain };
                    }
                }
            }
        }

        // Phase 2: DmaReady → start Fabric DMA → DmaInFlight
        for i in 0..NUM_SLOTS {
            if matches!(self.slots[i], SlotState::DmaReady { .. }) {
                let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                if let SlotState::DmaReady { request, dma_domain } = state {
                    let block_data = self.storage.read_block(request.block_number)
                        .expect("accepted block request must name a valid block");
                    let dma_req = super::fabric::dma_request(
                        self.storage_agent,
                        dma_domain,
                        request.target_object,
                        request.target_offset,
                        self.storage.block_size(),
                        AccessKind::Write,
                    );
                    let tx_idx = fabric.submit(dma_req, Some(block_data));
                    self.slots[i] = SlotState::DmaInFlight {
                        request, dma_domain, tx_idx,
                    };
                }
            }
        }

        // Phase 3: DmaInFlight → advance transaction; if terminal → Completed
        for i in 0..NUM_SLOTS {
            if let SlotState::DmaInFlight { tx_idx, .. } = &self.slots[i] {
                let tx_idx = *tx_idx;
                let tx_state = fabric.transaction(tx_idx).state;
                if !tx_state.is_terminal() {
                    fabric.advance(tx_idx);
                }
                let tx_state = fabric.transaction(tx_idx).state;
                if tx_state.is_terminal() {
                    let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                    if let SlotState::DmaInFlight { request, dma_domain, tx_idx } = state {
                        let status = match fabric.transaction(tx_idx).state {
                            TxState::Committed => CompletionStatus::Success,
                            TxState::Faulted => {
                                let reason = fabric.transaction(tx_idx)
                                    .fault.as_ref()
                                    .map(|f| f.reason)
                                    .unwrap_or(FaultReason::TranslationFault);
                                CompletionStatus::DmaFault(reason)
                            }
                            _ => unreachable!(),
                        };
                        fabric.destroy_domain(dma_domain);
                        let completion = BlockCompletion {
                            handle: RequestHandle {
                                slot: i as u8,
                                generation: self.slot_generations[i],
                            },
                            requester: request.requester,
                            block_number: request.block_number,
                            status,
                        };
                        self.slots[i] = SlotState::Completed { completion };
                        self.completion_order.push_back(i as u8);
                    }
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
    /// L_dev ≡ (C > 0).  Derived, never stored independently.
    ///
    /// Formal basis: anka_block_device.kleis LEVEL-1.
    pub fn requires_attention(&self) -> bool {
        self.completion_count() > 0
    }

    /// Number of slots currently in Completed state.
    pub fn completion_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_completed()).count()
    }

    /// Number of slots currently Free.
    pub fn free_slot_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_free()).count()
    }

    /// Current generation for a slot.
    pub fn slot_generation(&self, slot: u8) -> u64 {
        self.slot_generations[slot as usize]
    }

    /// Immutable access to the backing storage.
    pub fn storage_ref(&self) -> &BlockStorage {
        &self.storage
    }

    /// Mutable access to the backing storage (for test setup).
    pub fn storage_mut(&mut self) -> &mut BlockStorage {
        &mut self.storage
    }

    /// Structural conservation and coherence invariants.
    ///
    /// Checks:
    ///   F + O_wait + O_dma + C = NUM_SLOTS
    ///   |completion_order| = #C
    ///   ∀ q ∈ completion_order: q names a distinct Completed slot
    fn assert_conservation(&self) {
        let f = self.slots.iter().filter(|s| s.is_free()).count();
        let ow = self.slots.iter().filter(|s| s.is_waiting()).count();
        let od = self.slots.iter().filter(|s| s.is_odma()).count();
        let c = self.slots.iter().filter(|s| s.is_completed()).count();
        debug_assert_eq!(
            f + ow + od + c, NUM_SLOTS,
            "SLOT conservation violated: F={} + O_wait={} + O_dma={} + C={} ≠ {}",
            f, ow, od, c, NUM_SLOTS,
        );
        debug_assert_eq!(
            self.completion_order.len(), c,
            "completion-order/slot coherence: |queue|={} ≠ #C={}",
            self.completion_order.len(), c,
        );
        let mut seen = [false; NUM_SLOTS];
        for &slot_idx in &self.completion_order {
            let idx = slot_idx as usize;
            debug_assert!(
                self.slots[idx].is_completed(),
                "queue entry {} names a non-Completed slot", idx,
            );
            debug_assert!(!seen[idx], "queue entry {} appears more than once", idx);
            seen[idx] = true;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::state::*;

    const STORAGE_AGENT: AgentId = AgentId(100);

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

    /// Set up a Fabric with a 512-byte Active buffer object and a
    /// domain that has WRITE authority over it.
    ///
    /// Returns (fabric, buffer_object, process_domain).
    fn dma_setup() -> (Fabric, ObjectId, DomainId) {
        let mut f = Fabric::new(0x10000);
        let obj = f.alloc_object("buf", 512, ObjectKind::Memory);
        f.place_object(obj, 0x2000);
        let dom = f.create_domain();
        f.grant(dom, obj, 0, 512, Permissions::WRITE);
        (f, obj, dom)
    }

    fn make_request(
        block_number: u64,
        obj: ObjectId,
        dom: DomainId,
    ) -> BlockRequest {
        BlockRequest {
            block_number,
            requester: rk(0, 0),
            target_object: obj,
            target_offset: 0,
            source_domain: dom,
        }
    }

    // ─── Capacity / backpressure ──────────────────────────────────

    /// Two accepts exhaust capacity; third returns DeviceBusy.
    ///
    /// Formal: SLOT-1 (F=0 ⇒ no more accepts).
    #[test]
    fn p91b_two_slots_exhausted() {
        let (mut f, obj, dom) = dma_setup();
        // Need a second buffer object for the second slot.
        let obj2 = f.alloc_object("buf2", 512, ObjectKind::Memory);
        f.place_object(obj2, 0x3000);
        f.grant(dom, obj2, 0, 512, Permissions::WRITE);
        let obj3 = f.alloc_object("buf2", 512, ObjectKind::Memory);
        f.place_object(obj3, 0x4000);
        f.grant(dom, obj3, 0, 512, Permissions::WRITE);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        let r1 = ctrl.submit(make_request(0, obj, dom), &mut f);
        assert!(matches!(r1, SubmitResult::Accepted(_)));
        let r2 = ctrl.submit(make_request(1, obj2, dom), &mut f);
        assert!(matches!(r2, SubmitResult::Accepted(_)));
        let r3 = ctrl.submit(make_request(2, obj3, dom), &mut f);
        assert!(matches!(r3, SubmitResult::DeviceBusy));
    }

    // ─── Latency ──────────────────────────────────────────────────

    /// Exactly L ticks produce completion for several latency values.
    #[test]
    fn p91b_latency_exact() {
        for latency in [1u32, 2, 3, 5] {
            let (mut f, obj, dom) = dma_setup();
            let mut ctrl = BlockController::new(test_storage(), latency, STORAGE_AGENT);
            ctrl.submit(make_request(0, obj, dom), &mut f);

            for tick_num in 1..latency {
                ctrl.tick(&mut f);
                assert_eq!(ctrl.completion_count(), 0,
                    "latency={}: premature completion on tick {}", latency, tick_num);
            }
            // Tick L: latency expires → DmaReady.
            ctrl.tick(&mut f);
            // Tick L+1: DMA transaction advances through Fabric.
            // Multi-phase: Requested → Authorized → Prepared → Committed.
            // Each advance() does one phase, so we need a few more ticks.
            while ctrl.completion_count() == 0 {
                ctrl.tick(&mut f);
            }
            assert_eq!(ctrl.completion_count(), 1);
        }
    }

    /// Latency 0 means "next tick" (equivalent to latency 1).
    #[test]
    fn p91b_latency_zero_next_tick() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 0, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);
        assert_eq!(ctrl.completion_count(), 0, "not completed at submission");
        // Tick until completed (latency + Fabric phases).
        for _ in 0..10 {
            ctrl.tick(&mut f);
            if ctrl.completion_count() > 0 { break; }
        }
        assert_eq!(ctrl.completion_count(), 1, "completed");
    }

    // ─── Slot lifecycle ───────────────────────────────────────────

    /// Completed slots remain unavailable until consumed.
    #[test]
    fn p91b_completed_blocks_slot() {
        let (mut f, obj, dom) = dma_setup();
        let obj2 = f.alloc_object("buf2", 512, ObjectKind::Memory);
        f.place_object(obj2, 0x3000);
        f.grant(dom, obj2, 0, 512, Permissions::WRITE);
        let obj3 = f.alloc_object("buf2", 512, ObjectKind::Memory);
        f.place_object(obj3, 0x4000);
        f.grant(dom, obj3, 0, 512, Permissions::WRITE);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);
        ctrl.submit(make_request(1, obj2, dom), &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }
        assert_eq!(ctrl.completion_count(), 2);

        assert!(matches!(
            ctrl.submit(make_request(2, obj3, dom), &mut f),
            SubmitResult::DeviceBusy,
        ));

        ctrl.consume_completion();
        assert!(matches!(
            ctrl.submit(make_request(2, obj3, dom), &mut f),
            SubmitResult::Accepted(_),
        ));
    }

    // ─── Generation ───────────────────────────────────────────────

    /// Consuming increments slot generation.
    #[test]
    fn p91b_consume_increments_generation() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        let gen_before = ctrl.slot_generation(0);

        ctrl.submit(make_request(0, obj, dom), &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }
        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(
            ctrl.slot_generation(comp.handle.slot),
            gen_before + 1,
        );
    }

    /// Stale {slot, generation} does not match after recycling.
    #[test]
    fn p91b_stale_handle_no_match() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);

        let SubmitResult::Accepted(h1) = ctrl.submit(
            make_request(0, obj, dom), &mut f,
        ) else { panic!() };
        for _ in 0..10 { ctrl.tick(&mut f); }
        ctrl.consume_completion().unwrap();

        let SubmitResult::Accepted(h2) = ctrl.submit(
            make_request(1, obj, dom), &mut f,
        ) else { panic!() };

        assert_eq!(h1.slot, h2.slot);
        assert_ne!(h1.generation, h2.generation);
        assert_eq!(h2.generation, h1.generation + 1);
    }

    // ─── Multiple completions ─────────────────────────────────────

    /// Two completions coexist; requires_attention tracks count.
    #[test]
    fn p91b_two_completions_coexist() {
        let (mut f, obj, dom) = dma_setup();
        let obj2 = f.alloc_object("buf2", 512, ObjectKind::Memory);
        f.place_object(obj2, 0x3000);
        f.grant(dom, obj2, 0, 512, Permissions::WRITE);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);
        ctrl.submit(make_request(1, obj2, dom), &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }

        assert_eq!(ctrl.completion_count(), 2);
        assert!(ctrl.requires_attention());

        let c1 = ctrl.consume_completion().unwrap();
        assert_eq!(ctrl.completion_count(), 1);
        let c2 = ctrl.consume_completion().unwrap();
        assert_eq!(ctrl.completion_count(), 0);
        assert!(!ctrl.requires_attention());
        assert_ne!(c1.handle.slot, c2.handle.slot);
    }

    // ─── Derived attention ────────────────────────────────────────

    /// requires_attention() derived from completion state.
    #[test]
    fn p91b_requires_attention_derived() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        assert!(!ctrl.requires_attention());

        ctrl.submit(make_request(0, obj, dom), &mut f);
        assert!(!ctrl.requires_attention());

        for _ in 0..10 { ctrl.tick(&mut f); }
        assert!(ctrl.requires_attention());

        ctrl.consume_completion();
        assert!(!ctrl.requires_attention());
    }

    // ─── Conservation ─────────────────────────────────────────────

    /// F + O_wait + O_dma + C = 2 throughout full lifecycle.
    #[test]
    fn p91b_conservation_invariant() {
        let (mut f, obj, dom) = dma_setup();
        let obj2 = f.alloc_object("buf2", 512, ObjectKind::Memory);
        f.place_object(obj2, 0x3000);
        f.grant(dom, obj2, 0, 512, Permissions::WRITE);

        let mut ctrl = BlockController::new(test_storage(), 3, STORAGE_AGENT);
        assert_eq!(ctrl.free_slot_count(), 2);

        ctrl.submit(make_request(0, obj, dom), &mut f);
        assert_eq!(ctrl.free_slot_count(), 1);

        ctrl.submit(make_request(1, obj2, dom), &mut f);
        assert_eq!(ctrl.free_slot_count(), 0);

        for _ in 0..20 { ctrl.tick(&mut f); }
        assert_eq!(ctrl.completion_count(), 2);
        assert_eq!(ctrl.free_slot_count(), 0);

        ctrl.consume_completion();
        ctrl.consume_completion();
        assert_eq!(ctrl.free_slot_count(), 2);
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.1c — DMA integration tests
    // ═══════════════════════════════════════════════════════════════

    /// Exact 512-byte READ through narrow DMA domain succeeds
    /// and fills only the intended buffer.
    #[test]
    fn p91c_dma_read_512_succeeds() {
        let (mut f, obj, dom) = dma_setup();
        let sentinel = vec![0xDE; 512];
        f.initialize_object(obj, 0, &sentinel);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(1, obj, dom), &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }

        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.status, CompletionStatus::Success);

        let buf = f.read_physical(0x2000, 512);
        assert_eq!(buf, &vec![0xAA; 512][..], "guest buffer has block 1 data");
    }

    /// A broader submitter capability produces a DMA domain
    /// containing only the derived 512-byte WRITE authority.
    /// DMA domain cannot access another object or bytes outside span.
    #[test]
    fn p91c_narrow_dma_domain() {
        let (mut f, _obj, _dom) = dma_setup();
        let big_obj = f.alloc_object("bigbuf", 4096, ObjectKind::Memory);
        f.place_object(big_obj, 0x5000);
        let big_dom = f.create_domain();
        f.grant(big_dom, big_obj, 0, 4096, Permissions::WRITE);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        let req = BlockRequest {
            block_number: 0,
            requester: rk(0, 0),
            target_object: big_obj,
            target_offset: 1024,
            source_domain: big_dom,
        };
        ctrl.submit(req, &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }

        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.status, CompletionStatus::Success);

        let buf = f.read_physical(0x5000 + 1024, 512);
        let expected: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        assert_eq!(buf, &expected[..], "only 512 bytes at offset 1024 written");

        let before = f.read_physical(0x5000, 1024);
        assert_eq!(before, &vec![0u8; 1024][..], "bytes before span untouched");

        let after = f.read_physical(0x5000 + 1536, 512);
        assert_eq!(after, &vec![0u8; 512][..], "bytes after span untouched");
    }

    /// Revoke before DMA authorization produces error completion
    /// and zero mutation.
    #[test]
    fn p91c_revoke_before_dma_error_completion() {
        let (mut f, obj, dom) = dma_setup();
        let sentinel = vec![0xEE; 512];
        f.initialize_object(obj, 0, &sentinel);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);

        // Revoke the object before DMA can start.
        f.revoke(obj);

        for _ in 0..10 { ctrl.tick(&mut f); }
        let comp = ctrl.consume_completion().unwrap();
        assert!(matches!(comp.status, CompletionStatus::DmaFault(_)),
            "revocation before DMA must produce fault");

        let buf = f.read_physical(0x2000, 512);
        assert_eq!(buf, &sentinel[..], "zero mutation after revocation");
    }

    /// Authorize → revoke → commit produces StaleGeneration,
    /// error completion, zero mutation.
    ///
    /// This is the key I5 composition test: delegation at t₀,
    /// revocation at t₁, commit-time revalidation at t₂.
    #[test]
    fn p91c_authorize_revoke_commit_stale() {
        let (mut f, obj, dom) = dma_setup();
        let sentinel = vec![0xDD; 512];
        f.initialize_object(obj, 0, &sentinel);

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);

        // Tick once to expire latency → DmaReady.
        ctrl.tick(&mut f);
        // Tick again: DmaReady → DmaInFlight (Fabric submit).
        // Fabric advance does one phase: Requested → Authorized.
        ctrl.tick(&mut f);

        // Now revoke: the DMA domain's capability is stale.
        f.revoke(obj);

        // Further ticks advance: Authorized → Prepared → commit revalidation → Faulted.
        for _ in 0..10 { ctrl.tick(&mut f); }

        let comp = ctrl.consume_completion().unwrap();
        match comp.status {
            CompletionStatus::DmaFault(reason) => {
                assert_eq!(reason, FaultReason::StaleGeneration,
                    "commit-time revalidation must detect revocation");
            }
            CompletionStatus::Success => {
                panic!("DMA must not succeed after object revocation");
            }
        }

        let buf = f.read_physical(0x2000, 512);
        assert_eq!(buf, &sentinel[..], "zero mutation after stale-gen fault");
    }

    /// Successful Fabric terminal state produces exactly one
    /// Success completion.
    #[test]
    fn p91c_success_produces_one_completion() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(2, obj, dom), &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }

        assert_eq!(ctrl.completion_count(), 1);
        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.status, CompletionStatus::Success);
        assert_eq!(comp.block_number, 2);
        assert!(ctrl.consume_completion().is_none());
    }

    /// Faulted Fabric terminal state produces exactly one
    /// DmaFault completion.
    #[test]
    fn p91c_fault_produces_one_completion() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);
        f.revoke(obj);
        for _ in 0..10 { ctrl.tick(&mut f); }

        assert_eq!(ctrl.completion_count(), 1);
        let comp = ctrl.consume_completion().unwrap();
        assert!(matches!(comp.status, CompletionStatus::DmaFault(_)));
        assert!(ctrl.consume_completion().is_none());
    }

    /// DMA domain is destroyed after the transaction becomes terminal.
    #[test]
    fn p91c_dma_domain_destroyed_after_terminal() {
        let (mut f, obj, dom) = dma_setup();
        let domains_before = f.domain_count();

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(make_request(0, obj, dom), &mut f);

        // During DMA: one extra domain exists.
        assert_eq!(f.domain_count(), domains_before + 1);

        for _ in 0..10 { ctrl.tick(&mut f); }
        ctrl.consume_completion();

        // After completion + consume: DMA domain destroyed.
        assert_eq!(f.domain_count(), domains_before,
            "DMA domain must be destroyed after terminal");
    }

    /// Requester death without buffer revocation does not magically
    /// revoke DMA authority.
    ///
    /// Process death and buffer revocation are independent events
    /// in the formal model.  The DMA domain's authority survives
    /// as long as the underlying object is not revoked.
    #[test]
    fn p91c_requester_death_independent_of_buffer() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);

        // Submit request (process is "alive" at slot=0, gen=0).
        ctrl.submit(make_request(1, obj, dom), &mut f);

        // "Kill" the process: destroy its domain.
        // This simulates process death without revoking the buffer object.
        f.destroy_domain(dom);

        // DMA should still succeed — the DMA domain's capability
        // is independent of the process domain.
        for _ in 0..10 { ctrl.tick(&mut f); }
        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.status, CompletionStatus::Success,
            "DMA authority survives process death");

        let buf = f.read_physical(0x2000, 512);
        assert_eq!(buf, &vec![0xAA; 512][..], "data written despite dead process");
    }

    /// Delegation fails when source domain lacks authority.
    #[test]
    fn p91c_delegation_fails_no_authority() {
        let (mut f, obj, _dom) = dma_setup();
        let empty_dom = f.create_domain();

        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        let r = ctrl.submit(BlockRequest {
            block_number: 0,
            requester: rk(0, 0),
            target_object: obj,
            target_offset: 0,
            source_domain: empty_dom,
        }, &mut f);
        assert!(matches!(r, SubmitResult::DelegationFailed));
        assert_eq!(ctrl.free_slot_count(), 2, "no slot consumed");
    }

    /// Invalid block number rejected without consuming a slot.
    #[test]
    fn p91b_invalid_block_rejected() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        let r = ctrl.submit(make_request(99, obj, dom), &mut f);
        assert!(matches!(r, SubmitResult::InvalidBlock));
        assert_eq!(ctrl.free_slot_count(), 2);
    }

    /// Completion carries requester identity.
    #[test]
    fn p91b_requester_identity_carried() {
        let (mut f, obj, dom) = dma_setup();
        let key = rk(7, 42);
        let mut ctrl = BlockController::new(test_storage(), 1, STORAGE_AGENT);
        ctrl.submit(BlockRequest {
            block_number: 0,
            requester: key,
            target_object: obj,
            target_offset: 0,
            source_domain: dom,
        }, &mut f);
        for _ in 0..10 { ctrl.tick(&mut f); }
        let comp = ctrl.consume_completion().unwrap();
        assert_eq!(comp.requester, key);
    }

    /// Full lifecycle round trip: submit → tick → complete → consume → resubmit.
    #[test]
    fn p91b_full_lifecycle_round_trip() {
        let (mut f, obj, dom) = dma_setup();
        let mut ctrl = BlockController::new(test_storage(), 2, STORAGE_AGENT);

        let SubmitResult::Accepted(h0) = ctrl.submit(
            make_request(0, obj, dom), &mut f,
        ) else { panic!() };
        assert_eq!(h0.generation, 0);

        for _ in 0..20 { ctrl.tick(&mut f); }
        let c0 = ctrl.consume_completion().unwrap();
        assert_eq!(c0.status, CompletionStatus::Success);
        assert_eq!(ctrl.slot_generation(0), 1);

        let SubmitResult::Accepted(h1) = ctrl.submit(
            make_request(2, obj, dom), &mut f,
        ) else { panic!() };
        assert_eq!(h1.generation, 1);

        for _ in 0..20 { ctrl.tick(&mut f); }
        let c1 = ctrl.consume_completion().unwrap();
        assert_eq!(c1.status, CompletionStatus::Success);
        assert_eq!(ctrl.slot_generation(h1.slot), 2);
    }
}

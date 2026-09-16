//! NicController — bounded private RX queue + finite RX DMA (Phase 9.3e.4a).
//!
//! Unsolicited packet arrival semantics:
//!   * Admitted frames enter a bounded device-private RX queue.
//!   * Successful admission increments the activity epoch exactly once
//!     and latches arrival attention.
//!   * Arrival itself never mutates guest memory, creates a
//!     DeviceRequestKey, or produces a delegation.
//!   * Queued private RX is not pair-attributed work and does not
//!     constitute autonomous machine progress.
//!
//! Finite RX-copy semantics:
//!   * A later authorized SYS_NIC_RX presents exact NIC_RX authority
//!     and exact WRITE authority for a guest buffer.
//!   * Submission delegates exactly the front frame's byte span into a
//!     fresh DMA domain before dequeuing that frame.
//!   * Pre-admission failure leaves the private RX queue unchanged.
//!   * Once accepted, the frame belongs to the finite request.  A later
//!     DMA fault does not requeue it.
//!   * Accepted nonterminal DMA contributes to pair quiescence when the
//!     presented buffer carries DelegationId provenance.
//!   * RX-copy completion does NOT advance the unsolicited-arrival epoch.
//!
//! Frame size limit: untagged Ethernet (14-byte header + 1500 payload),
//! excluding FCS (stripped by hardware).  Does not imply 802.1Q VLAN
//! support.
//!
//! Formal basis: anka_userspace_nic.kleis NIC93E-1..24 and
//! anka93e3_nic_controller.kleis NIC93E3-1..32.

use std::collections::VecDeque;

use super::fabric::{dma_request, Fabric};
use super::state::{
    AccessKind, AgentId, AuthorityId, DelegationId, DeviceCompletionStatus,
    DomainId, FaultReason, ObjectId, Permissions, ProcessKey, RequestHandle,
    RequesterKey, TxState,
};

/// Maximum accepted frame size: 6 dst + 6 src + 2 EtherType + 1500 payload.
/// Excludes FCS (4 bytes, stripped by hardware).
pub const NIC_MAX_FRAME_SIZE: usize = 1514;

/// Bounded private RX queue capacity.
pub const NIC_RX_QUEUE_CAPACITY: usize = 16;

/// Number of finite DMA request slots.
const NUM_SLOTS: usize = 2;

/// One accepted finite RX-copy request.
///
/// The frame bytes themselves are controller-private until submission and
/// then move into the slot state.  This structure carries only routing,
/// authority and provenance metadata.
#[derive(Debug, Clone)]
pub struct NicRxRequest {
    pub requester: RequesterKey,
    pub target_object: ObjectId,
    pub target_offset: u64,
    pub source_domain: DomainId,
    pub source_authority_id: AuthorityId,
    pub delegation_id: Option<DelegationId>,
}

/// Completion of a finite NIC DMA request.
#[derive(Debug, Clone)]
pub struct NicCompletion {
    pub handle: RequestHandle,
    pub requester: RequesterKey,
    pub status: DeviceCompletionStatus,
    /// Number of bytes committed to guest memory.  Zero on DMA fault.
    pub transferred_len: u64,
    pub delegation_id: Option<DelegationId>,
}

/// Result of attempting to accept one queued RX frame for finite DMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicRxSubmitResult {
    Accepted(RequestHandle),
    NoPacket,
    DeviceBusy,
    DelegationFailed,
}

/// Per-slot lifecycle for finite RX DMA.
///
/// Conservation: Free + DmaReady + DmaInFlight + Completed = NUM_SLOTS.
#[derive(Debug)]
enum SlotState {
    Free,
    DmaReady {
        request: NicRxRequest,
        frame: Vec<u8>,
        dma_domain: DomainId,
    },
    DmaInFlight {
        request: NicRxRequest,
        frame_len: u64,
        dma_domain: DomainId,
        tx_idx: usize,
    },
    Completed {
        completion: NicCompletion,
    },
}

impl SlotState {
    fn is_free(&self) -> bool {
        matches!(self, SlotState::Free)
    }

    fn is_completed(&self) -> bool {
        matches!(self, SlotState::Completed { .. })
    }

    fn is_nonterminal(&self) -> bool {
        matches!(self, SlotState::DmaReady { .. } | SlotState::DmaInFlight { .. })
    }
}

/// Minimal NIC controller with bounded private RX and two finite DMA slots.
#[derive(Debug)]
pub struct NicController {
    rx_queue: VecDeque<Vec<u8>>,
    event_sequence: u64,
    /// Latched notification for admitted unsolicited arrivals only.
    /// Completion attention is derived separately from completion_count().
    attention_pending: bool,

    slots: [SlotState; NUM_SLOTS],
    slot_generations: [u64; NUM_SLOTS],
    completion_order: VecDeque<u8>,

    /// Stable bus-master identity used for Fabric fault records.
    pub dma_agent: AgentId,
}

impl NicController {
    pub fn new(dma_agent: AgentId) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            event_sequence: 0,
            attention_pending: false,
            slots: std::array::from_fn(|_| SlotState::Free),
            slot_generations: [0; NUM_SLOTS],
            completion_order: VecDeque::new(),
            dma_agent,
        }
    }

    /// Inject a received frame into the device-private RX queue.
    ///
    /// All semantic failure checks precede architectural mutation:
    ///   1. Frame size <= NIC_MAX_FRAME_SIZE
    ///   2. Queue length < NIC_RX_QUEUE_CAPACITY
    ///   3. Epoch can advance (checked_add, no silent wrap)
    ///
    /// On success: appends exactly one frame, increments epoch once,
    /// latches arrival attention.  Returns true.
    ///
    /// On failure (oversize, full, epoch exhaustion): no mutation.
    pub fn inject_rx(&mut self, frame: &[u8]) -> bool {
        if frame.len() > NIC_MAX_FRAME_SIZE {
            return false;
        }
        if self.rx_queue.len() >= NIC_RX_QUEUE_CAPACITY {
            return false;
        }
        let Some(next_epoch) = self.event_sequence.checked_add(1) else {
            return false;
        };

        self.rx_queue.push_back(frame.to_vec());
        self.event_sequence = next_epoch;
        self.attention_pending = true;
        true
    }

    /// Accept the front private RX frame for a finite WRITE DMA.
    ///
    /// Transactional admission order:
    ///   free slot -> front frame -> exact narrow delegation -> dequeue.
    ///
    /// Therefore any pre-admission failure implies ΔRXQueue = 0.
    /// For non-empty frames the fresh DMA domain is minted before the
    /// frame leaves private queue state.  Once accepted, later DMA failure
    /// consumes the frame rather than requeueing it.
    ///
    /// Empty frames are legal private events (preserving 9.3e.3 semantics).
    /// They complete immediately after admission because Fabric rejects
    /// zero-length memory transactions; no guest bytes are touched.
    pub fn submit_rx(
        &mut self,
        request: NicRxRequest,
        fabric: &mut Fabric,
    ) -> NicRxSubmitResult {
        let idx = match self.slots.iter().position(|s| s.is_free()) {
            Some(i) => i,
            None => return NicRxSubmitResult::DeviceBusy,
        };

        let frame_len = match self.rx_queue.front() {
            Some(frame) => frame.len() as u64,
            None => return NicRxSubmitResult::NoPacket,
        };

        let handle = RequestHandle {
            slot: idx as u8,
            generation: self.slot_generations[idx],
        };

        if frame_len == 0 {
            // All authority/kind/provenance gates are performed by the kernel
            // before this point.  There is no byte span to delegate or mutate.
            self.rx_queue.pop_front();
            let completion = NicCompletion {
                handle,
                requester: request.requester,
                status: DeviceCompletionStatus::Success,
                transferred_len: 0,
                delegation_id: request.delegation_id,
            };
            self.slots[idx] = SlotState::Completed { completion };
            self.completion_order.push_back(idx as u8);
            self.assert_conservation();
            return NicRxSubmitResult::Accepted(handle);
        }

        // Exact-authority delegation.  This helper performs all validation
        // before it creates a new domain, so failure has no Fabric side effect.
        let dma_domain = match fabric.delegate_dma_span_from_authority_id(
            request.source_domain,
            request.source_authority_id,
            request.target_object,
            request.target_offset,
            frame_len,
            Permissions::WRITE,
        ) {
            Some(domain) => domain,
            None => return NicRxSubmitResult::DelegationFailed,
        };

        // Delegation succeeded: ownership of the front frame now moves from
        // private queue state into the accepted finite request.
        let frame = self.rx_queue.pop_front()
            .expect("front frame must remain present across atomic submission");

        self.slots[idx] = SlotState::DmaReady {
            request,
            frame,
            dma_domain,
        };
        self.assert_conservation();
        NicRxSubmitResult::Accepted(handle)
    }

    /// Advance all accepted finite DMA work by one device tick.
    ///
    /// DmaReady -> Fabric Requested, then a single Fabric phase is advanced
    /// per tick.  On terminal state the narrow DMA domain is destroyed and
    /// a completion becomes ready.  RX completion never advances the
    /// unsolicited-arrival event epoch.
    pub fn tick(&mut self, fabric: &mut Fabric) {
        // DmaReady -> DmaInFlight
        for i in 0..NUM_SLOTS {
            if matches!(self.slots[i], SlotState::DmaReady { .. }) {
                let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                if let SlotState::DmaReady { request, frame, dma_domain } = state {
                    let frame_len = frame.len() as u64;
                    let dma_req = dma_request(
                        self.dma_agent,
                        dma_domain,
                        request.target_object,
                        request.target_offset,
                        frame_len,
                        AccessKind::Write,
                    );
                    let tx_idx = fabric.submit(dma_req, Some(frame));
                    self.slots[i] = SlotState::DmaInFlight {
                        request,
                        frame_len,
                        dma_domain,
                        tx_idx,
                    };
                }
            }
        }

        // DmaInFlight -> advance one Fabric phase; terminal -> Completed
        for i in 0..NUM_SLOTS {
            if let SlotState::DmaInFlight { tx_idx, .. } = &self.slots[i] {
                let tx_idx = *tx_idx;
                if !fabric.transaction(tx_idx).state.is_terminal() {
                    fabric.advance(tx_idx);
                }

                if fabric.transaction(tx_idx).state.is_terminal() {
                    let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                    if let SlotState::DmaInFlight {
                        request,
                        frame_len,
                        dma_domain,
                        tx_idx,
                    } = state
                    {
                        let (status, transferred_len) = match fabric.transaction(tx_idx).state {
                            TxState::Committed => (DeviceCompletionStatus::Success, frame_len),
                            TxState::Faulted => {
                                let reason = fabric.transaction(tx_idx)
                                    .fault
                                    .as_ref()
                                    .map(|f| f.reason)
                                    .unwrap_or(FaultReason::TranslationFault);
                                (DeviceCompletionStatus::DmaFault(reason), 0)
                            }
                            _ => unreachable!(),
                        };

                        fabric.destroy_domain(dma_domain);
                        let completion = NicCompletion {
                            handle: RequestHandle {
                                slot: i as u8,
                                generation: self.slot_generations[i],
                            },
                            requester: request.requester,
                            status,
                            transferred_len,
                            delegation_id: request.delegation_id,
                        };
                        self.slots[i] = SlotState::Completed { completion };
                        self.completion_order.push_back(i as u8);
                    }
                }
            }
        }

        self.assert_conservation();
    }

    /// Pop the oldest completion and recycle its request slot.
    pub fn consume_completion(&mut self) -> Option<NicCompletion> {
        let slot_idx = self.completion_order.pop_front()? as usize;
        let state = std::mem::replace(&mut self.slots[slot_idx], SlotState::Free);
        match state {
            SlotState::Completed { completion } => {
                self.slot_generations[slot_idx] = self.slot_generations[slot_idx]
                    .checked_add(1)
                    .expect("NIC request-slot generation exhausted");
                self.assert_conservation();
                Some(completion)
            }
            other => {
                self.slots[slot_idx] = other;
                None
            }
        }
    }

    /// Current unsolicited-RX activity epoch.
    ///
    /// Monotonic: advances only on successful `inject_rx`, never on DMA
    /// submission or completion.
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Queued private RX alone is not autonomous work.  Accepted finite DMA is.
    pub fn has_autonomous_work(&self) -> bool {
        self.slots.iter().any(|s| s.is_nonterminal())
    }

    /// Attention is the OR of two independent sources:
    ///   arrival latch OR ready completion.
    ///
    /// Acknowledging arrival never consumes a completion, and consuming a
    /// completion never clears an unrelated arrival latch.
    pub fn requires_attention(&self) -> bool {
        self.attention_pending || self.completion_count() != 0
    }

    /// Clear only the unsolicited-arrival notification latch.
    ///
    /// Preserves queued frames, event epoch, request slots and completions.
    pub fn acknowledge_attention(&mut self) {
        self.attention_pending = false;
    }

    /// Number of ready finite-DMA completions.
    pub fn completion_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_completed()).count()
    }

    /// Number of free finite-DMA request slots.
    pub fn free_slot_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_free()).count()
    }

    /// Quantitative pair-attributed nonterminal request count.
    ///
    /// Private queued RX is absent from this count.  Only accepted DmaReady /
    /// DmaInFlight work whose DelegationId names the exact client/driver pair
    /// contributes.  Completed work is terminal and therefore excluded.
    pub fn nonterminal_pair_request_count(
        &self,
        client: &ProcessKey,
        peer: &ProcessKey,
    ) -> usize {
        self.slots.iter().filter(|slot| {
            let request = match slot {
                SlotState::DmaReady { request, .. } => request,
                SlotState::DmaInFlight { request, .. } => request,
                _ => return false,
            };
            match request.delegation_id {
                Some(did) => did.client == *client && did.driver == *peer,
                None => false,
            }
        }).count()
    }

    /// Number of frames still resident in device-private RX state.
    pub fn rx_queue_len(&self) -> usize {
        self.rx_queue.len()
    }

    /// Peek at the private RX queue head without transferring ownership.
    pub fn peek_rx(&self) -> Option<&[u8]> {
        self.rx_queue.front().map(|v| v.as_slice())
    }

    /// Current generation for a request slot (test/diagnostic surface).
    pub fn slot_generation(&self, slot: u8) -> u64 {
        self.slot_generations[slot as usize]
    }

    /// Structural conservation and completion-order coherence.
    fn assert_conservation(&self) {
        let free = self.slots.iter().filter(|s| s.is_free()).count();
        let active = self.slots.iter().filter(|s| s.is_nonterminal()).count();
        let completed = self.slots.iter().filter(|s| s.is_completed()).count();
        debug_assert_eq!(free + active + completed, NUM_SLOTS);
        debug_assert_eq!(self.completion_order.len(), completed);

        let mut seen = [false; NUM_SLOTS];
        for &slot in &self.completion_order {
            let idx = slot as usize;
            debug_assert!(idx < NUM_SLOTS);
            debug_assert!(self.slots[idx].is_completed());
            debug_assert!(!seen[idx]);
            seen[idx] = true;
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::state::ObjectKind;

    const NIC_AGENT: AgentId = AgentId(90);

    fn dma_fixture(span: u64) -> (Fabric, DomainId, ObjectId, AuthorityId) {
        let mut fabric = Fabric::new(0x20000);
        let object = fabric.alloc_object("nic_rx_buf", 0x1000, ObjectKind::Memory);
        assert!(fabric.place_object(object, 0x4000));
        let domain = fabric.create_domain();
        let aid = fabric.alloc_authority_id().expect("authority id");
        fabric.grant_with_authority_id(
            domain,
            object,
            0,
            span,
            Permissions::WRITE,
            aid,
        ).expect("WRITE authority");
        (fabric, domain, object, aid)
    }

    fn request(domain: DomainId, object: ObjectId, aid: AuthorityId) -> NicRxRequest {
        NicRxRequest {
            requester: RequesterKey { slot: 0, generation: 0 },
            target_object: object,
            target_offset: 0,
            source_domain: domain,
            source_authority_id: aid,
            delegation_id: None,
        }
    }

    #[test]
    fn inject_rx_succeeds() {
        let mut nic = NicController::new(NIC_AGENT);
        assert_eq!(nic.event_sequence(), 0);
        assert_eq!(nic.rx_queue_len(), 0);
        assert!(!nic.requires_attention());

        assert!(nic.inject_rx(&[0xAA; 64]));
        assert_eq!(nic.event_sequence(), 1);
        assert_eq!(nic.rx_queue_len(), 1);
        assert!(nic.requires_attention());
        assert_eq!(nic.peek_rx(), Some([0xAA; 64].as_slice()));
    }

    #[test]
    fn inject_rx_exact_max_size() {
        let mut nic = NicController::new(NIC_AGENT);
        let frame = vec![0u8; NIC_MAX_FRAME_SIZE];
        assert!(nic.inject_rx(&frame));
        assert_eq!(nic.event_sequence(), 1);
        assert_eq!(nic.rx_queue_len(), 1);
    }

    #[test]
    fn inject_rx_empty_frame() {
        let mut nic = NicController::new(NIC_AGENT);
        assert!(nic.inject_rx(&[]));
        assert_eq!(nic.event_sequence(), 1);
        assert_eq!(nic.rx_queue_len(), 1);
    }

    #[test]
    fn inject_rx_oversize_rejected() {
        let mut nic = NicController::new(NIC_AGENT);
        let frame = vec![0u8; NIC_MAX_FRAME_SIZE + 1];
        assert!(!nic.inject_rx(&frame));
        assert_eq!(nic.event_sequence(), 0);
        assert_eq!(nic.rx_queue_len(), 0);
        assert!(!nic.requires_attention());
    }

    #[test]
    fn inject_rx_full_queue_rejected() {
        let mut nic = NicController::new(NIC_AGENT);
        for i in 0..NIC_RX_QUEUE_CAPACITY {
            assert!(nic.inject_rx(&[i as u8; 64]),
                "injection {} should succeed", i);
        }
        assert_eq!(nic.rx_queue_len(), NIC_RX_QUEUE_CAPACITY);
        assert_eq!(nic.event_sequence(), NIC_RX_QUEUE_CAPACITY as u64);

        let epoch_before = nic.event_sequence();
        assert!(!nic.inject_rx(&[0xFF; 64]));
        assert_eq!(nic.event_sequence(), epoch_before);
        assert_eq!(nic.rx_queue_len(), NIC_RX_QUEUE_CAPACITY);
    }

    #[test]
    fn acknowledge_attention_clears_only_arrival_latch() {
        let mut nic = NicController::new(NIC_AGENT);
        assert!(nic.inject_rx(&[1, 2, 3]));
        assert!(nic.requires_attention());
        let epoch = nic.event_sequence();
        let len = nic.rx_queue_len();

        nic.acknowledge_attention();

        assert!(!nic.requires_attention());
        assert_eq!(nic.event_sequence(), epoch);
        assert_eq!(nic.rx_queue_len(), len);
        assert_eq!(nic.peek_rx(), Some([1u8, 2, 3].as_slice()));
    }

    #[test]
    fn queued_rx_alone_is_not_autonomous_work() {
        let mut nic = NicController::new(NIC_AGENT);
        assert!(!nic.has_autonomous_work());
        nic.inject_rx(&[0; 64]);
        assert!(!nic.has_autonomous_work());
    }

    #[test]
    fn private_rx_alone_has_no_completion() {
        let mut nic = NicController::new(NIC_AGENT);
        assert_eq!(nic.completion_count(), 0);
        nic.inject_rx(&[0; 64]);
        assert_eq!(nic.completion_count(), 0);
        assert!(nic.consume_completion().is_none());
    }

    #[test]
    fn private_rx_alone_has_zero_pair_count() {
        let mut nic = NicController::new(NIC_AGENT);
        let pk = ProcessKey { slot: 0, generation: 0 };
        assert_eq!(nic.nonterminal_pair_request_count(&pk, &pk), 0);
        nic.inject_rx(&[0; 64]);
        assert_eq!(nic.nonterminal_pair_request_count(&pk, &pk), 0);
    }

    #[test]
    fn epoch_overflow_rejected() {
        let mut nic = NicController::new(NIC_AGENT);
        nic.event_sequence = u64::MAX;
        let queue_before = nic.rx_queue_len();
        let attn_before = nic.requires_attention();

        assert!(!nic.inject_rx(&[0; 64]));
        assert_eq!(nic.event_sequence(), u64::MAX);
        assert_eq!(nic.rx_queue_len(), queue_before);
        assert_eq!(nic.requires_attention(), attn_before);
    }

    #[test]
    fn rx_dma_success_moves_frame_through_fabric_without_epoch_change() {
        let (mut fabric, domain, object, aid) = dma_fixture(0x1000);
        let mut nic = NicController::new(NIC_AGENT);
        let frame = vec![0xA5; 64];
        assert!(nic.inject_rx(&frame));
        let epoch = nic.event_sequence();
        nic.acknowledge_attention();

        let result = nic.submit_rx(request(domain, object, aid), &mut fabric);
        let handle = match result {
            NicRxSubmitResult::Accepted(h) => h,
            other => panic!("expected accepted RX, got {:?}", other),
        };
        assert_eq!(handle.slot, 0);
        assert_eq!(handle.generation, 0);
        assert_eq!(nic.rx_queue_len(), 0,
            "accepted frame leaves private queue");
        assert!(nic.has_autonomous_work());
        assert_eq!(nic.event_sequence(), epoch,
            "RX-copy admission must not advance arrival epoch");

        for _ in 0..3 {
            nic.tick(&mut fabric);
        }
        assert!(!nic.has_autonomous_work());
        assert_eq!(nic.completion_count(), 1);
        assert!(nic.requires_attention(),
            "completion is an attention source independent of arrival latch");
        assert_eq!(nic.event_sequence(), epoch,
            "RX-copy completion must not advance arrival epoch");

        let phys = fabric.translate(object, 0).unwrap();
        assert_eq!(fabric.read_physical(phys, frame.len() as u64), frame.as_slice());

        let completion = nic.consume_completion().expect("NIC completion");
        assert_eq!(completion.handle, handle);
        assert_eq!(completion.status, DeviceCompletionStatus::Success);
        assert_eq!(completion.transferred_len, frame.len() as u64);
        assert_eq!(nic.slot_generation(0), 1);
        assert!(!nic.requires_attention());
    }

    #[test]
    fn rx_dma_delegation_failure_preserves_private_queue() {
        let (mut fabric, domain, object, aid) = dma_fixture(2);
        let mut nic = NicController::new(NIC_AGENT);
        let frame = [1u8, 2, 3, 4];
        assert!(nic.inject_rx(&frame));
        let domains_before = fabric.domain_count();
        let epoch_before = nic.event_sequence();

        let result = nic.submit_rx(request(domain, object, aid), &mut fabric);
        assert_eq!(result, NicRxSubmitResult::DelegationFailed);
        assert_eq!(fabric.domain_count(), domains_before,
            "failed exact delegation must not leak a DMA domain");
        assert_eq!(nic.rx_queue_len(), 1,
            "pre-admission failure must preserve queued frame");
        assert_eq!(nic.peek_rx(), Some(frame.as_slice()));
        assert_eq!(nic.event_sequence(), epoch_before);
        assert!(!nic.has_autonomous_work());
    }

    #[test]
    fn accepted_rx_dma_is_pair_attributed_until_terminal() {
        let (mut fabric, domain, object, aid) = dma_fixture(0x1000);
        let mut nic = NicController::new(NIC_AGENT);
        assert!(nic.inject_rx(&[0x11; 32]));

        let client = ProcessKey { slot: 3, generation: 4 };
        let driver = ProcessKey { slot: 7, generation: 9 };
        let mut req = request(domain, object, aid);
        req.delegation_id = Some(DelegationId {
            client,
            driver,
            incarnation: 1,
        });

        assert!(matches!(
            nic.submit_rx(req, &mut fabric),
            NicRxSubmitResult::Accepted(_)
        ));
        assert_eq!(nic.nonterminal_pair_request_count(&client, &driver), 1);

        for _ in 0..3 {
            nic.tick(&mut fabric);
        }
        assert_eq!(nic.nonterminal_pair_request_count(&client, &driver), 0,
            "terminal completion must no longer delay pair quiescence");
    }

    #[test]
    fn empty_frame_completes_without_zero_length_fabric_transaction() {
        let (mut fabric, domain, object, aid) = dma_fixture(0x1000);
        let mut nic = NicController::new(NIC_AGENT);
        assert!(nic.inject_rx(&[]));
        let domains_before = fabric.domain_count();
        let epoch = nic.event_sequence();

        let handle = match nic.submit_rx(request(domain, object, aid), &mut fabric) {
            NicRxSubmitResult::Accepted(h) => h,
            other => panic!("expected empty-frame acceptance, got {:?}", other),
        };

        assert_eq!(fabric.domain_count(), domains_before,
            "zero-byte RX must not mint an unusable zero-span DMA domain");
        assert_eq!(nic.rx_queue_len(), 0);
        assert!(!nic.has_autonomous_work());
        assert_eq!(nic.completion_count(), 1);
        assert_eq!(nic.event_sequence(), epoch);

        let completion = nic.consume_completion().unwrap();
        assert_eq!(completion.handle, handle);
        assert_eq!(completion.status, DeviceCompletionStatus::Success);
        assert_eq!(completion.transferred_len, 0);
    }

    #[test]
    fn third_rx_submission_is_busy_and_preserves_front_frame() {
        let (mut fabric, domain, object, aid) = dma_fixture(0x1000);
        let mut nic = NicController::new(NIC_AGENT);
        assert!(nic.inject_rx(&[0x10; 8]));
        assert!(nic.inject_rx(&[0x20; 8]));
        assert!(nic.inject_rx(&[0x30; 8]));

        assert!(matches!(
            nic.submit_rx(request(domain, object, aid), &mut fabric),
            NicRxSubmitResult::Accepted(_)
        ));
        assert!(matches!(
            nic.submit_rx(request(domain, object, aid), &mut fabric),
            NicRxSubmitResult::Accepted(_)
        ));
        assert_eq!(nic.free_slot_count(), 0);
        assert_eq!(nic.rx_queue_len(), 1);
        assert_eq!(nic.peek_rx(), Some([0x30; 8].as_slice()));
        let domains_before = fabric.domain_count();

        assert_eq!(
            nic.submit_rx(request(domain, object, aid), &mut fabric),
            NicRxSubmitResult::DeviceBusy,
        );
        assert_eq!(fabric.domain_count(), domains_before,
            "busy rejection must occur before any new DMA delegation");
        assert_eq!(nic.rx_queue_len(), 1);
        assert_eq!(nic.peek_rx(), Some([0x30; 8].as_slice()));
    }
}

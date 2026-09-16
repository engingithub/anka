//! NicController — bounded private RX + finite RX/TX DMA (Phase 9.3e.4).
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
//! Finite DMA semantics:
//!   * SYS_NIC_RX requires exact NIC_RX + guest-buffer WRITE authority.
//!   * SYS_NIC_TX requires exact NIC_TX + guest-buffer READ authority.
//!   * Both operations derive an exact narrow DMA domain before admission.
//!   * Accepted nonterminal DMA contributes to pair quiescence when the
//!     presented buffer carries DelegationId provenance.
//!   * RX completion does NOT advance the unsolicited-arrival epoch.
//!   * TX bytes come only from Fabric's committed read observation; the
//!     controller never peeks at physical memory after authorization.
//!
//! Frame size limit: untagged Ethernet (14-byte header + 1500 payload),
//! excluding FCS (stripped by hardware).  Does not imply 802.1Q VLAN
//! support.
//!
//! Formal basis: anka_userspace_nic.kleis and the focused 9.3e.4 gate.

use std::collections::VecDeque;

use super::fabric::{dma_request, Fabric};
use super::state::{
    AccessKind, AgentId, AuthorityId, DelegationId, DeviceCompletionStatus,
    DomainId, FaultReason, ObjectId, Permissions, ProcessKey, RequestHandle,
    RequesterKey, TxState,
};

/// Maximum accepted/transmitted frame size: 6 dst + 6 src + 2 EtherType +
/// 1500 payload. Excludes FCS (4 bytes, stripped by hardware).
pub const NIC_MAX_FRAME_SIZE: usize = 1514;

/// Bounded private RX queue capacity.
pub const NIC_RX_QUEUE_CAPACITY: usize = 16;

/// Number of finite DMA request slots shared by RX and TX.
const NUM_SLOTS: usize = 2;

/// Direction of one completed NIC finite-DMA operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicOperation {
    Rx,
    Tx,
}

/// One accepted finite RX-copy request.
#[derive(Debug, Clone)]
pub struct NicRxRequest {
    pub requester: RequesterKey,
    pub target_object: ObjectId,
    pub target_offset: u64,
    pub source_domain: DomainId,
    pub source_authority_id: AuthorityId,
    pub delegation_id: Option<DelegationId>,
}

/// One accepted finite TX-copy request.
///
/// `frame_len` is the exact byte span delegated from guest memory.  The bytes
/// themselves are not copied here; they are captured by Fabric at committed
/// READ and only then appended to the host-visible TX sink.
#[derive(Debug, Clone)]
pub struct NicTxRequest {
    pub requester: RequesterKey,
    pub source_object: ObjectId,
    pub source_offset: u64,
    pub source_domain: DomainId,
    pub source_authority_id: AuthorityId,
    pub frame_len: u64,
    pub delegation_id: Option<DelegationId>,
}

/// Completion of a finite NIC DMA request.
#[derive(Debug, Clone)]
pub struct NicCompletion {
    pub handle: RequestHandle,
    pub requester: RequesterKey,
    pub operation: NicOperation,
    pub status: DeviceCompletionStatus,
    /// Number of bytes committed by the operation. Zero on DMA fault.
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

/// Result of attempting to accept one finite TX request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicTxSubmitResult {
    Accepted(RequestHandle),
    DeviceBusy,
    DelegationFailed,
}

/// Per-slot lifecycle for finite NIC DMA.
///
/// Conservation: Free + Ready + InFlight + Completed = NUM_SLOTS.
#[derive(Debug)]
enum SlotState {
    Free,
    RxDmaReady {
        request: NicRxRequest,
        frame: Vec<u8>,
        dma_domain: DomainId,
    },
    TxDmaReady {
        request: NicTxRequest,
        dma_domain: DomainId,
    },
    DmaInFlight {
        requester: RequesterKey,
        operation: NicOperation,
        frame_len: u64,
        delegation_id: Option<DelegationId>,
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
        matches!(
            self,
            SlotState::RxDmaReady { .. }
                | SlotState::TxDmaReady { .. }
                | SlotState::DmaInFlight { .. }
        )
    }

    fn delegation_id(&self) -> Option<DelegationId> {
        match self {
            SlotState::RxDmaReady { request, .. } => request.delegation_id,
            SlotState::TxDmaReady { request, .. } => request.delegation_id,
            SlotState::DmaInFlight { delegation_id, .. } => *delegation_id,
            _ => None,
        }
    }
}

/// Minimal NIC controller with bounded private RX and two finite DMA slots.
#[derive(Debug)]
pub struct NicController {
    rx_queue: VecDeque<Vec<u8>>,
    /// Frames whose guest-memory READ has committed successfully and are now
    /// visible to the host backend.  This is not an Anka authority object;
    /// it is emulator/environment state.
    tx_sink: VecDeque<Vec<u8>>,
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
            tx_sink: VecDeque::new(),
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
    /// All semantic failure checks precede architectural mutation.
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
    /// Therefore any pre-admission failure implies ΔRXQueue = 0.
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
            // Empty private events preserve the pre-DMA 9.3e.3 semantics.
            self.rx_queue.pop_front();
            let completion = NicCompletion {
                handle,
                requester: request.requester,
                operation: NicOperation::Rx,
                status: DeviceCompletionStatus::Success,
                transferred_len: 0,
                delegation_id: request.delegation_id,
            };
            self.slots[idx] = SlotState::Completed { completion };
            self.completion_order.push_back(idx as u8);
            self.assert_conservation();
            return NicRxSubmitResult::Accepted(handle);
        }

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

        let frame = self.rx_queue.pop_front()
            .expect("front frame must remain present across atomic submission");

        self.slots[idx] = SlotState::RxDmaReady {
            request,
            frame,
            dma_domain,
        };
        self.assert_conservation();
        NicRxSubmitResult::Accepted(handle)
    }

    /// Accept a finite TX request for exact READ DMA from guest memory.
    ///
    /// The kernel preflights frame length, exact NIC_TX authority, exact READ
    /// authority, provenance and slot capacity before this call.  This method
    /// independently derives the exact READ span before making the request
    /// visible as controller work.
    pub fn submit_tx(
        &mut self,
        request: NicTxRequest,
        fabric: &mut Fabric,
    ) -> NicTxSubmitResult {
        let idx = match self.slots.iter().position(|s| s.is_free()) {
            Some(i) => i,
            None => return NicTxSubmitResult::DeviceBusy,
        };

        let dma_domain = match fabric.delegate_dma_span_from_authority_id(
            request.source_domain,
            request.source_authority_id,
            request.source_object,
            request.source_offset,
            request.frame_len,
            Permissions::READ,
        ) {
            Some(domain) => domain,
            None => return NicTxSubmitResult::DelegationFailed,
        };

        let handle = RequestHandle {
            slot: idx as u8,
            generation: self.slot_generations[idx],
        };
        self.slots[idx] = SlotState::TxDmaReady {
            request,
            dma_domain,
        };
        self.assert_conservation();
        NicTxSubmitResult::Accepted(handle)
    }

    /// Advance all accepted finite DMA work by one device tick.
    pub fn tick(&mut self, fabric: &mut Fabric) {
        // Ready -> DmaInFlight.
        for i in 0..NUM_SLOTS {
            if matches!(self.slots[i], SlotState::RxDmaReady { .. }) {
                let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                if let SlotState::RxDmaReady { request, frame, dma_domain } = state {
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
                        requester: request.requester,
                        operation: NicOperation::Rx,
                        frame_len,
                        delegation_id: request.delegation_id,
                        dma_domain,
                        tx_idx,
                    };
                }
            } else if matches!(self.slots[i], SlotState::TxDmaReady { .. }) {
                let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                if let SlotState::TxDmaReady { request, dma_domain } = state {
                    let dma_req = dma_request(
                        self.dma_agent,
                        dma_domain,
                        request.source_object,
                        request.source_offset,
                        request.frame_len,
                        AccessKind::Read,
                    );
                    let tx_idx = fabric.submit(dma_req, None);
                    self.slots[i] = SlotState::DmaInFlight {
                        requester: request.requester,
                        operation: NicOperation::Tx,
                        frame_len: request.frame_len,
                        delegation_id: request.delegation_id,
                        dma_domain,
                        tx_idx,
                    };
                }
            }
        }

        // InFlight -> advance one Fabric phase; terminal -> Completed.
        for i in 0..NUM_SLOTS {
            let tx_idx = match &self.slots[i] {
                SlotState::DmaInFlight { tx_idx, .. } => Some(*tx_idx),
                _ => None,
            };
            let Some(tx_idx) = tx_idx else { continue; };

            if !fabric.transaction(tx_idx).state.is_terminal() {
                fabric.advance(tx_idx);
            }

            if fabric.transaction(tx_idx).state.is_terminal() {
                let state = std::mem::replace(&mut self.slots[i], SlotState::Free);
                if let SlotState::DmaInFlight {
                    requester,
                    operation,
                    frame_len,
                    delegation_id,
                    dma_domain,
                    tx_idx,
                } = state
                {
                    let (status, transferred_len) = match fabric.transaction(tx_idx).state {
                        TxState::Committed => {
                            if operation == NicOperation::Tx {
                                let bytes = fabric.transaction(tx_idx).read_data.clone()
                                    .expect("committed NIC TX READ must retain read_data");
                                debug_assert_eq!(bytes.len() as u64, frame_len);
                                self.tx_sink.push_back(bytes);
                            }
                            (DeviceCompletionStatus::Success, frame_len)
                        }
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
                        requester,
                        operation,
                        status,
                        transferred_len,
                        delegation_id,
                    };
                    self.slots[i] = SlotState::Completed { completion };
                    self.completion_order.push_back(i as u8);
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
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Queued private RX and host-visible committed TX frames are inert.
    /// Only accepted nonterminal finite DMA is autonomous work.
    pub fn has_autonomous_work(&self) -> bool {
        self.slots.iter().any(|s| s.is_nonterminal())
    }

    /// Attention is the OR of arrival latch and ready completion.
    pub fn requires_attention(&self) -> bool {
        self.attention_pending || self.completion_count() != 0
    }

    /// Clear only the unsolicited-arrival notification latch.
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
    pub fn nonterminal_pair_request_count(
        &self,
        client: &ProcessKey,
        peer: &ProcessKey,
    ) -> usize {
        self.slots.iter().filter(|slot| {
            if !slot.is_nonterminal() {
                return false;
            }
            match slot.delegation_id() {
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

    /// Number of committed guest TX frames waiting for the host environment.
    pub fn tx_frame_count(&self) -> usize {
        self.tx_sink.len()
    }

    /// Peek at the oldest committed guest TX frame.
    pub fn peek_tx(&self) -> Option<&[u8]> {
        self.tx_sink.front().map(|v| v.as_slice())
    }

    /// Transfer one committed guest TX frame to the host environment.
    pub fn take_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_sink.pop_front()
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

    fn tx_dma_fixture(span: u64, bytes: &[u8]) -> (Fabric, DomainId, ObjectId, AuthorityId) {
        let mut fabric = Fabric::new(0x20000);
        let object = fabric.alloc_object("nic_tx_buf", 0x1000, ObjectKind::Memory);
        assert!(fabric.place_object(object, 0x5000));
        assert!(fabric.initialize_object(object, 0, bytes));
        let domain = fabric.create_domain();
        let aid = fabric.alloc_authority_id().expect("authority id");
        fabric.grant_with_authority_id(
            domain,
            object,
            0,
            span,
            Permissions::READ,
            aid,
        ).expect("READ authority");
        (fabric, domain, object, aid)
    }

    fn tx_request(
        domain: DomainId,
        object: ObjectId,
        aid: AuthorityId,
        frame_len: u64,
    ) -> NicTxRequest {
        NicTxRequest {
            requester: RequesterKey { slot: 1, generation: 2 },
            source_object: object,
            source_offset: 0,
            source_domain: domain,
            source_authority_id: aid,
            frame_len,
            delegation_id: None,
        }
    }

    #[test]
    fn tx_committed_read_becomes_host_visible_only_after_commit() {
        let frame: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_mul(3)).collect();
        let (mut fabric, domain, object, aid) = tx_dma_fixture(512, &frame);
        let mut nic = NicController::new(NIC_AGENT);

        let handle = match nic.submit_tx(
            tx_request(domain, object, aid, frame.len() as u64),
            &mut fabric,
        ) {
            NicTxSubmitResult::Accepted(h) => h,
            other => panic!("expected TX acceptance, got {:?}", other),
        };

        assert_eq!(nic.tx_frame_count(), 0,
            "accepted TX must not expose bytes before Fabric commit");
        assert!(nic.has_autonomous_work());

        for _ in 0..3 {
            nic.tick(&mut fabric);
        }

        assert_eq!(nic.tx_frame_count(), 1);
        assert_eq!(nic.peek_tx(), Some(frame.as_slice()));
        assert_eq!(nic.event_sequence(), 0,
            "driver-originated TX must not manufacture unsolicited RX activity");

        let completion = nic.consume_completion().expect("TX completion");
        assert_eq!(completion.handle, handle);
        assert_eq!(completion.operation, NicOperation::Tx);
        assert_eq!(completion.status, DeviceCompletionStatus::Success);
        assert_eq!(completion.transferred_len, frame.len() as u64);
        assert_eq!(nic.take_tx(), Some(frame));
        assert_eq!(nic.tx_frame_count(), 0);
    }

    #[test]
    fn tx_commit_time_revocation_produces_no_host_frame() {
        let frame = vec![0xA7; 80];
        let (mut fabric, domain, object, aid) = tx_dma_fixture(512, &frame);
        let mut nic = NicController::new(NIC_AGENT);

        assert!(matches!(
            nic.submit_tx(tx_request(domain, object, aid, frame.len() as u64), &mut fabric),
            NicTxSubmitResult::Accepted(_)
        ));

        // Advance through request creation/authorization, then invalidate the
        // object before commit-time revalidation.
        nic.tick(&mut fabric);
        nic.tick(&mut fabric);
        fabric.revoke(object);
        nic.tick(&mut fabric);

        assert_eq!(nic.tx_frame_count(), 0,
            "faulted READ must never append bytes to the host TX sink");
        let completion = nic.consume_completion().expect("fault completion");
        assert_eq!(completion.operation, NicOperation::Tx);
        assert!(matches!(completion.status, DeviceCompletionStatus::DmaFault(_)));
        assert_eq!(completion.transferred_len, 0);
    }

    #[test]
    fn third_tx_submission_is_busy_and_mints_no_dma_domain() {
        let frame = vec![0x39; 32];
        let (mut fabric, domain, object, aid) = tx_dma_fixture(512, &frame);
        let mut nic = NicController::new(NIC_AGENT);

        assert!(matches!(
            nic.submit_tx(tx_request(domain, object, aid, frame.len() as u64), &mut fabric),
            NicTxSubmitResult::Accepted(_)
        ));
        assert!(matches!(
            nic.submit_tx(tx_request(domain, object, aid, frame.len() as u64), &mut fabric),
            NicTxSubmitResult::Accepted(_)
        ));
        assert_eq!(nic.free_slot_count(), 0);
        let domains_before = fabric.domain_count();

        assert_eq!(
            nic.submit_tx(tx_request(domain, object, aid, frame.len() as u64), &mut fabric),
            NicTxSubmitResult::DeviceBusy,
        );
        assert_eq!(fabric.domain_count(), domains_before,
            "busy TX rejection must precede exact DMA delegation");
        assert_eq!(nic.tx_frame_count(), 0,
            "uncommitted/busy TX cannot become host-visible");
    }

    #[test]
    fn tx_sink_is_not_autonomous_work_or_device_attention() {
        let frame = vec![0x5C; 32];
        let (mut fabric, domain, object, aid) = tx_dma_fixture(512, &frame);
        let mut nic = NicController::new(NIC_AGENT);
        assert!(matches!(
            nic.submit_tx(tx_request(domain, object, aid, frame.len() as u64), &mut fabric),
            NicTxSubmitResult::Accepted(_)
        ));
        for _ in 0..3 { nic.tick(&mut fabric); }
        assert!(nic.requires_attention(), "ready completion is interrupt attention");
        let _ = nic.consume_completion().unwrap();
        assert!(!nic.has_autonomous_work());
        assert!(!nic.requires_attention(),
            "host-visible TX sink is passive environment state, not guest interrupt work");
        assert_eq!(nic.peek_tx(), Some(frame.as_slice()));
    }

}

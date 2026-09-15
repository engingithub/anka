//! NicController — bounded device-private RX queue (Phase 9.3e.3).
//!
//! Unsolicited packet arrival semantics:
//!   * Admitted frames enter a bounded device-private queue.
//!   * Successful admission increments the activity epoch exactly once
//!     and latches attention.
//!   * Arrival itself never mutates guest memory, creates a
//!     DeviceRequestKey, or produces a delegation.
//!   * Queued private RX is not pair-attributed work and does not
//!     constitute autonomous machine progress.
//!
//! Frame size limit: untagged Ethernet (14-byte header + 1500 payload),
//! excluding FCS (stripped by hardware).  Does not imply 802.1Q VLAN
//! support.
//!
//! Formal basis: anka93e3_nic_controller.kleis NIC93E3-1..32.

use std::collections::VecDeque;

use super::state::ProcessKey;

/// Maximum accepted frame size: 6 dst + 6 src + 2 EtherType + 1500 payload.
/// Excludes FCS (4 bytes, stripped by hardware).
pub const NIC_MAX_FRAME_SIZE: usize = 1514;

/// Bounded RX queue capacity.
pub const NIC_RX_QUEUE_CAPACITY: usize = 16;

/// A minimal NIC controller with bounded device-private RX queue.
///
/// No request/completion model, no DMA slots, no command submission.
/// Packets arrive unsolicited via `inject_rx` (host-driven) and sit in
/// device-private storage until a future authorized RX-copy operation
/// (9.3e.4) moves them into guest memory.
#[derive(Debug)]
pub struct NicController {
    rx_queue: VecDeque<Vec<u8>>,
    event_sequence: u64,
    attention_pending: bool,
}

impl NicController {
    pub fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            event_sequence: 0,
            attention_pending: false,
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
    /// latches attention.  Returns true.
    ///
    /// On failure (oversize, full, epoch exhaustion): no mutation.
    /// Returns false.
    ///
    /// Formal basis: anka93e3_nic_controller.kleis NIC93E3-2..8.
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

    /// Current activity-epoch sequence.
    ///
    /// Monotonic: only advances on successful `inject_rx`.
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Queued private RX is not autonomous machine work.
    ///
    /// No DMA is in flight; no state will advance without a driver action.
    /// Formal basis: NIC93E3-10.
    pub fn has_autonomous_work(&self) -> bool {
        false
    }

    /// Whether the attention latch is set.
    ///
    /// Attention is latched on successful `inject_rx` and cleared by
    /// `acknowledge_attention`.  This is distinct from queue occupancy:
    /// after acknowledgement, the queue may still be non-empty but
    /// attention is false.
    pub fn requires_attention(&self) -> bool {
        self.attention_pending
    }

    /// Clear the attention latch.
    ///
    /// Law: Ack(Q, e, true) = (Q, e, false).
    /// Does NOT dequeue frames or change the epoch.
    ///
    /// Formal basis: NIC93E3-15..17.
    pub fn acknowledge_attention(&mut self) {
        self.attention_pending = false;
    }

    /// NIC has no request/completion model in 9.3e.3.
    pub fn completion_count(&self) -> usize {
        0
    }

    /// NIC has no request/completion model in 9.3e.3.
    /// Always returns None.
    pub fn consume_completion(&mut self) -> Option<()> {
        None
    }

    /// Queued private RX does not contribute pair-attributed work.
    ///
    /// Formal basis: NIC93E3-9.
    pub fn nonterminal_pair_request_count(
        &self,
        _client: &ProcessKey,
        _peer: &ProcessKey,
    ) -> usize {
        0
    }

    /// Number of frames currently in the device-private RX queue.
    pub fn rx_queue_len(&self) -> usize {
        self.rx_queue.len()
    }

    /// Peek at the front of the RX queue without dequeuing.
    pub fn peek_rx(&self) -> Option<&[u8]> {
        self.rx_queue.front().map(|v| v.as_slice())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_rx_succeeds() {
        let mut nic = NicController::new();
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
        let mut nic = NicController::new();
        let frame = vec![0u8; NIC_MAX_FRAME_SIZE]; // 1514 bytes
        assert!(nic.inject_rx(&frame));
        assert_eq!(nic.event_sequence(), 1);
        assert_eq!(nic.rx_queue_len(), 1);
    }

    #[test]
    fn inject_rx_empty_frame() {
        let mut nic = NicController::new();
        assert!(nic.inject_rx(&[]));
        assert_eq!(nic.event_sequence(), 1);
        assert_eq!(nic.rx_queue_len(), 1);
    }

    #[test]
    fn inject_rx_oversize_rejected() {
        let mut nic = NicController::new();
        let frame = vec![0u8; NIC_MAX_FRAME_SIZE + 1]; // 1515 bytes
        assert!(!nic.inject_rx(&frame));
        assert_eq!(nic.event_sequence(), 0);
        assert_eq!(nic.rx_queue_len(), 0);
        assert!(!nic.requires_attention());
    }

    #[test]
    fn inject_rx_full_queue_rejected() {
        let mut nic = NicController::new();
        for i in 0..NIC_RX_QUEUE_CAPACITY {
            assert!(nic.inject_rx(&[i as u8; 64]),
                "injection {} should succeed", i);
        }
        assert_eq!(nic.rx_queue_len(), NIC_RX_QUEUE_CAPACITY);
        assert_eq!(nic.event_sequence(), NIC_RX_QUEUE_CAPACITY as u64);

        // 17th injection must fail
        let epoch_before = nic.event_sequence();
        assert!(!nic.inject_rx(&[0xFF; 64]));
        assert_eq!(nic.event_sequence(), epoch_before);
        assert_eq!(nic.rx_queue_len(), NIC_RX_QUEUE_CAPACITY);
    }

    #[test]
    fn acknowledge_attention_clears_latch() {
        let mut nic = NicController::new();
        assert!(nic.inject_rx(&[1, 2, 3]));
        assert!(nic.requires_attention());
        let epoch = nic.event_sequence();
        let len = nic.rx_queue_len();

        nic.acknowledge_attention();

        // Ack(Q, e, true) = (Q, e, false)
        assert!(!nic.requires_attention());
        assert_eq!(nic.event_sequence(), epoch);
        assert_eq!(nic.rx_queue_len(), len);
        assert_eq!(nic.peek_rx(), Some([1u8, 2, 3].as_slice()));
    }

    #[test]
    fn requires_attention_is_latch_not_queue() {
        let mut nic = NicController::new();
        assert!(nic.inject_rx(&[1]));
        assert!(nic.requires_attention());

        nic.acknowledge_attention();
        assert!(!nic.requires_attention());
        // Queue is still non-empty
        assert_eq!(nic.rx_queue_len(), 1);
    }

    #[test]
    fn has_autonomous_work_always_false() {
        let mut nic = NicController::new();
        assert!(!nic.has_autonomous_work());
        nic.inject_rx(&[0; 64]);
        assert!(!nic.has_autonomous_work());
    }

    #[test]
    fn completion_count_always_zero() {
        let mut nic = NicController::new();
        assert_eq!(nic.completion_count(), 0);
        nic.inject_rx(&[0; 64]);
        assert_eq!(nic.completion_count(), 0);
    }

    #[test]
    fn pair_request_count_always_zero() {
        let mut nic = NicController::new();
        let pk = ProcessKey { slot: 0, generation: 0 };
        assert_eq!(nic.nonterminal_pair_request_count(&pk, &pk), 0);
        nic.inject_rx(&[0; 64]);
        assert_eq!(nic.nonterminal_pair_request_count(&pk, &pk), 0);
    }

    #[test]
    fn epoch_overflow_rejected() {
        let mut nic = NicController::new();
        // Force epoch to u64::MAX
        nic.event_sequence = u64::MAX;
        let queue_before = nic.rx_queue_len();
        let attn_before = nic.requires_attention();

        assert!(!nic.inject_rx(&[0; 64]));
        assert_eq!(nic.event_sequence(), u64::MAX);
        assert_eq!(nic.rx_queue_len(), queue_before);
        assert_eq!(nic.requires_attention(), attn_before);
    }
}

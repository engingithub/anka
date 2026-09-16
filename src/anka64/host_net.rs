//! Host-controlled virtual NIC backends (Phase 9.3f).
//!
//! This module is deliberately outside Anka's guest capability model.  A
//! backend represents emulator/environment policy: it may observe a frame that
//! has already completed SYS_NIC_TX and may later offer a frame for explicit
//! host injection through `Kernel::inject_nic_rx`.
//!
//! Crucial separation:
//!   Guest TX completion != physical-network transmission.
//!   Backend RX availability != guest-memory mutation.
//!   Loopback is one host policy, never a NicController law.

use std::collections::VecDeque;

use super::state::DeviceBinding;

/// Opaque Ethernet-frame-sized byte sequence qualified by exact virtual-NIC
/// identity.  The backend does not interpret the bytes at this layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNicFrame {
    pub device: DeviceBinding,
    pub bytes: Vec<u8>,
}

impl HostNicFrame {
    pub fn new(device: DeviceBinding, bytes: Vec<u8>) -> Self {
        Self { device, bytes }
    }
}

/// Host policy boundary for a virtual NIC.
///
/// `accept_guest_tx` is called only after Anka's finite TX DMA has committed
/// and the host has explicitly extracted the frame from the controller.
/// `poll_rx` merely offers host/environment state; the host must still call
/// `Kernel::inject_nic_rx` explicitly to admit it into a NIC-private RX queue.
pub trait HostNicBackend {
    fn accept_guest_tx(&mut self, frame: HostNicFrame);
    fn poll_rx(&mut self) -> Option<HostNicFrame>;
}

/// Deterministic Ethernet-level loopback policy.
///
/// Every accepted guest TX frame is recorded exactly and queued unchanged as
/// a future host RX offer for the same DeviceBinding.  Nothing is injected into
/// Anka automatically.
#[derive(Debug, Default)]
pub struct LoopbackBackend {
    observed_tx: VecDeque<HostNicFrame>,
    pending_rx: VecDeque<HostNicFrame>,
}

impl LoopbackBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observed_tx_count(&self) -> usize {
        self.observed_tx.len()
    }

    pub fn pending_rx_count(&self) -> usize {
        self.pending_rx.len()
    }

    pub fn pop_observed_tx(&mut self) -> Option<HostNicFrame> {
        self.observed_tx.pop_front()
    }
}

impl HostNicBackend for LoopbackBackend {
    fn accept_guest_tx(&mut self, frame: HostNicFrame) {
        self.observed_tx.push_back(frame.clone());
        self.pending_rx.push_back(frame);
    }

    fn poll_rx(&mut self) -> Option<HostNicFrame> {
        self.pending_rx.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::state::{Generation, ObjectId};

    fn binding(n: u64) -> DeviceBinding {
        DeviceBinding {
            object: ObjectId(n),
            generation: Generation(3),
        }
    }

    #[test]
    fn loopback_preserves_exact_binding_and_bytes() {
        let mut backend = LoopbackBackend::new();
        let frame = HostNicFrame::new(binding(40), vec![1, 2, 3, 4, 5]);
        backend.accept_guest_tx(frame.clone());

        assert_eq!(backend.observed_tx_count(), 1);
        assert_eq!(backend.pending_rx_count(), 1);
        assert_eq!(backend.pop_observed_tx(), Some(frame.clone()));
        assert_eq!(backend.poll_rx(), Some(frame));
    }

    #[test]
    fn loopback_is_explicit_policy_not_spontaneous_rx() {
        let mut backend = LoopbackBackend::new();
        assert!(backend.poll_rx().is_none());
        assert_eq!(backend.pending_rx_count(), 0);
    }

    #[test]
    fn loopback_keeps_distinct_nic_bindings_distinct() {
        let mut backend = LoopbackBackend::new();
        backend.accept_guest_tx(HostNicFrame::new(binding(40), vec![0xAA]));
        backend.accept_guest_tx(HostNicFrame::new(binding(41), vec![0xBB]));

        let a = backend.poll_rx().unwrap();
        let b = backend.poll_rx().unwrap();
        assert_ne!(a.device, b.device);
        assert_eq!(a.bytes, vec![0xAA]);
        assert_eq!(b.bytes, vec![0xBB]);
    }
}

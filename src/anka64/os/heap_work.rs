//! Trusted heap work entry points. No guest syscall, DMA adapter or automatic
//! scheduler loop. The supervisor can explicitly advance the bounded backend.
use super::{CurrentHeapProcess, Kernel};
use crate::anka64::fabric::HeapWorkTicket;
use crate::anka64::scoped_pointers::{
    ScopedPointer,
    heap::{AllocationOwner, CleanupLease, HeapError},
};
use crate::anka64::state::{ObjectId, ProcessKey};

impl Kernel {
    /// Trusted cleanup dispatch: rechecks the current enrolled worker. The
    /// result is observational and cannot be passed as a reclamation permit.
    pub(crate) fn heap_cleanup_ready(
        &mut self,
        key: ProcessKey,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<bool, HeapError> {
        let current =
            CurrentHeapProcess::from_processes(&self.processes, key).ok_or(HeapError::Worker)?;
        self.fabric
            .heap_cleanup_ready(&current, lease, owner, object)
    }

    /// The key comes from trusted dispatch; the opaque pointer comes from
    /// protected-kind decoding. No integer-to-pointer conversion is available.
    pub(crate) fn register_heap_cpu_read(
        &mut self,
        key: ProcessKey,
        pointer: Option<ScopedPointer>,
        length: u64,
        expected: u64,
    ) -> Result<HeapWorkTicket, HeapError> {
        let current =
            CurrentHeapProcess::from_processes(&self.processes, key).ok_or(HeapError::Owner)?;
        self.fabric
            .register_heap_cpu_read(&current, pointer, length, expected)
    }

    pub(crate) fn register_heap_cpu_write(
        &mut self,
        key: ProcessKey,
        pointer: Option<ScopedPointer>,
        bytes: &[u8],
        expected: u64,
    ) -> Result<HeapWorkTicket, HeapError> {
        let current =
            CurrentHeapProcess::from_processes(&self.processes, key).ok_or(HeapError::Owner)?;
        self.fabric
            .register_heap_cpu_write(&current, pointer, bytes, expected)
    }
}

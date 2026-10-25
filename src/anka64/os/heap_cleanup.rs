//! Trusted cleanup dispatch. C/syscall publication is the next functional step.
use super::{CurrentHeapRetirement, Kernel};
use crate::anka64::fabric::HeapCleanupSnapshot;
use crate::anka64::scoped_pointers::heap::{AllocationOwner, CleanupLease, HeapError};
use crate::anka64::state::{ObjectId, ProcessKey};

impl Kernel {
    pub(crate) fn begin_heap_scrub(
        &mut self,
        key: ProcessKey,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<HeapCleanupSnapshot, HeapError> {
        let current = CurrentHeapRetirement::from_processes(&self.processes, key, object)?;
        self.fabric.begin_heap_scrub(&current, lease, owner)
    }

    pub(crate) fn scrub_heap_chunk(
        &mut self,
        key: ProcessKey,
        snapshot: HeapCleanupSnapshot,
        amount: u64,
    ) -> Result<HeapCleanupSnapshot, HeapError> {
        let current =
            CurrentHeapRetirement::from_processes(&self.processes, key, snapshot.object())?;
        self.fabric.scrub_heap_chunk(&current, snapshot, amount)
    }

    pub(crate) fn release_clean_heap(
        &mut self,
        key: ProcessKey,
        snapshot: HeapCleanupSnapshot,
    ) -> Result<(), HeapError> {
        let current =
            CurrentHeapRetirement::from_processes(&self.processes, key, snapshot.object())?;
        self.fabric.release_clean_heap(&current, snapshot)
    }
}

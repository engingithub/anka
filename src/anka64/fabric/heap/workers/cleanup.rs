//! Synchronous, bounded scrub and atomic release. No guest authority issuance.
use super::*;
use crate::anka64::scoped_pointers::heap::HeapCleanupStatus;

/// Copies are harmless. Each operation checks the exact current private row,
/// job, progress/version/sequence, lease and live worker again. Never accepted
/// by new-lifetime initialization/publication or any application access path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapCleanupSnapshot {
    row: PrivateHeapRow,
    status: HeapCleanupStatus,
}

impl HeapCleanupSnapshot {
    pub(crate) fn object(self) -> ObjectId {
        self.row.object
    }
    pub(crate) fn completed_bytes(self) -> u64 {
        self.status.done(self.rounded_bytes())
    }
    pub(crate) fn rounded_bytes(self) -> u64 {
        self.row.extents.physical.size
    }
    pub(crate) fn is_complete(self) -> bool {
        self.status.is_clean()
    }
    pub(crate) fn version(self) -> u64 {
        self.status.version()
    }
}

impl Fabric {
    pub(crate) fn begin_heap_scrub(
        &mut self,
        current: &CurrentHeapRetirement<'_>,
        lease: CleanupLease,
        owner: AllocationOwner,
    ) -> Result<HeapCleanupSnapshot, HeapError> {
        let identity = self.checked_cleanup_descriptor(current.worker())?;
        let plan = self
            .scoped_pointers
            .prepare_heap_scrub_begin(lease, identity, owner)?;
        self.check_heap_cleanup_drain(plan.closure(), current.object())?;
        let row = self.private_heap.as_ref().unwrap().rows[plan.closure().slot()].unwrap();
        let status = self.scoped_pointers.commit_heap_scrub(plan);
        Ok(HeapCleanupSnapshot { row, status })
    }

    fn check_cleanup_snapshot_row(
        &mut self,
        current: &CurrentHeapRetirement<'_>,
        snapshot: HeapCleanupSnapshot,
        plan: &crate::anka64::scoped_pointers::heap::HeapClosurePlan,
    ) -> Result<(), HeapError> {
        if current.object() != snapshot.row.object {
            return Err(HeapError::StaleCleanup);
        }
        self.check_heap_cleanup_drain(plan, current.object())?;
        if self.private_heap.as_ref().unwrap().rows[plan.slot()] != Some(snapshot.row) {
            return Err(HeapError::StaleCleanup);
        }
        Ok(())
    }

    /// One aligned prefix chunk, at most 4096 bytes including rounded padding.
    /// No callback/yield/outstanding scrub request exists between admission and
    /// the terminal byte/tag/progress commit. Invalid requests change nothing.
    pub(crate) fn scrub_heap_chunk(
        &mut self,
        current: &CurrentHeapRetirement<'_>,
        snapshot: HeapCleanupSnapshot,
        amount: u64,
    ) -> Result<HeapCleanupSnapshot, HeapError> {
        let identity = self.checked_cleanup_descriptor(current.worker())?;
        let plan = self.scoped_pointers.prepare_heap_scrub_chunk(
            snapshot.status,
            identity,
            snapshot.row.owner,
            amount,
        )?;
        self.check_cleanup_snapshot_row(current, snapshot, plan.closure())?;
        let extents = plan.closure().extents();
        let offset = plan.before().done(extents.physical.size);
        let span =
            self.checked_heap_backing_span(extents.physical.size, extents, offset, amount, false)?;
        // All indices, identities, counters and exclusions passed. No fallible
        // step remains: bytes, tags and the completed prefix linearize together.
        self.memory[span.bytes].fill(0);
        self.private_heap.as_mut().unwrap().shadow[span.shadow].fill(None);
        let status = self.scoped_pointers.commit_heap_scrub(plan);
        Ok(HeapCleanupSnapshot {
            row: snapshot.row,
            status,
        })
    }

    /// Return clean custody once. No whole-payload rescan: contiguous chunks
    /// establish zero bytes/tags, and all enabled writers reject Retired storage.
    /// The exact current prefix plus fresh exclusion checks preserve that fact.
    /// A cleanup snapshot alone never authorizes a later allocation to publish.
    pub(crate) fn release_clean_heap(
        &mut self,
        current: &CurrentHeapRetirement<'_>,
        snapshot: HeapCleanupSnapshot,
    ) -> Result<(), HeapError> {
        let identity = self.checked_cleanup_descriptor(current.worker())?;
        let plan = self.scoped_pointers.prepare_heap_release(
            snapshot.status,
            identity,
            snapshot.row.owner,
        )?;
        self.check_cleanup_snapshot_row(current, snapshot, plan.closure())?;
        let slot = plan.closure().slot();
        // Both manager returns were prepared before any mutation. Rust's one
        // exclusive borrow covers row removal, exact refunds and slot release.
        self.scoped_pointers.commit_heap_release(plan);
        self.private_heap.as_mut().unwrap().rows[slot] = None;
        // Keep fixed capacity/shadow charge and the nonrewinding ObjectId floor.
        Ok(())
    }
}

pub(super) fn snapshot(row: PrivateHeapRow, status: HeapCleanupStatus) -> HeapCleanupSnapshot { HeapCleanupSnapshot { row, status } }

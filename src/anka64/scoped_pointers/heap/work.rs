//! A2.3.5b work admissions share the common allocation/closure revision.
use super::*;

/// Same-operation preparation only; never retained across a yield.
#[derive(Debug)]
pub(crate) struct HeapWorkRevision(u64);

/// Same-exclusive-operation cleanup snapshot, including saturated revision.
/// Numerical equality never permits caching this across a yield.
pub(crate) struct HeapWorkCleanupRevision(u64);

impl ScopedPointers {
    pub(crate) fn prepare_heap_work_cleanup_revision(&self) -> HeapWorkCleanupRevision {
        HeapWorkCleanupRevision(self.heap.revision)
    }

    pub(crate) fn commit_heap_work_cleanup_revision(&mut self, plan: HeapWorkCleanupRevision) {
        assert_eq!(self.heap.revision, plan.0, "stale internal work cleanup");
        self.heap.advance();
    }

    /// Retained work survives application closure, but must still name the
    /// exact previously-published allocation and its retained cleanup/extent rows.
    pub(crate) fn prepare_retained_heap_work(
        &self,
        reservation: HeapReservation,
        owner: AllocationOwner,
    ) -> Result<HeapClosurePlan, HeapError> {
        let plan = self.prepare_attached_heap_closure(reservation, owner)?;
        let record = self.reservation_record(reservation)?;
        if !record.published
            || !matches!(
                self.slots[reservation.slot].state,
                SlotState::Live | SlotState::Closing
            )
        {
            return Err(HeapError::StaleWork);
        }
        Ok(plan)
    }

    pub(crate) fn prepare_heap_work_revision(
        &self,
        expected: u64,
    ) -> Result<HeapWorkRevision, HeapError> {
        if expected != self.heap.revision || expected == u64::MAX {
            return Err(HeapError::StaleRevision);
        }
        Ok(HeapWorkRevision(expected))
    }

    /// Only the already-prepared fixed Fabric rows may change between the
    /// preflight and this commit, under the same exclusive Fabric operation.
    pub(crate) fn commit_heap_work_revision(&mut self, plan: HeapWorkRevision) {
        assert_eq!(self.heap.revision, plan.0, "stale internal work admission");
        assert_ne!(plan.0, u64::MAX);
        self.heap.advance();
    }
}

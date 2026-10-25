//! A2.3.7: ut108_retire / conc107_retire. No scrub, slot reuse or refund.
use super::*;

/// Ephemeral preparation, consumed in the SAME exclusive Fabric operation.
/// In particular the saturated revision is not a reusable freshness token.
#[derive(Debug)]
pub(crate) struct HeapRetirementPlan {
    closure: HeapClosurePlan,
    lease: CleanupLease,
    cleanup: usize,
    revision: u64,
}

impl HeapRetirementPlan {
    pub(crate) fn closure(&self) -> &HeapClosurePlan {
        &self.closure
    }
}

impl ScopedPointers {
    pub(crate) fn prepare_heap_retirement(
        &self,
        lease: CleanupLease,
        identity: CleanupWorkerIdentity,
        owner: AllocationOwner,
    ) -> Result<HeapRetirementPlan, HeapError> {
        let closure = self.prepare_heap_worker_lease(lease, identity, owner)?;
        if closure.is_retired() {
            return Err(HeapError::Lease);
        }
        let cleanup = self.reservation_record(lease.reservation)?.cleanup;
        Ok(HeapRetirementPlan {
            closure,
            lease,
            cleanup,
            revision: self.heap.revision,
        })
    }

    /// Reject even stale/inactive local backing records: retirement must not
    /// infer absence from a token lookup that filters away conflicting rows.
    pub(crate) fn local_backing_references(&self, object: crate::anka64::state::ObjectId) -> bool {
        self.slots.iter().any(|s| match s.record {
            Record::Local(local) => local.backing.is_some_and(|b| b.object == object),
            _ => false,
        })
    }

    /// Fabric has rechecked custody, zero unconsumed work and absence of legacy
    /// authority/maps, while Kernel holds all process descriptors borrowed.
    /// All fallible work precedes this fixed-row-only commit.
    pub(crate) fn commit_heap_retirement(&mut self, plan: HeapRetirementPlan) {
        assert_eq!(
            self.heap.revision, plan.revision,
            "stale internal retirement plan"
        );
        let job = self.heap.cleanup[plan.cleanup].expect("checked cleanup row");
        assert_eq!(job.reservation, plan.lease.reservation);
        assert!(job.queued);
        assert_eq!(
            job.lease,
            JobLease::Held {
                epoch: plan.lease.epoch,
                worker: plan.lease.worker
            }
        );
        let slot = &mut self.slots[plan.lease.reservation.slot];
        assert_eq!(slot.generation, plan.lease.reservation.generation);
        assert_eq!(slot.state, SlotState::Closing);
        slot.state = SlotState::Retired;
        self.heap.advance();
        // Keep the job/lease/version, record, generation, placement and charges.
        // Stored aliases remain inert: every application path requires Live.
    }
}

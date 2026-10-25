//! Fenced recovery through queued, retired, scrubbing and clean stages.
//! Synchronous scrub effects cannot survive a call; progress restarts at zero.
use super::*;

/// Preparation and commit stay within ONE exclusive Fabric operation.
/// Never reuse this plan after a yield, even at saturated common revision.
#[derive(Debug)]
pub(crate) struct HeapWorkerRecoveryPlan {
    closure: HeapClosurePlan,
    cleanup: usize,
    prior: CleanupRecord,
    next_lease: JobLease,
    next_version: u64,
    revision: u64,
}

impl HeapWorkerRecoveryPlan {
    pub(crate) fn closure(&self) -> &HeapClosurePlan {
        &self.closure
    }
}

impl ScopedPointers {
    fn prepare_worker_transition(
        &self,
        lease: CleanupLease,
        owner: AllocationOwner,
        recover: bool,
    ) -> Result<HeapWorkerRecoveryPlan, HeapError> {
        // The retained role is authoritative after process/domain death.
        // A caller cannot replace it with a new process using the same slot.
        let worker = self.worker(lease.worker)?;
        let closure = self.prepare_attached_heap_closure(lease.reservation, owner)?;
        let record = self.reservation_record(lease.reservation)?;
        let job = self.heap.cleanup[record.cleanup].ok_or(HeapError::StaleReservation)?;
        if !matches!(
            self.slots[lease.reservation.slot].state,
            SlotState::Closing | SlotState::Retired
        ) || !job.queued
        {
            return Err(HeapError::Busy);
        }
        let expected = if recover {
            JobLease::Revoking {
                epoch: lease.epoch,
                worker: lease.worker,
            }
        } else {
            JobLease::Held {
                epoch: lease.epoch,
                worker: lease.worker,
            }
        };
        if lease.epoch == 0 || job.lease != expected {
            return Err(HeapError::Lease);
        }
        let (next_lease, next_version) = if recover {
            if worker.state != WorkerState::Fenced {
                return Err(HeapError::Worker);
            }
            // Recovery invalidates every old cleanup snapshot. A partial or
            // clean prefix restarts at retired/Pending; sequence is retained.
            // Private initialization history is separate and unchanged.
            let version = job
                .version
                .checked_add(1)
                .ok_or(HeapError::Capacity(Resource::Identity))?;
            (JobLease::Unowned { epoch: lease.epoch }, version)
        } else {
            // Fencing per-job admission consumes no identity/version headroom.
            // Global worker fencing may occur before or after this transition.
            (
                JobLease::Revoking {
                    epoch: lease.epoch,
                    worker: lease.worker,
                },
                job.version,
            )
        };
        Ok(HeapWorkerRecoveryPlan {
            closure,
            cleanup: record.cleanup,
            prior: job,
            next_lease,
            next_version,
            revision: self.heap.revision,
        })
    }

    pub(crate) fn prepare_heap_worker_revoke(
        &self,
        lease: CleanupLease,
        owner: AllocationOwner,
    ) -> Result<HeapWorkerRecoveryPlan, HeapError> {
        self.prepare_worker_transition(lease, owner, false)
    }

    pub(crate) fn prepare_heap_worker_recovery(
        &self,
        lease: CleanupLease,
        owner: AllocationOwner,
    ) -> Result<HeapWorkerRecoveryPlan, HeapError> {
        self.prepare_worker_transition(lease, owner, true)
    }

    /// Fabric has validated custody and, for recovery, current backend census
    /// and exclusion. Only fixed metadata writes remain. No quota is returned.
    pub(crate) fn commit_heap_worker_recovery(&mut self, plan: HeapWorkerRecoveryPlan) {
        assert_eq!(
            self.heap.revision, plan.revision,
            "stale internal recovery plan"
        );
        assert_eq!(self.heap.cleanup[plan.cleanup], Some(plan.prior));
        let job = self.heap.cleanup[plan.cleanup].as_mut().unwrap();
        job.lease = plan.next_lease;
        job.version = plan.next_version;
        if matches!(plan.next_lease, JobLease::Unowned { .. }) {
            job.progress = HeapScrubProgress::Pending;
        }
        self.heap.advance();
    }
}

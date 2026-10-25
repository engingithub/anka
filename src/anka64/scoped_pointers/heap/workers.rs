//! A2.3.5a: fixed cleanup-worker roles and leases on existing pending jobs.
//! The Kernel/Fabric boundary establishes current descriptors. These registry
//! operations share the allocation revision and never perform memory effects.
use super::*;
mod cleanup;
mod recovery;
mod retirement;
pub(crate) use cleanup::{HeapCleanupPlan, HeapCleanupStatus, HeapReleasePlan, HeapScrubProgress};
pub(crate) use recovery::HeapWorkerRecoveryPlan;
pub(crate) use retirement::HeapRetirementPlan;

/// Separate from AllocationOwner: owning allocations never grants this role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CleanupWorkerIdentity {
    pub process: ProcessKey,
    pub context: u64,
    pub domain: DomainId,
}

/// One-based directory row plus a registry-wide, nonreused serial. No integer
/// constructor or guest encoding is exposed; possession alone is insufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CleanupWorker {
    row: u32,
    serial: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    Active,
    Fenced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WorkerRecord {
    handle: CleanupWorker,
    identity: CleanupWorkerIdentity,
    state: WorkerState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JobLease {
    Unowned { epoch: u64 },
    Held { epoch: u64, worker: CleanupWorker },
    // Per-job admission is fenced; reclaiming this lease also requires the
    // retained worker's global fence and current backend exclusion checks.
    Revoking { epoch: u64, worker: CleanupWorker },
}

impl JobLease {
    pub(super) const EMPTY: Self = Self::Unowned { epoch: 0 };

    fn refers_to(self, handle: CleanupWorker) -> bool {
        match self {
            Self::Held { worker, .. } | Self::Revoking { worker, .. } => worker == handle,
            Self::Unowned { .. } => false,
        }
    }
}

/// Opaque metadata receipt, NOT authority to bytes, a drain result or a reusable
/// readiness certificate. Every use must authenticate the current worker/job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CleanupLease {
    reservation: HeapReservation,
    worker: CleanupWorker,
    epoch: u64,
}

#[derive(Debug)]
pub(crate) struct HeapWorkerClaimPlan {
    closure: HeapClosurePlan,
    cleanup: usize,
    prior: JobLease,
    lease: CleanupLease,
    revision: u64,
}

impl HeapWorkerClaimPlan {
    pub(crate) fn closure(&self) -> &HeapClosurePlan {
        &self.closure
    }
}

pub(super) fn record_scratch_bytes() -> Result<u64, HeapError> {
    bytes::<WorkerRecord>(1)?
        .checked_add(bytes::<CleanupRecord>(1)?)
        .ok_or(HeapError::Configuration)
}

impl ScopedPointers {
    /// Construction only. There is no table growth/reconfiguration after the
    /// registry is returned. Inline directory/serial and the cleanup extension
    /// are already charged by with_limits; add retained worker rows once.
    pub(crate) fn with_heap_placement_and_workers(
        limits: RegistryLimits,
        placement: HeapPlacementLimits,
        capacity: usize,
    ) -> Result<Self, HeapError> {
        if capacity > u32::MAX as usize {
            return Err(HeapError::Configuration);
        }
        let mut registry = Self::with_heap_placement(limits, placement)?;
        let remaining = limits.global_bytes - registry.fixed_metadata_bytes();
        if bytes::<Option<WorkerRecord>>(capacity)? > remaining {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let rows = fixed_table(capacity, None)?;
        let retained = bytes::<Option<WorkerRecord>>(rows.capacity())?;
        if retained > remaining {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        registry.heap.fixed_bytes += retained;
        registry.heap.workers = rows;
        Ok(registry)
    }

    fn worker(&self, handle: CleanupWorker) -> Result<&WorkerRecord, HeapError> {
        let index = handle.row.checked_sub(1).ok_or(HeapError::Worker)? as usize;
        self.heap
            .workers
            .get(index)
            .and_then(Option::as_ref)
            .filter(|r| handle.serial != 0 && r.handle == handle)
            .ok_or(HeapError::Worker)
    }

    pub(crate) fn current_worker(
        &self,
        handle: CleanupWorker,
        identity: CleanupWorkerIdentity,
    ) -> Result<(), HeapError> {
        let row = self.worker(handle)?;
        if row.state != WorkerState::Active || identity.context == 0 || row.identity != identity {
            return Err(HeapError::Worker);
        }
        Ok(())
    }

    /// Trusted role-granting primitive; only the Kernel enrollment boundary
    /// supplies the current descriptor. No application PID/owner grants a role.
    pub(crate) fn enroll_cleanup_worker_record(
        &mut self,
        identity: CleanupWorkerIdentity,
        expected: u64,
    ) -> Result<CleanupWorker, HeapError> {
        if expected != self.heap.revision || expected == u64::MAX {
            return Err(HeapError::StaleRevision);
        }
        if identity.context == 0
            || self
                .heap
                .workers
                .iter()
                .flatten()
                .any(|r| r.identity.process == identity.process)
        {
            return Err(HeapError::Worker);
        }
        if self.heap.next_worker == 0 || self.heap.next_worker == u64::MAX {
            return Err(HeapError::Capacity(Resource::Identity));
        }
        let index = self
            .heap
            .workers
            .iter()
            .position(Option::is_none)
            .ok_or(HeapError::Capacity(Resource::Workers))?;
        let handle = CleanupWorker {
            row: index as u32 + 1,
            serial: self.heap.next_worker,
        };
        self.heap.workers[index] = Some(WorkerRecord {
            handle,
            identity,
            state: WorkerState::Active,
        });
        self.heap.next_worker += 1;
        self.heap.advance();
        Ok(handle)
    }

    /// Claim queued jobs or recovered retired jobs. Scrubbing/clean jobs must
    /// first pass fenced recovery, which resets their progress to Pending.
    /// Claim grants a role lease, never byte access or a reusable drain permit.
    pub(crate) fn prepare_heap_worker_claim(
        &self,
        worker: CleanupWorker,
        identity: CleanupWorkerIdentity,
        reservation: HeapReservation,
        owner: AllocationOwner,
        expected: u64,
    ) -> Result<HeapWorkerClaimPlan, HeapError> {
        if expected != self.heap.revision || expected == u64::MAX {
            return Err(HeapError::StaleRevision);
        }
        self.current_worker(worker, identity)?;
        let closure = self.prepare_attached_heap_closure(reservation, owner)?;
        let record = self.reservation_record(reservation)?;
        let job = self.heap.cleanup[record.cleanup].ok_or(HeapError::StaleReservation)?;
        if !matches!(
            self.slots[reservation.slot].state,
            SlotState::Closing | SlotState::Retired
        ) || !job.queued
            || job.progress != HeapScrubProgress::Pending
        {
            return Err(HeapError::Busy);
        }
        let JobLease::Unowned { epoch } = job.lease else {
            return Err(HeapError::Lease);
        };
        let epoch = epoch
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        Ok(HeapWorkerClaimPlan {
            closure,
            cleanup: record.cleanup,
            prior: job.lease,
            lease: CleanupLease {
                reservation,
                worker,
                epoch,
            },
            revision: expected,
        })
    }

    /// Called only after Fabric rechecks its custody row in the same exclusive
    /// operation. No allocation, fallible work or queue removal remains.
    pub(crate) fn commit_heap_worker_claim(&mut self, plan: HeapWorkerClaimPlan) -> CleanupLease {
        assert_eq!(
            self.heap.revision, plan.revision,
            "stale internal worker plan"
        );
        let job = self.heap.cleanup[plan.cleanup]
            .as_mut()
            .expect("checked cleanup row");
        assert_eq!(job.reservation, plan.lease.reservation);
        assert!(job.queued);
        assert_eq!(job.lease, plan.prior);
        job.lease = JobLease::Held {
            epoch: plan.lease.epoch,
            worker: plan.lease.worker,
        };
        self.heap.advance();
        plan.lease
    }

    pub(crate) fn prepare_heap_worker_lease(
        &self,
        lease: CleanupLease,
        identity: CleanupWorkerIdentity,
        owner: AllocationOwner,
    ) -> Result<HeapClosurePlan, HeapError> {
        self.current_worker(lease.worker, identity)?;
        let plan = self.prepare_attached_heap_closure(lease.reservation, owner)?;
        let record = self.reservation_record(lease.reservation)?;
        let job = self.heap.cleanup[record.cleanup].ok_or(HeapError::StaleReservation)?;
        if !matches!(
            self.slots[lease.reservation.slot].state,
            SlotState::Closing | SlotState::Retired
        ) || !job.queued
            || lease.epoch == 0
            || job.lease
                != (JobLease::Held {
                    epoch: lease.epoch,
                    worker: lease.worker,
                })
        {
            return Err(HeapError::Lease);
        }
        Ok(plan)
    }

    /// Supervisor fence: independent of process liveness and admission
    /// headroom. Preserves all job/lease rows, effects and accounting.
    pub(crate) fn fence_cleanup_worker_record(
        &mut self,
        worker: CleanupWorker,
    ) -> Result<(), HeapError> {
        if self.worker(worker)?.state != WorkerState::Active {
            return Err(HeapError::Worker);
        }
        self.heap.workers[worker.row as usize - 1]
            .as_mut()
            .unwrap()
            .state = WorkerState::Fenced;
        self.heap.advance();
        Ok(())
    }

    /// Only a fenced, unreferenced role row can be removed. A2.3.5b CPU requests
    /// bind application accounts, never cleanup-role handles. No worker/scrub
    /// request can survive a synchronous cleanup call. Before enabling a queued
    /// scrub/device backend, extend this reference census to that directory.
    pub(crate) fn remove_cleanup_worker_record(
        &mut self,
        worker: CleanupWorker,
    ) -> Result<(), HeapError> {
        if self.worker(worker)?.state != WorkerState::Fenced {
            return Err(HeapError::Worker);
        }
        if self
            .heap
            .cleanup
            .iter()
            .flatten()
            .any(|job| job.lease.refers_to(worker))
        {
            return Err(HeapError::Busy);
        }
        self.heap.workers[worker.row as usize - 1] = None;
        self.heap.advance();
        Ok(())
    }
}

#[cfg(test)]
mod tests;

pub(super) fn cleanup_status(lease: CleanupLease, job: CleanupRecord) -> HeapCleanupStatus {
    HeapCleanupStatus { lease, job }
}

pub(super) fn held_lease(reservation: HeapReservation, worker: CleanupWorker, epoch: u64) -> CleanupLease { CleanupLease {reservation,worker,epoch} }

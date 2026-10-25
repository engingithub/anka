//! Complete synchronous cleanup state and atomic exact placement/quota return.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeapScrubProgress {
    Pending,
    Scrubbing(u64),
    Clean,
}

/// Exact observation, not a reusable authorization. Full job equality includes
/// reservation, lease, version, sequence and progress. No integer constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapCleanupStatus {
    pub(super) lease: CleanupLease,
    pub(super) job: CleanupRecord,
}

impl HeapCleanupStatus {
    pub(crate) fn lease(self) -> CleanupLease {
        self.lease
    }
    pub(crate) fn done(self, rounded: u64) -> u64 {
        match self.job.progress {
            HeapScrubProgress::Pending => 0,
            HeapScrubProgress::Scrubbing(done) => done,
            HeapScrubProgress::Clean => rounded,
        }
    }
    pub(crate) fn is_clean(self) -> bool {
        self.job.progress == HeapScrubProgress::Clean
    }
    pub(crate) fn version(self) -> u64 {
        self.job.version
    }
}

#[derive(Debug)]
pub(crate) struct HeapCleanupPlan {
    closure: HeapClosurePlan,
    lease: CleanupLease,
    cleanup: usize,
    prior: CleanupRecord,
    next: CleanupRecord,
    revision: u64,
}

impl HeapCleanupPlan {
    pub(crate) fn closure(&self) -> &HeapClosurePlan {
        &self.closure
    }
    pub(crate) fn before(&self) -> HeapCleanupStatus {
        HeapCleanupStatus {
            lease: self.lease,
            job: self.prior,
        }
    }
}

#[derive(Debug)]
pub(crate) struct HeapReleasePlan {
    cleanup: HeapCleanupPlan,
    placement: placement::ReturnPlacement,
    rounded: u64,
    account_reserved: u64,
}

impl HeapReleasePlan {
    pub(crate) fn closure(&self) -> &HeapClosurePlan {
        self.cleanup.closure()
    }
}

impl ScopedPointers {
    fn prepare_retired_cleanup(
        &self,
        lease: CleanupLease,
        identity: CleanupWorkerIdentity,
        owner: AllocationOwner,
        expected: Option<HeapCleanupStatus>,
    ) -> Result<HeapCleanupPlan, HeapError> {
        let closure = self.prepare_heap_worker_lease(lease, identity, owner)?;
        if !closure.is_retired() {
            return Err(HeapError::Busy);
        }
        let cleanup = self.reservation_record(lease.reservation)?.cleanup;
        let prior = self.heap.cleanup[cleanup].ok_or(HeapError::StaleReservation)?;
        if expected.is_some_and(|s| s != (HeapCleanupStatus { lease, job: prior })) {
            return Err(HeapError::StaleCleanup);
        }
        Ok(HeapCleanupPlan {
            closure,
            lease,
            cleanup,
            prior,
            next: prior,
            revision: self.heap.revision,
        })
    }

    pub(crate) fn prepare_heap_scrub_begin(
        &self,
        lease: CleanupLease,
        identity: CleanupWorkerIdentity,
        owner: AllocationOwner,
    ) -> Result<HeapCleanupPlan, HeapError> {
        let mut plan = self.prepare_retired_cleanup(lease, identity, owner, None)?;
        if plan.prior.progress != HeapScrubProgress::Pending {
            return Err(HeapError::Busy);
        }
        plan.next.progress = HeapScrubProgress::Scrubbing(0);
        Ok(plan)
    }

    pub(crate) fn prepare_heap_scrub_chunk(
        &self,
        status: HeapCleanupStatus,
        identity: CleanupWorkerIdentity,
        owner: AllocationOwner,
        amount: u64,
    ) -> Result<HeapCleanupPlan, HeapError> {
        let mut plan = self.prepare_retired_cleanup(status.lease, identity, owner, Some(status))?;
        let HeapScrubProgress::Scrubbing(done) = plan.prior.progress else {
            return Err(HeapError::Busy);
        };
        let rounded = plan.closure.extents().physical.size;
        if amount == 0 || amount > 4096 || amount % 16 != 0 || amount > rounded - done {
            return Err(HeapError::Size);
        }
        plan.next.version = plan
            .prior
            .version
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        plan.next.sequence = plan
            .prior
            .sequence
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        plan.next.progress = if done + amount == rounded {
            HeapScrubProgress::Clean
        } else {
            HeapScrubProgress::Scrubbing(done + amount)
        };
        Ok(plan)
    }

    fn check_cleanup_commit(&self, plan: &HeapCleanupPlan) {
        assert_eq!(
            self.heap.revision, plan.revision,
            "stale internal cleanup plan"
        );
        assert_eq!(self.heap.cleanup[plan.cleanup], Some(plan.prior));
        let slot = &self.slots[plan.lease.reservation.slot];
        assert_eq!(slot.state, SlotState::Retired);
        assert_eq!(slot.generation, plan.lease.reservation.generation);
    }

    /// Fabric has completed any byte/tag effect before advancing this prefix.
    /// All preparation and commit occur under the same exclusive borrow.
    pub(crate) fn commit_heap_scrub(&mut self, plan: HeapCleanupPlan) -> HeapCleanupStatus {
        self.check_cleanup_commit(&plan);
        self.heap.cleanup[plan.cleanup] = Some(plan.next);
        self.heap.advance();
        HeapCleanupStatus {
            lease: plan.lease,
            job: plan.next,
        }
    }

    pub(crate) fn prepare_heap_release(
        &self,
        status: HeapCleanupStatus,
        identity: CleanupWorkerIdentity,
        owner: AllocationOwner,
    ) -> Result<HeapReleasePlan, HeapError> {
        let cleanup = self.prepare_retired_cleanup(status.lease, identity, owner, Some(status))?;
        if !status.is_clean() {
            return Err(HeapError::Busy);
        }
        let reservation = cleanup.closure.reservation();
        let record = self.reservation_record(reservation)?;
        let account_reserved = self.account(reservation.owner)?.reserved;
        // closure already checked both exact manager claims and charges.
        let placement = self
            .heap
            .placement
            .as_ref()
            .ok_or(HeapError::Configuration)?
            .prepare_cancel(reservation, cleanup.closure.extents(), cleanup.revision)?;
        Ok(HeapReleasePlan {
            cleanup,
            placement,
            rounded: record.rounded,
            account_reserved,
        })
    }

    /// The enclosing Fabric operation removes its private row in this same
    /// commit. Both manager returns were prepared; no fallible operation remains.
    pub(crate) fn commit_heap_release(&mut self, plan: HeapReleasePlan) {
        self.check_cleanup_commit(&plan.cleanup);
        let reservation = plan.cleanup.closure.reservation();
        assert_eq!(
            self.heap.accounts[reservation.owner.index]
                .as_ref()
                .unwrap()
                .reserved,
            plan.account_reserved
        );
        self.heap.placement.as_mut().unwrap().commit_cancel(
            reservation.owner,
            plan.placement,
            plan.cleanup.revision,
        );
        self.heap.accounts[reservation.owner.index]
            .as_mut()
            .unwrap()
            .reserved -= plan.rounded;
        self.heap.reserved_bytes -= plan.rounded;
        self.heap.cleanup[plan.cleanup.cleanup] = None;
        let slot = &mut self.slots[reservation.slot];
        slot.record = Record::Empty;
        slot.release(); // Keeps the generation; MAX becomes permanently Exhausted.
        self.trim_active_slots();
        self.heap.advance();
    }
}

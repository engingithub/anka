//! A2.3.4: fence one attached lifetime and queue its reserved cleanup record.
//! This is admission closure, not drainage, retirement, scrubbing or release.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeapCloseOutcome {
    Closed,
    AlreadyClosing,
    AlreadyRetired,
}

/// Read-only preparation for the same exclusive Fabric operation. Never
/// cache this plan or carry it across a worker yield, including at revision MAX.
#[derive(Debug)]
pub(crate) struct HeapClosurePlan {
    reservation: HeapReservation,
    owner: AllocationOwner,
    logical: u64,
    writable: bool,
    extents: HeapExtents,
    cleanup: usize,
    stage: SlotState,
    revision: u64,
}

impl HeapClosurePlan {
    pub(crate) fn rights(&self) -> crate::anka64::state::Permissions {
        if self.writable { crate::anka64::state::Permissions::RW } else { crate::anka64::state::Permissions::READ }
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.stage == SlotState::Retired
    }
    pub(crate) fn slot(&self) -> usize {
        self.reservation.slot
    }
    pub(crate) fn reservation(&self) -> HeapReservation {
        self.reservation
    }
    pub(crate) fn owner(&self) -> AllocationOwner {
        self.owner
    }
    pub(crate) fn logical(&self) -> u64 {
        self.logical
    }
    pub(crate) fn extents(&self) -> HeapExtents {
        self.extents
    }
}

impl ScopedPointers {
    /// Cleanup uses the retained owner identity, not a live CPU or a fresh
    /// admission revision. It must still be possible after owner closure and
    /// counter exhaustion. A never-attached reservation uses abort_heap instead.
    pub(crate) fn prepare_attached_heap_closure(
        &self,
        reservation: HeapReservation,
        owner: AllocationOwner,
    ) -> Result<HeapClosurePlan, HeapError> {
        let account = self.account(reservation.owner)?;
        if account.owner != owner {
            return Err(HeapError::Owner);
        }
        let record = self.reservation_record(reservation)?;
        if !record.ever_attached {
            return Err(HeapError::Busy);
        }
        let stage = self.slots[reservation.slot].state;
        let job = self.heap.cleanup[record.cleanup].ok_or(HeapError::StaleReservation)?;
        let pending = matches!(stage, SlotState::Closing | SlotState::Retired);
        if job.queued != pending
            || (account.closed && !pending)
            || (stage == SlotState::Reserved && record.published)
            || (stage == SlotState::Live && !record.published)
        {
            return Err(HeapError::Configuration);
        }
        use workers::HeapScrubProgress;
        let progress_valid = match job.progress {
            HeapScrubProgress::Pending => true,
            HeapScrubProgress::Scrubbing(done) => {
                stage == SlotState::Retired && done < record.rounded && done % 16 == 0
            }
            HeapScrubProgress::Clean => {
                stage == SlotState::Retired && job.version != 0 && job.sequence != 0
            }
        };
        if !progress_valid {
            return Err(HeapError::Configuration);
        }
        // Neither closure nor a duplicate may drop an extent or its charge.
        // Reauthenticate both actual placement-manager claims before commit.
        let extents = self.reserved_extents(reservation)?;
        if record.logical == 0
            || record.logical > i64::MAX as u64
            || page_ceil(record.logical).map_err(|_| HeapError::Size)? != record.rounded
            || extents.physical.size != record.rounded
            || extents.virtual_extent.size != record.rounded
            || account.reserved < record.rounded
            || self.heap.reserved_bytes < account.reserved
        {
            return Err(HeapError::Configuration);
        }
        Ok(HeapClosurePlan {
            reservation,
            owner,
            logical: record.logical,
            extents,
            cleanup: record.cleanup,
            writable: record.writable,
            stage,
            revision: self.heap.revision,
        })
    }

    /// Fabric has checked its exact attached row in the same exclusive borrow.
    /// Only fixed-row writes remain; closure consumes no new identity, queue
    /// capacity or quota. A duplicate is an observation with no state change.
    pub(crate) fn commit_attached_heap_closure(
        &mut self,
        plan: HeapClosurePlan,
    ) -> HeapCloseOutcome {
        assert_eq!(
            plan.revision, self.heap.revision,
            "stale internal closure plan"
        );
        let slot = &mut self.slots[plan.reservation.slot];
        let job = self.heap.cleanup[plan.cleanup]
            .as_mut()
            .expect("closure preflight checked the reserved cleanup record");
        assert_eq!(slot.generation, plan.reservation.generation);
        assert_eq!(slot.state, plan.stage);
        assert_eq!(job.reservation, plan.reservation);
        assert_eq!(
            job.queued,
            matches!(plan.stage, SlotState::Closing | SlotState::Retired)
        );
        if plan.stage == SlotState::Retired {
            return HeapCloseOutcome::AlreadyRetired;
        }
        if plan.stage == SlotState::Closing {
            return HeapCloseOutcome::AlreadyClosing;
        }
        slot.state = SlotState::Closing;
        job.queued = true;
        self.heap.advance();
        HeapCloseOutcome::Closed
    }
}

#[cfg(test)]
mod tests;

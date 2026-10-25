//! A2.3: exact private attachment/initialization under the common revision.
//! Publication plans issue a pointer only through the owned reply commit.
//! The legacy local-pointer path cannot expose private heap backing.
use super::*;

/// Only produced by the registry's read-only preflight. The caller must keep
/// the exclusive Fabric borrow until the nonfallible commit; never cache it.
#[derive(Debug)]
pub(crate) struct HeapAttachmentPlan {
    reservation: HeapReservation,
    owner: AllocationOwner,
    logical: u64,
    extents: HeapExtents,
    revision: u64,
}

impl HeapAttachmentPlan {
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
    /// Construction only: charge storage owned by the encompassing Fabric.
    /// Existing registry descriptors and A2.2 tables are already charged.
    pub(crate) fn charge_heap_fabric_storage(&mut self, additional: u64) -> Result<(), HeapError> {
        if self.heap.revision != 0
            || self.active_slots_end != 0
            || self.active_scopes_end != 0
            || self.heap.reserved_bytes != 0
            || self.heap.accounts.iter().any(Option::is_some)
            || self.heap.cleanup.iter().any(Option::is_some)
            || self.heap.workers.iter().any(Option::is_some)
        {
            return Err(HeapError::Busy);
        }
        if additional > self.heap.limit - self.total_reserved_bytes() {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        self.heap.fixed_bytes += additional;
        Ok(())
    }

    pub(crate) fn prepare_heap_attachment(
        &self,
        reservation: HeapReservation,
        current_owner: AllocationOwner,
        expected_revision: u64,
    ) -> Result<HeapAttachmentPlan, HeapError> {
        self.prepare_heap_private(reservation, current_owner, expected_revision, false)
    }

    /// Reauthenticate attached private custody before every initialization
    /// observation or mutation. This is not a publication or cleanup ticket.
    pub(crate) fn prepare_heap_initialization(
        &self,
        reservation: HeapReservation,
        current_owner: AllocationOwner,
        expected_revision: u64,
    ) -> Result<HeapAttachmentPlan, HeapError> {
        self.prepare_heap_private(reservation, current_owner, expected_revision, true)
    }

    fn prepare_heap_private(
        &self,
        reservation: HeapReservation,
        current_owner: AllocationOwner,
        expected_revision: u64,
        attached: bool,
    ) -> Result<HeapAttachmentPlan, HeapError> {
        let account = self.account(reservation.owner)?;
        if account.owner != current_owner {
            return Err(HeapError::Owner);
        }
        if account.closed {
            return Err(HeapError::Closed);
        }
        if expected_revision != self.heap.revision {
            return Err(HeapError::StaleRevision);
        }
        if self.heap.revision == u64::MAX {
            return Err(HeapError::Capacity(Resource::Identity));
        }
        let record = self.reservation_record(reservation)?;
        if self.slots[reservation.slot].state != SlotState::Reserved
            || record.ever_attached != attached
            || record.published
            || self.heap.cleanup[record.cleanup].is_none_or(|job| job.queued)
        {
            return Err(HeapError::Busy);
        }
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
        Ok(HeapAttachmentPlan {
            reservation,
            owner: account.owner,
            logical: record.logical,
            extents,
            revision: self.heap.revision,
        })
    }

    /// Only plain fixed-row updates follow preflight, under the SAME &mut.
    /// No epoch/job/quota is consumed a second time. Attached resources can no
    /// longer take abort_heap's direct-return path, including after owner death.
    pub(crate) fn commit_heap_attachment(&mut self, plan: HeapAttachmentPlan) {
        assert_eq!(
            plan.revision, self.heap.revision,
            "stale internal attachment plan"
        );
        let Record::Heap(record) = &mut self.slots[plan.reservation.slot].record else {
            unreachable!("attachment preflight selected a heap record")
        };
        record.ever_attached = true;
        self.heap.advance();
    }

    /// Called only after Fabric's byte/tag/row update in the same exclusive
    /// borrow. Preflight excluded MAX, closure, publication and lost custody.
    pub(crate) fn commit_heap_initialization(&mut self, plan: HeapAttachmentPlan) {
        assert_eq!(
            plan.revision, self.heap.revision,
            "stale internal initialization plan"
        );
        self.heap.advance();
    }
}

#[cfg(test)]
mod tests;

impl ScopedPointers {
    /// Fabric has checked full initialization and the owned one-use event reply.
    /// Commit occurs within that same exclusive operation, with no fallible tail.
    pub(crate) fn commit_heap_publication(&mut self, plan: HeapAttachmentPlan) -> ScopedPointer {
        assert_eq!(plan.revision, self.heap.revision);
        let slot = &mut self.slots[plan.reservation.slot];
        assert_eq!(slot.state, SlotState::Reserved);
        assert_eq!(slot.generation, plan.reservation.generation);
        let Record::Heap(record) = &mut slot.record else { unreachable!() };
        assert!(record.ever_attached && !record.published);
        record.published = true;
        slot.state = SlotState::Live;
        self.heap.advance();
        ScopedPointer { slot: plan.reservation.slot, generation: plan.reservation.generation, position: 0 }
    }
}

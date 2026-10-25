//! Current heap lifetime authentication for A2.3 cell operations. No issuance,
//! state transition, integer-to-pointer conversion or publication API here.
use super::*;
use crate::anka64::scoped_pointers::PointerError;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HeapPointerPlan {
    reservation: HeapReservation,
    owner: AllocationOwner,
    logical: u64,
    extents: HeapExtents,
    position: u64,
}

impl HeapPointerPlan {
    pub(crate) fn slot(self) -> usize {
        self.reservation.slot
    }
    pub(crate) fn reservation(self) -> HeapReservation {
        self.reservation
    }
    pub(crate) fn owner(self) -> AllocationOwner {
        self.owner
    }
    pub(crate) fn logical(self) -> u64 {
        self.logical
    }
    pub(crate) fn extents(self) -> HeapExtents {
        self.extents
    }
    pub(crate) fn position(self) -> u64 {
        self.position
    }
}

impl ScopedPointers {
    /// Class selection only, never authentication. A stale heap token must
    /// still cross the complete lifetime check; it cannot use a local fallback.
    pub(crate) fn is_heap_pointer(&self, pointer: ScopedPointer) -> bool {
        self.slots
            .get(pointer.slot)
            .is_some_and(|s| matches!(s.record, Record::Heap(_)))
    }

    pub(crate) fn prepare_heap_pointer(
        &self,
        pointer: ScopedPointer,
        current_owner: AllocationOwner,
    ) -> Result<HeapPointerPlan, HeapError> {
        let slot = self
            .slots
            .get(pointer.slot)
            .ok_or(HeapError::Pointer(PointerError::Stale))?;
        if slot.generation != pointer.generation || slot.state != SlotState::Live {
            return Err(HeapError::Pointer(PointerError::Stale));
        }
        let Record::Heap(record) = slot.record else {
            return Err(HeapError::Pointer(PointerError::Stale));
        };
        let account = self.account(record.owner)?;
        if account.owner != current_owner {
            return Err(HeapError::Owner);
        }
        if account.closed {
            return Err(HeapError::Closed);
        }
        if !record.ever_attached || !record.published {
            return Err(HeapError::Pointer(PointerError::Stale));
        }
        let job = self
            .heap
            .cleanup
            .get(record.cleanup)
            .and_then(Option::as_ref)
            .ok_or(HeapError::StaleReservation)?;
        let reservation = job.reservation;
        if job.queued
            || reservation.slot != pointer.slot
            || reservation.generation != pointer.generation
            || reservation.owner != record.owner
        {
            return Err(HeapError::StaleReservation);
        }
        // This rechecks the exact job identity and both managers' current claims.
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
        // One-past is valid for transport only. Each cell/byte access checks
        // its own nonempty logical span separately, before shadow indexing.
        if pointer.position > record.logical {
            return Err(HeapError::Pointer(PointerError::Bounds));
        }
        // Ordinary data access neither spends nor needs a fresh ledger revision.
        // &mut Fabric serializes it with close; exhaustion only fences admission.
        Ok(HeapPointerPlan {
            reservation,
            owner: account.owner,
            logical: record.logical,
            extents,
            position: pointer.position,
        })
    }
}

//! A2.3.4: per-allocation attached-failure closure under exclusive Fabric access.
//! Reuses a23_close and the saturating cleanup revision; no worker is enabled.
use super::*;
use crate::anka64::scoped_pointers::heap::{HeapCloseOutcome, HeapClosurePlan};

pub(super) fn scratch_bytes() -> Result<u64, HeapError> {
    // Fixed value-storage allowance, not an exact host-stack or RSS bound.
    storage::<HeapClosurePlan>(1)?
        .checked_add(storage::<PrivateHeapRow>(1)?)
        .ok_or(HeapError::Configuration)
}

impl Fabric {
    /// Trusted failure/cleanup entry point for one already-attached allocation.
    /// `owner` comes from its retained trusted descriptor, never guest integers.
    /// No live domain/CPU, new ID or admission revision is needed to close it.
    /// The opaque reservation plus exact ObjectId selects the retained custody;
    /// this is not a public free-by-address or guest syscall interface.
    pub(crate) fn close_attached_heap(
        &mut self,
        reservation: HeapReservation,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<HeapCloseOutcome, HeapError> {
        let plan = self
            .scoped_pointers
            .prepare_attached_heap_closure(reservation, owner)?;
        self.check_attached_heap_custody(&plan, object)?;
        // No quiet/completion check: closure fences access before drainage.
        Ok(self.scoped_pointers.commit_attached_heap_closure(plan))
    }

    /// Common exact custody check for closure and worker metadata operations.
    /// This is deliberately not a drain/initialization/readiness certificate.
    pub(super) fn check_attached_heap_custody(
        &self,
        plan: &HeapClosurePlan,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        let row = heap
            .rows
            .get(plan.slot())
            .and_then(|r| *r)
            .ok_or(HeapError::StaleReservation)?;
        if row.reservation != plan.reservation()
            || row.owner != plan.owner()
            || row.object != object
            || row.object_generation != Generation(0)
            || row.object.0 >= heap.object_id_floor
            || row.logical != plan.logical()
            || row.extents != plan.extents()
            || row.planned_rights != plan.rights()
        {
            return Err(HeapError::StaleReservation);
        }
        heap.check_extents(row.extents)?;
        if row
            .extents
            .physical
            .end()
            .and_then(|end| usize::try_from(end).ok())
            .is_none_or(|end| end > self.memory.len())
        {
            return Err(HeapError::Configuration);
        }
        // Deliberately no heap_pool_is_private/quiet/completion check here.
        // Closure fences new access before drainage. Existing work, initialized
        // prefix/version, bytes, tags and both extent claims remain untouched.
        // A2.3.5c accounts for terminal work separately; safe release still
        // requires a later retirement/reclamation operation.
        Ok(())
    }
}

#[cfg(test)]
mod tests;

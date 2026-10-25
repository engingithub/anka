//! A2.3.7: retire authority only after a current, complete drain/exclusion check.
use super::*;

impl Fabric {
    pub(crate) fn retire_heap_authority(
        &mut self,
        current: &CurrentHeapRetirement<'_>,
        lease: CleanupLease,
        owner: AllocationOwner,
    ) -> Result<(), HeapError> {
        let identity = self.checked_cleanup_descriptor(current.worker())?;
        let object = current.object();
        let plan = self
            .scoped_pointers
            .prepare_heap_retirement(lease, identity, owner)?;
        self.check_heap_cleanup_drain(plan.closure(), object)?;
        self.scoped_pointers.commit_heap_retirement(plan);
        Ok(())
    }
    /// Fresh full backend census and actual legacy exclusions. The caller also
    /// holds Kernel's immutable process census before byte effects or release.
    /// Recovery uses only metadata; its later byte operation repeats that census.
    pub(in crate::anka64::fabric::heap) fn check_heap_cleanup_drain(
        &mut self,
        plan: &crate::anka64::scoped_pointers::heap::HeapClosurePlan,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        self.check_attached_heap_custody(plan, object)?;
        let owner = plan.owner();
        // Repeat the full source/ledger census here. An earlier ready result
        // cannot authorize retirement, even at saturated common revision.
        let counts = self.heap_work_census(plan.reservation(), owner, object)?;
        if counts.cpu != 0
            || counts.dma != 0
            || !self.heap_pool_is_private()
            || self.objects.contains_key(&object)
            || self.placement.contains_key(&object)
            || self.pointer_stack_objects.contains_key(&object)
            || self.scoped_pointers.local_backing_references(object)
            || self.domains.values().any(|domain| {
                domain
                    .capabilities
                    .iter()
                    .any(|entry| entry.cap.object() == object)
                    || domain
                        .device_authorities
                        .iter()
                        .any(|entry| entry.object == object)
            })
        {
            return Err(HeapError::Busy);
        }
        Ok(())
    }
}

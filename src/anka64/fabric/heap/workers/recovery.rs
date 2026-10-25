//! Trusted supervisor recovery of queued and retired/scrub/clean jobs.
//! Software scrubbing is synchronous; no effect survives the exclusive call.
use super::*;

impl Fabric {
    /// Fence one exact held lease before deciding whether recovery is safe.
    /// Pending application work and legacy conflicts do not prevent fencing.
    pub(crate) fn revoke_heap_cleanup_job(
        &mut self,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        let plan = self
            .scoped_pointers
            .prepare_heap_worker_revoke(lease, owner)?;
        self.check_attached_heap_custody(plan.closure(), object)?;
        self.scoped_pointers.commit_heap_worker_recovery(plan);
        Ok(())
    }

    /// Return the exact revoking lease to unowned state. This is NOT allocation
    /// drainage, retirement, initialized-memory certification or backing reuse.
    pub(crate) fn recover_heap_cleanup_job(
        &mut self,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        let plan = self
            .scoped_pointers
            .prepare_heap_worker_recovery(lease, owner)?;
        self.check_attached_heap_custody(plan.closure(), object)?;
        // Every queued source is ordinary CPU work. Scrubbing completes under
        // one exclusive borrow and creates no retained backend request.
        // Still authenticate the complete actual ledger/source census; orphan
        // or malformed records must not disappear behind that type invariant.
        // Application requests may remain and must NOT be consumed here.
        if plan.closure().is_retired() {
            self.check_heap_cleanup_drain(plan.closure(), object)?;
        } else {
            self.heap_work_census(plan.closure().reservation(), owner, object)?;
        }
        if !self.heap_pool_is_private() {
            return Err(HeapError::Busy);
        }
        // No enabled worker effects remain: software effects complete under
        // this same exclusive borrow; legacy bypasses were excluded above.
        // Extend these checks BEFORE admitting queued worker/scrub/DMA effects.
        self.scoped_pointers.commit_heap_worker_recovery(plan);
        Ok(())
    }
}

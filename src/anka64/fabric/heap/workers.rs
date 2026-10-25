//! A2.3.5a: current Kernel descriptor + registered CPU + exact heap custody.
//! Claims/fences change metadata only; no worker memory effects are enabled.
use super::*;
use crate::anka64::os::{CurrentHeapProcess, CurrentHeapRetirement};
use crate::anka64::scoped_pointers::heap::{
    CleanupLease, CleanupWorker, CleanupWorkerIdentity, HeapCleanupPlan, HeapReleasePlan,
    HeapRetirementPlan, HeapWorkerClaimPlan, HeapWorkerRecoveryPlan,
};
use crate::anka64::state::AgentKind;
mod cleanup;
mod recovery;
mod retirement;
pub(crate) use cleanup::HeapCleanupSnapshot;

pub(super) fn scratch_bytes() -> Result<u64, HeapError> {
    // Value-storage allowance, not an exact host stack/RSS measurement. The
    // enclosing registry charges inline fields, retained rows and job leases.
    [
        crate::anka64::scoped_pointers::heap::cleanup_worker_record_scratch_bytes()?,
        storage::<HeapWorkerClaimPlan>(1)?,
        storage::<HeapWorkerRecoveryPlan>(1)?,
        storage::<HeapRetirementPlan>(1)?,
        storage::<HeapCleanupPlan>(1)?,
        storage::<HeapReleasePlan>(1)?,
        storage::<HeapCleanupSnapshot>(1)?,
        storage::<CurrentHeapRetirement<'_>>(1)?,
        storage::<CleanupWorkerIdentity>(1)?,
        storage::<CleanupWorker>(1)?,
        storage::<CleanupLease>(1)?,
        storage::<CurrentHeapProcess<'_>>(1)?,
    ]
    .into_iter()
    .try_fold(0u64, |n, b| {
        n.checked_add(b).ok_or(HeapError::Configuration)
    })
}

impl Fabric {
    pub(super) fn checked_cleanup_descriptor(
        &self,
        current: &CurrentHeapProcess<'_>,
    ) -> Result<CleanupWorkerIdentity, HeapError> {
        let identity = current.identity();
        let agent = current.agent();
        if self.private_heap.is_none()
            || identity.context == 0
            || !self
                .domains
                .get(&identity.domain)
                .is_some_and(|d| d.id == identity.domain)
            || !self.agents.get(&agent).is_some_and(|a| {
                a.id == agent && a.domain == identity.domain && matches!(a.kind, AgentKind::Cpu(_))
            })
        {
            return Err(HeapError::Worker);
        }
        Ok(identity)
    }

    pub(crate) fn enroll_heap_cleanup_worker(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        expected: u64,
    ) -> Result<CleanupWorker, HeapError> {
        let identity = self.checked_cleanup_descriptor(current)?;
        self.scoped_pointers
            .enroll_cleanup_worker_record(identity, expected)
    }

    pub(crate) fn claim_heap_cleanup_job(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        worker: CleanupWorker,
        reservation: HeapReservation,
        owner: AllocationOwner,
        object: ObjectId,
        expected: u64,
    ) -> Result<CleanupLease, HeapError> {
        let identity = self.checked_cleanup_descriptor(current)?;
        let plan = self.scoped_pointers.prepare_heap_worker_claim(
            worker,
            identity,
            reservation,
            owner,
            expected,
        )?;
        self.check_attached_heap_custody(plan.closure(), object)?;
        Ok(self.scoped_pointers.commit_heap_worker_claim(plan))
    }

    /// Even this read-only observation takes an exclusive Fabric borrow. It is
    /// a current validation only; returning Ok does not authorize later effects.
    pub(crate) fn authenticate_heap_cleanup_job(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        let identity = self.checked_cleanup_descriptor(current)?;
        let plan = self
            .scoped_pointers
            .prepare_heap_worker_lease(lease, identity, owner)?;
        self.check_attached_heap_custody(&plan, object)
    }
}

#[cfg(test)]
mod tests;

pub(super) fn cleanup_snapshot(row: PrivateHeapRow, status: crate::anka64::scoped_pointers::heap::HeapCleanupStatus) -> HeapCleanupSnapshot { cleanup::snapshot(row, status) }

impl Fabric { pub(crate) fn check_heap_service_worker(&self, current: &CurrentHeapProcess<'_>, role: CleanupWorker) -> Result<(), HeapError> { let identity=self.checked_cleanup_descriptor(current)?;self.scoped_pointers.current_worker(role,identity) } }

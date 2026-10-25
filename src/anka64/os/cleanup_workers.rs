//! A2.3.5a trusted runtime boundary. No new guest syscall, scheduler or worker
//! execution loop. Enrollment is an explicit supervisor role grant.
use super::{CurrentHeapProcess, CurrentHeapRetirement, Kernel};
use crate::anka64::scoped_pointers::heap::{
    AllocationOwner, CleanupLease, CleanupWorker, HeapError, HeapReservation,
};
use crate::anka64::state::{ObjectId, ProcessKey};

impl Kernel {
    /// Explicit trusted dispatch; no guest syscall or automatic death hook.
    /// Borrow all process descriptors until the exclusive Fabric commit ends.
    pub(crate) fn retire_heap_authority(
        &mut self,
        key: ProcessKey,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        let current = CurrentHeapRetirement::from_processes(&self.processes, key, object)?;
        self.fabric.retire_heap_authority(&current, lease, owner)
    }

    /// Trusted host/supervisor configuration only, analogous to input
    /// provisioning. No syscall, IPC decoder or C builtin calls this method.
    /// Role issuance is explicit and separate from ordinary process spawning.
    pub(crate) fn enroll_cleanup_worker(
        &mut self,
        key: ProcessKey,
        expected: u64,
    ) -> Result<CleanupWorker, HeapError> {
        let current =
            CurrentHeapProcess::from_processes(&self.processes, key).ok_or(HeapError::Worker)?;
        self.fabric.enroll_heap_cleanup_worker(&current, expected)
    }

    /// `key` is selected by trusted runtime dispatch, never copied from guest
    /// registers. The exact descriptor and enrolled role are rechecked now.
    pub(crate) fn claim_heap_cleanup(
        &mut self,
        key: ProcessKey,
        worker: CleanupWorker,
        reservation: HeapReservation,
        owner: AllocationOwner,
        object: ObjectId,
        expected: u64,
    ) -> Result<CleanupLease, HeapError> {
        let current =
            CurrentHeapProcess::from_processes(&self.processes, key).ok_or(HeapError::Worker)?;
        self.fabric
            .claim_heap_cleanup_job(&current, worker, reservation, owner, object, expected)
    }

    pub(crate) fn authenticate_heap_cleanup(
        &mut self,
        key: ProcessKey,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        let current =
            CurrentHeapProcess::from_processes(&self.processes, key).ok_or(HeapError::Worker)?;
        self.fabric
            .authenticate_heap_cleanup_job(&current, lease, owner, object)
    }

    /// Trusted supervisor cleanup, usable after process/domain death. Fencing
    /// never asserts that delayed effects have stopped and never drops leases.
    pub(crate) fn fence_cleanup_worker(&mut self, worker: CleanupWorker) -> Result<(), HeapError> {
        self.fabric
            .scoped_pointers
            .fence_cleanup_worker_record(worker)
    }

    pub(crate) fn remove_cleanup_worker(&mut self, worker: CleanupWorker) -> Result<(), HeapError> {
        self.fabric
            .scoped_pointers
            .remove_cleanup_worker_record(worker)
    }

    /// Supervisor-selected exact job identity, usable after worker death.
    /// Does not fence unrelated jobs; the global role fence is separate.
    pub(crate) fn revoke_heap_cleanup(
        &mut self,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        self.fabric.revoke_heap_cleanup_job(lease, owner, object)
    }

    /// A fenced worker and a current complete backend check are mandatory.
    /// Reassignment does not complete ordinary application work or free memory.
    pub(crate) fn recover_heap_cleanup(
        &mut self,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<(), HeapError> {
        self.fabric.recover_heap_cleanup_job(lease, owner, object)
    }
}

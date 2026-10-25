//! Production publication, exact-base free and bounded cleanup-directory views.
use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HeapJob {
    pub reservation: HeapReservation,
    pub owner: AllocationOwner,
    pub retired: bool,
    pub lease: Option<CleanupLease>,
    pub progress: Option<HeapCleanupStatus>,
}

impl ScopedPointers {
    pub(crate) fn heap_account(&self, owner: AllocationOwner) -> Option<OwnerAccount> {
        self.heap
            .accounts
            .iter()
            .flatten()
            .find(|a| a.owner == owner)
            .map(|a| a.token)
    }
    pub(crate) fn heap_cleanup_capacity(&self) -> usize {
        self.heap.cleanup.len()
    }
    pub(crate) fn heap_job(&self, index: usize) -> Option<HeapJob> {
        let job = self.heap.cleanup.get(index).copied().flatten()?;
        if !job.queued {
            return None;
        }
        let owner = self.account(job.reservation.owner).ok()?.owner;
        let lease = match job.lease {
            workers::JobLease::Unowned { .. } => None,
            workers::JobLease::Held { worker, epoch } => {
                Some(workers::held_lease(job.reservation, worker, epoch))
            }
            workers::JobLease::Revoking { .. } => return None,
        };
        let progress = lease.and_then(|lease| match job.progress {
            workers::HeapScrubProgress::Pending => None,
            _ => Some(workers::cleanup_status(lease, job)),
        });
        Some(HeapJob {
            reservation: job.reservation,
            owner,
            retired: self.slots[job.reservation.slot].state == SlotState::Retired,
            lease,
            progress,
        })
    }
    pub(crate) fn heap_free_reservation(
        &self,
        pointer: ScopedPointer,
        owner: AllocationOwner,
    ) -> Result<HeapReservation, HeapError> {
        if pointer.position != 0 {
            return Err(HeapError::InvalidFree);
        }
        Ok(self.prepare_heap_pointer(pointer, owner)?.reservation())
    }
    pub(crate) fn add_heap_pointer(
        &self,
        pointer: ScopedPointer,
        owner: AllocationOwner,
        delta: i64,
    ) -> Result<ScopedPointer, HeapError> {
        let plan = self.prepare_heap_pointer(pointer, owner)?;
        let position = pointer
            .position
            .checked_add_signed(delta)
            .filter(|p| *p <= plan.logical())
            .ok_or(HeapError::Pointer(super::super::PointerError::Bounds))?;
        Ok(ScopedPointer {
            position,
            ..pointer
        })
    }
    pub(crate) fn release_closed_heap_accounts(&mut self) {
        for i in 0..self.heap.accounts.len() {
            if let Some(a) = self.heap.accounts[i] {
                if a.closed && a.reserved == 0 {
                    let _ = self.release_owner(a.token);
                }
            }
        }
    }
}

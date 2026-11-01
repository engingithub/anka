//! C2 shared host-storage quota. No guest pointer, object, physical or virtual
//! extent is created. Destruction is a trusted custodian obligation; CPU/DMA
//! scrub workers cannot discharge it. Closing an owner retains these charges.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostStorageReservation {
    row: usize,
    identity: u64,
    account: OwnerAccount,
}
impl HostStorageReservation {
    pub(crate) fn incarnation(self) -> u64 { self.identity }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HostStorageRecord {
    token: HostStorageReservation,
    logical: u64,
    rounded: u64,
}

impl ScopedPointers {
    /// Reserve BEFORE creating host payload. The fixed directory is charged at
    /// registry construction; shared owner/global counters include both kinds
    /// of storage. Identity comes from the same nonwrapping reservation stream.
    pub(crate) fn reserve_host_storage(&mut self, owner: OwnerAccount, logical: u64,
        expected_revision: u64) -> Result<HostStorageReservation, HeapError>
    {
        let account = *self.account(owner)?;
        if account.closed { return Err(HeapError::Closed); }
        if logical == 0 || logical > i64::MAX as u64 { return Err(HeapError::Size); }
        let rounded = page_ceil(logical).map_err(|_| HeapError::Size)?;
        if expected_revision != self.revision() { return Err(HeapError::StaleRevision); }
        if self.revision() == u64::MAX || self.heap.next_job == u64::MAX {
            return Err(HeapError::Capacity(Resource::Identity));
        }
        if account.limit.checked_sub(account.reserved).is_none_or(|n| n < rounded) {
            return Err(HeapError::Capacity(Resource::OwnerBytes));
        }
        if self.heap.limit.checked_sub(self.total_reserved_bytes()).is_none_or(|n| n < rounded) {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let row = self.heap.host_storage.iter().position(Option::is_none)
            .ok_or(HeapError::Capacity(Resource::HostStorage))?;
        let token = HostStorageReservation { row, identity: self.heap.next_job, account: owner };
        // All checks before any mutation; neither placement manager is touched.
        self.heap.host_storage[row] = Some(HostStorageRecord { token, logical, rounded });
        self.heap.accounts[owner.index].as_mut().unwrap().reserved += rounded;
        self.heap.reserved_bytes += rounded;
        self.heap.next_job += 1;
        self.heap.advance();
        Ok(token)
    }

    fn host_storage_record(&self, token: HostStorageReservation) -> Result<HostStorageRecord, HeapError> {
        self.account(token.account)?;
        self.heap.host_storage.get(token.row).copied().flatten()
            .filter(|r| r.token == token).ok_or(HeapError::StaleReservation)
    }

    /// Reauthenticate current live custody without preparing a heap attachment.
    pub(crate) fn check_host_storage(&self, token: HostStorageReservation,
        owner: AllocationOwner, expected_revision: u64) -> Result<u64, HeapError>
    {
        let account = self.account(token.account)?;
        if account.owner != owner { return Err(HeapError::Owner); }
        if account.closed { return Err(HeapError::Closed); }
        if expected_revision != self.revision() { return Err(HeapError::StaleRevision); }
        Ok(self.host_storage_record(token)?.logical)
    }

    /// Trusted custody release, ONLY after payload and scratch have been dropped
    /// or transferred into independently charged custody. Not a guest free API.
    /// Also works after owner closure or revision/identity exhaustion. A stale
    /// duplicate cannot refund a reused row. No backing requires scrub here.
    pub(crate) fn release_host_storage(&mut self, token: HostStorageReservation) -> Result<(), HeapError> {
        let record = self.host_storage_record(token)?;
        let account = *self.account(token.account)?;
        if account.reserved < record.rounded || self.heap.reserved_bytes < account.reserved {
            return Err(HeapError::Configuration);
        }
        self.heap.host_storage[token.row] = None;
        self.heap.accounts[token.account.index].as_mut().unwrap().reserved -= record.rounded;
        self.heap.reserved_bytes -= record.rounded;
        self.heap.advance();
        Ok(())
    }
}

#[cfg(test)]
mod tests;

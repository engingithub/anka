//! A2.1 metadata, A2.2 bounded physical/virtual reservations and A2.3 private
//! attachment/initialization/closure preflight. Fabric owns actual byte/tag effects.
//! Live heap access preflight exists, but no production heap pointer issuance
//! or worker execution is enabled. Worker identity/lease metadata is separate
//! from application allocation ownership and does not authorize memory effects.
//! The fixed cleanup directory is also the reserved queue. All mutators need
//! exclusive access to the same ScopedPointers, including local admissions.

use super::{Record, ScopedPointer, ScopedPointers, Slot, SlotState};
use crate::anka64::placement::{PlacementError, page_ceil};
use crate::anka64::state::{DomainId, ProcessKey};
use std::mem::size_of;
mod application;
pub(crate) use application::HeapJob;
mod placement;
mod fabric;
mod cells;
mod closure;
mod workers;
mod work;
pub(crate) use work::{HeapWorkCleanupRevision, HeapWorkRevision};
pub(crate) use workers::{CleanupLease, CleanupWorker, CleanupWorkerIdentity, HeapWorkerClaimPlan, HeapWorkerRecoveryPlan, HeapRetirementPlan};

pub(crate) fn cleanup_worker_record_scratch_bytes() -> Result<u64, HeapError> {
    workers::record_scratch_bytes()
}
pub(crate) use workers::{HeapCleanupPlan, HeapCleanupStatus, HeapReleasePlan};
pub(crate) use closure::{HeapCloseOutcome, HeapClosurePlan};
pub(crate) use fabric::HeapAttachmentPlan;
pub(crate) use cells::HeapPointerPlan;
pub(crate) use placement::{HeapExtents, HeapPlacementLimits};
#[cfg(test)]
pub(crate) use placement::tests::no_alloc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistryLimits {
    pub slots: usize,
    pub scopes: usize,
    pub owners: usize,
    pub cleanup: usize,
    pub global_bytes: u64,
}

/// Taken from the trusted process descriptor, never a caller-supplied PID.
/// ProcessKey generations start at zero in the existing kernel. The nonzero,
/// nonreused account identity below supplies the additional admission epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AllocationOwner {
    pub process: ProcessKey,
    pub context: u64,
    pub domain: DomainId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resource {
    GlobalBytes,
    OwnerBytes,
    Slots,
    Owners,
    Cleanup,
    Workers,
    WorkTickets,
    BackendRequests,
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeapError {
    Configuration,
    HostAllocation,
    Capacity(Resource),
    Size,
    Owner,
    Closed,
    StaleReservation,
    StaleRevision,
    StaleInitialization,
    Pointer(super::PointerError),
    MissingKind,
    InvalidFree,
    Busy,
    Worker,
    Lease,
    StaleWork,
    WorkState,
    StaleCleanup,
    PhysicalPlacement(PlacementError),
    VirtualPlacement(PlacementError),
}

/// An opaque account capability; a reused process or account row cannot select
/// an old obligation. No constructor from integer payloads is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerAccount {
    index: usize,
    serial: u64,
}

/// Private staging identity, NOT a protected pointer or authority to memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapReservation {
    slot: usize,
    generation: u32,
    job: u64,
    owner: OwnerAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Account {
    token: OwnerAccount,
    owner: AllocationOwner,
    closed: bool,
    limit: u64,
    reserved: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HeapRecord {
    owner: OwnerAccount,
    logical: u64,
    rounded: u64,
    cleanup: usize,
    published: bool,
    writable: bool,
    /// Sticky once Fabric/work is attached; direct cancellation then closes.
    ever_attached: bool,
    extents: Option<HeapExtents>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CleanupRecord {
    reservation: HeapReservation,
    // Durable pending obligation, retained through Closing and Retired.
    queued: bool,
    lease: workers::JobLease,
    // Cleanup mutation identity, distinct from lease epoch and private
    // initialization version. Recovery advances it without wrapping.
    version: u64,
    sequence: u64,
    progress: workers::HeapScrubProgress,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct HeapLedger {
    accounts: Vec<Option<Account>>,
    cleanup: Vec<Option<CleanupRecord>>,
    workers: Vec<Option<workers::WorkerRecord>>,
    next_worker: u64,
    next_owner: u64,
    next_job: u64,
    pub(super) revision: u64,
    fixed_bytes: u64,
    reserved_bytes: u64,
    limit: u64,
    placement: Option<placement::HeapPlacement>,
}

impl HeapLedger {
    /// MAX is a terminal admission fence. Cleanup still runs after exhaustion;
    /// no successful admission can ever use a snapshot at MAX. No wrap/reset.
    pub(super) fn advance(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}

fn fixed_table<T: Clone>(length: usize, value: T) -> Result<Vec<T>, HeapError> {
    let mut table = Vec::new();
    table
        .try_reserve_exact(length)
        .map_err(|_| HeapError::HostAllocation)?;
    table.resize(length, value);
    Ok(table)
}

fn bytes<T>(count: usize) -> Result<u64, HeapError> {
    count
        .checked_mul(size_of::<T>())
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(HeapError::Configuration)
}

impl OwnerAccount { pub(crate) fn serial(self) -> u64 { self.serial } }
impl HeapReservation { pub(crate) fn incarnation(self) -> u64 { self.job } }

impl ScopedPointers {
    pub(crate) fn with_limits(limits: RegistryLimits) -> Result<Self, HeapError> {
        if limits.slots > u32::MAX as usize || limits.cleanup > u32::MAX as usize {
            return Err(HeapError::Configuration);
        }
        // Reject impossible budgets before allocating. Recompute with actual
        // retained capacities below (try_reserve_exact may return more).
        let footprint = |slots, scopes, owners, cleanup| -> Result<u64, HeapError> {
            [
                bytes::<Self>(1)?,
                bytes::<Slot>(slots)?,
                bytes::<Option<super::ScopeRecord>>(scopes)?,
                bytes::<Option<Account>>(owners)?,
                bytes::<Option<CleanupRecord>>(cleanup)?,
            ]
            .into_iter()
            .try_fold(0u64, |sum, n| {
                sum.checked_add(n).ok_or(HeapError::Configuration)
            })
        };
        if footprint(limits.slots, limits.scopes, limits.owners, limits.cleanup)?
            > limits.global_bytes
        {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let slots = fixed_table(limits.slots, Slot::EMPTY)?;
        let scopes = fixed_table(limits.scopes, None)?;
        let accounts = fixed_table(limits.owners, None)?;
        let cleanup = fixed_table(limits.cleanup, None)?;
        let fixed_bytes = footprint(
            slots.capacity(),
            scopes.capacity(),
            accounts.capacity(),
            cleanup.capacity(),
        )?;
        if fixed_bytes > limits.global_bytes {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        Ok(Self {
            slots,
            scopes,
            active_slots_end: 0,
            active_scopes_end: 0,
            next_scope: 1,
            heap: HeapLedger {
                accounts,
                cleanup,
                workers: Vec::new(),
                next_worker: 1,
                next_owner: 1,
                next_job: 1,
                revision: 0,
                fixed_bytes,
                reserved_bytes: 0,
                limit: limits.global_bytes,
                placement: None,
            },
        })
    }

    pub(crate) fn revision(&self) -> u64 {
        self.heap.revision
    }
    pub(crate) fn fixed_metadata_bytes(&self) -> u64 {
        self.heap.fixed_bytes
    }
    pub(crate) fn total_reserved_bytes(&self) -> u64 {
        self.heap.fixed_bytes + self.heap.reserved_bytes
    }

    fn account(&self, token: OwnerAccount) -> Result<&Account, HeapError> {
        self.heap
            .accounts
            .get(token.index)
            .and_then(Option::as_ref)
            .filter(|a| a.token == token)
            .ok_or(HeapError::Owner)
    }

    pub(crate) fn account_reserved_bytes(&self, token: OwnerAccount) -> Result<u64, HeapError> {
        Ok(self.account(token)?.reserved)
    }

    /// Reserve retained owner/account capacity before process heap admission.
    pub(crate) fn admit_owner(
        &mut self,
        owner: AllocationOwner,
        limit: u64,
    ) -> Result<OwnerAccount, HeapError> {
        if owner.context == 0 {
            return Err(HeapError::Owner);
        }
        // One account for an exact process incarnation, regardless of whether a
        // mistaken caller changes its context/domain. Closed rows remain held.
        if self
            .heap
            .accounts
            .iter()
            .flatten()
            .any(|a| a.owner.process == owner.process)
        {
            return Err(HeapError::Owner);
        }
        if self.heap.revision == u64::MAX || self.heap.next_owner == u64::MAX {
            return Err(HeapError::Capacity(Resource::Identity));
        }
        let index = self
            .heap
            .accounts
            .iter()
            .position(Option::is_none)
            .ok_or(HeapError::Capacity(Resource::Owners))?;
        let token = OwnerAccount {
            index,
            serial: self.heap.next_owner,
        };
        if let Some(p) = &self.heap.placement {
            p.virtual_arenas[index]
                .check_binding(None)
                .map_err(HeapError::VirtualPlacement)?;
        }
        if let Some(p) = &mut self.heap.placement {
            p.virtual_arenas[index].bind_owner(Some(token.serial));
        }
        self.heap.accounts[index] = Some(Account {
            token,
            owner,
            closed: false,
            limit,
            reserved: 0,
        });
        self.heap.next_owner += 1;
        self.heap.advance();
        Ok(token)
    }

    /// Reserve identity, cleanup, quota and (in the A2.2 profile) both extents
    /// under the same exclusive borrow and revision. All fallible checks precede
    /// the first write. This creates custody only, with no Fabric authority.
    pub(crate) fn reserve_heap(
        &mut self,
        owner: OwnerAccount,
        logical: u64,
        expected_revision: u64,
    ) -> Result<HeapReservation, HeapError> {
        let account = *self.account(owner)?;
        if account.closed {
            return Err(HeapError::Closed);
        }
        if logical == 0 || logical > i64::MAX as u64 {
            return Err(HeapError::Size);
        }
        let rounded = page_ceil(logical).map_err(|_| HeapError::Size)?;
        if expected_revision != self.heap.revision {
            return Err(HeapError::StaleRevision);
        }
        if self.heap.revision == u64::MAX || self.heap.next_job == u64::MAX {
            return Err(HeapError::Capacity(Resource::Identity));
        }
        if rounded > account.limit - account.reserved {
            return Err(HeapError::Capacity(Resource::OwnerBytes));
        }
        if rounded > self.heap.limit - self.total_reserved_bytes() {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let slot = self
            .free_slot()
            .ok_or(HeapError::Capacity(Resource::Slots))?;
        let cleanup = self
            .heap
            .cleanup
            .iter()
            .position(Option::is_none)
            .ok_or(HeapError::Capacity(Resource::Cleanup))?;
        let generation = self.slots[slot].generation + 1;
        let reservation = HeapReservation {
            slot,
            generation,
            job: self.heap.next_job,
            owner,
        };
        let plan = self
            .heap
            .placement
            .as_ref()
            .map(|p| p.prepare_reserve(reservation, rounded, self.heap.revision))
            .transpose()?;
        let extents = plan.as_ref().map(placement::AdmissionPlacement::extents);
        // Every check precedes the first write. All tables already exist.
        if let Some(plan) = plan {
            self.heap
                .placement
                .as_mut()
                .unwrap()
                .commit_reserve(owner, plan, self.heap.revision);
        }
        self.slots[slot] = Slot {
            generation,
            state: SlotState::Reserved,
            record: Record::Heap(HeapRecord {
                owner,
                logical,
                rounded,
                cleanup,
                published: false,
                writable: true,
                ever_attached: false,
                extents,
            }),
        };
        self.active_slots_end = self.active_slots_end.max(slot + 1);
        self.heap.cleanup[cleanup] = Some(CleanupRecord {
            reservation,
            queued: false,
            lease: workers::JobLease::EMPTY,
            version: 0,
            sequence: 0,
            progress: workers::HeapScrubProgress::Pending,
        });
        self.heap.accounts[owner.index].as_mut().unwrap().reserved += rounded;
        self.heap.reserved_bytes += rounded;
        self.heap.next_job += 1;
        self.heap.advance();
        Ok(reservation)
    }

    fn reservation_record(&self, reservation: HeapReservation) -> Result<HeapRecord, HeapError> {
        self.account(reservation.owner)?;
        let slot = self
            .slots
            .get(reservation.slot)
            .ok_or(HeapError::StaleReservation)?;
        if slot.generation != reservation.generation
            || !matches!(
                slot.state,
                SlotState::Reserved | SlotState::Live | SlotState::Closing | SlotState::Retired
            )
        {
            return Err(HeapError::StaleReservation);
        }
        let Record::Heap(record) = slot.record else {
            return Err(HeapError::StaleReservation);
        };
        if record.owner != reservation.owner
            || self.heap.cleanup.get(record.cleanup).and_then(Option::as_ref)
                .is_none_or(|job| job.reservation != reservation)
        {
            return Err(HeapError::StaleReservation);
        }
        Ok(record)
    }

    /// Cancel an exact never-attached private reservation, including after owner
    /// closure/terminal revision. Preflight BOTH returns before any mutation.
    /// Previously attached or published resources require the later Undertaker.
    pub(crate) fn abort_heap(&mut self, reservation: HeapReservation) -> Result<(), HeapError> {
        let record = self.reservation_record(reservation)?;
        if record.published
            || record.ever_attached
            || !matches!(
                self.slots[reservation.slot].state,
                SlotState::Reserved | SlotState::Closing
            )
        {
            return Err(HeapError::Busy);
        }
        let held = self.account(record.owner)?.reserved;
        if held < record.rounded || self.heap.reserved_bytes < held {
            return Err(HeapError::Configuration);
        }
        let plan = match (&self.heap.placement, record.extents) {
            (None, None) => None,
            (Some(p), Some(e)) => {
                if e.physical.size != record.rounded || e.virtual_extent.size != record.rounded {
                    return Err(HeapError::StaleReservation);
                }
                Some(p.prepare_cancel(reservation, e, self.heap.revision)?)
            }
            _ => return Err(HeapError::Configuration),
        };
        if let Some(plan) = plan {
            self.heap.placement.as_mut().unwrap().commit_cancel(
                record.owner,
                plan,
                self.heap.revision,
            );
        }
        self.heap.accounts[record.owner.index]
            .as_mut()
            .unwrap()
            .reserved -= record.rounded;
        self.heap.reserved_bytes -= record.rounded;
        self.heap.cleanup[record.cleanup] = None;
        let slot = &mut self.slots[reservation.slot];
        slot.record = Record::Empty;
        slot.release();
        self.trim_active_slots();
        self.heap.advance();
        Ok(())
    }

    /// Close one whole live heap, independently of local-frame or heap order.
    /// No currently enabled runtime path issues such a pointer. The eventual
    /// publication path must recheck owner/ledger and attach all actual backing.
    pub(crate) fn close_heap(
        &mut self,
        owner: OwnerAccount,
        pointer: ScopedPointer,
    ) -> Result<(), HeapError> {
        if self.account(owner)?.closed {
            return Err(HeapError::Closed);
        }
        let slot = self.slots.get(pointer.slot).ok_or(HeapError::InvalidFree)?;
        if pointer.position != 0
            || slot.generation != pointer.generation
            || slot.state != SlotState::Live
        {
            return Err(HeapError::InvalidFree);
        }
        let Record::Heap(record) = slot.record else {
            return Err(HeapError::InvalidFree);
        };
        if record.owner != owner || !record.published {
            return Err(HeapError::InvalidFree);
        }
        self.slots[pointer.slot].state = SlotState::Closing;
        self.heap.cleanup[record.cleanup].as_mut().unwrap().queued = true;
        self.heap.advance();
        Ok(())
    }

    /// Atomic owner fence plus a complete census. The fixed directory IS the
    /// queue: even a full queue/identity exhaustion needs no allocation or ID.
    /// Already queued jobs are not counted twice, and all charges remain held.
    pub(crate) fn close_owner(&mut self, owner: OwnerAccount) -> Result<usize, HeapError> {
        if self.account(owner)?.closed {
            return Ok(0);
        }
        self.heap.accounts[owner.index].as_mut().unwrap().closed = true;
        for slot in &mut self.slots {
            if matches!(slot.record, Record::Heap(record) if record.owner == owner)
                && matches!(slot.state, SlotState::Reserved | SlotState::Live)
            {
                slot.state = SlotState::Closing;
            }
        }
        let mut queued = 0;
        for job in self.heap.cleanup.iter_mut().flatten() {
            if job.reservation.owner == owner && !job.queued {
                job.queued = true;
                queued += 1;
            }
        }
        self.heap.advance();
        Ok(queued)
    }

    /// Return only the account row, never its fixed infrastructure charge.
    pub(crate) fn release_owner(&mut self, owner: OwnerAccount) -> Result<(), HeapError> {
        let account = self.account(owner)?;
        if !account.closed
            || account.reserved != 0
            || self
                .heap
                .cleanup
                .iter()
                .flatten()
                .any(|j| j.reservation.owner == owner)
        {
            return Err(HeapError::Busy);
        }
        if let Some(p) = &self.heap.placement {
            p.virtual_arenas[owner.index]
                .check_binding(Some(owner.serial))
                .map_err(HeapError::VirtualPlacement)?;
        }
        if let Some(p) = &mut self.heap.placement {
            p.virtual_arenas[owner.index].bind_owner(None);
        }
        self.heap.accounts[owner.index] = None;
        self.heap.advance();
        Ok(())
    }
}

#[cfg(test)]
mod tests;

// Synthetic live lifetimes for conditional access tests only. This module is
// absent from non-test builds; it is not the future publication implementation.
#[cfg(test)]
pub(crate) mod cell_test_support;

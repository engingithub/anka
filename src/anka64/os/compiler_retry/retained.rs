//! C2.5b custody/cleanup boundary. Ready candidates are PRIVATE, not published
//! artifacts or receipts. Final current-provenance/authority/epoch commit follows.
use super::*;
use crate::anka64::compiler_adapter::RebuildAdmissionRole;
use crate::anka64::scoped_pointers::heap::HeapReservation;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompilerCandidateError {
    Unknown,
    Custodian,
    Discarding,
    Storage,
    Heap(HeapError),
}
impl From<HeapError> for CompilerCandidateError {
    fn from(error: HeapError) -> Self { Self::Heap(error) }
}

/// Non-Clone opaque reference. Reservation incarnation never wraps/reuses;
/// custodian context distinguishes independent Kernel/Fabric instances.
#[derive(Debug)]
pub(crate) struct CompilerCandidateHandle {
    reservation: HeapReservation,
    custodian: AllocationOwner,
}

pub(super) struct Candidate {
    reservation: HeapReservation,
    custodian: AllocationOwner,
    producer: AllocationOwner,
    context: CompilerReplyContext,
    role: RebuildAdmissionRole,
    publication: Option<super::publication::PublicationKey>,
    charge: u64,
    pub(super) bytes: Vec<u8>,
    ready: bool,
    discarding: bool,
}

#[derive(Default)]
pub(crate) struct CompilerCandidates {
    records: BTreeMap<u64, Candidate>,
}
impl CompilerCandidates {
    pub(super) fn get(&self, handle: &CompilerCandidateHandle) -> Result<&Candidate, CompilerCandidateError> {
        self.records.get(&handle.reservation.incarnation()).filter(|r|
            r.reservation == handle.reservation && r.custodian == handle.custodian)
            .ok_or(CompilerCandidateError::Unknown)
    }
}

/// Borrow of admitted bytes after exact producer cleanup, not execution rights.
/// It holds the Kernel immutably; mutation or removal cannot interleave its use.
pub(crate) struct CompilerCandidateView<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) context: CompilerReplyContext,
    pub(crate) role: RebuildAdmissionRole,
    pub(crate) producer: AllocationOwner,
    pub(super) publication: Option<super::publication::PublicationKey>,
}

impl Kernel {
    pub(super) fn retain_compiler_candidate(
        &mut self, producer: AllocationOwner, context: CompilerReplyContext,
        role: RebuildAdmissionRole, publication: Option<super::publication::PublicationKey>,
        bytes: &mut Vec<u8>,
    ) -> Result<CompilerCandidateHandle, CompilerCandidateError> {
        // Only capture's private constructor calls this. Keep source ownership
        // live until the new charge and record are both installed.
        if self.compiler_owner(producer.process).ok() != Some(producer) || bytes.is_empty() {
            return Err(CompilerCandidateError::Custodian);
        }
        let (custodian, account) = self.compiler_candidate_account()?;
        if custodian == producer { return Err(CompilerCandidateError::Custodian); }
        // Charge actual Vec capacity and a conservative per-record/node allowance.
        // No new payload copy; both old staging and new custody are charged at
        // the handoff peak. Host allocator overhead/RSS is not claimed exact.
        let charge = u64::try_from(bytes.capacity()).ok()
            .and_then(|n| n.checked_add(std::mem::size_of::<Candidate>() as u64))
            .and_then(|n| n.checked_add(4096)).ok_or(CompilerCandidateError::Storage)?;
        let reservation = self.fabric.scoped_pointers.reserve_heap(
            account, charge, self.fabric.scoped_pointers.revision())?;
        let id = reservation.incarnation();
        // Registry incarnations are injective; do not replace an old record if
        // that invariant is ever broken. No byte ownership moves on failure.
        if self.compiler_candidates.records.contains_key(&id) {
            self.fabric.scoped_pointers.abort_heap(reservation)?;
            return Err(CompilerCandidateError::Storage);
        }
        self.compiler_candidates.records.insert(id, Candidate {
            reservation, custodian, producer, context, role, publication, charge,
            bytes: std::mem::take(bytes), ready: false, discarding: false,
        });
        Ok(CompilerCandidateHandle { reservation, custodian })
    }

    fn check_compiler_candidate(&self, handle: &CompilerCandidateHandle)
        -> Result<&Candidate, CompilerCandidateError>
    {
        let record = self.compiler_candidates.get(handle)?;
        if record.discarding { return Err(CompilerCandidateError::Discarding); }
        if self.compiler_candidate_custodian()? != record.custodian {
            return Err(CompilerCandidateError::Custodian);
        }
        // Existing exact, read-only reservation preflight: owner, generation,
        // incarnation, current revision, unclosed account, and reserved state.
        let plan = self.fabric.scoped_pointers.prepare_heap_attachment(
            record.reservation, record.custodian, self.fabric.scoped_pointers.revision())?;
        if plan.logical() != record.charge { return Err(CompilerCandidateError::Storage); }
        Ok(record)
    }

    /// At most one existing cleanup step; caller-supplied flags/timeouts cannot
    /// establish readiness. A stalled producer leaves the candidate charged.
    pub(crate) fn poll_compiler_candidate(&mut self, handle: &CompilerCandidateHandle)
        -> Result<bool, CompilerCandidateError>
    {
        let producer = self.check_compiler_candidate(handle)?.producer;
        self.advance_heap_cleanup();
        let released = self.fabric.compiler_heap_owner_released(producer);
        self.check_compiler_candidate(handle)?;
        if released {
            self.compiler_candidates.records.get_mut(&handle.reservation.incarnation())
                .ok_or(CompilerCandidateError::Unknown)?.ready = true;
        }
        Ok(released)
    }

    pub(crate) fn compiler_candidate(&self, handle: &CompilerCandidateHandle)
        -> Result<Option<CompilerCandidateView<'_>>, CompilerCandidateError>
    {
        let record = self.check_compiler_candidate(handle)?;
        if !record.ready || !self.fabric.compiler_heap_owner_released(record.producer) {
            return Ok(None);
        }
        Ok(Some(CompilerCandidateView { bytes: &record.bytes, context: record.context,
            role: record.role, producer: record.producer, publication: record.publication }))
    }

    /// Destroy bytes before refunding. If exact abort fails, retain an empty,
    /// unreadable tombstone AND its reservation so the cancellation can retry.
    pub(crate) fn discard_compiler_candidate(&mut self, handle: &CompilerCandidateHandle)
        -> Result<(), CompilerCandidateError>
    {
        self.compiler_candidates.get(handle)?;
        let id = handle.reservation.incarnation();
        let record = self.compiler_candidates.records.get_mut(&id).unwrap();
        record.discarding = true;
        drop(std::mem::take(&mut record.bytes));
        self.fabric.scoped_pointers.abort_heap(record.reservation)?;
        self.compiler_candidates.records.remove(&id);
        Ok(())
    }

    pub(crate) fn discard_compiler_candidates_owned_by(&mut self, owner: AllocationOwner) {
        // Account closure may subsequently refund never-attached reservations.
        // Drop every payload first, even if one reservation cannot be cancelled.
        for record in self.compiler_candidates.records.values_mut().filter(|r| r.custodian == owner) {
            record.discarding = true;
            drop(std::mem::take(&mut record.bytes));
        }
        // retain() here is BTreeMap's in-place traversal, not a candidate handoff.
        let registry = &mut self.fabric.scoped_pointers;
        self.compiler_candidates.records.retain(|_, r|
            r.custodian != owner || registry.abort_heap(r.reservation).is_err());
    }

    pub(crate) fn discard_all_compiler_candidates(&mut self) -> bool {
        for record in self.compiler_candidates.records.values_mut() {
            record.discarding = true;
            drop(std::mem::take(&mut record.bytes));
        }
        let registry = &mut self.fabric.scoped_pointers;
        self.compiler_candidates.records.retain(|_, r| registry.abort_heap(r.reservation).is_err());
        self.compiler_candidates.records.is_empty()
    }
}

#[cfg(test)]
mod tests;

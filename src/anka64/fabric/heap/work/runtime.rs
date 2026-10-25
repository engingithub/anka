//! A2.3.5c: synchronous software effects, exact terminal consumption and current
//! census. Every operation holds the same exclusive Fabric borrow throughout.
//! No device, guest completion, worker scrub or memory-release path is enabled.
use super::*;
use crate::anka64::fabric::heap::cells::HeapSpan;
use crate::anka64::scoped_pointers::heap::{CleanupLease, HeapWorkCleanupRevision};

/// Diagnostic counts of registered, UNCONSUMED records (including terminal
/// sources). No mutator accepts these counts or treats them as authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapWorkCounts {
    pub cpu: u64,
    pub dma: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeapWorkOutcome {
    Committed,
    Cancelled,
}

struct EffectPlan {
    record: WorkRecord,
    span: HeapSpan,
    revision: HeapWorkCleanupRevision,
}

struct FinishPlan {
    record: WorkRecord,
    outcome: HeapWorkOutcome,
    revision: HeapWorkCleanupRevision,
}

pub(super) fn scratch_bytes() -> Result<u64, HeapError> {
    [
        storage::<EffectPlan>(1)?,
        storage::<FinishPlan>(1)?,
        storage::<HeapWorkCounts>(1)?,
    ]
    .into_iter()
    .try_fold(0u64, |n, b| {
        n.checked_add(b).ok_or(HeapError::Configuration)
    })
}

impl Fabric {
    fn checked_work_record(&self, ticket: HeapWorkTicket) -> Result<WorkRecord, HeapError> {
        let work = self
            .private_heap
            .as_ref()
            .and_then(|h| h.work.as_ref())
            .ok_or(HeapError::Configuration)?;
        work.check_pins()?;
        let record = work.checked_record(ticket)?;
        self.check_retained_work_record(record)?;
        Ok(record)
    }

    fn work_state(&self, record: WorkRecord) -> CpuRequestState {
        // The exact pin was checked in this exclusive operation; no callback
        // or externally retained mutable reference can change the source row.
        self.private_heap
            .as_ref()
            .unwrap()
            .work
            .as_ref()
            .unwrap()
            .sources[record.source.index as usize]
            .request
            .as_ref()
            .unwrap()
            .state
    }

    fn require_prepared_work(&self, record: WorkRecord) -> Result<(), HeapError> {
        if self.work_state(record) != CpuRequestState::Prepared {
            return Err(HeapError::WorkState);
        }
        Ok(())
    }

    /// Execute one already-admitted request. Its exact retained authorization
    /// can finish after allocation/owner closure, while new admission remains
    /// fenced. There is no partially-running backend or delayed callback here.
    pub(crate) fn execute_heap_cpu_work(
        &mut self,
        ticket: HeapWorkTicket,
    ) -> Result<(), HeapError> {
        let record = self.checked_work_record(ticket)?;
        self.require_prepared_work(record)?;
        if !self.heap_pool_is_private() {
            return Err(HeapError::Busy);
        }
        let b = record.binding;
        let plan = EffectPlan {
            record,
            span: self
                .checked_heap_backing_span(b.logical, b.extents, b.offset, b.length, false)?,
            revision: self.scoped_pointers.prepare_heap_work_cleanup_revision(),
        };
        let heap = self.private_heap.as_mut().unwrap();
        let source = heap.work.as_mut().unwrap().sources[plan.record.source.index as usize]
            .request
            .as_mut()
            .unwrap();
        let length = plan.record.binding.length as usize;
        match plan.record.binding.access {
            CpuAccess::Read => {
                source.payload[..length].copy_from_slice(&self.memory[plan.span.bytes])
            }
            CpuAccess::Write => {
                self.memory[plan.span.bytes].copy_from_slice(&source.payload[..length]);
                // Scalar writes invalidate every intersected protected cell,
                // including partial writes to either half. No tag laundering.
                heap.shadow[plan.span.shadow].fill(None);
            }
        }
        // Effects and read capture are complete/visible before terminal state.
        source.state = CpuRequestState::Committed;
        self.scoped_pointers
            .commit_heap_work_cleanup_revision(plan.revision);
        Ok(())
    }

    /// Explicit trusted cancellation before execution. Prepared means no
    /// effects have started in this backend, so this establishes stopped work;
    /// a timeout/notification alone never sets terminal state or consumes a pin.
    pub(crate) fn cancel_heap_cpu_work(&mut self, ticket: HeapWorkTicket) -> Result<(), HeapError> {
        let record = self.checked_work_record(ticket)?;
        self.require_prepared_work(record)?;
        let revision = self.scoped_pointers.prepare_heap_work_cleanup_revision();
        let source = self
            .private_heap
            .as_mut()
            .unwrap()
            .work
            .as_mut()
            .unwrap()
            .sources[record.source.index as usize]
            .request
            .as_mut()
            .unwrap();
        source.payload.fill(0);
        source.state = CpuRequestState::Cancelled;
        self.scoped_pointers
            .commit_heap_work_cleanup_revision(revision);
        Ok(())
    }

    /// Full pin/source scan AND full active-record custody validation. Foreign
    /// jobs do not contribute, but malformed foreign records still reject.
    /// Called afresh in each consuming/deciding operation, even at revision MAX.
    fn current_work_census(&self, selected: HeapReservation) -> Result<HeapWorkCounts, HeapError> {
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        let mut counts = HeapWorkCounts { cpu: 0, dma: 0 };
        if let Some(work) = &heap.work {
            work.check_pins()?;
            for record in work.records.iter().flatten() {
                self.check_retained_work_record(*record)?;
                // All source states count until the exact pair is consumed.
                // CPU/software class is fixed by these private record types.
                if record.binding.reservation == selected {
                    counts.cpu = counts.cpu.checked_add(1).ok_or(HeapError::Configuration)?;
                }
            }
        }
        Ok(counts)
    }

    /// Trusted diagnostics, not a reusable drain certificate. The exact
    /// selected job may be live or closing, including unpublished cleanup.
    pub(crate) fn heap_work_census(
        &mut self,
        reservation: HeapReservation,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<HeapWorkCounts, HeapError> {
        let plan = self
            .scoped_pointers
            .prepare_attached_heap_closure(reservation, owner)?;
        self.check_attached_heap_custody(&plan, object)?;
        self.current_work_census(reservation)
    }

    /// Terminal status is read from the exact source, never supplied by a
    /// caller. A fresh complete census precedes removing BOTH rows once.
    /// Read results are trusted backend data until this explicit consumption;
    /// guest result delivery is not wired, and consumption discards that data.
    pub(crate) fn finish_heap_cpu_work(
        &mut self,
        ticket: HeapWorkTicket,
    ) -> Result<HeapWorkOutcome, HeapError> {
        let record = self.checked_work_record(ticket)?;
        let outcome = match self.work_state(record) {
            CpuRequestState::Prepared => return Err(HeapError::WorkState),
            CpuRequestState::Committed => HeapWorkOutcome::Committed,
            CpuRequestState::Cancelled => HeapWorkOutcome::Cancelled,
        };
        let census = self.current_work_census(record.binding.reservation)?;
        if census.cpu == 0 || census.dma != 0 {
            return Err(HeapError::StaleWork);
        }
        let plan = FinishPlan {
            record,
            outcome,
            revision: self.scoped_pointers.prepare_heap_work_cleanup_revision(),
        };
        let work = self.private_heap.as_mut().unwrap().work.as_mut().unwrap();
        let source = &mut work.sources[plan.record.source.index as usize];
        source.request.as_mut().unwrap().payload.fill(0);
        source.request = None;
        work.records[plan.record.ticket.row as usize - 1] = None;
        // Neither issuance counter nor next source generation is reset.
        // No backing/tag/extent/accounting mutation and no cleanup job removal.
        self.scoped_pointers
            .commit_heap_work_cleanup_revision(plan.revision);
        Ok(plan.outcome)
    }

    /// Current observation only. Future retirement must repeat these checks in
    /// its own exclusive operation; this boolean cannot authorize later reuse.
    pub(crate) fn heap_cleanup_ready(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        lease: CleanupLease,
        owner: AllocationOwner,
        object: ObjectId,
    ) -> Result<bool, HeapError> {
        let identity = self.checked_cleanup_descriptor(current)?;
        let plan = self
            .scoped_pointers
            .prepare_heap_worker_lease(lease, identity, owner)?;
        self.check_attached_heap_custody(&plan, object)?;
        let census = self.current_work_census(plan.reservation())?;
        // No private-heap DMA/worker effect path is enabled. Registered CPU
        // effects are synchronous and pinned until consumed. The existing
        // pool exclusion checks all enabled legacy paths separately.
        Ok(census.cpu == 0 && census.dma == 0 && self.heap_pool_is_private())
    }
}

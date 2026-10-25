//! A2.3.5b: atomic registration in a bounded ledger AND concrete software CPU
//! request backend. A2.3.5c supplies synchronous effects and terminal accounting.
//! All records are application CPU work, never worker scrub or DMA operations.
use super::*;
use crate::anka64::os::CurrentHeapProcess;
use crate::anka64::scoped_pointers::heap::HeapWorkRevision;
use crate::anka64::state::{AgentId, AgentKind};
mod runtime;
pub(crate) use runtime::{HeapWorkCounts, HeapWorkOutcome};

const MAX_CPU_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HeapWorkLimits {
    pub tickets: usize,
    pub requests: usize,
}

/// No guest/integer constructor. Row is one-based; operation is globally
/// nonreused within this heap backend and distinct from legacy TransactionId.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapWorkTicket {
    row: u32,
    operation: u64,
}

/// These source indices/generations/request IDs may be zero. They are not
/// heap operation IDs and cannot select a legacy transaction or device request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuSourceKey {
    index: u32,
    generation: u64,
    request: u64,
}

// Closed type encodes the accepted first profile. There is no integer decoder,
// controller backend, atomic access or DMA work class in this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkBinding {
    reservation: HeapReservation,
    owner: AllocationOwner,
    object: ObjectId,
    object_generation: Generation,
    logical: u64,
    extents: HeapExtents,
    rights: Permissions,
    agent: AgentId,
    offset: u64,
    length: u64,
    access: CpuAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkRecord {
    ticket: HeapWorkTicket,
    source: CpuSourceKey,
    binding: WorkBinding,
}

/// Real queued command, pinned to exactly one ledger row/operation. Write input
/// is copied into fixed owned storage at admission; reads start with zeros.
/// Scalar bytes carry no pointer-kind authority. Only the synchronous trusted
/// executor/canceller may change state; application notifications cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CpuRequest {
    key: CpuSourceKey,
    pin: HeapWorkTicket,
    binding: WorkBinding,
    payload: [u8; MAX_CPU_BYTES],
    state: CpuRequestState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuRequestState {
    Prepared,
    Committed,
    /// Concrete faulted terminal case: cancelled before execution began.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CpuSourceSlot {
    next_generation: Option<u64>,
    request: Option<CpuRequest>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct HeapCpuWork {
    records: Vec<Option<WorkRecord>>,
    sources: Vec<CpuSourceSlot>,
    next_operation: u64,
    next_request: Option<u64>,
}

struct PreparedPair {
    record: WorkRecord,
    request: CpuRequest,
}

struct Admission {
    revision: HeapWorkRevision,
    pair: PreparedPair,
}

impl HeapCpuWork {
    fn footprint(tickets: usize, requests: usize) -> Result<u64, HeapError> {
        // Inline Vec/counter/Option descriptors are already in HeapFabric's
        // sizeof charge. Payloads are included in the source element size.
        // Scratch is a value allowance, not an exact stack/RSS measurement.
        [
            storage::<Option<WorkRecord>>(tickets)?,
            storage::<CpuSourceSlot>(requests)?,
            storage::<Admission>(1)?,
            storage::<WorkBinding>(1)?,
            storage::<WorkRecord>(1)?,
            runtime::scratch_bytes()?,
        ]
        .into_iter()
        .try_fold(0u64, |n, b| {
            n.checked_add(b).ok_or(HeapError::Configuration)
        })
    }

    pub(super) fn new(limits: HeapWorkLimits, remaining: u64) -> Result<Self, HeapError> {
        if limits.tickets > u32::MAX as usize || limits.requests > u32::MAX as usize {
            return Err(HeapError::Configuration);
        }
        if Self::footprint(limits.tickets, limits.requests)? > remaining {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let result = Self {
            records: table(limits.tickets, None)?,
            sources: table(
                limits.requests,
                CpuSourceSlot {
                    next_generation: Some(0),
                    request: None,
                },
            )?,
            next_operation: 1,
            next_request: Some(0),
        };
        if result.retained_bytes()? > remaining {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        Ok(result)
    }

    pub(super) fn retained_bytes(&self) -> Result<u64, HeapError> {
        Self::footprint(self.records.capacity(), self.sources.capacity())
    }

    fn checked_record(&self, ticket: HeapWorkTicket) -> Result<WorkRecord, HeapError> {
        let index = ticket.row.checked_sub(1).ok_or(HeapError::StaleWork)? as usize;
        let record = self
            .records
            .get(index)
            .and_then(|r| *r)
            .ok_or(HeapError::StaleWork)?;
        if ticket.operation == 0 || ticket != record.ticket {
            return Err(HeapError::StaleWork);
        }
        let slot = self
            .sources
            .get(record.source.index as usize)
            .ok_or(HeapError::StaleWork)?;
        let source = slot.request.as_ref().ok_or(HeapError::StaleWork)?;
        let b = record.binding;
        if source.key != record.source
            || source.pin != ticket
            || source.binding != b
            || slot.next_generation != source.key.generation.checked_add(1)
            || b.length == 0
            || b.length > MAX_CPU_BYTES as u64
            || b.offset > b.logical
            || b.length > b.logical - b.offset
            || b.offset.checked_add(b.length).is_none()
        {
            return Err(HeapError::StaleWork);
        }
        Ok(record)
    }

    /// Structural pin integrity; the runtime census additionally checks every
    /// active row against current allocation/placement/Fabric custody.
    /// Both directions are checked; an orphan backend request cannot be
    /// mistaken for free capacity or disappear from an admission preflight.
    fn check_pins(&self) -> Result<(), HeapError> {
        for (index, record) in self.records.iter().enumerate() {
            if let Some(record) = record {
                if record.ticket.row as usize != index + 1 {
                    return Err(HeapError::StaleWork);
                }
                self.checked_record(record.ticket)?;
            }
        }
        for (index, slot) in self.sources.iter().enumerate() {
            if let Some(source) = &slot.request {
                if source.key.index as usize != index
                    || self.checked_record(source.pin)?.source != source.key
                {
                    return Err(HeapError::StaleWork);
                }
            }
        }
        Ok(())
    }

    fn prepare(
        &self,
        binding: WorkBinding,
        write: Option<&[u8]>,
    ) -> Result<PreparedPair, HeapError> {
        self.check_pins()?;
        if self.next_operation == 0 || self.next_operation == u64::MAX {
            return Err(HeapError::Capacity(Resource::Identity));
        }
        let request = self
            .next_request
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        let ledger = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(HeapError::Capacity(Resource::WorkTickets))?;
        let source = self
            .sources
            .iter()
            .position(|s| s.request.is_none() && s.next_generation.is_some())
            .ok_or(HeapError::Capacity(Resource::BackendRequests))?;
        let ticket = HeapWorkTicket {
            row: ledger as u32 + 1,
            operation: self.next_operation,
        };
        let key = CpuSourceKey {
            index: source as u32,
            generation: self.sources[source].next_generation.unwrap(),
            request,
        };
        let mut prepared = CpuRequest {
            key,
            pin: ticket,
            binding,
            payload: [0; MAX_CPU_BYTES],
            state: CpuRequestState::Prepared,
        };
        match (binding.access, write) {
            (CpuAccess::Write, Some(bytes))
                if bytes.len() == binding.length as usize && bytes.len() <= MAX_CPU_BYTES =>
            {
                prepared.payload[..bytes.len()].copy_from_slice(bytes);
            }
            (CpuAccess::Read, None) => {}
            _ => return Err(HeapError::Configuration),
        }
        Ok(PreparedPair {
            record: WorkRecord {
                ticket,
                source: key,
                binding,
            },
            request: prepared,
        })
    }

    fn commit(&mut self, plan: PreparedPair) -> HeapWorkTicket {
        let ticket = plan.record.ticket;
        let key = plan.record.source;
        let index = ticket.row as usize - 1;
        // Internal preflight assertions all precede the first row mutation.
        assert_eq!(ticket.operation, self.next_operation);
        assert_eq!(self.next_request, Some(key.request));
        assert!(self.records[index].is_none());
        let source = &mut self.sources[key.index as usize];
        assert!(source.request.is_none());
        assert_eq!(source.next_generation, Some(key.generation));
        source.next_generation = key.generation.checked_add(1);
        source.request = Some(plan.request);
        self.records[index] = Some(plan.record);
        self.next_operation += 1; // preflight rejected MAX
        self.next_request = key.request.checked_add(1);
        ticket
    }
}

impl Fabric {
    fn prepare_heap_cpu_work(
        &self,
        current: &CurrentHeapProcess<'_>,
        pointer: Option<ScopedPointer>,
        length: u64,
        write: Option<&[u8]>,
        expected: u64,
    ) -> Result<Admission, HeapError> {
        let work = self
            .private_heap
            .as_ref()
            .and_then(|h| h.work.as_ref())
            .ok_or(HeapError::Configuration)?;
        let revision = self.scoped_pointers.prepare_heap_work_revision(expected)?;
        let owner = current.owner();
        let agent = current.agent();
        if owner.context == 0
            || !self
                .domains
                .get(&owner.domain)
                .is_some_and(|d| d.id == owner.domain)
            || !self.agents.get(&agent).is_some_and(|a| {
                a.id == agent && a.domain == owner.domain && matches!(a.kind, AgentKind::Cpu(_))
            })
        {
            return Err(HeapError::Owner);
        }
        let live = self.checked_live_heap(owner, agent, pointer.ok_or(HeapError::MissingKind)?)?;
        self.checked_heap_span(&live, length, false)?;
        let binding = WorkBinding {
            reservation: live.pointer.reservation(),
            owner,
            object: live.row.object,
            object_generation: live.row.object_generation,
            logical: live.row.logical,
            extents: live.row.extents,
            rights: live.row.planned_rights,
            agent,
            offset: live.pointer.position(),
            length,
            access: if write.is_some() {
                CpuAccess::Write
            } else {
                CpuAccess::Read
            },
        };
        Ok(Admission {
            revision,
            pair: work.prepare(binding, write)?,
        })
    }

    pub(crate) fn register_heap_cpu_read(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        pointer: Option<ScopedPointer>,
        length: u64,
        expected: u64,
    ) -> Result<HeapWorkTicket, HeapError> {
        let plan = self.prepare_heap_cpu_work(current, pointer, length, None, expected)?;
        Ok(self.commit_heap_cpu_work(plan))
    }

    pub(crate) fn register_heap_cpu_write(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        pointer: Option<ScopedPointer>,
        bytes: &[u8],
        expected: u64,
    ) -> Result<HeapWorkTicket, HeapError> {
        let length = u64::try_from(bytes.len()).map_err(|_| HeapError::Size)?;
        let plan = self.prepare_heap_cpu_work(current, pointer, length, Some(bytes), expected)?;
        Ok(self.commit_heap_cpu_work(plan))
    }

    fn commit_heap_cpu_work(&mut self, plan: Admission) -> HeapWorkTicket {
        let ticket = self
            .private_heap
            .as_mut()
            .unwrap()
            .work
            .as_mut()
            .unwrap()
            .commit(plan.pair);
        self.scoped_pointers
            .commit_heap_work_revision(plan.revision);
        ticket
    }

    /// Trusted current binding observation only; no effects, consumption,
    /// refund or reusable readiness certificate. Owner death and
    /// admission-counter exhaustion do not erase retained request identity.
    pub(crate) fn validate_heap_work_ticket(
        &mut self,
        ticket: HeapWorkTicket,
    ) -> Result<(), HeapError> {
        let work = self
            .private_heap
            .as_ref()
            .and_then(|h| h.work.as_ref())
            .ok_or(HeapError::Configuration)?;
        work.check_pins()?;
        let record = work.checked_record(ticket)?;
        self.check_retained_work_record(record)
    }

    fn check_retained_work_record(&self, record: WorkRecord) -> Result<(), HeapError> {
        let b = record.binding;
        let plan = self
            .scoped_pointers
            .prepare_retained_heap_work(b.reservation, b.owner)?;
        self.check_attached_heap_custody(&plan, b.object)?;
        if b.object_generation != Generation(0)
            || b.rights != Permissions::RW
            || b.logical != plan.logical()
            || b.extents != plan.extents()
        {
            return Err(HeapError::StaleWork);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

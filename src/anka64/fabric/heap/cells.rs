//! A2.3.3: bounded protected heap-cell transport and scalar-write invalidation.
//! Live access requires current publication, exact owner and private custody.
//! All methods finish under one exclusive Fabric borrow, with no queued plan,
//! transaction-log growth, BTreeMap insertion or fallible work after mutation.
use super::*;
use crate::anka64::scoped_pointers::PointerError;
use crate::anka64::scoped_pointers::heap::HeapPointerPlan;
use crate::anka64::state::{AgentId, AgentKind};
use std::ops::Range;

pub(super) struct LiveHeap {
    pub(super) pointer: HeapPointerPlan,
    pub(super) row: PrivateHeapRow,
}

pub(super) struct HeapSpan {
    pub(super) bytes: Range<usize>,
    pub(super) shadow: Range<usize>,
}

pub(super) fn scratch_bytes() -> Result<u64, HeapError> {
    // Destination/source plans plus a span and coherent 16-byte payload.
    // Fixed value allowance, not an exact host stack or RSS measurement.
    storage::<LiveHeap>(2)?
        .checked_add(storage::<HeapSpan>(1)?)
        .and_then(|n| n.checked_add(16))
        .ok_or(HeapError::Configuration)
}

fn pointer_bytes(pointer: Option<ScopedPointer>) -> [u8; 16] {
    let words = pointer.map(|p| p.words()).unwrap_or([0, 0]);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&words[0].to_le_bytes());
    bytes[8..].copy_from_slice(&words[1].to_le_bytes());
    bytes
}

impl Fabric {
    pub(super) fn checked_live_heap(
        &self,
        owner: AllocationOwner,
        agent: AgentId,
        pointer: ScopedPointer,
    ) -> Result<LiveHeap, HeapError> {
        if !self.domains.contains_key(&owner.domain)
            || !self
                .agents
                .get(&agent)
                .is_some_and(|a| a.domain == owner.domain && matches!(a.kind, AgentKind::Cpu(_)))
        {
            return Err(HeapError::Owner);
        }
        let plan = self.scoped_pointers.prepare_heap_pointer(pointer, owner)?;
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        let row = heap
            .rows
            .get(plan.slot())
            .and_then(|r| *r)
            .ok_or(HeapError::StaleReservation)?;
        if row.reservation != plan.reservation()
            || row.owner != plan.owner()
            || row.logical != plan.logical()
            || row.extents != plan.extents()
            || row.object_generation != Generation(0)
            || row.object.0 >= heap.object_id_floor
        {
            return Err(HeapError::StaleReservation);
        }
        if row.planned_rights != plan.rights() {
            return Err(HeapError::Pointer(PointerError::Rights));
        }
        // The registry's published live state is the visibility gate. Complete
        // initialization alone never authorizes access. Once live, ordinary
        // writes do not reset a private initialization prefix or spend revision.
        if row.initialized_bytes != row.extents.physical.size || row.initialization_version == 0 {
            return Err(HeapError::Busy);
        }
        heap.check_extents(row.extents)?;
        let end = row.extents.physical.end().ok_or(HeapError::Configuration)?;
        if usize::try_from(end)
            .ok()
            .is_none_or(|end| end > self.memory.len())
        {
            return Err(HeapError::Configuration);
        }
        if self.objects.contains_key(&row.object)
            || self.placement.contains_key(&row.object)
            || !self.heap_pool_is_private()
        {
            return Err(HeapError::Busy);
        }
        Ok(LiveHeap { pointer: plan, row })
    }

    pub(super) fn checked_heap_span(
        &self,
        live: &LiveHeap,
        length: u64,
        cell: bool,
    ) -> Result<HeapSpan, HeapError> {
        self.checked_heap_backing_span(
            live.row.logical,
            live.row.extents,
            live.pointer.position(),
            length,
            cell,
        )
    }

    /// Indexing only, never authority: each caller must first authenticate
    /// either a current live pointer or an exact retained pinned request.
    pub(super) fn checked_heap_backing_span(
        &self,
        logical: u64,
        extents: HeapExtents,
        offset: u64,
        length: u64,
        cell: bool,
    ) -> Result<HeapSpan, HeapError> {
        if length == 0 || length > 4096 || offset > logical || length > logical - offset {
            return Err(HeapError::Pointer(PointerError::Bounds));
        }
        if cell && (length != 16 || offset % 16 != 0) {
            return Err(HeapError::Size);
        }
        let base = extents.physical.base;
        let start = base.checked_add(offset).ok_or(HeapError::Size)?;
        let end = start.checked_add(length).ok_or(HeapError::Size)?;
        let first_byte = usize::try_from(start).map_err(|_| HeapError::Size)?;
        let last_byte = usize::try_from(end).map_err(|_| HeapError::Size)?;
        if self.memory.get(first_byte..last_byte).is_none() {
            return Err(HeapError::Configuration);
        }
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        // Storage indexing happens only after current object/lifetime and
        // logical-span authentication. Padding never becomes user-addressable.
        let first = heap
            .shadow_index(start & !15)
            .ok_or(HeapError::Configuration)?;
        let last = heap
            .shadow_index((end - 1) & !15)
            .ok_or(HeapError::Configuration)?;
        let past = last.checked_add(1).ok_or(HeapError::Configuration)?;
        if heap.shadow.get(first..past).is_none() {
            return Err(HeapError::Configuration);
        }
        Ok(HeapSpan {
            bytes: first_byte..last_byte,
            shadow: first..past,
        })
    }

    fn authenticate_heap_cell_source(
        &self,
        owner: AllocationOwner,
        agent: AgentId,
        pointer: ScopedPointer,
    ) -> Result<(), HeapError> {
        if self.scoped_pointers.is_heap_pointer(pointer) {
            // Transport accepts the point at logical end, but no dereference.
            self.checked_live_heap(owner, agent, pointer)?;
        } else {
            // Local pointers may be stored in a heap; a later scope exit must
            // invalidate EVERY surviving copy, including this dense shadow.
            self.scoped_pointers
                .read_span(pointer, owner.domain.0, owner.context, 0)
                .map_err(HeapError::Pointer)?;
            let (object, offset) = self
                .scoped_pointer_backing(pointer, owner.domain)
                .map_err(|_| HeapError::Pointer(PointerError::Stale))?;
            if !self.authorize_pointer_output(agent, owner.domain, object, offset, 0) {
                return Err(HeapError::Pointer(PointerError::Rights));
            }
        }
        Ok(())
    }

    /// Coherent typed store into a live, aligned heap cell. The source is an
    /// opaque authenticated token or canonical null, never two scalar words.
    /// owner is from the trusted current process descriptor, not guest inputs.
    pub(crate) fn store_heap_pointer_cell(
        &mut self,
        owner: AllocationOwner,
        agent: AgentId,
        destination: ScopedPointer,
        source: Option<ScopedPointer>,
    ) -> Result<(), HeapError> {
        let live = self.checked_live_heap(owner, agent, destination)?;
        if live.row.planned_rights != Permissions::RW {
            return Err(HeapError::Pointer(PointerError::Rights));
        }
        let span = self.checked_heap_span(&live, 16, true)?;
        if let Some(pointer) = source {
            self.authenticate_heap_cell_source(owner, agent, pointer)?;
        }
        let bytes = pointer_bytes(source);
        // No allocation, logging or fallible check beyond this point. Payload
        // and protected kind change together; the old cell survives rejection.
        self.memory[span.bytes].copy_from_slice(&bytes);
        self.private_heap.as_mut().unwrap().shadow[span.shadow.start] = source;
        Ok(())
    }

    /// Observe both words and kind together, then reauthenticate the stored
    /// source against CURRENT lifetime/owner/backing. Error returns no token.
    pub(crate) fn load_heap_pointer_cell(
        &mut self,
        owner: AllocationOwner,
        agent: AgentId,
        source_cell: ScopedPointer,
    ) -> Result<Option<ScopedPointer>, HeapError> {
        let live = self.checked_live_heap(owner, agent, source_cell)?;
        let span = self.checked_heap_span(&live, 16, true)?;
        let pointer = self.private_heap.as_ref().unwrap().shadow[span.shadow.start];
        if self.memory[span.bytes] != pointer_bytes(pointer) {
            return Err(HeapError::MissingKind);
        }
        if let Some(pointer) = pointer {
            self.authenticate_heap_cell_source(owner, agent, pointer)?;
        }
        Ok(pointer)
    }

    /// Bounded live scalar write; every overlapping tag clears, even when the
    /// supplied bytes equal the prior pointer payload. No data can mint kind.
    /// Unlike the private staging writer, this uses LOGICAL bounds and requires
    /// a published current lifetime. DMA/atomic/legacy paths remain excluded.
    pub(crate) fn write_heap_bytes(
        &mut self,
        owner: AllocationOwner,
        agent: AgentId,
        destination: ScopedPointer,
        bytes: &[u8],
    ) -> Result<(), HeapError> {
        let live = self.checked_live_heap(owner, agent, destination)?;
        if live.row.planned_rights != Permissions::RW {
            return Err(HeapError::Pointer(PointerError::Rights));
        }
        let length = u64::try_from(bytes.len()).map_err(|_| HeapError::Size)?;
        let span = self.checked_heap_span(&live, length, false)?;
        self.memory[span.bytes].copy_from_slice(bytes);
        self.private_heap.as_mut().unwrap().shadow[span.shadow].fill(None);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

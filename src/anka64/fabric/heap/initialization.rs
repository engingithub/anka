//! A2.3.2: synchronous, bounded initialization under one exclusive Fabric
//! borrow. Implements a23_chunk/a23_dirty and init108 byte/tag/prefix effects.
//! Completion does not publish anything or permit reclaiming attached storage.
use super::*;
use std::ops::Range;

const CHUNK_LIMIT: u64 = 4096;
mod compiler_loader;

/// Opaque snapshot of exact private custody and trusted progress. Copies are
/// harmless: every use rechecks the current row, registry and both managers.
/// is_complete() describes this snapshot, not its continued validity. Even a
/// complete, current snapshot is NOT a grant, pointer or publication decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapInitialization {
    row: PrivateHeapRow,
}

impl HeapInitialization {
    pub(crate) fn initialized_bytes(self) -> u64 {
        self.row.initialized_bytes
    }
    pub(crate) fn rounded_bytes(self) -> u64 {
        self.row.extents.physical.size
    }
    pub(crate) fn version(self) -> u64 {
        self.row.initialization_version
    }
    pub(crate) fn is_complete(self) -> bool {
        self.initialized_bytes() == self.rounded_bytes()
    }
}

struct InitializationPlan {
    registry: HeapAttachmentPlan,
    row: PrivateHeapRow,
}

struct MutationSpan {
    bytes: Range<usize>,
    shadow: Range<usize>,
}

pub(super) fn scratch_bytes() -> Result<u64, HeapError> {
    // Additional value-storage allowance, not host RSS or an exact stack bound.
    // Input bytes are borrowed; no chunk buffer or completion directory grows.
    storage::<InitializationPlan>(1)?
        .checked_add(storage::<MutationSpan>(1)?)
        .and_then(|n| n.checked_add(size_of::<HeapInitialization>() as u64))
        .ok_or(HeapError::Configuration)
}

impl Fabric {
    fn prepare_private_initialization(
        &self,
        reservation: HeapReservation,
        current_owner: AllocationOwner,
        object: ObjectId,
        expected_revision: u64,
    ) -> Result<InitializationPlan, HeapError> {
        if !self.domains.contains_key(&current_owner.domain) {
            return Err(HeapError::Owner);
        }
        let registry = self.scoped_pointers.prepare_heap_initialization(
            reservation,
            current_owner,
            expected_revision,
        )?;
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        let row = heap
            .rows
            .get(registry.slot())
            .and_then(|r| *r)
            .ok_or(HeapError::StaleInitialization)?;
        if row.reservation != reservation
            || row.owner != registry.owner()
            || row.object != object
            || row.object_generation != Generation(0)
            || row.logical != registry.logical()
            || row.extents != registry.extents()
            || row.planned_rights != Permissions::RW
        {
            return Err(HeapError::StaleInitialization);
        }
        heap.check_layout(&registry)?;
        let end = row.extents.physical.end().ok_or(HeapError::Configuration)?;
        if usize::try_from(end)
            .ok()
            .is_none_or(|end| end > self.memory.len())
            || row.initialized_bytes > row.extents.physical.size
            || row.initialized_bytes % 16 != 0
        {
            return Err(HeapError::Configuration);
        }
        // Repeat the actual census before every observation/mutation. An old
        // successful attachment is not evidence that today's pipeline is quiet.
        if !self.heap_pool_is_private() {
            return Err(HeapError::Busy);
        }
        Ok(InitializationPlan { registry, row })
    }

    fn check_initialization_snapshot(
        &self,
        snapshot: HeapInitialization,
        current_owner: AllocationOwner,
        expected_revision: u64,
    ) -> Result<InitializationPlan, HeapError> {
        let plan = self.prepare_private_initialization(
            snapshot.row.reservation,
            current_owner,
            snapshot.row.object,
            expected_revision,
        )?;
        if plan.row != snapshot.row {
            return Err(HeapError::StaleInitialization);
        }
        Ok(plan)
    }

    /// Trusted diagnostic entry point; it derives progress from the current
    /// row. No caller can set a completed count, version or "already zero" flag.
    pub(crate) fn private_heap_initialization(
        &self,
        reservation: HeapReservation,
        current_owner: AllocationOwner,
        object: ObjectId,
        expected_revision: u64,
    ) -> Result<HeapInitialization, HeapError> {
        let plan = self.prepare_private_initialization(
            reservation,
            current_owner,
            object,
            expected_revision,
        )?;
        Ok(HeapInitialization { row: plan.row })
    }

    fn private_initialization_span(
        &self,
        row: &PrivateHeapRow,
        offset: u64,
        amount: u64,
    ) -> Result<MutationSpan, HeapError> {
        let physical = row.extents.physical;
        if amount == 0
            || amount > CHUNK_LIMIT
            || offset > physical.size
            || amount > physical.size - offset
        {
            return Err(HeapError::Size);
        }
        let start = physical.base.checked_add(offset).ok_or(HeapError::Size)?;
        let end = start.checked_add(amount).ok_or(HeapError::Size)?;
        let byte_start = usize::try_from(start).map_err(|_| HeapError::Size)?;
        let byte_end = usize::try_from(end).map_err(|_| HeapError::Size)?;
        if self.memory.get(byte_start..byte_end).is_none() {
            return Err(HeapError::Configuration);
        }
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        // For unaligned trusted writes clear EVERY overlapping 16-byte cell,
        // including the first and last partial cells. Never synthesize kind.
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
        Ok(MutationSpan {
            bytes: byte_start..byte_end,
            shadow: first..past,
        })
    }

    /// Commit the next aligned prefix chunk, at most one page. Each success
    /// advances initialization version and the shared revision exactly once.
    pub(crate) fn initialize_private_heap_chunk(
        &mut self,
        snapshot: HeapInitialization,
        current_owner: AllocationOwner,
        amount: u64,
        expected_revision: u64,
    ) -> Result<HeapInitialization, HeapError> {
        let mut plan =
            self.check_initialization_snapshot(snapshot, current_owner, expected_revision)?;
        if amount % 16 != 0 {
            return Err(HeapError::Size);
        }
        let span =
            self.private_initialization_span(&plan.row, plan.row.initialized_bytes, amount)?;
        plan.row.initialization_version = plan
            .row
            .initialization_version
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        // Span preflight proved this addition cannot exceed rounded custody.
        plan.row.initialized_bytes += amount;
        Ok(self.commit_private_initialization(plan, span, None))
    }

    /// Arbitrary private-staging byte writer. This is a trusted runtime API,
    /// not guest I/O or the C2.3 checked image overlay at first publication.
    /// Every successful write (even writing zero-valued bytes) invalidates
    /// the ENTIRE prefix and all older completion records. Re-scrub is required.
    pub(crate) fn write_private_heap(
        &mut self,
        snapshot: HeapInitialization,
        current_owner: AllocationOwner,
        offset: u64,
        data: &[u8],
        expected_revision: u64,
    ) -> Result<HeapInitialization, HeapError> {
        let mut plan =
            self.check_initialization_snapshot(snapshot, current_owner, expected_revision)?;
        let amount = u64::try_from(data.len()).map_err(|_| HeapError::Size)?;
        let span = self.private_initialization_span(&plan.row, offset, amount)?;
        plan.row.initialization_version = plan
            .row
            .initialization_version
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        plan.row.initialized_bytes = 0;
        Ok(self.commit_private_initialization(plan, span, Some(data)))
    }

    fn commit_private_initialization(
        &mut self,
        plan: InitializationPlan,
        span: MutationSpan,
        data: Option<&[u8]>,
    ) -> HeapInitialization {
        // All indexes, lengths, identity increments and custody checks have
        // succeeded under this same &mut Fabric. No fallible work or allocation
        // remains; no observer can see bytes, tags and progress separately.
        match data {
            Some(bytes) => self.memory[span.bytes].copy_from_slice(bytes),
            None => self.memory[span.bytes].fill(0),
        }
        let heap = self.private_heap.as_mut().unwrap();
        heap.shadow[span.shadow].fill(None);
        heap.set_row(plan.registry.slot(),plan.row);
        self.scoped_pointers
            .commit_heap_initialization(plan.registry);
        HeapInitialization { row: plan.row }
    }

    /// Revalidate an exact completed prefix now. Future publication MUST repeat
    /// this check under its own exclusive commit, together with lifecycle and
    /// typed-result gates. Returning Ok here creates no visibility or authority.
    pub(crate) fn validate_private_heap_initialization(
        &self,
        snapshot: HeapInitialization,
        current_owner: AllocationOwner,
        expected_revision: u64,
    ) -> Result<(), HeapError> {
        let plan =
            self.check_initialization_snapshot(snapshot, current_owner, expected_revision)?;
        if plan.row.initialized_bytes != plan.row.extents.physical.size {
            return Err(HeapError::Busy);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

impl Fabric {
    /// Reply and lifetime visibility commit under the same exclusive core/Fabric
    /// borrow. The permit is rechecked, not trusted merely because it was issued.
    pub(crate) fn publish_heap_reply(&mut self, core: &mut crate::anka64::core::Anka64Core,
        owner: AllocationOwner, permit: crate::anka64::core::HeapEventPermit,
        snapshot: HeapInitialization) -> Result<(), HeapError> {
        if !core.valid_heap_event(permit, owner) { return Err(HeapError::Owner); }
        let plan = self.check_initialization_snapshot(snapshot, owner, self.scoped_pointers.revision())?;
        if !snapshot.is_complete() || snapshot.version() == 0 { return Err(HeapError::StaleInitialization); }
        if !self.agents.get(&core.agent).is_some_and(|a| a.domain == owner.domain && matches!(a.kind, crate::anka64::state::AgentKind::Cpu(_))) { return Err(HeapError::Owner); }
        let closure = self.scoped_pointers.prepare_attached_heap_closure(plan.row.reservation, owner)?;
        self.check_heap_cleanup_drain(&closure, plan.row.object)?;
        if core.address_map.references_object(plan.row.object) { return Err(HeapError::Busy); }
        let pointer = self.scoped_pointers.commit_heap_publication(plan.registry);
        core.commit_heap_event(permit, Some(pointer), 0, true);
        Ok(())
    }
}

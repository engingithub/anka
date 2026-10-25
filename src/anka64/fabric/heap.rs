//! Bounded software heap custody, initialization, access and reclamation.
//! Heap rows never enter the legacy public object/placement maps. Production
//! publication is atomic with an exact owned syscall reply after current
//! initialization and exclusion checks. Kernel wires cleanup and owner death.
use super::Fabric;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};
use crate::anka64::scoped_pointers::heap::{
    AllocationOwner, HeapAttachmentPlan, HeapError, HeapExtents, HeapPlacementLimits,
    HeapReservation, RegistryLimits, Resource,
};
use crate::anka64::scoped_pointers::{ScopedPointer, ScopedPointers};
use crate::anka64::state::{Generation, ObjectId, Permissions};
use std::mem::size_of;
mod application;
mod initialization;
mod cells;
mod closure;
mod workers;
mod work;
pub(crate) use workers::HeapCleanupSnapshot;
pub(crate) use work::{HeapWorkCounts, HeapWorkLimits, HeapWorkOutcome, HeapWorkTicket};
pub(crate) use initialization::HeapInitialization;

/// Fixed composite object/placement/private-map/grant plan. An ObjectId alone
/// is diagnostic identity, not authority. Visibility is controlled by the
/// registry's current lifetime; this row adds no independent visibility switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateHeapRow {
    reservation: HeapReservation,
    owner: AllocationOwner,
    object: ObjectId,
    object_generation: Generation,
    logical: u64,
    extents: HeapExtents,
    planned_rights: Permissions,
    initialized_bytes: u64,
    initialization_version: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct HeapFabric {
    pool: PhysicalExtent,
    virtual_window: VirtualExtent,
    rows: Vec<Option<PrivateHeapRow>>,
    // Opaque tokens rather than integers. Checked cell operations authenticate
    // destination and source lifetimes before accessing this fixed array.
    shadow: Vec<Option<ScopedPointer>>,
    /// Optional fixed CPU request backend and its separately bounded ledger.
    /// Absent in earlier profiles; the explicit CPU profile has a bounded
    /// trusted executor. It creates no guest publication or DMA path.
    work: Option<work::HeapCpuWork>,
    /// Even eventual row removal cannot let the legacy rollback helper rewind
    /// across an identity consumed by an attached heap.
    pub(super) object_id_floor: u64,
}

fn table<T: Clone>(n: usize, empty: T) -> Result<Vec<T>, HeapError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| HeapError::HostAllocation)?;
    v.resize(n, empty);
    Ok(v)
}

fn storage<T>(n: usize) -> Result<u64, HeapError> {
    n.checked_mul(size_of::<T>())
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(HeapError::Configuration)
}

impl HeapFabric {
    fn footprint(rows: usize, shadow: usize) -> Result<u64, HeapError> {
        // Charge inline descriptors once, plus actual retained array storage.
        // Scratch is a value-storage allowance, not a complete host RSS bound.
        [
            storage::<Option<Self>>(1)?,
            storage::<Option<PrivateHeapRow>>(rows)?,
            storage::<Option<ScopedPointer>>(shadow)?,
            storage::<HeapAttachmentPlan>(1)?,
            storage::<PrivateHeapRow>(1)?,
            initialization::scratch_bytes()?,
            cells::scratch_bytes()?,
            closure::scratch_bytes()?,
            workers::scratch_bytes()?,
        ]
        .into_iter()
        .try_fold(0u64, |n, b| {
            n.checked_add(b).ok_or(HeapError::Configuration)
        })
    }

    fn new(slots: usize, limits: HeapPlacementLimits, remaining: u64) -> Result<Self, HeapError> {
        // The existing managers have already validated page geometry.
        let cells = usize::try_from(limits.physical_pool.size / 16)
            .map_err(|_| HeapError::Configuration)?;
        if Self::footprint(slots, cells)? > remaining {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let result = Self {
            pool: limits.physical_pool,
            virtual_window: limits.virtual_window,
            rows: table(slots, None)?,
            shadow: table(cells, None)?,
            work: None,
            object_id_floor: 0,
        };
        if result.retained_bytes()? > remaining {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        Ok(result)
    }

    fn retained_bytes(&self) -> Result<u64, HeapError> {
        Self::footprint(self.rows.capacity(), self.shadow.capacity())
    }

    pub(super) fn contains_object(&self, id: ObjectId) -> bool {
        self.rows.iter().flatten().any(|r| r.object == id)
    }

    pub(super) fn end(&self) -> u64 {
        self.pool.end().expect("validated heap pool")
    }

    fn overlaps(&self, base: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        base.checked_add(length)
            .is_none_or(|end| base < self.end() && self.pool.base < end)
    }

    /// Index only; never authorization. Actual cell operations must first
    /// authenticate the exact live object/generation/offset and logical span.
    fn shadow_index(&self, physical: u64) -> Option<usize> {
        let offset = physical.checked_sub(self.pool.base)?;
        if physical % 16 != 0 || offset.checked_add(16)? > self.pool.size {
            return None;
        }
        let index = usize::try_from(offset / 16).ok()?;
        (index < self.shadow.len()).then_some(index)
    }

    fn check_plan(&self, plan: &HeapAttachmentPlan) -> Result<(), HeapError> {
        let Some(row) = self.rows.get(plan.slot()) else {
            return Err(HeapError::Configuration);
        };
        if row.is_some() {
            return Err(HeapError::Busy);
        }
        self.check_layout(plan)?;
        let e = plan.extents();
        // Additional bounded census, independent of the placement managers.
        for held in self.rows.iter().flatten() {
            let p = held.extents.physical;
            let v = held.extents.virtual_extent;
            if (e.physical.base < p.end().unwrap() && p.base < e.physical.end().unwrap())
                || (held.owner == plan.owner()
                    && e.virtual_extent.base < v.end().unwrap()
                    && v.base < e.virtual_extent.end().unwrap())
            {
                return Err(HeapError::Busy);
            }
        }
        Ok(())
    }

    fn check_layout(&self, plan: &HeapAttachmentPlan) -> Result<(), HeapError> {
        self.check_extents(plan.extents())
    }

    fn check_extents(&self, e: HeapExtents) -> Result<(), HeapError> {
        if e.physical.base < self.pool.base
            || e.physical.end().is_none_or(|end| end > self.end())
            || e.virtual_extent.base < self.virtual_window.base
            || e.virtual_extent.end().is_none_or(|end| {
                end > self.virtual_window.end().expect("validated virtual window")
            })
            || self.shadow_index(e.physical.base).is_none()
            || e.physical
                .end()
                .and_then(|end| end.checked_sub(16))
                .and_then(|last| self.shadow_index(last))
                .is_none()
        {
            return Err(HeapError::Configuration);
        }
        Ok(())
    }
}

impl Fabric {
    /// Fresh machine profile only: no pre-existing objects, grants, transactions
    /// or device work can occupy the pool at installation. This does not enable
    /// guest malloc, publication or worker execution. This compatibility
    /// constructor has zero worker capacity.
    pub(crate) fn with_private_heap(
        mem_size: usize,
        limits: RegistryLimits,
        placement: HeapPlacementLimits,
    ) -> Result<Self, HeapError> {
        Self::with_private_heap_and_workers(mem_size, limits, placement, 0)
    }

    /// Trusted fresh-profile setup. Fixed worker storage is charged before
    /// service exposure; worker enrollment is a separate supervisor operation.
    pub(crate) fn with_private_heap_and_workers(
        mem_size: usize,
        limits: RegistryLimits,
        placement: HeapPlacementLimits,
        workers: usize,
    ) -> Result<Self, HeapError> {
        Self::with_private_heap_profile(mem_size, limits, placement, workers, None)
    }

    /// Explicit trusted CPU-work profile, including bounded execution and
    /// terminal accounting. Publication, guest delivery and DMA remain disabled.
    pub(crate) fn with_private_heap_cpu_work(
        mem_size: usize,
        limits: RegistryLimits,
        placement: HeapPlacementLimits,
        workers: usize,
        work: HeapWorkLimits,
    ) -> Result<Self, HeapError> {
        Self::with_private_heap_profile(mem_size, limits, placement, workers, Some(work))
    }

    fn with_private_heap_profile(
        mem_size: usize,
        limits: RegistryLimits,
        placement: HeapPlacementLimits,
        workers: usize,
        work_limits: Option<HeapWorkLimits>,
    ) -> Result<Self, HeapError> {
        let memory_size = u64::try_from(mem_size).map_err(|_| HeapError::Configuration)?;
        if placement
            .physical_pool
            .end()
            .is_none_or(|end| end > memory_size)
        {
            return Err(HeapError::Configuration);
        }
        let mut registry = ScopedPointers::with_heap_placement_and_workers(limits, placement, workers)?;
        let mut heap = HeapFabric::new(
            limits.slots,
            placement,
            limits.global_bytes - registry.fixed_metadata_bytes(),
        )?;
        registry.charge_heap_fabric_storage(heap.retained_bytes()?)?;
        if let Some(work_limits) = work_limits {
            let work = work::HeapCpuWork::new(work_limits, limits.global_bytes - registry.fixed_metadata_bytes())?;
            registry.charge_heap_fabric_storage(work.retained_bytes()?)?;
            heap.work = Some(work);
        }
        let memory = table(mem_size, 0u8)?;
        Ok(Self::from_parts(memory, registry, Some(heap)))
    }

    pub(super) fn private_heap_object(&self, object: ObjectId) -> bool {
        self.private_heap
            .as_ref()
            .is_some_and(|h| h.contains_object(object))
    }

    pub(super) fn heap_pool_overlaps(&self, base: u64, length: u64) -> bool {
        self.private_heap
            .as_ref()
            .is_some_and(|h| h.overlaps(base, length))
    }

    /// Recheck actual legacy placement and outstanding pipeline state, not
    /// caller-supplied "quiet" flags. Future device/controller ownership must
    /// be connected before exposing this profile to those agents.
    /// This is pool exclusion, not a lifecycle flag; checked heap-cell paths
    /// use it too, and never enter the legacy transaction pipeline.
    fn heap_pool_is_private(&self) -> bool {
        for (&id, &base) in &self.placement {
            let Some(object) = self.objects.get(&id) else {
                return false;
            };
            if self.heap_pool_overlaps(base, object.size) {
                return false;
            }
        }
        for tx in &self.transactions {
            if tx.state.is_terminal() {
                continue;
            }
            if self.private_heap_object(tx.request.object)
                || tx
                    .physical_address
                    .is_some_and(|p| self.heap_pool_overlaps(p, tx.request.length))
            {
                return false;
            }
        }
        for &(object, _, offset) in self.pointer_cells.keys() {
            let Some(base) = self
                .placement
                .get(&object)
                .and_then(|base| base.checked_add(offset))
            else {
                return false;
            };
            if self.heap_pool_overlaps(base, 16) {
                return false;
            }
        }
        true
    }

    /// Attach exact private custody. current_owner comes from the trusted
    /// process descriptor, never an application PID. Domain and common owner
    /// account are checked here; OS process/exit integration is a later gate.
    /// The returned ObjectId confers no read/write/mapping/pointer authority.
    pub(crate) fn attach_private_heap(
        &mut self,
        reservation: HeapReservation,
        current_owner: AllocationOwner,
        expected_revision: u64,
    ) -> Result<ObjectId, HeapError> {
        if !self.domains.contains_key(&current_owner.domain) {
            return Err(HeapError::Owner);
        }
        let plan = self.scoped_pointers.prepare_heap_attachment(
            reservation,
            current_owner,
            expected_revision,
        )?;
        let heap = self.private_heap.as_ref().ok_or(HeapError::Configuration)?;
        heap.check_plan(&plan)?;
        if !self.heap_pool_is_private() {
            return Err(HeapError::Busy);
        }
        let object = self
            .next_fresh_object_id()
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        let next = object
            .0
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        let slot = plan.slot();
        let row = PrivateHeapRow {
            reservation: plan.reservation(),
            owner: plan.owner(),
            object,
            object_generation: Generation(0),
            logical: plan.logical(),
            extents: plan.extents(),
            planned_rights: Permissions::RW,
            initialized_bytes: 0,
            initialization_version: 0,
        };
        // No allocation/fallible operation after this point. One &mut Fabric
        // owns the registry, managers, counter and all fixed storage together.
        self.scoped_pointers.commit_heap_attachment(plan);
        let heap = self.private_heap.as_mut().unwrap();
        heap.rows[slot] = Some(row);
        heap.object_id_floor = next;
        self.next_object_id = next;
        Ok(object)
    }
}

#[cfg(test)]
mod tests;

//! Anka64 placement management (Phase 9.3g).
//!
//! Placement is deliberately separate from identity and authority:
//!   - physical placement chooses disjoint physical extents for ObjectId owners;
//!   - virtual layout chooses disjoint per-process virtual extents;
//!   - neither operation mints capabilities, authorities, or delegations;
//!   - Fabric remains the final physical-placement enforcement boundary.
//!
//! The implementation is intentionally simple and deterministic.  Physical
//! allocation uses first-fit over a sorted/coalesced free list.  The policy is
//! not architectural; the invariants are.

use std::collections::BTreeMap;

use super::fabric::Fabric;
use super::state::ObjectId;

/// Architectural page size used by the Phase 9.3g placement contracts.
pub const PLACEMENT_PAGE_SIZE: u64 = 0x1000;
const PLACEMENT_PAGE_MASK: u64 = PLACEMENT_PAGE_SIZE - 1;

/// A contiguous, half-open physical extent `[base, base + size)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalExtent {
    pub base: u64,
    pub size: u64,
}

impl PhysicalExtent {
    pub fn end(self) -> Option<u64> {
        self.base.checked_add(self.size)
    }
}

/// A contiguous, half-open virtual extent `[base, base + size)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualExtent {
    pub base: u64,
    pub size: u64,
}

impl VirtualExtent {
    pub fn end(self) -> Option<u64> {
        self.base.checked_add(self.size)
    }
}

/// Placement failures are explicit and side-effect free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    /// A pool/range description is not page aligned, is empty, or overflows.
    InvalidPool,
    /// Requested logical size is zero.
    ZeroSize,
    /// Page rounding or range arithmetic overflowed u64.
    Overflow,
    /// The exact ObjectId already owns a live physical extent.
    OwnerAlreadyAllocated,
    /// The requested ObjectId has no live reservation to release.
    UnknownOwner,
    /// No free extent can satisfy the request.
    OutOfMemory,
    /// Fabric has no such object.
    UnknownObject,
    /// The object already has a physical placement outside this transaction.
    ObjectAlreadyPlaced,
    /// The manager reserved an extent but Fabric rejected the placement.
    FabricRejected,
    /// A virtual layout start/limit is invalid.
    InvalidVirtualLayout,
}

fn is_page_aligned(value: u64) -> bool {
    value & PLACEMENT_PAGE_MASK == 0
}

/// Minimal page rounding.  Zero is not a valid placement request.
pub fn page_ceil(size: u64) -> Result<u64, PlacementError> {
    if size == 0 {
        return Err(PlacementError::ZeroSize);
    }
    size.checked_add(PLACEMENT_PAGE_MASK)
        .map(|v| v & !PLACEMENT_PAGE_MASK)
        .filter(|&v| v != 0)
        .ok_or(PlacementError::Overflow)
}

fn valid_extent(extent: PhysicalExtent) -> bool {
    extent.size != 0
        && is_page_aligned(extent.base)
        && is_page_aligned(extent.size)
        && extent.end().is_some()
}

/// Deterministic physical extent allocator.
///
/// Ownership is keyed by `ObjectId`, not generation.  Object generation is an
/// authority/lifecycle coordinate and may change while the same object remains
/// physically placed (e.g. Active -> Sealed).
#[derive(Debug, Clone)]
pub struct PhysicalPlacementManager {
    pool: PhysicalExtent,
    free: Vec<PhysicalExtent>,
    allocated: BTreeMap<ObjectId, PhysicalExtent>,
}

impl PhysicalPlacementManager {
    /// Create a manager over one page-aligned allocatable physical pool.
    pub fn new(pool_base: u64, pool_size: u64) -> Result<Self, PlacementError> {
        let pool = PhysicalExtent { base: pool_base, size: pool_size };
        if !valid_extent(pool) {
            return Err(PlacementError::InvalidPool);
        }
        Ok(Self {
            pool,
            free: vec![pool],
            allocated: BTreeMap::new(),
        })
    }

    pub fn pool(&self) -> PhysicalExtent {
        self.pool
    }

    pub fn allocated_extent(&self, owner: ObjectId) -> Option<PhysicalExtent> {
        self.allocated.get(&owner).copied()
    }

    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    pub fn free_extents(&self) -> &[PhysicalExtent] {
        &self.free
    }

    pub fn free_bytes(&self) -> u64 {
        self.free.iter().map(|e| e.size).sum()
    }

    /// Reserve a physical extent for an exact ObjectId owner.
    ///
    /// Failure is transactional: no free-list or allocation-table mutation.
    pub fn allocate(
        &mut self,
        owner: ObjectId,
        requested_size: u64,
    ) -> Result<PhysicalExtent, PlacementError> {
        if self.allocated.contains_key(&owner) {
            return Err(PlacementError::OwnerAlreadyAllocated);
        }
        let size = page_ceil(requested_size)?;

        // Find first fit before mutating any state.
        let idx = self.free.iter().position(|e| e.size >= size)
            .ok_or(PlacementError::OutOfMemory)?;
        let slot = self.free[idx];
        let candidate = PhysicalExtent { base: slot.base, size };
        let candidate_end = candidate.end().ok_or(PlacementError::Overflow)?;
        let slot_end = slot.end().ok_or(PlacementError::Overflow)?;
        if candidate_end > slot_end {
            // Defensive: should be impossible after e.size >= size.
            return Err(PlacementError::OutOfMemory);
        }

        // Commit the reservation only after every fallible check above.
        if candidate.size == slot.size {
            self.free.remove(idx);
        } else {
            self.free[idx] = PhysicalExtent {
                base: candidate_end,
                size: slot_end - candidate_end,
            };
        }
        self.allocated.insert(owner, candidate);
        Ok(candidate)
    }

    /// Release the extent owned by exactly `owner` and coalesce free space.
    pub fn release(&mut self, owner: ObjectId) -> Result<PhysicalExtent, PlacementError> {
        let extent = self.allocated.remove(&owner)
            .ok_or(PlacementError::UnknownOwner)?;
        self.insert_free_and_coalesce(extent);
        Ok(extent)
    }

    /// Reserve an extent and ask Fabric to commit the object's physical
    /// placement.  Fabric remains the final enforcement boundary.
    ///
    /// On Fabric rejection, the allocator reservation is rolled back fully.
    pub fn allocate_and_place_object(
        &mut self,
        fabric: &mut Fabric,
        owner: ObjectId,
    ) -> Result<PhysicalExtent, PlacementError> {
        let object_size = fabric.objects.get(&owner)
            .map(|o| o.size)
            .ok_or(PlacementError::UnknownObject)?;
        if fabric.physical_base(owner).is_some() {
            return Err(PlacementError::ObjectAlreadyPlaced);
        }

        let extent = self.allocate(owner, object_size)?;
        if !fabric.place_object(owner, extent.base) {
            // Exact owner was just inserted above; rollback must succeed.
            let rolled_back = self.release(owner)
                .expect("fresh placement reservation must be releasable");
            debug_assert_eq!(rolled_back, extent);
            return Err(PlacementError::FabricRejected);
        }
        Ok(extent)
    }

    fn insert_free_and_coalesce(&mut self, extent: PhysicalExtent) {
        debug_assert!(valid_extent(extent));
        self.free.push(extent);
        self.free.sort_by_key(|e| e.base);

        let mut merged: Vec<PhysicalExtent> = Vec::with_capacity(self.free.len());
        for ext in self.free.drain(..) {
            if let Some(last) = merged.last_mut() {
                let last_end = last.end()
                    .expect("manager stores only non-overflowing extents");
                if last_end == ext.base {
                    last.size = last.size.checked_add(ext.size)
                        .expect("coalesced extents remain within manager pool");
                    continue;
                }
                debug_assert!(last_end < ext.base,
                    "free extents must never overlap");
            }
            merged.push(ext);
        }
        self.free = merged;
    }
}

/// Monotonic per-process virtual layout builder.
///
/// The builder starts at the first page boundary at or above the executable
/// image end.  Code itself is not relocated by this phase; callers may keep
/// `code_vaddr == 0` (or any other base) and reserve subsequent regions here.
#[derive(Debug, Clone)]
pub struct VirtualLayoutBuilder {
    layout_start: u64,
    next: u64,
    limit: u64,
    regions: Vec<VirtualExtent>,
}

impl VirtualLayoutBuilder {
    pub fn after_image(
        code_base: u64,
        code_size: u64,
        limit: u64,
    ) -> Result<Self, PlacementError> {
        if code_size == 0 {
            return Err(PlacementError::ZeroSize);
        }
        let image_end = code_base.checked_add(code_size)
            .ok_or(PlacementError::Overflow)?;
        let layout_start = page_ceil(image_end)?;
        if !is_page_aligned(layout_start)
            || layout_start < image_end
            || layout_start > limit
        {
            return Err(PlacementError::InvalidVirtualLayout);
        }
        Ok(Self {
            layout_start,
            next: layout_start,
            limit,
            regions: Vec::new(),
        })
    }

    pub fn layout_start(&self) -> u64 {
        self.layout_start
    }

    pub fn next(&self) -> u64 {
        self.next
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn regions(&self) -> &[VirtualExtent] {
        &self.regions
    }

    /// Reserve the next page-rounded virtual extent.
    /// Failure leaves cursor and region set unchanged.
    pub fn reserve(&mut self, requested_size: u64) -> Result<VirtualExtent, PlacementError> {
        let size = page_ceil(requested_size)?;
        let end = self.next.checked_add(size)
            .ok_or(PlacementError::Overflow)?;
        if end > self.limit {
            return Err(PlacementError::OutOfMemory);
        }

        let extent = VirtualExtent { base: self.next, size };
        self.next = end;
        self.regions.push(extent);
        Ok(extent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anka64::state::ObjectKind;

    #[test]
    fn p93g1_page_rounding_is_minimal() {
        assert_eq!(page_ceil(1), Ok(0x1000));
        assert_eq!(page_ceil(0x1000), Ok(0x1000));
        assert_eq!(page_ceil(0x1001), Ok(0x2000));
    }

    #[test]
    fn p93g1_page_rounding_rejects_zero_and_overflow() {
        assert_eq!(page_ceil(0), Err(PlacementError::ZeroSize));
        assert_eq!(page_ceil(u64::MAX), Err(PlacementError::Overflow));
    }

    #[test]
    fn p93g1_first_fit_returns_disjoint_page_extents() {
        let mut pm = PhysicalPlacementManager::new(0x10000, 0x10000).unwrap();
        let a = pm.allocate(ObjectId(1), 1).unwrap();
        let b = pm.allocate(ObjectId(2), 0x1800).unwrap();
        assert_eq!(a, PhysicalExtent { base: 0x10000, size: 0x1000 });
        assert_eq!(b, PhysicalExtent { base: 0x11000, size: 0x2000 });
        assert!(a.end().unwrap() <= b.base);
    }

    #[test]
    fn p93g1_duplicate_owner_rejected_without_mutation() {
        let mut pm = PhysicalPlacementManager::new(0x10000, 0x4000).unwrap();
        let first = pm.allocate(ObjectId(7), 0x1000).unwrap();
        let free_before = pm.free_extents().to_vec();
        assert_eq!(
            pm.allocate(ObjectId(7), 0x1000),
            Err(PlacementError::OwnerAlreadyAllocated)
        );
        assert_eq!(pm.allocated_extent(ObjectId(7)), Some(first));
        assert_eq!(pm.free_extents(), free_before.as_slice());
    }

    #[test]
    fn p93g1_exhaustion_is_side_effect_free() {
        let mut pm = PhysicalPlacementManager::new(0x20000, 0x2000).unwrap();
        pm.allocate(ObjectId(1), 0x1000).unwrap();
        let free_before = pm.free_extents().to_vec();
        let count_before = pm.allocated_count();
        assert_eq!(
            pm.allocate(ObjectId(2), 0x2000),
            Err(PlacementError::OutOfMemory)
        );
        assert_eq!(pm.free_extents(), free_before.as_slice());
        assert_eq!(pm.allocated_count(), count_before);
    }

    #[test]
    fn p93g1_release_requires_exact_owner_and_coalesces() {
        let mut pm = PhysicalPlacementManager::new(0x30000, 0x4000).unwrap();
        let a = pm.allocate(ObjectId(1), 0x1000).unwrap();
        let _b = pm.allocate(ObjectId(2), 0x1000).unwrap();
        assert_eq!(pm.release(ObjectId(99)), Err(PlacementError::UnknownOwner));
        assert_eq!(pm.release(ObjectId(1)), Ok(a));
        pm.release(ObjectId(2)).unwrap();
        assert_eq!(pm.free_extents(), &[PhysicalExtent { base: 0x30000, size: 0x4000 }]);
    }

    #[test]
    fn p93g1_released_hole_is_reused_by_first_fit() {
        let mut pm = PhysicalPlacementManager::new(0x40000, 0x5000).unwrap();
        let a = pm.allocate(ObjectId(1), 0x1000).unwrap();
        pm.allocate(ObjectId(2), 0x1000).unwrap();
        pm.release(ObjectId(1)).unwrap();
        let c = pm.allocate(ObjectId(3), 0x800).unwrap();
        assert_eq!(c.base, a.base);
    }

    #[test]
    fn p93g1_generation_is_not_part_of_placement_owner() {
        let mut fabric = Fabric::new(0x80000);
        let obj = fabric.alloc_object("sealed-owner", 0x1000, ObjectKind::Memory);
        let mut pm = PhysicalPlacementManager::new(0x10000, 0x10000).unwrap();
        let ext = pm.allocate_and_place_object(&mut fabric, obj).unwrap();
        assert!(fabric.seal_object(obj));
        assert_eq!(pm.allocated_extent(obj), Some(ext),
            "generation transition must not orphan placement ownership");
        fabric.destroy_object(obj);
        assert_eq!(pm.release(obj), Ok(ext));
    }

    #[test]
    fn p93g3_fabric_rejection_rolls_allocator_back() {
        let mut fabric = Fabric::new(0x80000);
        let blocker = fabric.alloc_object("blocker", 0x1000, ObjectKind::Memory);
        assert!(fabric.place_object(blocker, 0x10000));
        let victim = fabric.alloc_object("victim", 0x1000, ObjectKind::Memory);

        let mut pm = PhysicalPlacementManager::new(0x10000, 0x4000).unwrap();
        let free_before = pm.free_extents().to_vec();
        assert_eq!(
            pm.allocate_and_place_object(&mut fabric, victim),
            Err(PlacementError::FabricRejected)
        );
        assert_eq!(pm.allocated_extent(victim), None);
        assert_eq!(pm.free_extents(), free_before.as_slice());
        assert_eq!(fabric.physical_base(victim), None);
    }

    #[test]
    fn p93g3_successful_composition_agrees_on_exact_base() {
        let mut fabric = Fabric::new(0x80000);
        let obj = fabric.alloc_object("placed", 0x1800, ObjectKind::Memory);
        let mut pm = PhysicalPlacementManager::new(0x20000, 0x10000).unwrap();
        let ext = pm.allocate_and_place_object(&mut fabric, obj).unwrap();
        assert_eq!(ext.size, 0x2000);
        assert_eq!(fabric.physical_base(obj), Some(ext.base));
        assert_eq!(pm.allocated_extent(obj), Some(ext));
    }

    #[test]
    fn p93g3_preplaced_object_rejected_without_allocator_mutation() {
        let mut fabric = Fabric::new(0x80000);
        let obj = fabric.alloc_object("already", 0x1000, ObjectKind::Memory);
        assert!(fabric.place_object(obj, 0x50000));
        let mut pm = PhysicalPlacementManager::new(0x20000, 0x10000).unwrap();
        let free_before = pm.free_extents().to_vec();
        assert_eq!(
            pm.allocate_and_place_object(&mut fabric, obj),
            Err(PlacementError::ObjectAlreadyPlaced)
        );
        assert_eq!(pm.free_extents(), free_before.as_slice());
        assert_eq!(pm.allocated_count(), 0);
    }

    #[test]
    fn p93g2_layout_starts_at_page_ceil_of_image_end() {
        let layout = VirtualLayoutBuilder::after_image(0, 67_824, 0x40000).unwrap();
        assert_eq!(layout.layout_start(), 0x11000);
        assert_eq!(layout.next(), 0x11000);
    }

    #[test]
    fn p93g2_layout_supports_nonzero_code_base_without_relocation_assumption() {
        let layout = VirtualLayoutBuilder::after_image(0x30000, 0x4000, 0x50000).unwrap();
        assert_eq!(layout.layout_start(), 0x34000);
    }

    #[test]
    fn p93g2_buffer_rounds_to_one_page_and_regions_are_disjoint() {
        let mut layout = VirtualLayoutBuilder::after_image(0, 0x10000, 0x20000).unwrap();
        let rx = layout.reserve(2048).unwrap();
        let tx = layout.reserve(2048).unwrap();
        assert_eq!(rx.size, 0x1000);
        assert_eq!(tx.size, 0x1000);
        assert_eq!(rx.end(), Some(tx.base));
    }

    #[test]
    fn p93g2_exact_limit_succeeds_then_exhausts_without_mutation() {
        let mut layout = VirtualLayoutBuilder::after_image(0, 0x1000, 0x3000).unwrap();
        let a = layout.reserve(0x2000).unwrap();
        assert_eq!(a.end(), Some(0x3000));
        let next_before = layout.next();
        let regions_before = layout.regions().to_vec();
        assert_eq!(layout.reserve(1), Err(PlacementError::OutOfMemory));
        assert_eq!(layout.next(), next_before);
        assert_eq!(layout.regions(), regions_before.as_slice());
    }

    #[test]
    fn p93g2_overflowing_image_or_reservation_is_rejected() {
        assert!(matches!(
            VirtualLayoutBuilder::after_image(u64::MAX - 1, 8, u64::MAX),
            Err(PlacementError::Overflow)
        ));

        let mut layout = VirtualLayoutBuilder {
            layout_start: u64::MAX & !PLACEMENT_PAGE_MASK,
            next: u64::MAX & !PLACEMENT_PAGE_MASK,
            limit: u64::MAX,
            regions: Vec::new(),
        };
        assert_eq!(layout.reserve(0x1000), Err(PlacementError::Overflow));
        assert!(layout.regions().is_empty());
    }
}

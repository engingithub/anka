//! A2.2 composition owns both manager kinds under ScopedPointers' one &mut.
//! No Fabric objects, grants, mappings, writes, or heap pointer publication.
use super::*;
use crate::anka64::placement::{
    PhysicalExtent, PhysicalPlacementManager, PhysicalReturn, PhysicalTake, ReservationKey,
    VirtualExtent, VirtualLayoutBuilder, VirtualReturn, VirtualTake,
};

/// Trusted profile configuration. The physical pool must be dedicated to this
/// service; each independent process gets this virtual window in its own space.
/// Loader/Fabric integration must establish those partitions before publication.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeapPlacementLimits {
    pub physical_pool: PhysicalExtent,
    pub physical_claims: usize,
    pub virtual_window: VirtualExtent,
    pub per_owner_claims: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapExtents {
    pub physical: PhysicalExtent,
    pub virtual_extent: VirtualExtent,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct HeapPlacement {
    pub(super) physical: PhysicalPlacementManager,
    pub(super) virtual_arenas: Vec<VirtualLayoutBuilder>,
}

#[derive(Debug)]
pub(super) struct AdmissionPlacement {
    physical: PhysicalTake,
    virtual_plan: VirtualTake,
}
#[derive(Debug)]
pub(super) struct ReturnPlacement {
    physical: PhysicalReturn,
    virtual_plan: VirtualReturn,
}

impl HeapReservation {
    fn key(self) -> ReservationKey {
        ReservationKey {
            owner: self.owner.serial,
            slot: self.slot as u32 + 1,
            generation: self.generation,
            job: self.job,
        }
    }
}

impl AdmissionPlacement {
    pub(super) fn extents(&self) -> HeapExtents {
        HeapExtents {
            physical: self.physical.extent(),
            virtual_extent: self.virtual_plan.extent(),
        }
    }
}

impl HeapPlacement {
    // One precharged operation at a time; these are actual Rust plan values.
    // This is a value-storage allowance, not a host stack/RSS measurement.
    pub(super) fn scratch_bytes() -> u64 {
        size_of::<Option<AdmissionPlacement>>().max(size_of::<Option<ReturnPlacement>>()) as u64
    }

    fn minimum_bytes(limits: HeapPlacementLimits, owners: usize) -> Result<u64, HeapError> {
        let physical = PhysicalPlacementManager::minimum_reservation_bytes(limits.physical_claims)
            .map_err(HeapError::PhysicalPlacement)?;
        let virtual_bytes = VirtualLayoutBuilder::minimum_reservation_bytes(
            limits.virtual_window,
            limits.per_owner_claims,
        )
        .map_err(HeapError::VirtualPlacement)?;
        (size_of::<VirtualLayoutBuilder>() as u64)
            .checked_add(virtual_bytes)
            .and_then(|n| n.checked_mul(u64::try_from(owners).ok()?))
            .and_then(|n| n.checked_add(physical))
            .and_then(|n| n.checked_add(Self::scratch_bytes()))
            .ok_or(HeapError::Configuration)
    }

    fn new(limits: HeapPlacementLimits, owners: usize) -> Result<Self, HeapError> {
        let physical =
            PhysicalPlacementManager::bounded(limits.physical_pool, limits.physical_claims)
                .map_err(HeapError::PhysicalPlacement)?;
        let mut virtual_arenas = Vec::new();
        virtual_arenas
            .try_reserve_exact(owners)
            .map_err(|_| HeapError::HostAllocation)?;
        for _ in 0..owners {
            virtual_arenas.push(
                VirtualLayoutBuilder::reusable(limits.virtual_window, limits.per_owner_claims)
                    .map_err(HeapError::VirtualPlacement)?,
            );
        }
        Ok(Self {
            physical,
            virtual_arenas,
        })
    }

    pub(super) fn retained_bytes(&self) -> Result<u64, HeapError> {
        let mut n = bytes::<VirtualLayoutBuilder>(self.virtual_arenas.capacity())?
            .checked_add(
                self.physical
                    .reservation_bytes()
                    .map_err(HeapError::PhysicalPlacement)?,
            )
            .and_then(|n| n.checked_add(Self::scratch_bytes()))
            .ok_or(HeapError::Configuration)?;
        for arena in &self.virtual_arenas {
            n = n
                .checked_add(
                    arena
                        .reservation_bytes()
                        .map_err(HeapError::VirtualPlacement)?,
                )
                .ok_or(HeapError::Configuration)?;
        }
        Ok(n)
    }

    pub(super) fn prepare_reserve(
        &self,
        reservation: HeapReservation,
        rounded: u64,
        revision: u64,
    ) -> Result<AdmissionPlacement, HeapError> {
        let physical = self
            .physical
            .prepare_heap_take(reservation.key(), rounded, revision)
            .map_err(HeapError::PhysicalPlacement)?;
        let virtual_plan = self.virtual_arenas[reservation.owner.index]
            .prepare_heap_take(reservation.key(), rounded, revision)
            .map_err(HeapError::VirtualPlacement)?;
        Ok(AdmissionPlacement {
            physical,
            virtual_plan,
        })
    }

    pub(super) fn commit_reserve(
        &mut self,
        owner: OwnerAccount,
        plan: AdmissionPlacement,
        revision: u64,
    ) {
        self.physical.commit_heap_take(plan.physical, revision);
        self.virtual_arenas[owner.index].commit_heap_take(plan.virtual_plan, revision);
    }

    pub(super) fn prepare_cancel(
        &self,
        reservation: HeapReservation,
        extents: HeapExtents,
        revision: u64,
    ) -> Result<ReturnPlacement, HeapError> {
        let physical = self
            .physical
            .prepare_heap_return(reservation.key(), extents.physical, revision)
            .map_err(HeapError::PhysicalPlacement)?;
        let virtual_plan = self.virtual_arenas[reservation.owner.index]
            .prepare_heap_return(reservation.key(), extents.virtual_extent, revision)
            .map_err(HeapError::VirtualPlacement)?;
        Ok(ReturnPlacement {
            physical,
            virtual_plan,
        })
    }

    pub(super) fn commit_cancel(
        &mut self,
        owner: OwnerAccount,
        plan: ReturnPlacement,
        revision: u64,
    ) {
        self.physical.commit_heap_return(plan.physical, revision);
        self.virtual_arenas[owner.index].commit_heap_return(plan.virtual_plan, revision);
    }
}

impl ScopedPointers {
    pub(crate) fn with_heap_placement(
        limits: RegistryLimits,
        placement: HeapPlacementLimits,
    ) -> Result<Self, HeapError> {
        let mut registry = Self::with_limits(limits)?;
        let minimum = HeapPlacement::minimum_bytes(placement, limits.owners)?;
        if minimum > limits.global_bytes - registry.fixed_metadata_bytes() {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        let placement = HeapPlacement::new(placement, limits.owners)?;
        let additional = placement.retained_bytes()?;
        if additional > limits.global_bytes - registry.fixed_metadata_bytes() {
            return Err(HeapError::Capacity(Resource::GlobalBytes));
        }
        registry.heap.fixed_bytes += additional;
        registry.heap.placement = Some(placement);
        Ok(registry)
    }

    /// Trusted diagnostic only; addresses do not grant access or mint a pointer.
    pub(crate) fn reserved_extents(
        &self,
        reservation: HeapReservation,
    ) -> Result<HeapExtents, HeapError> {
        let record = self.reservation_record(reservation)?;
        let extents = record.extents.ok_or(HeapError::Configuration)?;
        let placement = self
            .heap
            .placement
            .as_ref()
            .ok_or(HeapError::Configuration)?;
        if placement.physical.reservation_extent(reservation.key()) != Some(extents.physical)
            || placement.virtual_arenas[reservation.owner.index]
                .reservation_extent(reservation.key())
                != Some(extents.virtual_extent)
        {
            return Err(HeapError::StaleReservation);
        }
        Ok(extents)
    }
}

#[cfg(test)]
pub(super) mod tests;

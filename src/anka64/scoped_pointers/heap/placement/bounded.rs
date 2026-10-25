//! A2.2 shared extent operations for bounded physical and virtual managers.
//! Plans remain private to one synchronous compound operation. Preparing a plan
//! never mutates a manager; applying one needs the same exclusive boundary.
use super::{PhysicalExtent, PlacementError, page_ceil, valid_extent};
use std::mem::size_of;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReservationKey {
    pub owner: u64,
    pub slot: u32, // one-based stable directory slot
    pub generation: u32,
    pub job: u64,
}

impl ReservationKey {
    fn valid(self) -> bool {
        self.owner != 0
            && self.slot != 0
            && self.generation != 0
            && self.job != 0
            && self.job != u64::MAX
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Claim {
    key: ReservationKey,
    extent: PhysicalExtent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Claims {
    rows: Vec<Option<Claim>>,
    held: usize,
}

#[derive(Debug)]
pub(super) struct Take {
    claim: usize,
    hole: usize,
    before: PhysicalExtent,
    suffix: Option<PhysicalExtent>,
    key: ReservationKey,
    pub extent: PhysicalExtent,
    revision: u64,
}

#[derive(Debug)]
pub(super) struct Return {
    claim: usize,
    index: usize,
    left: bool,
    right: bool,
    merged: PhysicalExtent,
    key: ReservationKey,
    extent: PhysicalExtent,
    revision: u64,
}

pub(super) fn storage_bytes<T>(capacity: usize) -> Result<u64, PlacementError> {
    capacity
        .checked_mul(size_of::<T>())
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(PlacementError::Overflow)
}

impl Claims {
    pub fn minimum_bytes(k: usize) -> Result<u64, PlacementError> {
        if k > u32::MAX as usize {
            return Err(PlacementError::ReservationCapacity);
        }
        let n = k.checked_add(2).ok_or(PlacementError::Overflow)?;
        storage_bytes::<Option<Claim>>(k)?
            .checked_add(storage_bytes::<PhysicalExtent>(n)?)
            .ok_or(PlacementError::Overflow)
    }

    pub fn new(
        k: usize,
        pool: PhysicalExtent,
    ) -> Result<(Self, Vec<PhysicalExtent>), PlacementError> {
        Self::minimum_bytes(k)?;
        if !valid_extent(pool) {
            return Err(PlacementError::InvalidPool);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(k)
            .map_err(|_| PlacementError::HostAllocation)?;
        rows.resize(k, None);
        let mut free = Vec::new();
        free.try_reserve_exact(k + 2)
            .map_err(|_| PlacementError::HostAllocation)?;
        free.push(pool);
        Ok((Self { rows, held: 0 }, free))
    }

    pub fn retained_bytes(&self, free: &Vec<PhysicalExtent>) -> Result<u64, PlacementError> {
        storage_bytes::<Option<Claim>>(self.rows.capacity())?
            .checked_add(storage_bytes::<PhysicalExtent>(free.capacity())?)
            .ok_or(PlacementError::Overflow)
    }

    pub fn count(&self) -> usize {
        self.held
    }
    pub fn extent(&self, key: ReservationKey) -> Option<PhysicalExtent> {
        self.rows
            .iter()
            .flatten()
            .find(|c| c.key == key)
            .map(|c| c.extent)
    }

    fn shape(&self, free: &Vec<PhysicalExtent>) -> Result<(), PlacementError> {
        if self.held > self.rows.len()
            || free.len() > self.held + 1
            || free.capacity() < self.rows.len() + 2
        {
            return Err(PlacementError::ReservationMismatch);
        }
        Ok(())
    }

    pub fn prepare_take(
        &self,
        free: &Vec<PhysicalExtent>,
        key: ReservationKey,
        logical: u64,
        revision: u64,
    ) -> Result<Take, PlacementError> {
        self.shape(free)?;
        if !key.valid() || revision == u64::MAX || self.extent(key).is_some() {
            return Err(PlacementError::ReservationMismatch);
        }
        if self.held == self.rows.len() {
            return Err(PlacementError::ReservationCapacity);
        }
        let claim = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(PlacementError::ReservationCapacity)?;
        let size = page_ceil(logical)?;
        let hole = free
            .iter()
            .position(|e| e.size >= size)
            .ok_or(PlacementError::OutOfMemory)?;
        let before = free[hole];
        let end = before
            .base
            .checked_add(size)
            .ok_or(PlacementError::Overflow)?;
        let suffix = (size < before.size).then_some(PhysicalExtent {
            base: end,
            size: before.size - size,
        });
        Ok(Take {
            claim,
            hole,
            before,
            suffix,
            key,
            extent: PhysicalExtent {
                base: before.base,
                size,
            },
            revision,
        })
    }

    pub fn take(&mut self, free: &mut Vec<PhysicalExtent>, plan: Take, revision: u64) {
        // The compound caller holds exclusive access from preparation through
        // this nonallocating commit; none of these assertions can be input errors.
        debug_assert_eq!(plan.revision, revision);
        debug_assert!(self.rows[plan.claim].is_none());
        debug_assert_eq!(free[plan.hole], plan.before);
        if let Some(suffix) = plan.suffix {
            free[plan.hole] = suffix;
        } else {
            free.remove(plan.hole);
        }
        self.rows[plan.claim] = Some(Claim {
            key: plan.key,
            extent: plan.extent,
        });
        self.held += 1;
    }

    pub fn prepare_return(
        &self,
        free: &Vec<PhysicalExtent>,
        pool: PhysicalExtent,
        key: ReservationKey,
        extent: PhysicalExtent,
        revision: u64,
    ) -> Result<Return, PlacementError> {
        self.shape(free)?;
        let claim = self
            .rows
            .iter()
            .position(|c| *c == Some(Claim { key, extent }))
            .ok_or(PlacementError::ReservationMismatch)?;
        let end = extent.end().ok_or(PlacementError::Overflow)?;
        if !valid_extent(extent)
            || extent.base < pool.base
            || end > pool.end().unwrap()
            || self.held == 0
            || free.len() == free.capacity()
        {
            return Err(PlacementError::ReservationMismatch);
        }
        let index = free.partition_point(|e| e.base < extent.base);
        let before = index.checked_sub(1).map(|i| free[i]);
        let after = free.get(index).copied();
        if before.is_some_and(|e| e.end().is_none_or(|n| n > extent.base))
            || after.is_some_and(|e| end > e.base)
        {
            return Err(PlacementError::ReservationMismatch);
        }
        let left = before.is_some_and(|e| e.end() == Some(extent.base));
        let right = after.is_some_and(|e| e.base == end);
        let base = if left {
            before.unwrap().base
        } else {
            extent.base
        };
        let merged_end = if right {
            after.unwrap().end().ok_or(PlacementError::Overflow)?
        } else {
            end
        };
        let merged = PhysicalExtent {
            base,
            size: merged_end
                .checked_sub(base)
                .ok_or(PlacementError::Overflow)?,
        };
        Ok(Return {
            claim,
            index,
            left,
            right,
            merged,
            key,
            extent,
            revision,
        })
    }

    pub fn give_back(&mut self, free: &mut Vec<PhysicalExtent>, plan: Return, revision: u64) {
        debug_assert_eq!(plan.revision, revision);
        debug_assert_eq!(
            self.rows[plan.claim],
            Some(Claim {
                key: plan.key,
                extent: plan.extent
            })
        );
        debug_assert!(free.len() < free.capacity());
        // K+2 includes this insertion slot. Neither insert nor remove reallocates.
        free.insert(plan.index, plan.extent);
        if plan.right {
            free.remove(plan.index + 1);
        }
        if plan.left {
            free.remove(plan.index);
            free[plan.index - 1] = plan.merged;
        } else {
            free[plan.index] = plan.merged;
        }
        self.rows[plan.claim] = None;
        self.held -= 1;
    }

    #[cfg(test)]
    pub fn audit(&self, free: &[PhysicalExtent], pool: PhysicalExtent) {
        assert_eq!(self.held, self.rows.iter().flatten().count());
        let mut partition: Vec<_> = free
            .iter()
            .map(|&e| (e, true))
            .chain(self.rows.iter().flatten().map(|c| (c.extent, false)))
            .collect();
        partition.sort_by_key(|(e, _)| e.base);
        let mut end = pool.base;
        let mut was_free = false;
        for (e, is_free) in partition {
            assert!(valid_extent(e));
            assert_eq!(e.base, end);
            assert!(!(was_free && is_free));
            end = e.end().unwrap();
            was_free = is_free;
        }
        assert_eq!(end, pool.end().unwrap());
        for pair in free.windows(2) {
            assert!(pair[0].end().unwrap() < pair[1].base);
        }
        assert!(free.len() <= self.held + 1);
        for (i, c) in self.rows.iter().enumerate() {
            if let Some(c) = c {
                assert!(c.key.valid());
                assert!(
                    !self.rows[i + 1..]
                        .iter()
                        .flatten()
                        .any(|other| other.key == c.key)
                );
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct PhysicalTake(pub(super) Take);
#[derive(Debug)]
pub(crate) struct VirtualTake(pub(super) Take);
#[derive(Debug)]
pub(crate) struct PhysicalReturn(pub(super) Return);
#[derive(Debug)]
pub(crate) struct VirtualReturn(pub(super) Return);

impl PhysicalTake {
    pub(crate) fn extent(&self) -> PhysicalExtent {
        self.0.extent
    }
}
impl VirtualTake {
    pub(crate) fn extent(&self) -> super::VirtualExtent {
        super::VirtualExtent {
            base: self.0.extent.base,
            size: self.0.extent.size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VirtualArena {
    pub free: Vec<PhysicalExtent>,
    pub claims: Claims,
    pub owner: Option<u64>,
}

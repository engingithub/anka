//! Stable, bounded namespace for protected local and heap identities.
//! A2.1 metadata and A2.2 private extent reservations share this directory;
//! no guest heap pointer is issued here.

pub(crate) mod heap;
use heap::RegistryLimits;

use super::state::{Generation, ObjectId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerError {
    Exhausted,
    InvalidScope,
    InvalidRange,
    Stale,
    Domain,
    Rights,
    Bounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scope(u64);

/// Fields remain private: integer payloads cannot mint a trusted pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopedPointer {
    slot: usize,
    generation: u32,
    position: u64,
}

impl ScopedPointer {
    /// ABI payload only. Reconstructing these integers does not reconstruct kind.
    pub fn words(self) -> [u64; 2] {
        [
            ((self.generation as u64) << 32) | (self.slot as u64 + 1),
            self.position,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PointerBacking {
    pub object: ObjectId,
    pub generation: Generation,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalAllocation {
    scope: Scope,
    domain: u64,
    base: u64,
    length: u64,
    writable: bool,
    backing: Option<PointerBacking>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Free,
    Reserved,
    Live,
    Closing,
    Exhausted,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record {
    Empty,
    Local(LocalAllocation),
    Heap(heap::HeapRecord),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    generation: u32,
    state: SlotState,
    record: Record,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 0,
        state: SlotState::Free,
        record: Record::Empty,
    };
    fn release(&mut self) {
        self.state = if self.generation == u32::MAX {
            SlotState::Exhausted
        } else {
            SlotState::Free
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeRecord {
    scope: Scope,
    owner: u64,
}

/// Tables are fully allocated at construction; their capacity never grows.
/// One mutable borrow serializes local and heap admissions across all owners.
/// Deliberately not Clone: duplicating an active ledger is not rollback.
#[derive(Debug, PartialEq, Eq)]
pub struct ScopedPointers {
    slots: Vec<Slot>,
    scopes: Vec<Option<ScopeRecord>>,
    active_slots_end: usize,
    active_scopes_end: usize,
    next_scope: u64,
    heap: heap::HeapLedger,
}

impl ScopedPointers {
    /// Compatibility constructor for the existing local-only machine profile.
    /// Heap owners/jobs remain disabled until the complete service is connected.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.min(u32::MAX as usize);
        Self::with_limits(RegistryLimits {
            slots: capacity,
            scopes: capacity,
            owners: 0,
            cleanup: 0,
            global_bytes: u64::MAX,
        })
        .expect("protected pointer infrastructure allocation failed")
    }

    pub fn enter_scope(&mut self) -> Result<Scope, PointerError> {
        self.enter_scope_for(0)
    }

    pub(crate) fn enter_scope_for(&mut self, owner: u64) -> Result<Scope, PointerError> {
        self.preflight_frame(0)?;
        let index = self.scopes.iter().position(Option::is_none).unwrap();
        let scope = Scope(self.next_scope);
        self.next_scope += 1;
        self.scopes[index] = Some(ScopeRecord { scope, owner });
        self.active_scopes_end = self.active_scopes_end.max(index + 1);
        self.heap.advance();
        Ok(scope)
    }

    fn scope_owner(&self, scope: Scope) -> Option<u64> {
        self.scopes[..self.active_scopes_end]
            .iter()
            .flatten()
            .find(|s| s.scope == scope)
            .map(|s| s.owner)
    }

    fn is_top(&self, scope: Scope) -> bool {
        self.scope_owner(scope).is_some_and(|owner| {
            !self.scopes[..self.active_scopes_end]
                .iter()
                .flatten()
                .any(|s| s.owner == owner && s.scope > scope)
        })
    }

    fn free_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.state == SlotState::Free && s.generation < u32::MAX)
    }

    /// Preflight the entire frame before changing any scope/generation/backing.
    pub(crate) fn preflight_frame(&self, locals: usize) -> Result<(), PointerError> {
        let mutations = u64::try_from(locals).ok().and_then(|n| n.checked_add(1));
        if self.next_scope == u64::MAX
            || !self.scopes.iter().any(Option::is_none)
            || self
                .slots
                .iter()
                .filter(|s| s.state == SlotState::Free && s.generation < u32::MAX)
                .take(locals)
                .count()
                < locals
            || mutations
                .and_then(|n| self.heap.revision.checked_add(n))
                .is_none()
        {
            return Err(PointerError::Exhausted);
        }
        Ok(())
    }

    /// Register bounds for a trusted already allocated local buffer. This does
    /// not allocate payload, grant Fabric authority or accept a guest address.
    pub fn register(
        &mut self,
        scope: Scope,
        domain: u64,
        base: u64,
        length: u64,
        writable: bool,
    ) -> Result<ScopedPointer, PointerError> {
        if !self.is_top(scope) {
            return Err(PointerError::InvalidScope);
        }
        base.checked_add(length).ok_or(PointerError::InvalidRange)?;
        if self.heap.revision == u64::MAX {
            return Err(PointerError::Exhausted);
        }
        let slot = self.free_slot().ok_or(PointerError::Exhausted)?;
        let generation = self.slots[slot].generation + 1;
        self.slots[slot] = Slot {
            generation,
            state: SlotState::Live,
            record: Record::Local(LocalAllocation {
                scope,
                domain,
                base,
                length,
                writable,
                backing: None,
            }),
        };
        self.active_slots_end = self.active_slots_end.max(slot + 1);
        self.heap.advance();
        Ok(ScopedPointer {
            slot,
            generation,
            position: 0,
        })
    }

    fn allocation(
        &self,
        pointer: ScopedPointer,
        domain: u64,
    ) -> Result<&LocalAllocation, PointerError> {
        let slot = self.slots.get(pointer.slot).ok_or(PointerError::Stale)?;
        if slot.state != SlotState::Live || slot.generation != pointer.generation {
            return Err(PointerError::Stale);
        }
        // Heap access stays closed until the full publication/Fabric refinement.
        let Record::Local(a) = &slot.record else {
            return Err(PointerError::Stale);
        };
        if a.domain != domain {
            return Err(PointerError::Domain);
        }
        Ok(a)
    }

    /// Byte displacement. One-past is transportable but never dereferenceable.
    pub fn add(
        &self,
        pointer: ScopedPointer,
        domain: u64,
        delta: i64,
    ) -> Result<ScopedPointer, PointerError> {
        let a = self.allocation(pointer, domain)?;
        let position = pointer
            .position
            .checked_add_signed(delta)
            .ok_or(PointerError::Bounds)?;
        if position > a.length {
            return Err(PointerError::Bounds);
        }
        Ok(ScopedPointer {
            position,
            ..pointer
        })
    }

    /// Resolve only a nonempty exact span; Fabric must still authorize its transaction.
    pub fn resolve(
        &self,
        pointer: ScopedPointer,
        domain: u64,
        width: u64,
        write: bool,
    ) -> Result<u64, PointerError> {
        let a = self.allocation(pointer, domain)?;
        if write && !a.writable {
            return Err(PointerError::Rights);
        }
        let end = pointer
            .position
            .checked_add(width)
            .ok_or(PointerError::Bounds)?;
        if width == 0 || end > a.length {
            return Err(PointerError::Bounds);
        }
        a.base
            .checked_add(pointer.position)
            .ok_or(PointerError::Bounds)
    }

    pub(crate) fn read_span(
        &self,
        pointer: ScopedPointer,
        domain: u64,
        owner: u64,
        length: u64,
    ) -> Result<u64, PointerError> {
        let a = self.allocation(pointer, domain)?;
        if self.scope_owner(a.scope) != Some(owner) {
            return Err(PointerError::InvalidScope);
        }
        if pointer.position > a.length || length > a.length - pointer.position {
            return Err(PointerError::Bounds);
        }
        a.base
            .checked_add(pointer.position)
            .ok_or(PointerError::Bounds)
    }

    pub(crate) fn write_span(
        &self,
        pointer: ScopedPointer,
        domain: u64,
        owner: u64,
        length: u64,
    ) -> Result<u64, PointerError> {
        let address = self.read_span(pointer, domain, owner, length)?;
        if !self.allocation(pointer, domain)?.writable {
            return Err(PointerError::Rights);
        }
        Ok(address)
    }

    pub(crate) fn storage_span(&self, pointer: ScopedPointer) -> Option<(u64, u64)> {
        let slot = self.slots.get(pointer.slot)?;
        if slot.generation != pointer.generation {
            return None;
        }
        let Record::Local(a) = slot.record else {
            return None;
        };
        Some((a.base, a.length))
    }

    pub(super) fn bind_backing(&mut self, pointer: ScopedPointer, backing: PointerBacking) {
        let slot = &mut self.slots[pointer.slot];
        assert_eq!(slot.generation, pointer.generation);
        assert_eq!(slot.state, SlotState::Live);
        let Record::Local(a) = &mut slot.record else {
            unreachable!()
        };
        assert!(a.backing.is_none());
        a.backing = Some(backing);
    }

    pub(super) fn backing(&self, pointer: ScopedPointer) -> Option<PointerBacking> {
        let slot = self.slots.get(pointer.slot)?;
        if slot.generation != pointer.generation {
            return None;
        }
        let Record::Local(a) = slot.record else {
            return None;
        };
        a.backing
    }

    pub(super) fn take_backing(&mut self, pointer: ScopedPointer) -> Option<PointerBacking> {
        let slot = self.slots.get_mut(pointer.slot)?;
        if slot.generation != pointer.generation || slot.state == SlotState::Live {
            return None;
        }
        let Record::Local(a) = &mut slot.record else {
            return None;
        };
        a.backing.take()
    }

    // Only shorten the scan range. The complete directory and every generation
    // remain allocated/charged, including exhausted slots outside this prefix.
    fn trim_active_slots(&mut self) {
        while self.active_slots_end > 0
            && matches!(
                self.slots[self.active_slots_end - 1].state,
                SlotState::Free | SlotState::Exhausted
            )
        {
            self.active_slots_end -= 1;
        }
    }

    /// LIFO exit affects only local records of this scope, never heap lifetimes.
    pub fn leave_scope(&mut self, scope: Scope) -> Result<(), PointerError> {
        if !self.is_top(scope) {
            return Err(PointerError::InvalidScope);
        }
        for slot in &mut self.slots[..self.active_slots_end] {
            if matches!(slot.record, Record::Local(a) if a.scope == scope) {
                slot.release();
            }
        }
        let index = self
            .scopes
            .iter()
            .position(|s| s.is_some_and(|s| s.scope == scope))
            .unwrap();
        self.scopes[index] = None;
        while self.active_scopes_end > 0 && self.scopes[self.active_scopes_end - 1].is_none() {
            self.active_scopes_end -= 1;
        }
        self.trim_active_slots();
        self.heap.advance();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_buffer_traversal_and_scope_escape() {
        let mut table = ScopedPointers::new(2);
        let scope = table.enter_scope().unwrap();
        let p = table.register(scope, 7, 4096, 4, true).unwrap();
        assert_eq!(p.words(), [0x1_0000_0001, 0]);
        for i in 0..4 {
            assert_eq!(
                table.resolve(table.add(p, 7, i).unwrap(), 7, 1, true),
                Ok(4096 + i as u64)
            );
        }
        let end = table.add(p, 7, 4).unwrap();
        assert_eq!(table.resolve(end, 7, 1, false), Err(PointerError::Bounds));
        assert_eq!(table.add(p, 7, -1), Err(PointerError::Bounds));
        table.leave_scope(scope).unwrap();
        let next = table.enter_scope().unwrap();
        let fresh = table.register(next, 7, 4096, 4, true).unwrap();
        assert_eq!(table.resolve(p, 7, 1, false), Err(PointerError::Stale));
        assert_eq!(table.resolve(fresh, 7, 1, false), Ok(4096));
    }
    #[test]
    fn rejects_domains_rights_overflow_and_exhaustion() {
        let mut table = ScopedPointers::new(1);
        let scope = table.enter_scope().unwrap();
        assert_eq!(
            table.register(scope, 1, u64::MAX, 1, true),
            Err(PointerError::InvalidRange)
        );
        let p = table.register(scope, 1, 100, 8, false).unwrap();
        assert_eq!(table.resolve(p, 2, 1, false), Err(PointerError::Domain));
        assert_eq!(table.resolve(p, 1, 1, true), Err(PointerError::Rights));
        assert_eq!(table.resolve(p, 1, 9, false), Err(PointerError::Bounds));
        assert_eq!(
            table.register(scope, 1, 200, 1, true),
            Err(PointerError::Exhausted)
        );
        assert_eq!(table.enter_scope(), Err(PointerError::Exhausted));
        table.slots[0].generation = u32::MAX;
        table.leave_scope(scope).unwrap();
        let scope = table.enter_scope().unwrap();
        assert_eq!(
            table.register(scope, 1, 100, 8, false),
            Err(PointerError::Exhausted)
        );
    }
    #[test]
    fn nested_scope_exit_preserves_parent_and_rejects_wrong_order() {
        let mut table = ScopedPointers::new(3);
        let outer = table.enter_scope().unwrap();
        let p = table.register(outer, 1, 100, 8, true).unwrap();
        let inner = table.enter_scope().unwrap();
        let q = table.register(inner, 1, 200, 8, true).unwrap();
        assert_eq!(table.leave_scope(outer), Err(PointerError::InvalidScope));
        assert_eq!(table.resolve(p, 1, 8, false), Ok(100));
        table.leave_scope(inner).unwrap();
        assert_eq!(table.resolve(q, 1, 1, false), Err(PointerError::Stale));
        assert_eq!(table.resolve(p, 1, 8, false), Ok(100));
    }
}

//! Trusted runtime foundation for fixed-buffer pointers. No guest allocator.
//! Opaque trusted tokens expose a two-word ABI payload, never a constructor
//! from integers. CC2 lowering and architectural opcodes are not enabled yet.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerError { Exhausted, InvalidScope, InvalidRange, Stale, Domain, Rights, Bounds }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scope(u64);

/// Fields remain private: integer payloads cannot mint a trusted pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopedPointer { slot: usize, generation: u32, position: u64 }

impl ScopedPointer {
    /// ABI payload only. Reconstructing these integers does not reconstruct kind.
    pub fn words(self) -> [u64; 2] {
        [((self.generation as u64) << 32) | (self.slot as u64 + 1), self.position]
    }
}

#[derive(Debug, Clone)]
struct Allocation { generation: u32, scope: Scope, domain: u64, base: u64, length: u64, writable: bool, live: bool }

#[derive(Debug, Clone)]
pub struct ScopedPointers { slots: Vec<Allocation>, capacity: usize, scopes: std::collections::BTreeMap<u64, Vec<Scope>>, owners: std::collections::BTreeMap<Scope,u64>, next_scope: u64 }

impl ScopedPointers {
    pub fn new(capacity: usize) -> Self {
        Self { slots: Vec::new(), capacity: capacity.min(u32::MAX as usize), scopes: Default::default(), owners: Default::default(), next_scope: 1 }
    }

    pub fn enter_scope(&mut self) -> Result<Scope, PointerError> { self.enter_scope_for(0) }

    pub(crate) fn enter_scope_for(&mut self, owner: u64) -> Result<Scope, PointerError> {
        if self.owners.len() >= self.capacity { return Err(PointerError::Exhausted); }
        let next = self.next_scope.checked_add(1).ok_or(PointerError::Exhausted)?;
        let scope = Scope(self.next_scope);
        self.next_scope = next;
        self.scopes.entry(owner).or_default().push(scope);
        self.owners.insert(scope, owner);
        Ok(scope)
    }

    fn is_top(&self, scope: Scope) -> bool {
        self.owners.get(&scope).and_then(|o| self.scopes.get(o)).and_then(|s| s.last()) == Some(&scope)
    }

    /// The trusted caller must supply an already allocated buffer and its owner domain.
    /// This registers bounds; it does not allocate memory or grant Fabric authority.
    pub fn register(&mut self, scope: Scope, domain: u64, base: u64, length: u64, writable: bool) -> Result<ScopedPointer, PointerError> {
        if !self.is_top(scope) { return Err(PointerError::InvalidScope); }
        base.checked_add(length).ok_or(PointerError::InvalidRange)?;
        let reusable = self.slots.iter().position(|a| !a.live && a.generation != u32::MAX);
        let (slot, generation) = match reusable {
            Some(slot) => (slot, self.slots[slot].generation + 1),
            None if self.slots.len() < self.capacity => (self.slots.len(), 1),
            None => return Err(PointerError::Exhausted),
        };
        let allocation = Allocation { generation, scope, domain, base, length, writable, live: true };
        if slot == self.slots.len() { self.slots.push(allocation); } else { self.slots[slot] = allocation; }
        Ok(ScopedPointer { slot, generation, position: 0 })
    }

    fn allocation(&self, pointer: ScopedPointer, domain: u64) -> Result<&Allocation, PointerError> {
        let a = self.slots.get(pointer.slot).ok_or(PointerError::Stale)?;
        if !a.live || a.generation != pointer.generation { return Err(PointerError::Stale); }
        if a.domain != domain { return Err(PointerError::Domain); }
        Ok(a)
    }

    /// Byte displacement. One-past is transportable but never dereferenceable.
    pub fn add(&self, pointer: ScopedPointer, domain: u64, delta: i64) -> Result<ScopedPointer, PointerError> {
        let a = self.allocation(pointer, domain)?;
        let position = pointer.position.checked_add_signed(delta).ok_or(PointerError::Bounds)?;
        if position > a.length { return Err(PointerError::Bounds); }
        Ok(ScopedPointer { position, ..pointer })
    }

    /// Resolve only a nonempty exact span; Fabric must still authorize its transaction.
    pub fn resolve(&self, pointer: ScopedPointer, domain: u64, width: u64, write: bool) -> Result<u64, PointerError> {
        let a = self.allocation(pointer, domain)?;
        if write && !a.writable { return Err(PointerError::Rights); }
        let end = pointer.position.checked_add(width).ok_or(PointerError::Bounds)?;
        if width == 0 || end > a.length { return Err(PointerError::Bounds); }
        a.base.checked_add(pointer.position).ok_or(PointerError::Bounds)
    }

    /// Synchronous syscall borrow: authentic live allocation, exact owner and
    /// range, including a validated one-past empty range. No token escapes.
    pub(crate) fn read_span(&self, pointer: ScopedPointer, domain: u64,
        owner: u64, length: u64) -> Result<u64, PointerError> {
        let a = self.allocation(pointer, domain)?;
        if self.owners.get(&a.scope) != Some(&owner) { return Err(PointerError::InvalidScope); }
        if pointer.position > a.length || length > a.length - pointer.position {
            return Err(PointerError::Bounds);
        }
        a.base.checked_add(pointer.position).ok_or(PointerError::Bounds)
    }

    pub(crate) fn storage_span(&self, pointer:ScopedPointer) -> Option<(u64,u64)> {
        let a=self.slots.get(pointer.slot)?;
        if a.generation!=pointer.generation { return None; }
        Some((a.base,a.length))
    }

    /// LIFO scope exit invalidates all local identities before slots can be reused.
    /// Concurrent admitted transactions will require the separate lease protocol.
    pub fn leave_scope(&mut self, scope: Scope) -> Result<(), PointerError> {
        if !self.is_top(scope) { return Err(PointerError::InvalidScope); }
        for a in &mut self.slots { if a.scope == scope { a.live = false; } }
        let owner = self.owners.remove(&scope).unwrap();
        let stack = self.scopes.get_mut(&owner).unwrap();
        stack.pop();
        if stack.is_empty() { self.scopes.remove(&owner); }
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
        for i in 0..4 { assert_eq!(table.resolve(table.add(p, 7, i).unwrap(), 7, 1, true), Ok(4096 + i as u64)); }
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
        assert_eq!(table.register(scope, 1, u64::MAX, 1, true), Err(PointerError::InvalidRange));
        let p = table.register(scope, 1, 100, 8, false).unwrap();
        assert_eq!(table.resolve(p, 2, 1, false), Err(PointerError::Domain));
        assert_eq!(table.resolve(p, 1, 1, true), Err(PointerError::Rights));
        assert_eq!(table.resolve(p, 1, 9, false), Err(PointerError::Bounds));
        assert_eq!(table.register(scope, 1, 200, 1, true), Err(PointerError::Exhausted));
        assert_eq!(table.enter_scope(), Err(PointerError::Exhausted));
        table.slots[0].generation = u32::MAX;
        table.leave_scope(scope).unwrap();
        let scope = table.enter_scope().unwrap();
        assert_eq!(table.register(scope, 1, 100, 8, false), Err(PointerError::Exhausted));
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

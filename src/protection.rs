//! Anka protection model — capability-based memory authority.
//!
//! Separates three concerns that conventional MMUs conflate:
//!
//!   **Authority**   — may this agent perform this operation?
//!   **Translation** — where does this object physically reside?
//!   **Consistency** — when do other agents see the write?
//!
//! A capability is:
//!
//!   C = (O, g, b, ℓ, π)
//!
//! where O identifies a memory object, g is a generation counter
//! (for revocation), b is the base address, ℓ the length, and π
//! the permission set {Read, Write, Execute}.
//!
//! A domain is a set of capabilities.  Every agent (CPU core, DMA
//! engine, device) executes within some domain.  Supervisor mode
//! bypasses all checks.
//!
//! The fundamental access check is:
//!
//!   (agent, domain, address, operation) → permit | deny
//!
//! Deny causes a bus error (68000 vector 2).

use crate::abi;
use crate::bus::mapped::MappedBus;
use crate::bus::{Bus, ADDR_MASK_68K};

// ───────────────────────────────────────────────────────────────────
// Permissions
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perm(pub u8);

impl Perm {
    pub const READ: Perm = Perm(0x01);
    pub const WRITE: Perm = Perm(0x02);
    pub const EXEC: Perm = Perm(0x04);
    pub const RW: Perm = Perm(0x03);
    pub const RWX: Perm = Perm(0x07);
    pub const RX: Perm = Perm(0x05);

    pub fn contains(self, other: Perm) -> bool {
        self.0 & other.0 == other.0
    }
}

// ───────────────────────────────────────────────────────────────────
// Capability
// ───────────────────────────────────────────────────────────────────

/// A capability grants access to a range of addresses within a
/// named memory object.
#[derive(Debug, Clone)]
pub struct Capability {
    /// Object identity — what logical object does this refer to?
    pub object_id: u32,
    /// Generation — protects against stale references after recycling.
    pub generation: u32,
    /// Base address (physical).
    pub base: u32,
    /// Length in bytes.
    pub length: u32,
    /// Permission set.
    pub perms: Perm,
}

impl Capability {
    pub fn new(object_id: u32, base: u32, length: u32, perms: Perm) -> Self {
        Self { object_id, generation: 0, base, length, perms }
    }

    /// Check whether this capability authorises an access.
    pub fn permits(&self, addr: u32, size: u32, op: Perm) -> bool {
        if !self.perms.contains(op) {
            return false;
        }
        addr >= self.base
            && size <= self.length
            && addr - self.base <= self.length - size
    }
}

// ───────────────────────────────────────────────────────────────────
// Domain — a set of capabilities
// ───────────────────────────────────────────────────────────────────

/// A protection domain.  Processes, drivers, and devices each
/// execute within a domain.
#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub caps: Vec<Capability>,
}

impl Domain {
    pub fn new(name: &str) -> Self {
        Self { name: name.into(), caps: Vec::new() }
    }

    pub fn grant(&mut self, cap: Capability) {
        self.caps.push(cap);
    }

    /// Check whether any capability in this domain authorises the access.
    pub fn permits(&self, addr: u32, size: u32, op: Perm) -> bool {
        self.caps.iter().any(|c| c.permits(addr, size, op))
    }
}

// ───────────────────────────────────────────────────────────────────
// ProtectedBus — wraps MappedBus with capability enforcement
// ───────────────────────────────────────────────────────────────────

/// A bus that enforces capability-based protection.
///
/// In supervisor mode, all accesses pass through unchecked.
/// In user mode, every read/write is checked against the active
/// domain's capabilities.  A denied access sets a fault flag;
/// the CPU must check `bus_fault()` and take a bus error exception.
pub struct ProtectedBus {
    pub inner: MappedBus,
    domains: Vec<Domain>,
    active_domain: usize,
    supervisor: bool,
    fault: Option<(u32, Perm)>, // (faulting address, attempted operation)
    violations: u64,
}

impl ProtectedBus {
    pub fn new(inner: MappedBus) -> Self {
        Self {
            inner,
            domains: Vec::new(),
            active_domain: 0,
            supervisor: true, // boot in supervisor mode
            fault: None,
            violations: 0,
        }
    }

    /// Add a protection domain.  Returns the domain index.
    pub fn add_domain(&mut self, domain: Domain) -> usize {
        let idx = self.domains.len();
        self.domains.push(domain);
        idx
    }

    /// Switch the active protection domain.
    pub fn set_domain(&mut self, domain_id: usize) {
        self.active_domain = domain_id;
    }

    /// Check and clear the fault flag.  Returns the faulting address.
    pub fn take_fault(&mut self) -> Option<(u32, Perm)> {
        self.fault.take()
    }

    /// Total number of access violations.
    pub fn violation_count(&self) -> u64 {
        self.violations
    }

    /// Check whether an access is permitted.
    fn check(&mut self, addr: u32, size: u32, op: Perm) -> bool {
        if self.supervisor {
            return true;
        }
        if let Some(domain) = self.domains.get(self.active_domain) {
            if domain.permits(addr, size, op) {
                return true;
            }
        }
        // Deny
        self.fault = Some((addr, op));
        self.violations += 1;
        false
    }
}

impl ProtectedBus {
    /// Is this address in the protection controller MMIO range?
    fn is_protect_reg(&self, addr: u32) -> bool {
        let base = abi::PROTECT_BASE;
        addr >= base && addr < base + 8
    }

    fn read_protect_reg(&self, offset: u32) -> u8 {
        match offset {
            0x00 => self.active_domain as u8,
            0x04 => (self.violations >> 24) as u8,
            0x05 => (self.violations >> 16) as u8,
            0x06 => (self.violations >> 8) as u8,
            0x07 => self.violations as u8,
            _ => 0,
        }
    }

    fn write_protect_reg(&mut self, offset: u32, val: u8) {
        if offset == 0x00 {
            self.active_domain = val as usize;
        }
    }
}

impl Bus for ProtectedBus {
    fn read8(&mut self, addr: u32) -> u8 {
        let masked = addr & ADDR_MASK_68K;
        if self.is_protect_reg(masked) {
            return self.read_protect_reg(masked - abi::PROTECT_BASE);
        }
        if !self.check(masked, 1, Perm::READ) {
            return 0xFF;
        }
        self.inner.read8(addr)
    }

    fn write8(&mut self, addr: u32, val: u8) {
        let masked = addr & ADDR_MASK_68K;
        if self.is_protect_reg(masked) {
            self.write_protect_reg(masked - abi::PROTECT_BASE, val);
            return;
        }
        if !self.check(masked, 1, Perm::WRITE) {
            return;
        }
        self.inner.write8(addr, val);
    }

    fn pending_irq(&mut self) -> u8 {
        self.inner.pending_irq()
    }

    fn tick(&mut self, cycles: u32) {
        self.inner.tick(cycles);
    }

    fn set_supervisor(&mut self, is_super: bool) {
        self.supervisor = is_super;
    }

    fn bus_fault(&mut self) -> Option<u32> {
        self.fault.map(|(addr, _)| addr)
    }

    fn clear_bus_fault(&mut self) {
        self.fault = None;
    }
}

// ───────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_permits_within_bounds() {
        let cap = Capability::new(1, 0x1000, 0x100, Perm::RW);
        assert!(cap.permits(0x1000, 4, Perm::READ));
        assert!(cap.permits(0x1000, 4, Perm::WRITE));
        assert!(cap.permits(0x10FC, 4, Perm::READ));  // last 4 bytes
        assert!(!cap.permits(0x10FD, 4, Perm::READ)); // 1 byte past end
        assert!(!cap.permits(0x0FFF, 1, Perm::READ)); // 1 byte before start
    }

    #[test]
    fn capability_denies_wrong_permission() {
        let cap = Capability::new(1, 0x1000, 0x100, Perm::READ);
        assert!(cap.permits(0x1000, 4, Perm::READ));
        assert!(!cap.permits(0x1000, 4, Perm::WRITE));
    }

    #[test]
    fn domain_checks_all_capabilities() {
        let mut dom = Domain::new("test");
        dom.grant(Capability::new(1, 0x1000, 0x100, Perm::RW));
        dom.grant(Capability::new(2, 0x5000, 0x200, Perm::READ));

        assert!(dom.permits(0x1050, 4, Perm::WRITE));
        assert!(dom.permits(0x5100, 4, Perm::READ));
        assert!(!dom.permits(0x5100, 4, Perm::WRITE)); // read-only region
        assert!(!dom.permits(0x3000, 4, Perm::READ));   // no capability
    }

    #[test]
    fn protected_bus_blocks_user_access() {
        let mut inner = MappedBus::new(0x10000);
        inner.write8(0x5000, 0x42);

        let mut bus = ProtectedBus::new(inner);

        // Grant access only to 0x1000-0x1FFF
        let mut dom = Domain::new("proc0");
        dom.grant(Capability::new(1, 0x1000, 0x1000, Perm::RW));
        bus.add_domain(dom);
        bus.set_domain(0);

        // Supervisor mode — can read anything
        bus.set_supervisor(true);
        assert_eq!(bus.read8(0x5000), 0x42);

        // User mode — 0x5000 is outside capabilities
        bus.set_supervisor(false);
        let val = bus.read8(0x5000);
        assert_eq!(val, 0xFF); // denied — returns 0xFF
        assert!(bus.take_fault().is_some());
        assert_eq!(bus.violation_count(), 1);

        // User mode — 0x1000 is within capabilities
        bus.inner.write8(0x1000, 0xAB);
        bus.set_supervisor(false);
        let val = bus.read8(0x1000);
        assert_eq!(val, 0xAB); // permitted
        assert!(bus.take_fault().is_none());
    }

    #[test]
    fn generation_field_is_structural() {
        let cap = Capability::new(1, 0x1000, 0x100, Perm::RW);
        assert!(cap.permits(0x1050, 4, Perm::WRITE));
        assert_eq!(cap.generation, 0);
        assert_eq!(cap.object_id, 1);
        // Full generation-based revocation checking will be added
        // when object IDs are tracked at the domain level.
    }
}

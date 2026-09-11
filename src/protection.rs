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

use std::fmt;

// ───────────────────────────────────────────────────────────────────
// Object table — named memory objects with generation counters
// ───────────────────────────────────────────────────────────────────

/// State of a memory object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectState {
    /// Object is live and its capabilities are valid.
    Active,
    /// Object has been freed; generation was bumped on free.
    Freed,
}

/// An entry in the object table.
#[derive(Debug, Clone)]
pub struct ObjectEntry {
    pub generation: u32,
    pub base: u32,
    pub length: u32,
    pub state: ObjectState,
    pub name: String,
}

/// The object table maps ObjectId → (generation, placement, state).
///
/// Revocation is accomplished by incrementing the generation counter.
/// All capabilities holding the old generation become stale and will
/// fail the generation check on access.
#[derive(Debug, Clone, Default)]
pub struct ObjectTable {
    entries: Vec<ObjectEntry>,
}

impl ObjectTable {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    /// Allocate a new object.  Returns the object ID.
    pub fn alloc(&mut self, name: &str, base: u32, length: u32) -> u32 {
        let id = self.entries.len() as u32;
        self.entries.push(ObjectEntry {
            generation: 0,
            base,
            length,
            state: ObjectState::Active,
            name: name.into(),
        });
        id
    }

    /// Create a capability for an object at its current generation.
    pub fn make_cap(&self, object_id: u32, perms: Perm) -> Option<Capability> {
        let entry = self.entries.get(object_id as usize)?;
        if entry.state != ObjectState::Active { return None; }
        Some(Capability {
            object_id,
            generation: entry.generation,
            base: entry.base,
            length: entry.length,
            perms,
        })
    }

    /// Create a sub-capability: same object, possibly narrower range
    /// and attenuated permissions.  Authority cannot be widened.
    pub fn derive_cap(
        &self,
        parent: &Capability,
        base: u32,
        length: u32,
        perms: Perm,
    ) -> Option<Capability> {
        // Parent must still be valid
        let entry = self.entries.get(parent.object_id as usize)?;
        if entry.state != ObjectState::Active { return None; }
        if parent.generation != entry.generation { return None; }
        // Cannot widen permissions
        if !parent.perms.contains(perms) { return None; }
        // Cannot widen range: sub-range must be within parent
        if base < parent.base { return None; }
        if length > parent.length { return None; }
        if base - parent.base > parent.length - length { return None; }

        Some(Capability {
            object_id: parent.object_id,
            generation: parent.generation,
            base,
            length,
            perms,
        })
    }

    /// Revoke an object: bump generation, mark freed.
    /// All capabilities holding the old generation become stale.
    pub fn revoke(&mut self, object_id: u32) {
        if let Some(entry) = self.entries.get_mut(object_id as usize) {
            entry.generation = entry.generation.wrapping_add(1);
            entry.state = ObjectState::Freed;
        }
    }

    /// Validate a capability against the object table.
    ///
    /// Returns true iff:
    ///   1. The object exists and is Active
    ///   2. The capability's generation matches the object's
    ///   3. The capability's range ⊆ the object's recorded range
    ///
    /// Condition 3 closes the forgery boundary: even if Rust code
    /// constructs a `Capability` with a valid object_id/generation,
    /// it cannot claim a range outside the object's placement.
    ///
    /// valid(C, O) ⟹ range(C) ⊆ range(O)
    pub fn validate(&self, cap: &Capability) -> bool {
        if let Some(entry) = self.entries.get(cap.object_id as usize) {
            entry.state == ObjectState::Active
                && cap.generation == entry.generation
                && cap.base >= entry.base
                && cap.length <= entry.length
                && cap.base - entry.base <= entry.length - cap.length
        } else {
            false
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Fault records
// ───────────────────────────────────────────────────────────────────

/// Why a protection fault occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// No capability in the domain covers this address.
    NoCapability,
    /// A capability covers the address but not the requested permission.
    WrongPermission,
    /// Access to a supervisor-only device register from user mode.
    DeviceAccessDenied,
    /// Object generation mismatch (stale reference).
    StaleGeneration,
}

impl fmt::Display for FaultReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapability => write!(f, "no authority"),
            Self::WrongPermission => write!(f, "wrong permission"),
            Self::DeviceAccessDenied => write!(f, "device access denied"),
            Self::StaleGeneration => write!(f, "stale generation"),
        }
    }
}

/// A forensic fault record.
///
/// Carries enough context for the kernel to produce a precise
/// diagnostic and for post-mortem analysis of adversarial behaviour.
#[derive(Debug, Clone)]
pub struct FaultRecord {
    /// Faulting address.
    pub address: u32,
    /// Access width in bytes.
    pub size: u32,
    /// Attempted operation.
    pub operation: Perm,
    /// Why the access was denied.
    pub reason: FaultReason,
    /// Active domain index at fault time.
    pub domain_id: usize,
    /// Domain name (if available).
    pub domain_name: String,
}

impl FaultRecord {
    pub fn new(address: u32, size: u32, operation: Perm, reason: FaultReason) -> Self {
        Self {
            address, size, operation, reason,
            domain_id: 0,
            domain_name: String::new(),
        }
    }

    fn with_domain(mut self, id: usize, name: &str) -> Self {
        self.domain_id = id;
        self.domain_name = name.to_string();
        self
    }
}

impl fmt::Display for FaultRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = if self.operation == Perm::READ { "READ" }
                 else if self.operation == Perm::WRITE { "WRITE" }
                 else { "EXEC" };
        write!(f, "PROTECTION FAULT  domain={}({}) addr={:06X} {}x{} reason={}",
            self.domain_id, self.domain_name,
            self.address, op, self.size, self.reason)
    }
}

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
///
/// Fields are private.  Capabilities are minted only through
/// [`ObjectTable::make_cap`] or [`ObjectTable::derive_cap`].
/// The legacy constructor [`Capability::new`] is `pub(crate)`
/// for v0.1/v0.2 backward compatibility where no object table
/// is configured.
#[derive(Debug, Clone)]
pub struct Capability {
    object_id: u32,
    generation: u32,
    base: u32,
    length: u32,
    perms: Perm,
}

impl Capability {
    /// Legacy constructor — creates a capability without an object
    /// table entry.  Use `ObjectTable::make_cap()` for new code.
    pub(crate) fn new(object_id: u32, base: u32, length: u32, perms: Perm) -> Self {
        Self { object_id, generation: 0, base, length, perms }
    }

    // ── Accessors ─────────────────────────────────────────────

    pub fn object_id(&self) -> u32 { self.object_id }
    pub fn generation(&self) -> u32 { self.generation }
    pub fn base(&self) -> u32 { self.base }
    pub fn length(&self) -> u32 { self.length }
    pub fn perms(&self) -> Perm { self.perms }

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
    fault: Option<FaultRecord>,
    violations: u64,
    /// Complete fault log for post-mortem analysis.
    pub fault_log: Vec<FaultRecord>,
    /// Object table for generation-based revocation.
    pub objects: ObjectTable,
}

impl ProtectedBus {
    pub fn new(inner: MappedBus) -> Self {
        Self {
            inner,
            domains: Vec::new(),
            active_domain: 0,
            supervisor: true,
            fault: None,
            violations: 0,
            fault_log: Vec::new(),
            objects: ObjectTable::new(),
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

    /// Check and clear the fault flag.  Returns the full fault record.
    pub fn take_fault(&mut self) -> Option<FaultRecord> {
        self.fault.take()
    }

    /// Total number of access violations.
    pub fn violation_count(&self) -> u64 {
        self.violations
    }

    /// Check whether an access is permitted.
    ///
    /// The domain is a **set** of capabilities.  Authorization is
    /// existential:
    ///
    ///   authorize(D, R) ⟺ ∃ C ∈ D : valid(C) ∧ C ⊢ R
    ///
    /// We scan all capabilities before deciding.  A valid match
    /// anywhere in the domain authorizes the access, regardless of
    /// ordering.  Only after scanning the entire set do we report
    /// a fault — StaleGeneration if any stale cap covered the
    /// request, otherwise NoCapability or WrongPermission.
    ///
    /// This preserves monotonicity: Authority(D) ⊆ Authority(D+C)
    /// implies Allowed(D) ⊆ Allowed(D+C).
    fn check(&mut self, addr: u32, size: u32, op: Perm) -> bool {
        if self.supervisor {
            return true;
        }
        if let Some(domain) = self.domains.get(self.active_domain) {
            let mut stale_match = false;

            for cap in &domain.caps {
                if cap.permits(addr, size, op) {
                    if self.objects.entries.is_empty() {
                        // No object table — legacy mode
                        return true;
                    }
                    if self.objects.validate(cap) {
                        return true;
                    }
                    stale_match = true;
                }
            }

            // No valid capability authorizes the request.
            let reason = if stale_match {
                FaultReason::StaleGeneration
            } else if domain.caps.iter().any(|c|
                c.permits(addr, size, Perm::READ)
                || c.permits(addr, size, Perm::WRITE)
                || c.permits(addr, size, Perm(Perm::EXEC.0)))
            {
                FaultReason::WrongPermission
            } else {
                FaultReason::NoCapability
            };
            let record = FaultRecord::new(addr, size, op, reason)
                .with_domain(self.active_domain, &domain.name);
            self.fault_log.push(record.clone());
            self.fault = Some(record);
        } else {
            let record = FaultRecord::new(addr, size, op, FaultReason::NoCapability)
                .with_domain(self.active_domain, "<invalid>");
            self.fault_log.push(record.clone());
            self.fault = Some(record);
        }
        self.violations += 1;
        false
    }

    /// Perform a DMA write on behalf of a device agent.
    ///
    /// The device provides its own capability (not the CPU's domain).
    /// The write is checked against the object table for generation
    /// validity.  This is the same protection fabric — every bus
    /// master is an agent.
    pub fn dma_write(&mut self, cap: &Capability, offset: u32, data: &[u8]) -> Result<(), FaultRecord> {
        let addr = cap.base.wrapping_add(offset);

        // Validate the capability against the object table
        if !self.objects.validate(cap) {
            let record = FaultRecord::new(addr, data.len() as u32, Perm::WRITE,
                FaultReason::StaleGeneration)
                .with_domain(usize::MAX, "dma-agent");
            self.fault_log.push(record.clone());
            self.violations += 1;
            return Err(record);
        }

        // Check range
        if !cap.permits(addr, data.len() as u32, Perm::WRITE) {
            let record = FaultRecord::new(addr, data.len() as u32, Perm::WRITE,
                FaultReason::NoCapability)
                .with_domain(usize::MAX, "dma-agent");
            self.fault_log.push(record.clone());
            self.violations += 1;
            return Err(record);
        }

        // Authorized — perform the write
        for (i, &byte) in data.iter().enumerate() {
            self.inner.write8(addr.wrapping_add(i as u32), byte);
        }
        Ok(())
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
        // Protection controller is supervisor-only privileged state,
        // not an ordinary device.  User access → fault.
        if self.is_protect_reg(masked) {
            if !self.supervisor {
                let dom_name = self.domains.get(self.active_domain)
                    .map(|d| d.name.as_str()).unwrap_or("<invalid>");
                let record = FaultRecord::new(
                    masked, 1, Perm::READ,
                    FaultReason::DeviceAccessDenied,
                ).with_domain(self.active_domain, dom_name);
                self.fault_log.push(record.clone());
                self.fault = Some(record);
                self.violations += 1;
                return 0xFF;
            }
            return self.read_protect_reg(masked - abi::PROTECT_BASE);
        }
        if !self.check(masked, 1, Perm::READ) {
            return 0xFF;
        }
        self.inner.read8(addr)
    }

    fn write8(&mut self, addr: u32, val: u8) {
        let masked = addr & ADDR_MASK_68K;
        // Protection controller is supervisor-only.
        if self.is_protect_reg(masked) {
            if !self.supervisor {
                let dom_name = self.domains.get(self.active_domain)
                    .map(|d| d.name.as_str()).unwrap_or("<invalid>");
                let record = FaultRecord::new(
                    masked, 1, Perm::WRITE,
                    FaultReason::DeviceAccessDenied,
                ).with_domain(self.active_domain, dom_name);
                self.fault_log.push(record.clone());
                self.fault = Some(record);
                self.violations += 1;
                return;
            }
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
        self.fault.as_ref().map(|r| r.address)
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
    fn object_table_alloc_and_revoke() {
        let mut ot = ObjectTable::new();
        let id = ot.alloc("buffer", 0x1000, 0x100);
        assert_eq!(id, 0);

        // Make a capability
        let cap = ot.make_cap(id, Perm::RW).unwrap();
        assert_eq!(cap.generation(), 0);
        assert!(ot.validate(&cap));

        // Revoke — generation bumps, cap becomes stale
        ot.revoke(id);
        assert!(!ot.validate(&cap));
        assert_eq!(ot.entries[0].generation, 1);
        assert_eq!(ot.entries[0].state, ObjectState::Freed);
    }

    #[test]
    fn sub_capability_cannot_widen() {
        let mut ot = ObjectTable::new();
        let id = ot.alloc("region", 0x2000, 0x1000);
        let parent = ot.make_cap(id, Perm::READ).unwrap();

        // Cannot widen permissions
        assert!(ot.derive_cap(&parent, 0x2000, 0x100, Perm::RW).is_none());

        // Can narrow range
        let child = ot.derive_cap(&parent, 0x2100, 0x100, Perm::READ).unwrap();
        assert_eq!(child.base(), 0x2100);
        assert_eq!(child.length(), 0x100);
        assert_eq!(child.generation(), parent.generation());
    }

    #[test]
    fn generation_check_in_bus() {
        let mut inner = MappedBus::new(0x10000);
        inner.write8(0x1000, 0x42);

        let mut bus = ProtectedBus::new(inner);

        // Set up object table
        let obj_id = bus.objects.alloc("testobj", 0x1000, 0x100);
        let cap = bus.objects.make_cap(obj_id, Perm::RW).unwrap();

        // Grant the capability to domain 0
        let mut dom = Domain::new("proc0");
        dom.grant(cap.clone());
        bus.add_domain(dom);
        bus.set_domain(0);

        // User mode read — should succeed (generation matches)
        bus.set_supervisor(false);
        assert_eq!(bus.read8(0x1000), 0x42);
        assert!(bus.take_fault().is_none());

        // Revoke the object
        bus.objects.revoke(obj_id);

        // User mode read — should fail (generation stale)
        let val = bus.read8(0x1000);
        assert_eq!(val, 0xFF);
        let fault = bus.take_fault().unwrap();
        assert_eq!(fault.reason, FaultReason::StaleGeneration);
    }

    /// Kleis counterexample: two capabilities covering the same range,
    /// C₁ = stale, C₂ = valid.  With order [C₁, C₂], the old scan
    /// returned StaleGeneration on C₁ and never examined C₂.
    ///
    /// Under set semantics, the valid C₂ must authorize the access
    /// regardless of ordering.  This test verifies both orderings
    /// produce the same result.
    /// Kleis TCB witness: a fabricated capability claiming the same
    /// object_id/generation but a different range must be rejected
    /// by validate().
    #[test]
    fn forgery_boundary_range_check() {
        let mut ot = ObjectTable::new();
        let id = ot.alloc("real_obj", 0x20000, 0x1000);

        // Legitimate capability — should validate
        let legit = ot.make_cap(id, Perm::RW).unwrap();
        assert!(ot.validate(&legit));

        // Fabricated capability: same object_id and generation,
        // but claims range 0x50000..0x50FFF (outside the object)
        let fabricated = Capability {
            object_id: id,
            generation: 0,
            base: 0x50000,
            length: 0x1000,
            perms: Perm::RW,
        };
        assert!(!ot.validate(&fabricated),
            "validate() accepted fabricated cap outside object range");

        // Fabricated: correct base but excessive length
        let oversized = Capability {
            object_id: id,
            generation: 0,
            base: 0x20000,
            length: 0x2000, // twice the object's length
            perms: Perm::RW,
        };
        assert!(!ot.validate(&oversized),
            "validate() accepted oversized cap");

        // Sub-range within object — should validate
        let sub = Capability {
            object_id: id,
            generation: 0,
            base: 0x20100,
            length: 0x100,
            perms: Perm::READ,
        };
        assert!(ot.validate(&sub),
            "validate() rejected sub-range within object");
    }

    #[test]
    fn scan_order_independence() {
        // Try stale-first ordering
        let inner = MappedBus::new(0x10000);
        let mut bus = ProtectedBus::new(inner);

        let obj_id = bus.objects.alloc("region", 0x1000, 0x1000);

        // Cap at generation 0 (will become stale)
        let stale_cap = bus.objects.make_cap(obj_id, Perm::RW).unwrap();

        // Revoke and re-alloc at generation 1
        bus.objects.revoke(obj_id);
        bus.objects.entries[obj_id as usize].state = ObjectState::Active;
        bus.objects.entries[obj_id as usize].generation = 1;

        // Valid cap at generation 1
        let valid_cap = bus.objects.make_cap(obj_id, Perm::RW).unwrap();

        // Domain with [stale, valid] ordering
        let mut dom = Domain::new("test");
        dom.grant(stale_cap);
        dom.grant(valid_cap);
        bus.add_domain(dom);
        bus.set_domain(0);

        // Write sentinel
        bus.inner.write8(0x1050, 0x42);

        // User mode read — must succeed (valid cap exists in set)
        bus.set_supervisor(false);
        let val = bus.read8(0x1050);
        assert_eq!(val, 0x42, "set semantics: stale-first ordering denied valid access");
        assert!(bus.take_fault().is_none(),
            "set semantics: spurious fault with valid cap in domain");
        assert_eq!(bus.violation_count(), 0);
    }

    #[test]
    fn dma_write_and_revocation() {
        let inner = MappedBus::new(0x10000);
        let mut bus = ProtectedBus::new(inner);

        // Allocate a buffer object
        let buf_id = bus.objects.alloc("dma-buffer", 0x4000, 0x100);
        let cap = bus.objects.make_cap(buf_id, Perm::RW).unwrap();

        // DMA write succeeds before revocation
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(bus.dma_write(&cap, 0, &data).is_ok());
        assert_eq!(bus.inner.read8(0x4000), 0xDE);
        assert_eq!(bus.inner.read8(0x4003), 0xEF);

        // Revoke the buffer
        bus.objects.revoke(buf_id);

        // DMA write with stale capability — DENIED
        let stale_data = [0xFF, 0xFF, 0xFF, 0xFF];
        let result = bus.dma_write(&cap, 0, &stale_data);
        assert!(result.is_err());
        let fault = result.unwrap_err();
        assert_eq!(fault.reason, FaultReason::StaleGeneration);

        // Memory is UNCHANGED — the denied write had no side effect
        assert_eq!(bus.inner.read8(0x4000), 0xDE);
        assert_eq!(bus.inner.read8(0x4003), 0xEF);
        assert_eq!(bus.violation_count(), 1);
    }
}

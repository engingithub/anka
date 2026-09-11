//! Anka64 multi-agent concurrent fabric.
//!
//! Every request carries its context.  There is no global mutable
//! `bus.supervisor` or `bus.active_domain` — those cannot make sense
//! in a multicore machine.
//!
//! The fabric enforces the separation:
//!   - **Authorization** answers: may this domain perform this operation?
//!   - **Translation** answers: where does this object physically reside?
//!   - These are independent (Invariant I3).

use std::collections::BTreeMap;

use super::state::*;

// ───────────────────────────────────────────────────────────────────
// Authorization result
// ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AuthResult {
    Authorized(Generation),
    Denied(FaultReason),
}

// ───────────────────────────────────────────────────────────────────
// Fabric
// ───────────────────────────────────────────────────────────────────

pub struct Fabric {
    pub objects: BTreeMap<ObjectId, Object>,
    pub domains: BTreeMap<DomainId, DomainState>,
    pub agents: BTreeMap<AgentId, AgentState>,
    placement: BTreeMap<ObjectId, u64>,
    memory: Vec<u8>,
    pub fault_log: Vec<FaultRecord>,
    transactions: Vec<Transaction>,
    next_object_id: u64,
    next_domain_id: u64,
    next_tx_id: u64,
}

impl Fabric {
    pub fn new(mem_size: usize) -> Self {
        Self {
            objects: BTreeMap::new(),
            domains: BTreeMap::new(),
            agents: BTreeMap::new(),
            placement: BTreeMap::new(),
            memory: vec![0u8; mem_size],
            fault_log: Vec::new(),
            transactions: Vec::new(),
            next_object_id: 0,
            next_domain_id: 0,
            next_tx_id: 0,
        }
    }

    // ───────────────── Object management ─────────────────────────

    pub fn alloc_object(&mut self, name: &str, size: u64, kind: ObjectKind) -> ObjectId {
        let id = ObjectId(self.next_object_id);
        self.next_object_id += 1;
        self.objects.insert(id, Object {
            id,
            generation: Generation(0),
            size,
            state: ObjectState::Active,
            kind,
            name: name.to_string(),
        });
        id
    }

    /// Place an object at a physical address.
    ///
    /// Rejects overlapping placements (I9: every physical memory
    /// effect has exactly one logical object provenance).
    pub fn place_object(&mut self, id: ObjectId, physical_base: u64) -> bool {
        let obj = match self.objects.get(&id) {
            Some(o) => o,
            None => return false,
        };
        let new_end = physical_base + obj.size;

        for (&existing_id, &existing_base) in &self.placement {
            if existing_id == id { continue; }
            if let Some(existing_obj) = self.objects.get(&existing_id) {
                if !matches!(existing_obj.state, ObjectState::Active | ObjectState::Sealed) {
                    continue;
                }
                let existing_end = existing_base + existing_obj.size;
                if physical_base < existing_end && new_end > existing_base {
                    return false; // overlap rejected (I9)
                }
            }
        }

        self.placement.insert(id, physical_base);
        true
    }

    /// Move an object to a new physical address.
    ///
    /// Authority is unchanged (I3).
    pub fn move_object(&mut self, id: ObjectId, new_base: u64) -> bool {
        self.placement.remove(&id);
        self.place_object(id, new_base)
    }

    /// Revoke an object — bump generation, mark Revoked.
    ///
    /// All capabilities minted at the old generation become stale.
    /// Generation is monotonic (I8).
    pub fn revoke(&mut self, id: ObjectId) {
        if let Some(obj) = self.objects.get_mut(&id) {
            obj.generation = obj.generation.next();
            obj.state = ObjectState::Revoked;
        }
    }

    /// Seal an object — transition Active → Sealed, bump generation.
    ///
    /// W⊕X structural invariant: once sealed, `grant()` refuses to
    /// create WRITE or ATOMIC capabilities for this object.
    /// All existing capabilities (including RW) become stale.
    ///
    /// Returns false if the object is not Active.
    pub fn seal_object(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.state != ObjectState::Active { return false; }
            obj.generation = obj.generation.next();
            obj.state = ObjectState::Sealed;
            true
        } else {
            false
        }
    }

    // ───────────────── Domain management ─────────────────────────

    pub fn create_domain(&mut self) -> DomainId {
        let id = DomainId(self.next_domain_id);
        self.next_domain_id += 1;
        self.domains.insert(id, DomainState {
            id,
            capabilities: Vec::new(),
        });
        id
    }

    pub fn register_agent(&mut self, id: AgentId, kind: AgentKind, domain: DomainId) {
        self.agents.insert(id, AgentState { id, kind, domain });
    }

    /// Grant a new capability covering a range within an object.
    ///
    /// W⊕X: refuses WRITE or ATOMIC on Sealed objects.
    pub fn grant(
        &mut self,
        domain: DomainId,
        object: ObjectId,
        offset: u64,
        length: u64,
        perms: Permissions,
    ) -> Option<Capability64> {
        let obj = self.objects.get(&object)?;
        match obj.state {
            ObjectState::Active => {
                if perms.contains(Permissions::EXECUTE) {
                    return None; // W⊕X: active objects reject execute
                }
            }
            ObjectState::Sealed => {
                if perms.contains(Permissions::WRITE)
                    || perms.contains(Permissions::ATOMIC)
                    || perms.contains(Permissions::SEAL)
                {
                    return None; // W⊕X: sealed objects reject write/atomic/seal
                }
            }
            _ => return None,
        }
        // Overflow-safe range check (Rule 28: match Kleis subtraction form).
        //   Kleis: bvule(cap_len, obj_size) ∧ bvule(cap_off, bvsub(obj_size, cap_len))
        //   Rust:  length <= obj.size       && offset <= obj.size - length
        if length > obj.size { return None; }
        if offset > obj.size - length { return None; }

        let cap = Capability64::new(object, obj.generation, offset, length, perms);
        self.domains.get_mut(&domain)?.capabilities.push(cap.clone());
        Some(cap)
    }

    /// Derive a child capability from a parent — cannot amplify (I7).
    pub fn derive(
        &mut self,
        domain: DomainId,
        parent: &Capability64,
        child_offset: u64,
        child_length: u64,
        child_perms: Permissions,
    ) -> Option<Capability64> {
        if !self.validate(parent) { return None; }
        if !child_perms.is_subset_of(parent.permissions()) { return None; }
        if child_offset < parent.offset() { return None; }
        if child_length > parent.length() { return None; }
        if child_offset - parent.offset() > parent.length() - child_length {
            return None;
        }

        let cap = Capability64::new(
            parent.object(),
            parent.generation(),
            child_offset,
            child_length,
            child_perms,
        );
        self.domains.get_mut(&domain)?.capabilities.push(cap.clone());
        Some(cap)
    }

    /// Write bytes into an Active object (bounds-checked, object-relative).
    ///
    /// This is the formal initialization path for objects that will
    /// later be sealed and become executable.  Once sealed, not even
    /// this method can modify the object's bytes (Active-only check).
    ///
    /// `write_physical()` remains for test bootstrap only.
    pub fn initialize_object(&mut self, id: ObjectId, offset: u64, data: &[u8]) -> bool {
        let obj = match self.objects.get(&id) {
            Some(o) if o.state == ObjectState::Active => o,
            _ => return false,
        };
        let len = data.len() as u64;
        if len > obj.size { return false; }
        if offset > obj.size - len { return false; }
        let phys_base = match self.placement.get(&id) {
            Some(&b) => b,
            None => return false,
        };
        let base = (phys_base + offset) as usize;
        for (i, &byte) in data.iter().enumerate() {
            if base + i < self.memory.len() {
                self.memory[base + i] = byte;
            }
        }
        true
    }

    // ───────────────── Authorization ─────────────────────────────

    /// Validate a capability against the object table.
    ///
    /// Checks: object alive (Active or Sealed), generation match,
    /// range ⊆ object.  A Sealed object is still alive — it accepts
    /// READ/EXECUTE operations but no WRITE (enforced by `grant()`).
    pub fn validate(&self, cap: &Capability64) -> bool {
        if let Some(obj) = self.objects.get(&cap.object()) {
            matches!(obj.state, ObjectState::Active | ObjectState::Sealed)
                && cap.generation() == obj.generation
                && cap.length() <= obj.size
                && cap.offset() <= obj.size - cap.length()
        } else {
            false
        }
    }

    /// Find a valid capability in a domain that covers a specific range
    /// with the required permissions.
    ///
    /// This is the range-exact authority check. The old object-level
    /// `has_authority()` asked only "does the domain have *some* capability
    /// on this object?" — that lets narrow authority amplify to whole-object
    /// authority, violating attenuation (I7).
    ///
    /// This method answers the stronger question:
    ///   ∃ C ∈ D : valid(C) ∧ C ⊢ (O, offset, length, permission)
    pub fn find_authorizing_cap(
        &self,
        domain: DomainId,
        object: ObjectId,
        offset: u64,
        length: u64,
        required: Permissions,
    ) -> Option<&Capability64> {
        self.domains.get(&domain)?.capabilities.iter().find(|cap| {
            self.validate(cap)
                && cap.covers(object, offset, length, required)
        })
    }

    /// Authorize a memory request against a domain's capabilities.
    ///
    /// Set semantics: ∃ C ∈ D : valid(C) ∧ C ⊢ R.
    ///
    /// The function signature takes (domain, request).
    /// It does NOT take AgentId or CoreId (I1, I2).
    pub fn authorize(&self, request: &MemoryRequest) -> AuthResult {
        let domain = match self.domains.get(&request.context.domain) {
            Some(d) => d,
            None => return AuthResult::Denied(FaultReason::NoCapability),
        };

        let required = request.kind.required_permission();
        let width = request.width.bytes();
        let mut stale = false;

        for cap in &domain.capabilities {
            if cap.covers(request.object, request.offset, width, required) {
                if self.validate(cap) {
                    return AuthResult::Authorized(cap.generation());
                }
                stale = true;
            }
        }

        let reason = if stale {
            FaultReason::StaleGeneration
        } else if domain.capabilities.iter().any(|c| {
            c.object() == request.object && self.validate(c)
        }) {
            FaultReason::WrongPermission
        } else {
            FaultReason::NoCapability
        };

        AuthResult::Denied(reason)
    }

    // ───────────────── Translation ───────────────────────────────

    /// Translate (object, offset) → physical address.
    ///
    /// Knows nothing about whether the caller is allowed.
    /// That decision has already happened (I3).
    pub fn translate(&self, object: ObjectId, offset: u64) -> Option<u64> {
        self.placement.get(&object).map(|base| base + offset)
    }

    // ───────────────── Transaction lifecycle ─────────────────────

    /// Submit a request, returning its transaction index.
    pub fn submit(
        &mut self,
        request: MemoryRequest,
        write_data: Option<Vec<u8>>,
    ) -> usize {
        let id = TransactionId(self.next_tx_id);
        self.next_tx_id += 1;
        let tx = Transaction {
            id,
            request,
            state: TxState::Requested,
            auth_generation: None,
            physical_address: None,
            write_data,
            fault: None,
        };
        self.transactions.push(tx);
        self.transactions.len() - 1
    }

    /// Advance a transaction to its next phase.
    pub fn advance(&mut self, idx: usize) {
        let state = self.transactions[idx].state;
        match state {
            TxState::Requested => self.phase_authorize(idx),
            TxState::Authorized => self.phase_translate(idx),
            TxState::Prepared => self.phase_commit(idx),
            TxState::Committed | TxState::Faulted => {}
        }
    }

    fn phase_authorize(&mut self, idx: usize) {
        let request = self.transactions[idx].request;
        match self.authorize(&request) {
            AuthResult::Authorized(g) => {
                self.transactions[idx].auth_generation = Some(g);
                self.transactions[idx].state = TxState::Authorized;
            }
            AuthResult::Denied(reason) => {
                self.fault_transaction(idx, reason);
            }
        }
    }

    fn phase_translate(&mut self, idx: usize) {
        let request = self.transactions[idx].request;
        match self.translate(request.object, request.offset) {
            Some(phys) => {
                self.transactions[idx].physical_address = Some(phys);
                self.transactions[idx].state = TxState::Prepared;
            }
            None => {
                self.fault_transaction(idx, FaultReason::TranslationFault);
            }
        }
    }

    fn phase_commit(&mut self, idx: usize) {
        let request = self.transactions[idx].request;

        // COMMIT-TIME REVALIDATION (I5)
        //
        // Re-authorize at the current generation.
        // If the object was revoked since authorization, fault.
        match self.authorize(&request) {
            AuthResult::Authorized(_gen) => {}
            AuthResult::Denied(reason) => {
                self.fault_transaction(idx, reason);
                return;
            }
        }

        let phys = match self.transactions[idx].physical_address {
            Some(p) => p,
            None => {
                self.fault_transaction(idx, FaultReason::TranslationFault);
                return;
            }
        };

        match request.kind {
            AccessKind::Write | AccessKind::Atomic => {
                if let Some(ref data) = self.transactions[idx].write_data {
                    let base = phys as usize;
                    for (i, &byte) in data.iter().enumerate() {
                        if base + i < self.memory.len() {
                            self.memory[base + i] = byte;
                        }
                    }
                }
            }
            AccessKind::Read | AccessKind::Fetch => {
                // Read data from physical memory
            }
        }

        self.transactions[idx].state = TxState::Committed;
    }

    fn fault_transaction(&mut self, idx: usize, reason: FaultReason) {
        let tx = &mut self.transactions[idx];
        tx.state = TxState::Faulted;
        let record = FaultRecord {
            agent: tx.request.context.agent,
            domain: tx.request.context.domain,
            privilege: tx.request.context.privilege,
            transaction: tx.id,
            object: tx.request.object,
            generation: tx.auth_generation,
            offset: tx.request.offset,
            width: tx.request.width,
            kind: tx.request.kind,
            pc: None,
            reason,
        };
        tx.fault = Some(record.clone());
        self.fault_log.push(record);
    }

    // ───────────────── Deterministic scheduler ───────────────────

    pub fn run_schedule(&mut self, events: &[Event]) {
        for event in events {
            match event {
                Event::Advance(idx) => self.advance(*idx),
                Event::Revoke(id) => self.revoke(*id),
                Event::Move(id, base) => { self.move_object(*id, *base); }
            }
        }
    }

    // ───────────────── Core integration ─────────────────────────

    /// Execute a complete read transaction, returning data or fault.
    ///
    /// The full lifecycle runs: authorize → translate → commit.
    /// On success, data is read from the translated physical address.
    pub fn execute_read(
        &mut self,
        request: MemoryRequest,
    ) -> Result<Vec<u8>, FaultRecord> {
        let width = request.width.bytes() as usize;
        let idx = self.submit(request, None);
        self.advance(idx); // authorize
        self.advance(idx); // translate
        self.advance(idx); // commit
        match self.transactions[idx].state {
            TxState::Committed => {
                let phys = self.transactions[idx].physical_address.unwrap() as usize;
                Ok(self.memory[phys..phys + width].to_vec())
            }
            TxState::Faulted => {
                Err(self.transactions[idx].fault.clone().unwrap())
            }
            _ => unreachable!("transaction not terminal after 3 advances"),
        }
    }

    /// Execute a complete write transaction, or return a fault.
    pub fn execute_write(
        &mut self,
        request: MemoryRequest,
        data: Vec<u8>,
    ) -> Result<(), FaultRecord> {
        let idx = self.submit(request, Some(data));
        self.advance(idx);
        self.advance(idx);
        self.advance(idx);
        match self.transactions[idx].state {
            TxState::Committed => Ok(()),
            TxState::Faulted => {
                Err(self.transactions[idx].fault.clone().unwrap())
            }
            _ => unreachable!("transaction not terminal after 3 advances"),
        }
    }

    /// Execute an atomic exchange: read old value, write new value,
    /// one indivisible transaction.  Under SC this is guaranteed
    /// atomic because only one core steps at a time.
    pub fn execute_atomic_xchg(
        &mut self,
        request: MemoryRequest,
        new_value: Vec<u8>,
    ) -> Result<Vec<u8>, FaultRecord> {
        let width = request.width.bytes() as usize;
        let idx = self.submit(request, Some(new_value));
        self.advance(idx); // authorize
        self.advance(idx); // translate → Prepared

        if self.transactions[idx].state == TxState::Faulted {
            return Err(self.transactions[idx].fault.clone().unwrap());
        }

        // Capture old value while in Prepared state (before commit writes)
        let phys = self.transactions[idx].physical_address.unwrap() as usize;
        let old_value = self.memory[phys..phys + width].to_vec();

        // Commit (writes new value, revalidates generation)
        self.advance(idx);

        match self.transactions[idx].state {
            TxState::Committed => Ok(old_value),
            TxState::Faulted => {
                Err(self.transactions[idx].fault.clone().unwrap())
            }
            _ => unreachable!("transaction not terminal after 3 advances"),
        }
    }

    // ───────────────── Observation ───────────────────────────────

    pub fn transaction(&self, idx: usize) -> &Transaction {
        &self.transactions[idx]
    }

    pub fn read_physical(&self, addr: u64, len: u64) -> &[u8] {
        let a = addr as usize;
        let l = len as usize;
        &self.memory[a..a + l]
    }

    pub fn write_physical(&mut self, addr: u64, data: &[u8]) {
        let a = addr as usize;
        for (i, &b) in data.iter().enumerate() {
            self.memory[a + i] = b;
        }
    }

    fn mem4(&self, addr: u64) -> [u8; 4] {
        let s = self.read_physical(addr, 4);
        [s[0], s[1], s[2], s[3]]
    }
}

// ───────────────────────────────────────────────────────────────────
// Helper: build a MemoryRequest
// ───────────────────────────────────────────────────────────────────

pub fn request(
    agent: AgentId,
    domain: DomainId,
    object: ObjectId,
    offset: u64,
    width: Width,
    kind: AccessKind,
) -> MemoryRequest {
    MemoryRequest {
        context: AccessContext {
            agent,
            domain,
            privilege: Privilege::User,
        },
        object,
        offset,
        width,
        kind,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — invariants I1–I9 and exit criterion
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const CPU0: AgentId = AgentId(0);
    const CPU1: AgentId = AgentId(1);
    const DMA0: AgentId = AgentId(2);

    const SENTINEL: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
    const PAYLOAD_A: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    const PAYLOAD_B: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    fn setup_basic() -> (Fabric, ObjectId, DomainId) {
        let mut f = Fabric::new(0x100000);
        let obj = f.alloc_object("buffer", 0x1000, ObjectKind::Memory);
        f.place_object(obj, 0x4000);
        f.write_physical(0x4000, &SENTINEL);
        let dom = f.create_domain();
        f.grant(dom, obj, 0, 0x1000, Permissions::RW);
        (f, obj, dom)
    }

    fn write_req(agent: AgentId, domain: DomainId, obj: ObjectId, off: u64) -> MemoryRequest {
        request(agent, domain, obj, off, Width::Word, AccessKind::Write)
    }

    fn read_req(agent: AgentId, domain: DomainId, obj: ObjectId, off: u64) -> MemoryRequest {
        request(agent, domain, obj, off, Width::Word, AccessKind::Read)
    }

    // ═══════════════════════════════════════════════════════════
    // Basic operations
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn basic_commit() {
        let (mut f, obj, dom) = setup_basic();
        let idx = f.submit(write_req(CPU0, dom, obj, 0), Some(PAYLOAD_A.to_vec()));
        f.advance(idx); // Authorize
        f.advance(idx); // Translate
        f.advance(idx); // Commit
        assert_eq!(f.transaction(idx).state, TxState::Committed);
        assert_eq!(f.mem4(0x4000), PAYLOAD_A);
    }

    #[test]
    fn no_capability_denied() {
        let (mut f, obj, _dom) = setup_basic();
        let empty_dom = f.create_domain();
        let idx = f.submit(write_req(CPU0, empty_dom, obj, 0), Some(PAYLOAD_A.to_vec()));
        f.advance(idx);
        assert_eq!(f.transaction(idx).state, TxState::Faulted);
        assert_eq!(f.transaction(idx).fault.as_ref().unwrap().reason, FaultReason::NoCapability);
        assert_eq!(f.mem4(0x4000), SENTINEL, "denied write corrupted memory");
    }

    // ═══════════════════════════════════════════════════════════
    // I1: Authority is independent of AgentId
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i1_authority_independent_of_agent() {
        let (f, obj, dom) = setup_basic();

        let req_cpu0 = write_req(CPU0, dom, obj, 0);
        let req_cpu1 = write_req(CPU1, dom, obj, 0);
        let req_dma0 = write_req(DMA0, dom, obj, 0);

        let r0 = matches!(f.authorize(&req_cpu0), AuthResult::Authorized(_));
        let r1 = matches!(f.authorize(&req_cpu1), AuthResult::Authorized(_));
        let r2 = matches!(f.authorize(&req_dma0), AuthResult::Authorized(_));

        assert_eq!(r0, r1, "I1: same domain, different agents, different result");
        assert_eq!(r1, r2, "I1: CPU vs DMA with same domain diverged");
    }

    // ═══════════════════════════════════════════════════════════
    // I2: Authority is independent of CoreId
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i2_domain_migration_preserves_authority() {
        let (mut f, obj, dom) = setup_basic();

        // Agent initially on Core 0
        f.register_agent(CPU0, AgentKind::Cpu(CoreId(0)), dom);
        let req = write_req(CPU0, dom, obj, 0);
        let before = matches!(f.authorize(&req), AuthResult::Authorized(_));

        // "Migrate" domain to Core 3 (just change agent's core metadata)
        f.agents.get_mut(&CPU0).unwrap().kind = AgentKind::Cpu(CoreId(3));
        let after = matches!(f.authorize(&req), AuthResult::Authorized(_));

        assert_eq!(before, after, "I2: domain migration changed authorization");
    }

    // ═══════════════════════════════════════════════════════════
    // I3: Authority is independent of placement
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i3_move_object_preserves_authority() {
        let (mut f, obj, dom) = setup_basic();

        let req = write_req(CPU0, dom, obj, 0);
        let before = matches!(f.authorize(&req), AuthResult::Authorized(_));

        // Move object to a completely different physical address
        f.move_object(obj, 0x80000);
        let after = matches!(f.authorize(&req), AuthResult::Authorized(_));

        assert_eq!(before, after, "I3: moving object changed authorization");

        // Translation changed, but authority didn't
        assert_eq!(f.translate(obj, 0), Some(0x80000));
    }

    // ═══════════════════════════════════════════════════════════
    // I4: Every memory effect has an authorized transaction witness
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i4_committed_transaction_was_authorized() {
        let (mut f, obj, dom) = setup_basic();
        let idx = f.submit(write_req(CPU0, dom, obj, 0), Some(PAYLOAD_A.to_vec()));

        f.advance(idx); // Authorize
        assert_eq!(f.transaction(idx).state, TxState::Authorized);
        assert!(f.transaction(idx).auth_generation.is_some(),
            "I4: authorized transaction has no generation witness");

        f.advance(idx); // Translate
        f.advance(idx); // Commit
        assert_eq!(f.transaction(idx).state, TxState::Committed);

        // The committed transaction carried authorization from gen 0
        assert_eq!(f.transaction(idx).auth_generation, Some(Generation(0)));
    }

    // ═══════════════════════════════════════════════════════════
    // I5: Every committed transaction was valid at commit
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i5_commit_time_revalidation() {
        let (mut f, obj, dom) = setup_basic();
        let idx = f.submit(write_req(CPU0, dom, obj, 0), Some(PAYLOAD_A.to_vec()));

        f.advance(idx); // Authorize at gen 0
        assert_eq!(f.transaction(idx).auth_generation, Some(Generation(0)));

        f.revoke(obj); // gen → 1

        f.advance(idx); // Translate (succeeds — translation doesn't check gen)
        f.advance(idx); // Commit → Faulted (revalidation fails)

        assert_eq!(f.transaction(idx).state, TxState::Faulted);
        assert_eq!(f.transaction(idx).fault.as_ref().unwrap().reason,
            FaultReason::StaleGeneration);
        assert_eq!(f.mem4(0x4000), SENTINEL, "I5: stale commit wrote to memory");
    }

    // ═══════════════════════════════════════════════════════════
    // I6: Faulted transactions have no ordinary side effects (N8c)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i6_concurrent_noninterference() {
        // Scenario A: revoke only
        let (mut fa, obj_a, _dom_a) = setup_basic();
        fa.revoke(obj_a);
        let mem_a = fa.mem4(0x4000);
        let gen_a = fa.objects[&obj_a].generation;
        let faults_a = fa.fault_log.len();

        // Scenario B: authorize → revoke → attempt commit
        let (mut fb, obj_b, dom_b) = setup_basic();
        let idx = fb.submit(write_req(CPU0, dom_b, obj_b, 0), Some(PAYLOAD_A.to_vec()));
        fb.advance(idx); // Authorize
        fb.revoke(obj_b); // Revoke
        fb.advance(idx); // Translate
        fb.advance(idx); // Commit → Faulted

        let mem_b = fb.mem4(0x4000);
        let gen_b = fb.objects[&obj_b].generation;

        assert_eq!(mem_a, mem_b, "I6/N8c: stale transaction altered memory");
        assert_eq!(gen_a, gen_b, "I6/N8c: generation diverged");
        assert_eq!(faults_a, 0);
        assert!(fb.fault_log.len() >= 1);
    }

    // ═══════════════════════════════════════════════════════════
    // I7: Delegation cannot amplify authority
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i7_derive_cannot_widen_range() {
        let (mut f, obj, dom) = setup_basic();
        let parent = f.grant(dom, obj, 0x100, 0x200, Permissions::RW).unwrap();

        // Try to derive a child wider than parent → None
        let child = f.derive(dom, &parent, 0x100, 0x300, Permissions::RW);
        assert!(child.is_none(), "I7: derive widened range");
    }

    #[test]
    fn i7_derive_cannot_escalate_permissions() {
        let (mut f, obj, dom) = setup_basic();
        let parent = f.grant(dom, obj, 0, 0x1000, Permissions::READ).unwrap();

        let child = f.derive(dom, &parent, 0, 0x1000, Permissions::RW);
        assert!(child.is_none(), "I7: derive escalated permissions");
    }

    #[test]
    fn i7_valid_derive() {
        let (mut f, obj, dom) = setup_basic();
        let parent = f.grant(dom, obj, 0, 0x1000, Permissions::RW).unwrap();

        let child = f.derive(dom, &parent, 0x100, 0x200, Permissions::READ);
        assert!(child.is_some(), "I7: valid derive rejected");
        let c = child.unwrap();
        assert_eq!(c.offset(), 0x100);
        assert_eq!(c.length(), 0x200);
        assert_eq!(c.permissions(), Permissions::READ);
    }

    // ═══════════════════════════════════════════════════════════
    // I8: Revocation cannot resurrect authority
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i8_generation_monotonic() {
        let (mut f, obj, _dom) = setup_basic();
        let g0 = f.objects[&obj].generation;
        f.revoke(obj);
        let g1 = f.objects[&obj].generation;
        f.revoke(obj);
        let g2 = f.objects[&obj].generation;

        assert!(g1 > g0, "I8: revocation didn't advance generation");
        assert!(g2 > g1, "I8: double revocation didn't advance");
    }

    #[test]
    fn i8_stale_capability_stays_dead() {
        let (mut f, obj, dom) = setup_basic();

        f.revoke(obj);

        // Re-activate with new generation (simulate object recycling)
        f.objects.get_mut(&obj).unwrap().state = ObjectState::Active;

        // Old capability (gen 0) is still dead
        let req = write_req(CPU0, dom, obj, 0);
        assert!(matches!(f.authorize(&req), AuthResult::Denied(FaultReason::StaleGeneration)),
            "I8: stale capability resurrected after recycling");
    }

    // ═══════════════════════════════════════════════════════════
    // I9: Every physical memory effect has exactly one object provenance
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn i9_overlapping_placement_rejected() {
        let mut f = Fabric::new(0x100000);

        let obj_a = f.alloc_object("A", 0x1000, ObjectKind::Memory);
        let obj_b = f.alloc_object("B", 0x1000, ObjectKind::Memory);

        assert!(f.place_object(obj_a, 0x4000));
        assert!(!f.place_object(obj_b, 0x4800), // overlaps A
            "I9: overlapping placement accepted");
    }

    // ═══════════════════════════════════════════════════════════
    // W⊕X structural invariant: Sealed objects reject WRITE
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn wx1_sealed_object_rejects_write_grant() {
        let (mut f, obj, dom) = setup_basic();

        // Seal the object
        assert!(f.seal_object(obj));
        assert_eq!(f.objects[&obj].state, ObjectState::Sealed);

        // Try to grant WRITE — must fail
        let new_dom = f.create_domain();
        assert!(f.grant(new_dom, obj, 0, 0x1000, Permissions::WRITE).is_none(),
            "W⊕X: sealed object accepted WRITE grant");

        // Try to grant RW — must fail (contains WRITE)
        assert!(f.grant(new_dom, obj, 0, 0x1000, Permissions::RW).is_none(),
            "W⊕X: sealed object accepted RW grant");

        // Try to grant ATOMIC — must fail
        assert!(f.grant(new_dom, obj, 0, 0x1000, Permissions::ATOMIC).is_none(),
            "W⊕X: sealed object accepted ATOMIC grant");

        // Grant READ — must succeed
        assert!(f.grant(new_dom, obj, 0, 0x1000, Permissions::READ).is_some(),
            "W⊕X: sealed object rejected READ grant");

        // Grant RX — must succeed
        assert!(f.grant(new_dom, obj, 0, 0x1000, Permissions::RX).is_some(),
            "W⊕X: sealed object rejected RX grant");

        eprintln!("WX1: Sealed(O) ⇒ ¬∃C: valid(C,O) ∧ W ∈ C.perms ✓");
    }

    #[test]
    fn wx2_sealed_object_denies_write_transaction() {
        let (mut f, obj, dom) = setup_basic();

        // Write before seal — should succeed
        let idx1 = f.submit(write_req(CPU0, dom, obj, 0), Some(PAYLOAD_A.to_vec()));
        f.advance(idx1); f.advance(idx1); f.advance(idx1);
        assert_eq!(f.transaction(idx1).state, TxState::Committed);

        // Seal the object
        assert!(f.seal_object(obj));

        // Grant RX at new generation for read access
        let rx_dom = f.create_domain();
        f.grant(rx_dom, obj, 0, 0x1000, Permissions::RX);

        // Write after seal — old cap is stale, no new WRITE cap possible
        let idx2 = f.submit(write_req(CPU0, dom, obj, 0), Some(PAYLOAD_B.to_vec()));
        f.advance(idx2);
        assert_eq!(f.transaction(idx2).state, TxState::Faulted);
        assert_eq!(f.transaction(idx2).fault.as_ref().unwrap().reason,
            FaultReason::StaleGeneration);

        // Read after seal — should succeed with new RX cap
        let read_idx = f.submit(read_req(CPU0, rx_dom, obj, 0), None);
        f.advance(read_idx); f.advance(read_idx); f.advance(read_idx);
        assert_eq!(f.transaction(read_idx).state, TxState::Committed);

        // Verify data unchanged (PAYLOAD_A from before seal)
        assert_eq!(f.mem4(0x4000), PAYLOAD_A);

        eprintln!("WX2: write transaction on sealed object → StaleGeneration ✓");
    }

    #[test]
    fn wx3_seal_only_from_active() {
        let (mut f, obj, _) = setup_basic();

        // Seal works on Active
        assert!(f.seal_object(obj), "seal should succeed on Active");
        assert_eq!(f.objects[&obj].state, ObjectState::Sealed);

        // Double-seal fails — already Sealed, not Active
        assert!(!f.seal_object(obj), "seal should fail on already-Sealed");

        // Revoke the sealed object
        f.revoke(obj);
        assert_eq!(f.objects[&obj].state, ObjectState::Revoked);

        // Seal on Revoked fails
        assert!(!f.seal_object(obj), "seal should fail on Revoked");
    }

    #[test]
    fn wx4_active_object_rejects_execute_grant() {
        let (mut f, obj, _dom) = setup_basic();

        // Object is Active — try to grant EXECUTE
        assert_eq!(f.objects[&obj].state, ObjectState::Active);

        let exec_dom = f.create_domain();
        assert!(f.grant(exec_dom, obj, 0, 0x1000, Permissions::EXECUTE).is_none(),
            "W⊕X: active object accepted EXECUTE grant");

        // RX also contains EXECUTE — must fail
        assert!(f.grant(exec_dom, obj, 0, 0x1000, Permissions::RX).is_none(),
            "W⊕X: active object accepted RX grant");

        // WRITE on Active — must succeed
        assert!(f.grant(exec_dom, obj, 0, 0x1000, Permissions::WRITE).is_some(),
            "Active object rejected WRITE grant");

        // READ on Active — must succeed
        assert!(f.grant(exec_dom, obj, 0, 0x1000, Permissions::READ).is_some(),
            "Active object rejected READ grant");

        eprintln!("WX4: Active(O) ⇒ ¬∃C: valid(C,O) ∧ X ∈ C.perms ✓");
    }

    #[test]
    fn wx4b_initialize_object() {
        let (mut f, obj, _dom) = setup_basic();

        // Active → initialize succeeds
        assert!(f.initialize_object(obj, 0, &[1, 2, 3, 4]));

        // Bounds check: offset + length > size fails
        assert!(!f.initialize_object(obj, 0x1000, &[1]),
            "initialize_object should reject out-of-bounds write");

        // Seal → initialize fails
        assert!(f.seal_object(obj));
        assert!(!f.initialize_object(obj, 0, &[1]),
            "initialize_object should reject Sealed object");

        eprintln!("WX4b: initialize_object: Active ✓, bounds ✓, Sealed ✗ ✓");
    }

    #[test]
    fn wx5_full_wx_lifecycle() {
        // Complete lifecycle: alloc Active → write → seal → grant RX
        let (mut f, obj, dom) = setup_basic();

        // Step 1: Active object can be written
        let w_dom = f.create_domain();
        assert!(f.grant(w_dom, obj, 0, 0x1000, Permissions::WRITE).is_some());

        // Step 2: Seal the object
        assert!(f.seal_object(obj));

        // Step 3: Sealed object can be granted RX
        let rx_dom = f.create_domain();
        assert!(f.grant(rx_dom, obj, 0, 0x1000, Permissions::RX).is_some());

        // Step 4: No domain has WRITE + EXECUTE on same object
        // - w_dom's cap is stale (generation bumped by seal)
        // - rx_dom's cap has no WRITE
        let w_cap = f.find_authorizing_cap(w_dom, obj, 0, 0x1000, Permissions::WRITE);
        assert!(w_cap.is_none(), "stale write cap should not validate");

        let rx_cap = f.find_authorizing_cap(rx_dom, obj, 0, 0x1000, Permissions::EXECUTE);
        assert!(rx_cap.is_some(), "post-seal RX cap should validate");

        eprintln!("WX5: full W⊕X lifecycle: Active(W) → Sealed(RX), no overlap ✓");
    }

    #[test]
    fn i9_adjacent_placement_ok() {
        let mut f = Fabric::new(0x100000);

        let obj_a = f.alloc_object("A", 0x1000, ObjectKind::Memory);
        let obj_b = f.alloc_object("B", 0x1000, ObjectKind::Memory);

        assert!(f.place_object(obj_a, 0x4000));
        assert!(f.place_object(obj_b, 0x5000), // adjacent, not overlapping
            "I9: adjacent placement rejected");
    }

    // ═══════════════════════════════════════════════════════════
    // Phase 1 exit criterion
    //
    //   CPU0 / Domain A  ──read──▶ Object X
    //   CPU1 / Domain B  ──write─▶ Object Y
    //   DMA0 / Domain C  ──write─▶ Object X
    //                              │
    //   CPU1 ─────────── revoke X ─┘
    //
    // Deterministic scheduling.  All outcomes defined.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn exit_criterion_multiagent_revocation() {
        let mut f = Fabric::new(0x100000);

        // Objects
        let obj_x = f.alloc_object("X", 0x1000, ObjectKind::Memory);
        let obj_y = f.alloc_object("Y", 0x1000, ObjectKind::Memory);
        f.place_object(obj_x, 0x10000);
        f.place_object(obj_y, 0x20000);

        // Sentinels
        f.write_physical(0x10000, &SENTINEL);
        f.write_physical(0x20000, &SENTINEL);

        // Domains
        let dom_a = f.create_domain();
        let dom_b = f.create_domain();
        let dom_c = f.create_domain();

        // Grant capabilities
        f.grant(dom_a, obj_x, 0, 0x1000, Permissions::READ);  // A reads X
        f.grant(dom_b, obj_y, 0, 0x1000, Permissions::RW);    // B writes Y
        f.grant(dom_b, obj_x, 0, 0x1000, Permissions::RW);    // B can revoke X
        f.grant(dom_c, obj_x, 0, 0x1000, Permissions::WRITE); // C writes X

        // Register agents
        f.register_agent(CPU0, AgentKind::Cpu(CoreId(0)), dom_a);
        f.register_agent(CPU1, AgentKind::Cpu(CoreId(1)), dom_b);
        f.register_agent(DMA0, AgentKind::Dma, dom_c);

        // Submit transactions
        let tx_read_x = f.submit(
            read_req(CPU0, dom_a, obj_x, 0),
            None,
        );
        let tx_write_y = f.submit(
            write_req(CPU1, dom_b, obj_y, 0),
            Some(PAYLOAD_A.to_vec()),
        );
        let tx_dma_x = f.submit(
            write_req(DMA0, dom_c, obj_x, 0),
            Some(PAYLOAD_B.to_vec()),
        );

        // ─── Schedule: CPU0 reads X, CPU1 writes Y, then
        //               CPU1 revokes X, DMA0 attempts write X ───
        let schedule = [
            // CPU0 reads X — full lifecycle before revocation
            Event::Advance(tx_read_x),   // Authorize
            Event::Advance(tx_read_x),   // Translate
            Event::Advance(tx_read_x),   // Commit (read)

            // CPU1 writes Y — full lifecycle (unaffected by X revocation)
            Event::Advance(tx_write_y),  // Authorize
            Event::Advance(tx_write_y),  // Translate
            Event::Advance(tx_write_y),  // Commit

            // DMA0 starts writing X — authorized at gen 0
            Event::Advance(tx_dma_x),    // Authorize (gen 0 ✓)
            Event::Advance(tx_dma_x),    // Translate

            // CPU1 REVOKES X — generation bumps to 1
            Event::Revoke(obj_x),

            // DMA0 tries to commit — DENIED (gen 0 ≠ gen 1)
            Event::Advance(tx_dma_x),    // Commit → Faulted
        ];

        f.run_schedule(&schedule);

        // ─── Verify all outcomes ───

        // CPU0's read of X committed (before revocation)
        assert_eq!(f.transaction(tx_read_x).state, TxState::Committed,
            "CPU0 read of X should have committed");

        // CPU1's write to Y committed (Y was never revoked)
        assert_eq!(f.transaction(tx_write_y).state, TxState::Committed,
            "CPU1 write to Y should have committed");
        assert_eq!(f.mem4(0x20000), PAYLOAD_A,
            "Y should contain CPU1's write");

        // DMA0's write to X FAULTED (stale generation)
        assert_eq!(f.transaction(tx_dma_x).state, TxState::Faulted,
            "DMA0 write to X should have faulted");
        assert_eq!(
            f.transaction(tx_dma_x).fault.as_ref().unwrap().reason,
            FaultReason::StaleGeneration,
            "DMA0 fault reason should be StaleGeneration"
        );

        // X's memory unchanged — sentinel intact (N8c)
        assert_eq!(f.mem4(0x10000), SENTINEL,
            "Object X memory should be unchanged after denied DMA write");

        // Object X is now revoked with generation 1
        assert_eq!(f.objects[&obj_x].generation, Generation(1));
        assert_eq!(f.objects[&obj_x].state, ObjectState::Revoked);

        // Object Y is unaffected
        assert_eq!(f.objects[&obj_y].generation, Generation(0));
        assert_eq!(f.objects[&obj_y].state, ObjectState::Active);

        // Exactly one fault in the log (the DMA write)
        assert_eq!(f.fault_log.len(), 1);
        assert_eq!(f.fault_log[0].agent, DMA0);
        assert_eq!(f.fault_log[0].object, obj_x);

        eprintln!("Exit criterion: 2 CPUs + 1 DMA, revocation race");
        eprintln!("  CPU0 read X:  {:?}", f.transaction(tx_read_x).state);
        eprintln!("  CPU1 write Y: {:?}", f.transaction(tx_write_y).state);
        eprintln!("  DMA0 write X: {:?} ({})",
            f.transaction(tx_dma_x).state,
            f.transaction(tx_dma_x).fault.as_ref().unwrap().reason);
        eprintln!("  X memory:     {:02X?} (sentinel intact)", f.mem4(0x10000));
        eprintln!("  Y memory:     {:02X?} (CPU1 write landed)", f.mem4(0x20000));
        eprintln!("  faults:       {}", f.fault_log.len());
    }

    // ═══════════════════════════════════════════════════════════
    // Exhaustive phase × revocation (Anka64 version)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn exhaustive_revocation_timing_64() {
        struct Case {
            name: &'static str,
            revoke_after_step: Option<usize>,
            expect: TxState,
            expect_mem: [u8; 4],
        }

        let cases = [
            Case { name: "no revocation", revoke_after_step: None,
                   expect: TxState::Committed, expect_mem: PAYLOAD_A },
            Case { name: "revoke before authorize", revoke_after_step: Some(0),
                   expect: TxState::Faulted, expect_mem: SENTINEL },
            Case { name: "revoke between authorize and translate", revoke_after_step: Some(1),
                   expect: TxState::Faulted, expect_mem: SENTINEL },
            Case { name: "revoke between translate and commit", revoke_after_step: Some(2),
                   expect: TxState::Faulted, expect_mem: SENTINEL },
            Case { name: "revoke after commit", revoke_after_step: Some(3),
                   expect: TxState::Committed, expect_mem: PAYLOAD_A },
        ];

        for case in &cases {
            let (mut f, obj, dom) = setup_basic();
            let idx = f.submit(write_req(CPU0, dom, obj, 0), Some(PAYLOAD_A.to_vec()));

            for step in 0..3 {
                if case.revoke_after_step == Some(step) {
                    f.revoke(obj);
                }
                f.advance(idx);
            }
            if case.revoke_after_step == Some(3) {
                f.revoke(obj);
            }

            assert_eq!(f.transaction(idx).state, case.expect,
                "case '{}': expected {:?}, got {:?}",
                case.name, case.expect, f.transaction(idx).state);
            assert_eq!(f.mem4(0x4000), case.expect_mem,
                "case '{}': memory mismatch", case.name);

            eprintln!("  ✓ {}: {:?}", case.name, f.transaction(idx).state);
        }
    }
}

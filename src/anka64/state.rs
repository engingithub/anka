//! Anka64 type definitions — the architectural state space.
//!
//! None of these collapses into another merely because conventional
//! machines often conflate them.

use std::fmt;

// ───────────────────────────────────────────────────────────────────
// Identity types
// ───────────────────────────────────────────────────────────────────

macro_rules! id_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u64);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

id_type!(CoreId, "Identifies a CPU core.");
id_type!(AgentId, "Identifies any bus master (CPU, DMA, GPU, …).");
id_type!(DomainId, "Identifies a protection domain.");
id_type!(ObjectId, "Identifies a memory object.");
id_type!(TransactionId, "Identifies a fabric transaction.");

/// Object/capability generation counter (64-bit for Anka64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Generation(pub u64);

impl Generation {
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "g{}", self.0)
    }
}

// ───────────────────────────────────────────────────────────────────
// Permissions
// ───────────────────────────────────────────────────────────────────

/// Permission bitfield.
///
/// Includes `ATOMIC` from Phase 1 onward even though detailed
/// atomics semantics are deferred to multicore (Phase 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Permissions(pub u8);

impl Permissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(0x01);
    pub const WRITE: Self = Self(0x02);
    pub const EXECUTE: Self = Self(0x04);
    pub const ATOMIC: Self = Self(0x08);
    /// Authority to seal an object (Active → Sealed).
    ///
    /// Separate from WRITE because writing a buffer and authorizing
    /// it to become executable code are different powers:
    ///   WRITE authority ≠ authority to create executable code.
    pub const SEAL: Self = Self(0x10);
    pub const RW: Self = Self(0x03);
    pub const RX: Self = Self(0x05);
    pub const RWX: Self = Self(0x07);
    /// Read + Write + Seal: the capability needed for a code
    /// emission buffer that will later be sealed.
    pub const RWS: Self = Self(0x13);

    pub fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub fn is_subset_of(self, superset: Self) -> bool {
        superset.contains(self)
    }
}

// ───────────────────────────────────────────────────────────────────
// Capability
// ───────────────────────────────────────────────────────────────────

/// A capability granting authority over a range within an object.
///
/// Fields are private (forgery boundary — Phase 0 lesson).
/// Construction only through `Fabric::grant` or `Fabric::derive`.
#[derive(Debug, Clone)]
pub struct Capability64 {
    object: ObjectId,
    generation: Generation,
    offset: u64,
    length: u64,
    permissions: Permissions,
}

impl Capability64 {
    pub(crate) fn new(
        object: ObjectId,
        generation: Generation,
        offset: u64,
        length: u64,
        permissions: Permissions,
    ) -> Self {
        Self { object, generation, offset, length, permissions }
    }

    pub fn object(&self) -> ObjectId { self.object }
    pub fn generation(&self) -> Generation { self.generation }
    pub fn offset(&self) -> u64 { self.offset }
    pub fn length(&self) -> u64 { self.length }
    pub fn permissions(&self) -> Permissions { self.permissions }

    /// Does this capability cover a request to the given object?
    ///
    /// Checks: same object, sufficient permissions, request range
    /// within capability window.  Does NOT check generation — that
    /// is `Fabric::validate`.
    pub fn covers(
        &self,
        object: ObjectId,
        req_offset: u64,
        req_width: u64,
        required: Permissions,
    ) -> bool {
        self.object == object
            && req_width > 0
            && self.permissions.contains(required)
            && req_offset >= self.offset
            && req_width <= self.length
            && req_offset - self.offset <= self.length - req_width
    }
}

// ───────────────────────────────────────────────────────────────────
// Object
// ───────────────────────────────────────────────────────────────────

/// Object lifecycle state.
///
/// ```text
///   Active ──seal──▶ Sealed ──revoke──▶ Revoked ──free──▶ Freed
///     │                                    ▲
///     └──────────revoke────────────────────┘
/// ```
///
/// Once Sealed, no WRITE or ATOMIC capability can be minted (W⊕X).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectState {
    Active,
    Sealed,
    Revoked,
    Freed,
}

/// Object kind (extensible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Memory,
    Device,
    Ipc,
}

/// A memory object.
///
/// Notice what's absent: `physical_base`.
/// Placement belongs to the translation layer.
pub struct Object {
    pub id: ObjectId,
    pub generation: Generation,
    pub size: u64,
    pub state: ObjectState,
    pub kind: ObjectKind,
    pub name: String,
}

// ───────────────────────────────────────────────────────────────────
// Core state
// ───────────────────────────────────────────────────────────────────

/// Abstract register file.  ISA design (Phase 2) defines this.
pub struct RegisterFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    User,
    Supervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    Running,
    Halted,
    Faulted,
}

/// CPU core state.
///
/// Crucially: `domain ≠ core`.  A domain may migrate:
///   D₇: Core₀ → Core₃.
pub struct CoreState {
    pub id: CoreId,
    pub registers: RegisterFile,
    pub pc: u64,
    pub privilege: Privilege,
    pub domain: DomainId,
    pub execution_state: ExecutionState,
}

// ───────────────────────────────────────────────────────────────────
// Agent state
// ───────────────────────────────────────────────────────────────────

/// Agent kind.  The CPU is just one kind of bus master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    Cpu(CoreId),
    Dma,
    Gpu,
    Storage,
    Network,
}

/// Non-CPU agents and CPU agents share the same authority model.
///
///   AgentId = CPU₀, CPU₁, DMA₀, GPU₀, …
///
/// is an ordinary architectural namespace.
pub struct AgentState {
    pub id: AgentId,
    pub kind: AgentKind,
    pub domain: DomainId,
}

// ───────────────────────────────────────────────────────────────────
// Domain state
// ───────────────────────────────────────────────────────────────────

/// A protection domain — an authority container.
///
///   authorize(D, R) ⟺ ∃ C ∈ D : valid(C) ∧ C ⊢ R
///
/// Set semantics.  No ordering.  No hidden "current global domain."
pub struct DomainState {
    pub id: DomainId,
    pub capabilities: Vec<Capability64>,
}

// ───────────────────────────────────────────────────────────────────
// Memory request
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Fetch,
    Read,
    Write,
    Atomic,
}

impl AccessKind {
    pub fn required_permission(self) -> Permissions {
        match self {
            AccessKind::Fetch => Permissions::EXECUTE,
            AccessKind::Read => Permissions::READ,
            AccessKind::Write => Permissions::WRITE,
            AccessKind::Atomic => Permissions::ATOMIC,
        }
    }
}

/// Transaction width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Byte = 1,
    Half = 2,
    Word = 4,
    Double = 8,
}

impl Width {
    pub fn bytes(self) -> u64 { self as u64 }
}

/// Access context — carried per-request, not global mutable state.
///
/// Agent and core are present for fault reporting, not authorization.
/// Authority depends only on domain (I1, I2).
#[derive(Debug, Clone, Copy)]
pub struct AccessContext {
    pub agent: AgentId,
    pub domain: DomainId,
    pub privilege: Privilege,
}

/// The canonical Anka64 memory request.
///
/// Each request concerns exactly one object.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRequest {
    pub context: AccessContext,
    pub object: ObjectId,
    pub offset: u64,
    pub width: Width,
    pub kind: AccessKind,
}

// ───────────────────────────────────────────────────────────────────
// Transaction state machine
// ───────────────────────────────────────────────────────────────────

/// Transaction lifecycle phase.
///
/// ```text
/// Requested → Authorized → Prepared → Committed
///     ↓            ↓           ↓
///   Faulted     Faulted     Faulted
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    Requested,
    Authorized,
    Prepared,
    Committed,
    Faulted,
}

impl TxState {
    pub fn is_terminal(self) -> bool {
        matches!(self, TxState::Committed | TxState::Faulted)
    }
}

/// A fabric transaction with explicit lifecycle.
///
/// The crucial invariant:
///   g_commit = g_authorized, or the transaction faults.
pub struct Transaction {
    pub id: TransactionId,
    pub request: MemoryRequest,
    pub state: TxState,
    pub auth_generation: Option<Generation>,
    pub physical_address: Option<u64>,
    pub write_data: Option<Vec<u8>>,
    pub fault: Option<FaultRecord>,
}

// ───────────────────────────────────────────────────────────────────
// Fault state
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    NoCapability,
    StaleGeneration,
    WrongPermission,
    InvalidObject,
    TranslationFault,
    AlignmentFault,
    /// RET target does not carry return authority minted by matching CALL.
    ///
    /// Rule 29: "An executable address is not control-flow authority."
    ControlFlowViolation,
}

impl fmt::Display for FaultReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapability => write!(f, "NoCapability"),
            Self::StaleGeneration => write!(f, "StaleGeneration"),
            Self::WrongPermission => write!(f, "WrongPermission"),
            Self::InvalidObject => write!(f, "InvalidObject"),
            Self::TranslationFault => write!(f, "TranslationFault"),
            Self::AlignmentFault => write!(f, "AlignmentFault"),
            Self::ControlFlowViolation => write!(f, "ControlFlowViolation"),
        }
    }
}

/// Protected return authority minted by CALL.
///
/// Lives on a per-core protected stack, not in ordinary memory.
/// CALL is the only mint.  LD/ST/ALU cannot forge, read, or modify
/// return authority.  RET validates against the top of the stack.
///
/// Rule 29: data that names executable code is not, by itself,
/// authority to transfer control to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnAuthority {
    /// Code object containing the CALL site.
    pub code_object: ObjectId,
    /// Generation of that object at CALL time.
    pub generation: Generation,
    /// Virtual return address (PC + 4 of the CALL).
    pub target: u64,
}

/// A first-class architectural fault record.
///
/// A DMA fault may have no meaningful PC.
/// A CPU fault does.
/// The architecture doesn't fake one unified model where it doesn't exist.
#[derive(Debug, Clone)]
pub struct FaultRecord {
    pub agent: AgentId,
    pub domain: DomainId,
    pub privilege: Privilege,
    pub transaction: TransactionId,
    pub object: ObjectId,
    pub generation: Option<Generation>,
    pub offset: u64,
    pub width: Width,
    pub kind: AccessKind,
    pub pc: Option<u64>,
    pub reason: FaultReason,
}

// ───────────────────────────────────────────────────────────────────
// Events (deterministic scheduler)
// ───────────────────────────────────────────────────────────────────

/// A deterministic event in the Anka64 fabric.
#[derive(Debug, Clone)]
pub enum Event {
    /// Advance a transaction to its next phase.
    Advance(usize),
    /// Revoke an object (bump generation).
    Revoke(ObjectId),
    /// Move an object to a new physical base (translation change).
    /// Authority must be unaffected (I3).
    Move(ObjectId, u64),
}

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

    /// Mask of all defined permission bits (R|W|X|ATOMIC|SEAL).
    pub const ALL_BITS: u64 = 0x1F;

    /// Checked permission decoder — the single authority for valid
    /// permission bits.  Accepts `u64` so the SPAWN ABI's native
    /// register-width field can be validated without a truncating cast.
    /// The system-image wire format widens its `u8` before calling.
    pub fn from_bits_checked(bits: u64) -> Option<Self> {
        if bits & !Self::ALL_BITS != 0 {
            return None;
        }
        Some(Self(bits as u8))
    }

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
/// Each request concerns exactly one object and an explicit byte span.
///
/// `length` is the Fabric-level authorization span in bytes.  CPU scalar
/// paths derive it from `width.bytes()`.  DMA paths set it directly
/// (e.g. `length: 512` for a block transfer).  This prevents an ISA
/// representation detail from becoming an architectural limitation of
/// the Fabric.
///
/// `width` remains for ISA context in fault records and CPU decode.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRequest {
    pub context: AccessContext,
    pub object: ObjectId,
    pub offset: u64,
    /// ISA-level transaction width (CPU context).  DMA paths may set
    /// this to `Width::Byte` as a placeholder — the Fabric uses
    /// `length`, not `width`, for authorization and commit.
    pub width: Width,
    /// Byte span authorized and committed.  Must be nonzero.
    /// CPU paths: `width.bytes()`.  DMA paths: e.g. 512.
    pub length: u64,
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
    /// Decoded opcode has no semantic mapping in the description table.
    ///
    /// Distinct from Halted: an illegal instruction is an architectural
    /// fault, not a deliberate stop.  Without this distinction, an
    /// unknown opcode with R0 == 42 in user mode would be silently
    /// reported as "normal exit 42" instead of a fault.
    IllegalInstruction,
    /// Declared transaction span does not match provided data length.
    ///
    /// Protection boundary: length mismatch implies zero memory mutation.
    /// DMA span commit is all-or-nothing — authorization, bounds,
    /// generation revalidation, AND data-length validation all complete
    /// before the first byte changes.
    LengthMismatch,
    /// Transaction span is zero bytes or overflows address arithmetic.
    ///
    /// `offset + length` or `physical + length` would wrap.
    InvalidSpan,
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
            Self::IllegalInstruction => write!(f, "IllegalInstruction"),
            Self::LengthMismatch => write!(f, "LengthMismatch"),
            Self::InvalidSpan => write!(f, "InvalidSpan"),
        }
    }
}

/// Protected return authority minted by CALL.
///
/// Lives on a per-execution-context protected stack, not in ordinary
/// memory.  CALL is the only mint.  LD/ST/ALU cannot forge, read,
/// or modify return authority.  RET validates against the top of
/// the stack; failed RET leaves R unchanged (fault atomicity).
///
/// Rule 29: data that names executable code is not, by itself,
/// authority to transfer control to it.
///
/// **Future: ExecutionContext separation.**
/// Currently stored on `Anka64Core`.  The architectural intent is
/// that an `ExecutionContext` owns R and migrates between cores:
///   `Core0 owns Context7 → migrate → Core1 owns Context7`
/// This is structurally correct today (Rust move semantics carry
/// `return_stack` with the core) but should become explicit when
/// the architecture gains context switching.
///
/// **Future: remapping provenance.**
/// `target` is a virtual address.  RET currently checks that
/// `target` matches LR and that `code_object`'s generation is
/// valid, but does NOT re-verify that `target` still resolves
/// to `code_object`.  While address mappings are effectively
/// static today, once Anka gains mutable remapping the stronger
/// invariant should be: `resolve(target) = (code_object, offset)`
/// at RET time.  Otherwise the same virtual address could be
/// remapped to a different sealed code object while the original
/// object's generation remains valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnAuthority {
    /// Code object containing the CALL site.
    pub code_object: ObjectId,
    /// Generation of that object at CALL time.
    pub generation: Generation,
    /// Virtual return address (PC + 4 of the CALL).
    pub target: u64,
}

// ───────────────────────────────────────────────────────────────────
// Event architecture (Phase 9.0)
// ───────────────────────────────────────────────────────────────────

/// Why a privilege-changing event entry occurred.
///
/// Every privilege-changing entry (TRAP, timer interrupt, future device
/// interrupts, etc.) pushes a protected EventFrame whose cause field
/// records why entry happened.  ERET consumes the frame regardless of
/// cause — the return-integrity mechanism is unified.
///
/// Formal basis: anka_interrupts.kleis FRAME-UNIFIED-1 through
/// FRAME-UNIFIED-5 prove that both causes use the identical
/// frame-entry law and common event-return law.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCause {
    /// Synchronous syscall entry via TRAP instruction.
    Syscall,
    /// Asynchronous timer interrupt delivered at instruction boundary.
    TimerInterrupt,
    /// Asynchronous device interrupt delivered at instruction boundary.
    ///
    /// Formal basis: anka_block_device.kleis IRQ-INDEP-1 through
    /// IRQ-INDEP-3 prove P_timer and P_dev are independent.
    DeviceInterrupt,
    // Future: InterprocessorInterrupt,
    //         ProtectionFault, IllegalInstruction, ...
    // Synchronous exceptions vs asynchronous interrupts differ in
    // entry semantics but share the same return-integrity mechanism.
}

/// Protected event frame — architecturally protected, not in ordinary memory.
///
/// Captures the exact interrupted control state.  ERET (or the host's
/// `event_return()` primitive) is the only consumer.  LD/ST/ALU cannot
/// read, write, or forge frames.
///
/// Corresponds to formal place F in the interrupt Petri net.
/// Formal invariants: CONS-2 (U+F=1), CONS-4 (F=M), INT-1 (H⇒F),
/// INT-4 (ERET consumes exactly one frame), INT-5 (¬F⇒ERET disabled).
#[derive(Debug, Clone)]
pub struct EventFrame {
    /// PC to resume at (instruction after TRAP, or next instruction
    /// after asynchronous delivery).
    pub return_pc: u64,
    /// Privilege level at the time of entry.
    pub return_privilege: Privilege,
    /// Whether interrupts were enabled before this entry.
    /// Stored rather than reconstructed, so the frame represents
    /// the complete interrupted control state (INT-8b).
    pub interrupts_were_enabled: bool,
    /// Why this frame was created.
    pub cause: EventCause,
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
    /// Byte span of the faulting transaction.
    pub length: u64,
    pub kind: AccessKind,
    pub pc: Option<u64>,
    pub reason: FaultReason,
}

// ───────────────────────────────────────────────────────────────────
// Generation-qualified requester identity (Phase 9.1a)
// ───────────────────────────────────────────────────────────────────

/// Architecturally neutral requester identity token.
///
/// The block controller stores and returns this opaquely; the kernel
/// interprets it (slot = process index, generation = incarnation).
/// The block layer does not know what "process" means.
///
/// Formal basis: anka_block_device.kleis GEN-REQ-1 through GEN-REQ-3.
/// Late completion cannot wake a recycled process because the
/// generation in the completion record no longer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequesterKey {
    pub slot: u32,
    pub generation: u32,
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

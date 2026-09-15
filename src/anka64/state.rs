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

/// A tagged capability entry — the capability plus its optional
/// protected identity.
///
/// Legacy grants (from existing `grant`/`derive`) have `authority_id: None`.
/// Phase 9.2+ grants via `grant_with_authority_id` have `Some(id)`.
/// `remove_by_authority_id` removes only the entry with the exact matching id.
#[derive(Debug, Clone)]
pub struct CapabilityEntry {
    pub cap: Capability64,
    pub authority_id: Option<AuthorityId>,
}

/// A protection domain — an authority container.
///
///   authorize(D, R) ⟺ ∃ C ∈ D : valid(C) ∧ C ⊢ R
///
/// Set semantics.  No ordering.  No hidden "current global domain."
/// Memory and device authorities are stored separately because they
/// carry structurally different rights (Permissions vs DeviceRights).
pub struct DomainState {
    pub id: DomainId,
    pub capabilities: Vec<CapabilityEntry>,
    pub device_authorities: Vec<DeviceAuthorityEntry>,
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
// Generation-qualified process identity (Phase 9.2b)
// ───────────────────────────────────────────────────────────────────

/// Neutral generation-qualified process identity.
///
/// Lives in state.rs rather than os.rs because it is needed by
/// DelegationId (state.rs), will travel into block-request metadata
/// (block.rs), and appears in the extended Message envelope.
/// RequesterKey is the device-layer analogue; ProcessKey is the
/// inter-process analogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub slot: usize,
    pub generation: u32,
}

impl fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProcessKey(slot={}, gen={})", self.slot, self.generation)
    }
}

// ───────────────────────────────────────────────────────────────────
// Delegation provenance (Phase 9.2b)
// ───────────────────────────────────────────────────────────────────

/// Structured provenance of a capability transfer event.
///
/// Created by SYS_SEND_CAP on successful atomic transfer.
/// The incarnation is monotonic (never reused).  The ProcessKeys
/// identify the exact transfer participants so 9.2e can query
/// `T.client` directly for DMA quiescence without a global lookup.
///
/// A fresh DelegationId is the identity of the immediate transfer
/// event: if A→B produces T1 and B→C produces T2, C carries T2.
///
/// Formal basis: anka_userspace_driver.kleis PROV-1..3, PERSIST-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DelegationId {
    pub client: ProcessKey,
    pub driver: ProcessKey,
    pub incarnation: u64,
}

impl fmt::Display for DelegationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DelegationId(client={}, driver={}, inc={})",
            self.client, self.driver, self.incarnation)
    }
}

// ───────────────────────────────────────────────────────────────────
// Device rights (Phase 9.2c)
//
// Structurally separate from Permissions.  Memory authority carries
// Permissions; device authority carries DeviceRights.  Illegal
// combinations (e.g. executable device, SubmitRead memory) are
// impossible by construction, not by runtime check.
// ───────────────────────────────────────────────────────────────────

/// Permission bitfield for device objects.
///
/// Separate from `Permissions` so that Memory authority and Device
/// authority carry disjoint right types — no SubmitRead on memory,
/// no R/W/X on devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceRights(pub u8);

impl DeviceRights {
    pub const NONE: Self = Self(0);
    pub const SUBMIT_READ: Self = Self(0x01);
    // 0x02 is deliberately undefined — preserved hostile witness.
    /// Authority to subscribe to device activity-epoch notifications.
    ///
    /// Independent of SUBMIT_READ: a process may wait for events
    /// without being able to submit I/O.  Formal basis:
    /// anka_user_device_events.kleis DEVEVENT-3, DEVEVENT-4.
    pub const EVENT_WAIT: Self = Self(0x04);
    /// Authority to copy a queued RX frame into guest memory (Phase 9.3e.3).
    pub const NIC_RX: Self = Self(0x08);
    /// Authority to transmit bytes read from guest memory (Phase 9.3e.3).
    pub const NIC_TX: Self = Self(0x10);

    /// Mask of all defined device right bits.
    ///
    /// "Defined encoding" means the bit pattern is a valid DeviceRights
    /// value at the decoder level.  It does NOT mean every defined right
    /// is valid for every device kind.  Kind-valid subsets:
    ///   Block: SUBMIT_READ | EVENT_WAIT = 0x05
    ///   NIC:   EVENT_WAIT | NIC_RX | NIC_TX = 0x1C
    ///
    /// Formal basis: anka93e3_nic_controller.kleis NIC93E3-24..29.
    pub const ALL_BITS: u64 = 0x1D;

    /// Kind-valid rights for Block devices.
    pub const BLOCK_ALLOWED: Self = Self(0x05);
    /// Kind-valid rights for NIC devices.
    pub const NIC_ALLOWED: Self = Self(0x1C);

    /// Checked decoder — rejects undefined bits.
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

impl fmt::Display for DeviceRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceRights(0x{:02X})", self.0)
    }
}

// ───────────────────────────────────────────────────────────────────
// Generation-qualified device binding (Phase 9.2c)
// ───────────────────────────────────────────────────────────────────

/// Generation-qualified device binding.
///
/// Prevents a revoked+recycled ObjectId from appearing bound to
/// the old controller.  The device equivalent of ProcessKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBinding {
    pub object: ObjectId,
    pub generation: Generation,
}

// ───────────────────────────────────────────────────────────────────
// Generic device request/completion primitives (Phase 9.3e)
//
// Controller-local request identity and finite-DMA transaction
// outcome.  Shared by all device controller types (Block, NIC, …).
// ───────────────────────────────────────────────────────────────────

/// Opaque handle identifying a specific request submission.
///
/// Controller-local: two controllers may independently issue
/// `(slot=0, gen=0)`.  Global uniqueness requires pairing with
/// a `DeviceBinding` (see `DeviceRequestKey` in `os.rs`).
///
/// Generation is u64 to match the formal model (anka_block_device.kleis
/// uses BitVec64 for request-slot generations).
///
/// Formal basis: anka_block_device.kleis GEN-1..GEN-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHandle {
    pub slot: u8,
    pub generation: u64,
}

/// Outcome of an accepted finite device/DMA transaction.
///
/// Semantically narrow: this covers only the transaction commit
/// result, not device-type-specific payload (block number, frame
/// length, etc.).  Device-specific information belongs in the
/// respective completion type (`BlockCompletion`, future
/// `NicCompletion`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCompletionStatus {
    /// DMA transaction committed — data is in guest buffer.
    Success,
    /// DMA transaction faulted — guest buffer unchanged.
    DmaFault(FaultReason),
}

// ───────────────────────────────────────────────────────────────────
// Device authority entry (Phase 9.2c)
// ───────────────────────────────────────────────────────────────────

/// A tagged device authority entry in a Fabric domain.
///
/// Analogous to `CapabilityEntry` for memory, but carries
/// `DeviceRights` instead of `Permissions` and has no offset/length
/// (device objects have identity without spatial extent).
#[derive(Debug, Clone)]
pub struct DeviceAuthorityEntry {
    pub object: ObjectId,
    pub generation: Generation,
    pub rights: DeviceRights,
    pub authority_id: AuthorityId,
}

// ───────────────────────────────────────────────────────────────────
// Capability handle architecture (Phase 9.2a)
//
// Three distinct lifetimes, proved orthogonal in
// anka_userspace_driver.kleis RESOLVE-1..5 and DROP-1..4:
//
//   handle_generation   cap-table slot incarnation (u32)
//   object_generation   Fabric object incarnation (Generation / u64)
//   AuthorityId         live authority entry in a Fabric domain
//
// resolve(H) succeeds iff all three conditions hold simultaneously.
// CAP_DROP invalidates the first two.  Object revocation invalidates
// the third independently.
// ───────────────────────────────────────────────────────────────────

/// Protected identity of a single authority entry in a Fabric domain.
///
/// Monotonic, never reused.  Created when authority is installed;
/// destroyed when CAP_DROP or domain destruction removes it.
/// Two capabilities with identical (object, offset, length, perms)
/// have different AuthorityIds if they were installed separately.
///
/// Formal basis: anka_userspace_driver.kleis DROP-2, DROP-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorityId(pub u64);

impl fmt::Display for AuthorityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorityId({})", self.0)
    }
}

/// Opaque generation-qualified handle into a per-process capability table.
///
/// Knowing the bits does not confer authority; the handle resolves
/// only in the holder's table.  Modeled after LifecycleHandle.
///
/// Formal basis: anka_userspace_driver.kleis CAPTAB-1..6, RESOLVE-1..5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityHandle {
    pub slot: u32,
    pub generation: u32,
}

impl fmt::Display for CapabilityHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapHandle(slot={}, gen={})", self.slot, self.generation)
    }
}

/// One slot in a per-process capability table.
///
/// `handle_generation` tracks slot reuse (like ProcessKey.generation).
/// Kind-sensitive sum type: Memory and Device slots carry different
/// right representations, making illegal combinations structurally
/// impossible (no SubmitRead on memory, no R/W/X on devices).
///
/// `authority_id` links to the exact entry in the Fabric domain — so
/// dropping one handle removes only its backing authority, even if
/// another handle names an equal-looking capability.
///
/// Formal basis: anka_userspace_driver.kleis CAPTAB, RESOLVE, DROP.
#[derive(Debug, Clone)]
pub enum CapabilitySlotState {
    /// Slot is free for reuse.  `handle_generation` still records the
    /// last incarnation so stale handles are permanently rejected.
    Free,
    /// Slot holds live memory authority.
    Memory {
        object: ObjectId,
        object_generation: Generation,
        offset: u64,
        length: u64,
        perms: Permissions,
        authority_id: AuthorityId,
        /// Transfer provenance.  None for boot/spawn-installed caps;
        /// Some for caps installed by SYS_SEND_CAP.  A fresh transfer
        /// always stamps a new DelegationId (not inherited from prior
        /// transfers in a chain).
        delegation_id: Option<DelegationId>,
    },
    /// Slot holds live device authority.
    Device {
        object: ObjectId,
        object_generation: Generation,
        rights: DeviceRights,
        authority_id: AuthorityId,
        delegation_id: Option<DelegationId>,
    },
}

#[derive(Debug, Clone)]
pub struct CapabilitySlot {
    pub handle_generation: u32,
    pub state: CapabilitySlotState,
}

/// Fixed-size per-process capability table.
///
/// Bounded: F + O = CAP_TABLE_SIZE at all times (CAPTAB-5).
/// Installation and drop are the only transitions (CAPTAB-6).
pub const CAP_TABLE_SIZE: usize = 16;

#[derive(Debug, Clone)]
pub struct CapabilityTable {
    slots: [CapabilitySlot; CAP_TABLE_SIZE],
}

/// Result of resolving a CapabilityHandle.
///
/// Kind-sensitive: Memory and Device carry different authority
/// representations.  All callers must pattern-match.
#[derive(Debug, Clone)]
pub enum ResolvedCapability {
    Memory {
        object: ObjectId,
        object_generation: Generation,
        offset: u64,
        length: u64,
        perms: Permissions,
        authority_id: AuthorityId,
        delegation_id: Option<DelegationId>,
    },
    Device {
        object: ObjectId,
        object_generation: Generation,
        rights: DeviceRights,
        authority_id: AuthorityId,
        delegation_id: Option<DelegationId>,
    },
}

impl ResolvedCapability {
    /// Extract the authority_id regardless of kind.
    pub fn authority_id(&self) -> AuthorityId {
        match self {
            ResolvedCapability::Memory { authority_id, .. } => *authority_id,
            ResolvedCapability::Device { authority_id, .. } => *authority_id,
        }
    }

    /// Extract the object regardless of kind.
    pub fn object(&self) -> ObjectId {
        match self {
            ResolvedCapability::Memory { object, .. } => *object,
            ResolvedCapability::Device { object, .. } => *object,
        }
    }

    /// Extract the object generation regardless of kind.
    pub fn object_generation(&self) -> Generation {
        match self {
            ResolvedCapability::Memory { object_generation, .. } => *object_generation,
            ResolvedCapability::Device { object_generation, .. } => *object_generation,
        }
    }

    /// Extract the delegation_id regardless of kind.
    pub fn delegation_id(&self) -> Option<DelegationId> {
        match self {
            ResolvedCapability::Memory { delegation_id, .. } => *delegation_id,
            ResolvedCapability::Device { delegation_id, .. } => *delegation_id,
        }
    }

    /// True if this is a Memory capability.
    pub fn is_memory(&self) -> bool {
        matches!(self, ResolvedCapability::Memory { .. })
    }

    /// True if this is a Device capability.
    pub fn is_device(&self) -> bool {
        matches!(self, ResolvedCapability::Device { .. })
    }

    /// Extract memory-specific fields.  Panics if Device.
    pub fn as_memory(&self) -> (u64, u64, Permissions) {
        match self {
            ResolvedCapability::Memory { offset, length, perms, .. } => (*offset, *length, *perms),
            ResolvedCapability::Device { .. } => panic!("as_memory called on Device capability"),
        }
    }

    /// Extract device-specific rights.  Panics if Memory.
    pub fn as_device_rights(&self) -> DeviceRights {
        match self {
            ResolvedCapability::Device { rights, .. } => *rights,
            ResolvedCapability::Memory { .. } => panic!("as_device_rights called on Memory capability"),
        }
    }
}

impl CapabilityTable {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| CapabilitySlot {
                handle_generation: 0,
                state: CapabilitySlotState::Free,
            }),
        }
    }

    /// Read-only access to slots — used by preflight checks that
    /// must inspect slot state without mutating the table.
    pub fn slots(&self) -> &[CapabilitySlot; CAP_TABLE_SIZE] {
        &self.slots
    }

    /// Mutable access to slots — used by tests to force boundary
    /// conditions (e.g. generation = u32::MAX).
    #[cfg(test)]
    pub fn slots_mut(&mut self) -> &mut [CapabilitySlot; CAP_TABLE_SIZE] {
        &mut self.slots
    }

    /// Install a new memory capability.  Returns the handle on success,
    /// or None if the table is full.
    pub fn install_memory(
        &mut self,
        object: ObjectId,
        object_generation: Generation,
        offset: u64,
        length: u64,
        perms: Permissions,
        authority_id: AuthorityId,
        delegation_id: Option<DelegationId>,
    ) -> Option<CapabilityHandle> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if matches!(slot.state, CapabilitySlotState::Free)
                && slot.handle_generation != u32::MAX
            {
                slot.state = CapabilitySlotState::Memory {
                    object,
                    object_generation,
                    offset,
                    length,
                    perms,
                    authority_id,
                    delegation_id,
                };
                return Some(CapabilityHandle {
                    slot: i as u32,
                    generation: slot.handle_generation,
                });
            }
        }
        None
    }

    /// Install a new device capability.  Returns the handle on success,
    /// or None if the table is full.
    pub fn install_device(
        &mut self,
        object: ObjectId,
        object_generation: Generation,
        rights: DeviceRights,
        authority_id: AuthorityId,
        delegation_id: Option<DelegationId>,
    ) -> Option<CapabilityHandle> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if matches!(slot.state, CapabilitySlotState::Free)
                && slot.handle_generation != u32::MAX
            {
                slot.state = CapabilitySlotState::Device {
                    object,
                    object_generation,
                    rights,
                    authority_id,
                    delegation_id,
                };
                return Some(CapabilityHandle {
                    slot: i as u32,
                    generation: slot.handle_generation,
                });
            }
        }
        None
    }

    /// Three-condition resolution.
    ///
    /// Succeeds iff:
    ///   1. handle_generation matches slot
    ///   2. Slot is occupied (Memory or Device — not Free)
    ///   3. object_generation matches current Fabric generation
    ///
    /// The caller must supply the current Fabric object generation
    /// for condition 3.  Returns a kind-sensitive ResolvedCapability.
    pub fn resolve(
        &self,
        handle: CapabilityHandle,
        current_object_gen: impl Fn(ObjectId) -> Option<Generation>,
    ) -> Option<ResolvedCapability> {
        let slot = self.slots.get(handle.slot as usize)?;

        // Condition 1: handle generation matches slot
        if slot.handle_generation != handle.generation {
            return None;
        }

        // Condition 2: slot is occupied (Memory or Device)
        let resolved = match &slot.state {
            CapabilitySlotState::Memory {
                object, object_generation, offset, length, perms,
                authority_id, delegation_id,
            } => ResolvedCapability::Memory {
                object: *object,
                object_generation: *object_generation,
                offset: *offset,
                length: *length,
                perms: *perms,
                authority_id: *authority_id,
                delegation_id: *delegation_id,
            },
            CapabilitySlotState::Device {
                object, object_generation, rights,
                authority_id, delegation_id,
            } => ResolvedCapability::Device {
                object: *object,
                object_generation: *object_generation,
                rights: *rights,
                authority_id: *authority_id,
                delegation_id: *delegation_id,
            },
            CapabilitySlotState::Free => return None,
        };

        // Condition 3: object generation is current
        let obj_id = resolved.object();
        let stored_gen = resolved.object_generation();
        let current_gen = current_object_gen(obj_id)?;
        if stored_gen != current_gen {
            return None;
        }

        Some(resolved)
    }

    /// Drop a capability handle: invalidate the naming, remove
    /// the linked authority.  Returns the AuthorityId that was
    /// removed (so the caller can remove it from the Fabric domain).
    ///
    /// Fails if the slot generation is `u32::MAX` — advancing it
    /// would wrap to 0, making an ancient stale handle current again.
    /// The Kleis model requires `recyclable(g) ≡ g ≠ 2^32 − 1`.
    ///
    /// Formal: DROP-1, DROP-2.
    pub fn drop_handle(&mut self, handle: CapabilityHandle) -> Option<AuthorityId> {
        let slot = self.slots.get_mut(handle.slot as usize)?;

        if slot.handle_generation != handle.generation {
            return None;
        }

        let auth_id = match &slot.state {
            CapabilitySlotState::Memory { authority_id, .. } => *authority_id,
            CapabilitySlotState::Device { authority_id, .. } => *authority_id,
            CapabilitySlotState::Free => return None,
        };

        // Checked: refuse if advancing the generation would wrap.
        let next_gen = slot.handle_generation.checked_add(1)?;

        slot.state = CapabilitySlotState::Free;
        slot.handle_generation = next_gen;

        Some(auth_id)
    }

    /// Read-only preflight for drop: checks handle generation,
    /// occupancy, AND recyclability (generation can advance).
    ///
    /// Returns the AuthorityId if all conditions hold, without
    /// mutating the table.  The kernel uses this to verify
    /// everything before committing the two-sided removal.
    ///
    /// Three conditions checked:
    ///   1. handle generation matches slot
    ///   2. slot is Occupied (has an AuthorityId)
    ///   3. generation is recyclable (g_h ≠ u32::MAX)
    pub fn preflight_drop(&self, handle: CapabilityHandle) -> Option<AuthorityId> {
        let slot = self.slots.get(handle.slot as usize)?;

        if slot.handle_generation != handle.generation {
            return None;
        }

        let auth_id = match &slot.state {
            CapabilitySlotState::Memory { authority_id, .. } => *authority_id,
            CapabilitySlotState::Device { authority_id, .. } => *authority_id,
            CapabilitySlotState::Free => return None,
        };

        // Recyclability: generation must be able to advance.
        slot.handle_generation.checked_add(1)?;

        Some(auth_id)
    }

    /// Number of free slots.
    /// Structural free count: all unoccupied slots, including
    /// retired ones at terminal generation.  F_structural + O = N.
    pub fn free_count(&self) -> usize {
        self.slots.iter()
            .filter(|s| matches!(s.state, CapabilitySlotState::Free))
            .count()
    }

    /// Allocatable free count: unoccupied AND generation < u32::MAX.
    /// These are the slots that install() will actually use.
    /// Used by install_capability() preflight to avoid burning
    /// AuthorityIds on doomed installation attempts.
    pub fn allocatable_count(&self) -> usize {
        self.slots.iter()
            .filter(|s| matches!(s.state, CapabilitySlotState::Free)
                && s.handle_generation != u32::MAX)
            .count()
    }

    /// Number of occupied slots.
    pub fn occupied_count(&self) -> usize {
        CAP_TABLE_SIZE - self.free_count()
    }
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

// ───────────────────────────────────────────────────────────────────
// Tests — capability table (Phase 9.2a)
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod cap_table_tests {
    use super::*;

    fn obj(n: u64) -> ObjectId { ObjectId(n) }
    fn g(n: u64) -> Generation { Generation(n) }
    fn aid(n: u64) -> AuthorityId { AuthorityId(n) }

    /// Stub generation lookup: returns the generation stored in the map.
    fn gen_lookup(map: &[(ObjectId, Generation)]) -> impl Fn(ObjectId) -> Option<Generation> + '_ {
        move |oid| map.iter().find(|(o, _)| *o == oid).map(|(_, g)| *g)
    }

    // ─── CAPTAB-5: F + O = N at all times ───

    #[test]
    fn captab_invariant_fo_eq_n() {
        let mut ct = CapabilityTable::new();
        assert_eq!(ct.free_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 0);

        let h = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(0), None)
            .expect("install should succeed");
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 1);

        ct.drop_handle(h).expect("drop should succeed");
        assert_eq!(ct.free_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 0);
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);
    }

    // ─── CAPTAB-6: table exhaustion ───

    #[test]
    fn captab_exhaustion() {
        let mut ct = CapabilityTable::new();
        let mut handles = Vec::new();
        for i in 0..CAP_TABLE_SIZE {
            let h = ct.install_memory(obj(i as u64), g(0), 0, 4096, Permissions::READ, aid(i as u64), None)
                .expect("install should succeed");
            handles.push(h);
        }
        assert_eq!(ct.free_count(), 0);

        // 17th install must fail
        assert!(ct.install_memory(obj(99), g(0), 0, 4096, Permissions::READ, aid(99), None).is_none());

        // Drop one, try again
        ct.drop_handle(handles[0]).expect("drop should succeed");
        assert_eq!(ct.free_count(), 1);
        assert!(ct.install_memory(obj(99), g(0), 0, 4096, Permissions::READ, aid(99), None).is_some());
    }

    // ─── RESOLVE-1: handle generation mismatch fails ───

    #[test]
    fn resolve_stale_handle_generation() {
        let mut ct = CapabilityTable::new();
        let gens = [(obj(1), g(0))];

        let h = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(0), None)
            .expect("install should succeed");

        // Valid resolution
        assert!(ct.resolve(h, gen_lookup(&gens)).is_some());

        // Drop and reinstall — old handle must fail
        ct.drop_handle(h).expect("drop should succeed");
        let h2 = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(1), None)
            .expect("reinstall should succeed");

        // Old handle: stale generation
        assert!(ct.resolve(h, gen_lookup(&gens)).is_none(),
            "stale handle must not resolve after drop+reinstall");

        // New handle: valid
        assert!(ct.resolve(h2, gen_lookup(&gens)).is_some());

        // Verify different generations
        assert_ne!(h.generation, h2.generation);
    }

    // ─── RESOLVE-3: object generation revocation ───

    #[test]
    fn resolve_object_generation_revoked() {
        let mut ct = CapabilityTable::new();
        let h = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(0), None)
            .expect("install should succeed");

        // Object at g(0) → resolves
        let gens_ok = [(obj(1), g(0))];
        assert!(ct.resolve(h, gen_lookup(&gens_ok)).is_some());

        // Object revoked → g(1) → handle fails condition 3
        let gens_revoked = [(obj(1), g(1))];
        assert!(ct.resolve(h, gen_lookup(&gens_revoked)).is_none(),
            "handle to revoked object must not resolve");
    }

    // ─── RESOLVE: object not found ───

    #[test]
    fn resolve_object_not_found() {
        let mut ct = CapabilityTable::new();
        let h = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(0), None)
            .expect("install should succeed");

        // Object doesn't exist in lookup
        let empty: [(ObjectId, Generation); 0] = [];
        assert!(ct.resolve(h, gen_lookup(&empty)).is_none(),
            "handle to nonexistent object must not resolve");
    }

    // ─── DROP-1: drop invalidates handle permanently ───

    #[test]
    fn drop_invalidates_permanently() {
        let mut ct = CapabilityTable::new();
        let h = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(0), None)
            .expect("install should succeed");

        ct.drop_handle(h).expect("drop should succeed");

        // Second drop with same handle must fail
        assert!(ct.drop_handle(h).is_none(),
            "double-drop must fail");

        let gens = [(obj(1), g(0))];
        assert!(ct.resolve(h, gen_lookup(&gens)).is_none(),
            "dropped handle must not resolve");
    }

    // ─── DROP-2, DROP-3: equal-looking capabilities, distinct AuthorityIds ───

    #[test]
    fn drop_removes_only_linked_authority() {
        let mut ct = CapabilityTable::new();

        // Two handles to the same object/range/perms but different AuthorityIds
        let h1 = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(100), None)
            .expect("install h1");
        let h2 = ct.install_memory(obj(1), g(0), 0, 4096, Permissions::READ, aid(200), None)
            .expect("install h2");

        // Drop h1: returns aid(100), NOT aid(200)
        let removed = ct.drop_handle(h1).expect("drop h1 should succeed");
        assert_eq!(removed, AuthorityId(100),
            "drop(H1) must remove A1, not A2");

        // h2 still resolves
        let gens = [(obj(1), g(0))];
        assert!(ct.resolve(h2, gen_lookup(&gens)).is_some(),
            "H2 must survive drop(H1) even though A1 == A2 by value");
    }

    // ─── Slot reuse increments generation ───

    #[test]
    fn slot_reuse_increments_generation() {
        let mut ct = CapabilityTable::new();

        // Fill all slots, then drop slot 0, install a new one
        let h0 = ct.install_memory(obj(0), g(0), 0, 4096, Permissions::READ, aid(0), None)
            .expect("install");
        assert_eq!(h0.slot, 0);
        assert_eq!(h0.generation, 0);

        ct.drop_handle(h0).expect("drop");

        let h0_next = ct.install_memory(obj(0), g(0), 0, 4096, Permissions::READ, aid(1), None)
            .expect("reinstall");
        assert_eq!(h0_next.slot, 0);
        assert_eq!(h0_next.generation, 1,
            "slot reuse must increment handle generation");
    }

    // ─── F+O=N through install/drop/reinstall cycles ───

    #[test]
    fn fo_conservation_through_cycles() {
        let mut ct = CapabilityTable::new();
        let mut handles = Vec::new();

        // Install 8 caps
        for i in 0..8u64 {
            handles.push(
                ct.install_memory(obj(i), g(0), 0, 4096, Permissions::READ, aid(i), None)
                    .expect("install")
            );
        }
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);

        // Drop every other one
        for i in (0..8).step_by(2) {
            ct.drop_handle(handles[i]).expect("drop");
        }
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 4);

        // Reinstall in freed slots
        for i in (0..8).step_by(2) {
            ct.install_memory(obj(100 + i as u64), g(0), 0, 4096, Permissions::RW, aid(100 + i as u64), None)
                .expect("reinstall");
        }
        assert_eq!(ct.free_count() + ct.occupied_count(), CAP_TABLE_SIZE);
        assert_eq!(ct.occupied_count(), 8);
    }

    // ─── Out-of-bounds slot index ───

    #[test]
    fn resolve_out_of_bounds_slot() {
        let ct = CapabilityTable::new();
        let bad_handle = CapabilityHandle { slot: CAP_TABLE_SIZE as u32, generation: 0 };
        let gens = [(obj(1), g(0))];
        assert!(ct.resolve(bad_handle, gen_lookup(&gens)).is_none(),
            "out-of-bounds slot must return None");
    }

    #[test]
    fn drop_out_of_bounds_slot() {
        let mut ct = CapabilityTable::new();
        let bad_handle = CapabilityHandle { slot: CAP_TABLE_SIZE as u32, generation: 0 };
        assert!(ct.drop_handle(bad_handle).is_none(),
            "out-of-bounds drop must return None");
    }

    // ─── Resolve on free slot fails ───

    #[test]
    fn resolve_free_slot_fails() {
        let ct = CapabilityTable::new();
        let handle = CapabilityHandle { slot: 0, generation: 0 };
        let gens = [(obj(1), g(0))];
        assert!(ct.resolve(handle, gen_lookup(&gens)).is_none(),
            "handle to free slot must not resolve");
    }
}

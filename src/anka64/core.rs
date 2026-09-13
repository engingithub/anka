//! Anka64 CPU core — execution engine.
//!
//! instruction decode → architectural operation → MemoryRequest/Fabric
//!
//! The core NEVER pokes RAM directly.  Every memory effect travels
//! through the Phase-1 fabric.
//!
//! Execution is table-driven: the decoder produces a DecodedInsn
//! carrying a reference to the description table; the executor
//! dispatches on the semantic tag, not a hand-written match of
//! each opcode.

use super::desc::{Sem, AluOp, FlagEffect as DescFlagEffect};
use super::fabric::Fabric;
use super::isa::*;
use super::state::*;

// ───────────────────────────────────────────────────────────────────
// Address map: virtual address → (ObjectId, offset)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AddressMapEntry {
    pub virt_base: u64,
    pub size: u64,
    pub object: ObjectId,
    pub obj_offset: u64,
}

#[derive(Debug, Clone)]
pub struct AddressMap {
    entries: Vec<AddressMapEntry>,
}

impl AddressMap {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn add(&mut self, virt_base: u64, size: u64, object: ObjectId) {
        self.entries.push(AddressMapEntry { virt_base, size, object, obj_offset: 0 });
    }

    /// Map a virtual range to a non-zero offset within an object.
    /// Used when the mapped region does not start at the beginning
    /// of the object (e.g., literal segment within a sealed image).
    pub fn add_at(&mut self, virt_base: u64, size: u64, object: ObjectId, obj_offset: u64) {
        self.entries.push(AddressMapEntry { virt_base, size, object, obj_offset });
    }

    pub fn resolve(&self, addr: u64) -> Option<(ObjectId, u64)> {
        for e in &self.entries {
            if addr >= e.virt_base && addr < e.virt_base + e.size {
                return Some((e.object, e.obj_offset + (addr - e.virt_base)));
            }
        }
        None
    }

    /// Resolve a virtual range [vaddr, vaddr+size) and prove that
    /// the entire range falls within exactly one AddressMapEntry.
    ///
    /// Returns (ObjectId, base_obj_offset) on success.
    /// Unlike resolving two endpoints and comparing, this checks
    /// structural containment: it finds the unique entry whose
    /// [virt_base, virt_base+size) contains the requested range.
    /// Adjacent entries mapping contiguous portions of the same
    /// object cannot be stitched together.
    pub fn resolve_range_single_entry(
        &self, vaddr: u64, size: u64,
    ) -> Option<(ObjectId, u64)> {
        if size == 0 {
            return None;
        }
        let last = vaddr.checked_add(size - 1)?;
        for e in &self.entries {
            let entry_end = e.virt_base.checked_add(e.size)?;
            if vaddr >= e.virt_base && last < entry_end {
                let obj_offset = e.obj_offset + (vaddr - e.virt_base);
                return Some((e.object, obj_offset));
            }
        }
        None
    }
}

// ───────────────────────────────────────────────────────────────────
// Flags
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {

    pub z: bool,
    pub n: bool,
    pub c: bool,
    pub v: bool,
}

impl Flags {
    pub fn test(&self, cond: Cond) -> bool {
        match cond {
            Cond::Eq  => self.z,
            Cond::Ne  => !self.z,
            Cond::Lt  => self.n != self.v,
            Cond::Ge  => self.n == self.v,
            Cond::Le  => self.z || (self.n != self.v),
            Cond::Gt  => !self.z && (self.n == self.v),
            Cond::Ult => !self.c,
            Cond::Uge => self.c,
            Cond::Ule => !self.c || self.z,
            Cond::Ugt => self.c && !self.z,
            Cond::Al  => true,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Step result
// ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StepResult {
    Continue,
    Halted,
    Fault(FaultRecord),
}

// ───────────────────────────────────────────────────────────────────
// Multi-source pending interrupt state (Phase 9.1a)
// ───────────────────────────────────────────────────────────────────

/// Per-source pending interrupt bits.
///
/// Each asynchronous source has independent Boolean pending truth.
/// Posting one source does not alter the other.  Both may be
/// simultaneously true — the arbiter resolves ties.
///
/// Formal basis: anka_block_device.kleis IRQ-INDEP-1 through
/// IRQ-INDEP-3.  Phase 9.0's `Option<EventCause>` could not
/// represent `(P_timer=1, P_dev=1)`.
#[derive(Debug, Clone)]
pub struct PendingSet {
    pub timer: bool,
    pub device: bool,
}

impl PendingSet {
    pub fn new() -> Self {
        Self { timer: false, device: false }
    }

    /// True if any source is pending.
    pub fn any_pending(&self) -> bool {
        self.timer || self.device
    }
}

/// Interrupt arbiter turn state.
///
/// When both `P_timer` and `P_dev` are true, the arbiter selects
/// the source matching the current turn, then flips.  A lone
/// pending source is always selected regardless of turn.
///
/// Formal basis: anka_block_device.kleis ARB-7/ARB-8 prove
/// bounded service: both sources served within two eligible
/// delivery opportunities from either initial turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptTurn {
    Timer,
    Device,
}

// ───────────────────────────────────────────────────────────────────
// Core
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Anka64Core {
    pub r: [u64; 16],
    pub pc: u64,
    pub flags: Flags,
    pub agent: AgentId,
    pub domain: DomainId,
    pub privilege: Privilege,
    pub address_map: AddressMap,
    pub halted: bool,

    pub trap_vector: u64,

    /// Protected event-frame stack (Phase 9.0).
    ///
    /// Not in ordinary memory.  Not accessible through capabilities.
    /// TRAP and interrupt delivery are the only producers;
    /// `event_return()` (used by ERET and resume_from_trap) is the
    /// only consumer.
    ///
    /// Replaces the old single-slot saved_pc / saved_privilege.
    /// A stack rather than a single slot prevents baking the
    /// no-nesting assumption into the architecture.
    ///
    /// Formal basis: place F in anka_interrupts.kleis.
    /// CONS-2: U+F=1.  CONS-4: F=M.
    pub event_frames: Vec<EventFrame>,

    /// Whether asynchronous interrupt delivery is enabled.
    ///
    /// TRAP and interrupt delivery set this to false (mask).
    /// event_return() restores the prior value from the EventFrame.
    ///
    /// Formal basis: place M in anka_interrupts.kleis (inverted sense:
    /// M=1 means masked, interrupts_enabled=false).
    pub interrupts_enabled: bool,

    /// Per-source pending interrupt state (Phase 9.1a).
    ///
    /// Replaces `Option<EventCause>` from Phase 9.0.  Each source
    /// has independent Boolean pending truth (coalescing per source).
    ///
    /// Formal basis: anka_block_device.kleis IRQ-INDEP-1 through
    /// IRQ-INDEP-3 prove P_timer and P_dev are independent.
    pub pending: PendingSet,

    /// Interrupt arbitration state (Phase 9.1a).
    ///
    /// When both sources are simultaneously pending, the arbiter
    /// uses this turn bit to select which is served first.
    /// Serving one source flips the turn to the other.
    ///
    /// Formal basis: anka_block_device.kleis ARB-7 and ARB-8
    /// prove bounded service within two eligible opportunities.
    pub interrupt_turn: InterruptTurn,

    /// Protected return-authority stack (6S.2 + 6S.2a).
    ///
    /// Not in ordinary memory.  Not accessible through capabilities.
    /// CALL is the only mint; RET is the only consumer.
    /// LD/ST/ALU cannot read, write, or forge entries.
    ///
    /// Fault atomicity: failed RET does not pop (peek → validate → pop).
    /// CALL atomicity: mint-or-fault (no partial state change).
    ///
    /// Architecturally belongs to the execution context, not the
    /// physical core.  See `ReturnAuthority` doc for future plans.
    pub return_stack: Vec<ReturnAuthority>,
}

impl Anka64Core {
    pub fn new(agent: AgentId, domain: DomainId) -> Self {
        Self {
            r: [0; 16],
            pc: 0,
            flags: Flags::default(),
            agent,
            domain,
            privilege: Privilege::User,
            address_map: AddressMap::new(),
            halted: false,
            trap_vector: 0,
            event_frames: Vec::new(),
            interrupts_enabled: true,
            pending: PendingSet::new(),
            interrupt_turn: InterruptTurn::Timer,
            return_stack: Vec::new(),
        }
    }

    /// Unified event return: validates and consumes one protected EventFrame.
    ///
    /// Used by both `Sem::Eret` (ISA instruction) and `resume_from_trap`
    /// (host-mediated syscall return).  This is the single implementation
    /// primitive corresponding to formal transition T_eret in
    /// anka_interrupts.kleis:  R + F + M → U.
    ///
    /// Returns Some(return_pc) on success, None if the event-frame stack
    /// is empty (INT-5: ¬F ⇒ ERET cannot fire).
    pub fn event_return(&mut self) -> Option<u64> {
        let frame = self.event_frames.pop()?;
        self.privilege = frame.return_privilege;
        self.interrupts_enabled = frame.interrupts_were_enabled;
        Some(frame.return_pc)
    }

    // ───────────── Posting (Phase 9.1a) ──────────────────────────

    /// Post a timer interrupt.  Does not alter P_dev.
    ///
    /// Formal basis: anka_block_device.kleis IRQ-INDEP-1.
    pub fn post_timer_interrupt(&mut self) {
        self.pending.timer = true;
    }

    /// Post a device interrupt.  Does not alter P_timer.
    ///
    /// Formal basis: anka_block_device.kleis IRQ-INDEP-2.
    pub fn post_device_interrupt(&mut self) {
        self.pending.device = true;
    }

    // ───────────── Delivery with arbitration (Phase 9.1a) ───────

    /// Multi-source interrupt delivery gate.
    ///
    /// If any source is pending and interrupts are enabled:
    ///   - Arbiter selects one source (turn-based if both pending).
    ///   - Consumes only the chosen source's pending bit.
    ///   - Preserves the other source's pending bit.
    ///   - Pushes exactly one protected EventFrame.
    ///   - Enters Supervisor, masks, redirects to trap_vector.
    ///   - Flips the turn after serving a tied request.
    ///
    /// Returns true if delivery occurred, false otherwise.
    ///
    /// Formal basis: anka_block_device.kleis
    ///   ARB-1..ARB-11: turn-based arbitration with bounded service.
    ///   IRQ-MASK-1: masked pending is not deliverable.
    ///   IRQ-MASK-2: masking preserves latched pending truth.
    pub fn deliver_pending(&mut self) -> bool {
        if !self.interrupts_enabled {
            // IRQ-MASK-1/2: masked — preserve all pending bits, no delivery.
            return false;
        }

        // Select which source to deliver (if any).
        let cause = match (self.pending.timer, self.pending.device) {
            (false, false) => return false,
            (true, false) => {
                // ARB-9: lone timer, always selected.
                self.pending.timer = false;
                EventCause::TimerInterrupt
            }
            (false, true) => {
                // ARB-10: lone device, always selected.
                self.pending.device = false;
                EventCause::DeviceInterrupt
            }
            (true, true) => {
                // ARB-1..ARB-8: both pending, use turn.
                match self.interrupt_turn {
                    InterruptTurn::Timer => {
                        self.pending.timer = false;
                        self.interrupt_turn = InterruptTurn::Device;
                        EventCause::TimerInterrupt
                    }
                    InterruptTurn::Device => {
                        self.pending.device = false;
                        self.interrupt_turn = InterruptTurn::Timer;
                        EventCause::DeviceInterrupt
                    }
                }
            }
        };

        self.event_frames.push(EventFrame {
            return_pc: self.pc,
            return_privilege: self.privilege,
            interrupts_were_enabled: self.interrupts_enabled,
            cause,
        });
        self.privilege = Privilege::Supervisor;
        self.interrupts_enabled = false;
        self.pc = self.trap_vector;
        true
    }

    /// Execute one instruction cycle through the fabric.
    ///
    /// Dispatch is on the semantic tag from the description table,
    /// not a hand-written match of each opcode.
    pub fn step(&mut self, fabric: &mut Fabric) -> StepResult {
        if self.halted { return StepResult::Halted; }

        // 0. PC alignment — 32-bit fixed-width ISA.
        // Without this, attacker-controlled LR can point to byte offsets
        // inside existing instructions, creating overlapping instruction
        // streams that bypass code sealing.
        if self.pc & 3 != 0 {
            return StepResult::Fault(FaultRecord {
                agent: self.agent,
                domain: self.domain,
                privilege: self.privilege,
                transaction: TransactionId(0),
                object: ObjectId(0),
                generation: None,
                offset: self.pc,
                width: Width::Word,
                length: Width::Word.bytes(),
                kind: AccessKind::Fetch,
                pc: Some(self.pc),
                reason: FaultReason::AlignmentFault,
            });
        }

        // 1. Fetch (through fabric)
        let word = match self.fabric_read(fabric, self.pc, Width::Word, AccessKind::Fetch) {
            Ok(bytes) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Err(fault) => return StepResult::Fault(fault),
        };

        // 2. Decode (table-driven)
        let insn = decode(word);

        if insn.is_illegal() {
            return StepResult::Fault(FaultRecord {
                agent: self.agent,
                domain: self.domain,
                privilege: self.privilege,
                transaction: TransactionId(0),
                object: ObjectId(0),
                generation: None,
                offset: self.pc,
                width: Width::Word,
                length: Width::Word.bytes(),
                kind: AccessKind::Fetch,
                pc: Some(self.pc),
                reason: FaultReason::IllegalInstruction,
            });
        }

        // 3. Execute (semantic dispatch)
        let mut next_pc = self.pc + 4;

        match insn.desc.semantics {
            // ─── ALU: register-register or register-immediate ───
            Sem::Alu(alu_op) => {
                let a = self.r[insn.rs1 as usize];
                let b = self.alu_operand_b(&insn);
                let result = Self::alu_eval(alu_op, a, b);
                self.r[insn.rd as usize] = result;
                self.update_flags(insn.desc.flags, a, b, result);
            }

            // ─── Compare (ALU subtract, flags only) ─────────────
            Sem::Cmp => {
                let a = self.r[insn.rs1 as usize];
                let b = self.cmp_operand_b(&insn);
                let result = a.wrapping_sub(b);
                self.update_flags(insn.desc.flags, a, b, result);
            }

            // ─── Move / Load immediate ──────────────────────────
            Sem::Mov  => { self.r[insn.rd as usize] = self.r[insn.rs1 as usize]; }
            Sem::Movi => { self.r[insn.rd as usize] = insn.imm as u64; }

            // ─── Memory (one transaction per instruction) ───────
            Sem::Load => {
                let addr = self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64);
                match self.fabric_read(fabric, addr, Width::Double, AccessKind::Read) {
                    Ok(bytes) => {
                        self.r[insn.rd as usize] = u64::from_le_bytes(
                            [bytes[0], bytes[1], bytes[2], bytes[3],
                             bytes[4], bytes[5], bytes[6], bytes[7]]);
                    }
                    Err(fault) => return StepResult::Fault(fault),
                }
            }
            Sem::Store => {
                let addr = self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64);
                let data = self.r[insn.rd as usize].to_le_bytes().to_vec();
                match self.fabric_write(fabric, addr, Width::Double, data) {
                    Ok(()) => {}
                    Err(fault) => return StepResult::Fault(fault),
                }
            }
            Sem::Lea => {
                self.r[insn.rd as usize] =
                    self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64);
            }
            Sem::Xchg => {
                let addr = self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64);
                let new_val = self.r[insn.rd as usize].to_le_bytes().to_vec();
                match self.fabric_atomic_xchg(fabric, addr, Width::Double, new_val) {
                    Ok(old_bytes) => {
                        self.r[insn.rd as usize] = u64::from_le_bytes(
                            [old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3],
                             old_bytes[4], old_bytes[5], old_bytes[6], old_bytes[7]]);
                    }
                    Err(fault) => return StepResult::Fault(fault),
                }
            }

            // ─── Control flow ───────────────────────────────────
            Sem::Branch => {
                if self.flags.test(insn.cond) {
                    next_pc = (self.pc as i64 + insn.imm * 4) as u64;
                }
            }
            Sem::Call => {
                // Mint-or-fault: CALL either mints authority and transfers,
                // or faults without changing any state.
                let return_addr = self.pc + 4;
                let (code_obj, _offset) = match self.address_map.resolve(self.pc) {
                    Some(r) => r,
                    None => {
                        return StepResult::Fault(FaultRecord {
                            agent: self.agent,
                            domain: self.domain,
                            privilege: self.privilege,
                            transaction: TransactionId(0),
                            object: ObjectId(0),
                            generation: None,
                            offset: self.pc,
                            width: Width::Word,
                            length: Width::Word.bytes(),
                            kind: AccessKind::Fetch,
                            pc: Some(self.pc),
                            reason: FaultReason::ControlFlowViolation,
                        });
                    }
                };
                let obj_gen = match fabric.objects.get(&code_obj) {
                    Some(obj) => obj.generation,
                    None => {
                        return StepResult::Fault(FaultRecord {
                            agent: self.agent,
                            domain: self.domain,
                            privilege: self.privilege,
                            transaction: TransactionId(0),
                            object: code_obj,
                            generation: None,
                            offset: self.pc,
                            width: Width::Word,
                            length: Width::Word.bytes(),
                            kind: AccessKind::Fetch,
                            pc: Some(self.pc),
                            reason: FaultReason::ControlFlowViolation,
                        });
                    }
                };
                // All resolved — commit atomically:
                self.r[LR as usize] = return_addr;
                self.return_stack.push(ReturnAuthority {
                    code_object: code_obj,
                    generation: obj_gen,
                    target: return_addr,
                });
                next_pc = (self.pc as i64 + insn.imm * 4) as u64;
            }
            Sem::Ret => {
                // Peek → validate → pop only on success.
                // Failed RET leaves R unchanged (fault atomicity, N8 analogue).
                let lr_val = self.r[LR as usize];
                let ret_auth = match self.return_stack.last() {
                    None => {
                        return StepResult::Fault(FaultRecord {
                            agent: self.agent,
                            domain: self.domain,
                            privilege: self.privilege,
                            transaction: TransactionId(0),
                            object: ObjectId(0),
                            generation: None,
                            offset: lr_val,
                            width: Width::Word,
                            length: Width::Word.bytes(),
                            kind: AccessKind::Fetch,
                            pc: Some(self.pc),
                            reason: FaultReason::ControlFlowViolation,
                        });
                    }
                    Some(auth) => auth.clone(),
                };
                // Check 1: LR matches the minted return target
                if lr_val != ret_auth.target {
                    return StepResult::Fault(FaultRecord {
                        agent: self.agent,
                        domain: self.domain,
                        privilege: self.privilege,
                        transaction: TransactionId(0),
                        object: ret_auth.code_object,
                        generation: Some(ret_auth.generation),
                        offset: lr_val,
                        width: Width::Word,
                        length: Width::Word.bytes(),
                        kind: AccessKind::Fetch,
                        pc: Some(self.pc),
                        reason: FaultReason::ControlFlowViolation,
                    });
                }
                // Check 2: code object generation still valid
                match fabric.objects.get(&ret_auth.code_object) {
                    Some(obj) if obj.generation == ret_auth.generation => {}
                    _ => {
                        return StepResult::Fault(FaultRecord {
                            agent: self.agent,
                            domain: self.domain,
                            privilege: self.privilege,
                            transaction: TransactionId(0),
                            object: ret_auth.code_object,
                            generation: Some(ret_auth.generation),
                            offset: lr_val,
                            width: Width::Word,
                            length: Width::Word.bytes(),
                            kind: AccessKind::Fetch,
                            pc: Some(self.pc),
                            reason: FaultReason::ControlFlowViolation,
                        });
                    }
                }
                // All checks pass — NOW pop (fault atomicity)
                self.return_stack.pop();
                next_pc = ret_auth.target;
            }

            // ─── System ─────────────────────────────────────────
            Sem::Trap => {
                // Formal T_deliver (syscall variant): push EventFrame,
                // enter Supervisor, mask interrupts, jump to trap_vector.
                self.event_frames.push(EventFrame {
                    return_pc: self.pc + 4,
                    return_privilege: self.privilege,
                    interrupts_were_enabled: self.interrupts_enabled,
                    cause: EventCause::Syscall,
                });
                self.privilege = Privilege::Supervisor;
                self.interrupts_enabled = false;
                next_pc = self.trap_vector;
            }
            Sem::Eret => {
                // Formal T_eret: consume one protected EventFrame.
                // Unified with event_return() — one semantic primitive.
                match self.event_return() {
                    Some(pc) => { next_pc = pc; }
                    None => {
                        // INT-5: no EventFrame means ERET faults.
                        return StepResult::Fault(FaultRecord {
                            agent: self.agent,
                            domain: self.domain,
                            privilege: self.privilege,
                            transaction: TransactionId(0),
                            object: ObjectId(0),
                            generation: None,
                            offset: self.pc,
                            width: Width::Word,
                            length: Width::Word.bytes(),
                            kind: AccessKind::Fetch,
                            pc: Some(self.pc),
                            reason: FaultReason::ControlFlowViolation,
                        });
                    }
                }
            }
            Sem::Nop  => {}
            Sem::Halt => {
                self.halted = true;
                return StepResult::Halted;
            }
        }

        self.pc = next_pc;
        StepResult::Continue
    }

    // ───────────── ALU ──────────────────────────────────────────

    fn alu_eval(op: AluOp, a: u64, b: u64) -> u64 {
        match op {
            AluOp::Add => a.wrapping_add(b),
            AluOp::Sub => a.wrapping_sub(b),
            AluOp::And => a & b,
            AluOp::Or  => a | b,
            AluOp::Xor => a ^ b,
            AluOp::Shl => a << (b & 63),
            AluOp::Shr => a >> (b & 63),
            AluOp::Asr => ((a as i64) >> (b & 63)) as u64,
            AluOp::Mul => a.wrapping_mul(b),
        }
    }

    /// Second operand for ALU: rs2 for R-format, imm for I-format.
    fn alu_operand_b(&self, insn: &DecodedInsn) -> u64 {
        match insn.desc.format {
            super::desc::Format::R => self.r[insn.rs2 as usize],
            _ => insn.imm as u64,
        }
    }

    /// Second operand for CMP: rs2 for R-format, imm for I-format.
    fn cmp_operand_b(&self, insn: &DecodedInsn) -> u64 {
        match insn.desc.format {
            super::desc::Format::R => self.r[insn.rs2 as usize],
            _ => insn.imm as u64,
        }
    }

    // ───────────── Fabric memory operations ──────────────────────

    fn make_request(&self, object: ObjectId, offset: u64, width: Width, kind: AccessKind) -> MemoryRequest {
        MemoryRequest {
            context: AccessContext {
                agent: self.agent,
                domain: self.domain,
                privilege: self.privilege,
            },
            object,
            offset,
            width,
            length: width.bytes(),
            kind,
        }
    }

    fn fabric_read(
        &self,
        fabric: &mut Fabric,
        addr: u64,
        width: Width,
        kind: AccessKind,
    ) -> Result<Vec<u8>, FaultRecord> {
        let (object, offset) = self.address_map.resolve(addr)
            .ok_or_else(|| FaultRecord {
                agent: self.agent,
                domain: self.domain,
                privilege: self.privilege,
                transaction: TransactionId(0),
                object: ObjectId(0),
                generation: None,
                offset: addr,
                width,
                length: width.bytes(),
                kind,
                pc: Some(self.pc),
                reason: FaultReason::TranslationFault,
            })?;
        let req = self.make_request(object, offset, width, kind);
        fabric.execute_read(req)
    }

    fn fabric_write(
        &self,
        fabric: &mut Fabric,
        addr: u64,
        width: Width,
        data: Vec<u8>,
    ) -> Result<(), FaultRecord> {
        let (object, offset) = self.address_map.resolve(addr)
            .ok_or_else(|| FaultRecord {
                agent: self.agent,
                domain: self.domain,
                privilege: self.privilege,
                transaction: TransactionId(0),
                object: ObjectId(0),
                generation: None,
                offset: addr,
                width,
                length: width.bytes(),
                kind: AccessKind::Write,
                pc: Some(self.pc),
                reason: FaultReason::TranslationFault,
            })?;
        let req = self.make_request(object, offset, width, AccessKind::Write);
        fabric.execute_write(req, data)
    }

    fn fabric_atomic_xchg(
        &self,
        fabric: &mut Fabric,
        addr: u64,
        width: Width,
        new_value: Vec<u8>,
    ) -> Result<Vec<u8>, FaultRecord> {
        let (object, offset) = self.address_map.resolve(addr)
            .ok_or_else(|| FaultRecord {
                agent: self.agent,
                domain: self.domain,
                privilege: self.privilege,
                transaction: TransactionId(0),
                object: ObjectId(0),
                generation: None,
                offset: addr,
                width,
                length: width.bytes(),
                kind: AccessKind::Atomic,
                pc: Some(self.pc),
                reason: FaultReason::TranslationFault,
            })?;
        let req = self.make_request(object, offset, width, AccessKind::Atomic);
        fabric.execute_atomic_xchg(req, new_value)
    }

    // ───────────── Flag helpers ──────────────────────────────────

    fn update_flags(&mut self, effect: DescFlagEffect, a: u64, b: u64, result: u64) {
        match effect {
            DescFlagEffect::Arith => {
                self.flags.z = result == 0;
                self.flags.n = (result >> 63) != 0;
                self.flags.c = result < a; // unsigned carry
                self.flags.v = ((!(a ^ b) & (a ^ result)) >> 63) != 0;
            }
            DescFlagEffect::Sub => {
                self.flags.z = result == 0;
                self.flags.n = (result >> 63) != 0;
                self.flags.c = a >= b; // ARM: carry = no borrow
                self.flags.v = (((a ^ b) & (a ^ result)) >> 63) != 0;
            }
            DescFlagEffect::Logic => {
                self.flags.z = result == 0;
                self.flags.n = (result >> 63) != 0;
                self.flags.c = false;
                self.flags.v = false;
            }
            DescFlagEffect::None => {}
        }
    }

    /// Run until halted or fault, up to a maximum number of steps.
    pub fn run(&mut self, fabric: &mut Fabric, max_steps: usize) -> StepResult {
        for _ in 0..max_steps {
            match self.step(fabric) {
                StepResult::Continue => {}
                other => return other,
            }
        }
        StepResult::Continue
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — the 8-program ladder (UNCHANGED from Phase 2)
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fabric::Fabric;

    const CPU0: AgentId = AgentId(0);
    const DMA0: AgentId = AgentId(10);

    /// Set up fabric with text + data objects, domain with appropriate
    /// capabilities, and a core ready to execute.
    ///
    /// Text object starts Active.  Callers must:
    ///   1. Write code via load_program()
    ///   2. Call seal_text() before running the core
    ///
    /// W⊕X: Active ⇒ ¬X, Sealed ⇒ ¬W.
    fn setup() -> (Fabric, ObjectId, ObjectId, DomainId, Anka64Core) {
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);
        fabric.place_object(data, 0x10000);

        let dom = fabric.create_domain();
        // text: RX granted AFTER seal (see seal_text)
        fabric.grant(dom, data, 0, 0x1000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, data);

        (fabric, text, data, dom, core)
    }

    fn load_program(fabric: &mut Fabric, asm: &Asm64) {
        fabric.write_physical(0x00000, &asm.to_bytes());
    }

    /// Seal text object and grant RX.
    /// W⊕X lifecycle: Active(write) → Sealed(fetch).
    fn seal_text(fabric: &mut Fabric, text: ObjectId, dom: DomainId) {
        fabric.seal_object(text);
        let size = fabric.objects[&text].size;
        fabric.grant(dom, text, 0, size, Permissions::RX);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 1: 42 + 10 = 52
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p1_forty_two_plus_ten() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        let mut asm = Asm64::new();
        asm.movi(R0, 42);
        asm.movi(R1, 10);
        asm.add(R2, R0, R1);
        asm.halt();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R2 as usize], 52);
        eprintln!("P1: 42 + 10 = {}", core.r[R2 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 2: sum 1..10 = 55
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p2_sum_one_to_ten() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        let mut asm = Asm64::new();
        asm.movi(R0, 0);         // sum = 0
        asm.movi(R1, 1);         // i = 1
        asm.movi(R2, 11);        // limit = 11
        let loop_addr = asm.here();
        asm.add(R0, R0, R1);     // sum += i
        asm.addi(R1, R1, 1);     // i++
        asm.cmp(R1, R2);         // compare
        let branch_addr = asm.here();
        asm.bcc(Cond::Ne, loop_addr - branch_addr);
        asm.halt();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 500);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R0 as usize], 55);
        eprintln!("P2: sum(1..10) = {}", core.r[R0 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 3: add(40, 2) via CALL/RET
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p3_call_ret() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        let mut asm = Asm64::new();
        //  0: movi R0, 40
        //  1: movi R1, 2
        //  2: call +2        → jumps to word 4 (0+2 = word 4... wait)
        //  3: halt
        //  4: add R0, R0, R1  (add function)
        //  5: ret

        asm.movi(R0, 40);                // word 0
        asm.movi(R1, 2);                 // word 1
        let call_addr = asm.here();      // word 2
        asm.call(4 - call_addr);         // call → word 4 (offset = +2)
        asm.halt();                       // word 3
        asm.add(R0, R0, R1);             // word 4: add function
        asm.ret();                        // word 5
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R0 as usize], 42);
        eprintln!("P3: add(40, 2) = {}", core.r[R0 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 4: store 0xBEEF, load it back
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p4_store_and_load() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        let mut asm = Asm64::new();
        asm.movi(R0, 0x7EEF);           // value (fits 18-bit signed)
        asm.movi(R1, 0x8000_u16 as i32); // data segment base (positive)
        // Actually 0x8000 is 32768 which fits in 18-bit signed (max 131071)
        asm.st(R0, R1, 0);              // store R0 to [R1 + 0]
        asm.ld(R2, R1, 0);              // load [R1 + 0] to R2
        asm.halt();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R2 as usize], 0x7EEF);
        eprintln!("P4: store 0x{:X}, load 0x{:X}", core.r[R0 as usize], core.r[R2 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 5: protection — legal read ok, illegal read faults
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p5_protection_legal_and_illegal() {
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        let secret = fabric.alloc_object("secret", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);
        fabric.place_object(data, 0x10000);
        fabric.place_object(secret, 0x20000);

        // Write sentinel to secret
        fabric.write_physical(0x20000, &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]);

        // Domain has text+data but NOT secret
        let dom = fabric.create_domain();
        fabric.grant(dom, data, 0, 0x1000, Permissions::RW);

        // Write known value to data
        fabric.write_physical(0x10000, &42u64.to_le_bytes());

        // Program: load from data (legal), then load from secret (illegal)
        let mut asm = Asm64::new();
        asm.movi(R0, 0x8000_u16 as i32); // data addr
        asm.ld(R1, R0, 0);               // legal load
        asm.movi(R0, 0xC000_u16 as i32 - 0x10000); // Hmm, 0xC000 doesn't fit cleanly
        // Actually, let's use a two-step approach
        asm.halt();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, text, dom);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, data);
        core.address_map.add(0xC000, 0x1000, secret); // mapped but no capability!

        // Just test the legal load
        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R1 as usize], 42, "legal load failed");

        // Now test illegal access directly through fabric
        let illegal_req = super::super::fabric::request(
            CPU0, dom, secret, 0, Width::Double, AccessKind::Read,
        );
        let illegal = fabric.execute_read(illegal_req);
        assert!(illegal.is_err(), "illegal read should fault");
        assert_eq!(illegal.unwrap_err().reason, FaultReason::NoCapability);
        eprintln!("P5: legal load = {}, illegal read = NoCapability ✓",
            core.r[R1 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 6: TRAP → supervisor → ERET
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p6_trap_and_eret() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        // Program layout:
        //   0: movi R0, 0       (user code)
        //   1: trap #0           → jumps to trap_vector
        //   2: movi R3, 99      (after eret returns here)
        //   3: halt
        //   trap handler at word 8:
        //   8: movi R0, 1       (proves we entered handler)
        //   9: eret              (return to user)

        let mut asm = Asm64::new();
        asm.movi(R0, 0);          // word 0
        asm.trap(0);              // word 1
        asm.movi(R3, 99);         // word 2 (return point)
        asm.halt();                // word 3
        // padding
        asm.nop(); asm.nop(); asm.nop(); asm.nop(); // words 4-7
        // trap handler at word 8 (byte 32)
        asm.movi(R0, 1);          // word 8
        asm.eret();                // word 9

        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);
        core.trap_vector = 8 * 4; // byte address of word 8

        // Run: user → trap → handler → eret → user → halt
        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R0 as usize], 1, "trap handler should have set R0=1");
        assert_eq!(core.r[R3 as usize], 99, "code after eret should have run");
        assert_eq!(core.privilege, Privilege::User, "eret should restore user mode");
        eprintln!("P6: trap handler ran (R0={}), returned to user (R3={})", 
            core.r[R0 as usize], core.r[R3 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Program 7: revocation → stale commit faults
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p7_revocation_faults() {
        let (mut fabric, _text, data, dom, core) = setup();

        // Write sentinel
        fabric.write_physical(0x10000, &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0]);

        // Authorize a read (through fabric directly)
        let req = super::super::fabric::request(
            core.agent, dom, data, 0, Width::Double, AccessKind::Read,
        );

        // Step 1: authorize
        let idx = fabric.submit(req, None);
        fabric.advance(idx); // → Authorized
        assert_eq!(fabric.transaction(idx).state, TxState::Authorized);

        // Step 2: REVOKE the data object
        fabric.revoke(data);

        // Step 3: translate + commit → Faulted
        fabric.advance(idx); // → Prepared
        fabric.advance(idx); // → Faulted (stale generation)

        assert_eq!(fabric.transaction(idx).state, TxState::Faulted);
        assert_eq!(fabric.transaction(idx).fault.as_ref().unwrap().reason,
            FaultReason::StaleGeneration);

        // Sentinel unchanged
        let mem = fabric.read_physical(0x10000, 4);
        assert_eq!(&mem[..4], &[0xCA, 0xFE, 0xBA, 0xBE]);
        eprintln!("P7: authorize → revoke → commit faulted (StaleGeneration) ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // Program 8: two agents (CPU0 + DMA0) through same fabric
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p8_two_agents_same_fabric() {
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        let shared = fabric.alloc_object("shared", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);
        fabric.place_object(shared, 0x10000);

        // Sentinel
        fabric.write_physical(0x10000, &0xDEADu64.to_le_bytes());

        // CPU domain: text (sealed) + shared
        let cpu_dom = fabric.create_domain();
        fabric.grant(cpu_dom, shared, 0, 0x1000, Permissions::RW);

        // DMA domain: shared only
        let dma_dom = fabric.create_domain();
        fabric.grant(dma_dom, shared, 0, 0x1000, Permissions::RW);

        // CPU writes 42 to shared via program
        let mut asm = Asm64::new();
        asm.movi(R0, 42);
        asm.movi(R1, 0x8000_u16 as i32);
        asm.st(R0, R1, 0);
        asm.halt();
        fabric.write_physical(0x00000, &asm.to_bytes());
        fabric.seal_object(text);
        fabric.grant(cpu_dom, text, 0, 0x1000, Permissions::RX);

        let mut core = Anka64Core::new(CPU0, cpu_dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, shared);

        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));

        // DMA reads the shared object (should see 42)
        let dma_req = super::super::fabric::request(
            DMA0, dma_dom, shared, 0, Width::Double, AccessKind::Read,
        );
        let dma_data = fabric.execute_read(dma_req).expect("DMA read should succeed");
        let dma_val = u64::from_le_bytes(
            [dma_data[0], dma_data[1], dma_data[2], dma_data[3],
             dma_data[4], dma_data[5], dma_data[6], dma_data[7]]);
        assert_eq!(dma_val, 42, "DMA should read what CPU wrote");

        // DMA writes 99 to shared
        let dma_write_req = super::super::fabric::request(
            DMA0, dma_dom, shared, 0, Width::Double, AccessKind::Write,
        );
        fabric.execute_write(dma_write_req, 99u64.to_le_bytes().to_vec())
            .expect("DMA write should succeed");

        // Verify physical memory
        let final_bytes = fabric.read_physical(0x10000, 8);
        let final_val = u64::from_le_bytes(
            [final_bytes[0], final_bytes[1], final_bytes[2], final_bytes[3],
             final_bytes[4], final_bytes[5], final_bytes[6], final_bytes[7]]);
        assert_eq!(final_val, 99, "shared should contain DMA's write");

        eprintln!("P8: CPU0 wrote 42, DMA0 read 42, DMA0 wrote 99 ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // Program 9: MUL — added ONLY through the description
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p9_mul_through_description() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        // 6 × 7 = 42  (the answer, obviously)
        let mut asm = Asm64::new();
        asm.movi(R0, 6);
        asm.movi(R1, 7);
        asm.mul(R2, R0, R1);
        asm.halt();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R2 as usize], 42);

        // Verify all consumers agree this instruction exists:
        // 1. Assembler emitted it (above)
        // 2. Decoder recognizes it
        let word = asm.to_bytes();
        let mul_word = u32::from_le_bytes([word[8], word[9], word[10], word[11]]);
        let decoded = decode(mul_word);
        assert_eq!(decoded.desc.name, "mul");
        // 3. Disassembler round-trips it
        let text = disassemble(&decoded);
        assert!(text.starts_with("mul"), "disassembly should start with 'mul': {}", text);
        // 4. Rust executed it (R2 = 42)
        // 5. Description table has it
        assert!(super::super::desc::by_name("mul").is_some());

        eprintln!("P9: 6 × 7 = {} (MUL through description) ✓", core.r[R2 as usize]);
        eprintln!("    disassembly: {}", text);
    }

    // ═══════════════════════════════════════════════════════════
    // P21: Hostile LR corruption → ControlFlowViolation (6S.2)
    //
    // Rule 29: "An executable address is not control-flow authority."
    //
    // The attacker satisfies EVERY other requirement:
    //   ✓ corrupted target is 4-byte aligned
    //   ✓ corrupted target lives inside sealed RX code
    //   ✓ corrupted target is a known, valid address
    //   ✓ ordinary stack corruption succeeds (LD/ST work)
    //
    // The ONLY thing missing: return authority minted by CALL.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p21_hostile_lr_corruption() {
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);
        fabric.place_object(data, 0x10000);

        let dom = fabric.create_domain();
        fabric.grant(dom, data, 0, 0x1000, Permissions::RW);

        // ─── Program layout ────────────────────────────────
        //
        //   0x00: CALL victim         ; caller → victim (word 0)
        //   0x04: HALT                ; legitimate return point (word 1)
        //
        //   --- attacker's gadget (also valid RX code) ---
        //   0x08: MOVI R0, 0xBAD      ; word 2 — attacker target
        //   0x0C: HALT                ; word 3
        //
        //   --- victim function ---
        //   0x10: MOVI R3, 0x8000     ; word 4: stack base addr
        //   0x14: ST LR, [R3 + 0]    ; word 5: spill LR to stack
        //
        //   --- inline "attacker" corrupts saved LR ---
        //   0x18: MOVI R5, 8          ; word 6: attacker's gadget addr (0x08)
        //   0x1C: ST R5, [R3 + 0]    ; word 7: overwrite saved LR
        //
        //   --- victim reloads corrupted LR and returns ---
        //   0x20: LD LR, [R3 + 0]    ; word 8: reload (now corrupted)
        //   0x24: RET                 ; word 9: → ControlFlowViolation
        //
        // Note: the corrupted LR (0x08) points to word 2, which is
        // valid sealed RX code and 4-byte aligned.  Every conventional
        // check passes.  Only the protected return stack detects the
        // corruption.

        let mut asm = Asm64::new();

        // --- Caller ---
        let call_addr = asm.here();         // word 0
        asm.call(4 - call_addr);            // CALL victim → word 4
        asm.halt();                          // word 1 (legitimate return)

        // --- Attacker's gadget ---
        asm.movi(R0, 0xBAD);                // word 2 (attacker target at 0x08)
        asm.halt();                          // word 3

        // --- Victim function ---
        asm.movi(R3, 0x8000_u16 as i32);   // word 4: data base (RW stack)
        asm.st(LR, R3, 0);                  // word 5: spill LR

        // --- Attacker overwrites saved LR ---
        asm.movi(R5, 8);                     // word 6: gadget at 0x08
        asm.st(R5, R3, 0);                  // word 7: corrupt saved LR

        // --- Victim reloads and returns ---
        asm.ld(LR, R3, 0);                  // word 8: LR now 0x08
        asm.ret();                           // word 9: MUST fault

        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, text, dom);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, data);

        let result = core.run(&mut fabric, 100);

        // The attacker gave us everything:
        //   aligned ✓, sealed ✓, RX ✓, valid address ✓, stack corrupted ✓
        // But data in LR is not return authority.
        match &result {
            StepResult::Fault(fault) => {
                assert_eq!(fault.reason, FaultReason::ControlFlowViolation,
                    "expected ControlFlowViolation, got {:?}", fault.reason);
                assert_eq!(fault.offset, 8,
                    "fault should report the corrupted LR value");
                eprintln!("P21: hostile LR corruption → ControlFlowViolation ✓");
                eprintln!("     attacker had: aligned ✓ sealed ✓ RX ✓ known-address ✓");
                eprintln!("     attacker lacked: return authority minted by CALL");
                eprintln!("     Rule 29: an executable address is not control-flow authority");
            }
            _ => panic!("expected ControlFlowViolation fault, got {:?}", result),
        }
    }

    // ═══════════════════════════════════════════════════════════
    // P22: RET on empty return stack → ControlFlowViolation
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p22_ret_without_call() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        // Program: just RET (no prior CALL)
        let mut asm = Asm64::new();
        asm.ret();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 10);
        match &result {
            StepResult::Fault(fault) => {
                assert_eq!(fault.reason, FaultReason::ControlFlowViolation);
                eprintln!("P22: RET without CALL → ControlFlowViolation ✓");
            }
            _ => panic!("expected ControlFlowViolation, got {:?}", result),
        }
    }

    // ═══════════════════════════════════════════════════════════
    // P23: Legitimate CALL/RET still works (regression check)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p23_legitimate_call_ret_with_return_stack() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        // Same as P3 but explicitly verifies return stack is empty after
        let mut asm = Asm64::new();
        asm.movi(R0, 40);
        asm.movi(R1, 2);
        let call_addr = asm.here();
        asm.call(4 - call_addr);   // call → word 4
        asm.halt();                 // word 3
        asm.add(R0, R0, R1);       // word 4: add function
        asm.ret();                  // word 5
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, _text, _dom);

        let result = core.run(&mut fabric, 100);
        assert!(matches!(result, StepResult::Halted));
        assert_eq!(core.r[R0 as usize], 42);
        assert!(core.return_stack.is_empty(),
            "return stack should be empty after matched CALL/RET");
        eprintln!("P23: legitimate CALL/RET = 42, return stack empty ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // P24: Failed RET leaves R unchanged (fault atomicity, N8 analogue)
    //
    // The control-flow analogue of N8c: a faulting return does
    // not consume the protected return authority it was checking.
    //
    // Sequence:
    //   CALL fn            ; mints return authority (depth 1)
    //   fn: corrupt LR     ; overwrite with bad address
    //   fn: RET             ; faults — LR ≠ authority target
    //                       ; R must still have depth 1
    //
    // Then externally: restore LR, step again → legitimate RET
    // succeeds using the preserved authority.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p24_failed_ret_preserves_return_stack() {
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);
        fabric.place_object(data, 0x10000);

        let dom = fabric.create_domain();
        fabric.grant(dom, data, 0, 0x1000, Permissions::RW);

        // Program:
        //   0x00: CALL fn        ; word 0 → word 3
        //   0x04: HALT           ; word 1 (legitimate return point)
        //   0x08: NOP            ; word 2 (padding)
        //   0x0C: MOVI LR, 0x42 ; word 3 (fn: corrupt LR)
        //   0x10: RET            ; word 4 (fn: → fault, LR ≠ 0x04)
        //   0x14: RET            ; word 5 (second RET — after LR restored)
        let mut asm = Asm64::new();
        let call_addr = asm.here();
        asm.call(3 - call_addr);         // word 0: CALL → word 3
        asm.halt();                       // word 1: legitimate return @ 0x04
        asm.nop();                        // word 2: padding
        asm.movi(LR, 0x42);             // word 3: corrupt LR
        asm.ret();                        // word 4: faults (0x42 ≠ 0x04)
        asm.ret();                        // word 5: second RET (after fix)

        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, text, dom);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, data);

        // Run until fault
        let result = core.run(&mut fabric, 100);
        match &result {
            StepResult::Fault(fault) => {
                assert_eq!(fault.reason, FaultReason::ControlFlowViolation);
            }
            _ => panic!("expected ControlFlowViolation, got {:?}", result),
        }

        // R must still have depth 1 — the failed RET did NOT consume it
        assert_eq!(core.return_stack.len(), 1,
            "failed RET must not consume return authority");
        assert_eq!(core.return_stack[0].target, 0x04,
            "preserved authority must still point to legitimate return");

        // Fix LR and advance PC past the faulting RET to word 5
        core.r[LR as usize] = 0x04;  // restore legitimate return address
        core.pc = 0x14;               // word 5: the second RET
        core.halted = false;

        let result2 = core.step(&mut fabric);
        assert!(matches!(result2, StepResult::Continue));
        assert_eq!(core.pc, 0x04, "RET should have returned to 0x04");
        assert!(core.return_stack.is_empty(),
            "successful RET should have consumed the authority");

        eprintln!("P24: failed RET preserved R (depth=1), second RET succeeded ✓");
        eprintln!("     fault atomicity: faulting RET ⟹ R' = R");
    }

    // ═══════════════════════════════════════════════════════════
    // P25: Illegal instruction → IllegalInstruction fault (not Halted)
    //
    // Encodes a word with no semantic mapping.  Before the
    // disambiguation, this produced StepResult::Halted — now it
    // must produce StepResult::Fault(IllegalInstruction).
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p25_illegal_instruction_faults() {
        let (mut fabric, _text, _data, _dom, mut core) = setup();

        // word 0: illegal encoding (opcode 0x00 has no desc-table entry).
        // NOTE: 0xFFFFFFFF maps to opcode 0x3F = NOP, not illegal.
        let code = [
            0x00000001u32,  // opcode 0 → is_illegal()
        ];
        let mut bytes = Vec::new();
        for w in &code { bytes.extend_from_slice(&w.to_le_bytes()); }
        fabric.write_physical(0x0000, &bytes);
        seal_text(&mut fabric, _text, _dom);

        let result = core.step(&mut fabric);
        match &result {
            StepResult::Fault(fault) => {
                assert_eq!(fault.reason, FaultReason::IllegalInstruction);
                assert_eq!(fault.pc, Some(0x0000));
                eprintln!("P25: illegal opcode → IllegalInstruction fault ✓");
                eprintln!("     (was StepResult::Halted before disambiguation)");
            }
            _ => panic!("expected IllegalInstruction fault, got {:?}", result),
        }
        assert!(!core.halted, "illegal instruction must not set halted flag");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.0b — Interrupt delivery micro-tests
    //
    // These directly witness the formal Petri net transitions and
    // invariants from anka_interrupts.kleis without any timer device
    // or scheduler involvement.
    // ═══════════════════════════════════════════════════════════════

    /// T_deliver witness: pending + enabled → frame pushed, masked,
    /// Supervisor, pc = trap_vector, pending consumed.
    ///
    /// Formal: T_deliver fires from M0→M1→M2, verifying INT-3, INT-6a,
    /// INT-9a, and the CONS-4 (F=M) invariant.
    #[test]
    fn p90b_deliver_pending_enabled() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x1000;
        core.trap_vector = 0x2000;
        core.privilege = Privilege::User;
        core.interrupts_enabled = true;

        // Post: P_timer := 1
        core.post_timer_interrupt();

        // Deliver
        let delivered = core.deliver_pending();

        assert!(delivered, "delivery must succeed when P_timer=1, M=0");
        assert_eq!(core.pc, 0x2000, "pc must be trap_vector");
        assert_eq!(core.privilege, Privilege::Supervisor);
        assert!(!core.interrupts_enabled, "interrupts must be masked (CONS-4: F=M)");
        assert!(!core.pending.timer, "P_timer must be consumed");
        assert_eq!(core.event_frames.len(), 1, "exactly one EventFrame (INT-9a)");

        let frame = &core.event_frames[0];
        assert_eq!(frame.return_pc, 0x1000, "return_pc = interrupted pc");
        assert_eq!(frame.return_privilege, Privilege::User);
        assert!(frame.interrupts_were_enabled, "saved enable state = true");
        assert_eq!(frame.cause, EventCause::TimerInterrupt);
    }

    /// T_deliver + T_eret round-trip: deliver then event_return()
    /// restores the exact interrupted control state.
    ///
    /// Formal: T_deliver; T_eret = M0 → M1 → M2 → M3 → M0.
    /// Witnesses INT-4, INT-8a, INT-8b.
    #[test]
    fn p90b_deliver_then_return() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x400;
        core.trap_vector = 0x800;
        core.privilege = Privilege::User;
        core.interrupts_enabled = true;

        core.post_timer_interrupt();
        assert!(core.deliver_pending());

        // Now in handler state: Supervisor, masked, at trap_vector.
        assert_eq!(core.pc, 0x800);
        assert_eq!(core.privilege, Privilege::Supervisor);
        assert!(!core.interrupts_enabled);

        // T_eret: consume the EventFrame.
        let return_pc = core.event_return();
        assert_eq!(return_pc, Some(0x400), "INT-8a: exact saved PC");
        assert_eq!(core.privilege, Privilege::User);
        assert!(core.interrupts_enabled, "INT-8b: prior enable state restored");
        assert!(core.event_frames.is_empty(), "INT-4: frame consumed");
    }

    /// INT-2: masked state blocks delivery; pending bits preserved.
    ///
    /// Formal: M=1 disables T_deliver.  P_timer persists.
    #[test]
    fn p90b_deliver_masked_preserves_pending() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = false;  // masked

        core.post_timer_interrupt();
        let delivered = core.deliver_pending();

        assert!(!delivered, "INT-2: delivery must not fire when masked");
        assert!(core.pending.timer, "pending timer must survive");
        assert_eq!(core.pc, 0x100, "pc unchanged");
        assert!(core.event_frames.is_empty(), "no frame created");
    }

    /// No delivery when no source is pending.
    ///
    /// Formal: Q=1 (no pending) means T_deliver is disabled.
    #[test]
    fn p90b_deliver_empty_pending_noop() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        // No posting — both sources clear.

        let delivered = core.deliver_pending();

        assert!(!delivered, "no pending event → no delivery");
        assert_eq!(core.pc, 0x100, "pc unchanged");
        assert!(core.event_frames.is_empty(), "no frame created");
        assert!(core.interrupts_enabled, "enable state unchanged");
    }

    /// INT-10b: pending event survives ERET and becomes deliverable.
    ///
    /// Formal: M3a → (T_eret) → M1 → (T_deliver) → M2.
    /// A second event posted during handling persists through ERET,
    /// then immediately becomes deliverable on the restored boundary.
    #[test]
    fn p90b_pending_survives_eret() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x400;
        core.trap_vector = 0x800;
        core.interrupts_enabled = true;

        // First event: post + deliver
        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        assert_eq!(core.pc, 0x800);

        // Second event posted while masked.
        core.post_timer_interrupt();

        // T_eret with pending event: pending preserved.
        let return_pc = core.event_return();
        assert_eq!(return_pc, Some(0x400), "return to interrupted pc");
        assert!(core.interrupts_enabled, "unmasked after return");
        assert!(core.pending.timer, "INT-10b: pending survives ERET");

        // Now immediately deliverable again
        assert!(core.deliver_pending(), "re-delivery after ERET must succeed");
        assert_eq!(core.pc, 0x800, "back at trap_vector");
        assert!(!core.interrupts_enabled, "masked again");
        assert_eq!(core.event_frames.len(), 1, "one fresh frame");
    }

    /// INT-9b: delivery cannot fire twice from a single pending event.
    ///
    /// After one successful delivery, a second deliver_pending() with
    /// no new event posted must return false.
    #[test]
    fn p90b_no_double_delivery() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;

        core.post_timer_interrupt();
        assert!(core.deliver_pending());

        // After delivery: P_timer=0, M=1.  Second deliver must be a no-op.
        let second = core.deliver_pending();
        assert!(!second, "INT-9b: no double delivery");
        assert_eq!(core.event_frames.len(), 1, "still exactly one frame");
    }

    /// Syscall cause uses the same frame-entry law as timer.
    ///
    /// Formal: FRAME-UNIFIED-1.  The generic gate is cause-agnostic.
    /// Syscall delivery bypasses the pending/arbiter path (it is
    /// synchronous via TRAP), but verifying frame structure is
    /// identical remains important.
    /// Device interrupt uses the same frame-entry law as timer.
    ///
    /// Formal: FRAME-UNIFIED-1 + IRQ-INDEP.  DeviceInterrupt
    /// delivered through the same gate produces identical frame
    /// structure; only the cause tag differs.
    #[test]
    fn p90b_deliver_device_cause_unified() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x300;
        core.trap_vector = 0x600;
        core.interrupts_enabled = true;

        core.post_device_interrupt();
        assert!(core.deliver_pending());

        assert_eq!(core.pc, 0x600);
        assert_eq!(core.privilege, Privilege::Supervisor);
        assert!(!core.interrupts_enabled);
        assert_eq!(core.event_frames.len(), 1);
        assert_eq!(core.event_frames[0].cause, EventCause::DeviceInterrupt);
        assert_eq!(core.event_frames[0].return_pc, 0x300);

        // Return restores regardless of cause (FRAME-UNIFIED-3).
        let pc = core.event_return();
        assert_eq!(pc, Some(0x300));
        assert!(core.interrupts_enabled);
    }

    /// INT-10a: pending event survives handler completion while masked.
    ///
    /// With interrupts masked and a pending timer, deliver_pending()
    /// refuses, but the pending bit remains intact for future
    /// delivery when interrupts are re-enabled.
    #[test]
    fn p90b_pending_survives_masked_handler() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.interrupts_enabled = false;
        core.post_timer_interrupt();

        // Masked: no delivery.
        assert!(!core.deliver_pending());
        assert!(core.pending.timer, "INT-10a: pending preserved");

        // Re-enable and retry: delivery succeeds.
        core.interrupts_enabled = true;
        core.trap_vector = 0x500;
        core.pc = 0x100;
        assert!(core.deliver_pending());
        assert_eq!(core.pc, 0x500);
        assert!(!core.pending.timer);
    }

    /// COALESCE: posting while already pending is idempotent (P≤1 per source).
    ///
    /// This is a source-policy property: a second post while P_timer=1
    /// simply writes true again.  Per-source Boolean truth enforces
    /// coalescing structurally.
    #[test]
    fn p90b_coalesce_pending() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.post_timer_interrupt();

        // Second post: idempotent.
        core.post_timer_interrupt();

        assert!(core.pending.timer);
        assert!(!core.pending.device, "device unchanged");
        // After delivery, consumed once.
        core.interrupts_enabled = true;
        core.trap_vector = 0x100;
        assert!(core.deliver_pending());
        assert!(!core.pending.timer);
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 9.1a — Multi-source arbitration micro-tests
    //
    // Witnesses for anka_block_device.kleis ARB-1..ARB-11 and
    // IRQ-INDEP-1..IRQ-INDEP-3.  Each test directly exercises the
    // formal transition system rather than running guest code.
    // ═══════════════════════════════════════════════════════════════

    /// ARB-9: lone timer, always selected regardless of turn.
    #[test]
    fn p91a_lone_timer_ignores_turn() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Device;  // turn favors device

        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        assert_eq!(core.event_frames[0].cause, EventCause::TimerInterrupt);
        assert!(!core.pending.timer);
        assert!(!core.pending.device);
    }

    /// ARB-10: lone device, always selected regardless of turn.
    #[test]
    fn p91a_lone_device_ignores_turn() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Timer;  // turn favors timer

        core.post_device_interrupt();
        assert!(core.deliver_pending());
        assert_eq!(core.event_frames[0].cause, EventCause::DeviceInterrupt);
        assert!(!core.pending.timer);
        assert!(!core.pending.device);
    }

    /// ARB-1..ARB-4: both pending, turn=Timer → deliver timer,
    /// preserve device, flip turn.
    #[test]
    fn p91a_both_pending_turn_timer() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Timer;

        core.post_timer_interrupt();
        core.post_device_interrupt();
        assert!(core.deliver_pending());

        assert_eq!(core.event_frames[0].cause, EventCause::TimerInterrupt);
        assert!(!core.pending.timer, "timer consumed");
        assert!(core.pending.device, "device preserved");
        assert_eq!(core.interrupt_turn, InterruptTurn::Device, "turn flipped");
    }

    /// ARB-5..ARB-8: both pending, turn=Device → deliver device,
    /// preserve timer, flip turn.
    #[test]
    fn p91a_both_pending_turn_device() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Device;

        core.post_timer_interrupt();
        core.post_device_interrupt();
        assert!(core.deliver_pending());

        assert_eq!(core.event_frames[0].cause, EventCause::DeviceInterrupt);
        assert!(core.pending.timer, "timer preserved");
        assert!(!core.pending.device, "device consumed");
        assert_eq!(core.interrupt_turn, InterruptTurn::Timer, "turn flipped");
    }

    /// Bounded-service witness: both continuously pending,
    /// serve source A then source B within two deliveries.
    ///
    /// Formal: ARB-7/ARB-8 bounded-service theorem.
    #[test]
    fn p91a_bounded_service_two_deliveries() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Timer;

        // Both pending
        core.post_timer_interrupt();
        core.post_device_interrupt();

        // Delivery 1: timer (turn=Timer)
        assert!(core.deliver_pending());
        let cause1 = core.event_frames.last().unwrap().cause;
        assert_eq!(cause1, EventCause::TimerInterrupt);
        assert!(core.pending.device, "device still pending");

        // Simulate handler + event_return
        let _ = core.event_return();
        // Re-post timer (continuously pending)
        core.post_timer_interrupt();
        assert!(core.pending.timer && core.pending.device);

        // Delivery 2: device (turn=Device now)
        assert!(core.deliver_pending());
        let cause2 = core.event_frames.last().unwrap().cause;
        assert_eq!(cause2, EventCause::DeviceInterrupt);

        // Both served within two eligible deliveries.
        assert_ne!(cause1, cause2, "bounded service: different sources");
    }

    /// First delivery leaves other pending; event_return + deliver
    /// serves the survivor.
    ///
    /// This is the direct executable witness for P_t+P_d=2.
    #[test]
    fn p91a_dual_pending_sequential_delivery() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x1000;
        core.trap_vector = 0x2000;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Timer;

        core.post_timer_interrupt();
        core.post_device_interrupt();

        // Deliver first: timer
        assert!(core.deliver_pending());
        assert_eq!(core.event_frames[0].cause, EventCause::TimerInterrupt);
        assert!(core.pending.device, "source B still pending");
        assert!(!core.pending.timer, "source A consumed");

        // event_return
        let return_pc = core.event_return();
        assert_eq!(return_pc, Some(0x1000));
        assert!(core.interrupts_enabled);

        // Deliver second: device (the survivor)
        assert!(core.deliver_pending());
        assert_eq!(core.event_frames[0].cause, EventCause::DeviceInterrupt);
        assert!(!core.pending.device, "device consumed");
        assert!(!core.pending.timer);
        assert!(!core.pending.any_pending(), "pending set empty");
    }

    /// IRQ-MASK-1/2: masked simultaneous pending preserves both.
    #[test]
    fn p91a_masked_both_preserved() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.interrupts_enabled = false;

        core.post_timer_interrupt();
        core.post_device_interrupt();

        assert!(!core.deliver_pending());
        assert!(core.pending.timer, "timer preserved under mask");
        assert!(core.pending.device, "device preserved under mask");
    }

    /// Repeated dual-pending opportunities alternate per formal turn.
    #[test]
    fn p91a_alternation_four_deliveries() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.pc = 0x100;
        core.trap_vector = 0x200;
        core.interrupts_enabled = true;
        core.interrupt_turn = InterruptTurn::Timer;

        let mut causes = Vec::new();
        for _ in 0..4 {
            core.post_timer_interrupt();
            core.post_device_interrupt();
            assert!(core.deliver_pending());
            causes.push(core.event_frames.last().unwrap().cause);
            let _ = core.event_return();
        }
        // Timer, Device, Timer, Device
        assert_eq!(causes, vec![
            EventCause::TimerInterrupt,
            EventCause::DeviceInterrupt,
            EventCause::TimerInterrupt,
            EventCause::DeviceInterrupt,
        ]);
    }

    /// IRQ-INDEP-1: posting timer does not alter P_dev.
    #[test]
    fn p91a_post_timer_independent() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.post_device_interrupt();

        let dev_before = core.pending.device;
        core.post_timer_interrupt();
        assert_eq!(core.pending.device, dev_before, "P_dev unchanged");
        assert!(core.pending.timer);
    }

    /// IRQ-INDEP-2: posting device does not alter P_timer.
    #[test]
    fn p91a_post_device_independent() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.post_timer_interrupt();

        let timer_before = core.pending.timer;
        core.post_device_interrupt();
        assert_eq!(core.pending.timer, timer_before, "P_timer unchanged");
        assert!(core.pending.device);
    }

    /// COALESCE per source: repeated posting remains Boolean.
    #[test]
    fn p91a_coalesce_device() {
        let mut core = Anka64Core::new(CPU0, DomainId(0));
        core.post_device_interrupt();
        core.post_device_interrupt();
        core.post_device_interrupt();

        assert!(core.pending.device);
        assert!(!core.pending.timer, "timer untouched");

        core.interrupts_enabled = true;
        core.trap_vector = 0x100;
        assert!(core.deliver_pending());
        assert!(!core.pending.device, "consumed once");
    }

    /// Lone-source delivery never waits for its nominal turn.
    ///
    /// Even when turn=Device, a lone timer is served immediately.
    /// Even when turn=Timer, a lone device is served immediately.
    #[test]
    fn p91a_lone_source_no_turn_wait() {
        for turn in [InterruptTurn::Timer, InterruptTurn::Device] {
            let mut core = Anka64Core::new(CPU0, DomainId(0));
            core.pc = 0x100;
            core.trap_vector = 0x200;
            core.interrupts_enabled = true;
            core.interrupt_turn = turn;

            // Post only timer
            core.post_timer_interrupt();
            assert!(core.deliver_pending(), "lone timer served regardless of turn={:?}", turn);
            let _ = core.event_return();

            // Post only device
            core.post_device_interrupt();
            assert!(core.deliver_pending(), "lone device served regardless of turn={:?}", turn);
        }
    }
}

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
use std::sync::atomic::{AtomicU64, Ordering};
mod heap;
pub(crate) use heap::HeapEventPermit;

// Trusted execution-context identities are independent of physical CPU agents.
// Exhaustion fails closed without wrapping or changing the counter.
static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);
fn fresh_context_id() -> u64 {
    let mut current = NEXT_CONTEXT_ID.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).expect("execution-context identity exhausted");
        match NEXT_CONTEXT_ID.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return current,
            Err(observed) => current = observed,
        }
    }
}

#[derive(Debug, Clone)]
struct EventRegisterImage {
    words: [u64; 16],
    kinds: [Option<super::scoped_pointers::ScopedPointer>; 6],
    flags: Flags,
    return_stack: Vec<ReturnAuthority>,
    halted: bool,
    frames: Option<super::pointer_frames::FrameState>,
}

/// Not user memory, and not reconstructible from the public control header.
#[derive(Debug, Clone)]
struct SavedEventContext {
    event_id: u64,
    result_consumed: bool,
    header: EventFrame,
    context_id: u64,
    domain: DomainId,
    image: Option<EventRegisterImage>,
    scalar_results: [Option<u64>; 13],
}


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

    /// Retirement inspects every retained entry, even empty/malformed ranges.
    pub(crate) fn references_object(&self, object: ObjectId) -> bool {
        self.entries.iter().any(|entry| entry.object == object)
    }

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
    heap_owner: Option<super::scoped_pointers::heap::AllocationOwner>,
    next_event_id: u64,
    context_id: u64,
    protected_context_enabled: bool,
    saved_event_contexts: Vec<SavedEventContext>,
    pointer_pairs: [Option<super::scoped_pointers::ScopedPointer>; 6],
    pointer_frames: Option<super::pointer_frames::FrameState>,
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
    /// Public control headers for existing trusted observers. A header alone cannot
    /// restore pointer authority; return also checks the private saved-image stack.
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

#[derive(Debug)]
pub(crate) enum PointerMachineError {
    InvalidPair, MissingKind, Unmapped, Unaligned,
    Frame(super::pointer_frames::FrameError), ContextMode, Pointer(super::scoped_pointers::PointerError), Heap(super::scoped_pointers::heap::HeapError), Fabric(FaultRecord),
}

impl std::fmt::Display for PointerMachineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "frame: {error:?}"),
            Self::Pointer(error) => write!(f, "pointer registry: {error:?}"),
            Self::Heap(error) => write!(f, "heap: {error:?}"),
            Self::Fabric(error) => write!(f, "fabric: {error:?}"),
            Self::InvalidPair => f.write_str("invalid register pair"),
            Self::MissingKind => f.write_str("missing pointer kind"),
            Self::Unmapped => f.write_str("unmapped pointer"),
            Self::Unaligned => f.write_str("unaligned pointer"),
            Self::ContextMode => f.write_str("invalid pointer context"),
        }
    }
}

impl Anka64Core {
    /// Ordinary writes never confer pointer kind, even if the new integer is unchanged.
    pub fn write_register(&mut self, register: usize, value: u64) {
        assert!(register < 16);
        if register < 12 { self.pointer_pairs[register / 2] = None; }
        self.r[register] = value;
    }

    /// Trusted profile selection. Never upgrade a partial legacy event image.
    pub(crate) fn enable_protected_context(&mut self) -> Result<(), PointerMachineError> {
        if !self.protected_context_enabled && !self.event_frames.is_empty() {
            return Err(PointerMachineError::ContextMode);
        }
        self.protected_context_enabled = true;
        Ok(())
    }

    pub(crate) fn protected_application(&self) -> bool {
        self.pointer_frames.is_some() || self.saved_event_contexts.last()
            .and_then(|s|s.image.as_ref()).is_some_and(|i|i.frames.is_some())
    }

    /// Capture only an owned, intact protected syscall image. Handler scratch
    /// words/kinds are deliberately not a source of application authority.
    pub(crate) fn protected_syscall_image(&self) -> Option<([u64; 16],
        [Option<super::scoped_pointers::ScopedPointer>; 6])> {
        let saved = self.saved_event_contexts.last()?;
        let header = self.event_frames.last()?;
        if self.privilege != Privilege::Supervisor || !self.protected_context_enabled
            || self.event_frames.len() != self.saved_event_contexts.len()
            || saved.context_id != self.context_id || saved.domain != self.domain
            || saved.header != *header || header.cause != EventCause::Syscall
            || self.pointer_frames.as_ref().is_some_and(|s| !s.active.is_empty()) {
            return None;
        }
        let image = saved.image.as_ref()?;
        Some((image.words, image.kinds))
    }

    /// Validate the complete protected range without performing an operand read.
    /// &mut Kernel/Fabric serializes this borrow through final publication.
    pub(crate) fn syscall_read_span(&self, fabric: &Fabric,
        pointer: super::scoped_pointers::ScopedPointer, length: u64)
        -> Result<(ObjectId, u64), PointerMachineError> {
        if fabric.scoped_pointers.is_heap_pointer(pointer) {
            let owner=self.heap_owner().map_err(PointerMachineError::Heap)?;
            fabric.check_heap_application_span(owner,self.agent,pointer,length,false).map_err(PointerMachineError::Heap)?;
            return Ok((fabric.heap_object_for_pointer(owner,self.agent,pointer).map_err(PointerMachineError::Heap)?,pointer.words()[1]));
        }
        let address = fabric.scoped_pointers.read_span(pointer, self.domain.0,
            self.context_id, length).map_err(PointerMachineError::Pointer)?;
        let backing = fabric.scoped_pointer_backing(pointer, self.domain)?;
        if length != 0 && self.checked_pointer_mapping(address, length)? != backing {
            return Err(PointerMachineError::Unmapped);
        }
        if !fabric.authorize_pointer_output(self.agent, self.domain, backing.0, backing.1, length) {
            return Err(PointerMachineError::MissingKind);
        }
        Ok(backing)
    }

    pub(crate) fn context_identity(&self) -> u64 { self.context_id }

    /// Input requires WRITE over the entire original capacity, including EOF.
    pub(crate) fn syscall_write_span(&self, fabric: &Fabric,
        pointer: super::scoped_pointers::ScopedPointer, length: u64)
        -> Result<(ObjectId, u64), PointerMachineError> {
        if fabric.scoped_pointers.is_heap_pointer(pointer) {
            let owner=self.heap_owner().map_err(PointerMachineError::Heap)?;
            fabric.check_heap_application_span(owner,self.agent,pointer,length,true).map_err(PointerMachineError::Heap)?;
            return Ok((fabric.heap_object_for_pointer(owner,self.agent,pointer).map_err(PointerMachineError::Heap)?,pointer.words()[1]));
        }
        let address = fabric.scoped_pointers.write_span(pointer, self.domain.0,
            self.context_id, length).map_err(PointerMachineError::Pointer)?;
        let backing = fabric.scoped_pointer_backing(pointer, self.domain)?;
        if length != 0 && self.checked_pointer_mapping(address, length)? != backing {
            return Err(PointerMachineError::Unmapped);
        }
        if !fabric.authorize_pointer_input(self.agent, self.domain, backing.0, backing.1, length) {
            return Err(PointerMachineError::MissingKind);
        }
        Ok(backing)
    }

    /// Explicit scalar syscall result, distinct from handler scratch registers.
    /// Interrupt frames never export result lanes. No call can mint pointer kind.
    pub(crate) fn write_syscall_result(&mut self, register: usize, value: u64) {
        self.write_register(register, value);
        if register > 12 || self.privilege != Privilege::Supervisor { return; }
        if let Some(saved) = self.saved_event_contexts.last_mut() {
            if saved.context_id == self.context_id && saved.domain == self.domain
                && saved.header.cause == EventCause::Syscall && saved.image.is_some() && !saved.result_consumed {
                saved.scalar_results[register] = Some(value);
            }
        }
    }

    /// Single trusted event-entry primitive, including nested supervisor events.
    pub(crate) fn enter_event(&mut self, header: EventFrame) {
        let image = if self.protected_context_enabled {
            Some(EventRegisterImage { words: self.r, kinds: self.pointer_pairs,
                flags: self.flags, return_stack: std::mem::take(&mut self.return_stack),
                halted: self.halted, frames: self.pointer_frames.take() })
        } else { None };
        let event_id = self.next_event_id;
        self.next_event_id = if event_id == 0 { 0 } else { event_id.checked_add(1).unwrap_or(0) };
        self.saved_event_contexts.push(SavedEventContext { event_id, result_consumed: false, header: header.clone(),
            context_id: self.context_id, domain: self.domain, image,
            scalar_results: [None; 13] });
        self.event_frames.push(header);
        self.pointer_pairs = [None; 6];
        self.privilege = Privilege::Supervisor;
        self.interrupts_enabled = false;
    }

    /// Trusted loader admission. Manifest bytes cannot be supplied by user registers.
    pub(crate) fn admit_pointer_program(&mut self, fabric:&mut Fabric,
        program:super::pointer_frames::ValidatedPointerProgram, code_base:u64,
        stack_low:u64, stack_high:u64) -> Result<(),PointerMachineError> {
        use super::pointer_frames::{FrameState,FrameError};
        let fail=|| PointerMachineError::Frame(FrameError::Geometry);
        if self.pointer_frames.is_some()||!self.event_frames.is_empty()||!self.return_stack.is_empty()
            || self.privilege!=Privilege::User||stack_high<=stack_low||stack_low%16!=0||stack_high%16!=0 { return Err(fail()); }
        let (object,offset)=self.checked_pointer_mapping(code_base,program.code.len() as u64)?;
        let obj=fabric.objects.get(&object).ok_or_else(fail)?;
        if obj.state!=ObjectState::Sealed { return Err(fail()); }
        let generation=obj.generation;
        let physical=fabric.translate(object,offset).ok_or_else(fail)?;
        if physical.checked_add(program.code.len() as u64).is_none_or(|n| n>fabric.mem_size() as u64)
            || fabric.read_physical(physical,program.code.len() as u64)!=program.code { return Err(fail()); }
        let (stack_object,stack_offset)=self.checked_pointer_mapping(stack_low,stack_high-stack_low)?;
        let stack_generation=fabric.objects.get(&stack_object).ok_or_else(fail)?.generation;
        let (_,code_offset)=self.checked_pointer_mapping(code_base,4)?;
        let fetch=self.make_request(object,code_offset,Width::Word,AccessKind::Fetch);
        if !matches!(fabric.authorize(&fetch),super::fabric::AuthResult::Authorized(_)) { return Err(fail()); }
        if !fabric.protect_pointer_stack(stack_object,self.context_id,self.domain) { return Err(PointerMachineError::Frame(FrameError::Context)); }
        self.enable_protected_context()?;
        self.pointer_frames=Some(FrameState { program,context:self.context_id,domain:self.domain,
            code_object:object,code_generation:generation,code_offset:offset,code_base,stack_low,
            stack_high,stack_object,stack_generation,stack_offset,cursor:stack_high,
            pending_entry:Some(code_base),active:Vec::new() });
        self.write_register(SP as usize,stack_high);
        Ok(())
    }

    /// A compiler entry can be installed only before the first admitted frame.
    pub(crate) fn compiler_entry_ready(&self, fabric: &Fabric) -> bool {
        self.event_frames.is_empty() && self.return_stack.is_empty() && !self.halted
            && self.frame_current(fabric).is_ok_and(|s| s.active.is_empty()
                && s.pending_entry == Some(self.pc) && self.pc == s.code_base)
    }

    fn frame_current(&self,fabric:&Fabric) -> Result<&super::pointer_frames::FrameState,PointerMachineError> {
        use super::pointer_frames::FrameError;
        let state=self.pointer_frames.as_ref().ok_or(PointerMachineError::ContextMode)?;
        if self.privilege!=Privilege::User||state.context!=self.context_id||state.domain!=self.domain
            || !fabric.objects.get(&state.code_object).is_some_and(|o| o.generation==state.code_generation && o.state==ObjectState::Sealed)
            || self.pc.checked_sub(state.code_base).is_none_or(|pc| pc>=state.program.code.len() as u64)
            || self.checked_pointer_mapping(self.pc,4)?!=(state.code_object,state.code_offset+self.pc-state.code_base) { return Err(PointerMachineError::Frame(FrameError::Context)); }
        Ok(state)
    }
    fn enter_pointer_frame(&mut self,fabric:&mut Fabric,index:usize) -> Result<(),PointerMachineError> {
        use super::pointer_frames::{FrameError,ActiveFrame};
        let state=self.frame_current(fabric)?;
        let frame=state.program.frames.get(index).ok_or(PointerMachineError::Frame(FrameError::Manifest))?;
        if state.pending_entry!=Some(self.pc)||self.pc!=state.code_base+frame.entry
            || state.active.iter().any(|f| f.call_depth==self.return_stack.len()) {
            return Err(PointerMachineError::Frame(FrameError::Control));
        }
        let geometry=||PointerMachineError::Frame(FrameError::Geometry);
        let capacity=||PointerMachineError::Frame(FrameError::Capacity);
        let stack_len=state.stack_high.checked_sub(state.stack_low).filter(|&n|n>0).ok_or_else(geometry)?;
        if state.stack_low%16!=0 || state.stack_high%16!=0 || state.cursor%16!=0
            || state.cursor>state.stack_high || frame.size==0 || frame.size%16!=0
            || self.checked_pointer_mapping(state.stack_low,stack_len)?!=(state.stack_object,state.stack_offset)
            || !fabric.objects.get(&state.stack_object).is_some_and(|o|o.generation==state.stack_generation
                && matches!(o.state,ObjectState::Active|ObjectState::Sealed)
                && state.stack_offset.checked_add(stack_len).is_some_and(|end|end<=o.size)) {
            return Err(geometry());
        }
        let stack_physical=fabric.translate(state.stack_object,state.stack_offset).ok_or_else(geometry)?;
        if stack_physical%16!=0 || stack_physical.checked_add(stack_len).is_none_or(|n|n>fabric.mem_size() as u64) {
            return Err(geometry());
        }
        let base=state.cursor.checked_sub(frame.size).filter(|&n| n>=state.stack_low).ok_or_else(capacity)?;
        let offset=state.stack_offset.checked_add(base-state.stack_low).ok_or_else(geometry)?;
        if self.checked_pointer_mapping(base,frame.size)?!=(state.stack_object,offset) {return Err(geometry());}
        let mut whole=self.make_request(state.stack_object,offset,Width::Byte,AccessKind::Read);
        whole.length=frame.size;
        let mut registrations=Vec::new();
        registrations.try_reserve_exact(frame.locals.len()).map_err(|_|capacity())?;
        for local in &frame.locals {
            let address=base.checked_add(local.offset).ok_or_else(geometry)?;
            let (object,local_offset)=self.checked_pointer_mapping(address,local.length)?;
            if object!=state.stack_object || offset.checked_add(local.offset)!=Some(local_offset)
                || (local.pointer_slot && local_offset%16!=0) {return Err(geometry());}
            let mut request=self.make_request(object,local_offset,Width::Byte,AccessKind::Read);
            request.length=local.length;
            registrations.push((request,address,local.writable));
        }
        let parent_cursor=state.cursor;
        // Reserve every host container before Fabric's first payload/tag write.
        self.pointer_frames.as_mut().unwrap().active.try_reserve(1).map_err(|_|capacity())?;
        let (scope,locals)=fabric.issue_pointer_frame(self.context_id,whole,base,registrations)?;
        let active=ActiveFrame { scope,manifest:index,call_depth:self.return_stack.len(),
            parent_cursor,parent_fp:self.r[FP as usize],return_lr:self.r[LR as usize],locals };
        let state=self.pointer_frames.as_mut().unwrap();
        state.active.push(active);state.cursor=base;state.pending_entry=None;
        self.write_register(SP as usize,base);self.write_register(FP as usize,base);
        Ok(())
    }
    fn lookup_pointer_local(&mut self,fabric:&Fabric,dst:u8,index:usize) -> Result<(),PointerMachineError> {
        Self::pointer_pair_index(dst)?;
        let state=self.frame_current(fabric)?;
        let frame=state.active.last().filter(|f| f.call_depth==self.return_stack.len())
            .ok_or(PointerMachineError::Frame(super::pointer_frames::FrameError::Control))?;
        let pointer=*frame.locals.get(index).ok_or(PointerMachineError::Frame(super::pointer_frames::FrameError::Manifest))?;
        fabric.scoped_pointer_backing(pointer,self.domain)?;
        self.install_pointer(dst,Some(pointer))
    }
    fn leave_pointer_frame(&mut self,fabric:&mut Fabric) -> Result<(),PointerMachineError> {
        let state=self.frame_current(fabric)?;
        let frame=state.active.last().ok_or(PointerMachineError::Frame(super::pointer_frames::FrameError::Control))?;
        if frame.call_depth!=self.return_stack.len() || !state.program.frames[frame.manifest].exits.contains(&(self.pc-state.code_base)) {
            return Err(PointerMachineError::Frame(super::pointer_frames::FrameError::Control));
        }
        fabric.retire_pointer_frame(frame.scope,&frame.locals)?;
        let frame=self.pointer_frames.as_mut().unwrap().active.pop().unwrap();
        self.pointer_frames.as_mut().unwrap().cursor=frame.parent_cursor;
        self.write_register(SP as usize,frame.parent_cursor);self.write_register(FP as usize,frame.parent_fp);
        self.write_register(LR as usize,frame.return_lr);
        Ok(())
    }
    /// Trusted death/unwind path also retires event-suspended allocations.
    pub(crate) fn retire_all_pointer_frames(&mut self,fabric:&mut Fabric) {
        if let Some(mut state)=self.pointer_frames.take() {
            while let Some(frame)=state.active.pop() { let _=fabric.retire_pointer_frame(frame.scope,&frame.locals); }
        }
        for saved in self.saved_event_contexts.iter_mut().rev() {
            if let Some(state)=saved.image.as_mut().and_then(|i| i.frames.take()) {
                for frame in state.active.iter().rev() { let _=fabric.retire_pointer_frame(frame.scope,&frame.locals); }
            }
        }
    }
    fn pointer_address(&self,fabric:&Fabric,start:u8,disp:i64,write:bool) -> Result<u64,PointerMachineError> {
        let pointer=self.authenticated_pointer(fabric,start)?.ok_or(PointerMachineError::MissingKind)?;
        let pointer=fabric.scoped_pointers.add(pointer,self.domain.0,disp).map_err(PointerMachineError::Pointer)?;
        let address=fabric.scoped_pointers.resolve(pointer,self.domain.0,16,write).map_err(PointerMachineError::Pointer)?;
        if self.checked_pointer_mapping(address,16)?!=fabric.scoped_pointer_backing(pointer,self.domain)? { return Err(PointerMachineError::Unmapped); }
        Ok(address)
    }
    fn pointer_fault(&self,error:PointerMachineError) -> StepResult {
        // Test diagnostics retain the cause before architectural fault conversion.
        // Guest-visible fault classification and transition semantics are unchanged.
        #[cfg(test)]
        eprintln!("protected pointer fault: pc={:#x}: {error}", self.pc);
        if let PointerMachineError::Fabric(fault)=error { return StepResult::Fault(fault); }
        StepResult::Fault(FaultRecord {agent:self.agent,domain:self.domain,privilege:self.privilege,
            transaction:TransactionId(0),object:ObjectId(0),generation:None,offset:self.pc,
            width:Width::Word,length:4,kind:AccessKind::Fetch,pc:Some(self.pc),reason:FaultReason::ControlFlowViolation})
    }

    fn pointer_pair_index(start: u8) -> Result<usize, PointerMachineError> {
        if start > 10 || start % 2 != 0 { return Err(PointerMachineError::InvalidPair); }
        Ok(start as usize / 2)
    }

    fn captured_pointer(&self, start: u8) -> Result<Option<super::scoped_pointers::ScopedPointer>, PointerMachineError> {
        let index = Self::pointer_pair_index(start)?;
        let words = [self.r[start as usize], self.r[start as usize + 1]];
        match self.pointer_pairs[index] {
            Some(pointer) if pointer.words() == words => Ok(Some(pointer)),
            None if words == [0, 0] => Ok(None),
            _ => Err(PointerMachineError::MissingKind),
        }
    }

    /// Trusted issuance/transport primitive; integer payloads cannot call this path.
    pub(crate) fn install_pointer(&mut self, start: u8, pointer: Option<super::scoped_pointers::ScopedPointer>) -> Result<(), PointerMachineError> {
        let index = Self::pointer_pair_index(start)?;
        self.enable_protected_context()?;
        let words = pointer.map(|p| p.words()).unwrap_or([0, 0]);
        self.r[start as usize] = words[0];
        self.r[start as usize + 1] = words[1];
        self.pointer_pairs[index] = pointer;
        Ok(())
    }

    /// Called by the trusted frame/allocation runtime, never by raw integer data.
    pub(crate) fn register_local_pointer(&mut self, fabric: &mut Fabric, scope: super::scoped_pointers::Scope,
        dst: u8, address: u64, length: u64, writable: bool) -> Result<(), PointerMachineError> {
        Self::pointer_pair_index(dst)?;
        // Reject profile upgrades before issuing any new allocation identity.
        if !self.protected_context_enabled && !self.event_frames.is_empty() { return Err(PointerMachineError::ContextMode); }
        let (object, offset) = self.checked_pointer_mapping(address, length)?;
        let mut request = self.make_request(object, offset, Width::Byte, AccessKind::Read);
        request.length = length;
        let pointer = fabric.register_scoped_pointer(scope, request, address, writable)?;
        self.install_pointer(dst, Some(pointer))
    }

    pub(crate) fn authenticated_pointer(&self, fabric: &Fabric, start: u8) -> Result<Option<super::scoped_pointers::ScopedPointer>, PointerMachineError> {
        let pointer = self.captured_pointer(start)?;
        if let Some(pointer) = pointer {
            self.check_application_pointer(fabric, pointer)?;
        }
        Ok(pointer)
    }

    pub(crate) fn pointer_move(&mut self, fabric: &Fabric, dst: u8, src: u8) -> Result<(), PointerMachineError> {
        Self::pointer_pair_index(dst)?;
        let captured = self.authenticated_pointer(fabric, src)?;
        self.install_pointer(dst, captured)
    }

    pub(crate) fn pointer_add(&mut self, fabric: &Fabric, dst: u8, src: u8, delta: i64) -> Result<(), PointerMachineError> {
        Self::pointer_pair_index(dst)?;
        let pointer = self.authenticated_pointer(fabric, src)?.ok_or(PointerMachineError::MissingKind)?;
        let pointer = self.add_application_pointer(fabric, pointer, delta)?;
        self.install_pointer(dst, Some(pointer))
    }

    fn checked_pointer_mapping(&self, address: u64, length: u64) -> Result<(ObjectId, u64), PointerMachineError> {
        let end = address.checked_add(length).filter(|_| length != 0).ok_or(PointerMachineError::Unmapped)?;
        let mut selected = None;
        for entry in &self.address_map.entries {
            let entry_end = entry.virt_base.checked_add(entry.size).ok_or(PointerMachineError::Unmapped)?;
            if address < entry_end && entry.virt_base < end {
                if selected.is_some() || address < entry.virt_base || end > entry_end { return Err(PointerMachineError::Unmapped); }
                let offset = entry.obj_offset.checked_add(address - entry.virt_base).ok_or(PointerMachineError::Unmapped)?;
                offset.checked_add(length).ok_or(PointerMachineError::Unmapped)?;
                selected = Some((entry.object, offset));
            }
        }
        selected.ok_or(PointerMachineError::Unmapped)
    }

    fn pointer_cell_request(&self, address: u64, kind: AccessKind) -> Result<MemoryRequest, PointerMachineError> {
        let (object, offset) = self.checked_pointer_mapping(address, 16)?;
        if offset % 16 != 0 { return Err(PointerMachineError::Unaligned); }
        let mut request = self.make_request(object, offset, Width::Double, kind);
        request.length = 16;
        Ok(request)
    }

    pub(crate) fn pointer_store(&self, fabric: &mut Fabric, src: u8, address: u64) -> Result<(), PointerMachineError> {
        let captured = self.authenticated_pointer(fabric, src)?;
        let request = self.pointer_cell_request(address, AccessKind::Write)?;
        if let Some(pointer) = captured.filter(|p| fabric.scoped_pointers.is_heap_pointer(*p)) {
            fabric.store_heap_token_in_local(request, self.heap_owner().map_err(PointerMachineError::Heap)?, pointer).map_err(PointerMachineError::Fabric)
        } else { fabric.store_pointer_cell(request, captured).map_err(PointerMachineError::Fabric) }
    }

    pub(crate) fn pointer_load(&mut self, fabric: &mut Fabric, dst: u8, address: u64) -> Result<(), PointerMachineError> {
        Self::pointer_pair_index(dst)?;
        let request = self.pointer_cell_request(address, AccessKind::Read)?;
        let pointer = fabric.load_pointer_cell(request).map_err(PointerMachineError::Fabric)?;
        if let Some(pointer) = pointer {
            self.check_application_pointer(fabric, pointer)?;
        }
        self.install_pointer(dst, pointer)
    }

    pub(crate) fn pointer_read(&mut self, fabric: &mut Fabric, start: u8, width: Width) -> Result<Vec<u8>, PointerMachineError> {
        let pointer = self.authenticated_pointer(fabric, start)?.ok_or(PointerMachineError::MissingKind)?;
        if fabric.scoped_pointers.is_heap_pointer(pointer) {
            let mut bytes=vec![0; width.bytes() as usize];
            fabric.read_heap_bytes(self.heap_owner().map_err(PointerMachineError::Heap)?,self.agent,pointer,&mut bytes).map_err(PointerMachineError::Heap)?;
            return Ok(bytes);
        }
        let address = fabric.scoped_pointers.resolve(pointer, self.domain.0, width.bytes(), false).map_err(PointerMachineError::Pointer)?;
        let (object, offset) = self.checked_pointer_mapping(address, width.bytes())?;
        if fabric.scoped_pointer_backing(pointer, self.domain)? != (object, offset) { return Err(PointerMachineError::Unmapped); }
        let request = self.make_request(object, offset, width, AccessKind::Read);
        fabric.execute_read(request).map_err(PointerMachineError::Fabric)
    }

    pub(crate) fn pointer_write(&self, fabric: &mut Fabric, start: u8, width: Width, data: Vec<u8>) -> Result<(), PointerMachineError> {
        let pointer = self.authenticated_pointer(fabric, start)?.ok_or(PointerMachineError::MissingKind)?;
        if fabric.scoped_pointers.is_heap_pointer(pointer) {
            if data.len() as u64 != width.bytes() { return Err(PointerMachineError::MissingKind); }
            return fabric.write_heap_bytes(self.heap_owner().map_err(PointerMachineError::Heap)?,self.agent,pointer,&data).map_err(PointerMachineError::Heap);
        }
        let address = fabric.scoped_pointers.resolve(pointer, self.domain.0, width.bytes(), true).map_err(PointerMachineError::Pointer)?;
        let (object, offset) = self.checked_pointer_mapping(address, width.bytes())?;
        if fabric.scoped_pointer_backing(pointer, self.domain)? != (object, offset) { return Err(PointerMachineError::Unmapped); }
        let request = self.make_request(object, offset, width, AccessKind::Write);
        fabric.execute_write(request, data).map_err(PointerMachineError::Fabric)
    }

    pub fn new(agent: AgentId, domain: DomainId) -> Self {
        Self {
            heap_owner: None,
            next_event_id: 1,
            r: [0; 16],
            context_id: fresh_context_id(),
            protected_context_enabled: false,
            saved_event_contexts: Vec::new(),
            pointer_pairs: [None; 6],
            pointer_frames: None,
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
    /// Protected mode restores words, kinds, flags and return authority, then
    /// overlays explicit scalar syscall results. Legacy register behavior remains.
    /// Owner/domain/depth/header/mode rejection preserves both image and frames.
    /// Returns Some(return_pc) and restores PC on success; None on rejection,
    /// including an empty stack (INT-5: ERET requires an outstanding event).
    pub fn event_return(&mut self) -> Option<u64> {
        // Peek -> validate -> consume. Rejection mutates neither image nor frames.
        let header = self.event_frames.last()?;
        let saved = self.saved_event_contexts.last()?;
        if self.event_frames.len() != self.saved_event_contexts.len()
            || saved.context_id != self.context_id || saved.domain != self.domain
            || saved.header != *header
            || self.protected_context_enabled != saved.image.is_some() {
            return None;
        }
        if self.pointer_frames.as_ref().is_some_and(|s| !s.active.is_empty()) { return None; }
        let saved = self.saved_event_contexts.pop().unwrap();
        let frame = self.event_frames.pop().unwrap();
        if let Some(image) = saved.image {
            self.r = image.words;
            self.pointer_pairs = image.kinds;
            self.flags = image.flags;
            self.return_stack = image.return_stack;
            self.pointer_frames = image.frames;
            self.halted = image.halted;
            if frame.cause == EventCause::Syscall {
                for (register, result) in saved.scalar_results.into_iter().enumerate() {
                    if let Some(value) = result { self.write_register(register, value); }
                }
            }
        }
        self.privilege = frame.return_privilege;
        self.interrupts_enabled = frame.interrupts_were_enabled;
        self.pc = frame.return_pc;
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

        self.enter_event(EventFrame {
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

        if self.pointer_frames.is_some() && matches!(insn.desc.semantics,Sem::Load|Sem::Store|Sem::LoadByte|Sem::StoreByte|Sem::Xchg) {
            return self.pointer_fault(PointerMachineError::ContextMode);
        }
        match insn.desc.semantics {
            Sem::PointerMove|Sem::PointerAdd|Sem::PointerLoad|Sem::PointerStore|Sem::PointerRead|Sem::PointerWrite|Sem::PointerFrame|Sem::PointerLocal|Sem::PointerUnframe => {
                if let Err(error)=self.frame_current(fabric) { return self.pointer_fault(error); }
                let result=(|| {
                    match insn.desc.semantics {
                        Sem::PointerMove=>self.pointer_move(fabric,insn.rd,insn.rs1),
                        Sem::PointerAdd=>self.pointer_add(fabric,insn.rd,insn.rs1,self.r[insn.rs2 as usize] as i64),
                        Sem::PointerLoad=>self.pointer_load_indirect(fabric,insn.rd,insn.rs1,insn.imm),
                        Sem::PointerStore=>self.pointer_store_indirect(fabric,insn.rd,insn.rs1,insn.imm),
                        Sem::PointerRead=> {
                            let width=match insn.raw&3 {0=>Width::Byte,1=>Width::Half,2=>Width::Word,_=>Width::Double};
                            let bytes=self.pointer_read(fabric,insn.rs1,width)?;
                            let mut word=[0u8;8];word[..bytes.len()].copy_from_slice(&bytes);
                            self.write_register(insn.rd as usize,u64::from_le_bytes(word));Ok(())
                        },
                        Sem::PointerWrite=> {
                            let width=match insn.raw&3 {0=>Width::Byte,1=>Width::Half,2=>Width::Word,_=>Width::Double};
                            let bytes=self.r[insn.rd as usize].to_le_bytes()[..width.bytes() as usize].to_vec();
                            self.pointer_write(fabric,insn.rs1,width,bytes)
                        },
                        Sem::PointerFrame=>self.enter_pointer_frame(fabric,insn.imm as usize),
                        Sem::PointerLocal=>self.lookup_pointer_local(fabric,insn.rd,insn.imm as usize),
                        Sem::PointerUnframe=>self.leave_pointer_frame(fabric),
                        _=>unreachable!(),
                    }
                })();
                if let Err(error)=result {return self.pointer_fault(error);}
            }
            // ─── ALU: register-register or register-immediate ───
            Sem::Alu(alu_op) => {
                let a = self.r[insn.rs1 as usize];
                let b = self.alu_operand_b(&insn);
                let result = Self::alu_eval(alu_op, a, b);
                self.write_register(insn.rd as usize, result);
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
            Sem::Mov  => { self.write_register(insn.rd as usize, self.r[insn.rs1 as usize]); }
            Sem::Movi => { self.write_register(insn.rd as usize, insn.imm as u64); }

            // ─── Memory (one transaction per instruction) ───────
            Sem::Load => {
                let addr = self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64);
                match self.fabric_read(fabric, addr, Width::Double, AccessKind::Read) {
                    Ok(bytes) => {
                        self.write_register(insn.rd as usize, u64::from_le_bytes(
                            [bytes[0], bytes[1], bytes[2], bytes[3],
                             bytes[4], bytes[5], bytes[6], bytes[7]]));
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
            Sem::LoadByte | Sem::StoreByte => {
                let kind = if insn.desc.semantics == Sem::LoadByte { AccessKind::Read } else { AccessKind::Write };
                let request = match self.byte_request(self.r[insn.rs1 as usize], insn.imm, kind) {
                    Ok(request) => request,
                    Err(fault) => return StepResult::Fault(fault),
                };
                if kind == AccessKind::Read {
                    match fabric.execute_read(request) {
                        Ok(bytes) => self.write_register(insn.rd as usize, u64::from(bytes[0])),
                        Err(fault) => return StepResult::Fault(fault),
                    }
                } else {
                    let data = vec![self.r[insn.rd as usize] as u8];
                    if let Err(fault) = fabric.execute_write(request, data) {
                        return StepResult::Fault(fault);
                    }
                }
            }
            Sem::Lea => {
                self.write_register(insn.rd as usize,
                    self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64));
            }
            Sem::Xchg => {
                let addr = self.r[insn.rs1 as usize].wrapping_add(insn.imm as u64);
                let new_val = self.r[insn.rd as usize].to_le_bytes().to_vec();
                match self.fabric_atomic_xchg(fabric, addr, Width::Double, new_val) {
                    Ok(old_bytes) => {
                        self.write_register(insn.rd as usize, u64::from_le_bytes(
                            [old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3],
                             old_bytes[4], old_bytes[5], old_bytes[6], old_bytes[7]]));
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
                if let Some(state)=&self.pointer_frames {
                    let target=(self.pc as i128)+(insn.imm as i128)*4;
                    if !state.program.frames.iter().any(|f| (state.code_base+f.entry) as i128==target) {
                        return self.pointer_fault(PointerMachineError::Frame(super::pointer_frames::FrameError::Control));
                    }
                }
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
                self.write_register(LR as usize, return_addr);
                self.return_stack.push(ReturnAuthority {
                    code_object: code_obj,
                    generation: obj_gen,
                    target: return_addr,
                });
                next_pc = (self.pc as i64 + insn.imm * 4) as u64;
                if let Some(state)=self.pointer_frames.as_mut() { state.pending_entry=Some(next_pc); }
            }
            Sem::Ret => {
                if self.pointer_frames.as_ref().is_some_and(|s| s.active.iter().any(|f| f.call_depth==self.return_stack.len())) {
                    return self.pointer_fault(PointerMachineError::Frame(super::pointer_frames::FrameError::Control));
                }
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
                self.enter_event(EventFrame {
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

    /// Resolve only the operand byte; no enclosing-word read or wrapping address.
    fn byte_request(&self, base: u64, displacement: i64, kind: AccessKind) -> Result<MemoryRequest, FaultRecord> {
        let address = base.checked_add_signed(displacement);
        let resolved = address.and_then(|addr| {
            let mut selected = None;
            for entry in &self.address_map.entries {
                if let Some(relative) = addr.checked_sub(entry.virt_base) {
                    if relative < entry.size {
                        if selected.is_some() { return None; }
                        selected = Some((entry.object, entry.obj_offset.checked_add(relative)?));
                    }
                }
            }
            selected
        });
        let (object, offset) = resolved.ok_or_else(|| FaultRecord {
            agent: self.agent, domain: self.domain, privilege: self.privilege,
            transaction: TransactionId(0), object: ObjectId(0), generation: None,
            offset: address.unwrap_or(base), width: Width::Byte, length: 1,
            kind, pc: Some(self.pc), reason: FaultReason::TranslationFault,
        })?;
        Ok(self.make_request(object, offset, Width::Byte, kind))
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


    pub(super) fn protected_frame_fixture() -> (Fabric,Anka64Core,usize) {
        use super::super::pointer_frames::*;
        let (mut fabric,text,_,domain,mut core)=setup();
        let mut asm=Asm64::new();
        asm.pframe(0);asm.plocal(R4,0);asm.movi(R12,42);asm.pwrite(R12,R4,1);
        asm.plocal(R8,1);asm.pstore(R4,R8,0);asm.pload(R0,R8,0);
        let call=asm.here();asm.call(0);
        asm.pmov(R4,R0);asm.pread(R12,R4,1);
        let exit0=asm.here() as u64*4;asm.punframe();asm.ret();
        let entry1=asm.here() as u64*4;
        asm.words_mut()[call as usize]=(0x32u32<<26)|((entry1 as i32/4-call) as u32&0x3fffff);
        asm.pframe(1);asm.plocal(R8,0);asm.pstore(R0,R8,0);asm.pload(R4,R8,0);asm.pmov(R0,R4);
        let exit1=asm.here() as u64*4;asm.punframe();asm.ret();
        let bytes=asm.to_bytes();
        let program=ValidatedPointerProgram::validate(&bytes,vec![
            FrameManifest{entry:0,end:entry1,size:32,exits:vec![exit0],locals:vec![
                LocalStorage{offset:0,length:4,alignment:1,writable:true,pointer_slot:false},
                LocalStorage{offset:16,length:16,alignment:16,writable:true,pointer_slot:true}]},
            FrameManifest{entry:entry1,end:bytes.len() as u64,size:16,exits:vec![exit1],locals:vec![
                LocalStorage{offset:0,length:16,alignment:16,writable:true,pointer_slot:true}]}]).unwrap();
        load_program(&mut fabric,&asm);seal_text(&mut fabric,text,domain);
        fabric.register_agent(core.agent,AgentKind::Cpu(CoreId(0)),domain);
        core.admit_pointer_program(&mut fabric,program,0,0x8000,0x9000).unwrap();
        (fabric,core,exit0 as usize/4)
    }

    #[test]
    fn p108_input_span_requires_writable_descriptor_even_for_empty_range() {
        let (mut fabric, _, _, _, mut core) = setup();
        fabric.register_agent(core.agent, AgentKind::Cpu(CoreId(0)), core.domain);
        let scope = fabric.scoped_pointers.enter_scope_for(core.context_id).unwrap();
        core.register_local_pointer(&mut fabric, scope, R2, 0x8000, 4, false).unwrap();
        let pointer = core.captured_pointer(R2).unwrap().unwrap();
        assert!(core.syscall_read_span(&fabric, pointer, 0).is_ok());
        assert!(core.syscall_write_span(&fabric, pointer, 0).is_err());
        assert!(core.syscall_write_span(&fabric, pointer, 1).is_err());
    }

    #[test]
    fn p108_syscall_range_rejects_foreign_owner_and_stale_zero_length() {
        let (mut fabric, _, _, _, mut core) = setup();
        fabric.register_agent(core.agent, AgentKind::Cpu(CoreId(0)), core.domain);
        let foreign = fabric.scoped_pointers.enter_scope_for(core.context_id + 1).unwrap();
        core.register_local_pointer(&mut fabric, foreign, R2, 0x8000, 4, true).unwrap();
        let p = core.captured_pointer(R2).unwrap().unwrap();
        assert!(core.syscall_read_span(&fabric, p, 0).is_err());
        fabric.scoped_pointers.leave_scope(foreign).unwrap();
        let own = fabric.scoped_pointers.enter_scope_for(core.context_id).unwrap();
        core.register_local_pointer(&mut fabric, own, R2, 0x8000, 4, true).unwrap();
        let p = core.captured_pointer(R2).unwrap().unwrap();
        let end = fabric.scoped_pointers.add(p, core.domain.0, 4).unwrap();
        assert!(core.syscall_read_span(&fabric, end, 0).is_ok());
        assert!(core.syscall_read_span(&fabric, end, 1).is_err());
        fabric.scoped_pointers.leave_scope(own).unwrap();
        assert!(core.syscall_read_span(&fabric, end, 0).is_err());
    }

    #[test]
    fn p107_encoded_frames_transport_call_spill_and_retire_escape() {
        let (mut fabric,mut core,exit)=protected_frame_fixture();
        while core.pc!=(exit as u64)*4 {
            assert!(matches!(core.step(&mut fabric),StepResult::Continue),"pc={}",core.pc);
        }
        assert_eq!(core.r[R12 as usize],42);
        assert_eq!(core.pointer_frames.as_ref().unwrap().active.len(),1);
        let escaped=core.captured_pointer(R4).unwrap().unwrap();
        assert!(matches!(core.step(&mut fabric),StepResult::Continue));
        assert!(core.pointer_frames.as_ref().unwrap().active.is_empty());
        assert_eq!(core.r[SP as usize],0x9000);
        assert!(fabric.scoped_pointer_backing(escaped,core.domain).is_err());
        assert!(core.pointer_read(&mut fabric,R4,Width::Byte).is_err());
    }
    #[test]
    fn p107_frame_event_image_restores_cursor_and_scope_ownership() {
        let (mut fabric,mut core,_)=protected_frame_fixture();
        assert!(matches!(core.step(&mut fabric),StepResult::Continue));
        let cursor=core.pointer_frames.as_ref().unwrap().cursor;
        core.enter_event(EventFrame{return_pc:4,return_privilege:Privilege::User,
            interrupts_were_enabled:true,cause:EventCause::TimerInterrupt});
        assert!(core.pointer_frames.is_none());
        assert!(core.enter_pointer_frame(&mut fabric,0).is_err());
        assert_eq!(core.event_return(),Some(4));
        assert_eq!(core.pointer_frames.as_ref().unwrap().cursor,cursor);
        assert!(core.lookup_pointer_local(&fabric,R4,0).is_ok());
        core.retire_all_pointer_frames(&mut fabric);
        assert!(core.pointer_read(&mut fabric,R4,Width::Byte).is_err());
    }
    #[test]
    fn p107_frame_capacity_failure_and_duplicate_entry_are_atomic() {
        let (mut fabric,mut core,_)=protected_frame_fixture();
        fabric.scoped_pointers=super::super::scoped_pointers::ScopedPointers::new(1);
        let words=core.r;
        assert!(core.enter_pointer_frame(&mut fabric,0).is_err());
        assert_eq!(core.r,words);assert!(core.pointer_frames.as_ref().unwrap().active.is_empty());
        fabric.scoped_pointers=super::super::scoped_pointers::ScopedPointers::new(4);
        core.enter_pointer_frame(&mut fabric,0).unwrap();
        let cursor=core.pointer_frames.as_ref().unwrap().cursor;
        assert!(core.enter_pointer_frame(&mut fabric,0).is_err());
        assert_eq!(core.pointer_frames.as_ref().unwrap().cursor,cursor);
    }
    #[test]
    fn p107_interleaved_context_frames_do_not_share_lifo_order() {
        let mut pointers=super::super::scoped_pointers::ScopedPointers::new(8);
        let a=pointers.enter_scope_for(7).unwrap();let b=pointers.enter_scope_for(8).unwrap();
        let p=pointers.register(a,1,100,4,true).unwrap();
        let q=pointers.register(b,2,200,4,true).unwrap();
        pointers.leave_scope(a).unwrap();
        assert!(pointers.resolve(p,1,1,false).is_err());
        assert_eq!(pointers.resolve(q,2,1,false),Ok(200));
        pointers.leave_scope(b).unwrap();
    }
    #[test]
    fn p107_manifest_and_pointer_word_hostile_cases_reject() {
        use super::super::pointer_frames::*;
        let mut asm=Asm64::new();asm.pframe(0);asm.punframe();asm.ret();
        let bytes=asm.to_bytes();
        let good=FrameManifest{entry:0,end:12,size:32,exits:vec![4],locals:vec![LocalStorage{
            offset:0,length:16,alignment:16,writable:true,pointer_slot:true}]};
        assert!(ValidatedPointerProgram::validate(&bytes,vec![good.clone()]).is_ok());
        let mut bad=good.clone();bad.locals.push(bad.locals[0].clone());
        assert!(ValidatedPointerProgram::validate(&bytes,vec![bad]).is_err());
        let mut bad=good.clone();bad.locals[0].offset=24;
        assert!(ValidatedPointerProgram::validate(&bytes,vec![bad]).is_err());
        let mut bad=good.clone();bad.exits=vec![8];
        assert!(ValidatedPointerProgram::validate(&bytes,vec![bad]).is_err());
        for word in [(0x26<<26)|(1<<22),(0x26<<26)|1,(0x2a<<26)|4,(0x2e<<26)|1,(0x2d<<26)|(1<<17)] {
            assert!(decode(word).is_illegal());
        }
    }

    #[test]
    fn p107_frame_binding_rejects_context_change_and_shared_stack() {
        let (mut fabric,mut core,_)=protected_frame_fixture();
        assert!(!fabric.protect_pointer_stack(core.address_map.resolve(0x8000).unwrap().0,core.context_id+1,core.domain));
        let prior=core.context_id;core.context_id+=1;
        let registers=core.r;
        assert!(core.enter_pointer_frame(&mut fabric,0).is_err());
        assert_eq!(core.r,registers);
        core.context_id=prior;
        assert!(core.enter_pointer_frame(&mut fabric,0).is_ok());
    }

    fn pointer_fixture() -> (Fabric, Anka64Core, super::super::scoped_pointers::Scope) {
        let (mut fabric, _, _, _, mut core) = setup();
        let scope = fabric.scoped_pointers.enter_scope().unwrap();
        core.register_local_pointer(&mut fabric, scope, R4, 0x8100, 4, true).unwrap();
        (fabric, core, scope)
    }

    #[test]
    fn p107_protected_pointer_transport_traverses_spills_and_rejects_escape() {
        use super::super::scoped_pointers::PointerError;
        let (mut fabric, mut core, scope) = pointer_fixture();
        // Simulate typed argument transport and a live-pointer spill across a call.
        core.pointer_move(&fabric, R0, R4).unwrap();
        core.pointer_store(&mut fabric, R0, 0x8000).unwrap();
        for i in 0..4 {
            core.pointer_add(&fabric, R2, R0, i).unwrap();
            core.pointer_write(&mut fabric, R2, Width::Byte, vec![10 + i as u8]).unwrap();
            assert_eq!(core.pointer_read(&mut fabric, R2, Width::Byte).unwrap(), vec![10 + i as u8]);
        }
        core.pointer_add(&fabric, R2, R0, 4).unwrap();
        let before = core.r;
        assert!(matches!(core.pointer_read(&mut fabric, R2, Width::Byte), Err(PointerMachineError::Pointer(PointerError::Bounds))));
        assert!(matches!(core.pointer_add(&fabric, R2, R0, 5), Err(PointerMachineError::Pointer(PointerError::Bounds))));
        assert_eq!(core.r, before);
        core.write_register(R0 as usize, 99);
        core.pointer_load(&mut fabric, R4, 0x8000).unwrap();
        assert_eq!(core.pointer_read(&mut fabric, R4, Width::Byte).unwrap(), vec![10]);
        fabric.scoped_pointers.leave_scope(scope).unwrap();
        let before = core.r;
        assert!(matches!(core.pointer_load(&mut fabric, R4, 0x8000), Err(PointerMachineError::Pointer(PointerError::Stale))));
        assert_eq!(core.r, before);
    }

    #[test]
    fn p107_raw_register_write_cannot_preserve_or_forge_kind() {
        let (fabric, mut core, _) = pointer_fixture();
        let words = [core.r[R4 as usize], core.r[R5 as usize]];
        core.write_register(R5 as usize, words[1]);
        assert!(matches!(core.pointer_move(&fabric, R0, R4), Err(PointerMachineError::MissingKind)));
        core.write_register(R4 as usize, words[0]);
        assert!(matches!(core.pointer_move(&fabric, R0, R4), Err(PointerMachineError::MissingKind)));
        assert!(matches!(core.pointer_move(&fabric, R13, R4), Err(PointerMachineError::InvalidPair)));
    }

    #[test]
    fn p107_raw_memory_alias_write_clears_kind_and_failed_write_preserves_it() {
        let (mut fabric, mut core, _) = pointer_fixture();
        core.pointer_store(&mut fabric, R4, 0x8000).unwrap();
        let (object, _) = core.address_map.resolve(0x8000).unwrap();
        core.address_map.add(0xa000, 0x1000, object);
        core.pointer_load(&mut fabric, R0, 0xa000).unwrap();
        // Failed payload-length validation must not clear the existing cell kind.
        let req = core.make_request(object, 0, Width::Double, AccessKind::Write);
        assert!(fabric.execute_write(req, vec![0; 7]).is_err());
        core.pointer_load(&mut fabric, R0, 0x8000).unwrap();
        // Even an unchanged byte write through an alias destroys pointer kind.
        let byte = core.r[R4 as usize].to_le_bytes()[0];
        core.fabric_write(&mut fabric, 0xa000, Width::Byte, vec![byte]).unwrap();
        let before = core.r;
        assert!(matches!(core.pointer_load(&mut fabric, R0, 0x8000), Err(PointerMachineError::Fabric(_))));
        assert_eq!(core.r, before);
    }


    #[test]
    fn p107_encoded_cmp_preserves_kind_and_mov_clears_it() {
        let (mut fabric, text, _, dom, mut core) = setup();
        let scope = fabric.scoped_pointers.enter_scope().unwrap();
        core.register_local_pointer(&mut fabric, scope, R4, 0x8100, 4, true).unwrap();
        let mut asm = Asm64::new();
        asm.cmp(R4, R4);
        asm.mov(R5, R5);
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, text, dom);
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        core.pointer_move(&fabric, R0, R4).unwrap();
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        assert!(matches!(core.pointer_move(&fabric, R0, R4), Err(PointerMachineError::MissingKind)));
    }

    #[test]
    fn p107_dma_span_atomic_and_bootstrap_writes_invalidate_pointer_cells() {
        let (mut fabric, mut core, _) = pointer_fixture();
        let (object, _) = core.address_map.resolve(0x8000).unwrap();
        core.pointer_store(&mut fabric, R4, 0x8000).unwrap();
        core.pointer_store(&mut fabric, R4, 0x8010).unwrap();
        let mut request = core.make_request(object, 15, Width::Byte, AccessKind::Write);
        request.length = 2;
        request.context.agent = DMA0;
        fabric.register_agent(DMA0, AgentKind::Dma, core.domain);
        fabric.execute_write(request, vec![0, core.r[R4 as usize] as u8]).unwrap();
        for address in [0x8000, 0x8010] {
            assert!(matches!(core.pointer_load(&mut fabric, R0, address), Err(PointerMachineError::Fabric(f)) if f.reason == FaultReason::NoCapability));
        }
        core.pointer_store(&mut fabric, R4, 0x8000).unwrap();
        let mut request = core.make_request(object, 0, Width::Double, AccessKind::Atomic);
        fabric.grant(core.domain, object, 0, 0x1000, Permissions::ATOMIC);
        request.kind = AccessKind::Atomic;
        fabric.execute_atomic_xchg(request, core.r[R4 as usize].to_le_bytes().to_vec()).unwrap();
        assert!(core.pointer_load(&mut fabric, R0, 0x8000).is_err());
        core.pointer_store(&mut fabric, R4, 0x8000).unwrap();
        fabric.write_physical(0x10000, &core.r[R4 as usize].to_le_bytes());
        assert!(core.pointer_load(&mut fabric, R0, 0x8000).is_err());
        core.pointer_store(&mut fabric, R4, 0x8000).unwrap();
        assert!(fabric.initialize_object(object, 0, &core.r[R4 as usize].to_le_bytes()));
        assert!(core.pointer_load(&mut fabric, R0, 0x8000).is_err());
    }

    #[test]
    fn p107_pointer_backing_regrant_does_not_revive_old_identity() {
        use super::super::scoped_pointers::PointerError;
        let (mut fabric, mut core, _) = pointer_fixture();
        let (object, _) = core.address_map.resolve(0x8100).unwrap();
        fabric.revoke(object);
        fabric.objects.get_mut(&object).unwrap().state = ObjectState::Active;
        fabric.grant(core.domain, object, 0, 0x1000, Permissions::RW);
        assert!(matches!(core.pointer_read(&mut fabric, R4, Width::Byte), Err(PointerMachineError::Pointer(PointerError::Stale))));
    }

    #[test]
    fn p107_pointer_null_transport_and_denied_issuance_are_atomic() {
        let (mut fabric, mut core, scope) = pointer_fixture();
        core.pointer_move(&fabric, R0, R2).unwrap();
        core.pointer_store(&mut fabric, R0, 0x8000).unwrap();
        core.pointer_load(&mut fabric, R2, 0x8000).unwrap();
        assert!(matches!(core.pointer_read(&mut fabric, R2, Width::Byte), Err(PointerMachineError::MissingKind)));
        let words = core.r;
        fabric.domains.get_mut(&core.domain).unwrap().capabilities.clear();
        assert!(core.register_local_pointer(&mut fabric, scope, R4, 0x8200, 4, true).is_err());
        assert_eq!(core.r, words);
    }


    #[test]
    fn p107_pointer_cells_reject_ambiguous_mapping_without_destination_mutation() {
        let (mut fabric, mut core, _) = pointer_fixture();
        core.pointer_store(&mut fabric, R4, 0x8000).unwrap();
        let (object, _) = core.address_map.resolve(0x8000).unwrap();
        core.address_map.add_at(0x8008, 8, object, 8);
        let before = core.r;
        assert!(matches!(core.pointer_load(&mut fabric, R0, 0x8000), Err(PointerMachineError::Unmapped)));
        assert_eq!(core.r, before);
    }

    fn syscall_frame(core: &Anka64Core) -> EventFrame {
        EventFrame { return_pc: core.pc + 4, return_privilege: core.privilege,
            interrupts_were_enabled: core.interrupts_enabled, cause: EventCause::Syscall }
    }

    #[test]
    fn p107_event_irq_restores_complete_image_and_discards_handler_authority() {
        let (mut fabric, mut core, scope) = pointer_fixture();
        core.pc = 0x400;
        core.trap_vector = 0x900;
        core.write_register(FP as usize, 0x8880);
        core.write_register(SP as usize, 0x8900);
        core.flags = Flags { z: true, n: false, c: true, v: false };
        core.return_stack.push(ReturnAuthority { code_object: ObjectId(99), generation: Generation(2), target: 0x44 });
        let user = core.r;
        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        assert!(core.return_stack.is_empty());
        assert!(matches!(core.pointer_move(&fabric, R0, R4), Err(PointerMachineError::MissingKind)));
        core.register_local_pointer(&mut fabric, scope, R6, 0x8200, 4, true).unwrap();
        core.write_syscall_result(R4 as usize, 123); // IRQ must not export this.
        core.write_register(SP as usize, 0x8000);
        core.flags = Flags::default();
        core.return_stack.push(ReturnAuthority { code_object: ObjectId(100), generation: Generation(3), target: 0x88 });
        core.post_device_interrupt();
        assert_eq!(core.event_return(), Some(0x400));
        assert_eq!(core.pc, 0x400);
        assert_eq!(core.r, user);
        assert!(core.flags.z && core.flags.c && !core.flags.n && !core.flags.v);
        assert_eq!(core.return_stack.len(), 1);
        assert_eq!(core.return_stack[0].target, 0x44);
        assert_eq!(core.privilege, Privilege::User);
        assert!(core.interrupts_enabled && core.pending.device);
        assert_eq!(core.pointer_read(&mut fabric, R4, Width::Byte).unwrap(), vec![0]);
        assert!(core.pointer_pairs[R6 as usize / 2].is_none());
    }

    #[test]
    fn p107_event_syscall_exports_only_explicit_scalars_and_clears_pair_kind() {
        let (fabric, mut core, _) = pointer_fixture();
        core.pointer_move(&fabric, R0, R4).unwrap();
        let user = core.r;
        core.enter_event(syscall_frame(&core));
        core.write_register(R8 as usize, 777); // Handler scratch is not a result.
        core.write_syscall_result(R1 as usize, user[R1 as usize]); // Same bits still clear kind.
        core.write_syscall_result(FP as usize, 123); // Reserved lanes cannot be exported.
        assert_eq!(core.event_return(), Some(4));
        assert_eq!(core.r, user);
        assert!(matches!(core.pointer_move(&fabric, R2, R0), Err(PointerMachineError::MissingKind)));
        core.pointer_move(&fabric, R2, R4).unwrap();
    }

    #[test]
    fn p107_event_nested_interrupt_restores_handler_then_user_image() {
        let (fabric, mut core, _) = pointer_fixture();
        core.pc = 0x400;
        core.trap_vector = 0x900;
        let user = core.r;
        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        let pointer = core.saved_event_contexts[0].image.as_ref().unwrap().kinds[2];
        core.install_pointer(R6, pointer).unwrap(); // Trusted handler-local protected value.
        core.pc = 0x920;
        core.interrupts_enabled = true;
        let handler = core.r;
        core.post_device_interrupt();
        assert!(core.deliver_pending());
        core.write_register(R7 as usize, 444);
        assert_eq!(core.event_frames.len(), 2);
        assert_eq!(core.event_return(), Some(0x920));
        assert_eq!(core.r, handler);
        assert_eq!(core.privilege, Privilege::Supervisor);
        core.pointer_move(&fabric, R0, R6).unwrap();
        assert_eq!(core.event_return(), Some(0x400));
        assert_eq!(core.r, user);
        core.pointer_move(&fabric, R0, R4).unwrap();
    }

    #[test]
    fn p107_event_wrong_domain_tampered_header_and_replay_are_no_ops() {
        let (_, mut core, _) = pointer_fixture();
        core.pc = 0x400;
        core.trap_vector = 0x900;
        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        let domain = core.domain;
        let header = core.event_frames[0].clone();
        let words = core.r;
        core.domain = DomainId(domain.0 + 1);
        assert_eq!(core.event_return(), None);
        assert_eq!(core.r, words);
        assert_eq!(core.event_frames.len(), 1);
        assert_eq!(core.saved_event_contexts.len(), 1);
        assert_eq!(core.pc, 0x900);
        core.domain = domain;
        core.event_frames[0].return_pc += 4;
        assert_eq!(core.event_return(), None);
        assert_eq!(core.event_frames.len(), 1);
        core.event_frames[0] = header.clone();
        assert_eq!(core.event_return(), Some(0x400));
        core.event_frames.push(header); // Public header alone cannot restore authority.
        let kinds = core.pointer_pairs;
        assert_eq!(core.event_return(), None);
        assert_eq!(core.pointer_pairs, kinds);
        assert_eq!(core.event_frames.len(), 1);
    }

    #[test]
    fn p107_event_context_identity_rejects_other_thread_but_allows_cpu_migration() {
        let (_, mut core, _) = pointer_fixture();
        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        let mut other = Anka64Core::new(core.agent, core.domain);
        other.enable_protected_context().unwrap();
        other.event_frames = core.event_frames.clone();
        other.saved_event_contexts = core.saved_event_contexts.clone();
        assert_eq!(other.event_return(), None);
        assert_eq!(other.event_frames.len(), 1);
        core.agent = AgentId(42); // Physical agent changes, execution context does not.
        assert_eq!(core.event_return(), Some(0));
    }

    #[test]
    fn p107_event_restore_does_not_revive_expired_allocation() {
        use super::super::scoped_pointers::PointerError;
        let (mut fabric, mut core, scope) = pointer_fixture();
        core.post_timer_interrupt();
        assert!(core.deliver_pending());
        fabric.scoped_pointers.leave_scope(scope).unwrap();
        assert_eq!(core.event_return(), Some(0));
        assert!(matches!(core.pointer_read(&mut fabric, R4, Width::Byte), Err(PointerMachineError::Pointer(PointerError::Stale))));
    }

    #[test]
    fn p107_event_rejects_profile_upgrade_before_issuing_local_pointer() {
        let (mut fabric, _, _, _, mut core) = setup();
        let scope = fabric.scoped_pointers.enter_scope().unwrap();
        core.enter_event(syscall_frame(&core));
        let words = core.r;
        assert!(matches!(core.register_local_pointer(&mut fabric, scope, R4, 0x8100, 4, true), Err(PointerMachineError::ContextMode)));
        assert_eq!(core.r, words);
        assert_eq!(core.event_return(), Some(4));
        core.register_local_pointer(&mut fabric, scope, R4, 0x8100, 4, true).unwrap();
        assert_eq!(core.r[R4 as usize], 0x1_0000_0001);
    }

    #[test]
    fn p107_event_encoded_trap_eret_restore_pointer_and_fault_without_pop() {
        let (mut fabric, text, _, dom, mut core) = setup();
        let scope = fabric.scoped_pointers.enter_scope().unwrap();
        core.register_local_pointer(&mut fabric, scope, R4, 0x8100, 4, true).unwrap();
        let user = core.r;
        let mut asm = Asm64::new();
        asm.trap(0); asm.halt();
        while asm.here() < 64 { asm.nop(); }
        asm.movi(R4, 99); asm.eret();
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, text, dom);
        core.trap_vector = 0x100;
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        core.event_frames[0].return_pc = 8;
        let words = core.r;
        assert!(matches!(core.step(&mut fabric), StepResult::Fault(f) if f.reason == FaultReason::ControlFlowViolation));
        assert_eq!(core.r, words);
        assert_eq!(core.event_frames.len(), 1);
        core.event_frames[0].return_pc = 4;
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        assert_eq!(core.pc, 4);
        assert_eq!(core.r, user);
        core.pointer_move(&fabric, R0, R4).unwrap();
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

    fn byte_fixture(store: bool, permission: Permissions, offset: u64, length: u64)
        -> (Fabric, ObjectId, DomainId, Anka64Core) {
        let (mut fabric, text, data, dom, mut core) = setup();
        fabric.domains.get_mut(&dom).unwrap().capabilities.clear();
        fabric.grant(dom, data, offset, length, permission);
        fabric.write_physical(0x10000, &[0x11, 0x22, 0x33]);
        fabric.write_physical(0x10fff, &[0xff]);
        let mut asm = Asm64::new();
        if store { asm.stb(R0, R1, 0); } else { asm.ldb(R0, R1, 0); }
        load_program(&mut fabric, &asm);
        seal_text(&mut fabric, text, dom);
        core.r[R0 as usize] = 0x1ab;
        core.r[R1 as usize] = 0x8000 + offset;
        (fabric, data, dom, core)
    }

    #[test]
    fn p107_byte_load_last_authorized_byte_zero_extends_exact_transaction() {
        let (mut fabric, data, _, mut core) = byte_fixture(false, Permissions::READ, 0xfff, 1);
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        assert_eq!(core.r[R0 as usize], 255);
        let tx = fabric.transaction(1);
        assert_eq!(tx.request.object, data);
        assert_eq!(tx.request.offset, 0xfff);
        assert_eq!(tx.request.width, Width::Byte);
        assert_eq!(tx.request.length, 1);
        assert_eq!(tx.read_data.as_deref(), Some(&[0xff][..]));
        assert_eq!(tx.state, TxState::Committed);
    }

    #[test]
    fn p107_byte_store_write_only_truncates_and_preserves_neighbors() {
        let (mut fabric, data, _, mut core) = byte_fixture(true, Permissions::WRITE, 1, 1);
        assert!(matches!(core.step(&mut fabric), StepResult::Continue));
        assert_eq!(fabric.read_physical(0x10000, 3), &[0x11, 0xab, 0x33]);
        let tx = fabric.transaction(1);
        assert_eq!(tx.request.object, data);
        assert_eq!(tx.request.offset, 1);
        assert_eq!(tx.request.length, 1);
        assert_eq!(tx.request.width, Width::Byte);
        assert_eq!(tx.write_data.as_deref(), Some(&[0xab][..]));
        assert!(tx.read_data.is_none());
        assert_eq!(tx.state, TxState::Committed);
    }

    #[test]
    fn p107_byte_denied_load_and_store_leave_state_and_no_prepared_data() {
        for store in [false, true] {
            let permission = if store { Permissions::READ } else { Permissions::WRITE };
            let (mut fabric, _, _, mut core) = byte_fixture(store, permission, 1, 1);
            assert!(matches!(core.step(&mut fabric), StepResult::Fault(_)));
            assert_eq!(core.r[R0 as usize], 0x1ab);
            assert_eq!(fabric.read_physical(0x10000, 3), &[0x11, 0x22, 0x33]);
            let tx = fabric.transaction(1);
            assert_eq!(tx.state, TxState::Faulted);
            assert!(tx.read_data.is_none());
            assert!(tx.physical_address.is_none());
        }
    }

    #[test]
    fn p107_byte_stale_generation_faults_before_backing_read() {
        let (mut fabric, data, _, mut core) = byte_fixture(false, Permissions::READ, 1, 1);
        fabric.objects.get_mut(&data).unwrap().generation.0 += 1;
        assert!(matches!(core.step(&mut fabric), StepResult::Fault(_)));
        assert_eq!(core.r[R0 as usize], 0x1ab);
        let tx = fabric.transaction(1);
        assert_eq!(tx.state, TxState::Faulted);
        assert!(tx.physical_address.is_none());
        assert!(tx.read_data.is_none());
    }

    #[test]
    fn p107_byte_capability_bound_and_one_past_mapping_reject() {
        let (mut fabric, _, _, mut core) = byte_fixture(true, Permissions::WRITE, 1, 1);
        core.r[R1 as usize] = 0x8002;
        assert!(matches!(core.step(&mut fabric), StepResult::Fault(_)));
        assert_eq!(fabric.read_physical(0x10000, 3), &[0x11, 0x22, 0x33]);
        assert!(fabric.transaction(1).physical_address.is_none());
        let (mut fabric, _, _, mut core) = byte_fixture(false, Permissions::READ, 0xfff, 1);
        core.r[R1 as usize] = 0x9000;
        assert!(matches!(core.step(&mut fabric), StepResult::Fault(_)));
        assert_eq!(core.r[R0 as usize], 0x1ab);
    }

    #[test]
    fn p107_byte_address_arithmetic_rejects_overflow_and_underflow() {
        let (_, _, _, _, core) = setup();
        assert!(core.byte_request(u64::MAX, 1, AccessKind::Read).is_err());
        assert!(core.byte_request(0, -1, AccessKind::Write).is_err());
        let req = core.byte_request(0x8001, -1, AccessKind::Write).unwrap();
        assert_eq!(req.offset, 0);
        assert_eq!(req.length, 1);
    }

    #[test]
    fn p107_byte_ambiguous_mapping_and_object_offset_overflow_reject() {
        let (_, _, data, _, mut core) = setup();
        core.address_map.add(0x8000, 1, data);
        assert!(core.byte_request(0x8000, 0, AccessKind::Read).is_err());
        let (_, _, data, _, mut core) = setup();
        core.address_map.add_at(0x20000, 2, data, u64::MAX);
        assert!(core.byte_request(0x20001, 0, AccessKind::Write).is_err());
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

#[cfg(test)]
mod local_initialization_tests;

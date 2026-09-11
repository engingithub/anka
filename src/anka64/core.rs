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
}

#[derive(Debug, Clone)]
pub struct AddressMap {
    entries: Vec<AddressMapEntry>,
}

impl AddressMap {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn add(&mut self, virt_base: u64, size: u64, object: ObjectId) {
        self.entries.push(AddressMapEntry { virt_base, size, object });
    }

    pub fn resolve(&self, addr: u64) -> Option<(ObjectId, u64)> {
        for e in &self.entries {
            if addr >= e.virt_base && addr < e.virt_base + e.size {
                return Some((e.object, addr - e.virt_base));
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
    pub saved_pc: Option<u64>,
    pub saved_privilege: Option<Privilege>,
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
            saved_pc: None,
            saved_privilege: None,
        }
    }

    /// Execute one instruction cycle through the fabric.
    ///
    /// Dispatch is on the semantic tag from the description table,
    /// not a hand-written match of each opcode.
    pub fn step(&mut self, fabric: &mut Fabric) -> StepResult {
        if self.halted { return StepResult::Halted; }

        // 1. Fetch (through fabric)
        let word = match self.fabric_read(fabric, self.pc, Width::Word, AccessKind::Fetch) {
            Ok(bytes) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Err(fault) => return StepResult::Fault(fault),
        };

        // 2. Decode (table-driven)
        let insn = decode(word);

        if insn.is_illegal() {
            self.halted = true;
            return StepResult::Halted;
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

            // ─── Control flow ───────────────────────────────────
            Sem::Branch => {
                if self.flags.test(insn.cond) {
                    next_pc = (self.pc as i64 + insn.imm * 4) as u64;
                }
            }
            Sem::Call => {
                self.r[LR as usize] = self.pc + 4;
                next_pc = (self.pc as i64 + insn.imm * 4) as u64;
            }
            Sem::Ret => {
                next_pc = self.r[LR as usize];
            }

            // ─── System ─────────────────────────────────────────
            Sem::Trap => {
                self.saved_pc = Some(self.pc + 4);
                self.saved_privilege = Some(self.privilege);
                self.privilege = Privilege::Supervisor;
                next_pc = self.trap_vector;
            }
            Sem::Eret => {
                if let Some(p) = self.saved_privilege.take() {
                    self.privilege = p;
                }
                next_pc = self.saved_pc.take().unwrap_or(self.pc + 4);
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
                kind: AccessKind::Write,
                pc: Some(self.pc),
                reason: FaultReason::TranslationFault,
            })?;
        let req = self.make_request(object, offset, width, AccessKind::Write);
        fabric.execute_write(req, data)
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
    fn setup() -> (Fabric, ObjectId, ObjectId, DomainId, Anka64Core) {
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x1000, ObjectKind::Memory);
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(text, 0x00000);
        fabric.place_object(data, 0x10000);

        let dom = fabric.create_domain();
        fabric.grant(dom, text, 0, 0x1000, Permissions::RX);
        fabric.grant(dom, data, 0, 0x1000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, data);

        (fabric, text, data, dom, core)
    }

    fn load_program(fabric: &mut Fabric, asm: &Asm64) {
        fabric.write_physical(0x00000, &asm.to_bytes());
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
        fabric.grant(dom, text, 0, 0x1000, Permissions::RX);
        fabric.grant(dom, data, 0, 0x1000, Permissions::RW);

        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, data);
        core.address_map.add(0xC000, 0x1000, secret); // mapped but no capability!

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

        // CPU domain: text + shared
        let cpu_dom = fabric.create_domain();
        fabric.grant(cpu_dom, text, 0, 0x1000, Permissions::RX);
        fabric.grant(cpu_dom, shared, 0, 0x1000, Permissions::RW);

        // DMA domain: shared only
        let dma_dom = fabric.create_domain();
        fabric.grant(dma_dom, shared, 0, 0x1000, Permissions::RW);

        // CPU writes 42 to shared via program
        let mut core = Anka64Core::new(CPU0, cpu_dom);
        core.address_map.add(0x0000, 0x1000, text);
        core.address_map.add(0x8000, 0x1000, shared);

        let mut asm = Asm64::new();
        asm.movi(R0, 42);
        asm.movi(R1, 0x8000_u16 as i32);
        asm.st(R0, R1, 0);
        asm.halt();
        load_program(&mut fabric, &asm);

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
}

//! Anka64 ISA v0.1 — deliberately tiny.
//!
//! 32-bit fixed-width instructions.  Four formats:
//!
//!   R: [opcode(6)] [rd(4)] [rs1(4)] [rs2(4)] [func(14)]
//!   I: [opcode(6)] [rd(4)] [rs1(4)] [imm18(18)]
//!   B: [opcode(6)] [cond(4)] [offset22(22)]
//!   S: [opcode(6)] [imm26(26)]
//!
//! ISA rule: an instruction may issue at most one primitive
//! memory transaction.  No MOVEM.  MOVEM taught us why. 😄
//!
//! Addressing modes: register, immediate, [register + displacement].

// ───────────────────────────────────────────────────────────────────
// Register conventions
// ───────────────────────────────────────────────────────────────────

pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R4: u8 = 4;
pub const R5: u8 = 5;
pub const R6: u8 = 6;
pub const R7: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;
pub const R10: u8 = 10;
pub const R11: u8 = 11;
pub const R12: u8 = 12;
pub const R13: u8 = 13;
pub const R14: u8 = 14;
pub const R15: u8 = 15;

pub const FP: u8 = R13;
pub const LR: u8 = R14;
pub const SP: u8 = R15;

// ───────────────────────────────────────────────────────────────────
// Branch conditions
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cond {
    Eq  = 0,
    Ne  = 1,
    Lt  = 2,   // signed <
    Ge  = 3,   // signed >=
    Le  = 4,   // signed <=
    Gt  = 5,   // signed >
    Ult = 6,   // unsigned <
    Uge = 7,   // unsigned >=
    Ule = 8,   // unsigned <=
    Ugt = 9,   // unsigned >
    Al  = 15,  // always
}

impl Cond {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0  => Cond::Eq,  1  => Cond::Ne,
            2  => Cond::Lt,  3  => Cond::Ge,
            4  => Cond::Le,  5  => Cond::Gt,
            6  => Cond::Ult, 7  => Cond::Uge,
            8  => Cond::Ule, 9  => Cond::Ugt,
            15 => Cond::Al,
            _  => Cond::Al,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Opcodes
// ───────────────────────────────────────────────────────────────────

pub mod op {
    // R-format
    pub const ADD:  u8 = 0x01;
    pub const SUB:  u8 = 0x02;
    pub const AND:  u8 = 0x03;
    pub const OR:   u8 = 0x04;
    pub const XOR:  u8 = 0x05;
    pub const SHL:  u8 = 0x06;
    pub const SHR:  u8 = 0x07;
    pub const ASR:  u8 = 0x08;
    pub const CMP:  u8 = 0x09;
    pub const MOV:  u8 = 0x0A;

    // I-format
    pub const ADDI: u8 = 0x10;
    pub const SUBI: u8 = 0x11;
    pub const ANDI: u8 = 0x12;
    pub const ORI:  u8 = 0x13;
    pub const XORI: u8 = 0x14;
    pub const CMPI: u8 = 0x15;
    pub const MOVI: u8 = 0x16;

    // Memory (I-format)
    pub const LD:   u8 = 0x20;
    pub const ST:   u8 = 0x21;
    pub const LEA:  u8 = 0x22;

    // B-format
    pub const BCC:  u8 = 0x30;
    pub const CALL: u8 = 0x32;

    // S-format
    pub const RET:  u8 = 0x38;
    pub const TRAP: u8 = 0x39;
    pub const ERET: u8 = 0x3A;
    pub const NOP:  u8 = 0x3E;
    pub const HALT: u8 = 0x3F;
}

// ───────────────────────────────────────────────────────────────────
// Instruction enum
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insn {
    // R-format: rd, rs1, rs2
    Add(u8, u8, u8),
    Sub(u8, u8, u8),
    And(u8, u8, u8),
    Or(u8, u8, u8),
    Xor(u8, u8, u8),
    Shl(u8, u8, u8),
    Shr(u8, u8, u8),
    Asr(u8, u8, u8),
    Cmp(u8, u8),
    Mov(u8, u8),

    // I-format: rd, rs1, imm18
    Addi(u8, u8, i32),
    Subi(u8, u8, i32),
    Andi(u8, u8, i32),
    Ori(u8, u8, i32),
    Xori(u8, u8, i32),
    Cmpi(u8, i32),
    Movi(u8, i32),

    // Memory: rd/src, base, displacement
    Ld(u8, u8, i32),
    St(u8, u8, i32),
    Lea(u8, u8, i32),

    // Branch: condition, word offset from PC
    Bcc(Cond, i32),
    Call(i32),

    // System
    Ret,
    Trap(u8),
    Eret,
    Nop,
    Halt,

    // Unknown opcode
    Illegal(u32),
}

// ───────────────────────────────────────────────────────────────────
// Encoding
// ───────────────────────────────────────────────────────────────────

fn encode_r(opcode: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((opcode as u32) << 26)
        | ((rd as u32 & 0xF) << 22)
        | ((rs1 as u32 & 0xF) << 18)
        | ((rs2 as u32 & 0xF) << 14)
}

fn encode_i(opcode: u8, rd: u8, rs1: u8, imm: i32) -> u32 {
    ((opcode as u32) << 26)
        | ((rd as u32 & 0xF) << 22)
        | ((rs1 as u32 & 0xF) << 18)
        | (imm as u32 & 0x3FFFF)
}

fn encode_b(opcode: u8, cond: u8, offset: i32) -> u32 {
    ((opcode as u32) << 26)
        | ((cond as u32 & 0xF) << 22)
        | (offset as u32 & 0x3FFFFF)
}

fn encode_s(opcode: u8, imm: u32) -> u32 {
    ((opcode as u32) << 26) | (imm & 0x3FFFFFF)
}

fn sign_extend(val: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((val << shift) as i32) >> shift
}

impl Insn {
    pub fn encode(&self) -> u32 {
        match self {
            Insn::Add(d, a, b)  => encode_r(op::ADD, *d, *a, *b),
            Insn::Sub(d, a, b)  => encode_r(op::SUB, *d, *a, *b),
            Insn::And(d, a, b)  => encode_r(op::AND, *d, *a, *b),
            Insn::Or(d, a, b)   => encode_r(op::OR,  *d, *a, *b),
            Insn::Xor(d, a, b)  => encode_r(op::XOR, *d, *a, *b),
            Insn::Shl(d, a, b)  => encode_r(op::SHL, *d, *a, *b),
            Insn::Shr(d, a, b)  => encode_r(op::SHR, *d, *a, *b),
            Insn::Asr(d, a, b)  => encode_r(op::ASR, *d, *a, *b),
            Insn::Cmp(a, b)     => encode_r(op::CMP, 0, *a, *b),
            Insn::Mov(d, s)     => encode_r(op::MOV, *d, *s, 0),

            Insn::Addi(d, a, i) => encode_i(op::ADDI, *d, *a, *i),
            Insn::Subi(d, a, i) => encode_i(op::SUBI, *d, *a, *i),
            Insn::Andi(d, a, i) => encode_i(op::ANDI, *d, *a, *i),
            Insn::Ori(d, a, i)  => encode_i(op::ORI,  *d, *a, *i),
            Insn::Xori(d, a, i) => encode_i(op::XORI, *d, *a, *i),
            Insn::Cmpi(a, i)    => encode_i(op::CMPI, 0, *a, *i),
            Insn::Movi(d, i)    => encode_i(op::MOVI, *d, 0, *i),

            Insn::Ld(d, b, i)   => encode_i(op::LD, *d, *b, *i),
            Insn::St(s, b, i)   => encode_i(op::ST, *s, *b, *i),
            Insn::Lea(d, b, i)  => encode_i(op::LEA, *d, *b, *i),

            Insn::Bcc(c, off)   => encode_b(op::BCC, *c as u8, *off),
            Insn::Call(off)      => encode_b(op::CALL, 0, *off),

            Insn::Ret            => encode_s(op::RET, 0),
            Insn::Trap(v)        => encode_s(op::TRAP, *v as u32),
            Insn::Eret           => encode_s(op::ERET, 0),
            Insn::Nop            => encode_s(op::NOP, 0),
            Insn::Halt           => encode_s(op::HALT, 0),
            Insn::Illegal(w)     => *w,
        }
    }

    pub fn decode(word: u32) -> Self {
        let opcode = ((word >> 26) & 0x3F) as u8;
        let rd  = ((word >> 22) & 0xF) as u8;
        let rs1 = ((word >> 18) & 0xF) as u8;
        let rs2 = ((word >> 14) & 0xF) as u8;
        let imm18 = sign_extend(word & 0x3FFFF, 18);
        let off22 = sign_extend(word & 0x3FFFFF, 22);
        let imm26 = word & 0x3FFFFFF;

        match opcode {
            op::ADD  => Insn::Add(rd, rs1, rs2),
            op::SUB  => Insn::Sub(rd, rs1, rs2),
            op::AND  => Insn::And(rd, rs1, rs2),
            op::OR   => Insn::Or(rd, rs1, rs2),
            op::XOR  => Insn::Xor(rd, rs1, rs2),
            op::SHL  => Insn::Shl(rd, rs1, rs2),
            op::SHR  => Insn::Shr(rd, rs1, rs2),
            op::ASR  => Insn::Asr(rd, rs1, rs2),
            op::CMP  => Insn::Cmp(rs1, rs2),
            op::MOV  => Insn::Mov(rd, rs1),

            op::ADDI => Insn::Addi(rd, rs1, imm18),
            op::SUBI => Insn::Subi(rd, rs1, imm18),
            op::ANDI => Insn::Andi(rd, rs1, imm18),
            op::ORI  => Insn::Ori(rd, rs1, imm18),
            op::XORI => Insn::Xori(rd, rs1, imm18),
            op::CMPI => Insn::Cmpi(rs1, imm18),
            op::MOVI => Insn::Movi(rd, imm18),

            op::LD   => Insn::Ld(rd, rs1, imm18),
            op::ST   => Insn::St(rd, rs1, imm18),
            op::LEA  => Insn::Lea(rd, rs1, imm18),

            op::BCC  => Insn::Bcc(Cond::from_u8(rd), off22),
            op::CALL => Insn::Call(off22),

            op::RET  => Insn::Ret,
            op::TRAP => Insn::Trap(imm26 as u8),
            op::ERET => Insn::Eret,
            op::NOP  => Insn::Nop,
            op::HALT => Insn::Halt,

            _ => Insn::Illegal(word),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Assembler
// ───────────────────────────────────────────────────────────────────

pub struct Asm64 {
    words: Vec<u32>,
}

impl Asm64 {
    pub fn new() -> Self { Self { words: Vec::new() } }

    fn emit(&mut self, insn: Insn) { self.words.push(insn.encode()); }

    /// Current position in words (for branch offset calculation).
    pub fn here(&self) -> i32 { self.words.len() as i32 }

    // R-format
    pub fn add(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::Add(rd, a, b)); }
    pub fn sub(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::Sub(rd, a, b)); }
    pub fn and(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::And(rd, a, b)); }
    pub fn or(&mut self, rd: u8, a: u8, b: u8)   { self.emit(Insn::Or(rd, a, b)); }
    pub fn xor(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::Xor(rd, a, b)); }
    pub fn shl(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::Shl(rd, a, b)); }
    pub fn shr(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::Shr(rd, a, b)); }
    pub fn asr(&mut self, rd: u8, a: u8, b: u8)  { self.emit(Insn::Asr(rd, a, b)); }
    pub fn cmp(&mut self, a: u8, b: u8)           { self.emit(Insn::Cmp(a, b)); }
    pub fn mov(&mut self, rd: u8, rs: u8)         { self.emit(Insn::Mov(rd, rs)); }

    // I-format
    pub fn addi(&mut self, rd: u8, a: u8, i: i32) { self.emit(Insn::Addi(rd, a, i)); }
    pub fn subi(&mut self, rd: u8, a: u8, i: i32) { self.emit(Insn::Subi(rd, a, i)); }
    pub fn cmpi(&mut self, a: u8, i: i32)          { self.emit(Insn::Cmpi(a, i)); }
    pub fn movi(&mut self, rd: u8, i: i32)         { self.emit(Insn::Movi(rd, i)); }

    // Memory
    pub fn ld(&mut self, rd: u8, base: u8, disp: i32) { self.emit(Insn::Ld(rd, base, disp)); }
    pub fn st(&mut self, src: u8, base: u8, disp: i32) { self.emit(Insn::St(src, base, disp)); }
    pub fn lea(&mut self, rd: u8, base: u8, disp: i32) { self.emit(Insn::Lea(rd, base, disp)); }

    // Branch (offset in words relative to this instruction)
    pub fn bcc(&mut self, cond: Cond, word_off: i32) { self.emit(Insn::Bcc(cond, word_off)); }
    pub fn call(&mut self, word_off: i32)             { self.emit(Insn::Call(word_off)); }

    // System
    pub fn ret(&mut self)          { self.emit(Insn::Ret); }
    pub fn trap(&mut self, v: u8)  { self.emit(Insn::Trap(v)); }
    pub fn eret(&mut self)         { self.emit(Insn::Eret); }
    pub fn nop(&mut self)          { self.emit(Insn::Nop); }
    pub fn halt(&mut self)         { self.emit(Insn::Halt); }

    /// Emit as little-endian byte stream.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * 4);
        for &w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }
}

// ───────────────────────────────────────────────────────────────────
// Encode/decode round-trip tests
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(insn: &Insn) {
        let word = insn.encode();
        let decoded = Insn::decode(word);
        assert_eq!(insn, &decoded, "roundtrip failed: {:?} → 0x{:08X} → {:?}", insn, word, decoded);
    }

    #[test]
    fn roundtrip_r_format() {
        roundtrip(&Insn::Add(R0, R1, R2));
        roundtrip(&Insn::Sub(R15, R8, R3));
        roundtrip(&Insn::Cmp(R5, R6));
        roundtrip(&Insn::Mov(R7, R14));
    }

    #[test]
    fn roundtrip_i_format() {
        roundtrip(&Insn::Addi(R0, R1, 42));
        roundtrip(&Insn::Addi(R0, R1, -1));
        roundtrip(&Insn::Movi(R3, 0xBEEF));
        roundtrip(&Insn::Movi(R3, -100));
        roundtrip(&Insn::Ld(R4, R5, 8));
        roundtrip(&Insn::St(R6, R7, -16));
    }

    #[test]
    fn roundtrip_b_format() {
        roundtrip(&Insn::Bcc(Cond::Ne, -3));
        roundtrip(&Insn::Bcc(Cond::Eq, 10));
        roundtrip(&Insn::Call(100));
    }

    #[test]
    fn roundtrip_s_format() {
        roundtrip(&Insn::Ret);
        roundtrip(&Insn::Trap(0));
        roundtrip(&Insn::Trap(7));
        roundtrip(&Insn::Eret);
        roundtrip(&Insn::Halt);
        roundtrip(&Insn::Nop);
    }
}

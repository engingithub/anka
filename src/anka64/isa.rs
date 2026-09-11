//! Anka64 ISA v0.1 — decoder, assembler, disassembler.
//!
//! All three are table-driven from `desc::INSNS`.
//! Nothing here invents an opcode or format rule; the description
//! is the single source of truth.

use super::desc::{self, Format, Operands, Sem, InsnDesc};

// ───────────────────────────────────────────────────────────────────
// Register conventions (unchanged from Phase 2)
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

const REG_NAMES: [&str; 16] = [
    "r0","r1","r2","r3","r4","r5","r6","r7",
    "r8","r9","r10","r11","r12","fp","lr","sp",
];

// ───────────────────────────────────────────────────────────────────
// Branch conditions
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cond {
    Eq  = 0,
    Ne  = 1,
    Lt  = 2,
    Ge  = 3,
    Le  = 4,
    Gt  = 5,
    Ult = 6,
    Uge = 7,
    Ule = 8,
    Ugt = 9,
    Al  = 15,
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

    pub fn suffix(self) -> &'static str {
        match self {
            Cond::Eq  => "eq",  Cond::Ne  => "ne",
            Cond::Lt  => "lt",  Cond::Ge  => "ge",
            Cond::Le  => "le",  Cond::Gt  => "gt",
            Cond::Ult => "ult", Cond::Uge => "uge",
            Cond::Ule => "ule", Cond::Ugt => "ugt",
            Cond::Al  => "",
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Decoded instruction — description pointer + extracted fields
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub desc: &'static InsnDesc,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: i64,
    pub cond: Cond,
    pub raw: u32,
}

/// Sentinel for illegal/unknown instructions.
static ILLEGAL_DESC: InsnDesc = InsnDesc {
    name: "???",
    opcode: 0xFF,
    format: Format::S,
    operands: Operands::NoOps,
    semantics: Sem::Halt,
    mem: desc::MemEffect::None,
    flags: desc::FlagEffect::None,
};

impl DecodedInsn {
    pub fn is_illegal(&self) -> bool { self.desc.opcode == 0xFF }
}

// ───────────────────────────────────────────────────────────────────
// Encoding helpers (format-level, shared by assembler and tests)
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

fn sign_extend(val: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    (((val << shift) as i32) >> shift) as i64
}

// ───────────────────────────────────────────────────────────────────
// Table-driven decoder
// ───────────────────────────────────────────────────────────────────

pub fn decode(word: u32) -> DecodedInsn {
    let opcode = ((word >> 26) & 0x3F) as u8;
    let rd     = ((word >> 22) & 0xF) as u8;
    let rs1    = ((word >> 18) & 0xF) as u8;
    let rs2    = ((word >> 14) & 0xF) as u8;
    let imm18  = sign_extend(word & 0x3FFFF, 18);
    let off22  = sign_extend(word & 0x3FFFFF, 22);
    let imm26  = (word & 0x3FFFFFF) as i64;

    match desc::by_opcode(opcode) {
        Some(d) => {
            let (imm, cond_val) = match d.format {
                Format::R => (0i64, Cond::Al),
                Format::I => (imm18, Cond::Al),
                Format::B => (off22, Cond::from_u8(rd)),
                Format::S => (imm26, Cond::Al),
            };
            DecodedInsn { desc: d, rd, rs1, rs2, imm, cond: cond_val, raw: word }
        }
        None => DecodedInsn {
            desc: &ILLEGAL_DESC,
            rd: 0, rs1: 0, rs2: 0, imm: 0, cond: Cond::Al, raw: word,
        },
    }
}

// ───────────────────────────────────────────────────────────────────
// Table-driven disassembler
// ───────────────────────────────────────────────────────────────────

pub fn disassemble(insn: &DecodedInsn) -> String {
    if insn.is_illegal() {
        return format!(".word 0x{:08X}", insn.raw);
    }
    let d = insn.desc;
    match d.operands {
        Operands::RdRs1Rs2 => format!("{} {}, {}, {}",
            d.name, REG_NAMES[insn.rd as usize],
            REG_NAMES[insn.rs1 as usize], REG_NAMES[insn.rs2 as usize]),
        Operands::RdRs1 => format!("{} {}, {}",
            d.name, REG_NAMES[insn.rd as usize], REG_NAMES[insn.rs1 as usize]),
        Operands::Rs1Rs2 => format!("{} {}, {}",
            d.name, REG_NAMES[insn.rs1 as usize], REG_NAMES[insn.rs2 as usize]),
        Operands::RdRs1Imm => format!("{} {}, {}, #{}",
            d.name, REG_NAMES[insn.rd as usize],
            REG_NAMES[insn.rs1 as usize], insn.imm),
        Operands::Rs1Imm => format!("{} {}, #{}",
            d.name, REG_NAMES[insn.rs1 as usize], insn.imm),
        Operands::RdImm => format!("{} {}, #{}",
            d.name, REG_NAMES[insn.rd as usize], insn.imm),
        Operands::RdBaseDisp => format!("{} {}, [{} + {}]",
            d.name, REG_NAMES[insn.rd as usize],
            REG_NAMES[insn.rs1 as usize], insn.imm),
        Operands::SrcBaseDisp => format!("{} {}, [{} + {}]",
            d.name, REG_NAMES[insn.rd as usize],
            REG_NAMES[insn.rs1 as usize], insn.imm),
        Operands::CondOff => format!("b{} {}",
            insn.cond.suffix(), insn.imm),
        Operands::Off => format!("{} {}",
            d.name, insn.imm),
        Operands::Imm8 => format!("{} #{}",
            d.name, insn.imm as u8),
        Operands::NoOps => d.name.to_string(),
    }
}

// ───────────────────────────────────────────────────────────────────
// Table-driven assembler
// ───────────────────────────────────────────────────────────────────

pub struct Asm64 {
    words: Vec<u32>,
}

impl Asm64 {
    pub fn new() -> Self { Self { words: Vec::new() } }

    /// Current position in words (for branch offset calculation).
    pub fn here(&self) -> i32 { self.words.len() as i32 }

    // ─── Generic emitters (table-driven) ────────────────────────

    fn emit_r_named(&mut self, name: &str, rd: u8, rs1: u8, rs2: u8) {
        let d = desc::by_name(name)
            .unwrap_or_else(|| panic!("unknown R-format instruction: {}", name));
        debug_assert_eq!(d.format, Format::R, "{} is not R-format", name);
        self.words.push(encode_r(d.opcode, rd, rs1, rs2));
    }

    fn emit_i_named(&mut self, name: &str, rd: u8, rs1: u8, imm: i32) {
        let d = desc::by_name(name)
            .unwrap_or_else(|| panic!("unknown I-format instruction: {}", name));
        debug_assert_eq!(d.format, Format::I, "{} is not I-format", name);
        self.words.push(encode_i(d.opcode, rd, rs1, imm));
    }

    fn emit_b_named(&mut self, name: &str, cond: u8, offset: i32) {
        let d = desc::by_name(name)
            .unwrap_or_else(|| panic!("unknown B-format instruction: {}", name));
        debug_assert_eq!(d.format, Format::B, "{} is not B-format", name);
        self.words.push(encode_b(d.opcode, cond, offset));
    }

    fn emit_s_named(&mut self, name: &str, imm: u32) {
        let d = desc::by_name(name)
            .unwrap_or_else(|| panic!("unknown S-format instruction: {}", name));
        debug_assert_eq!(d.format, Format::S, "{} is not S-format", name);
        self.words.push(encode_s(d.opcode, imm));
    }

    // ─── Named methods (API unchanged from Phase 2) ─────────────

    // R-format
    pub fn add(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("add", rd, a, b); }
    pub fn sub(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("sub", rd, a, b); }
    pub fn and(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("and", rd, a, b); }
    pub fn or(&mut self, rd: u8, a: u8, b: u8)   { self.emit_r_named("or",  rd, a, b); }
    pub fn xor(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("xor", rd, a, b); }
    pub fn shl(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("shl", rd, a, b); }
    pub fn shr(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("shr", rd, a, b); }
    pub fn asr(&mut self, rd: u8, a: u8, b: u8)  { self.emit_r_named("asr", rd, a, b); }
    pub fn cmp(&mut self, a: u8, b: u8)           { self.emit_r_named("cmp", 0, a, b); }
    pub fn mov(&mut self, rd: u8, rs: u8)         { self.emit_r_named("mov", rd, rs, 0); }
    pub fn mul(&mut self, rd: u8, a: u8, b: u8)   { self.emit_r_named("mul", rd, a, b); }

    // I-format
    pub fn addi(&mut self, rd: u8, a: u8, i: i32) { self.emit_i_named("addi", rd, a, i); }
    pub fn subi(&mut self, rd: u8, a: u8, i: i32) { self.emit_i_named("subi", rd, a, i); }
    pub fn cmpi(&mut self, a: u8, i: i32)          { self.emit_i_named("cmpi", 0, a, i); }
    pub fn movi(&mut self, rd: u8, i: i32)         { self.emit_i_named("movi", rd, 0, i); }

    // Memory
    pub fn ld(&mut self, rd: u8, base: u8, disp: i32) { self.emit_i_named("ld", rd, base, disp); }
    pub fn st(&mut self, src: u8, base: u8, disp: i32) { self.emit_i_named("st", src, base, disp); }
    pub fn lea(&mut self, rd: u8, base: u8, disp: i32) { self.emit_i_named("lea", rd, base, disp); }
    pub fn xchg(&mut self, rd: u8, base: u8, disp: i32) { self.emit_i_named("xchg", rd, base, disp); }

    // Branch (offset in words relative to this instruction)
    pub fn bcc(&mut self, cond: Cond, word_off: i32) { self.emit_b_named("b", cond as u8, word_off); }
    pub fn call(&mut self, word_off: i32)             { self.emit_b_named("call", 0, word_off); }

    // System
    pub fn ret(&mut self)          { self.emit_s_named("ret", 0); }
    pub fn trap(&mut self, v: u8)  { self.emit_s_named("trap", v as u32); }
    pub fn eret(&mut self)         { self.emit_s_named("eret", 0); }
    pub fn nop(&mut self)          { self.emit_s_named("nop", 0); }
    pub fn halt(&mut self)         { self.emit_s_named("halt", 0); }

    /// Direct access to encoded words (for fixups).
    pub fn words_mut(&mut self) -> &mut Vec<u32> { &mut self.words }

    /// Emit as little-endian byte stream.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * 4);
        for &w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Disassemble all emitted words.
    pub fn listing(&self) -> String {
        let mut out = String::new();
        for (i, &w) in self.words.iter().enumerate() {
            let insn = decode(w);
            out.push_str(&format!("{:04X}: {:08X}  {}\n", i * 4, w, disassemble(&insn)));
        }
        out
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode via assembler, decode, check description matches.
    fn roundtrip_r(name: &str, rd: u8, rs1: u8, rs2: u8) {
        let d = desc::by_name(name).unwrap();
        let word = encode_r(d.opcode, rd, rs1, rs2);
        let decoded = decode(word);
        assert_eq!(decoded.desc.name, name);
        assert_eq!(decoded.rd, rd);
        assert_eq!(decoded.rs1, rs1);
        assert_eq!(decoded.rs2, rs2);
    }

    fn roundtrip_i(name: &str, rd: u8, rs1: u8, imm: i32) {
        let d = desc::by_name(name).unwrap();
        let word = encode_i(d.opcode, rd, rs1, imm);
        let decoded = decode(word);
        assert_eq!(decoded.desc.name, name);
        assert_eq!(decoded.rd, rd);
        assert_eq!(decoded.rs1, rs1);
        assert_eq!(decoded.imm, sign_extend(imm as u32 & 0x3FFFF, 18));
    }

    fn roundtrip_b(name: &str, cond: Cond, off: i32) {
        let d = desc::by_name(name).unwrap();
        let word = encode_b(d.opcode, cond as u8, off);
        let decoded = decode(word);
        assert_eq!(decoded.desc.name, name);
        assert_eq!(decoded.imm, sign_extend(off as u32 & 0x3FFFFF, 22));
    }

    fn roundtrip_s(name: &str) {
        let d = desc::by_name(name).unwrap();
        let word = encode_s(d.opcode, 0);
        let decoded = decode(word);
        assert_eq!(decoded.desc.name, name);
    }

    #[test]
    fn roundtrip_all_r_format() {
        roundtrip_r("add", R0, R1, R2);
        roundtrip_r("sub", R15, R8, R3);
        roundtrip_r("cmp", 0, R5, R6);
        roundtrip_r("mov", R7, R14, 0);
        roundtrip_r("mul", R3, R4, R5);
    }

    #[test]
    fn roundtrip_all_i_format() {
        roundtrip_i("addi", R0, R1, 42);
        roundtrip_i("addi", R0, R1, -1);
        roundtrip_i("movi", R3, 0, 0x7EEF);
        roundtrip_i("movi", R3, 0, -100);
        roundtrip_i("ld", R4, R5, 8);
        roundtrip_i("st", R6, R7, -16);
    }

    #[test]
    fn roundtrip_all_b_format() {
        roundtrip_b("b", Cond::Ne, -3);
        roundtrip_b("b", Cond::Eq, 10);
        roundtrip_b("call", Cond::Al, 100);
    }

    #[test]
    fn roundtrip_all_s_format() {
        roundtrip_s("ret");
        roundtrip_s("trap");
        roundtrip_s("eret");
        roundtrip_s("halt");
        roundtrip_s("nop");
    }

    #[test]
    fn disassemble_roundtrip() {
        let cases: Vec<(&str, u32)> = desc::INSNS.iter().map(|d| {
            let word = match d.format {
                Format::R => encode_r(d.opcode, 1, 2, 3),
                Format::I => encode_i(d.opcode, 1, 2, 42),
                Format::B => encode_b(d.opcode, Cond::Ne as u8, -5),
                Format::S => encode_s(d.opcode, 7),
            };
            (d.name, word)
        }).collect();

        for (name, word) in &cases {
            let decoded = decode(*word);
            let text = disassemble(&decoded);
            assert!(
                !text.is_empty(),
                "disassembly empty for {}", name
            );
            // Verify the disassembly contains the mnemonic
            let expected_prefix = if decoded.desc.semantics == Sem::Branch {
                "b"
            } else {
                decoded.desc.name
            };
            assert!(
                text.starts_with(expected_prefix),
                "disassembly '{}' doesn't start with '{}'", text, expected_prefix
            );
        }
    }

    #[test]
    fn every_desc_entry_assembles_and_decodes() {
        for d in desc::INSNS {
            let word = match d.format {
                Format::R => encode_r(d.opcode, 5, 6, 7),
                Format::I => encode_i(d.opcode, 5, 6, -17),
                Format::B => encode_b(d.opcode, 3, 10),
                Format::S => encode_s(d.opcode, 0),
            };
            let decoded = decode(word);
            assert_eq!(
                decoded.desc.opcode, d.opcode,
                "instruction '{}' did not round-trip through decode", d.name
            );
        }
    }

    #[test]
    fn assembler_listing() {
        let mut asm = Asm64::new();
        asm.movi(R0, 42);
        asm.movi(R1, 10);
        asm.add(R2, R0, R1);
        asm.halt();
        let listing = asm.listing();
        assert!(listing.contains("movi"));
        assert!(listing.contains("add"));
        assert!(listing.contains("halt"));
        eprintln!("Listing:\n{}", listing);
    }
}

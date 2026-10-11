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
    pub fn is_illegal(&self) -> bool {
        if self.desc.opcode == 0xFF { return true; }
        let pair=|v:u8| v<=10 && v%2==0;
        let func=self.raw & 0x3fff;
        match self.desc.semantics {
            Sem::PointerMove => !pair(self.rd)||!pair(self.rs1)||self.rs2!=0||func!=0,
            Sem::PointerAdd => !pair(self.rd)||!pair(self.rs1)||self.rs2>12||func!=0,
            Sem::PointerLoad|Sem::PointerStore => !pair(self.rd)||!pair(self.rs1),
            Sem::PointerRead|Sem::PointerWrite => self.rd>12||!pair(self.rs1)||self.rs2!=0||func>3,
            Sem::PointerLocal => !pair(self.rd)||self.rs1!=0||self.imm<0,
            Sem::PointerUnframe => self.raw & 0x3ffffff != 0,
            _=>false,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// ───────────────────────────────────────────────────────────────────
// I-format immediate range — the single definition of representability
// used by both the assembler and the compiler.
//
// Signed 18-bit: [-2^17, 2^17 - 1] = [-131072, 131071].
// No code-generation layer may pre-mask or truncate a value to
// make it fit.  Either the source literal is exactly representable,
// or it must be rejected.
// ───────────────────────────────────────────────────────────────────

pub const IMM18_MIN: i32 = -(1 << 17);   // -131072
pub const IMM18_MAX: i32 =  (1 << 17) - 1; // 131071

pub fn fits_imm18(v: i64) -> bool {
    v >= IMM18_MIN as i64 && v <= IMM18_MAX as i64
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
        Operands::PointerWidth => format!("{} {}, [{}], {}",d.name,REG_NAMES[insn.rd as usize],REG_NAMES[insn.rs1 as usize],1u64 << (insn.raw&3)),
        Operands::ManifestIndex => format!("{} #{}",d.name,insn.imm),
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
        assert!(
            fits_imm18(imm as i64),
            "I-format immediate out of signed 18-bit range: {imm} \
             (valid: {IMM18_MIN}..={IMM18_MAX})",
        );
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
    pub fn ldb(&mut self, rd: u8, base: u8, disp: i32) { self.emit_i_named("ldb", rd, base, disp); }
    pub fn stb(&mut self, src: u8, base: u8, disp: i32) { self.emit_i_named("stb", src, base, disp); }
    pub fn st(&mut self, src: u8, base: u8, disp: i32) { self.emit_i_named("st", src, base, disp); }
    pub fn lea(&mut self, rd: u8, base: u8, disp: i32) { self.emit_i_named("lea", rd, base, disp); }
    pub fn xchg(&mut self, rd: u8, base: u8, disp: i32) { self.emit_i_named("xchg", rd, base, disp); }

    fn emit_pointer_word(&mut self, word: u32) {
        assert!(!decode(word).is_illegal(), "invalid protected pointer operands");
        self.words.push(word);
    }
    fn assert_pair(r:u8) { assert!(r<=10 && r%2==0,"invalid pointer pair"); }
    pub fn pmov(&mut self,d:u8,s:u8) { Self::assert_pair(d); Self::assert_pair(s); self.emit_pointer_word(encode_r(0x26,d,s,0)); }
    pub fn padd(&mut self,d:u8,s:u8,t:u8) { Self::assert_pair(d);Self::assert_pair(s);assert!(t<=12); self.emit_pointer_word(encode_r(0x27,d,s,t)); }
    pub fn pload(&mut self,d:u8,s:u8,disp:i32) { Self::assert_pair(d);Self::assert_pair(s);assert!(fits_imm18(disp as i64)); self.emit_pointer_word(encode_i(0x28,d,s,disp)); }
    pub fn pstore(&mut self,d:u8,s:u8,disp:i32) { Self::assert_pair(d);Self::assert_pair(s);assert!(fits_imm18(disp as i64)); self.emit_pointer_word(encode_i(0x29,d,s,disp)); }
    fn pointer_width(&mut self,op:u8,d:u8,s:u8,width:u64) {
        assert!(d<=12);Self::assert_pair(s);assert!(matches!(width,1|2|4|8));
        self.emit_pointer_word(encode_r(op,d,s,0)|width.trailing_zeros());
    }
    pub fn pread(&mut self,d:u8,s:u8,width:u64) { self.pointer_width(0x2a,d,s,width); }
    pub fn pwrite(&mut self,d:u8,s:u8,width:u64) { self.pointer_width(0x2b,d,s,width); }
    pub fn pframe(&mut self,index:u32) { assert!(index<1<<26);self.emit_pointer_word(encode_s(0x2c,index)); }
    pub fn plocal(&mut self,d:u8,index:u32) { Self::assert_pair(d);assert!(index<1<<17);self.emit_pointer_word(encode_i(0x2d,d,0,index as i32)); }
    pub fn punframe(&mut self) { self.emit_pointer_word(encode_s(0x2e,0)); }

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
        roundtrip_i("ldb", R4, R5, 7);
        roundtrip_i("stb", R6, R7, -1);
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

    fn canonical_pointer_test_word(d:&InsnDesc) -> Option<u32> {
        match d.semantics {
            Sem::PointerMove=>Some(encode_r(d.opcode,4,6,0)),
            Sem::PointerAdd=>Some(encode_r(d.opcode,4,6,12)),
            Sem::PointerLoad|Sem::PointerStore=>Some(encode_i(d.opcode,4,6,-17)),
            Sem::PointerRead|Sem::PointerWrite=>Some(encode_r(d.opcode,12,6,0)|3),
            Sem::PointerFrame=>Some(encode_s(d.opcode,7)),
            Sem::PointerLocal=>Some(encode_i(d.opcode,4,0,7)),
            Sem::PointerUnframe=>Some(encode_s(d.opcode,0)),
            _=>None,
        }
    }

    #[test]
    fn pointer_fields_reject_reserved_lanes_and_funcs() {
        for d in 0..16 {for s in 0..16 {for f in 0..5 {
            let pair=|x:u8|x<=10&&x%2==0;
            assert_eq!(!decode(encode_r(0x26,d,s,0)|f).is_illegal(),pair(d)&&pair(s)&&f==0);
            assert_eq!(!decode(encode_r(0x2a,d,s,0)|f).is_illegal(),d<=12&&pair(s)&&f<=3);
        }}}
        let mut asm=Asm64::new();asm.pmov(4,6);asm.padd(4,6,12);asm.pload(4,6,-131072);asm.pstore(4,6,131071);
        for w in [1,2,4,8] {asm.pread(12,6,w);asm.pwrite(12,6,w);}
        asm.pframe((1<<26)-1);asm.plocal(4,(1<<17)-1);asm.punframe();
        assert!(asm.words.iter().all(|&w| !decode(w).is_illegal()));
    }

    #[test]
    fn disassemble_roundtrip() {
        let cases: Vec<(&str, u32)> = desc::INSNS.iter().map(|d| {
            let word = canonical_pointer_test_word(d).unwrap_or_else(|| match d.format {
                Format::R => encode_r(d.opcode, 1, 2, 3),
                Format::I => encode_i(d.opcode, 1, 2, 42),
                Format::B => encode_b(d.opcode, Cond::Ne as u8, -5),
                Format::S => encode_s(d.opcode, 7),
            });
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
            let word = canonical_pointer_test_word(d).unwrap_or_else(|| match d.format {
                Format::R => encode_r(d.opcode, 5, 6, 7),
                Format::I => encode_i(d.opcode, 5, 6, -17),
                Format::B => encode_b(d.opcode, 3, 10),
                Format::S => encode_s(d.opcode, 0),
            });
            assert!(!decode(word).is_illegal());
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

    // ═══════════════════════════════════════════════════════════════
    // I-format immediate range — boundary and rejection tests
    //
    // The assembler must never silently alias an out-of-range
    // immediate.  These tests close the full round trip:
    //   source literal → encode → decode → same literal
    // and verify that out-of-range values are rejected.
    // ═══════════════════════════════════════════════════════════════

    /// Boundary acceptance: -131072 and 131071 encode and decode
    /// to exactly the same signed value.
    #[test]
    fn imm18_boundary_accepted() {
        let mut asm = Asm64::new();
        asm.movi(R0, IMM18_MIN);
        asm.movi(R1, IMM18_MAX);
        let bytes = asm.to_bytes();

        let word0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let word1 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let d0 = decode(word0);
        let d1 = decode(word1);

        assert_eq!(d0.imm, IMM18_MIN as i64,
            "decode(-131072) must equal -131072");
        assert_eq!(d1.imm, IMM18_MAX as i64,
            "decode(131071) must equal 131071");
        eprintln!("imm18 boundary: -131072 ✓, 131071 ✓");
    }

    /// Boundary rejection: -131073 must panic.
    #[test]
    #[should_panic(expected = "I-format immediate out of signed 18-bit range")]
    fn imm18_reject_negative_overflow() {
        let mut asm = Asm64::new();
        asm.movi(R0, IMM18_MIN - 1); // -131073
    }

    /// Boundary rejection: 131072 must panic.
    #[test]
    #[should_panic(expected = "I-format immediate out of signed 18-bit range")]
    fn imm18_reject_positive_overflow() {
        let mut asm = Asm64::new();
        asm.movi(R0, IMM18_MAX + 1); // 131072
    }
}

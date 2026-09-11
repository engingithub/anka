//! MC68000 textual assembler (AnkaASM).
//!
//! Parses Motorola-syntax source text and produces a flat binary image.
//! Uses its own code buffer and fixup system — the same algebraic
//! approach as the programmatic [`super::Asm`] builder, but driven by
//! parsed text rather than Rust method calls.
//!
//! # Syntax
//!
//! ```text
//! label:                      ; labels end with ':'
//! CONSOLE = $F00000           ; equates (constant definition)
//!     move.b  (a0)+,d0        ; mnemonic.size  src,dst
//!     beq     done            ; branches take a label
//!     .ascii  "Hello\n"       ; directives start with '.'
//!     .byte   0               ; raw data
//! ; comments start with ';'   * or '*' in column 0
//! ```

use std::collections::HashMap;
use std::fmt;

// ───────────────────────────────────────────────────────────────────
// Public error type
// ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AsmError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

// ───────────────────────────────────────────────────────────────────
// Internal types
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Size { Byte, Word, Long }

#[derive(Debug, Clone)]
enum Operand {
    DataReg(u8),
    AddrReg(u8),
    Indirect(u8),
    PostInc(u8),
    PreDec(u8),
    Disp(i16, u8),
    AbsLong(u32),
    Imm(i32),
    ImmSym(String),
    Symbol(String),
}

enum FixupKind { Branch16, Abs32 }

struct Fixup {
    offset: usize,
    label:  String,
    kind:   FixupKind,
    pc_base: u32,
    line:   usize,
}

// ───────────────────────────────────────────────────────────────────
// Number parser
// ───────────────────────────────────────────────────────────────────

fn parse_number(s: &str) -> Result<i32, String> {
    let s = s.trim();
    if s.is_empty() { return Err("empty".into()); }

    let (neg, s) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else {
        (false, s)
    };

    let val: u64 = if let Some(hex) = s.strip_prefix('$') {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())?
    } else if s.len() > 2 && s[..2].eq_ignore_ascii_case("0x") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| e.to_string())?
    } else if let Some(bin) = s.strip_prefix('%') {
        u64::from_str_radix(bin, 2).map_err(|e| e.to_string())?
    } else if s.len() == 3 && s.starts_with('\'') && s.ends_with('\'') {
        s.as_bytes()[1] as u64
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())?
    };

    if neg {
        if val > (i32::MAX as u64 + 1) { return Err("too negative".into()); }
        Ok(-(val as i64) as i32)
    } else {
        if val > u32::MAX as u64 { return Err("too large".into()); }
        Ok(val as i32)
    }
}

// ───────────────────────────────────────────────────────────────────
// Operand parser
// ───────────────────────────────────────────────────────────────────

fn parse_reg(s: &str) -> Option<Operand> {
    let lo = s.to_ascii_lowercase();
    if lo == "sp" { return Some(Operand::AddrReg(7)); }
    let b = lo.as_bytes();
    if b.len() == 2 && b[1] >= b'0' && b[1] <= b'7' {
        let n = b[1] - b'0';
        match b[0] {
            b'd' => return Some(Operand::DataReg(n)),
            b'a' => return Some(Operand::AddrReg(n)),
            _ => {}
        }
    }
    None
}

fn parse_reg_inside(s: &str) -> Result<u8, String> {
    let lo = s.to_ascii_lowercase();
    if lo == "sp" { return Ok(7); }
    let b = lo.as_bytes();
    if b.len() == 2 && b[0] == b'a' && b[1] >= b'0' && b[1] <= b'7' {
        return Ok(b[1] - b'0');
    }
    Err(format!("expected address register, got '{}'", s))
}

fn parse_operand(s: &str) -> Result<Operand, String> {
    let s = s.trim();
    if s.is_empty() { return Err("empty operand".into()); }

    // Immediate: #value or #label
    if let Some(rest) = s.strip_prefix('#') {
        let rest = rest.trim();
        return match parse_number(rest) {
            Ok(n) => Ok(Operand::Imm(n)),
            Err(_) => Ok(Operand::ImmSym(rest.to_string())),
        };
    }

    // Pre-decrement: -(An)
    if let Some(rest) = s.strip_prefix("-(") {
        let inner = rest.strip_suffix(')').ok_or("expected ')'")?;
        let reg = parse_reg_inside(inner)?;
        return Ok(Operand::PreDec(reg));
    }

    // Indirect or post-increment: (An) or (An)+
    if s.starts_with('(') {
        let (inner, post) = if let Some(r) = s.strip_suffix(")+") {
            (&r[1..], true)
        } else {
            let inner = s.strip_prefix('(').unwrap()
                         .strip_suffix(')').ok_or("expected ')'")?;
            (inner, false)
        };
        let reg = parse_reg_inside(inner)?;
        return if post { Ok(Operand::PostInc(reg)) } else { Ok(Operand::Indirect(reg)) };
    }

    // Register?
    if let Some(op) = parse_reg(s) {
        return Ok(op);
    }

    // Number possibly followed by (An) for displacement
    if let Some(paren) = s.find('(') {
        let num_part = &s[..paren];
        if let Ok(n) = parse_number(num_part) {
            let reg_part = s[paren+1..].strip_suffix(')')
                .ok_or("expected ')' after displacement")?;
            let reg = parse_reg_inside(reg_part)?;
            if n > i16::MAX as i32 || n < i16::MIN as i32 {
                return Err("displacement out of 16-bit range".into());
            }
            return Ok(Operand::Disp(n as i16, reg));
        }
    }

    // Absolute number
    if let Ok(n) = parse_number(s) {
        return Ok(Operand::AbsLong(n as u32));
    }

    // Symbol (label reference)
    Ok(Operand::Symbol(s.to_string()))
}

fn split_operands(s: &str) -> Vec<&str> {
    if s.trim().is_empty() { return Vec::new(); }
    let mut parts = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

// ───────────────────────────────────────────────────────────────────
// String parser (for .ascii directives)
// ───────────────────────────────────────────────────────────────────

fn parse_string_literal(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.starts_with('"') { return Err("expected '\"'".into()); }
    let mut bytes = Vec::new();
    let mut chars = s[1..].chars();
    loop {
        match chars.next() {
            None => return Err("unterminated string".into()),
            Some('"') => break,
            Some('\\') => match chars.next() {
                Some('n')  => bytes.push(b'\n'),
                Some('r')  => bytes.push(b'\r'),
                Some('t')  => bytes.push(b'\t'),
                Some('0')  => bytes.push(0),
                Some('\\') => bytes.push(b'\\'),
                Some('"')  => bytes.push(b'"'),
                Some(c)    => return Err(format!("unknown escape \\{}", c)),
                None       => return Err("unterminated escape".into()),
            },
            Some(c) if c.is_ascii() => bytes.push(c as u8),
            Some(c) => return Err(format!("non-ASCII: {}", c)),
        }
    }
    Ok(bytes)
}

// ───────────────────────────────────────────────────────────────────
// Comment stripper
// ───────────────────────────────────────────────────────────────────

fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        if c == '"' { in_str = !in_str; }
        if c == ';' && !in_str { return &line[..i]; }
    }
    line
}

// ───────────────────────────────────────────────────────────────────
// Mnemonic parser
// ───────────────────────────────────────────────────────────────────

fn parse_mnemonic(tok: &str) -> (&str, Option<Size>) {
    if let Some(dot) = tok.rfind('.') {
        let base = &tok[..dot];
        let sfx = &tok[dot+1..];
        let sz = match sfx.to_ascii_lowercase().as_str() {
            "b" => Some(Size::Byte),
            "w" => Some(Size::Word),
            "l" => Some(Size::Long),
            "s" => Some(Size::Byte),
            _ => None,
        };
        if sz.is_some() { return (base, sz); }
    }
    (tok, None)
}

// ═══════════════════════════════════════════════════════════════════
// Assembler context
// ═══════════════════════════════════════════════════════════════════

struct Ctx {
    code:   Vec<u8>,
    base:   u32,
    labels: HashMap<String, u32>,
    fixups: Vec<Fixup>,
    errors: Vec<AsmError>,
}

impl Ctx {

fn new(base: u32) -> Self {
    Self { code: Vec::new(), base, labels: HashMap::new(),
           fixups: Vec::new(), errors: Vec::new() }
}

fn here(&self) -> u32 { self.base + self.code.len() as u32 }

fn w(&mut self, v: u16) { self.code.extend_from_slice(&v.to_be_bytes()); }
fn l(&mut self, v: u32) { self.code.extend_from_slice(&v.to_be_bytes()); }
fn byte(&mut self, b: u8) { self.code.push(b); }
fn align(&mut self) { if self.code.len() % 2 != 0 { self.code.push(0); } }

fn error(&mut self, line: usize, msg: &str) {
    self.errors.push(AsmError { line, message: msg.into() });
}

fn define_label(&mut self, name: &str, val: u32, line: usize) {
    if self.labels.insert(name.to_ascii_lowercase(), val).is_some() {
        self.error(line, &format!("duplicate label: {}", name));
    }
}

// ───────────────────────────────────────────────────────────────
// EA encoding helpers
// ───────────────────────────────────────────────────────────────

fn ea_bits(&self, op: &Operand) -> (u8, u8) {
    match op {
        Operand::DataReg(r)  => (0b000, *r),
        Operand::AddrReg(r)  => (0b001, *r),
        Operand::Indirect(r) => (0b010, *r),
        Operand::PostInc(r)  => (0b011, *r),
        Operand::PreDec(r)   => (0b100, *r),
        Operand::Disp(_, r)  => (0b101, *r),
        Operand::AbsLong(_)  => (0b111, 0b001),
        Operand::Imm(_) | Operand::ImmSym(_) => (0b111, 0b100),
        Operand::Symbol(_)   => (0b111, 0b001),
    }
}

fn ea6(&self, op: &Operand) -> u16 {
    let (m, r) = self.ea_bits(op);
    ((m as u16) << 3) | r as u16
}

fn emit_ea_ext(&mut self, op: &Operand, size: Size, line: usize) {
    match op {
        Operand::DataReg(_) | Operand::AddrReg(_) |
        Operand::Indirect(_) | Operand::PostInc(_) |
        Operand::PreDec(_) => {}

        Operand::Disp(d, _) => self.w(*d as u16),

        Operand::AbsLong(a)  => self.l(*a),

        Operand::Imm(v) => match size {
            Size::Byte => self.w((*v as u8) as u16),
            Size::Word => self.w(*v as u16),
            Size::Long => self.l(*v as u32),
        },
        Operand::ImmSym(lbl) => {
            let off = self.code.len();
            self.l(0);
            self.fixups.push(Fixup { offset: off,
                label: lbl.to_ascii_lowercase(), kind: FixupKind::Abs32,
                pc_base: 0, line });
        }
        Operand::Symbol(lbl) => {
            let off = self.code.len();
            self.l(0);
            self.fixups.push(Fixup { offset: off,
                label: lbl.to_ascii_lowercase(), kind: FixupKind::Abs32,
                pc_base: 0, line });
        }
    }
}

// ───────────────────────────────────────────────────────────────
// Size helpers
// ───────────────────────────────────────────────────────────────

fn std_ss(size: Size) -> u16 {
    match size { Size::Byte => 0, Size::Word => 1, Size::Long => 2 }
}

fn move_ss(size: Size) -> u16 {
    match size { Size::Byte => 0b01, Size::Word => 0b11, Size::Long => 0b10 }
}


// ───────────────────────────────────────────────────────────────
// MOVE / MOVEA
// ───────────────────────────────────────────────────────────────

fn enc_move(&mut self, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "MOVE requires 2 operands"); }
    let (src, dst) = (&ops[0], &ops[1]);

    if let Operand::AddrReg(an) = dst {
        // MOVEA
        if size == Size::Byte {
            return self.error(line, "MOVEA does not support byte size");
        }
        let (sm, sr) = self.ea_bits(src);
        let opword = (Self::move_ss(size) << 12) | ((*an as u16) << 9)
            | (0b001 << 6) | ((sm as u16) << 3) | sr as u16;
        self.w(opword);
        self.emit_ea_ext(src, size, line);
        return;
    }

    let (sm, sr) = self.ea_bits(src);
    let (dm, dr) = self.ea_bits(dst);
    let opword = (Self::move_ss(size) << 12) | ((dr as u16) << 9)
        | ((dm as u16) << 6) | ((sm as u16) << 3) | sr as u16;
    self.w(opword);
    self.emit_ea_ext(src, size, line);
    self.emit_ea_ext(dst, size, line);
}

// ───────────────────────────────────────────────────────────────
// MOVEQ
// ───────────────────────────────────────────────────────────────

fn enc_moveq(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "MOVEQ requires 2 operands"); }
    let imm = match &ops[0] {
        Operand::Imm(v) => *v,
        _ => { return self.error(line, "MOVEQ: first operand must be immediate"); }
    };
    let dn = match &ops[1] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "MOVEQ: dest must be Dn"); }
    };
    self.w(0x7000 | ((dn as u16) << 9) | (imm as u8 as u16));
}

// ───────────────────────────────────────────────────────────────
// LEA / PEA
// ───────────────────────────────────────────────────────────────

fn enc_lea(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "LEA requires 2 operands"); }
    let an = match &ops[1] {
        Operand::AddrReg(r) => *r,
        _ => { return self.error(line, "LEA: dest must be An"); }
    };
    let (m, r) = self.ea_bits(&ops[0]);
    let opword = 0x4000 | ((an as u16) << 9) | (0b111 << 6) | ((m as u16) << 3) | r as u16;
    self.w(opword);
    self.emit_ea_ext(&ops[0], Size::Long, line);
}

fn enc_pea(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "PEA requires 1 operand"); }
    let (m, r) = self.ea_bits(&ops[0]);
    self.w(0x4840 | ((m as u16) << 3) | r as u16);
    self.emit_ea_ext(&ops[0], Size::Long, line);
}

// ───────────────────────────────────────────────────────────────
// Unary: CLR, NEG, NEGX, NOT, TST
// ───────────────────────────────────────────────────────────────

fn enc_unary(&mut self, base: u16, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "expected 1 operand"); }
    let opword = base | (Self::std_ss(size) << 6) | self.ea6(&ops[0]);
    self.w(opword);
    self.emit_ea_ext(&ops[0], size, line);
}

// ───────────────────────────────────────────────────────────────
// EXT, SWAP
// ───────────────────────────────────────────────────────────────

fn enc_ext(&mut self, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "EXT requires 1 operand"); }
    let dn = match &ops[0] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "EXT: operand must be Dn"); }
    };
    let opword = match size {
        Size::Word => 0x4880 | dn as u16,
        Size::Long => 0x48C0 | dn as u16,
        Size::Byte => { return self.error(line, "EXT: byte not valid"); }
    };
    self.w(opword);
}

fn enc_swap(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "SWAP requires 1 operand"); }
    let dn = match &ops[0] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "SWAP: operand must be Dn"); }
    };
    self.w(0x4840 | dn as u16);
}

// ───────────────────────────────────────────────────────────────
// Immediate ALU: ADDI, SUBI, CMPI, ANDI, ORI, EORI
// ───────────────────────────────────────────────────────────────

fn enc_imm_alu(&mut self, base: u16, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "expected 2 operands"); }
    let imm = match &ops[0] {
        Operand::Imm(v) => *v,
        _ => { return self.error(line, "first operand must be immediate"); }
    };
    let (m, r) = self.ea_bits(&ops[1]);
    self.w(base | (Self::std_ss(size) << 6) | ((m as u16) << 3) | r as u16);
    match size {
        Size::Byte => self.w((imm as u8) as u16),
        Size::Word => self.w(imm as u16),
        Size::Long => self.l(imm as u32),
    }
    self.emit_ea_ext(&ops[1], size, line);
}

// ───────────────────────────────────────────────────────────────
// ADDQ / SUBQ
// ───────────────────────────────────────────────────────────────

fn enc_quick(&mut self, sub: bool, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "expected 2 operands"); }
    let imm = match &ops[0] {
        Operand::Imm(v) => *v,
        _ => { return self.error(line, "first operand must be immediate 1–8"); }
    };
    if imm < 1 || imm > 8 {
        return self.error(line, "quick immediate must be 1–8");
    }
    let field = if imm == 8 { 0u16 } else { imm as u16 };
    let bit8 = if sub { 1u16 } else { 0u16 };
    let opword = 0x5000 | (field << 9) | (bit8 << 8)
        | (Self::std_ss(size) << 6) | self.ea6(&ops[1]);
    self.w(opword);
    self.emit_ea_ext(&ops[1], size, line);
}

// ───────────────────────────────────────────────────────────────
// ALU: ADD, SUB, AND, OR
// ───────────────────────────────────────────────────────────────

fn enc_alu(&mut self, group: u16, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "expected 2 operands"); }
    let (src, dst) = (&ops[0], &ops[1]);

    // Auto-select immediate form
    if matches!(src, Operand::Imm(_)) {
        let imm_base = match group {
            0xD => 0x0600, // ADDI
            0x9 => 0x0400, // SUBI
            0xC => 0x0200, // ANDI
            0x8 => 0x0000, // ORI
            _   => { return self.error(line, "unexpected immediate form"); }
        };
        return self.enc_imm_alu(imm_base, size, ops, line);
    }

    let base = group << 12;
    let ss = Self::std_ss(size);

    // Destination is An → ADDA/SUBA
    if let Operand::AddrReg(an) = dst {
        if group != 0xD && group != 0x9 {
            return self.error(line, "address register dest only valid for ADD/SUB");
        }
        let opm = if size == Size::Word { 0b011u16 } else { 0b111u16 };
        let opword = base | ((*an as u16) << 9) | (opm << 6) | self.ea6(src);
        self.w(opword);
        self.emit_ea_ext(src, size, line);
        return;
    }

    // Destination is Dn → ea OP Dn → Dn
    if let Operand::DataReg(dn) = dst {
        let opm = ss; // 000/001/010
        let opword = base | ((*dn as u16) << 9) | (opm << 6) | self.ea6(src);
        self.w(opword);
        self.emit_ea_ext(src, size, line);
        return;
    }

    // Source is Dn → Dn OP ea → ea
    if let Operand::DataReg(dn) = src {
        let opm = ss + 4; // 100/101/110
        let opword = base | ((*dn as u16) << 9) | (opm << 6) | self.ea6(dst);
        self.w(opword);
        self.emit_ea_ext(dst, size, line);
        return;
    }

    self.error(line, "invalid operand combination for ALU instruction");
}

// ───────────────────────────────────────────────────────────────
// CMP / CMPA
// ───────────────────────────────────────────────────────────────

fn enc_cmp(&mut self, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "CMP requires 2 operands"); }
    let (src, dst) = (&ops[0], &ops[1]);

    if matches!(src, Operand::Imm(_)) {
        return self.enc_imm_alu(0x0C00, size, ops, line); // CMPI
    }

    if let Operand::AddrReg(an) = dst {
        let opm = if size == Size::Word { 0b011u16 } else { 0b111u16 };
        let opword = 0xB000 | ((*an as u16) << 9) | (opm << 6) | self.ea6(src);
        self.w(opword);
        self.emit_ea_ext(src, size, line);
        return;
    }

    if let Operand::DataReg(dn) = dst {
        let opm = Self::std_ss(size);
        let opword = 0xB000 | ((*dn as u16) << 9) | (opm << 6) | self.ea6(src);
        self.w(opword);
        self.emit_ea_ext(src, size, line);
        return;
    }

    self.error(line, "CMP: dest must be Dn or An");
}

// ───────────────────────────────────────────────────────────────
// EOR
// ───────────────────────────────────────────────────────────────

fn enc_eor(&mut self, size: Size, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "EOR requires 2 operands"); }

    if matches!(&ops[0], Operand::Imm(_)) {
        return self.enc_imm_alu(0x0A00, size, ops, line); // EORI
    }

    let dn = match &ops[0] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "EOR: source must be Dn"); }
    };
    let opm = Self::std_ss(size) + 4; // 100/101/110
    let opword = 0xB000 | ((dn as u16) << 9) | (opm << 6) | self.ea6(&ops[1]);
    self.w(opword);
    self.emit_ea_ext(&ops[1], size, line);
}

// ───────────────────────────────────────────────────────────────
// MUL / DIV
// ───────────────────────────────────────────────────────────────

fn enc_muldiv(&mut self, base: u16, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "expected 2 operands"); }
    let dn = match &ops[1] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "dest must be Dn"); }
    };
    let opword = base | ((dn as u16) << 9) | self.ea6(&ops[0]);
    self.w(opword);
    self.emit_ea_ext(&ops[0], Size::Word, line);
}

// ───────────────────────────────────────────────────────────────
// Shifts / Rotates
// ───────────────────────────────────────────────────────────────

fn enc_shift(&mut self, left: bool, shift_type: u16, size: Size,
             ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "shift requires 2 operands"); }
    let dn = match &ops[1] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "shift: dest must be Dn"); }
    };
    let dir = if left { 1u16 } else { 0u16 };
    let ss = Self::std_ss(size);

    match &ops[0] {
        Operand::Imm(count) => {
            let c = *count;
            if c < 1 || c > 8 {
                return self.error(line, "shift count must be 1–8");
            }
            let cf = if c == 8 { 0u16 } else { c as u16 };
            self.w(0xE000 | (cf << 9) | (dir << 8) | (ss << 6)
                   | (shift_type << 3) | dn as u16);
        }
        Operand::DataReg(cr) => {
            self.w(0xE000 | ((*cr as u16) << 9) | (dir << 8) | (ss << 6)
                   | (1 << 5) | (shift_type << 3) | dn as u16);
        }
        _ => self.error(line, "shift: source must be #count or Dn"),
    }
}

// ───────────────────────────────────────────────────────────────
// Bcc / BRA / BSR
// ───────────────────────────────────────────────────────────────

fn enc_bcc(&mut self, cond: u8, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "branch requires 1 operand"); }
    match &ops[0] {
        Operand::Symbol(lbl) => {
            self.w(0x6000 | ((cond as u16) << 8));
            let pc_base = self.here();
            let off = self.code.len();
            self.w(0);
            self.fixups.push(Fixup { offset: off,
                label: lbl.to_ascii_lowercase(), kind: FixupKind::Branch16,
                pc_base, line });
        }
        _ => self.error(line, "branch target must be a label"),
    }
}

// ───────────────────────────────────────────────────────────────
// DBcc
// ───────────────────────────────────────────────────────────────

fn enc_dbcc(&mut self, cond: u8, ops: &[Operand], line: usize) {
    if ops.len() != 2 { return self.error(line, "DBcc requires Dn,label"); }
    let dn = match &ops[0] {
        Operand::DataReg(r) => *r,
        _ => { return self.error(line, "DBcc: first operand must be Dn"); }
    };
    match &ops[1] {
        Operand::Symbol(lbl) => {
            self.w(0x50C8 | ((cond as u16) << 8) | dn as u16);
            let pc_base = self.here();
            let off = self.code.len();
            self.w(0);
            self.fixups.push(Fixup { offset: off,
                label: lbl.to_ascii_lowercase(), kind: FixupKind::Branch16,
                pc_base, line });
        }
        _ => self.error(line, "DBcc: second operand must be a label"),
    }
}

// ───────────────────────────────────────────────────────────────
// JMP / JSR
// ───────────────────────────────────────────────────────────────

fn enc_jmp(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "JMP requires 1 operand"); }
    let (m, r) = self.ea_bits(&ops[0]);
    self.w(0x4EC0 | ((m as u16) << 3) | r as u16);
    self.emit_ea_ext(&ops[0], Size::Long, line);
}

fn enc_jsr(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "JSR requires 1 operand"); }
    let (m, r) = self.ea_bits(&ops[0]);
    self.w(0x4E80 | ((m as u16) << 3) | r as u16);
    self.emit_ea_ext(&ops[0], Size::Long, line);
}

// ───────────────────────────────────────────────────────────────
// STOP / TRAP / no-operand
// ───────────────────────────────────────────────────────────────

fn enc_stop(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "STOP requires #imm"); }
    let v = match &ops[0] {
        Operand::Imm(v) => *v as u16,
        _ => { return self.error(line, "STOP: operand must be immediate"); }
    };
    self.w(0x4E72);
    self.w(v);
}

fn enc_trap(&mut self, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "TRAP requires #vector"); }
    let v = match &ops[0] {
        Operand::Imm(v) => *v,
        _ => { return self.error(line, "TRAP: operand must be immediate"); }
    };
    if v < 0 || v > 15 {
        return self.error(line, "TRAP vector must be 0–15");
    }
    self.w(0x4E40 | v as u16);
}

// ───────────────────────────────────────────────────────────────
// Scc
// ───────────────────────────────────────────────────────────────

fn enc_scc(&mut self, cond: u8, ops: &[Operand], line: usize) {
    if ops.len() != 1 { return self.error(line, "Scc requires 1 operand"); }
    self.w(0x50C0 | ((cond as u16) << 8) | self.ea6(&ops[0]));
    self.emit_ea_ext(&ops[0], Size::Byte, line);
}

// ───────────────────────────────────────────────────────────────
// Directives
// ───────────────────────────────────────────────────────────────

fn dir_ascii(&mut self, rest: &str, null_term: bool, line: usize) {
    match parse_string_literal(rest) {
        Ok(bytes) => {
            for b in &bytes { self.byte(*b); }
            if null_term { self.byte(0); }
            self.align();
        }
        Err(e) => self.error(line, &e),
    }
}

fn dir_data(&mut self, rest: &str, size: Size, line: usize) {
    for tok in split_operands(rest) {
        match parse_number(tok) {
            Ok(v) => match size {
                Size::Byte => self.byte(v as u8),
                Size::Word => self.w(v as u16),
                Size::Long => self.l(v as u32),
            },
            Err(e) => self.error(line, &format!("bad value '{}': {}", tok, e)),
        }
    }
    if matches!(size, Size::Byte) { self.align(); }
}

fn dir_align(&mut self, _rest: &str, _line: usize) {
    self.align();
}

// ───────────────────────────────────────────────────────────────
// Instruction dispatch
// ───────────────────────────────────────────────────────────────

fn dispatch(&mut self, mn: &str, size: Option<Size>, ops: &[Operand], line: usize) {
    // Resolve size — default to Word if unspecified.  Individual
    // encoders report errors for invalid sizes (e.g. MOVEA.B).
    let s = size.unwrap_or(Size::Word);

    match mn {
        "move" | "movea" => self.enc_move(s, ops, line),
        "moveq"          => self.enc_moveq(ops, line),
        "lea"            => self.enc_lea(ops, line),
        "pea"            => self.enc_pea(ops, line),
        "clr"            => self.enc_unary(0x4200, s, ops, line),
        "neg"            => self.enc_unary(0x4400, s, ops, line),
        "negx"           => self.enc_unary(0x4000, s, ops, line),
        "not"            => self.enc_unary(0x4600, s, ops, line),
        "tst"            => self.enc_unary(0x4A00, s, ops, line),
        "ext"            => self.enc_ext(s, ops, line),
        "swap"           => self.enc_swap(ops, line),

        "add"  => self.enc_alu(0xD, s, ops, line),
        "sub"  => self.enc_alu(0x9, s, ops, line),
        "and"  => self.enc_alu(0xC, s, ops, line),
        "or"   => self.enc_alu(0x8, s, ops, line),
        "cmp"  => self.enc_cmp(s, ops, line),
        "eor"  => self.enc_eor(s, ops, line),

        "addi" => self.enc_imm_alu(0x0600, s, ops, line),
        "subi" => self.enc_imm_alu(0x0400, s, ops, line),
        "cmpi" => self.enc_imm_alu(0x0C00, s, ops, line),
        "andi" => self.enc_imm_alu(0x0200, s, ops, line),
        "ori"  => self.enc_imm_alu(0x0000, s, ops, line),
        "eori" => self.enc_imm_alu(0x0A00, s, ops, line),

        "addq" => self.enc_quick(false, s, ops, line),
        "subq" => self.enc_quick(true,  s, ops, line),

        "mulu" => self.enc_muldiv(0xC0C0, ops, line),
        "muls" => self.enc_muldiv(0xC1C0, ops, line),
        "divu" => self.enc_muldiv(0x80C0, ops, line),
        "divs" => self.enc_muldiv(0x81C0, ops, line),

        "asl"  => self.enc_shift(true,  0b00, s, ops, line),
        "asr"  => self.enc_shift(false, 0b00, s, ops, line),
        "lsl"  => self.enc_shift(true,  0b01, s, ops, line),
        "lsr"  => self.enc_shift(false, 0b01, s, ops, line),
        "rol"  => self.enc_shift(true,  0b11, s, ops, line),
        "ror"  => self.enc_shift(false, 0b11, s, ops, line),
        "roxl" => self.enc_shift(true,  0b10, s, ops, line),
        "roxr" => self.enc_shift(false, 0b10, s, ops, line),

        "bra" => self.enc_bcc(0x0, ops, line),
        "bsr" => self.enc_bcc(0x1, ops, line),
        "bhi" => self.enc_bcc(0x2, ops, line),
        "bls" => self.enc_bcc(0x3, ops, line),
        "bcc" => self.enc_bcc(0x4, ops, line),
        "bcs" => self.enc_bcc(0x5, ops, line),
        "bne" => self.enc_bcc(0x6, ops, line),
        "beq" => self.enc_bcc(0x7, ops, line),
        "bvc" => self.enc_bcc(0x8, ops, line),
        "bvs" => self.enc_bcc(0x9, ops, line),
        "bpl" => self.enc_bcc(0xA, ops, line),
        "bmi" => self.enc_bcc(0xB, ops, line),
        "bge" => self.enc_bcc(0xC, ops, line),
        "blt" => self.enc_bcc(0xD, ops, line),
        "bgt" => self.enc_bcc(0xE, ops, line),
        "ble" => self.enc_bcc(0xF, ops, line),

        "dbra" | "dbf" => self.enc_dbcc(0x1, ops, line),

        "jmp"  => self.enc_jmp(ops, line),
        "jsr"  => self.enc_jsr(ops, line),

        "rts"  => self.w(0x4E75),
        "rte"  => self.w(0x4E73),
        "rtr"  => self.w(0x4E77),
        "nop"  => self.w(0x4E71),

        "stop" => self.enc_stop(ops, line),
        "trap" => self.enc_trap(ops, line),

        "st"  => self.enc_scc(0x0, ops, line),
        "sf"  => self.enc_scc(0x1, ops, line),
        "shi" => self.enc_scc(0x2, ops, line),
        "sls" => self.enc_scc(0x3, ops, line),
        "scc" => self.enc_scc(0x4, ops, line),
        "scs" => self.enc_scc(0x5, ops, line),
        "sne" => self.enc_scc(0x6, ops, line),
        "seq" => self.enc_scc(0x7, ops, line),
        "svc" => self.enc_scc(0x8, ops, line),
        "svs" => self.enc_scc(0x9, ops, line),
        "spl" => self.enc_scc(0xA, ops, line),
        "smi" => self.enc_scc(0xB, ops, line),
        "sge" => self.enc_scc(0xC, ops, line),
        "slt" => self.enc_scc(0xD, ops, line),
        "sgt" => self.enc_scc(0xE, ops, line),
        "sle" => self.enc_scc(0xF, ops, line),

        _ => self.error(line, &format!("unknown instruction: {}", mn)),
    }
}

// ───────────────────────────────────────────────────────────────
// Fixup resolution
// ───────────────────────────────────────────────────────────────

fn resolve(mut self) -> Result<Vec<u8>, Vec<AsmError>> {
    for fixup in &self.fixups {
        let target = match self.labels.get(&fixup.label) {
            Some(a) => *a,
            None => {
                self.errors.push(AsmError {
                    line: fixup.line,
                    message: format!("unresolved label: {}", fixup.label),
                });
                continue;
            }
        };
        match fixup.kind {
            FixupKind::Branch16 => {
                let disp = target as i32 - fixup.pc_base as i32;
                if disp > i16::MAX as i32 || disp < i16::MIN as i32 {
                    self.errors.push(AsmError {
                        line: fixup.line,
                        message: format!("branch to '{}' out of range ({})",
                                         fixup.label, disp),
                    });
                    continue;
                }
                let b = (disp as i16).to_be_bytes();
                self.code[fixup.offset] = b[0];
                self.code[fixup.offset + 1] = b[1];
            }
            FixupKind::Abs32 => {
                let b = target.to_be_bytes();
                self.code[fixup.offset..fixup.offset + 4].copy_from_slice(&b);
            }
        }
    }
    if self.errors.is_empty() { Ok(self.code) } else { Err(self.errors) }
}

} // impl Ctx

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

/// Assemble MC68000 source text into a flat binary image.
///
/// `base` is the load address of the first emitted byte.
/// Returns the binary or a list of errors with line numbers.
pub fn assemble(source: &str, base: u32) -> Result<Vec<u8>, Vec<AsmError>> {
    let mut ctx = Ctx::new(base);

    for (i, raw) in source.lines().enumerate() {
        let line = i + 1;

        // Full-line comment
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('*') {
            continue;
        }

        let text = strip_comment(raw);
        let text = text.trim();
        if text.is_empty() { continue; }

        // ── Equate: LABEL = VALUE ──────────────────────────────
        if let Some(eq) = text.find('=') {
            if !text[..eq].contains('"') {
                let lbl = text[..eq].trim().trim_end_matches(':');
                let val_s = text[eq+1..].trim();
                match parse_number(val_s) {
                    Ok(v) => ctx.define_label(lbl, v as u32, line),
                    Err(e) => ctx.error(line, &format!("bad equate value: {}", e)),
                }
                continue;
            }
        }

        // ── Extract label (if colon present) ───────────────────
        let (label, rest) = if let Some(colon) = text.find(':') {
            let before = text[..colon].trim();
            if !before.is_empty() && !before.contains(' ') && !before.contains('\t') {
                (Some(before), text[colon+1..].trim())
            } else {
                (None, text)
            }
        } else {
            (None, text)
        };

        if let Some(lbl) = label {
            ctx.define_label(lbl, ctx.here(), line);
        }

        if rest.is_empty() { continue; }

        // ── Split mnemonic from operand string ─────────────────
        let (first, operand_str) = match rest.find(|c: char| c == ' ' || c == '\t') {
            Some(pos) => (&rest[..pos], rest[pos..].trim()),
            None      => (rest, ""),
        };

        let (mn, size) = parse_mnemonic(first);
        let mn = mn.to_ascii_lowercase();

        // ── Directives ─────────────────────────────────────────
        match mn.as_str() {
            ".ascii"  => { ctx.dir_ascii(operand_str, false, line); continue; }
            ".asciiz" => { ctx.dir_ascii(operand_str, true,  line); continue; }
            ".byte" | "dc.b" => { ctx.dir_data(operand_str, Size::Byte, line); continue; }
            ".word" | "dc.w" => { ctx.dir_data(operand_str, Size::Word, line); continue; }
            ".long" | "dc.l" => { ctx.dir_data(operand_str, Size::Long, line); continue; }
            ".align"         => { ctx.dir_align(operand_str, line); continue; }
            ".equ" => {
                if let Some(lbl) = label {
                    match parse_number(operand_str) {
                        Ok(v) => {
                            // Re-define: remove the address label, set value
                            ctx.labels.insert(lbl.to_ascii_lowercase(), v as u32);
                        }
                        Err(e) => ctx.error(line, &format!(".equ: {}", e)),
                    }
                } else {
                    ctx.error(line, ".equ requires a label");
                }
                continue;
            }
            _ => {}
        }

        // ── Parse operands and dispatch instruction ────────────
        let op_strs = split_operands(operand_str);
        let mut ops = Vec::with_capacity(op_strs.len());
        for os in &op_strs {
            if os.is_empty() { continue; }
            match parse_operand(os) {
                Ok(op)  => ops.push(op),
                Err(e)  => ctx.error(line, &format!("bad operand '{}': {}", os, e)),
            }
        }

        if ctx.errors.len() > 100 {
            ctx.error(line, "too many errors, stopping");
            break;
        }

        ctx.dispatch(&mn, size, &ops, line);
    }

    ctx.resolve()
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_number() {
        assert_eq!(parse_number("$FF").unwrap(), 255);
        assert_eq!(parse_number("0xFF").unwrap(), 255);
        assert_eq!(parse_number("$F00000").unwrap(), 0xF00000_i32);
        assert_eq!(parse_number("42").unwrap(), 42);
        assert_eq!(parse_number("-1").unwrap(), -1);
    }

    #[test]
    fn parse_operands() {
        assert!(matches!(parse_operand("d0").unwrap(), Operand::DataReg(0)));
        assert!(matches!(parse_operand("A7").unwrap(), Operand::AddrReg(7)));
        assert!(matches!(parse_operand("sp").unwrap(), Operand::AddrReg(7)));
        assert!(matches!(parse_operand("(a0)").unwrap(), Operand::Indirect(0)));
        assert!(matches!(parse_operand("(a3)+").unwrap(), Operand::PostInc(3)));
        assert!(matches!(parse_operand("-(a7)").unwrap(), Operand::PreDec(7)));
        assert!(matches!(parse_operand("#$2700").unwrap(), Operand::Imm(0x2700)));
        assert!(matches!(parse_operand("$F00000").unwrap(), Operand::AbsLong(0xF00000)));
        assert!(matches!(parse_operand("4(a0)").unwrap(), Operand::Disp(4, 0)));
        assert!(matches!(parse_operand("label").unwrap(), Operand::Symbol(_)));
    }

    #[test]
    fn assemble_hello() {
        let source = r#"
; Hello from Anka — assembled from text source
start:
    lea     message,a0
    lea     $f00000,a1
loop:
    move.b  (a0)+,d0
    beq     done
    move.b  d0,(a1)
    bra     loop
done:
    stop    #$2700
message:
    .ascii  "Hello from Anka!\n"
    .byte   0
"#;
        let bin = assemble(source, 0x1000).expect("assembly failed");
        assert!(!bin.is_empty());

        // The string should appear in the binary
        let needle = b"Hello from Anka!";
        assert!(bin.windows(needle.len()).any(|w| w == needle),
            "string not found in output");

        // First word should be part of LEA (0x41F9)
        assert_eq!(bin[0], 0x41);
        assert_eq!(bin[1], 0xF9);
    }

    #[test]
    fn assemble_with_equate() {
        let source = r#"
CONSOLE = $F00000
    lea     CONSOLE,a1
    stop    #$2700
"#;
        let bin = assemble(source, 0x1000).expect("assembly failed");
        // LEA $F00000,A1 = 43 F9 00 F0 00 00
        assert_eq!(&bin[0..6], &[0x43, 0xF9, 0x00, 0xF0, 0x00, 0x00]);
    }

    #[test]
    fn moveq_encoding() {
        let source = "    moveq #42,d0\n    stop #$2700\n";
        let bin = assemble(source, 0x1000).unwrap();
        assert_eq!(bin[0], 0x70); // MOVEQ
        assert_eq!(bin[1], 0x2A); // #42
    }

    #[test]
    fn shift_encoding() {
        let source = "    lsr.b #4,d0\n";
        let bin = assemble(source, 0x1000).unwrap();
        // LSR.B #4,D0: 1110 100 0 00 0 01 000 = 0xE808
        assert_eq!(bin[0], 0xE8);
        assert_eq!(bin[1], 0x08);
    }

    #[test]
    fn unresolved_label_is_error() {
        let source = "    bra nowhere\n";
        let result = assemble(source, 0x1000);
        assert!(result.is_err());
    }
}

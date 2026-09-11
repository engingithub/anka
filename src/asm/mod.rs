//! Programmatic MC68000 assembler.
//!
//! Constructs binary images from Rust method calls rather than parsing
//! text.  Supports labels with forward references and two fixup kinds:
//!
//!   - Branch16: 16-bit PC-relative displacement (Bcc.W, BSR.W, DBcc)
//!   - Absolute32: 32-bit absolute address (LEA xxx.L)
//!
//! This is the seed of AnkaASM.

use std::collections::HashMap;

enum FixupKind {
    Branch16,
    Absolute32,
}

struct Fixup {
    code_offset: usize,
    label: String,
    kind: FixupKind,
    pc_base: u32,
}

pub struct Asm {
    code: Vec<u8>,
    base: u32,
    labels: HashMap<String, u32>,
    fixups: Vec<Fixup>,
}

impl Asm {
    pub fn new(base: u32) -> Self {
        Self {
            code: Vec::new(),
            base,
            labels: HashMap::new(),
            fixups: Vec::new(),
        }
    }

    pub fn here(&self) -> u32 {
        self.base + self.code.len() as u32
    }

    pub fn label(&mut self, name: &str) {
        let addr = self.here();
        assert!(
            self.labels.insert(name.into(), addr).is_none(),
            "duplicate label: {}",
            name
        );
    }

    // ---------------------------------------------------------------
    // Raw emit
    // ---------------------------------------------------------------

    fn w(&mut self, v: u16) {
        self.code.extend_from_slice(&v.to_be_bytes());
    }

    fn l(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_be_bytes());
    }

    // ---------------------------------------------------------------
    // Branch/fixup helpers
    // ---------------------------------------------------------------

    fn branch16(&mut self, cond: u8, label: &str) {
        let pc_base = self.here() + 2;
        self.w(0x6000 | ((cond as u16) << 8));
        let off = self.code.len();
        self.w(0);
        self.fixups.push(Fixup {
            code_offset: off,
            label: label.into(),
            kind: FixupKind::Branch16,
            pc_base,
        });
    }

    fn abs32_fixup(&mut self, label: &str) {
        let off = self.code.len();
        self.l(0);
        self.fixups.push(Fixup {
            code_offset: off,
            label: label.into(),
            kind: FixupKind::Absolute32,
            pc_base: 0,
        });
    }

    // ---------------------------------------------------------------
    // Data registers
    // ---------------------------------------------------------------

    /// MOVEQ #imm8, Dn
    pub fn moveq(&mut self, imm: i8, dn: u8) {
        self.w(0x7000 | ((dn as u16) << 9) | (imm as u8 as u16));
    }

    /// CLR.L Dn
    pub fn clr_l(&mut self, dn: u8) {
        self.w(0x4280 | dn as u16);
    }

    /// SWAP Dn
    pub fn swap(&mut self, dn: u8) {
        self.w(0x4840 | dn as u16);
    }

    /// TST.L Dn
    pub fn tst_l(&mut self, dn: u8) {
        self.w(0x4A80 | dn as u16);
    }

    /// EXT.W Dn (sign-extend byte → word)
    pub fn ext_w(&mut self, dn: u8) {
        self.w(0x4880 | dn as u16);
    }

    /// EXT.L Dn (sign-extend word → long)
    pub fn ext_l(&mut self, dn: u8) {
        self.w(0x48C0 | dn as u16);
    }

    // ---------------------------------------------------------------
    // MOVE variants
    // ---------------------------------------------------------------

    /// MOVE.B (An)+, Dn
    pub fn move_b_postinc_dn(&mut self, an: u8, dn: u8) {
        self.w(0x1018 | ((dn as u16) << 9) | an as u16);
    }

    /// MOVE.B Dn, (An) — write Dn byte to address in An
    pub fn move_b_dn_indirect(&mut self, dn: u8, an: u8) {
        self.w(0x1080 | ((an as u16) << 9) | dn as u16);
    }

    /// MOVE.B d16(An), Dn — displacement addressing
    pub fn move_b_disp_dn(&mut self, disp: i16, an: u8, dn: u8) {
        self.w(0x1028 | ((dn as u16) << 9) | an as u16);
        self.w(disp as u16);
    }

    /// MOVE.L Dn, Dm
    pub fn move_l_dn_dn(&mut self, src: u8, dst: u8) {
        self.w(0x2000 | ((dst as u16) << 9) | src as u16);
    }

    /// MOVE.L An, Dn
    pub fn move_l_an_dn(&mut self, an: u8, dn: u8) {
        self.w(0x2008 | ((dn as u16) << 9) | an as u16);
    }

    /// MOVEA.L Dn, An
    pub fn movea_l_dn(&mut self, dn: u8, an: u8) {
        self.w(0x2040 | ((an as u16) << 9) | dn as u16);
    }

    /// MOVE.L Dn, -(A7) — push long
    pub fn push_l(&mut self, dn: u8) {
        self.w(0x2F00 | dn as u16);
    }

    /// MOVE.L (A7)+, Dn — pop long
    pub fn pop_l(&mut self, dn: u8) {
        self.w(0x201F | ((dn as u16) << 9));
    }

    // ---------------------------------------------------------------
    // Address registers
    // ---------------------------------------------------------------

    /// LEA xxx.L, An — load effective address (absolute long)
    pub fn lea(&mut self, addr: u32, an: u8) {
        self.w(0x41F9 | ((an as u16) << 9));
        self.l(addr);
    }

    /// LEA label, An — with forward-reference fixup
    pub fn lea_label(&mut self, label: &str, an: u8) {
        self.w(0x41F9 | ((an as u16) << 9));
        self.abs32_fixup(label);
    }

    // ---------------------------------------------------------------
    // Immediate operations on Dn
    // ---------------------------------------------------------------

    /// ANDI.B #imm, Dn
    pub fn andi_b(&mut self, imm: u8, dn: u8) {
        self.w(0x0200 | dn as u16);
        self.w(imm as u16);
    }

    /// CMPI.B #imm, Dn
    pub fn cmpi_b(&mut self, imm: u8, dn: u8) {
        self.w(0x0C00 | dn as u16);
        self.w(imm as u16);
    }

    /// ADDI.B #imm, Dn
    pub fn addi_b(&mut self, imm: u8, dn: u8) {
        self.w(0x0600 | dn as u16);
        self.w(imm as u16);
    }

    /// SUBI.B #imm, Dn
    pub fn subi_b(&mut self, imm: u8, dn: u8) {
        self.w(0x0400 | dn as u16);
        self.w(imm as u16);
    }

    /// ADDQ.L #imm3, Dn  (imm 1–8)
    pub fn addq_l(&mut self, imm: u8, dn: u8) {
        let field = if imm == 8 { 0u16 } else { imm as u16 };
        self.w(0x5080 | (field << 9) | dn as u16);
    }

    /// OR.B Ds, Dd — result in Dd
    pub fn or_b_dn(&mut self, src: u8, dst: u8) {
        self.w(0x8000 | ((dst as u16) << 9) | src as u16);
    }

    // ---------------------------------------------------------------
    // Shifts
    // ---------------------------------------------------------------

    /// LSR.B #count, Dn (count 1–8)
    pub fn lsr_b(&mut self, count: u8, dn: u8) {
        let c = if count == 8 { 0u16 } else { count as u16 };
        self.w(0xE008 | (c << 9) | dn as u16);
    }

    /// LSR.W #count, Dn
    pub fn lsr_w(&mut self, count: u8, dn: u8) {
        let c = if count == 8 { 0u16 } else { count as u16 };
        self.w(0xE048 | (c << 9) | dn as u16);
    }

    /// LSL.L #count, Dn
    pub fn lsl_l(&mut self, count: u8, dn: u8) {
        let c = if count == 8 { 0u16 } else { count as u16 };
        self.w(0xE188 | (c << 9) | dn as u16);
    }

    // ---------------------------------------------------------------
    // Control flow
    // ---------------------------------------------------------------

    pub fn rts(&mut self) {
        self.w(0x4E75);
    }
    pub fn nop(&mut self) {
        self.w(0x4E71);
    }
    pub fn stop(&mut self, imm: u16) {
        self.w(0x4E72);
        self.w(imm);
    }
    /// JMP (An)
    pub fn jmp_indirect(&mut self, an: u8) {
        self.w(0x4ED0 | an as u16);
    }

    // ---------------------------------------------------------------
    // Branches (word displacement, label-based)
    // ---------------------------------------------------------------

    pub fn bra(&mut self, l: &str) { self.branch16(0x0, l); }
    pub fn bsr(&mut self, l: &str) { self.branch16(0x1, l); }
    pub fn bhi(&mut self, l: &str) { self.branch16(0x2, l); }
    pub fn bls(&mut self, l: &str) { self.branch16(0x3, l); }
    pub fn bcc(&mut self, l: &str) { self.branch16(0x4, l); }
    pub fn bcs(&mut self, l: &str) { self.branch16(0x5, l); }
    pub fn bne(&mut self, l: &str) { self.branch16(0x6, l); }
    pub fn beq(&mut self, l: &str) { self.branch16(0x7, l); }
    pub fn bpl(&mut self, l: &str) { self.branch16(0xA, l); }
    pub fn bmi(&mut self, l: &str) { self.branch16(0xB, l); }
    pub fn bge(&mut self, l: &str) { self.branch16(0xC, l); }
    pub fn blt(&mut self, l: &str) { self.branch16(0xD, l); }

    /// DBRA Dn, label  (decrement and branch if not −1)
    pub fn dbra(&mut self, dn: u8, label: &str) {
        let pc_base = self.here() + 2;
        self.w(0x51C8 | dn as u16);
        let off = self.code.len();
        self.w(0);
        self.fixups.push(Fixup {
            code_offset: off,
            label: label.into(),
            kind: FixupKind::Branch16,
            pc_base,
        });
    }

    // ---------------------------------------------------------------
    // Data
    // ---------------------------------------------------------------

    /// Emit a null-terminated ASCII string, word-aligned.
    pub fn ascii_z(&mut self, s: &str) {
        self.code.extend_from_slice(s.as_bytes());
        self.code.push(0);
        if self.code.len() % 2 != 0 {
            self.code.push(0);
        }
    }

    // ---------------------------------------------------------------
    // Resolve and produce binary
    // ---------------------------------------------------------------

    pub fn assemble(mut self) -> Vec<u8> {
        for fixup in &self.fixups {
            let target = *self
                .labels
                .get(fixup.label.as_str())
                .unwrap_or_else(|| panic!("unresolved label: {}", fixup.label));
            match fixup.kind {
                FixupKind::Branch16 => {
                    let disp = target as i32 - fixup.pc_base as i32;
                    let bytes = (disp as i16).to_be_bytes();
                    self.code[fixup.code_offset] = bytes[0];
                    self.code[fixup.code_offset + 1] = bytes[1];
                }
                FixupKind::Absolute32 => {
                    let bytes = target.to_be_bytes();
                    self.code[fixup.code_offset..fixup.code_offset + 4]
                        .copy_from_slice(&bytes);
                }
            }
        }
        self.code
    }
}

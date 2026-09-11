//! Anka64 machine description — THE single source of truth.
//!
//! Every semantic consumer of the ISA derives from this table:
//!   decoder, assembler, disassembler, Rust execution, Kleis theory.
//!
//! An instruction does not exist unless every consumer agrees
//! that it exists.

// ───────────────────────────────────────────────────────────────────
// Instruction format
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// [opcode(6)] [rd(4)] [rs1(4)] [rs2(4)] [func(14)]
    R,
    /// [opcode(6)] [rd(4)] [rs1(4)] [imm18(18)]
    I,
    /// [opcode(6)] [cond(4)] [offset22(22)]
    B,
    /// [opcode(6)] [imm26(26)]
    S,
}

// ───────────────────────────────────────────────────────────────────
// Semantics — what the instruction does architecturally
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sem {
    /// Register-register or register-immediate ALU operation.
    Alu(AluOp),
    /// Compare (ALU subtract, flags only, result discarded).
    Cmp,
    /// Register-to-register move.
    Mov,
    /// Load immediate (sign-extended).
    Movi,
    /// Load from memory (one read transaction).
    Load,
    /// Store to memory (one write transaction).
    Store,
    /// Compute effective address (no memory transaction).
    Lea,
    /// Conditional branch.
    Branch,
    /// Call with link (saves return address to LR).
    Call,
    /// Return to LR.
    Ret,
    /// Trap — user → supervisor.
    Trap,
    /// Exception return — supervisor → saved privilege.
    Eret,
    /// No operation.
    Nop,
    /// Halt execution.
    Halt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Asr,
    Mul,
}

// ───────────────────────────────────────────────────────────────────
// Memory effect
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemEffect {
    None,
    Load,
    Store,
}

// ───────────────────────────────────────────────────────────────────
// Flag effect
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagEffect {
    /// Z, N from result; C, V from addition.
    Arith,
    /// Z, N from result; C from unsigned comparison; V from signed.
    Sub,
    /// Z, N from result; C and V cleared.
    Logic,
    /// No flag change.
    None,
}

// ───────────────────────────────────────────────────────────────────
// Operand pattern — how to interpret/display the encoded fields
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operands {
    /// rd, rs1, rs2
    RdRs1Rs2,
    /// rd, rs1  (rs2 unused)
    RdRs1,
    /// rs1, rs2  (rd unused)
    Rs1Rs2,
    /// rd, rs1, #imm
    RdRs1Imm,
    /// rs1, #imm  (rd unused)
    Rs1Imm,
    /// rd, #imm  (rs1 unused)
    RdImm,
    /// rd, [rs1 + disp]
    RdBaseDisp,
    /// src, [rs1 + disp]
    SrcBaseDisp,
    /// cond, offset
    CondOff,
    /// offset
    Off,
    /// #imm8  (trap vector)
    Imm8,
    /// no operands
    NoOps,
}

// ───────────────────────────────────────────────────────────────────
// Instruction descriptor
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct InsnDesc {
    pub name: &'static str,
    pub opcode: u8,
    pub format: Format,
    pub operands: Operands,
    pub semantics: Sem,
    pub mem: MemEffect,
    pub flags: FlagEffect,
}

// ═══════════════════════════════════════════════════════════════════
// THE TABLE — nothing exists unless it appears here
// ═══════════════════════════════════════════════════════════════════

pub const INSNS: &[InsnDesc] = &[
    // ─── R-format ALU ───────────────────────────────────────────
    InsnDesc { name: "add",  opcode: 0x01, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Add), mem: MemEffect::None, flags: FlagEffect::Arith },
    InsnDesc { name: "sub",  opcode: 0x02, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Sub), mem: MemEffect::None, flags: FlagEffect::Sub   },
    InsnDesc { name: "and",  opcode: 0x03, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::And), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "or",   opcode: 0x04, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Or),  mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "xor",  opcode: 0x05, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Xor), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "shl",  opcode: 0x06, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Shl), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "shr",  opcode: 0x07, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Shr), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "asr",  opcode: 0x08, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Asr), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "mul",  opcode: 0x0B, format: Format::R, operands: Operands::RdRs1Rs2, semantics: Sem::Alu(AluOp::Mul), mem: MemEffect::None, flags: FlagEffect::Logic },

    InsnDesc { name: "cmp",  opcode: 0x09, format: Format::R, operands: Operands::Rs1Rs2,   semantics: Sem::Cmp,              mem: MemEffect::None, flags: FlagEffect::Sub   },
    InsnDesc { name: "mov",  opcode: 0x0A, format: Format::R, operands: Operands::RdRs1,    semantics: Sem::Mov,              mem: MemEffect::None, flags: FlagEffect::None  },

    // ─── I-format ALU ───────────────────────────────────────────
    InsnDesc { name: "addi", opcode: 0x10, format: Format::I, operands: Operands::RdRs1Imm, semantics: Sem::Alu(AluOp::Add), mem: MemEffect::None, flags: FlagEffect::Arith },
    InsnDesc { name: "subi", opcode: 0x11, format: Format::I, operands: Operands::RdRs1Imm, semantics: Sem::Alu(AluOp::Sub), mem: MemEffect::None, flags: FlagEffect::Sub   },
    InsnDesc { name: "andi", opcode: 0x12, format: Format::I, operands: Operands::RdRs1Imm, semantics: Sem::Alu(AluOp::And), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "ori",  opcode: 0x13, format: Format::I, operands: Operands::RdRs1Imm, semantics: Sem::Alu(AluOp::Or),  mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "xori", opcode: 0x14, format: Format::I, operands: Operands::RdRs1Imm, semantics: Sem::Alu(AluOp::Xor), mem: MemEffect::None, flags: FlagEffect::Logic },
    InsnDesc { name: "cmpi", opcode: 0x15, format: Format::I, operands: Operands::Rs1Imm,   semantics: Sem::Cmp,              mem: MemEffect::None, flags: FlagEffect::Sub   },
    InsnDesc { name: "movi", opcode: 0x16, format: Format::I, operands: Operands::RdImm,    semantics: Sem::Movi,             mem: MemEffect::None, flags: FlagEffect::None  },

    // ─── I-format memory ────────────────────────────────────────
    InsnDesc { name: "ld",   opcode: 0x20, format: Format::I, operands: Operands::RdBaseDisp,  semantics: Sem::Load,  mem: MemEffect::Load,  flags: FlagEffect::None },
    InsnDesc { name: "st",   opcode: 0x21, format: Format::I, operands: Operands::SrcBaseDisp, semantics: Sem::Store, mem: MemEffect::Store, flags: FlagEffect::None },
    InsnDesc { name: "lea",  opcode: 0x22, format: Format::I, operands: Operands::RdBaseDisp,  semantics: Sem::Lea,   mem: MemEffect::None,  flags: FlagEffect::None },

    // ─── B-format control ───────────────────────────────────────
    InsnDesc { name: "b",    opcode: 0x30, format: Format::B, operands: Operands::CondOff,  semantics: Sem::Branch, mem: MemEffect::None, flags: FlagEffect::None },
    InsnDesc { name: "call", opcode: 0x32, format: Format::B, operands: Operands::Off,      semantics: Sem::Call,   mem: MemEffect::None, flags: FlagEffect::None },

    // ─── S-format system ────────────────────────────────────────
    InsnDesc { name: "ret",  opcode: 0x38, format: Format::S, operands: Operands::NoOps, semantics: Sem::Ret,  mem: MemEffect::None, flags: FlagEffect::None },
    InsnDesc { name: "trap", opcode: 0x39, format: Format::S, operands: Operands::Imm8,  semantics: Sem::Trap, mem: MemEffect::None, flags: FlagEffect::None },
    InsnDesc { name: "eret", opcode: 0x3A, format: Format::S, operands: Operands::NoOps, semantics: Sem::Eret, mem: MemEffect::None, flags: FlagEffect::None },
    InsnDesc { name: "nop",  opcode: 0x3F, format: Format::S, operands: Operands::NoOps, semantics: Sem::Nop,  mem: MemEffect::None, flags: FlagEffect::None },
    InsnDesc { name: "halt", opcode: 0x3E, format: Format::S, operands: Operands::NoOps, semantics: Sem::Halt, mem: MemEffect::None, flags: FlagEffect::None },
];

// ───────────────────────────────────────────────────────────────────
// Table lookup
// ───────────────────────────────────────────────────────────────────

pub fn by_opcode(opcode: u8) -> Option<&'static InsnDesc> {
    INSNS.iter().find(|d| d.opcode == opcode)
}

pub fn by_name(name: &str) -> Option<&'static InsnDesc> {
    INSNS.iter().find(|d| d.name == name)
}

// ───────────────────────────────────────────────────────────────────
// Kleis theory generation
// ───────────────────────────────────────────────────────────────────

/// Generate Kleis theory source from the instruction table.
///
/// This is the machine description → formal semantics pipeline.
pub fn generate_kleis() -> String {
    let mut out = String::new();
    out.push_str("// Generated from desc.rs — do not edit by hand.\n");
    out.push_str("// An instruction does not exist unless every consumer agrees.\n\n");
    out.push_str("import \"stdlib/prelude.kleis\"\n\n");

    out.push_str("// Opcode: BitVec8, Register: BitVec4\n\n");

    // Opcode constants
    out.push_str("// ─── Opcode constants ───────────────────────────────\n\n");
    for d in INSNS {
        out.push_str(&format!(
            "define op_{} = bvconst({}, 8)\n",
            d.name, d.opcode
        ));
    }
    out.push_str("\n");

    // Format predicates
    out.push_str("// ─── Format classification ──────────────────────────\n\n");
    for fmt in &["R", "I", "B", "S"] {
        let members: Vec<&str> = INSNS.iter()
            .filter(|d| format!("{:?}", d.format) == *fmt)
            .map(|d| d.name)
            .collect();
        out.push_str(&format!("// Format {}: {}\n", fmt, members.join(", ")));
    }
    out.push_str("\n");

    // Memory-effect predicates
    out.push_str("// ─── Memory effects ─────────────────────────────────\n\n");
    out.push_str("define has_load_effect(op : BitVec8) =\n");
    let loads: Vec<String> = INSNS.iter()
        .filter(|d| d.mem == MemEffect::Load)
        .map(|d| format!("    op = op_{}", d.name))
        .collect();
    if loads.is_empty() {
        out.push_str("    false\n");
    } else {
        out.push_str(&loads.join("\n    ∨ "));
        out.push_str("\n");
    }
    out.push_str("\n");

    out.push_str("define has_store_effect(op : BitVec8) =\n");
    let stores: Vec<String> = INSNS.iter()
        .filter(|d| d.mem == MemEffect::Store)
        .map(|d| format!("    op = op_{}", d.name))
        .collect();
    if stores.is_empty() {
        out.push_str("    false\n");
    } else {
        out.push_str(&stores.join("\n    ∨ "));
        out.push_str("\n");
    }
    out.push_str("\n");

    out.push_str("define has_no_memory_effect(op : BitVec8) =\n");
    let nones: Vec<String> = INSNS.iter()
        .filter(|d| d.mem == MemEffect::None)
        .map(|d| format!("    op = op_{}", d.name))
        .collect();
    out.push_str(&nones.join("\n    ∨ "));
    out.push_str("\n\n");

    // ALU semantics (bitvector operations)
    out.push_str("// ─── ALU semantics ──────────────────────────────────\n\n");
    for d in INSNS {
        if let Sem::Alu(op) = d.semantics {
            let bv_op = match op {
                AluOp::Add => "bvadd",
                AluOp::Sub => "bvsub",
                AluOp::And => "bvand",
                AluOp::Or  => "bvor",
                AluOp::Xor => "bvxor",
                AluOp::Shl => "bvshl",
                AluOp::Shr => "bvlshr",
                AluOp::Asr => "bvashr",
                AluOp::Mul => "bvmul",
            };
            out.push_str(&format!(
                "// {}: rd ← {}(rs1, rs2/imm)\n",
                d.name, bv_op
            ));
            out.push_str(&format!(
                "define sem_{}(a : BitVec64, b : BitVec64) = {}(a, b)\n\n",
                d.name, bv_op
            ));
        }
    }

    // Key properties
    out.push_str("// ─── Properties ─────────────────────────────────────\n\n");

    // P1: Each opcode maps to exactly one instruction
    out.push_str("// P1: opcode uniqueness (checked by desc.rs validation)\n\n");

    // P2: Every memory instruction produces exactly one MemoryRequest
    out.push_str("example \"one memory effect per instruction\" {\n");
    out.push_str("    assert(\n");
    out.push_str("        ∀ op : BitVec8 .\n");
    out.push_str("        ¬(has_load_effect(op) ∧ has_store_effect(op))\n");
    out.push_str("    )\n");
    out.push_str("}\n\n");

    // P3: ALU commutativity for add/mul
    out.push_str("example \"ALU add is commutative\" {\n");
    out.push_str("    assert(\n");
    out.push_str("        ∀ a : BitVec64 . ∀ b : BitVec64 .\n");
    out.push_str("        sem_add(a, b) = sem_add(b, a)\n");
    out.push_str("    )\n");
    out.push_str("}\n\n");

    out.push_str("example \"ALU mul is commutative\" {\n");
    out.push_str("    assert(\n");
    out.push_str("        ∀ a : BitVec64 . ∀ b : BitVec64 .\n");
    out.push_str("        sem_mul(a, b) = sem_mul(b, a)\n");
    out.push_str("    )\n");
    out.push_str("}\n\n");

    // P4: sub(a, a) = 0
    out.push_str("example \"ALU sub self is zero\" {\n");
    out.push_str("    assert(\n");
    out.push_str("        ∀ a : BitVec64 .\n");
    out.push_str("        sem_sub(a, a) = bvconst(0, 64)\n");
    out.push_str("    )\n");
    out.push_str("}\n\n");

    // P5: xor(a, a) = 0 (register zeroing idiom)
    out.push_str("example \"ALU xor self is zero\" {\n");
    out.push_str("    assert(\n");
    out.push_str("        ∀ a : BitVec64 .\n");
    out.push_str("        sem_xor(a, a) = bvconst(0, 64)\n");
    out.push_str("    )\n");
    out.push_str("}\n\n");

    // P6: and(a, a) = a (identity)
    out.push_str("example \"ALU and self is identity\" {\n");
    out.push_str("    assert(\n");
    out.push_str("        ∀ a : BitVec64 .\n");
    out.push_str("        sem_and(a, a) = a\n");
    out.push_str("    )\n");
    out.push_str("}\n\n");

    // Total instruction count for audit
    out.push_str(&format!(
        "// Total instructions in table: {}\n",
        INSNS.len()
    ));

    out
}

// ═══════════════════════════════════════════════════════════════════
// Validation — structural invariants on the table itself
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_are_unique() {
        for (i, a) in INSNS.iter().enumerate() {
            for b in INSNS.iter().skip(i + 1) {
                assert_ne!(
                    a.opcode, b.opcode,
                    "duplicate opcode 0x{:02X}: {} and {}", a.opcode, a.name, b.name
                );
            }
        }
    }

    #[test]
    fn names_are_unique() {
        for (i, a) in INSNS.iter().enumerate() {
            for b in INSNS.iter().skip(i + 1) {
                assert_ne!(
                    a.name, b.name,
                    "duplicate name: {} (opcodes 0x{:02X} and 0x{:02X})",
                    a.name, a.opcode, b.opcode
                );
            }
        }
    }

    #[test]
    fn format_matches_operands() {
        for d in INSNS {
            match d.format {
                Format::R => assert!(
                    matches!(d.operands, Operands::RdRs1Rs2 | Operands::RdRs1 | Operands::Rs1Rs2),
                    "{}: R-format with {:?} operands", d.name, d.operands
                ),
                Format::I => assert!(
                    matches!(d.operands,
                        Operands::RdRs1Imm | Operands::Rs1Imm | Operands::RdImm |
                        Operands::RdBaseDisp | Operands::SrcBaseDisp
                    ),
                    "{}: I-format with {:?} operands", d.name, d.operands
                ),
                Format::B => assert!(
                    matches!(d.operands, Operands::CondOff | Operands::Off),
                    "{}: B-format with {:?} operands", d.name, d.operands
                ),
                Format::S => assert!(
                    matches!(d.operands, Operands::NoOps | Operands::Imm8),
                    "{}: S-format with {:?} operands", d.name, d.operands
                ),
            }
        }
    }

    #[test]
    fn memory_instructions_have_correct_semantics() {
        for d in INSNS {
            match d.mem {
                MemEffect::Load => assert_eq!(d.semantics, Sem::Load, "{} has Load effect but wrong semantics", d.name),
                MemEffect::Store => assert_eq!(d.semantics, Sem::Store, "{} has Store effect but wrong semantics", d.name),
                MemEffect::None => assert!(
                    !matches!(d.semantics, Sem::Load | Sem::Store),
                    "{} has no memory effect but Load/Store semantics", d.name
                ),
            }
        }
    }

    #[test]
    fn every_opcode_fits_in_6_bits() {
        for d in INSNS {
            assert!(d.opcode < 64, "{}: opcode 0x{:02X} exceeds 6 bits", d.name, d.opcode);
        }
    }

    #[test]
    fn kleis_generation_succeeds() {
        let kleis = generate_kleis();
        assert!(kleis.contains("op_add"), "missing op_add");
        assert!(kleis.contains("op_mul"), "missing op_mul");
        assert!(kleis.contains("sem_add"), "missing sem_add");
        assert!(kleis.contains("sem_mul"), "missing sem_mul");
        assert!(kleis.contains("has_load_effect"), "missing has_load_effect");
        assert!(kleis.contains("has_store_effect"), "missing has_store_effect");
        assert!(kleis.contains("one memory effect per instruction"), "missing theorem");
        eprintln!("Generated Kleis theory:\n{}", kleis);
    }
}

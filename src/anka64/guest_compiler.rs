//! Guest compiler bootstrap — Rust AST builder for the 6B.4 compiler.
//!
//! This module contains:
//!   - Shared AST helper functions used by all compiler phases
//!   - Instruction encoding helpers (I/R/S/B formats)
//!   - Workspace layout constants
//!   - Token and ISA encoding constants
//!   - Guest lexer builder functions
//!   - Shared test infrastructure (trap handler, seal)
//!   - The authoritative 6B.4 bootstrap compiler builder

#![allow(dead_code)]

use super::cc::{Program, Function, Stmt, Expr, BinOp, Type, VarId};
use super::isa::*;
use super::fabric::Fabric;
use super::state::*;
use super::os::{SYS_EXEC, SYS_SEAL};

mod canonical_source;
pub(crate) use canonical_source::canonical_compiler_source;

pub(crate) const CPU0: AgentId = AgentId(0);


// ═══════════════════════════════════════════════════════════
//  Shared AST helpers — one definition used by all phases
// ═══════════════════════════════════════════════════════════
pub(crate) fn lit(v: i64) -> Expr { Expr::IntLit(v) }
pub(crate) fn var(id: VarId) -> Expr { Expr::Var(id) }
pub(crate) fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
    Expr::BinOp(op, Box::new(a), Box::new(b))
}
pub(crate) fn assign(id: VarId, e: Expr) -> Stmt {
    Stmt::Expr(Expr::Assign(id, Box::new(e)))
}
pub(crate) fn deref(addr: Expr) -> Expr { Expr::Deref(Box::new(addr)) }
pub(crate) fn deref_assign(addr: Expr, val: Expr) -> Stmt {
    Stmt::Expr(Expr::DerefAssign(Box::new(addr), Box::new(val)))
}
pub(crate) fn call(name: &str, args: Vec<Expr>) -> Expr {
    Expr::Call(name.into(), args)
}
pub(crate) fn call_stmt(name: &str, args: Vec<Expr>) -> Stmt {
    Stmt::Expr(Expr::Call(name.into(), args))
}

/// Inclusive range predicate: lo ≤ x ≤ hi.
///
/// One definition of character-class membership.  Never use a one-sided
/// comparison plus an early return for range filtering — filtering belongs
/// in predicates; Return belongs to function semantics.
pub(crate) fn in_range(x: Expr, lo: i64, hi: i64) -> Expr {
    binop(BinOp::And,
        binop(BinOp::Le, lit(lo), x.clone()),
        binop(BinOp::Le, x, lit(hi)))
}

// ─── Instruction encoding helpers ────────────────────
pub(crate) fn enc_i(opcode: i64, rd: i64, rs1: i64, imm: Expr) -> Expr {
    let masked = binop(BinOp::Shr,
        binop(BinOp::Shl, imm, lit(46)), lit(46));
    binop(BinOp::Or,
        binop(BinOp::Or,
            binop(BinOp::Or,
                binop(BinOp::Shl, lit(opcode), lit(26)),
                binop(BinOp::Shl, lit(rd), lit(22))),
            binop(BinOp::Shl, lit(rs1), lit(18))),
        masked)
}
pub(crate) fn enc_r(opcode: i64, rd: i64, rs1: i64, rs2: i64) -> Expr {
    binop(BinOp::Or,
        binop(BinOp::Or,
            binop(BinOp::Or,
                binop(BinOp::Shl, lit(opcode), lit(26)),
                binop(BinOp::Shl, lit(rd), lit(22))),
            binop(BinOp::Shl, lit(rs1), lit(18))),
        binop(BinOp::Shl, lit(rs2), lit(14)))
}
pub(crate) fn enc_s(opcode: i64) -> Expr {
    binop(BinOp::Shl, lit(opcode), lit(26))
}


// ═══════════════════════════════════════════════════════════
//  Virtual memory layout — structurally derived
// ═══════════════════════════════════════════════════════════
//
// Each region's base is derived from the previous region's end:
//
//   Code  ≺  Source  ≺  Workspace  ≺  Output  ≺  Stack
//
// TEXT_SIZE = align_up(compiled_bytes, 0x1000).
// TEXT_SIZE: page-aligned upper bound on the HOST compiler (CC_A, ~27KB).
// The test `text_size_is_derived` enforces TEXT_SIZE = align_up(CC_A, 0x1000).
//
// The canonical compiler binary (CC_B, ~57KB) runs at a SEPARATE virtual
// base address (CCB_CODE_BASE = 0x30000) so its code does not overlap with
// data regions.  All CALL and BCC instructions use PC-relative displacements,
// so function calls work regardless of the code base address.  Data regions
// use absolute addresses (LAYOUT_SRC, LAYOUT_OUT, LAYOUT_WS) loaded via MOVI.
// These must fit in the 18-bit signed immediate: max address ≤ 131071.
pub(crate) const TEXT_SIZE: i64     = 0x7000;

// ── Region sizes ──────────────────────────────────────────
pub(crate) const SOURCE_SIZE: i64  = 0x5000;   //  20 KiB
pub(crate) const WS_SIZE: i64      = 0x6000;   //  24 KiB
pub(crate) const OUTPUT_SIZE: i64  = 0x14000;  //  80 KiB  (was 0x10000; enlarged in 9.3e.2)
pub(crate) const STACK_SIZE: i64   = 0x4000;   //  16 KiB

// ── Region bases (each derived from previous end) ─────────
//
//   [0, TEXT_SIZE)                      : compiler text (host only)
//   [LAYOUT_SRC, LAYOUT_SRC+SOURCE_SIZE) : source
//   [LAYOUT_WS,  LAYOUT_WS+WS_SIZE)     : workspace
//   [LAYOUT_OUT, LAYOUT_OUT+OUTPUT_SIZE) : output
//   [LAYOUT_STACK, LAYOUT_STACK+STACK_SIZE) : stack
//
// Workspace is placed BEFORE output so that workspace addresses
// (up to WS_LIT_POS ≈ 0x10B68) stay well within the MOVI 18-bit
// signed immediate range (max 131071).  Source, output, and stack
// addresses are set by the harness or derived from workspace slots
// and are NOT loaded via MOVI.
pub(crate) const LAYOUT_SRC: i64   = TEXT_SIZE;
pub(crate) const LAYOUT_WS: i64    = LAYOUT_SRC + SOURCE_SIZE;
pub(crate) const LAYOUT_OUT: i64   = LAYOUT_WS + WS_SIZE;
pub(crate) const LAYOUT_STACK: i64 = LAYOUT_OUT + OUTPUT_SIZE;

// ── Structural invariants ─────────────────────────────────
// Regions are contiguous and non-overlapping.
const _: () = assert!(LAYOUT_SRC   == TEXT_SIZE);
const _: () = assert!(LAYOUT_WS    == LAYOUT_SRC + SOURCE_SIZE);
const _: () = assert!(LAYOUT_OUT   == LAYOUT_WS  + WS_SIZE);
const _: () = assert!(LAYOUT_STACK == LAYOUT_OUT  + OUTPUT_SIZE);

// ── Physical placement (test harness) ─────────────────────
// Physical addresses for `Fabric::place_object()` in the bootstrap
// test harness.  Derived so that enlarging any region does not
// silently create overlapping placements.
pub(crate) const PHYS_SOURCE: u64 = 0x200000;
pub(crate) const PHYS_OUTPUT: u64 = 0x210000;
pub(crate) const PHYS_WORK: u64   = (PHYS_OUTPUT + OUTPUT_SIZE as u64 + 0xFFF) & !0xFFF;
// Non-overlap invariant.
const _: () = assert!(PHYS_OUTPUT >= PHYS_SOURCE + SOURCE_SIZE as u64);
const _: () = assert!(PHYS_WORK   >= PHYS_OUTPUT + OUTPUT_SIZE as u64);

// ─── MOVI immediate range ────────────────────────────────
// MOVI uses an 18-bit signed immediate.  The maximum positive
// value is (1 << 17) - 1 = 131071.  Literal offsets within the
// output buffer range from 0 to OUTPUT_SIZE-1 (81919), which fits.
// WS_LIT_POS must also fit (asserted below, after WS_LIT_POS def).
const MOVI_MAX: i64 = (1 << 17) - 1;
const _: () = assert!(OUTPUT_SIZE - 1 <= MOVI_MAX);

// ═══════════════════════════════════════════════════════════
//  Shared workspace layout — addresses within workspace object
//  All WS_* are absolute virtual addresses (LAYOUT_WS + offset).
// ═══════════════════════════════════════════════════════════
pub(crate) const WS_POS: i64            = LAYOUT_WS;
pub(crate) const WS_SRC_LEN: i64        = LAYOUT_WS + 0x008;
pub(crate) const WS_TEXT_BASE: i64       = LAYOUT_WS + 0x010;
pub(crate) const WS_ERROR: i64          = LAYOUT_WS + 0x018;
pub(crate) const WS_TOK_TYPE: i64       = LAYOUT_WS + 0x020;
pub(crate) const WS_TOK_VALUE: i64      = LAYOUT_WS + 0x028;
// Legacy keyword slots (6B.3 packed-name lexer)
pub(crate) const WS_KW_INT: i64         = LAYOUT_WS + 0x030;
pub(crate) const WS_KW_RETURN: i64      = LAYOUT_WS + 0x038;
pub(crate) const WS_KW_IF: i64          = LAYOUT_WS + 0x040;
pub(crate) const WS_KW_ELSE: i64        = LAYOUT_WS + 0x048;
pub(crate) const WS_KW_WHILE: i64       = LAYOUT_WS + 0x050;
// Source-slice name slots (6B.5+, aliases WS_KW_INT/WS_KW_RETURN)
pub(crate) const WS_TOK_NAME_START: i64 = LAYOUT_WS + 0x030;
pub(crate) const WS_TOK_NAME_LEN: i64   = LAYOUT_WS + 0x038;
pub(crate) const WS_SYM_COUNT: i64      = LAYOUT_WS + 0x040;
pub(crate) const WS_OUT_POS: i64        = LAYOUT_WS + 0x048;
pub(crate) const WS_EXPR_SP: i64        = LAYOUT_WS + 0x050;
pub(crate) const WS_FUNC_COUNT: i64     = LAYOUT_WS + 0x058;
pub(crate) const WS_FIX_COUNT: i64      = LAYOUT_WS + 0x060;
// Symbol table: 32 entries × 24 bytes = 0x300
pub(crate) const WS_SYM_TABLE: i64      = LAYOUT_WS + 0x068;
// Function table: 64 entries × 32 bytes = 0x800
pub(crate) const WS_FUNC_TABLE: i64     = LAYOUT_WS + 0x368;
// Fixup table: 512 entries × 32 bytes = 0x4000
// Extends from 0xB68 to 0x4B68 within the workspace.
pub(crate) const WS_FIX_TABLE: i64      = LAYOUT_WS + 0xB68;
// ─── Two-ended image allocator (7.2) ─────────────
// Code grows upward from offset 0 (tracked by WS_OUT_POS).
// Literals grow downward from OUTPUT_SIZE (tracked by WS_LIT_POS).
// Invariant: WS_OUT_POS <= WS_LIT_POS  (disjoint regions).
// WS_LIT_POS is initialized to OUTPUT_SIZE by the harness.
// After compilation: code = [0, WS_OUT_POS), lits = [WS_LIT_POS, OUTPUT_SIZE).
// Placed AFTER the fixup table (0x4B68) to avoid overlap.
pub(crate) const WS_LIT_POS: i64        = LAYOUT_WS + 0x4B68;
/// Development compiler mode word.  Zero preserves the historical CC_B
/// behavior (compile, seal, then SYS_EXEC).  Phase 9.3h.2 writes
/// CCB_MODE_COMPILE_ONLY so `compile` produces a sealed artifact without
/// executing developer source as part of compilation.
pub(crate) const WS_MODE: i64           = LAYOUT_WS + 0x4B70;
pub(crate) const CCB_MODE_COMPILE_AND_RUN: u64 = 0;
pub(crate) const CCB_MODE_COMPILE_ONLY: u64 = 1;
const _: () = assert!(WS_LIT_POS <= MOVI_MAX);
const _: () = assert!(WS_MODE <= MOVI_MAX);
const _: () = assert!((WS_MODE - LAYOUT_WS + 8) <= WS_SIZE);
// ─── Token types (same as 6B.3) ──────────────────

// ─── Token types ──────────────────────────────────
pub(crate) const TOK_EOF: i64    = 0;
pub(crate) const TOK_NUMBER: i64 = 1;
pub(crate) const TOK_IDENT: i64  = 2;
pub(crate) const TOK_PLUS: i64   = 3;
pub(crate) const TOK_MINUS: i64  = 4;
pub(crate) const TOK_STAR: i64   = 5;
pub(crate) const TOK_EQ: i64     = 6;
pub(crate) const TOK_SEMI: i64   = 7;
pub(crate) const TOK_INT_KW: i64 = 8;
pub(crate) const TOK_RETURN: i64 = 9;
pub(crate) const TOK_LPAREN: i64 = 10;
pub(crate) const TOK_RPAREN: i64 = 11;
pub(crate) const TOK_IF: i64     = 12;
pub(crate) const TOK_ELSE: i64   = 13;
pub(crate) const TOK_LBRACE: i64 = 14;
pub(crate) const TOK_RBRACE: i64 = 15;
pub(crate) const TOK_LT: i64     = 16;
pub(crate) const TOK_WHILE: i64  = 17;
pub(crate) const TOK_COMMA: i64  = 18;
// 6B.5.0b: multi-character and new single-character operators
pub(crate) const TOK_EQEQ: i64  = 19;   // ==
pub(crate) const TOK_NE: i64    = 20;   // !=
pub(crate) const TOK_LE: i64    = 21;   // <=
pub(crate) const TOK_SHL: i64   = 22;   // <<
pub(crate) const TOK_SHR: i64   = 23;   // >>
pub(crate) const TOK_PIPE: i64  = 24;   // |
pub(crate) const TOK_AMP: i64   = 25;   // &
pub(crate) const TOK_BANG: i64  = 26;   // ! (only valid before =)
pub(crate) const TOK_SYSCALL: i64 = 27; // syscall keyword
pub(crate) const TOK_STRING: i64 = 28;  // string literal "..."
pub(crate) const TOK_SYSRET: i64 = 29;  // sysret keyword (9.3e.2)


// ─── ISA encoding constants ──────────────────────
pub(crate) const OP_ADD: i64  = 1;
pub(crate) const OP_SUB: i64  = 2;
pub(crate) const OP_AND: i64  = 3;
pub(crate) const OP_OR: i64   = 4;
pub(crate) const OP_SHL: i64  = 6;
pub(crate) const OP_SHR: i64  = 7;
pub(crate) const OP_CMP: i64  = 9;
pub(crate) const OP_MOV: i64  = 10;   // 0x0A
pub(crate) const OP_MUL: i64  = 11;   // 0x0B
pub(crate) const OP_ADDI: i64 = 16;   // 0x10
pub(crate) const OP_SUBI: i64 = 17;   // 0x11
pub(crate) const OP_CMPI: i64 = 21;   // 0x15
pub(crate) const OP_MOVI: i64 = 22;   // 0x16
pub(crate) const OP_LD: i64   = 32;   // 0x20
pub(crate) const OP_ST: i64   = 33;   // 0x21
pub(crate) const OP_BCC: i64  = 48;   // 0x30
pub(crate) const OP_CALL: i64 = 50;   // 0x32
pub(crate) const OP_TRAP: i64 = 57;   // 0x39
pub(crate) const OP_RET: i64  = 56;   // 0x38
pub(crate) const OP_HALT: i64 = 62;   // 0x3E
pub(crate) const OP_NOP: i64  = 63;   // 0x3F

pub(crate) const COND_EQ: i64 = 0;
pub(crate) const COND_NE: i64 = 1;
pub(crate) const COND_LT: i64 = 2;
pub(crate) const COND_GE: i64 = 3;
pub(crate) const COND_LE: i64 = 4;
pub(crate) const COND_GT: i64 = 5;
pub(crate) const COND_AL: i64 = 15;

// ─── Register numbers ────────────────────────────
pub(crate) const GEN_R0: i64  = 0;
pub(crate) const GEN_R1: i64  = 1;
pub(crate) const GEN_R4: i64  = 4;
pub(crate) const GEN_R5: i64  = 5;
pub(crate) const GEN_FP: i64  = 13;
pub(crate) const GEN_LR: i64  = 14;
pub(crate) const GEN_SP: i64  = 15;

pub(crate) const EXPR_SP_INIT: i64 = -0x800;

pub(crate) fn syscall(num: u8, args: Vec<Expr>) -> Expr {
    Expr::Syscall(num, args)
}

pub(crate) fn sysret(k: u8) -> Expr {
    Expr::Sysret(k)
}

// ─── Expression-stack save/restore pattern ───────
// Used by every binary-op level in the precedence chain.
// After calling the sub-level for the left operand (result in R4),
// save R4 to the expression stack, then compile the right operand,
// then restore the left operand into R5.
// Local var 0 is used as a scratch for the stack offset.

/// Save R4 to expression stack: ST R4,[SP+expr_sp]; expr_sp -= 8.
fn expr_stack_save() -> Vec<Stmt> {
    vec![
        assign(0, deref(lit(WS_EXPR_SP))),
        call_stmt("emit", vec![
            enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
        deref_assign(lit(WS_EXPR_SP),
            binop(BinOp::Sub, deref(lit(WS_EXPR_SP)), lit(8))),
    ]
}

/// Restore left operand from expression stack into R5:
/// expr_sp += 8; LD R5,[SP+expr_sp].
fn expr_stack_restore() -> Vec<Stmt> {
    vec![
        deref_assign(lit(WS_EXPR_SP),
            binop(BinOp::Add, deref(lit(WS_EXPR_SP)), lit(8))),
        assign(0, deref(lit(WS_EXPR_SP))),
        call_stmt("emit", vec![
            enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
    ]
}

/// Emit comparison sequence: CMP 0,R5,R4; MOVI R4,0; BCC skip,+4; MOVI R4,1.
/// `first_tok`: the token constant for the "first" operator variant.
/// `first_skip_cond`: BCC condition to skip MOVI 1 for the first variant.
/// `second_skip_cond`: BCC condition to skip MOVI 1 for the second variant.
/// Uses var(1) to determine which operator was saved.
fn emit_cmp_sequence(first_tok: i64, first_skip_cond: i64,
                     second_skip_cond: i64) -> Vec<Stmt> {
    vec![
        call_stmt("emit", vec![
            enc_r(OP_CMP, 0, GEN_R5, GEN_R4)]),
        call_stmt("emit", vec![
            enc_i(OP_MOVI, GEN_R4, 0, lit(0))]),
        Stmt::If(
            binop(BinOp::Eq, var(1), lit(first_tok)),
            vec![call_stmt("emit", vec![
                enc_b(first_skip_cond, lit(4))])],
            vec![call_stmt("emit", vec![
                enc_b(second_skip_cond, lit(4))])],
        ),
        call_stmt("emit", vec![
            enc_i(OP_MOVI, GEN_R4, 0, lit(1))]),
    ]
}

pub(crate) fn enc_b(cond: i64, disp: Expr) -> Expr {
    let masked = binop(BinOp::Shr,
        binop(BinOp::Shl, disp, lit(42)), lit(42));
    binop(BinOp::Or,
        binop(BinOp::Or,
            binop(BinOp::Shl, lit(OP_BCC), lit(26)),
            binop(BinOp::Shl, lit(cond), lit(22))),
        masked)
}

// ═══════════════════════════════════════════════════════════
//  Token constant map — the values differ between phases,
//  but the lexer logic is identical once parameterized.
// ═══════════════════════════════════════════════════════════
#[derive(Clone)]
pub(crate) struct TokMap {
    pub(crate) eof: i64, pub(crate) number: i64, pub(crate) ident: i64,
    pub(crate) plus: i64, pub(crate) minus: i64, pub(crate) star: i64,
    pub(crate) eq: i64, pub(crate) semi: i64, pub(crate) comma: i64,
    pub(crate) int_kw: i64, pub(crate) return_kw: i64,
    pub(crate) lparen: i64, pub(crate) rparen: i64,
    pub(crate) if_kw: i64, pub(crate) else_kw: i64, pub(crate) while_kw: i64,
    pub(crate) lbrace: i64, pub(crate) rbrace: i64, pub(crate) lt: i64,
}

// ═══════════════════════════════════════════════════════════
//  Shared guest lexer builders — Rule 28: one language
//  semantic fact, one guest-compiler implementation.
// ═══════════════════════════════════════════════════════════

/// read_byte(pos) — the single canonical byte-extraction primitive.
///
/// Uses aligned 8-byte load + shift/mask so the underlying machine
/// access never crosses an object boundary:
///   aligned = text_base + (pos & ~7)
///   word    = *aligned
///   shift   = (pos & 7) * 8
///   byte    = (word >> shift) & 0xFF
pub(crate) fn guest_read_byte() -> Function {
    Function {
        name: "read_byte".into(),
        params: vec![(0, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (1, Type::Int), (2, Type::Int), (3, Type::Int),
        ],
        body: vec![
            // aligned_pos = pos & (-8)   (i.e. pos & ~7)
            Stmt::VarDecl(1, Type::Int, Some(
                binop(BinOp::And, var(0), lit(-8)))),
            // word = *(text_base + aligned_pos)
            Stmt::VarDecl(2, Type::Int, Some(
                deref(binop(BinOp::Add,
                    deref(lit(WS_TEXT_BASE)),
                    var(1))))),
            // shift = (pos & 7) * 8
            Stmt::VarDecl(3, Type::Int, Some(
                binop(BinOp::Mul,
                    binop(BinOp::And, var(0), lit(7)),
                    lit(8)))),
            // byte = (word >> shift) & 0xFF
            Stmt::Return(
                binop(BinOp::And,
                    binop(BinOp::Shr, var(2), var(3)),
                    lit(0xFF))),
        ],
    }
}

/// write_byte(addr, byte) — write one byte at an arbitrary address.
///
/// Uses read-modify-write on the 8-byte-aligned word containing the
/// target byte.  The mask is constructed as: ~(0xFF << shift) =
/// (0 - 1) - (0xFF << shift), avoiding the need for a bitwise NOT
/// instruction.
///
/// This is the inverse of read_byte: where read_byte extracts one byte
/// from an aligned word, write_byte patches one byte into an aligned word.
pub(crate) fn guest_write_byte() -> Function {
    Function {
        name: "write_byte".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],   // addr, byte
        ret_type: Type::Int,
        locals: vec![
            (2, Type::Int), (3, Type::Int), (4, Type::Int), (5, Type::Int),
        ],
        body: vec![
            // aligned = addr & ~7
            Stmt::VarDecl(2, Type::Int, Some(
                binop(BinOp::And, var(0), lit(-8)))),
            // shift = (addr & 7) * 8
            Stmt::VarDecl(3, Type::Int, Some(
                binop(BinOp::Mul,
                    binop(BinOp::And, var(0), lit(7)),
                    lit(8)))),
            // word = *(aligned)
            Stmt::VarDecl(4, Type::Int, Some(deref(var(2)))),
            // mask = 0xFF << shift
            Stmt::VarDecl(5, Type::Int, Some(
                binop(BinOp::Shl, lit(0xFF), var(3)))),
            // word = (word & ~mask) | ((byte & 0xFF) << shift)
            //      = (word & ((0-1) - mask)) | ((byte & 0xFF) << shift)
            assign(4, binop(BinOp::Or,
                binop(BinOp::And, var(4),
                    binop(BinOp::Sub, lit(-1), var(5))),
                binop(BinOp::Shl,
                    binop(BinOp::And, var(1), lit(0xFF)),
                    var(3)))),
            // *(aligned) = word
            deref_assign(var(2), var(4)),
            Stmt::Return(lit(0)),
        ],
    }
}

/// store_literal() — copy string token bytes into the output buffer.
///
/// Two-ended image allocator (7.2): literals grow downward from
/// OUTPUT_SIZE within the same output buffer that code grows upward
/// into.  WS_LIT_POS tracks the current literal frontier.
///
/// Layout of one literal object (at output-buffer offset np):
///   [u64 byte_len]        — 8-byte header (number of content bytes)
///   [u8  data[byte_len]]  — raw bytes copied from source
///   [padding to 8-byte alignment]
///
/// Returns the absolute offset within the output buffer where this
/// literal starts (the offset of the byte_len header).  This is the
/// value that MOVI R4 will load.
///
/// Underflow-safe: checks lp < size BEFORE the subtraction lp - size.
///
/// Architectural invariant: length is metadata, not inferred from contents.
/// Embedded NUL is legal.  No terminator byte is written.
///
pub(crate) fn guest_store_literal() -> Function {
    Function {
        name: "store_literal".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            // len = byte length of string content
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_TOK_NAME_LEN)))),
            // start = source byte offset of string content
            Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_TOK_NAME_START)))),
            // lp = *WS_LIT_POS (current literal frontier, starts at OUTPUT_SIZE)
            Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_LIT_POS)))),
            // aligned = (len + 7) & (-8)
            Stmt::VarDecl(3, Type::Int, Some(
                binop(BinOp::And,
                    binop(BinOp::Add, var(0), lit(7)),
                    lit(-8)))),
            // size = aligned + 8 (header)
            Stmt::VarDecl(4, Type::Int, Some(
                binop(BinOp::Add, var(3), lit(8)))),
            // Underflow guard: if (lp < size) { error; return 0; }
            Stmt::If(binop(BinOp::Lt, var(2), var(4)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ],
                vec![]),
            // np = lp - size (new literal frontier)
            assign(2, binop(BinOp::Sub, var(2), var(4))),
            // Write header: *(LAYOUT_OUT + np) = len
            deref_assign(
                binop(BinOp::Add, lit(LAYOUT_OUT), var(2)),
                var(0)),
            // Compute data base address: LAYOUT_OUT + np + 8
            assign(4, binop(BinOp::Add,
                binop(BinOp::Add, lit(LAYOUT_OUT), var(2)),
                lit(8))),
            // Copy bytes from source
            assign(3, lit(0)),  // reuse var(3) as loop index
            Stmt::While(
                binop(BinOp::Lt, var(3), var(0)),
                vec![
                    call_stmt("write_byte", vec![
                        binop(BinOp::Add, var(4), var(3)),
                        call("read_byte", vec![
                            binop(BinOp::Add, var(1), var(3))]),
                    ]),
                    assign(3, binop(BinOp::Add, var(3), lit(1))),
                ],
            ),
            // Update literal frontier
            deref_assign(lit(WS_LIT_POS), var(2)),
            // Return np — the absolute offset of this literal in the output buffer
            Stmt::Return(var(2)),
        ],
    }
}

/// peek_char() — read current source byte.
/// Delegates to read_byte(*WS_POS) with bounds check.
pub(crate) fn guest_peek_char() -> Function {
    Function {
        name: "peek_char".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
            Stmt::If(
                binop(BinOp::Le, deref(lit(WS_SRC_LEN)), var(0)),
                vec![Stmt::Return(lit(0))],
                vec![],
            ),
            Stmt::Return(call("read_byte", vec![var(0)])),
        ],
    }
}

pub(crate) fn guest_advance() -> Function {
    Function {
        name: "advance".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            deref_assign(lit(WS_POS),
                binop(BinOp::Add, deref(lit(WS_POS)), lit(1))),
            Stmt::Return(lit(0)),
        ],
    }
}

/// skip_ws() — skip ASCII whitespace: space, tab, newline, CR.
/// Condition: 0 < ch ≤ 32  (covers all standard ASCII whitespace
/// while excluding NUL, which is an error character).
pub(crate) fn guest_skip_ws() -> Function {
    Function {
        name: "skip_ws".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
            Stmt::While(
                binop(BinOp::And,
                    binop(BinOp::Lt, lit(0), var(0)),
                    binop(BinOp::Le, var(0), lit(32))),
                vec![
                    call_stmt("advance", vec![]),
                    assign(0, call("peek_char", vec![])),
                ],
            ),
            Stmt::Return(lit(0)),
        ],
    }
}

pub(crate) fn guest_set_char_token() -> Function {
    Function {
        name: "set_char_token".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            deref_assign(lit(WS_TOK_TYPE), var(0)),
            deref_assign(lit(WS_TOK_VALUE), var(1)),
            call_stmt("advance", vec![]),
            Stmt::Return(lit(0)),
        ],
    }
}

pub(crate) fn guest_scan_number(tc: &TokMap) -> Function {
    Function {
        name: "scan_number".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            Stmt::VarDecl(1, Type::Int, Some(call("peek_char", vec![]))),
            Stmt::While(
                in_range(var(1), 48, 57),
                vec![
                    assign(0, binop(BinOp::Add,
                        binop(BinOp::Mul, var(0), lit(10)),
                        binop(BinOp::Sub, var(1), lit(48)))),
                    Stmt::If(
                        binop(BinOp::Lt, lit(131071), var(0)),
                        vec![
                            deref_assign(lit(WS_ERROR), lit(1)),
                            assign(1, lit(0)),
                        ],
                        vec![
                            call_stmt("advance", vec![]),
                            assign(1, call("peek_char", vec![])),
                        ],
                    ),
                ],
            ),
            deref_assign(lit(WS_TOK_TYPE), lit(tc.number)),
            deref_assign(lit(WS_TOK_VALUE), var(0)),
            Stmt::Return(lit(0)),
        ],
    }
}

/// scan_number with direct TOK_NUMBER constant (no TokMap).
pub(crate) fn guest_scan_number_direct() -> Function {
    guest_scan_number(&TokMap {
        eof: TOK_EOF, number: TOK_NUMBER, ident: TOK_IDENT,
        plus: TOK_PLUS, minus: TOK_MINUS, star: TOK_STAR,
        eq: TOK_EQ, semi: TOK_SEMI, comma: TOK_COMMA,
        int_kw: TOK_INT_KW, return_kw: TOK_RETURN,
        lparen: TOK_LPAREN, rparen: TOK_RPAREN,
        if_kw: TOK_IF, else_kw: TOK_ELSE, while_kw: TOK_WHILE,
        lbrace: TOK_LBRACE, rbrace: TOK_RBRACE, lt: TOK_LT,
    })
}

/// Frozen packed-name scan_ident for legacy 6B.3 builder.
pub(crate) fn guest_scan_ident_packed(tc: &TokMap) -> Function {
    Function {
        name: "scan_ident".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int), (5, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::VarDecl(5, Type::Int, Some(lit(0))),
            // Letter loop: 97 ≤ ch ≤ 122
            Stmt::While(
                in_range(var(0), 97, 122),
                vec![
                    assign(5, binop(BinOp::Add, var(5), lit(1))),
                    Stmt::If(
                        binop(BinOp::Lt, lit(8), var(5)),
                        vec![
                            deref_assign(lit(WS_ERROR), lit(1)),
                            Stmt::Return(lit(0)),
                        ],
                        vec![],
                    ),
                    assign(1, binop(BinOp::Or,
                        binop(BinOp::Shl, var(1), lit(8)),
                        var(0))),
                    call_stmt("advance", vec![]),
                    assign(0, call("peek_char", vec![])),
                ],
            ),
            // Digit suffix loop: 48 ≤ ch ≤ 57
            Stmt::While(
                in_range(var(0), 48, 57),
                vec![
                    assign(5, binop(BinOp::Add, var(5), lit(1))),
                    Stmt::If(
                        binop(BinOp::Lt, lit(8), var(5)),
                        vec![
                            deref_assign(lit(WS_ERROR), lit(1)),
                            Stmt::Return(lit(0)),
                        ],
                        vec![],
                    ),
                    assign(1, binop(BinOp::Or,
                        binop(BinOp::Shl, var(1), lit(8)),
                        var(0))),
                    call_stmt("advance", vec![]),
                    assign(0, call("peek_char", vec![])),
                ],
            ),
            // Classify: keyword or identifier
            deref_assign(lit(WS_TOK_VALUE), var(1)),
            Stmt::If(binop(BinOp::Eq, var(1), deref(lit(WS_KW_INT))),
                vec![deref_assign(lit(WS_TOK_TYPE), lit(tc.int_kw))],
                vec![Stmt::If(binop(BinOp::Eq, var(1), deref(lit(WS_KW_RETURN))),
                    vec![deref_assign(lit(WS_TOK_TYPE), lit(tc.return_kw))],
                    vec![Stmt::If(binop(BinOp::Eq, var(1), deref(lit(WS_KW_IF))),
                        vec![deref_assign(lit(WS_TOK_TYPE), lit(tc.if_kw))],
                        vec![Stmt::If(binop(BinOp::Eq, var(1), deref(lit(WS_KW_ELSE))),
                            vec![deref_assign(lit(WS_TOK_TYPE), lit(tc.else_kw))],
                            vec![Stmt::If(binop(BinOp::Eq, var(1), deref(lit(WS_KW_WHILE))),
                                vec![deref_assign(lit(WS_TOK_TYPE), lit(tc.while_kw))],
                                vec![deref_assign(lit(WS_TOK_TYPE), lit(tc.ident))],
                            )],
                        )],
                    )],
                )],
            ),
            Stmt::Return(lit(0)),
        ],
    }
}

/// next_token: position-based EOF, not byte-value-based.
///
/// EOF is pos ≥ src_len.  A NUL byte (0x00) inside the declared source
/// length falls through to the invalid-character error handler.
/// Frozen packed-name next_token for legacy 6B.3 builder.
pub(crate) fn guest_next_token_packed(tc: &TokMap) -> Function {
    Function {
        name: "next_token".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            call_stmt("skip_ws", vec![]),
            // Position-based EOF — not byte-value-based
            Stmt::If(
                binop(BinOp::Le, deref(lit(WS_SRC_LEN)), deref(lit(WS_POS))),
                vec![
                    deref_assign(lit(WS_TOK_TYPE), lit(tc.eof)),
                    Stmt::Return(lit(0)),
                ], vec![]),
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
            // Single-character tokens
            Stmt::If(binop(BinOp::Eq, var(0), lit(43)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.plus), lit(43)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(45)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.minus), lit(45)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(42)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.star), lit(42)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(61)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.eq), lit(61)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(59)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.semi), lit(59)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(44)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.comma), lit(44)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(40)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.lparen), lit(40)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(41)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.rparen), lit(41)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(123)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.lbrace), lit(123)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(125)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.rbrace), lit(125)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(60)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(tc.lt), lit(60)]))], vec![]),
            // Letter → identifier or keyword
            Stmt::If(in_range(var(0), 97, 122),
                vec![Stmt::Return(call("scan_ident", vec![]))],
                vec![]),
            // Digit → number
            Stmt::If(in_range(var(0), 48, 57),
                vec![Stmt::Return(call("scan_number", vec![]))],
                vec![]),
            // Fall-through: invalid character (including NUL byte)
            deref_assign(lit(WS_ERROR), lit(1)),
            deref_assign(lit(WS_TOK_TYPE), lit(tc.eof)),
            Stmt::Return(lit(0)),
        ],
    }
}

/// Build the complete shared lexer function set for any phase.
/// Frozen packed-name lexer for legacy 6B.3 builder.
pub(crate) fn guest_lexer_packed(tc: &TokMap) -> Vec<Function> {
    vec![
        guest_read_byte(),
        guest_peek_char(),
        guest_advance(),
        guest_skip_ws(),
        guest_set_char_token(),
        guest_scan_number(tc),
        guest_scan_ident_packed(tc),
        guest_next_token_packed(tc),
    ]
}

// ═══════════════════════════════════════════════════════════
//  Canonical source-slice lexer — shared by 6B.4+
// ═══════════════════════════════════════════════════════════

/// names_equal(sa, la, sb, lb) → 0 or 1.
/// Byte-by-byte comparison of two source slices.
pub(crate) fn guest_names_equal() -> Function {
    Function {
        name: "names_equal".into(),
        params: vec![(0, Type::Int), (1, Type::Int),
                     (2, Type::Int), (3, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(4, Type::Int), (5, Type::Int), (6, Type::Int)],
        body: vec![
            Stmt::If(
                binop(BinOp::Ne, var(1), var(3)),
                vec![Stmt::Return(lit(0))],
                vec![],
            ),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::VarDecl(5, Type::Int, Some(lit(0))),
            Stmt::VarDecl(6, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(4), var(1)), vec![
                assign(5, call("read_byte", vec![
                    binop(BinOp::Add, var(0), var(4))])),
                assign(6, call("read_byte", vec![
                    binop(BinOp::Add, var(2), var(4))])),
                Stmt::If(
                    binop(BinOp::Ne, var(5), var(6)),
                    vec![Stmt::Return(lit(0))],
                    vec![],
                ),
                assign(4, binop(BinOp::Add, var(4), lit(1))),
            ]),
            Stmt::Return(lit(1)),
        ],
    }
}

/// classify_kw(start, len) → token type.
/// Length-first dispatch + byte-by-byte comparison.
pub(crate) fn guest_classify_kw() -> Function {
    Function {
        name: "classify_kw".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            Stmt::If(binop(BinOp::Eq, var(1), lit(2)), vec![
                kw_byte_chain(0, &[105, 102],
                    Stmt::Return(lit(TOK_IF))),
            ], vec![]),
            Stmt::If(binop(BinOp::Eq, var(1), lit(3)), vec![
                kw_byte_chain(0, &[105, 110, 116],
                    Stmt::Return(lit(TOK_INT_KW))),
            ], vec![]),
            Stmt::If(binop(BinOp::Eq, var(1), lit(4)), vec![
                kw_byte_chain(0, &[101, 108, 115, 101],
                    Stmt::Return(lit(TOK_ELSE))),
            ], vec![]),
            Stmt::If(binop(BinOp::Eq, var(1), lit(5)), vec![
                kw_byte_chain(0, &[119, 104, 105, 108, 101],
                    Stmt::Return(lit(TOK_WHILE))),
            ], vec![]),
            Stmt::If(binop(BinOp::Eq, var(1), lit(6)), vec![
                kw_byte_chain(0, &[114, 101, 116, 117, 114, 110],
                    Stmt::Return(lit(TOK_RETURN))),
                // sysret = 115,121,115,114,101,116
                kw_byte_chain(0, &[115, 121, 115, 114, 101, 116],
                    Stmt::Return(lit(TOK_SYSRET))),
            ], vec![]),
            Stmt::If(binop(BinOp::Eq, var(1), lit(7)), vec![
                kw_byte_chain(0, &[115, 121, 115, 99, 97, 108, 108],
                    Stmt::Return(lit(TOK_SYSCALL))),
            ], vec![]),
            Stmt::Return(lit(TOK_IDENT)),
        ],
    }
}

/// scan_ident() — source-slice version.
/// Records (start, len) in WS_TOK_NAME_START/LEN,
/// calls classify_kw for keyword classification.
pub(crate) fn guest_scan_ident() -> Function {
    Function {
        name: "scan_ident".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int), (2, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
            Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_POS)))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::While(
                in_range(var(0), 97, 122),
                vec![
                    assign(2, binop(BinOp::Add, var(2), lit(1))),
                    call_stmt("advance", vec![]),
                    assign(0, call("peek_char", vec![])),
                ],
            ),
            Stmt::While(
                in_range(var(0), 48, 57),
                vec![
                    assign(2, binop(BinOp::Add, var(2), lit(1))),
                    call_stmt("advance", vec![]),
                    assign(0, call("peek_char", vec![])),
                ],
            ),
            deref_assign(lit(WS_TOK_NAME_START), var(1)),
            deref_assign(lit(WS_TOK_NAME_LEN), var(2)),
            deref_assign(lit(WS_TOK_TYPE),
                call("classify_kw", vec![var(1), var(2)])),
            Stmt::Return(lit(0)),
        ],
    }
}

/// scan_string() — string literal tokenizer.
///
/// Precondition: current character is `"` (0x22).
/// Advances past the opening quote, records the start position,
/// scans forward byte-by-byte preserving all UTF-8 bytes until
/// closing `"` or source end.  Records byte length in WS_TOK_NAME_LEN.
/// No NUL termination.  No escape sequences (7.0).
///
/// Architectural invariant: byte length ≠ codepoint count ≠ grapheme count.
/// The tokenizer operates on raw bytes; UTF-8 validation is a separate layer.
pub(crate) fn guest_scan_string() -> Function {
    Function {
        name: "scan_string".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: vec![
            // Advance past opening "
            call_stmt("advance", vec![]),
            // Record start position (byte offset in source)
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            // Scan until closing " or EOF
            Stmt::While(
                binop(BinOp::Lt, deref(lit(WS_POS)), deref(lit(WS_SRC_LEN))),
                vec![
                    Stmt::If(
                        binop(BinOp::Eq, call("peek_char", vec![]), lit(34)), // "
                        vec![
                            deref_assign(lit(WS_TOK_NAME_START), var(0)),
                            deref_assign(lit(WS_TOK_NAME_LEN), var(1)),
                            deref_assign(lit(WS_TOK_TYPE), lit(TOK_STRING)),
                            call_stmt("advance", vec![]),
                            Stmt::Return(lit(0)),
                        ],
                        vec![],
                    ),
                    assign(1, binop(BinOp::Add, var(1), lit(1))),
                    call_stmt("advance", vec![]),
                ],
            ),
            // Unterminated string — set error
            deref_assign(lit(WS_ERROR), lit(1)),
            deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
            Stmt::Return(lit(0)),
        ],
    }
}

/// Emit: advance, set WS_TOK_TYPE, return 0.
fn set_type_and_return(tok: i64) -> Vec<Stmt> {
    vec![
        call_stmt("advance", vec![]),
        deref_assign(lit(WS_TOK_TYPE), lit(tok)),
        Stmt::Return(lit(0)),
    ]
}

/// next_token() — maximal-munch tokenizer with multi-char operators.
///
/// Multi-char operators (==, !=, <=, <<, >>) are recognized before
/// their single-character prefixes.
pub(crate) fn guest_next_token() -> Function {
    Function {
        name: "next_token".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            call_stmt("skip_ws", vec![]),
            Stmt::If(
                binop(BinOp::Le, deref(lit(WS_SRC_LEN)), deref(lit(WS_POS))),
                vec![
                    deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
                    Stmt::Return(lit(0)),
                ], vec![]),
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),

            // ─── Simple single-char tokens ───────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(43)),    // +
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_PLUS), lit(43)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(45)),    // -
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_MINUS), lit(45)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(42)),    // *
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_STAR), lit(42)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(59)),    // ;
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_SEMI), lit(59)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(44)),    // ,
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_COMMA), lit(44)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(40)),    // (
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_LPAREN), lit(40)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(41)),    // )
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_RPAREN), lit(41)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(123)),   // {
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_LBRACE), lit(123)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(125)),   // }
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_RBRACE), lit(125)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(124)),   // |
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_PIPE), lit(124)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(38)),    // &
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_AMP), lit(38)]))], vec![]),

            // ─── Maximal munch: = vs == ──────────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(61)), vec![  // '='
                call_stmt("advance", vec![]),
                Stmt::If(
                    binop(BinOp::Eq, call("peek_char", vec![]), lit(61)),
                    set_type_and_return(TOK_EQEQ),     // ==
                    vec![
                        deref_assign(lit(WS_TOK_TYPE), lit(TOK_EQ)),
                        Stmt::Return(lit(0)),
                    ],
                ),
            ], vec![]),

            // ─── Maximal munch: < vs <= vs << ───────
            Stmt::If(binop(BinOp::Eq, var(0), lit(60)), vec![  // '<'
                call_stmt("advance", vec![]),
                assign(0, call("peek_char", vec![])),
                Stmt::If(binop(BinOp::Eq, var(0), lit(61)),    // <=
                    set_type_and_return(TOK_LE),
                    vec![],
                ),
                Stmt::If(binop(BinOp::Eq, var(0), lit(60)),    // <<
                    set_type_and_return(TOK_SHL),
                    vec![],
                ),
                deref_assign(lit(WS_TOK_TYPE), lit(TOK_LT)),   // just <
                Stmt::Return(lit(0)),
            ], vec![]),

            // ─── Maximal munch: >> ───────────────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(62)), vec![  // '>'
                call_stmt("advance", vec![]),
                Stmt::If(
                    binop(BinOp::Eq, call("peek_char", vec![]), lit(62)),
                    set_type_and_return(TOK_SHR),       // >>
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
                        Stmt::Return(lit(0)),
                    ],
                ),
            ], vec![]),

            // ─── Maximal munch: != ───────────────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(33)), vec![  // '!'
                call_stmt("advance", vec![]),
                Stmt::If(
                    binop(BinOp::Eq, call("peek_char", vec![]), lit(61)),
                    set_type_and_return(TOK_NE),        // !=
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
                        Stmt::Return(lit(0)),
                    ],
                ),
            ], vec![]),

            // ─── String literals ──────────────────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(34)),    // "
                vec![Stmt::Return(call("scan_string", vec![]))],
                vec![]),

            // ─── Identifiers and numbers ─────────────
            Stmt::If(in_range(var(0), 97, 122),
                vec![Stmt::Return(call("scan_ident", vec![]))],
                vec![]),
            Stmt::If(in_range(var(0), 48, 57),
                vec![Stmt::Return(call("scan_number", vec![]))],
                vec![]),

            deref_assign(lit(WS_ERROR), lit(1)),
            deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
            Stmt::Return(lit(0)),
        ],
    }
}

/// find_main() — scan function table for "main" by source bytes.
pub(crate) fn guest_find_main() -> Function {
    Function {
        name: "find_main".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_FUNC_COUNT)))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(1), var(0)), vec![
                assign(2, binop(BinOp::Add, lit(WS_FUNC_TABLE),
                    binop(BinOp::Mul, var(1), lit(32)))),
                assign(3, deref(var(2))),
                assign(4, deref(binop(BinOp::Add, var(2), lit(8)))),
                Stmt::If(binop(BinOp::Eq, var(4), lit(4)), vec![
                    kw_byte_chain(3, &[109, 97, 105, 110],
                        Stmt::Return(deref(
                            binop(BinOp::Add, var(2), lit(16))))),
                ], vec![]),
                assign(1, binop(BinOp::Add, var(1), lit(1))),
            ]),
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    }
}

/// Canonical source-slice lexer for 6B.4+.
pub(crate) fn guest_lexer() -> Vec<Function> {
    vec![
        guest_read_byte(),
        guest_write_byte(),
        guest_peek_char(),
        guest_advance(),
        guest_skip_ws(),
        guest_set_char_token(),
        guest_scan_number_direct(),
        guest_scan_ident(),
        guest_scan_string(),
        guest_store_literal(),
        guest_classify_kw(),
        guest_names_equal(),
        guest_next_token(),
        guest_find_main(),
    ]
}

pub(crate) fn install_trap_handler(fabric: &mut Fabric, text_phys: u64, text_size: u64) {
    let mut handler = Asm64::new();
    handler.halt();
    fabric.write_physical(
        text_phys + text_size - 0x10,
        &handler.to_bytes());
}

/// Seal an object and grant RX to a domain.
/// W⊕X lifecycle: Active(write) → Sealed(fetch).
pub(crate) fn seal_code_object(fabric: &mut Fabric, obj: ObjectId, dom: DomainId) {
    fabric.seal_object(obj);
    let size = fabric.objects[&obj].size;
    fabric.grant(dom, obj, 0, size, Permissions::RX);
}

// ════════════════════════════════════════════════════════════
//  6B.4  User-defined functions
// ════════════════════════════════════════════════════════════
//
//  6B.4.0: _start, function table, direct CALL, prologue/
//          epilogue, RET.  Target program:
//
//    int f() { return 42; }
//    int main() { return f(); }
//
//  Generated child layout:
//    _start: CALL main; HALT
//    f:      prologue; MOVI R4,42; MOV R0,R4; epilogue; RET
//    main:   prologue; CALL f; MOV R4,R0; MOV R0,R4; epilogue; RET
//
//  Prologue:  SUBI SP,SP,16; ST LR,[SP,8]; ST FP,[SP,0]; MOV FP,SP
//  Epilogue:  MOV SP,FP; LD FP,[SP,0]; LD LR,[SP,8]; ADDI SP,SP,16; RET

/// Build a nested If chain that checks source bytes against a known keyword.
///
/// Produces: if (read_byte(start+0)==b0) { if (read_byte(start+1)==b1) { ... result } }
fn kw_byte_chain(start_var: VarId, bytes: &[i64], result: Stmt) -> Stmt {
    bytes.iter().enumerate().rfold(
        result,
        |inner, (i, &byte)| {
            Stmt::If(
                binop(BinOp::Eq,
                    call("read_byte", vec![
                        binop(BinOp::Add, var(start_var), lit(i as i64))]),
                    lit(byte)),
                vec![inner],
                vec![],
            )
        }
    )
}

pub fn build_6b4_compiler() -> Program {
    // ─── emit(word) ────────────────────────────────
    // emit(word): write one 8-byte instruction pair to the output buffer.
    // Width-safe collision guard (7.2): the full 8-byte write [pos, pos+8)
    // must fit below the literal frontier WS_LIT_POS.
    //   if (lp < 8)       → underflow guard (prevents lp-8 wrap)
    //   if (lp - 8 < pos) → collision (code would overlap literals)
    // When no literals exist (lp == OUTPUT_SIZE), this degenerates
    // to the original check: OUTPUT_SIZE - 8 < pos.
    let fn_emit = Function {
        name: "emit".into(),
        params: vec![(0, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(1, Type::Int), (2, Type::Int), (3, Type::Int)],
        body: vec![
            Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_OUT_POS)))),
            Stmt::VarDecl(3, Type::Int, Some(deref(lit(WS_LIT_POS)))),
            // Underflow guard: if (lp < 8) { error; }
            Stmt::If(
                binop(BinOp::Lt, var(3), lit(8)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ],
                vec![],
            ),
            // Width-safe collision: if (lp - 8 < pos) { error; }
            Stmt::If(
                binop(BinOp::Lt,
                    binop(BinOp::Sub, var(3), lit(8)),
                    var(1)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ],
                vec![],
            ),
            Stmt::VarDecl(2, Type::Int, Some(
                binop(BinOp::Or, var(0),
                    binop(BinOp::Shl,
                        binop(BinOp::Shl, lit(OP_NOP), lit(26)),
                        lit(32))))),
            deref_assign(
                binop(BinOp::Add, lit(LAYOUT_OUT), var(1)),
                var(2)),
            deref_assign(lit(WS_OUT_POS),
                binop(BinOp::Add, var(1), lit(8))),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── add_symbol(ns, nl) → offset ───────────────
    // Stride 24: (name_start, name_len, offset).
    // Duplicate detection via names_equal.
    let fn_add_symbol = Function {
        name: "add_symbol".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (2, Type::Int), (3, Type::Int), (4, Type::Int),
            (5, Type::Int), (6, Type::Int), (7, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_SYM_COUNT)))),
            Stmt::If(
                binop(BinOp::Le, lit(32), var(2)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ],
                vec![],
            ),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::VarDecl(5, Type::Int, Some(lit(0))),
            Stmt::VarDecl(6, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(3), var(2)), vec![
                assign(4, binop(BinOp::Add, lit(WS_SYM_TABLE),
                    binop(BinOp::Mul, var(3), lit(24)))),
                assign(5, deref(var(4))),
                assign(6, deref(binop(BinOp::Add, var(4), lit(8)))),
                Stmt::If(
                    call("names_equal", vec![
                        var(0), var(1), var(5), var(6)]),
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        Stmt::Return(lit(0)),
                    ],
                    vec![],
                ),
                assign(3, binop(BinOp::Add, var(3), lit(1))),
            ]),
            Stmt::VarDecl(7, Type::Int, Some(
                binop(BinOp::Sub, lit(0),
                    binop(BinOp::Mul,
                        binop(BinOp::Add, var(2), lit(1)),
                        lit(8))))),
            assign(4, binop(BinOp::Add, lit(WS_SYM_TABLE),
                binop(BinOp::Mul, var(2), lit(24)))),
            deref_assign(var(4), var(0)),
            deref_assign(
                binop(BinOp::Add, var(4), lit(8)),
                var(1)),
            deref_assign(
                binop(BinOp::Add, var(4), lit(16)),
                var(7)),
            deref_assign(lit(WS_SYM_COUNT),
                binop(BinOp::Add, var(2), lit(1))),
            Stmt::Return(var(7)),
        ],
    };

    // ─── lookup_symbol(ns, nl) → offset ────────────
    // Stride 24, uses names_equal.
    let fn_lookup_symbol = Function {
        name: "lookup_symbol".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (2, Type::Int), (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_SYM_COUNT)))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(3), var(2)), vec![
                assign(4, binop(BinOp::Add, lit(WS_SYM_TABLE),
                    binop(BinOp::Mul, var(3), lit(24)))),
                Stmt::If(
                    call("names_equal", vec![
                        var(0), var(1),
                        deref(var(4)),
                        deref(binop(BinOp::Add, var(4), lit(8)))]),
                    vec![Stmt::Return(deref(
                        binop(BinOp::Add, var(4), lit(16))))],
                    vec![],
                ),
                assign(3, binop(BinOp::Add, var(3), lit(1))),
            ]),
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── add_func(ns, nl, arity) ───────────────────
    // Stride 32: (name_start, name_len, address, arity).
    let fn_add_func = Function {
        name: "add_func".into(),
        params: vec![(0, Type::Int), (1, Type::Int), (2, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(3, Type::Int), (4, Type::Int)],
        body: vec![
            Stmt::VarDecl(3, Type::Int, Some(deref(lit(WS_FUNC_COUNT)))),
            Stmt::If(
                binop(BinOp::Le, lit(64), var(3)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ],
                vec![],
            ),
            Stmt::VarDecl(4, Type::Int, Some(
                binop(BinOp::Add, lit(WS_FUNC_TABLE),
                    binop(BinOp::Mul, var(3), lit(32))))),
            deref_assign(var(4), var(0)),
            deref_assign(
                binop(BinOp::Add, var(4), lit(8)),
                var(1)),
            deref_assign(
                binop(BinOp::Add, var(4), lit(16)),
                deref(lit(WS_OUT_POS))),
            deref_assign(
                binop(BinOp::Add, var(4), lit(24)),
                var(2)),
            deref_assign(lit(WS_FUNC_COUNT),
                binop(BinOp::Add, var(3), lit(1))),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── lookup_func(ns, nl) → address ─────────────
    // Stride 32, uses names_equal.
    let fn_lookup_func = Function {
        name: "lookup_func".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (2, Type::Int), (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_FUNC_COUNT)))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(3), var(2)), vec![
                assign(4, binop(BinOp::Add, lit(WS_FUNC_TABLE),
                    binop(BinOp::Mul, var(3), lit(32)))),
                Stmt::If(
                    call("names_equal", vec![
                        var(0), var(1),
                        deref(var(4)),
                        deref(binop(BinOp::Add, var(4), lit(8)))]),
                    vec![Stmt::Return(deref(
                        binop(BinOp::Add, var(4), lit(16))))],
                    vec![],
                ),
                assign(3, binop(BinOp::Add, var(3), lit(1))),
            ]),
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── lookup_arity(ns, nl) → arity ──────────────
    // Stride 32, uses names_equal.
    let fn_lookup_arity = Function {
        name: "lookup_arity".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (2, Type::Int), (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_FUNC_COUNT)))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(3), var(2)), vec![
                assign(4, binop(BinOp::Add, lit(WS_FUNC_TABLE),
                    binop(BinOp::Mul, var(3), lit(32)))),
                Stmt::If(
                    call("names_equal", vec![
                        var(0), var(1),
                        deref(var(4)),
                        deref(binop(BinOp::Add, var(4), lit(8)))]),
                    vec![Stmt::Return(deref(
                        binop(BinOp::Add, var(4), lit(24))))],
                    vec![],
                ),
                assign(3, binop(BinOp::Add, var(3), lit(1))),
            ]),
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── add_fixup(cp, ns, nl, argc) ───────────────
    // Stride 32: (call_pos, name_start, name_len, argc).
    let fn_add_fixup = Function {
        name: "add_fixup".into(),
        params: vec![(0, Type::Int), (1, Type::Int),
                     (2, Type::Int), (3, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(4, Type::Int), (5, Type::Int)],
        body: vec![
            Stmt::VarDecl(4, Type::Int, Some(deref(lit(WS_FIX_COUNT)))),
            Stmt::If(
                binop(BinOp::Le, lit(512), var(4)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ],
                vec![],
            ),
            Stmt::VarDecl(5, Type::Int, Some(
                binop(BinOp::Add, lit(WS_FIX_TABLE),
                    binop(BinOp::Mul, var(4), lit(32))))),
            deref_assign(var(5), var(0)),
            deref_assign(
                binop(BinOp::Add, var(5), lit(8)),
                var(1)),
            deref_assign(
                binop(BinOp::Add, var(5), lit(16)),
                var(2)),
            deref_assign(
                binop(BinOp::Add, var(5), lit(24)),
                var(3)),
            deref_assign(lit(WS_FIX_COUNT),
                binop(BinOp::Add, var(4), lit(1))),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── patch_call(call_pos, func_addr) ───────────
    let fn_patch_call = Function {
        name: "patch_call".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (2, Type::Int), (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(2, Type::Int, Some(
                binop(BinOp::Sub,
                    binop(BinOp::Shr, var(1), lit(2)),
                    binop(BinOp::Shr, var(0), lit(2))))),
            Stmt::VarDecl(3, Type::Int, Some(
                binop(BinOp::Or,
                    binop(BinOp::Shl, lit(OP_CALL), lit(26)),
                    binop(BinOp::Shr,
                        binop(BinOp::Shl, var(2), lit(42)),
                        lit(42))))),
            Stmt::VarDecl(4, Type::Int, Some(
                binop(BinOp::Or, var(3),
                    binop(BinOp::Shl,
                        binop(BinOp::Shl, lit(OP_NOP), lit(26)),
                        lit(32))))),
            deref_assign(
                binop(BinOp::Add, lit(LAYOUT_OUT), var(0)),
                var(4)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── resolve_fixups() ──────────────────────────
    // Stride 32: (call_pos, name_start, name_len, argc).
    // Reads ns/nl, passes both to lookup_func/lookup_arity.
    let fn_resolve_fixups = Function {
        name: "resolve_fixups".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int), (5, Type::Int),
            (6, Type::Int), (7, Type::Int), (8, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_FIX_COUNT)))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),
            Stmt::VarDecl(5, Type::Int, Some(lit(0))),
            Stmt::VarDecl(6, Type::Int, Some(lit(0))),
            Stmt::VarDecl(7, Type::Int, Some(lit(0))),
            Stmt::VarDecl(8, Type::Int, Some(lit(0))),
            Stmt::While(binop(BinOp::Lt, var(1), var(0)), vec![
                assign(2, binop(BinOp::Add, lit(WS_FIX_TABLE),
                    binop(BinOp::Mul, var(1), lit(32)))),
                assign(3, deref(var(2))),                            // call_pos
                assign(4, deref(binop(BinOp::Add, var(2), lit(8)))), // ns
                assign(5, deref(binop(BinOp::Add, var(2), lit(16)))),// nl
                assign(6, deref(binop(BinOp::Add, var(2), lit(24)))),// argc
                assign(7, call("lookup_func", vec![var(4), var(5)])),
                assign(8, call("lookup_arity", vec![var(4), var(5)])),
                Stmt::If(
                    binop(BinOp::Ne, var(6), var(8)),
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                    vec![],
                ),
                call_stmt("patch_call", vec![var(3), var(7)]),
                assign(1, binop(BinOp::Add, var(1), lit(1))),
            ]),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── patch_branch(pos, cond, target) ───────────
    let fn_patch_branch = Function {
        name: "patch_branch".into(),
        params: vec![(0, Type::Int), (1, Type::Int), (2, Type::Int)],
        ret_type: Type::Int,
        locals: vec![
            (3, Type::Int), (4, Type::Int), (5, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(3, Type::Int, Some(
                binop(BinOp::Shr,
                    binop(BinOp::Sub, var(2), var(0)),
                    lit(2)))),
            Stmt::VarDecl(4, Type::Int, Some(
                binop(BinOp::Or,
                    binop(BinOp::Or,
                        binop(BinOp::Shl, lit(OP_BCC), lit(26)),
                        binop(BinOp::Shl, var(1), lit(22))),
                    binop(BinOp::Shr,
                        binop(BinOp::Shl, var(3), lit(42)),
                        lit(42))))),
            Stmt::VarDecl(5, Type::Int, Some(
                binop(BinOp::Or, var(4),
                    binop(BinOp::Shl,
                        binop(BinOp::Shl, lit(OP_NOP), lit(26)),
                        lit(32))))),
            deref_assign(
                binop(BinOp::Add, lit(LAYOUT_OUT), var(0)),
                var(5)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_call(ns, nl) ──────────────────────
    // Shared call-expression compiler used by both
    // compile_primary (ident(...)) and compile_stmt (ident(...);).
    // At entry, current token is '('.
    // Params: ns(0)=name_start, nl(1)=name_len
    // Locals: argc(2), code_pos(3)
    let fn_compile_call = Function {
        name: "compile_call".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(2, Type::Int), (3, Type::Int)],
        body: vec![
            call_stmt("next_token", vec![]),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                vec![
                    call_stmt("compile_expr", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                    assign(2, lit(1)),
                    Stmt::While(
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_COMMA)),
                        vec![
                            Stmt::If(
                                binop(BinOp::Le, lit(4), var(2)),
                                vec![
                                    deref_assign(lit(WS_ERROR), lit(1)),
                                    Stmt::Return(lit(0)),
                                ],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            call_stmt("compile_expr", vec![]),
                            call_stmt("emit", vec![
                                enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                            call_stmt("emit", vec![
                                enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                            assign(2, binop(BinOp::Add, var(2), lit(1))),
                        ],
                    ),
                ],
                vec![],
            ),
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),
            call_stmt("next_token", vec![]),
            Stmt::If(binop(BinOp::Lt, lit(0), var(2)),
                vec![call_stmt("emit", vec![
                    enc_i(OP_LD, GEN_R0, GEN_SP,
                        binop(BinOp::Mul,
                            binop(BinOp::Sub, var(2), lit(1)),
                            lit(8)))])],
                vec![]),
            Stmt::If(binop(BinOp::Lt, lit(1), var(2)),
                vec![call_stmt("emit", vec![
                    enc_i(OP_LD, 1, GEN_SP,
                        binop(BinOp::Mul,
                            binop(BinOp::Sub, var(2), lit(2)),
                            lit(8)))])],
                vec![]),
            Stmt::If(binop(BinOp::Lt, lit(2), var(2)),
                vec![call_stmt("emit", vec![
                    enc_i(OP_LD, 2, GEN_SP,
                        binop(BinOp::Mul,
                            binop(BinOp::Sub, var(2), lit(3)),
                            lit(8)))])],
                vec![]),
            Stmt::If(binop(BinOp::Lt, lit(3), var(2)),
                vec![call_stmt("emit", vec![
                    enc_i(OP_LD, 3, GEN_SP,
                        binop(BinOp::Mul,
                            binop(BinOp::Sub, var(2), lit(4)),
                            lit(8)))])],
                vec![]),
            Stmt::If(binop(BinOp::Lt, lit(0), var(2)),
                vec![call_stmt("emit", vec![
                    enc_i(OP_ADDI, GEN_SP, GEN_SP,
                        binop(BinOp::Mul, var(2), lit(8)))])],
                vec![]),
            assign(3, deref(lit(WS_OUT_POS))),
            call_stmt("emit", vec![
                binop(BinOp::Shl, lit(OP_CALL), lit(26))]),
            call_stmt("add_fixup", vec![
                var(3), var(0), var(1), var(2)]),
            call_stmt("emit", vec![
                enc_r(OP_MOV, GEN_R4, GEN_R0, 0)]),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_primary() ─────────────────────────
    // Source-slice version: saves name_start/name_len
    // before consuming more tokens.
    // Locals: tok(0), ns(1), nl(2)
    let fn_compile_primary = Function {
        name: "compile_primary".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int),
            (2, Type::Int), (3, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_TOK_TYPE)))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            // NUMBER
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_NUMBER)),
                vec![
                    assign(1, deref(lit(WS_TOK_VALUE))),
                    call_stmt("next_token", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_MOVI, GEN_R4, 0, var(1))]),
                    Stmt::Return(lit(0)),
                ], vec![]),
            // IDENT — save name_start and name_len immediately
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IDENT)),
                vec![
                    assign(1, deref(lit(WS_TOK_NAME_START))),
                    assign(2, deref(lit(WS_TOK_NAME_LEN))),
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_LPAREN)),
                        vec![
                            call_stmt("compile_call",
                                vec![var(1), var(2)]),
                        ],
                        vec![
                            // Variable reference: LD R4, [FP, offset]
                            assign(0, call("lookup_symbol",
                                vec![var(1), var(2)])),
                            call_stmt("emit", vec![
                                enc_i(OP_LD, GEN_R4, GEN_FP, var(0))]),
                        ],
                    ),
                    Stmt::Return(lit(0)),
                ], vec![]),
            // ( expr )
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_LPAREN)),
                vec![
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_expr", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![call_stmt("next_token", vec![])],
                    ),
                    Stmt::Return(lit(0)),
                ], vec![]),
            // ─── syscall(n, a, b, c [, d [, e]]) ─────
            // Variable-arity builtin (9.3e.2): 4–6 expressions
            // (syscall number + 3..5 payload args).
            // Evaluates all args, pushes to stack, then pops into
            // R0..R(argc-1).  var(3) tracks argc at compile time.
            //
            // Syscall ABI: R0=number, R1..R5=payload.
            // Result: R0 → R4.
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_SYSCALL)),
                vec![
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_LPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // ── 4 mandatory args (n, a, b, c) ──
                    // arg 1 (n → R0)
                    call_stmt("compile_expr", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_COMMA)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // arg 2 (a → R1)
                    call_stmt("compile_expr", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_COMMA)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // arg 3 (b → R2)
                    call_stmt("compile_expr", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_COMMA)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // arg 4 (c → R3)
                    call_stmt("compile_expr", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                    assign(3, lit(4)), // argc = 4
                    // ── Optional 5th arg (d → R4) ──
                    Stmt::If(
                        binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_COMMA)),
                        vec![
                            call_stmt("next_token", vec![]),
                            call_stmt("compile_expr", vec![]),
                            call_stmt("emit", vec![
                                enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                            call_stmt("emit", vec![
                                enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                            assign(3, lit(5)), // argc = 5
                            // ── Optional 6th arg (e → R5) ──
                            Stmt::If(
                                binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_COMMA)),
                                vec![
                                    call_stmt("next_token", vec![]),
                                    call_stmt("compile_expr", vec![]),
                                    call_stmt("emit", vec![
                                        enc_i(OP_SUBI, GEN_SP, GEN_SP, lit(8))]),
                                    call_stmt("emit", vec![
                                        enc_i(OP_ST, GEN_R4, GEN_SP, lit(0))]),
                                    assign(3, lit(6)), // argc = 6
                                ], vec![],
                            ),
                        ], vec![],
                    ),
                    // ── Expect ')' ──
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // ── Pop args into R0..R(argc-1) ──
                    // R0 at highest offset: (argc-1)*8
                    // R1 at (argc-2)*8, ..., R(argc-1) at 0.
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R0, GEN_SP,
                            binop(BinOp::Mul,
                                binop(BinOp::Sub, var(3), lit(1)),
                                lit(8)))]),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R1, GEN_SP,
                            binop(BinOp::Mul,
                                binop(BinOp::Sub, var(3), lit(2)),
                                lit(8)))]),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, 2, GEN_SP,
                            binop(BinOp::Mul,
                                binop(BinOp::Sub, var(3), lit(3)),
                                lit(8)))]),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, 3, GEN_SP,
                            binop(BinOp::Mul,
                                binop(BinOp::Sub, var(3), lit(4)),
                                lit(8)))]),
                    // R4 only if argc > 4
                    Stmt::If(
                        binop(BinOp::Lt, lit(4), var(3)),
                        vec![call_stmt("emit", vec![
                            enc_i(OP_LD, GEN_R4, GEN_SP,
                                binop(BinOp::Mul,
                                    binop(BinOp::Sub, var(3), lit(5)),
                                    lit(8)))])],
                        vec![],
                    ),
                    // R5 only if argc > 5
                    Stmt::If(
                        binop(BinOp::Lt, lit(5), var(3)),
                        vec![call_stmt("emit", vec![
                            enc_i(OP_LD, GEN_R5, GEN_SP,
                                binop(BinOp::Mul,
                                    binop(BinOp::Sub, var(3), lit(6)),
                                    lit(8)))])],
                        vec![],
                    ),
                    // Reclaim stack: argc * 8
                    call_stmt("emit", vec![
                        enc_i(OP_ADDI, GEN_SP, GEN_SP,
                            binop(BinOp::Mul, var(3), lit(8)))]),
                    // TRAP 0 → kernel handles syscall
                    call_stmt("emit", vec![enc_s(OP_TRAP)]),
                    // Result: R0 → R4
                    call_stmt("emit", vec![
                        enc_r(OP_MOV, GEN_R4, GEN_R0, 0)]),
                    Stmt::Return(lit(0)),
                ], vec![]),
            // ─── sysret(1) ───────────────────────────
            // Retrieve secondary syscall result R1 → R4.
            // Only literal 1 is accepted (9.3e.2).
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_SYSRET)),
                vec![
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_LPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // Expect literal 1
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_NUMBER)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_VALUE)),
                            lit(1)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)),
                            lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // MOV R4, R1
                    call_stmt("emit", vec![
                        enc_r(OP_MOV, GEN_R4, GEN_R1, 0)]),
                    Stmt::Return(lit(0)),
                ], vec![]),
            // ─── STRING LITERAL (7.2) ────────────────
            // Store the literal in the output buffer (two-ended
            // allocator, growing downward).  store_literal returns the
            // absolute offset within the output buffer.
            // Emit MOVI R4, offset — the child receives this as a
            // pointer into its R-only literal segment.
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_STRING)),
                vec![
                    assign(1, call("store_literal", vec![])),
                    call_stmt("next_token", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_MOVI, GEN_R4, 0, var(1))]),
                    Stmt::Return(lit(0)),
                ], vec![]),
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_unary() ─────────────────────────
    // *unary → LD R4, [R4, 0]  (dereference)
    // otherwise → compile_primary
    let fn_compile_unary = Function {
        name: "compile_unary".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            Stmt::If(
                binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_STAR)),
                vec![
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_unary", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R4, GEN_R4, lit(0))]),
                    Stmt::Return(lit(0)),
                ],
                vec![],
            ),
            Stmt::Return(call("compile_primary", vec![])),
        ],
    };

    // ─── compile_mult() ────────────────────────────
    // multiplicative → unary {* unary}
    let fn_compile_mult = Function {
        name: "compile_mult".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_unary", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Eq,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_STAR)),
                {
                    let mut inner = vec![call_stmt("next_token", vec![])];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_unary", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.push(call_stmt("emit", vec![
                        enc_r(OP_MUL, GEN_R4, GEN_R5, GEN_R4)]));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_add() ─────────────────────────────
    // additive → multiplicative {(+|-) multiplicative}
    let fn_compile_add = Function {
        name: "compile_add".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_mult", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Or,
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_PLUS)),
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_MINUS))),
                {
                    let mut inner = vec![
                        assign(1, deref(lit(WS_TOK_TYPE))),
                        call_stmt("next_token", vec![]),
                    ];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_mult", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.push(Stmt::If(
                        binop(BinOp::Eq, var(1), lit(TOK_PLUS)),
                        vec![call_stmt("emit", vec![
                            enc_r(OP_ADD, GEN_R4, GEN_R5, GEN_R4)])],
                        vec![call_stmt("emit", vec![
                            enc_r(OP_SUB, GEN_R4, GEN_R5, GEN_R4)])],
                    ));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_shift() ───────────────────────────
    // shift → additive {(<< | >>) additive}
    let fn_compile_shift = Function {
        name: "compile_shift".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_add", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Or,
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_SHL)),
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_SHR))),
                {
                    let mut inner = vec![
                        assign(1, deref(lit(WS_TOK_TYPE))),
                        call_stmt("next_token", vec![]),
                    ];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_add", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.push(Stmt::If(
                        binop(BinOp::Eq, var(1), lit(TOK_SHL)),
                        vec![call_stmt("emit", vec![
                            enc_r(OP_SHL, GEN_R4, GEN_R5, GEN_R4)])],
                        vec![call_stmt("emit", vec![
                            enc_r(OP_SHR, GEN_R4, GEN_R5, GEN_R4)])],
                    ));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_bit_and() ─────────────────────────
    // bitwise_and → shift {& shift}
    let fn_compile_bit_and = Function {
        name: "compile_bit_and".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_shift", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Eq,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_AMP)),
                {
                    let mut inner = vec![call_stmt("next_token", vec![])];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_shift", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.push(call_stmt("emit", vec![
                        enc_r(OP_AND, GEN_R4, GEN_R5, GEN_R4)]));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_bit_or() ──────────────────────────
    // bitwise_or → bitwise_and {| bitwise_and}
    let fn_compile_bit_or = Function {
        name: "compile_bit_or".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_bit_and", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Eq,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_PIPE)),
                {
                    let mut inner = vec![call_stmt("next_token", vec![])];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_bit_and", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.push(call_stmt("emit", vec![
                        enc_r(OP_OR, GEN_R4, GEN_R5, GEN_R4)]));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_relational() ──────────────────────
    // relational → bitwise_or {(< | <=) bitwise_or}
    let fn_compile_relational = Function {
        name: "compile_relational".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_bit_or", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Or,
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_LT)),
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_LE))),
                {
                    let mut inner = vec![
                        assign(1, deref(lit(WS_TOK_TYPE))),
                        call_stmt("next_token", vec![]),
                    ];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_bit_or", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.extend(emit_cmp_sequence(
                        TOK_LT, COND_GE,   // < skips on GE
                        COND_GT,            // <= skips on GT
                    ));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_equality() ────────────────────────
    // equality → relational {(== | !=) relational}
    let fn_compile_equality = Function {
        name: "compile_equality".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: {
            let mut b = vec![
                call_stmt("compile_relational", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            ];
            b.push(Stmt::While(
                binop(BinOp::Or,
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_EQEQ)),
                    binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_NE))),
                {
                    let mut inner = vec![
                        assign(1, deref(lit(WS_TOK_TYPE))),
                        call_stmt("next_token", vec![]),
                    ];
                    inner.extend(expr_stack_save());
                    inner.push(call_stmt("compile_relational", vec![]));
                    inner.extend(expr_stack_restore());
                    inner.extend(emit_cmp_sequence(
                        TOK_EQEQ, COND_NE,  // == skips on NE
                        COND_EQ,             // != skips on EQ
                    ));
                    inner
                },
            ));
            b.push(Stmt::Return(lit(0)));
            b
        },
    };

    // ─── compile_expr() ────────────────────────────
    let fn_compile_expr = Function {
        name: "compile_expr".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            Stmt::Return(call("compile_equality", vec![])),
        ],
    };

    // ─── compile_stmt() ────────────────────────────
    // Source-slice version: saves name_start/name_len
    // for var decl and assignment.
    // Locals: tok(0), ns(1), nl(2) / temp, branch_pos(3), temp(4)
    let fn_compile_stmt = Function {
        name: "compile_stmt".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_TOK_TYPE)))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::VarDecl(4, Type::Int, Some(lit(0))),

            // ─── int IDENT = expr; (variable declaration) ──
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_INT_KW)),
                vec![
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_IDENT)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    assign(1, deref(lit(WS_TOK_NAME_START))),
                    assign(3, deref(lit(WS_TOK_NAME_LEN))),
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_EQ)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_expr", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_SEMI)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    assign(2, call("add_symbol", vec![var(1), var(3)])),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_FP, var(2))]),
                    Stmt::Return(lit(0)),
                ], vec![]),

            // ─── return expr; → epilogue + RET ─────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_RETURN)),
                vec![
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_expr", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_SEMI)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    call_stmt("emit", vec![
                        enc_r(OP_MOV, GEN_R0, GEN_R4, 0)]),
                    call_stmt("emit", vec![
                        enc_r(OP_MOV, GEN_SP, GEN_FP, 0)]),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_FP, GEN_SP, lit(0))]),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_LR, GEN_SP, lit(8))]),
                    call_stmt("emit", vec![
                        enc_i(OP_ADDI, GEN_SP, GEN_SP, lit(16))]),
                    call_stmt("emit", vec![enc_s(OP_RET)]),
                    Stmt::Return(lit(1)),
                ], vec![]),

            // ─── if ( expr ) { stmts } [else { stmts }] ──
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IF)),
                vec![
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_expr", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_CMPI, 0, GEN_R4, lit(0))]),
                    assign(3, deref(lit(WS_OUT_POS))),
                    call_stmt("emit", vec![
                        enc_b(COND_EQ, lit(0))]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LBRACE)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    assign(1, call("compile_block", vec![])),
                    Stmt::If(
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_ELSE)),
                        vec![
                            call_stmt("next_token", vec![]),
                            assign(4, deref(lit(WS_OUT_POS))),
                            call_stmt("emit", vec![
                                enc_b(COND_AL, lit(0))]),
                            call_stmt("patch_branch", vec![
                                var(3), lit(COND_EQ),
                                deref(lit(WS_OUT_POS))]),
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_LBRACE)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            assign(2, call("compile_block", vec![])),
                            call_stmt("patch_branch", vec![
                                var(4), lit(COND_AL),
                                deref(lit(WS_OUT_POS))]),
                            Stmt::Return(
                                binop(BinOp::And, var(1), var(2))),
                        ],
                        vec![
                            call_stmt("patch_branch", vec![
                                var(3), lit(COND_EQ),
                                deref(lit(WS_OUT_POS))]),
                            Stmt::Return(lit(0)),
                        ],
                    ),
                    Stmt::Return(lit(0)),
                ], vec![]),

            // ─── while ( expr ) { stmts } ──────────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_WHILE)),
                vec![
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    assign(3, deref(lit(WS_OUT_POS))),
                    call_stmt("compile_expr", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    call_stmt("emit", vec![
                        enc_i(OP_CMPI, 0, GEN_R4, lit(0))]),
                    assign(4, deref(lit(WS_OUT_POS))),
                    call_stmt("emit", vec![
                        enc_b(COND_EQ, lit(0))]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LBRACE)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_block", vec![]),
                    assign(1, binop(BinOp::Sub, lit(0),
                        binop(BinOp::Shr,
                            binop(BinOp::Sub,
                                deref(lit(WS_OUT_POS)), var(3)),
                            lit(2)))),
                    call_stmt("emit", vec![
                        enc_b(COND_AL, var(1))]),
                    call_stmt("patch_branch", vec![
                        var(4), lit(COND_EQ),
                        deref(lit(WS_OUT_POS))]),
                    Stmt::Return(lit(0)),
                ], vec![]),

            // ─── *expr = value; (dereference assignment) ──
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_STAR)),
                {
                    let mut s = vec![
                        call_stmt("next_token", vec![]),
                        call_stmt("compile_expr", vec![]),
                    ];
                    s.extend(expr_stack_save());
                    s.extend(vec![
                        Stmt::If(
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)), lit(TOK_EQ)),
                            vec![deref_assign(lit(WS_ERROR), lit(1))],
                            vec![],
                        ),
                        call_stmt("next_token", vec![]),
                        call_stmt("compile_expr", vec![]),
                    ]);
                    s.extend(expr_stack_restore());
                    s.extend(vec![
                        Stmt::If(
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)), lit(TOK_SEMI)),
                            vec![deref_assign(lit(WS_ERROR), lit(1))],
                            vec![],
                        ),
                        call_stmt("next_token", vec![]),
                        call_stmt("emit", vec![
                            enc_i(OP_ST, GEN_R4, GEN_R5, lit(0))]),
                        Stmt::Return(lit(0)),
                    ]);
                    s
                }, vec![]),

            // ─── IDENT ( args ); or IDENT = expr; ─────
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IDENT)),
                vec![
                    assign(1, deref(lit(WS_TOK_NAME_START))),
                    assign(3, deref(lit(WS_TOK_NAME_LEN))),
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LPAREN)),
                        // Function call as statement
                        vec![
                            call_stmt("compile_call",
                                vec![var(1), var(3)]),
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_SEMI)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            Stmt::Return(lit(0)),
                        ],
                        // Assignment
                        vec![
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)), lit(TOK_EQ)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            call_stmt("compile_expr", vec![]),
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_SEMI)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            assign(2, call("lookup_symbol",
                                vec![var(1), var(3)])),
                            call_stmt("emit", vec![
                                enc_i(OP_ST, GEN_R4, GEN_FP, var(2))]),
                            Stmt::Return(lit(0)),
                        ],
                    ),
                ], vec![]),

            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_block() ───────────────────────────
    let fn_compile_block = Function {
        name: "compile_block".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            Stmt::While(
                binop(BinOp::And,
                    binop(BinOp::And,
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RBRACE)),
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_EOF))),
                    binop(BinOp::Eq,
                        deref(lit(WS_ERROR)), lit(0))),
                vec![assign(0, binop(BinOp::Or, var(0),
                    call("compile_stmt", vec![])))],
            ),
            Stmt::If(deref(lit(WS_ERROR)),
                vec![Stmt::Return(var(0))],
                vec![],
            ),
            Stmt::If(
                binop(BinOp::Eq,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_EOF)),
                vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(var(0)),
                ],
                vec![],
            ),
            call_stmt("next_token", vec![]),
            Stmt::Return(var(0)),
        ],
    };

    // ─── compile_func_def() ────────────────────────
    // Source-slice version: saves name_start/name_len
    // for function name and parameters.
    // Locals: ns(0), param_count(1), pns(2)/temp, pnl(3)/temp,
    //         prologue_pos(4), frame_size(5), fnl(6)
    let fn_compile_func_def = Function {
        name: "compile_func_def".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int), (5, Type::Int),
            (6, Type::Int),
        ],
        body: vec![
            // Expect: int
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_INT_KW)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),
            call_stmt("next_token", vec![]),
            // Expect: IDENT (function name)
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_IDENT)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),
            Stmt::VarDecl(0, Type::Int, Some(
                deref(lit(WS_TOK_NAME_START)))),
            Stmt::VarDecl(6, Type::Int, Some(
                deref(lit(WS_TOK_NAME_LEN)))),
            call_stmt("next_token", vec![]),
            // Expect: (
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_LPAREN)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),
            call_stmt("next_token", vec![]),

            // Reset per-function symbol scope BEFORE parsing params
            deref_assign(lit(WS_SYM_COUNT), lit(0)),
            deref_assign(lit(WS_EXPR_SP), lit(EXPR_SP_INIT)),

            // Parse parameter list: int IDENT [, int IDENT]*
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
            Stmt::While(
                binop(BinOp::Eq,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_INT_KW)),
                vec![
                    Stmt::If(
                        binop(BinOp::Le, lit(4), var(1)),
                        vec![
                            deref_assign(lit(WS_ERROR), lit(1)),
                            Stmt::Return(lit(0)),
                        ],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_IDENT)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    assign(2, deref(lit(WS_TOK_NAME_START))),
                    assign(3, deref(lit(WS_TOK_NAME_LEN))),
                    call_stmt("next_token", vec![]),
                    call_stmt("add_symbol", vec![var(2), var(3)]),
                    assign(1, binop(BinOp::Add, var(1), lit(1))),
                    Stmt::If(
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_COMMA)),
                        vec![call_stmt("next_token", vec![])],
                        vec![],
                    ),
                ],
            ),
            // Expect: )
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),
            call_stmt("next_token", vec![]),
            // Expect: {
            Stmt::If(
                binop(BinOp::Ne,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_LBRACE)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),
            call_stmt("next_token", vec![]),

            // Record function in table (ns, nl, arity)
            call_stmt("add_func", vec![var(0), var(6), var(1)]),

            // ─── Prologue placeholder (backpatched after body) ──
            Stmt::VarDecl(4, Type::Int, Some(
                deref(lit(WS_OUT_POS)))),
            call_stmt("emit", vec![enc_s(OP_NOP)]),
            call_stmt("emit", vec![enc_s(OP_NOP)]),
            call_stmt("emit", vec![enc_s(OP_NOP)]),
            call_stmt("emit", vec![enc_s(OP_NOP)]),

            // Spill parameters R0..Rn into their frame slots.
            Stmt::If(binop(BinOp::Lt, lit(0), var(1)), vec![
                call_stmt("emit", vec![
                    enc_i(OP_ST, GEN_R0, GEN_FP, lit(-8))]),
            ], vec![]),
            Stmt::If(binop(BinOp::Lt, lit(1), var(1)), vec![
                call_stmt("emit", vec![
                    enc_i(OP_ST, 1, GEN_FP, lit(-16))]),
            ], vec![]),
            Stmt::If(binop(BinOp::Lt, lit(2), var(1)), vec![
                call_stmt("emit", vec![
                    enc_i(OP_ST, 2, GEN_FP, lit(-24))]),
            ], vec![]),
            Stmt::If(binop(BinOp::Lt, lit(3), var(1)), vec![
                call_stmt("emit", vec![
                    enc_i(OP_ST, 3, GEN_FP, lit(-32))]),
            ], vec![]),

            // Compile body; capture definitely-returns flag
            assign(0, call("compile_block", vec![])),

            // ─── Backpatch prologue with actual frame size ──
            Stmt::VarDecl(5, Type::Int, Some(
                binop(BinOp::Add, lit(16),
                    binop(BinOp::Mul,
                        deref(lit(WS_SYM_COUNT)), lit(8))))),
            assign(3, binop(BinOp::Shl,
                binop(BinOp::Shl, lit(OP_NOP), lit(26)),
                lit(32))),
            assign(1, binop(BinOp::Add, lit(LAYOUT_OUT), var(4))),

            // Instruction 0: SUBI SP, SP, frame_size
            assign(2, enc_i(OP_SUBI, GEN_SP, GEN_SP, var(5))),
            assign(2, binop(BinOp::Or, var(2), var(3))),
            deref_assign(var(1), var(2)),

            // Instruction 1: ST LR, [SP, frame_size - 8]
            assign(1, binop(BinOp::Add, var(1), lit(8))),
            assign(2, enc_i(OP_ST, GEN_LR, GEN_SP,
                binop(BinOp::Sub, var(5), lit(8)))),
            assign(2, binop(BinOp::Or, var(2), var(3))),
            deref_assign(var(1), var(2)),

            // Instruction 2: ST FP, [SP, frame_size - 16]
            assign(1, binop(BinOp::Add, var(1), lit(8))),
            assign(2, enc_i(OP_ST, GEN_FP, GEN_SP,
                binop(BinOp::Sub, var(5), lit(16)))),
            assign(2, binop(BinOp::Or, var(2), var(3))),
            deref_assign(var(1), var(2)),

            // Instruction 3: ADDI FP, SP, frame_size - 16
            assign(1, binop(BinOp::Add, var(1), lit(8))),
            assign(2, enc_i(OP_ADDI, GEN_FP, GEN_SP,
                binop(BinOp::Sub, var(5), lit(16)))),
            assign(2, binop(BinOp::Or, var(2), var(3))),
            deref_assign(var(1), var(2)),

            // ─── Return-path closure (6B.4.4) ──────────
            Stmt::If(
                binop(BinOp::Eq, var(0), lit(0)),
                vec![deref_assign(lit(WS_ERROR), lit(1))],
                vec![],
            ),

            Stmt::Return(lit(0)),
        ],
    };

    // ─── main() ────────────────────────────────────
    // No keyword pre-computation; uses find_main() after compilation.
    let fn_main = Function {
        name: "main".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![
            (0, Type::Int), (1, Type::Int), (2, Type::Int),
            (3, Type::Int), (4, Type::Int),
        ],
        body: vec![
            // ─── Source setup ─────────────────────────
            Stmt::VarDecl(0, Type::Int, Some(lit(LAYOUT_SRC))),
            Stmt::VarDecl(1, Type::Int, Some(deref(var(0)))),
            Stmt::VarDecl(2, Type::Int, Some(
                binop(BinOp::Add, var(0), lit(8)))),

            Stmt::If(
                binop(BinOp::Lt, lit(SOURCE_SIZE - 8), var(1)),
                vec![Stmt::Return(lit(-1))],
                vec![],
            ),

            // ─── Initialize workspace ────────────────
            deref_assign(lit(WS_POS), lit(0)),
            deref_assign(lit(WS_SRC_LEN), var(1)),
            deref_assign(lit(WS_TEXT_BASE), var(2)),
            deref_assign(lit(WS_ERROR), lit(0)),
            deref_assign(lit(WS_SYM_COUNT), lit(0)),
            deref_assign(lit(WS_OUT_POS), lit(0)),
            deref_assign(lit(WS_EXPR_SP), lit(EXPR_SP_INIT)),
            deref_assign(lit(WS_FUNC_COUNT), lit(0)),
            deref_assign(lit(WS_FIX_COUNT), lit(0)),

            // ─── Prime lexer ─────────────────────────
            call_stmt("next_token", vec![]),

            // ─── Emit _start stub ────────────────────
            //   CALL main (placeholder — patched by find_main)
            //   HALT
            assign(3, deref(lit(WS_OUT_POS))),
            call_stmt("emit", vec![
                binop(BinOp::Shl, lit(OP_CALL), lit(26))]),
            call_stmt("emit", vec![enc_s(OP_HALT)]),

            // ─── Compile function definitions ────────
            Stmt::While(
                binop(BinOp::And,
                    binop(BinOp::Ne,
                        deref(lit(WS_TOK_TYPE)), lit(TOK_EOF)),
                    binop(BinOp::Eq,
                        deref(lit(WS_ERROR)), lit(0))),
                vec![call_stmt("compile_func_def", vec![])],
            ),

            // ─── Resolve call fixups ─────────────────
            call_stmt("resolve_fixups", vec![]),

            // ─── Patch _start → main ─────────────────
            assign(4, call("find_main", vec![])),
            call_stmt("patch_call", vec![var(3), var(4)]),

            // ─── Check error flag ────────────────────
            Stmt::If(deref(lit(WS_ERROR)),
                vec![Stmt::Return(lit(-1))],
                vec![],
            ),

            // ─── Seal → optional Exec ─────────────────
            Stmt::Expr(syscall(SYS_SEAL as u8, vec![lit(LAYOUT_OUT)])),
            assign(3, deref(lit(WS_OUT_POS))),
            // Normalize literal segment offset:
            // If no literals were stored, WS_LIT_POS == OUTPUT_SIZE → pass 0.
            // Otherwise pass the literal frontier as R3.
            // Equality, not comparison: corruption should propagate.
            assign(0, deref(lit(WS_LIT_POS))),
            Stmt::If(binop(BinOp::Eq, var(0), lit(OUTPUT_SIZE)),
                vec![assign(0, lit(0))],
                vec![]),
            // Phase 9.3h.4 bootstrap closure: the Rust AST seed compiler must
            // obey the same compile-only mode contract as canonical CC_B.
            // Otherwise building CC_B for the shell would immediately execute
            // the freshly compiled compiler as a second child.
            Stmt::If(
                binop(
                    BinOp::Eq,
                    deref(lit(WS_MODE)),
                    lit(CCB_MODE_COMPILE_ONLY as i64),
                ),
                vec![Stmt::Return(lit(0))],
                vec![],
            ),
            assign(4, syscall(SYS_EXEC as u8,
                vec![lit(LAYOUT_OUT), var(3), var(0)])),
            Stmt::Return(var(4)),
        ],
    };

    let mut functions = vec![fn_main];
    functions.extend(guest_lexer());
    functions.extend(vec![
        fn_compile_call, fn_compile_primary, fn_compile_unary,
        fn_compile_mult, fn_compile_add, fn_compile_shift,
        fn_compile_bit_and, fn_compile_bit_or,
        fn_compile_relational, fn_compile_equality,
        fn_compile_expr,
        fn_compile_stmt, fn_compile_block, fn_compile_func_def,
        fn_patch_branch, fn_patch_call,
        fn_add_symbol, fn_lookup_symbol,
        fn_add_func, fn_lookup_func, fn_lookup_arity,
        fn_add_fixup, fn_resolve_fixups,
        fn_emit,
    ]);
    Program { functions }
}


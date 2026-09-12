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
//  Shared workspace layout — lexer-relevant addresses
//  (identical across 6B.3 and 6B.4)
// ═══════════════════════════════════════════════════════════
pub(crate) const WS_POS: i64       = 0x6000;
pub(crate) const WS_SRC_LEN: i64   = 0x6008;
pub(crate) const WS_TEXT_BASE: i64  = 0x6010;
pub(crate) const WS_ERROR: i64      = 0x6018;
pub(crate) const WS_TOK_TYPE: i64   = 0x6020;
pub(crate) const WS_TOK_VALUE: i64  = 0x6028;
pub(crate) const WS_KW_INT: i64     = 0x6030;
pub(crate) const WS_KW_RETURN: i64  = 0x6038;
pub(crate) const WS_KW_IF: i64      = 0x6040;
pub(crate) const WS_KW_ELSE: i64    = 0x6048;
pub(crate) const WS_KW_WHILE: i64   = 0x6050;

// Phase-specific workspace slots (6B.5: source-slice names)
pub(crate) const WS_TOK_NAME_START: i64 = 0x6030;
pub(crate) const WS_TOK_NAME_LEN: i64   = 0x6038;
pub(crate) const WS_SYM_COUNT: i64  = 0x6040;
pub(crate) const WS_OUT_POS: i64    = 0x6048;
pub(crate) const WS_EXPR_SP: i64    = 0x6050;
pub(crate) const WS_FUNC_COUNT: i64 = 0x6058;
pub(crate) const WS_FIX_COUNT: i64  = 0x6060;
// Symbol table: 32 entries × 24 bytes at 0x6068..0x6368
//   (name_start: i64, name_len: i64, offset: i64)
pub(crate) const WS_SYM_TABLE: i64  = 0x6068;
// Function table: 16 entries × 32 bytes at 0x6368..0x6568
//   (name_start: i64, name_len: i64, address: i64, arity: i64)
pub(crate) const WS_FUNC_TABLE: i64 = 0x6368;
// Fixup table: 32 entries × 32 bytes at 0x6568..0x6968
//   (call_pos: i64, name_start: i64, name_len: i64, argc: i64)
pub(crate) const WS_FIX_TABLE: i64  = 0x6568;
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


// ─── ISA encoding constants ──────────────────────
pub(crate) const OP_ADD: i64  = 1;
pub(crate) const OP_SUB: i64  = 2;
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
pub(crate) const OP_RET: i64  = 56;   // 0x38
pub(crate) const OP_HALT: i64 = 62;   // 0x3E
pub(crate) const OP_NOP: i64  = 63;   // 0x3F


pub(crate) const COND_EQ: i64 = 0;
pub(crate) const COND_GE: i64 = 3;
pub(crate) const COND_AL: i64 = 15;

// ─── Register numbers ────────────────────────────
pub(crate) const GEN_R0: i64  = 0;
pub(crate) const GEN_R4: i64  = 4;
pub(crate) const GEN_R5: i64  = 5;
pub(crate) const GEN_FP: i64  = 13;
pub(crate) const GEN_LR: i64  = 14;
pub(crate) const GEN_SP: i64  = 15;

pub(crate) const EXPR_SP_INIT: i64 = -0x800;

pub(crate) fn syscall(num: u8, args: Vec<Expr>) -> Expr {
    Expr::Syscall(num, args)
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

pub(crate) fn guest_peek_char() -> Function {
    Function {
        name: "peek_char".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int), (2, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
            Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SRC_LEN)))),
            Stmt::If(
                binop(BinOp::Le, var(1), var(0)),
                vec![Stmt::Return(lit(0))],
                vec![],
            ),
            Stmt::VarDecl(2, Type::Int, Some(
                deref(binop(BinOp::Add,
                    deref(lit(WS_TEXT_BASE)),
                    var(0))))),
            Stmt::Return(binop(BinOp::Shr,
                binop(BinOp::Shl, var(2), lit(56)), lit(56))),
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

pub(crate) fn guest_skip_ws() -> Function {
    Function {
        name: "skip_ws".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
            Stmt::While(
                binop(BinOp::Eq, var(0), lit(32)),
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

pub(crate) fn guest_scan_ident(tc: &TokMap) -> Function {
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
pub(crate) fn guest_next_token(tc: &TokMap) -> Function {
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
pub(crate) fn guest_lexer(tc: &TokMap) -> Vec<Function> {
    vec![
        guest_peek_char(),
        guest_advance(),
        guest_skip_ws(),
        guest_set_char_token(),
        guest_scan_number(tc),
        guest_scan_ident(tc),
        guest_next_token(tc),
    ]
}

pub(crate) fn install_trap_handler(fabric: &mut Fabric, text_phys: u64) {
    let mut handler = Asm64::new();
    handler.halt();
    fabric.write_physical(text_phys + 0x3FF0, &handler.to_bytes());
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
    // ─── Shared lexer functions (unchanged) ──────────
    // peek_char, advance, skip_ws, set_char_token, scan_number
    // use the shared builders; scan_ident and next_token are
    // replaced with source-slice versions below.
    let tok4 = TokMap {
        eof: TOK_EOF, number: TOK_NUMBER, ident: TOK_IDENT,
        plus: TOK_PLUS, minus: TOK_MINUS, star: TOK_STAR,
        eq: TOK_EQ, semi: TOK_SEMI, comma: TOK_COMMA,
        int_kw: TOK_INT_KW, return_kw: TOK_RETURN,
        lparen: TOK_LPAREN, rparen: TOK_RPAREN,
        if_kw: TOK_IF, else_kw: TOK_ELSE, while_kw: TOK_WHILE,
        lbrace: TOK_LBRACE, rbrace: TOK_RBRACE, lt: TOK_LT,
    };

    // ─── read_byte(pos) → byte value ───────────────
    // Same logic as peek_char but pos is a parameter.
    let fn_read_byte = Function {
        name: "read_byte".into(),
        params: vec![(0, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(1, Type::Int)],
        body: vec![
            Stmt::VarDecl(1, Type::Int, Some(
                deref(binop(BinOp::Add,
                    deref(lit(WS_TEXT_BASE)),
                    var(0))))),
            Stmt::Return(binop(BinOp::Shr,
                binop(BinOp::Shl, var(1), lit(56)), lit(56))),
        ],
    };

    // ─── names_equal(sa, la, sb, lb) → 0 or 1 ─────
    // Byte-by-byte comparison of two source slices.
    // Call results are saved to locals to avoid scratch register
    // conflicts (CALL clobbers R4-R6).
    let fn_names_equal = Function {
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
    };

    // ─── classify_kw(start, len) → token type ──────
    // Length-first dispatch + byte-by-byte comparison.
    // Params: (0: start, 1: len).
    let fn_classify_kw = Function {
        name: "classify_kw".into(),
        params: vec![(0, Type::Int), (1, Type::Int)],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            // len 2: "if" (105, 102)
            Stmt::If(binop(BinOp::Eq, var(1), lit(2)), vec![
                kw_byte_chain(0, &[105, 102],
                    Stmt::Return(lit(TOK_IF))),
            ], vec![]),
            // len 3: "int" (105, 110, 116)
            Stmt::If(binop(BinOp::Eq, var(1), lit(3)), vec![
                kw_byte_chain(0, &[105, 110, 116],
                    Stmt::Return(lit(TOK_INT_KW))),
            ], vec![]),
            // len 4: "else" (101, 108, 115, 101)
            Stmt::If(binop(BinOp::Eq, var(1), lit(4)), vec![
                kw_byte_chain(0, &[101, 108, 115, 101],
                    Stmt::Return(lit(TOK_ELSE))),
            ], vec![]),
            // len 5: "while" (119, 104, 105, 108, 101)
            Stmt::If(binop(BinOp::Eq, var(1), lit(5)), vec![
                kw_byte_chain(0, &[119, 104, 105, 108, 101],
                    Stmt::Return(lit(TOK_WHILE))),
            ], vec![]),
            // len 6: "return" (114, 101, 116, 117, 114, 110)
            Stmt::If(binop(BinOp::Eq, var(1), lit(6)), vec![
                kw_byte_chain(0, &[114, 101, 116, 117, 114, 110],
                    Stmt::Return(lit(TOK_RETURN))),
            ], vec![]),
            Stmt::Return(lit(TOK_IDENT)),
        ],
    };

    // ─── find_main() → address ─────────────────────
    // Scans function table for a 4-byte name spelling "main".
    // Params: none. Locals: count(0), i(1), base(2), ns(3), nl(4).
    let fn_find_main = Function {
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
                    // "main" = 109, 97, 105, 110
                    kw_byte_chain(3, &[109, 97, 105, 110],
                        Stmt::Return(deref(
                            binop(BinOp::Add, var(2), lit(16))))),
                ], vec![]),
                assign(1, binop(BinOp::Add, var(1), lit(1))),
            ]),
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── scan_ident() — source-slice version ───────
    // Records (start, len) in WS_TOK_NAME_START/LEN,
    // calls classify_kw for keyword classification.
    // Vars: ch(0), start(1), len(2).
    let fn_scan_ident = Function {
        name: "scan_ident".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int), (2, Type::Int)],
        body: vec![
            Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
            Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_POS)))),
            Stmt::VarDecl(2, Type::Int, Some(lit(0))),
            // Letter loop: 97 ≤ ch ≤ 122
            Stmt::While(
                in_range(var(0), 97, 122),
                vec![
                    assign(2, binop(BinOp::Add, var(2), lit(1))),
                    call_stmt("advance", vec![]),
                    assign(0, call("peek_char", vec![])),
                ],
            ),
            // Digit suffix loop: 48 ≤ ch ≤ 57
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
    };

    // ─── next_token() — direct TOK_* constants ─────
    // Position-based EOF. Uses source-slice scan_ident.
    let fn_next_token = Function {
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
            Stmt::If(binop(BinOp::Eq, var(0), lit(43)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_PLUS), lit(43)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(45)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_MINUS), lit(45)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(42)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_STAR), lit(42)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(61)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_EQ), lit(61)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(59)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_SEMI), lit(59)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(44)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_COMMA), lit(44)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(40)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_LPAREN), lit(40)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(41)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_RPAREN), lit(41)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(123)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_LBRACE), lit(123)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(125)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_RBRACE), lit(125)]))], vec![]),
            Stmt::If(binop(BinOp::Eq, var(0), lit(60)),
                vec![Stmt::Return(call("set_char_token",
                    vec![lit(TOK_LT), lit(60)]))], vec![]),
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
    };

    // ─── emit(word) ────────────────────────────────
    let fn_emit = Function {
        name: "emit".into(),
        params: vec![(0, Type::Int)],
        ret_type: Type::Int,
        locals: vec![(1, Type::Int), (2, Type::Int)],
        body: vec![
            Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_OUT_POS)))),
            Stmt::If(
                binop(BinOp::Lt, lit(0xFF8), var(1)),
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
                binop(BinOp::Add, lit(0x5000), var(1)),
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
                binop(BinOp::Le, lit(16), var(3)),
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
                binop(BinOp::Le, lit(32), var(4)),
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
                binop(BinOp::Add, lit(0x5000), var(0)),
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
                binop(BinOp::Add, lit(0x5000), var(0)),
                var(5)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_primary() ─────────────────────────
    // Source-slice version: saves name_start/name_len
    // before consuming more tokens.
    // Locals: tok(0), ns(1), nl(2), argc(3)
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
                            // Function call: IDENT ( args )
                            call_stmt("next_token", vec![]),
                            Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_RPAREN)),
                                vec![
                                    call_stmt("compile_expr", vec![]),
                                    call_stmt("emit", vec![
                                        enc_i(OP_SUBI, GEN_SP, GEN_SP,
                                            lit(8))]),
                                    call_stmt("emit", vec![
                                        enc_i(OP_ST, GEN_R4, GEN_SP,
                                            lit(0))]),
                                    assign(3, lit(1)),
                                    Stmt::While(
                                        binop(BinOp::Eq,
                                            deref(lit(WS_TOK_TYPE)),
                                            lit(TOK_COMMA)),
                                        vec![
                                            Stmt::If(
                                                binop(BinOp::Le,
                                                    lit(4), var(3)),
                                                vec![
                                                    deref_assign(
                                                        lit(WS_ERROR),
                                                        lit(1)),
                                                    Stmt::Return(lit(0)),
                                                ],
                                                vec![],
                                            ),
                                            call_stmt("next_token",
                                                vec![]),
                                            call_stmt("compile_expr",
                                                vec![]),
                                            call_stmt("emit", vec![
                                                enc_i(OP_SUBI, GEN_SP,
                                                    GEN_SP, lit(8))]),
                                            call_stmt("emit", vec![
                                                enc_i(OP_ST, GEN_R4,
                                                    GEN_SP, lit(0))]),
                                            assign(3, binop(BinOp::Add,
                                                var(3), lit(1))),
                                        ],
                                    ),
                                ],
                                vec![],
                            ),
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_RPAREN)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            Stmt::If(binop(BinOp::Lt, lit(0), var(3)),
                                vec![call_stmt("emit", vec![
                                    enc_i(OP_LD, GEN_R0, GEN_SP,
                                        binop(BinOp::Mul,
                                            binop(BinOp::Sub,
                                                var(3), lit(1)),
                                            lit(8)))])],
                                vec![]),
                            Stmt::If(binop(BinOp::Lt, lit(1), var(3)),
                                vec![call_stmt("emit", vec![
                                    enc_i(OP_LD, 1, GEN_SP,
                                        binop(BinOp::Mul,
                                            binop(BinOp::Sub,
                                                var(3), lit(2)),
                                            lit(8)))])],
                                vec![]),
                            Stmt::If(binop(BinOp::Lt, lit(2), var(3)),
                                vec![call_stmt("emit", vec![
                                    enc_i(OP_LD, 2, GEN_SP,
                                        binop(BinOp::Mul,
                                            binop(BinOp::Sub,
                                                var(3), lit(3)),
                                            lit(8)))])],
                                vec![]),
                            Stmt::If(binop(BinOp::Lt, lit(3), var(3)),
                                vec![call_stmt("emit", vec![
                                    enc_i(OP_LD, 3, GEN_SP,
                                        binop(BinOp::Mul,
                                            binop(BinOp::Sub,
                                                var(3), lit(4)),
                                            lit(8)))])],
                                vec![]),
                            Stmt::If(binop(BinOp::Lt, lit(0), var(3)),
                                vec![call_stmt("emit", vec![
                                    enc_i(OP_ADDI, GEN_SP, GEN_SP,
                                        binop(BinOp::Mul,
                                            var(3), lit(8)))])],
                                vec![]),
                            // Record fixup with name_start, name_len, argc
                            assign(0, deref(lit(WS_OUT_POS))),
                            call_stmt("emit", vec![
                                binop(BinOp::Shl,
                                    lit(OP_CALL), lit(26))]),
                            call_stmt("add_fixup", vec![
                                var(0), var(1), var(2), var(3)]),
                            call_stmt("emit", vec![
                                enc_r(OP_MOV, GEN_R4, GEN_R0, 0)]),
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
            deref_assign(lit(WS_ERROR), lit(1)),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_mult() ────────────────────────────
    let fn_compile_mult = Function {
        name: "compile_mult".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int)],
        body: vec![
            call_stmt("compile_primary", vec![]),
            Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            Stmt::While(
                binop(BinOp::Eq,
                    deref(lit(WS_TOK_TYPE)), lit(TOK_STAR)),
                vec![
                    call_stmt("next_token", vec![]),
                    assign(0, deref(lit(WS_EXPR_SP))),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
                    deref_assign(lit(WS_EXPR_SP),
                        binop(BinOp::Sub,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                    call_stmt("compile_primary", vec![]),
                    deref_assign(lit(WS_EXPR_SP),
                        binop(BinOp::Add,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                    assign(0, deref(lit(WS_EXPR_SP))),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
                    call_stmt("emit", vec![
                        enc_r(OP_MUL, GEN_R4, GEN_R5, GEN_R4)]),
                ],
            ),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_add() ─────────────────────────────
    let fn_compile_add = Function {
        name: "compile_add".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: vec![
            call_stmt("compile_mult", vec![]),
            Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::While(
                binop(BinOp::Le, lit(TOK_PLUS),
                    deref(lit(WS_TOK_TYPE))),
                vec![
                    Stmt::If(
                        binop(BinOp::Lt, lit(TOK_MINUS),
                            deref(lit(WS_TOK_TYPE))),
                        vec![Stmt::Return(lit(0))],
                        vec![],
                    ),
                    assign(1, deref(lit(WS_TOK_TYPE))),
                    call_stmt("next_token", vec![]),
                    assign(0, deref(lit(WS_EXPR_SP))),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
                    deref_assign(lit(WS_EXPR_SP),
                        binop(BinOp::Sub,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                    call_stmt("compile_mult", vec![]),
                    deref_assign(lit(WS_EXPR_SP),
                        binop(BinOp::Add,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                    assign(0, deref(lit(WS_EXPR_SP))),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
                    Stmt::If(
                        binop(BinOp::Eq, var(1), lit(TOK_PLUS)),
                        vec![call_stmt("emit", vec![
                            enc_r(OP_ADD, GEN_R4, GEN_R5, GEN_R4)])],
                        vec![call_stmt("emit", vec![
                            enc_r(OP_SUB, GEN_R4, GEN_R5, GEN_R4)])],
                    ),
                ],
            ),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_cmp() ─────────────────────────────
    let fn_compile_cmp = Function {
        name: "compile_cmp".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![(0, Type::Int), (1, Type::Int)],
        body: vec![
            call_stmt("compile_add", vec![]),
            Stmt::VarDecl(0, Type::Int, Some(lit(0))),
            Stmt::VarDecl(1, Type::Int, Some(lit(0))),
            Stmt::If(
                binop(BinOp::Eq, deref(lit(WS_TOK_TYPE)), lit(TOK_LT)),
                vec![
                    call_stmt("next_token", vec![]),
                    assign(0, deref(lit(WS_EXPR_SP))),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
                    deref_assign(lit(WS_EXPR_SP),
                        binop(BinOp::Sub,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                    call_stmt("compile_add", vec![]),
                    deref_assign(lit(WS_EXPR_SP),
                        binop(BinOp::Add,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                    assign(0, deref(lit(WS_EXPR_SP))),
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
                    call_stmt("emit", vec![
                        enc_r(OP_CMP, 0, GEN_R5, GEN_R4)]),
                    call_stmt("emit", vec![
                        enc_i(OP_MOVI, GEN_R4, 0, lit(0))]),
                    call_stmt("emit", vec![
                        enc_b(COND_GE, lit(4))]),
                    call_stmt("emit", vec![
                        enc_i(OP_MOVI, GEN_R4, 0, lit(1))]),
                ],
                vec![],
            ),
            Stmt::Return(lit(0)),
        ],
    };

    // ─── compile_expr() ────────────────────────────
    let fn_compile_expr = Function {
        name: "compile_expr".into(),
        params: vec![],
        ret_type: Type::Int,
        locals: vec![],
        body: vec![
            Stmt::Return(call("compile_cmp", vec![])),
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

            // ─── IDENT = expr; (assignment) ────────────
            Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IDENT)),
                vec![
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
                    assign(2, call("lookup_symbol", vec![var(1), var(3)])),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_FP, var(2))]),
                    Stmt::Return(lit(0)),
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
            assign(1, binop(BinOp::Add, lit(0x5000), var(4))),

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
            Stmt::VarDecl(0, Type::Int, Some(lit(0x4000))),
            Stmt::VarDecl(1, Type::Int, Some(deref(var(0)))),
            Stmt::VarDecl(2, Type::Int, Some(
                binop(BinOp::Add, var(0), lit(8)))),

            Stmt::If(
                binop(BinOp::Lt, lit(0xFF8), var(1)),
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

            // ─── Seal → Exec ─────────────────────────
            Stmt::Expr(syscall(SYS_SEAL as u8, vec![lit(0x5000)])),
            assign(3, deref(lit(WS_OUT_POS))),
            assign(4, syscall(SYS_EXEC as u8,
                vec![lit(0x5000), var(3)])),
            Stmt::Return(var(4)),
        ],
    };

    let mut functions = vec![fn_main];
    functions.extend(vec![
        guest_peek_char(),
        guest_advance(),
        guest_skip_ws(),
        guest_set_char_token(),
        guest_scan_number(&tok4),
        fn_scan_ident,
        fn_next_token,
        fn_read_byte,
        fn_names_equal,
        fn_classify_kw,
        fn_find_main,
    ]);
    functions.extend(vec![
        fn_compile_primary, fn_compile_mult, fn_compile_add,
        fn_compile_cmp, fn_compile_expr,
        fn_compile_stmt, fn_compile_block, fn_compile_func_def,
        fn_patch_branch, fn_patch_call,
        fn_add_symbol, fn_lookup_symbol,
        fn_add_func, fn_lookup_func, fn_lookup_arity,
        fn_add_fixup, fn_resolve_fixups,
        fn_emit,
    ]);
    Program { functions }
}


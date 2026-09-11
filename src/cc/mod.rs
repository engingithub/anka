//! AnkaCC — tiny C compiler targeting MC68000 via the Asm builder.
//!
//! Compiles a K&R-shaped subset of C into 68000 machine code.
//! The compiler emits calls to the [`crate::asm::Asm`] builder,
//! inheriting its label/fixup system and encoding knowledge.
//!
//! # Supported subset (v0)
//!
//! - Types: `int`, `char`, `void`, pointers
//! - Expressions: literals, variables, binary ops, unary ops, calls,
//!   assignment, dereference, address-of, postfix `++`
//! - Statements: `return`, `if`/`else`, `while`, blocks, local decls
//! - String literals (emitted to a data pool)
//! - Follows ACC v0 calling convention (D0/D1 data, A0/A1 pointers)

mod lex;
mod parse;
mod codegen;

pub use lex::Token;
pub use codegen::compile;

use std::fmt;

// ───────────────────────────────────────────────────────────────────
// Error
// ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CcError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for CcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

// ───────────────────────────────────────────────────────────────────
// Types
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Int,
    Char,
    Void,
    Ptr(Box<Type>),
}

impl Type {
    pub fn size(&self) -> u32 {
        match self {
            Type::Int | Type::Ptr(_) => 4,
            Type::Char => 1,
            Type::Void => 0,
        }
    }

    pub fn is_ptr(&self) -> bool {
        matches!(self, Type::Ptr(_))
    }
}

// ───────────────────────────────────────────────────────────────────
// AST
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    Eq, Ne, Lt, Gt, Le, Ge,
    And, Or,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp {
    Neg, Not, Deref, AddrOf,
}

#[derive(Debug, Clone)]
pub enum Expr {
    IntLit(i32),
    StrLit(String),
    Var(String),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Unary(UnOp, Box<Expr>),
    Call(String, Vec<Expr>),
    Assign(String, Box<Expr>),
    PostInc(String),
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Expr(Expr),
    Return(Option<Expr>),
    If(Expr, Box<Stmt>, Option<Box<Stmt>>),
    While(Expr, Box<Stmt>),
    Block(Vec<Stmt>),
    VarDecl(Type, String, Option<Expr>),
}

#[derive(Debug, Clone)]
pub struct Param {
    pub ty: Type,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub ret_type: Type,
    pub name: String,
    pub params: Vec<Param>,
    pub body: Option<Vec<Stmt>>,
}

#[derive(Debug)]
pub struct Program {
    pub functions: Vec<Function>,
}

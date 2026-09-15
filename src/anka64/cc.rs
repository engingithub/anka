//! AnkaCC₆₄ — minimal C compiler targeting Anka64.
//!
//! C source → AST → Anka64 Asm64 code.
//!
//! This compiler exists to be a demanding client of the ISA.
//! It emits only instructions that exist in desc::INSNS.
//! If it needs an instruction that doesn't exist, the ISA
//! must grow through the description — not the other way around.
//!
//! Function-call convention (Anka64 ABI v0.1):
//!   R0–R3   : arguments / return value (R0 = first arg, R0 = return)
//!   R4–R11  : caller-saved temporaries
//!   R12     : reserved
//!   R13 (FP): frame pointer (callee-saved)
//!   R14 (LR): link register (set by CALL)
//!   R15 (SP): stack pointer (callee-saved, grows downward)
//!
//! Syscall convention (via TRAP #0):
//!   R0      : syscall number (baked in by host compiler)
//!   R1–R5   : payload arguments (up to 5)
//!   R0      : primary return value
//!   R1      : secondary return value (retrieved via sysret(1))

use super::isa::*;

// ───────────────────────────────────────────────────────────────────
// AST — the tiniest subset of C that forces real compilation
// ───────────────────────────────────────────────────────────────────

pub type VarId = usize;

#[derive(Debug, Clone)]
pub enum Type {
    Int,        // 64-bit signed
    Void,
    Ptr(Box<Type>),
}

#[derive(Debug, Clone)]
pub enum Expr {
    IntLit(i64),
    Var(VarId),
    BinOp(BinOp, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
    Deref(Box<Expr>),           // *ptr
    AddrOf(VarId),              // &var
    Assign(VarId, Box<Expr>),   // var = expr
    DerefAssign(Box<Expr>, Box<Expr>), // *ptr = expr
    Syscall(u8, Vec<Expr>),     // syscall(number, args) → result in R0
    Sysret(u8),                 // sysret(k) → Rk (secondary syscall result)
}

#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Shl,
    Shr,
    Lt,
    Le,
    Eq,
    Ne,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Return(Expr),
    Expr(Expr),
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    While(Expr, Vec<Stmt>),
    VarDecl(VarId, Type, Option<Expr>),
    Trap(u8),
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<(VarId, Type)>,
    pub ret_type: Type,
    pub locals: Vec<(VarId, Type)>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub functions: Vec<Function>,
}

// ───────────────────────────────────────────────────────────────────
// Scratch-register depth analysis
//
// The backend evaluates BinOp expressions using R4, R5, R6 as scratch
// registers.  For BinOp(op, lhs, rhs), lhs is compiled into `dest`,
// rhs into `tmp`:
//     tmp = if dest == R5 { R6 } else { R5 }
//
// The register chain from R4 is: R4 → R5 → R6 → R5 (wraps).
// At the third right-spine step, R5 is reused, clobbering a live
// intermediate.  Maximum safe scratch depth from R4 is 3 registers.
//
// scratch_regs(expr) computes the number of scratch registers needed.
// Invariant: scratch_regs(expr) ≤ SCRATCH_REGS for every expression
// compiled from a statement root (dest = R0 or R4).
// ───────────────────────────────────────────────────────────────────

const SCRATCH_REGS: usize = 3;

/// Number of scratch registers needed to evaluate `expr` without
/// clobbering a live intermediate.
pub fn scratch_regs(expr: &Expr) -> usize {
    match expr {
        Expr::IntLit(_) | Expr::Var(_) | Expr::AddrOf(_) => 1,
        Expr::BinOp(_, lhs, rhs) => {
            std::cmp::max(scratch_regs(lhs), 1 + scratch_regs(rhs))
        }
        Expr::Deref(inner) => scratch_regs(inner),
        Expr::Call(_, args) => {
            args.iter().map(|a| scratch_regs(a)).max().unwrap_or(1)
        }
        Expr::Assign(_, val) => scratch_regs(val),
        Expr::DerefAssign(ptr, val) => {
            // val compiled into dest, ptr into tmp
            std::cmp::max(scratch_regs(val), 1 + scratch_regs(ptr))
        }
        Expr::Syscall(_, args) => {
            args.iter().map(|a| scratch_regs(a)).max().unwrap_or(1)
        }
        Expr::Sysret(_) => 1,
    }
}

fn assert_scratch(expr: &Expr) {
    let depth = scratch_regs(expr);
    assert!(depth <= SCRATCH_REGS,
        "expression needs {} scratch registers (backend has {})",
        depth, SCRATCH_REGS);
}

// ───────────────────────────────────────────────────────────────────
// Return-coverage analysis
//
// A non-void function must not have a fall-through path: every
// reachable execution path through the body must reach a Return
// statement.  Without this check, a missing Return silently falls
// off the end of the function into whatever code follows, producing
// a ControlFlowViolation at runtime (if R is non-empty) or silent
// wrong behavior (if R is empty).
//
// The predicate is structural over the AST — no CFG required:
//
//   definitely_returns(Return(_))       = true
//   definitely_returns(If(_, A, B))     = defs(A) ∧ defs(B)
//   definitely_returns(While(_, _))     = false  (conservative)
//   definitely_returns(Expr|VarDecl|…)  = false
//   definitely_returns([s₁, …, sₙ])    = ∃i. definitely_returns(sᵢ)
//
// This is conservative: it may reject functions that always return
// dynamically but whose coverage isn't provable structurally.
// ───────────────────────────────────────────────────────────────────

fn definitely_returns(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| stmt_definitely_returns(s))
}

fn stmt_definitely_returns(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return(_) => true,
        Stmt::If(_, then_body, else_body) => {
            definitely_returns(then_body) && definitely_returns(else_body)
        }
        Stmt::While(_, _) => false,
        Stmt::Expr(_) | Stmt::VarDecl(..) | Stmt::Trap(_) => false,
    }
}

// ───────────────────────────────────────────────────────────────────
// Compiler state
// ───────────────────────────────────────────────────────────────────

struct Compiler {
    asm: Asm64,
    /// Stack frame: variable → offset from FP (negative = below FP).
    frame: Vec<(VarId, i32)>,
    frame_size: i32,
    /// Function entry points: name → word address.
    functions: Vec<(String, i32)>,
    /// Fixups for forward calls: (word index of CALL, target name).
    call_fixups: Vec<(usize, String)>,
}

impl Compiler {
    fn new() -> Self {
        Self {
            asm: Asm64::new(),
            frame: Vec::new(),
            frame_size: 0,
            functions: Vec::new(),
            call_fixups: Vec::new(),
        }
    }

    fn var_offset(&self, id: VarId) -> i32 {
        self.frame.iter()
            .find(|(v, _)| *v == id)
            .map(|(_, off)| *off)
            .unwrap_or_else(|| panic!("undefined variable {}", id))
    }

    fn alloc_local(&mut self, id: VarId) -> i32 {
        self.frame_size += 8;
        let offset = -(self.frame_size);
        self.frame.push((id, offset));
        offset
    }

    // ─── Code generation ────────────────────────────────────────

    fn compile_program(&mut self, prog: &Program) {
        // Emit _start: call main; halt
        //
        // After main Returns, R0 holds the return value.
        // HALT in User mode is treated as implicit SYS_EXIT by the
        // kernel, with exit_code = R0.  (HALT in Supervisor mode,
        // reached through TRAP → trap handler, is a syscall where
        // R0 encodes the syscall number.)
        self.asm.call(0); // placeholder — will fixup
        let start_call_idx = (self.asm.here() - 1) as usize;
        self.call_fixups.push((start_call_idx, "main".to_string()));
        self.asm.halt();

        // Compile all functions
        for func in &prog.functions {
            self.compile_function(func);
        }

        // Fix up all CALL targets
        self.fixup_calls();
    }

    fn compile_function(&mut self, func: &Function) {
        let entry = self.asm.here();
        self.functions.push((func.name.clone(), entry));

        // Reset frame
        self.frame.clear();
        self.frame_size = 0;

        // Prologue: save FP, LR; set FP = SP
        self.asm.st(LR, SP, -8);   // push LR
        self.asm.st(FP, SP, -16);  // push FP
        self.asm.subi(SP, SP, 16);
        self.asm.mov(FP, SP);

        // Allocate parameter slots and store args from registers
        for (i, (param_id, _ty)) in func.params.iter().enumerate() {
            let offset = self.alloc_local(*param_id);
            if i < 4 {
                self.asm.st(i as u8, FP, offset); // store Ri to [FP + offset]
            }
        }

        // Allocate local variable slots
        for (local_id, _ty) in &func.locals {
            self.alloc_local(*local_id);
        }

        // Adjust SP for locals
        if self.frame_size > 0 {
            self.asm.subi(SP, SP, self.frame_size);
        }

        // Non-void functions must have complete return coverage.
        // Every reachable path through the body must hit a Return.
        if !matches!(func.ret_type, Type::Void) {
            assert!(definitely_returns(&func.body),
                "non-void function '{}' has a fall-through path without Return",
                func.name);
        }

        // Compile body
        for stmt in &func.body {
            self.compile_stmt(stmt);
        }

        // Implicit return for void functions
        if matches!(func.ret_type, Type::Void) {
            self.emit_epilogue();
        }
    }

    fn emit_epilogue(&mut self) {
        // Epilogue: restore SP, FP, LR; return
        self.asm.mov(SP, FP);
        self.asm.ld(FP, SP, 0);    // restore FP
        self.asm.ld(LR, SP, 8);    // restore LR
        self.asm.addi(SP, SP, 16);
        self.asm.ret();
    }

    fn compile_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Return(expr) => {
                assert_scratch(expr);
                self.compile_expr(expr, R0); // result → R0
                self.emit_epilogue();
            }
            Stmt::Expr(expr) => {
                assert_scratch(expr);
                self.compile_expr(expr, R4); // discard into R4
            }
            Stmt::VarDecl(id, _ty, init) => {
                if let Some(expr) = init {
                    assert_scratch(expr);
                    self.compile_expr(expr, R4);
                    let offset = self.var_offset(*id);
                    self.asm.st(R4, FP, offset);
                }
            }
            Stmt::If(cond, then_body, else_body) => {
                assert_scratch(cond);
                self.compile_expr(cond, R4);
                self.asm.cmpi(R4, 0);
                let branch_pos = self.asm.here();
                self.asm.bcc(Cond::Eq, 0); // placeholder: skip then-body if false

                for s in then_body {
                    self.compile_stmt(s);
                }

                if else_body.is_empty() {
                    // Patch branch to skip then-body
                    let target = self.asm.here();
                    self.patch_branch(branch_pos as usize, target);
                } else {
                    let jump_pos = self.asm.here();
                    self.asm.bcc(Cond::Al, 0); // placeholder: skip else-body

                    let else_start = self.asm.here();
                    self.patch_branch(branch_pos as usize, else_start);

                    for s in else_body {
                        self.compile_stmt(s);
                    }

                    let after_else = self.asm.here();
                    self.patch_branch(jump_pos as usize, after_else);
                }
            }
            Stmt::While(cond, body) => {
                assert_scratch(cond);
                let loop_top = self.asm.here();
                self.compile_expr(cond, R4);
                self.asm.cmpi(R4, 0);
                let exit_branch = self.asm.here();
                self.asm.bcc(Cond::Eq, 0); // placeholder: exit if false

                for s in body {
                    self.compile_stmt(s);
                }

                // Jump back to loop top
                let back_target = loop_top - self.asm.here();
                self.asm.bcc(Cond::Al, back_target);

                let after_loop = self.asm.here();
                self.patch_branch(exit_branch as usize, after_loop);
            }
            Stmt::Trap(vector) => {
                self.asm.trap(*vector);
            }
        }
    }

    fn compile_expr(&mut self, expr: &Expr, dest: u8) {
        match expr {
            Expr::IntLit(val) => {
                let v = *val;
                if super::isa::fits_imm18(v) {
                    self.asm.movi(dest, v as i32);
                } else {
                    panic!("constant {v} does not fit signed 18-bit immediate \
                            (valid: {}..={})", super::isa::IMM18_MIN, super::isa::IMM18_MAX);
                }
            }
            Expr::Var(id) => {
                let offset = self.var_offset(*id);
                self.asm.ld(dest, FP, offset);
            }
            Expr::BinOp(op, lhs, rhs) => {
                self.compile_expr(lhs, dest);
                // Use R5 as temp for RHS to avoid clobbering dest
                let tmp = if dest == R5 { R6 } else { R5 };
                self.compile_expr(rhs, tmp);
                match op {
                    BinOp::Add => self.asm.add(dest, dest, tmp),
                    BinOp::Sub => self.asm.sub(dest, dest, tmp),
                    BinOp::Mul => self.asm.mul(dest, dest, tmp),
                    BinOp::And => self.asm.and(dest, dest, tmp),
                    BinOp::Or  => self.asm.or(dest, dest, tmp),
                    BinOp::Shl => self.asm.shl(dest, dest, tmp),
                    BinOp::Shr => self.asm.shr(dest, dest, tmp),
                    BinOp::Lt => {
                        self.asm.cmp(dest, tmp);
                        self.asm.movi(dest, 0);
                        let skip = self.asm.here();
                        self.asm.bcc(Cond::Ge, 0);
                        self.asm.movi(dest, 1);
                        let after = self.asm.here();
                        self.patch_branch(skip as usize, after);
                    }
                    BinOp::Le => {
                        self.asm.cmp(dest, tmp);
                        self.asm.movi(dest, 0);
                        let skip = self.asm.here();
                        self.asm.bcc(Cond::Gt, 0);
                        self.asm.movi(dest, 1);
                        let after = self.asm.here();
                        self.patch_branch(skip as usize, after);
                    }
                    BinOp::Eq => {
                        self.asm.cmp(dest, tmp);
                        self.asm.movi(dest, 0);
                        let skip = self.asm.here();
                        self.asm.bcc(Cond::Ne, 0);
                        self.asm.movi(dest, 1);
                        let after = self.asm.here();
                        self.patch_branch(skip as usize, after);
                    }
                    BinOp::Ne => {
                        self.asm.cmp(dest, tmp);
                        self.asm.movi(dest, 0);
                        let skip = self.asm.here();
                        self.asm.bcc(Cond::Eq, 0);
                        self.asm.movi(dest, 1);
                        let after = self.asm.here();
                        self.patch_branch(skip as usize, after);
                    }
                }
            }
            Expr::Call(name, args) => {
                // Evaluate each argument and push to stack.  This matches
                // the canonical compiler's compilecall pattern and avoids
                // register clobber: a nested call in argN cannot overwrite
                // the already-pushed arg0..argN-1.
                let argc = args.len().min(4);
                for arg in args.iter().take(4) {
                    self.compile_expr(arg, R4);
                    self.asm.subi(SP, SP, 8);
                    self.asm.st(R4, SP, 0);
                }
                // Pop into R0–R3 (arg0 is deepest on the stack).
                for i in 0..argc {
                    self.asm.ld(i as u8, SP, ((argc - 1 - i) * 8) as i32);
                }
                if argc > 0 {
                    self.asm.addi(SP, SP, (argc * 8) as i32);
                }
                let call_pos = self.asm.here();
                self.asm.call(0); // placeholder
                self.call_fixups.push((call_pos as usize, name.clone()));
                if dest != R0 {
                    self.asm.mov(dest, R0);
                }
            }
            Expr::Deref(ptr_expr) => {
                self.compile_expr(ptr_expr, dest);
                self.asm.ld(dest, dest, 0);
            }
            Expr::AddrOf(id) => {
                let offset = self.var_offset(*id);
                self.asm.lea(dest, FP, offset);
            }
            Expr::Assign(id, val) => {
                self.compile_expr(val, dest);
                let offset = self.var_offset(*id);
                self.asm.st(dest, FP, offset);
            }
            Expr::DerefAssign(ptr_expr, val_expr) => {
                self.compile_expr(val_expr, dest);
                let tmp = if dest == R5 { R6 } else { R5 };
                self.compile_expr(ptr_expr, tmp);
                self.asm.st(dest, tmp, 0);
            }
            Expr::Syscall(num, args) => {
                // Syscall ABI: R0 = number, R1..R5 = payload args.
                // Max 5 payload arguments (reject > 5).
                assert!(args.len() <= 5,
                    "syscall accepts at most 5 payload arguments, got {}",
                    args.len());
                // Evaluate all args first and spill to stack to prevent
                // later arguments from clobbering already-staged regs.
                let argc = args.len();
                for arg in args.iter() {
                    self.compile_expr(arg, R4);
                    self.asm.subi(SP, SP, 8);
                    self.asm.st(R4, SP, 0);
                }
                // Pop into R1..R(argc) in order.
                // Stack layout (top): arg[argc-1] .. arg[0]
                for i in 0..argc {
                    let reg = (i as u8) + 1; // R1, R2, ..., R5
                    let offset = ((argc - 1 - i) * 8) as i32;
                    self.asm.ld(reg, SP, offset);
                }
                self.asm.addi(SP, SP, (argc * 8) as i32);
                self.asm.movi(R0, *num as i32);
                self.asm.trap(0);
                // After kernel handles the syscall, result is in R0
                if dest != R0 {
                    self.asm.mov(dest, R0);
                }
            }
            Expr::Sysret(k) => {
                // Retrieve secondary syscall result register Rk.
                // Only k=1 is accepted in 9.3e.
                assert_eq!(*k, 1, "sysret only accepts register 1 in 9.3e");
                self.asm.mov(dest, *k);
            }
        }
    }

    fn patch_branch(&mut self, word_idx: usize, target: i32) {
        let offset = target - word_idx as i32;
        // Re-encode the branch at word_idx with the correct offset
        let old = self.asm.words_mut()[word_idx];
        let opcode_and_cond = old & 0xFFC00000; // preserve opcode + cond
        let new = opcode_and_cond | (offset as u32 & 0x3FFFFF);
        self.asm.words_mut()[word_idx] = new;
    }

    fn fixup_calls(&mut self) {
        let fixups: Vec<(usize, String)> = self.call_fixups.drain(..).collect();
        for (word_idx, name) in fixups {
            let target = self.functions.iter()
                .find(|(n, _)| n == &name)
                .map(|(_, addr)| *addr)
                .unwrap_or_else(|| panic!("undefined function: {}", name));
            self.patch_branch(word_idx, target);
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Public API
// ───────────────────────────────────────────────────────────────────

/// Compile a program to Asm64 code.
pub fn compile(prog: &Program) -> Asm64 {
    let mut cc = Compiler::new();
    cc.compile_program(prog);
    cc.asm
}

// ═══════════════════════════════════════════════════════════════════
// Tests — the compiler teaches the ISA
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::core::{Anka64Core, StepResult};
    use super::super::fabric::Fabric;
    use super::super::state::*;

    const CPU0: AgentId = AgentId(0);

    /// Build a complete execution environment for compiled code.
    fn exec_env() -> (Fabric, ObjectId, ObjectId, ObjectId, DomainId) {
        let mut fabric = Fabric::new(0x200000);

        let text  = fabric.alloc_object("text",  0x4000, ObjectKind::Memory);
        let data  = fabric.alloc_object("data",  0x4000, ObjectKind::Memory);
        let stack = fabric.alloc_object("stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text,  0x000000);
        fabric.place_object(data,  0x010000);
        fabric.place_object(stack, 0x020000);

        let dom = fabric.create_domain();
        // text: RX granted after seal (in run_program)
        fabric.grant(dom, data,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        (fabric, text, data, stack, dom)
    }

    fn make_core(dom: DomainId, text: ObjectId, data: ObjectId, stack: ObjectId) -> Anka64Core {
        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x10000, 0x4000, data);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        core
    }

    fn run_program(prog: &Program) -> (Anka64Core, Fabric) {
        let (mut fabric, text, data, stack, dom) = exec_env();
        let asm = compile(prog);

        eprintln!("--- Compiled listing ---\n{}", asm.listing());

        fabric.write_physical(0x000000, &asm.to_bytes());
        fabric.seal_object(text);
        fabric.grant(dom, text, 0, 0x4000, Permissions::RX);
        let mut core = make_core(dom, text, data, stack);

        let result = core.run(&mut fabric, 10000);
        assert!(matches!(result, StepResult::Halted),
            "program did not halt: {:?}", result);

        (core, fabric)
    }

    // ═══════════════════════════════════════════════════════════
    // P10: int add(int a, int b) { return a + b; }
    //      int main() { return add(40, 2); }
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p10_c_add_function() {
        let prog = Program {
            functions: vec![
                Function {
                    name: "add".into(),
                    params: vec![(0, Type::Int), (1, Type::Int)],
                    ret_type: Type::Int,
                    locals: vec![],
                    body: vec![
                        Stmt::Return(Expr::BinOp(
                            BinOp::Add,
                            Box::new(Expr::Var(0)),
                            Box::new(Expr::Var(1)),
                        )),
                    ],
                },
                Function {
                    name: "main".into(),
                    params: vec![],
                    ret_type: Type::Int,
                    locals: vec![],
                    body: vec![
                        Stmt::Return(Expr::Call(
                            "add".into(),
                            vec![Expr::IntLit(40), Expr::IntLit(2)],
                        )),
                    ],
                },
            ],
        };

        let (core, _fabric) = run_program(&prog);
        assert_eq!(core.r[R0 as usize], 42);
        eprintln!("P10: add(40, 2) = {} ✓", core.r[R0 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // P11: int main() { int s=0; int i=1; while(i<=10){s=s+i;i=i+1;} return s; }
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p11_c_loop_sum() {
        // Variables: 0=s, 1=i
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int), (1, Type::Int)],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(0))),
                    Stmt::VarDecl(1, Type::Int, Some(Expr::IntLit(1))),
                    Stmt::While(
                        Expr::BinOp(BinOp::Le, Box::new(Expr::Var(1)), Box::new(Expr::IntLit(10))),
                        vec![
                            Stmt::Expr(Expr::Assign(0,
                                Box::new(Expr::BinOp(BinOp::Add,
                                    Box::new(Expr::Var(0)),
                                    Box::new(Expr::Var(1)),
                                ))
                            )),
                            Stmt::Expr(Expr::Assign(1,
                                Box::new(Expr::BinOp(BinOp::Add,
                                    Box::new(Expr::Var(1)),
                                    Box::new(Expr::IntLit(1)),
                                ))
                            )),
                        ],
                    ),
                    Stmt::Return(Expr::Var(0)),
                ],
            }],
        };

        let (core, _fabric) = run_program(&prog);
        assert_eq!(core.r[R0 as usize], 55);
        eprintln!("P11: sum(1..10) = {} ✓", core.r[R0 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // P12: pointer dereference
    //   int main() { int x = 42; int *p = &x; return *p; }
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p12_pointer_deref() {
        // Variables: 0=x, 1=p
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int), (1, Type::Ptr(Box::new(Type::Int)))],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(42))),
                    Stmt::VarDecl(1, Type::Ptr(Box::new(Type::Int)),
                        Some(Expr::AddrOf(0))),
                    Stmt::Return(Expr::Deref(Box::new(Expr::Var(1)))),
                ],
            }],
        };

        let (core, _fabric) = run_program(&prog);
        assert_eq!(core.r[R0 as usize], 42);
        eprintln!("P12: *p = {} ✓", core.r[R0 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // P13: pointer write-through
    //   int main() { int x=0; int *p=&x; *p=99; return x; }
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p13_pointer_write() {
        // Variables: 0=x, 1=p
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int), (1, Type::Ptr(Box::new(Type::Int)))],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(0))),
                    Stmt::VarDecl(1, Type::Ptr(Box::new(Type::Int)),
                        Some(Expr::AddrOf(0))),
                    Stmt::Expr(Expr::DerefAssign(
                        Box::new(Expr::Var(1)),
                        Box::new(Expr::IntLit(99)),
                    )),
                    Stmt::Return(Expr::Var(0)),
                ],
            }],
        };

        let (core, _fabric) = run_program(&prog);
        assert_eq!(core.r[R0 as usize], 99);
        eprintln!("P13: *p=99, x={} ✓", core.r[R0 as usize]);
    }

    // ═══════════════════════════════════════════════════════════
    // Scratch-register depth check
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn scratch_depth_safe_at_3() {
        // And(Le(a, b), Le(c, d)) needs 3 scratch registers.
        // This must compile without panic.
        let expr = Expr::BinOp(BinOp::And,
            Box::new(Expr::BinOp(BinOp::Le,
                Box::new(Expr::IntLit(48)),
                Box::new(Expr::Var(0)),
            )),
            Box::new(Expr::BinOp(BinOp::Le,
                Box::new(Expr::Var(0)),
                Box::new(Expr::IntLit(57)),
            )),
        );
        assert_eq!(scratch_regs(&expr), 3);
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int)],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(50))),
                    Stmt::Return(expr),
                ],
            }],
        };
        let _asm = compile(&prog);
        eprintln!("scratch_depth: depth=3 accepted ✓");
    }

    #[test]
    #[should_panic(expected = "scratch registers")]
    fn scratch_depth_rejects_4() {
        // Or(And(Le, Le), And(Le, Le)) needs 4 scratch registers.
        // This is the expression that caused the R5 clobbering bug.
        let expr = Expr::BinOp(BinOp::Or,
            Box::new(Expr::BinOp(BinOp::And,
                Box::new(Expr::BinOp(BinOp::Le,
                    Box::new(Expr::IntLit(97)),
                    Box::new(Expr::Var(0)),
                )),
                Box::new(Expr::BinOp(BinOp::Le,
                    Box::new(Expr::Var(0)),
                    Box::new(Expr::IntLit(122)),
                )),
            )),
            Box::new(Expr::BinOp(BinOp::And,
                Box::new(Expr::BinOp(BinOp::Le,
                    Box::new(Expr::IntLit(48)),
                    Box::new(Expr::Var(0)),
                )),
                Box::new(Expr::BinOp(BinOp::Le,
                    Box::new(Expr::Var(0)),
                    Box::new(Expr::IntLit(57)),
                )),
            )),
        );
        assert_eq!(scratch_regs(&expr), 4);
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int)],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(50))),
                    Stmt::Return(expr),
                ],
            }],
        };
        compile(&prog); // must panic
    }

    // ═══════════════════════════════════════════════════════════
    // Return-coverage check
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn returns_coverage_accepted() {
        // A non-void function with Return on every path compiles.
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int)],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(1))),
                    Stmt::If(
                        Expr::Var(0),
                        vec![Stmt::Return(Expr::IntLit(1))],
                        vec![Stmt::Return(Expr::IntLit(0))],
                    ),
                ],
            }],
        };
        let _asm = compile(&prog);
        eprintln!("definitely_returns: If with both arms returning → accepted ✓");
    }

    #[test]
    #[should_panic(expected = "fall-through path")]
    fn returns_coverage_rejects_missing() {
        // A non-void function without Return on every path is rejected.
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![],
                body: vec![
                    Stmt::Expr(Expr::IntLit(42)),
                ],
            }],
        };
        compile(&prog); // must panic: no Return
    }

    #[test]
    #[should_panic(expected = "fall-through path")]
    fn returns_coverage_rejects_one_arm() {
        // If with Return only in the then-branch is rejected.
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![(0, Type::Int)],
                body: vec![
                    Stmt::VarDecl(0, Type::Int, Some(Expr::IntLit(1))),
                    Stmt::If(
                        Expr::Var(0),
                        vec![Stmt::Return(Expr::IntLit(1))],
                        vec![], // no Return in else
                    ),
                ],
            }],
        };
        compile(&prog); // must panic
    }

    #[test]
    fn returns_void_no_check() {
        // A void function is allowed to fall through.
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Void,
                locals: vec![],
                body: vec![
                    Stmt::Expr(Expr::IntLit(0)),
                ],
            }],
        };
        let _asm = compile(&prog);
        eprintln!("definitely_returns: Void function → no check ✓");
    }

    /// Compiler rejects positive overflow: 131072 does not fit imm18.
    #[test]
    #[should_panic(expected = "does not fit signed 18-bit immediate")]
    fn cc_reject_positive_overflow() {
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![],
                body: vec![
                    Stmt::Return(Expr::IntLit(131072)),
                ],
            }],
        };
        let _asm = compile(&prog);
    }

    /// Compiler rejects negative overflow: -131073 does not fit imm18.
    #[test]
    #[should_panic(expected = "does not fit signed 18-bit immediate")]
    fn cc_reject_negative_overflow() {
        let prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![],
                body: vec![
                    Stmt::Return(Expr::IntLit(-131073)),
                ],
            }],
        };
        let _asm = compile(&prog);
    }
}

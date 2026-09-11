//! AnkaCC₆₄ — minimal C compiler targeting Anka64.
//!
//! C source → AST → Anka64 Asm64 code.
//!
//! This compiler exists to be a demanding client of the ISA.
//! It emits only instructions that exist in desc::INSNS.
//! If it needs an instruction that doesn't exist, the ISA
//! must grow through the description — not the other way around.
//!
//! Calling convention (Anka64 ABI v0.1):
//!   R0–R3   : arguments / return value (R0 = first arg, R0 = return)
//!   R4–R11  : caller-saved temporaries
//!   R12     : reserved
//!   R13 (FP): frame pointer (callee-saved)
//!   R14 (LR): link register (set by CALL)
//!   R15 (SP): stack pointer (callee-saved, grows downward)

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
        // Emit _start: call main, halt
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

        // Compile body
        for stmt in &func.body {
            self.compile_stmt(stmt);
        }

        // Implicit return 0 for void functions
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
                self.compile_expr(expr, R0); // result → R0
                self.emit_epilogue();
            }
            Stmt::Expr(expr) => {
                self.compile_expr(expr, R4); // discard into R4
            }
            Stmt::VarDecl(id, _ty, init) => {
                if let Some(expr) = init {
                    self.compile_expr(expr, R4);
                    let offset = self.var_offset(*id);
                    self.asm.st(R4, FP, offset);
                }
            }
            Stmt::If(cond, then_body, else_body) => {
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
                if v >= -131072 && v <= 131071 {
                    self.asm.movi(dest, v as i32);
                } else {
                    // Multi-instruction materialization for large constants
                    self.asm.movi(dest, (v & 0x3FFFF) as i32);
                    if v >> 18 != 0 && v >> 18 != -1i64 as u64 as i64 >> 18 {
                        // Need upper bits — for now, panic on huge constants
                        panic!("constant {} too large for v0.1 compiler", v);
                    }
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
                // Push arguments into R0–R3
                for (i, arg) in args.iter().enumerate() {
                    if i < 4 {
                        self.compile_expr(arg, i as u8);
                    }
                }
                // Save caller-saved registers if dest is not R0
                // (simplified: we trust the convention)
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
                // Put arguments in R1, R2, R3 (syscall ABI)
                for (i, arg) in args.iter().enumerate() {
                    if i < 3 {
                        self.compile_expr(arg, (i as u8) + 1);
                    }
                }
                self.asm.movi(R0, *num as i32);
                self.asm.trap(0);
                // After kernel handles the syscall, result is in R0
                if dest != R0 {
                    self.asm.mov(dest, R0);
                }
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
        fabric.grant(dom, text,  0, 0x4000, Permissions::RX);
        fabric.grant(dom, data,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        (fabric, text, data, stack, dom)
    }

    fn make_core(dom: DomainId, text: ObjectId, data: ObjectId, stack: ObjectId) -> Anka64Core {
        let mut core = Anka64Core::new(CPU0, dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x10000, 0x4000, data);
        core.address_map.add(0x20000, 0x4000, stack);
        // SP starts at top of stack
        core.r[SP as usize] = 0x20000 + 0x4000;
        core
    }

    fn run_program(prog: &Program) -> (Anka64Core, Fabric) {
        let (mut fabric, text, data, stack, dom) = exec_env();
        let asm = compile(prog);

        eprintln!("--- Compiled listing ---\n{}", asm.listing());

        fabric.write_physical(0x000000, &asm.to_bytes());
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
}

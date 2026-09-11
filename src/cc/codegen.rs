//! Code generator: AST → Asm builder → binary.
//!
//! Strategy: D0 is the expression accumulator.  Temporaries go on the
//! stack.  A6 is the frame pointer (LINK/UNLK).  String literals are
//! collected and emitted as a data pool after all functions.

use std::collections::HashMap;
use crate::asm::Asm;
use super::{BinOp, CcError, Expr, Function, Param, Program, Stmt, Type, UnOp};
use super::parse::Parser;

const CONSOLE_BASE: u32 = 0x00F0_0000;

// ───────────────────────────────────────────────────────────────────
// Local variable tracking
// ───────────────────────────────────────────────────────────────────

struct Local {
    offset: i16,  // negative offset from A6
    ty: Type,
}

struct FnCtx {
    locals: HashMap<String, Local>,
    frame_size: i16,
    label_seq: usize,
}

impl FnCtx {
    fn new(label_start: usize) -> Self {
        Self {
            locals: HashMap::new(),
            frame_size: 0,
            label_seq: label_start,
        }
    }

    fn alloc_local(&mut self, name: &str, ty: &Type) -> i16 {
        self.frame_size += 4; // always 4-byte aligned slots
        let offset = -self.frame_size;
        self.locals.insert(name.to_string(), Local { offset, ty: ty.clone() });
        offset
    }

    fn fresh_label(&mut self, prefix: &str) -> String {
        let n = self.label_seq;
        self.label_seq += 1;
        format!(".L{}_{}", prefix, n)
    }
}

// ───────────────────────────────────────────────────────────────────
// Code generator
// ───────────────────────────────────────────────────────────────────

struct Gen {
    asm: Asm,
    strings: Vec<(String, String)>, // (label, content)
    label_seq: usize,
    declared_fns: HashMap<String, Vec<Param>>,
}

impl Gen {
    fn new(base: u32) -> Self {
        Self {
            asm: Asm::new(base),
            strings: Vec::new(),
            label_seq: 0,
            declared_fns: HashMap::new(),
        }
    }

    fn fresh_label(&mut self, prefix: &str) -> String {
        let n = self.label_seq;
        self.label_seq += 1;
        format!(".L{}_{}", prefix, n)
    }

    // ───────────────────────────────────────────────────────────
    // Runtime prologue
    // ───────────────────────────────────────────────────────────

    fn emit_runtime(&mut self) {
        // _start: call main, then halt
        self.asm.label("_start");
        self.asm.bsr("_main");
        self.asm.stop(0x2700);

        // _putchar: write D0 byte to console
        self.asm.label("_putchar");
        // MOVE.B D0, $00F00000 (absolute long dest)
        self.asm.emit(0x13C0); // MOVE.B D0, xxx.L
        self.asm.emit((CONSOLE_BASE >> 16) as u16);
        self.asm.emit(CONSOLE_BASE as u16);
        self.asm.rts();
    }

    // ───────────────────────────────────────────────────────────
    // Functions
    // ───────────────────────────────────────────────────────────

    fn gen_function(&mut self, func: &Function) {
        // Record declaration for call-site argument routing
        self.declared_fns.insert(func.name.clone(), func.params.clone());

        let body = match &func.body {
            Some(b) => b,
            None => return, // forward declaration only
        };

        let mut ctx = FnCtx::new(self.label_seq);

        // Allocate slots for parameters (spilled from registers)
        for p in &func.params {
            ctx.alloc_local(&p.name, &p.ty);
        }

        // Pre-scan body for local variable declarations to size the frame
        Self::prescan_locals(body, &mut ctx);

        // Now emit code
        let fn_label = format!("_{}", func.name);
        self.asm.label(&fn_label);

        // Prologue: set up frame
        self.asm.link(6, -ctx.frame_size);

        // Spill parameters from registers to frame
        self.spill_params(&func.params, &ctx);

        // Generate body
        let ret_label = ctx.fresh_label("ret");
        for stmt in body {
            self.gen_stmt(stmt, &mut ctx, &ret_label);
        }

        // Epilogue
        self.asm.label(&ret_label);
        self.asm.unlk(6);
        self.asm.rts();

        self.label_seq = ctx.label_seq;
    }

    fn prescan_locals(stmts: &[Stmt], ctx: &mut FnCtx) {
        for s in stmts {
            match s {
                Stmt::VarDecl(ty, name, _) => { ctx.alloc_local(name, ty); }
                Stmt::Block(inner) => Self::prescan_locals(inner, ctx),
                Stmt::If(_, then, els) => {
                    if let Stmt::Block(b) = then.as_ref() { Self::prescan_locals(b, ctx); }
                    if let Some(e) = els {
                        if let Stmt::Block(b) = e.as_ref() { Self::prescan_locals(b, ctx); }
                    }
                }
                Stmt::While(_, body) => {
                    if let Stmt::Block(b) = body.as_ref() { Self::prescan_locals(b, ctx); }
                }
                _ => {}
            }
        }
    }

    fn spill_params(&mut self, params: &[Param], ctx: &FnCtx) {
        let mut di = 0u8; // data reg index (D0, D1)
        let mut ai = 0u8; // addr reg index (A0, A1)

        for p in params {
            let local = ctx.locals.get(&p.name).unwrap();
            if p.ty.is_ptr() {
                if ai < 2 {
                    // Param arrived in A0 or A1 — store to frame
                    // MOVE.L An, d(A6): need specific encoding
                    let an = ai;
                    // Use emit for MOVE.L An, d(A6)
                    // 0010 A6(3) 101 001 An(3)
                    let opword: u16 = 0x2D48 | an as u16;
                    self.asm.emit(opword);
                    self.asm.emit(local.offset as u16);
                    ai += 1;
                }
            } else {
                if di < 2 {
                    self.asm.move_l_dn_disp(di, local.offset, 6);
                    di += 1;
                }
            }
        }
    }

    // ───────────────────────────────────────────────────────────
    // Statements
    // ───────────────────────────────────────────────────────────

    fn gen_stmt(&mut self, stmt: &Stmt, ctx: &mut FnCtx, ret_label: &str) {
        match stmt {
            Stmt::Return(expr) => {
                if let Some(e) = expr {
                    self.gen_expr(e, ctx);
                }
                self.asm.bra(ret_label);
            }
            Stmt::Expr(e) => {
                self.gen_expr(e, ctx);
            }
            Stmt::Block(stmts) => {
                for s in stmts {
                    self.gen_stmt(s, ctx, ret_label);
                }
            }
            Stmt::VarDecl(_ty, name, init) => {
                if let Some(e) = init {
                    self.gen_expr(e, ctx);
                    let local = ctx.locals.get(name).unwrap();
                    self.asm.move_l_dn_disp(0, local.offset, 6); // D0 → frame
                }
            }
            Stmt::If(cond, then, els) => {
                let else_label = ctx.fresh_label("else");
                let end_label = ctx.fresh_label("endif");

                self.gen_expr(cond, ctx);
                self.asm.tst_l(0); // test D0
                if els.is_some() {
                    self.asm.beq(&else_label);
                } else {
                    self.asm.beq(&end_label);
                }

                self.gen_stmt(then, ctx, ret_label);

                if let Some(e) = els {
                    self.asm.bra(&end_label);
                    self.asm.label(&else_label);
                    self.gen_stmt(e, ctx, ret_label);
                }
                self.asm.label(&end_label);
            }
            Stmt::While(cond, body) => {
                let top = ctx.fresh_label("while");
                let end = ctx.fresh_label("wend");

                self.asm.label(&top);
                self.gen_expr(cond, ctx);
                self.asm.tst_l(0);
                self.asm.beq(&end);
                self.gen_stmt(body, ctx, ret_label);
                self.asm.bra(&top);
                self.asm.label(&end);
            }
        }
    }

    // ───────────────────────────────────────────────────────────
    // Expressions — result always in D0
    // ───────────────────────────────────────────────────────────

    fn gen_expr(&mut self, expr: &Expr, ctx: &mut FnCtx) {
        match expr {
            Expr::IntLit(v) => {
                let v = *v;
                if v >= -128 && v <= 127 {
                    self.asm.moveq(v as i8, 0);
                } else {
                    self.asm.move_l_imm(v as u32, 0);
                }
            }

            Expr::StrLit(s) => {
                let lbl = self.fresh_label("str");
                self.strings.push((lbl.clone(), s.clone()));
                // Load string address into A0, then MOVEA A0 → ...
                // For expressions, we put the address in D0
                // Actually: LEA label, A0; MOVE.L A0, D0
                self.asm.lea_label(&lbl, 0);
                self.asm.move_l_an_dn(0, 0); // MOVE.L A0, D0
            }

            Expr::Var(name) => {
                if let Some(local) = ctx.locals.get(name) {
                    self.asm.move_l_disp_dn(local.offset, 6, 0); // d(A6) → D0
                } else {
                    // Global or function address — treat as error for now
                    // (could be a function pointer)
                }
            }

            Expr::Assign(name, rhs) => {
                self.gen_expr(rhs, ctx);
                if let Some(local) = ctx.locals.get(name) {
                    self.asm.move_l_dn_disp(0, local.offset, 6);
                }
            }

            Expr::PostInc(name) => {
                // Load old value into D0, then increment in memory
                if let Some(local) = ctx.locals.get(name) {
                    let off = local.offset;
                    let ty = local.ty.clone();
                    self.asm.move_l_disp_dn(off, 6, 0); // old value → D0
                    self.asm.push_l(0);                   // save old value
                    self.asm.move_l_disp_dn(off, 6, 0);
                    self.asm.addq_l(if ty.is_ptr() { 1 } else { 1 }, 0);
                    self.asm.move_l_dn_disp(0, off, 6);  // store incremented
                    self.asm.pop_l(0);                    // restore old value
                }
            }

            Expr::Binary(op, lhs, rhs) => {
                self.gen_expr(lhs, ctx);     // lhs → D0
                self.asm.push_l(0);          // save lhs
                self.gen_expr(rhs, ctx);     // rhs → D0
                self.asm.move_l_dn_dn(0, 1); // rhs → D1
                self.asm.pop_l(0);           // lhs → D0

                match op {
                    BinOp::Add => self.asm.add_l_dn(1, 0),
                    BinOp::Sub => self.asm.sub_l_dn(1, 0),
                    BinOp::Mul => {
                        // MULS.W D1, D0 (16×16→32)
                        self.asm.muls_dn(1, 0);
                    }
                    BinOp::Div => {
                        // DIVS.W D1, D0 (32÷16→16q:16r)
                        self.asm.divs_dn(1, 0);
                        self.asm.ext_w(0); // sign-extend quotient
                        self.asm.ext_l(0);
                    }
                    BinOp::Mod => {
                        self.asm.divs_dn(1, 0);
                        self.asm.swap(0); // remainder is in high word
                        self.asm.ext_w(0);
                        self.asm.ext_l(0);
                    }
                    BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Gt
                    | BinOp::Le | BinOp::Ge => {
                        self.gen_compare(*op, ctx);
                    }
                    BinOp::And => {
                        // Logical AND: already evaluated both sides
                        // (short-circuit would be better, but v0 is simple)
                        self.asm.tst_l(0); // test D0
                        let z1 = ctx.fresh_label("and0");
                        let end = ctx.fresh_label("andE");
                        self.asm.beq(&z1);
                        self.asm.tst_l(1);
                        self.asm.beq(&z1);
                        self.asm.moveq(1, 0);
                        self.asm.bra(&end);
                        self.asm.label(&z1);
                        self.asm.moveq(0, 0);
                        self.asm.label(&end);
                    }
                    BinOp::Or => {
                        let nz = ctx.fresh_label("or1");
                        let end = ctx.fresh_label("orE");
                        self.asm.tst_l(0);
                        self.asm.bne(&nz);
                        self.asm.tst_l(1);
                        self.asm.bne(&nz);
                        self.asm.moveq(0, 0);
                        self.asm.bra(&end);
                        self.asm.label(&nz);
                        self.asm.moveq(1, 0);
                        self.asm.label(&end);
                    }
                }
            }

            Expr::Unary(op, inner) => {
                self.gen_expr(inner, ctx);
                match op {
                    UnOp::Neg => self.asm.neg_l(0),
                    UnOp::Not => {
                        // !x = (x == 0) ? 1 : 0
                        self.asm.tst_l(0);
                        let lbl_z = ctx.fresh_label("notz");
                        let lbl_e = ctx.fresh_label("notE");
                        self.asm.beq(&lbl_z);
                        self.asm.moveq(0, 0);
                        self.asm.bra(&lbl_e);
                        self.asm.label(&lbl_z);
                        self.asm.moveq(1, 0);
                        self.asm.label(&lbl_e);
                    }
                    UnOp::Deref => {
                        // D0 has pointer → read byte at that address
                        // MOVEA.L D0, A0; MOVE.B (A0), D0
                        self.asm.movea_l_dn(0, 0);
                        self.asm.move_b_indirect_dn(0, 0);
                        // Zero-extend byte in D0
                        self.asm.emit(0x0280); // ANDI.L #$FF, D0
                        self.asm.emit(0x0000);
                        self.asm.emit(0x00FF);
                    }
                    UnOp::AddrOf => {
                        // &var — the inner should be a Var
                        // We already generated code to load the value;
                        // what we actually want is the address.
                        // This is a v0 limitation: we overwrite D0 with
                        // the address using LEA.
                        // For proper handling, we'd need to detect this
                        // at a higher level.  For now, just ignore the
                        // value load and compute the address.
                        // This won't work perfectly, but it's a placeholder.
                    }
                }
            }

            Expr::Call(name, args) => {
                self.gen_call(name, args, ctx);
            }
        }
    }

    fn gen_compare(&mut self, op: BinOp, ctx: &mut FnCtx) {
        // After binary setup: D0=lhs, D1=rhs
        // CMP.L D1, D0 sets flags from D0 - D1
        self.asm.cmp_l_dn(1, 0);
        let set_true = ctx.fresh_label("cmpT");
        let end = ctx.fresh_label("cmpE");

        match op {
            BinOp::Eq => self.asm.beq(&set_true),
            BinOp::Ne => self.asm.bne(&set_true),
            BinOp::Lt => self.asm.blt(&set_true),
            BinOp::Gt => self.asm.bgt(&set_true),
            BinOp::Le => self.asm.ble(&set_true),
            BinOp::Ge => self.asm.bge(&set_true),
            _ => unreachable!(),
        }
        self.asm.moveq(0, 0);
        self.asm.bra(&end);
        self.asm.label(&set_true);
        self.asm.moveq(1, 0);
        self.asm.label(&end);
    }

    // ───────────────────────────────────────────────────────────
    // Function calls (ACC v0)
    // ───────────────────────────────────────────────────────────

    fn gen_call(&mut self, name: &str, args: &[Expr], ctx: &mut FnCtx) {
        // Evaluate all arguments, push onto stack
        for arg in args {
            self.gen_expr(arg, ctx);
            self.asm.push_l(0);
        }

        // Pop into registers per ACC v0
        // Look up the function's parameter types
        let params = self.declared_fns.get(name).cloned().unwrap_or_default();

        let n = args.len();
        let mut di = 0u8; // next data register (D0, D1)
        let mut ai = 0u8; // next addr register (A0, A1)

        // Pop in reverse order (last arg first)
        // But we need to route by type.  For simplicity in v0:
        // pop all into D-regs or A-regs based on param type.
        // We'll do it by popping into temporaries on the stack
        // and then loading registers.

        // Simple approach: pop in reverse, route to correct register
        for i in (0..n).rev() {
            let is_ptr = params.get(i).map_or(false, |p| p.ty.is_ptr());
            if is_ptr && ai < 2 {
                self.asm.pop_a(ai);
                ai += 1;
            } else if !is_ptr && di < 2 {
                self.asm.pop_l(di);
                di += 1;
            } else {
                // Leave on stack for callee to pick up
                // (not implemented in v0 — would need stack cleanup)
            }
        }

        let fn_label = format!("_{}", name);
        self.asm.bsr(&fn_label);
    }

    // ───────────────────────────────────────────────────────────
    // String literal pool
    // ───────────────────────────────────────────────────────────

    fn emit_strings(&mut self) {
        for (label, content) in &self.strings {
            self.asm.label(label);
            self.asm.ascii_z(content);
        }
    }

    // ───────────────────────────────────────────────────────────
    // Top-level compile
    // ───────────────────────────────────────────────────────────

    fn generate(mut self, prog: &Program) -> Vec<u8> {
        self.emit_runtime();

        // Register all function declarations for call-site routing
        for f in &prog.functions {
            self.declared_fns.insert(f.name.clone(), f.params.clone());
        }

        for f in &prog.functions {
            self.gen_function(f);
        }

        self.emit_strings();
        self.asm.assemble()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

/// Compile C source to a flat binary image at the given base address.
pub fn compile(source: &str, base: u32) -> Result<Vec<u8>, CcError> {
    let mut parser = Parser::new(source)?;
    let program = parser.parse_program()?;
    let cg = Gen::new(base);
    Ok(cg.generate(&program))
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{Bus, FlatBus};
    use crate::cpu::Cpu;

    fn run_program(source: &str) -> Cpu<FlatBus> {
        let binary = compile(source, 0x1000).expect("compilation failed");
        let mut bus = FlatBus::new_16mb();
        bus.write32(0x000000, 0x0010_0000); // SSP
        bus.write32(0x000004, 0x0000_1000); // PC = _start
        bus.load(0x1000, &binary);

        let mut cpu = Cpu::new(bus);
        let mut steps = 0u64;
        while !cpu.halted && steps < 100_000 {
            cpu.step();
            steps += 1;
        }
        assert!(cpu.halted, "CPU did not halt after {} steps", steps);
        cpu
    }

    #[test]
    fn return_42() {
        let cpu = run_program("int main() { return 42; }");
        assert_eq!(cpu.d[0], 42);
    }

    #[test]
    fn return_addition() {
        let cpu = run_program("int main() { return 40 + 2; }");
        assert_eq!(cpu.d[0], 42);
    }

    #[test]
    fn return_complex_expr() {
        let cpu = run_program("int main() { return (10 + 20) * 2 - 8; }");
        // (10+20)*2-8 = 30*2-8 = 60-8 = 52
        assert_eq!(cpu.d[0], 52);
    }

    #[test]
    fn function_call() {
        let source = "\
int add(int a, int b) { return a + b; }
int main() { return add(40, 2); }";
        let cpu = run_program(source);
        assert_eq!(cpu.d[0], 42);
    }

    #[test]
    fn if_statement() {
        let source = "\
int main() {
    int x = 10;
    if (x == 10) {
        return 42;
    }
    return 0;
}";
        let cpu = run_program(source);
        assert_eq!(cpu.d[0], 42);
    }

    #[test]
    fn while_loop() {
        let source = "\
int main() {
    int i = 0;
    int sum = 0;
    while (i < 10) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}";
        let cpu = run_program(source);
        // 0+1+2+...+9 = 45
        assert_eq!(cpu.d[0], 45);
    }
}

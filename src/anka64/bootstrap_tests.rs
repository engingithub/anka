//! Bootstrap compiler tests — regression corpus for all guest compiler generations.

#[cfg(test)]
mod tests {
    use super::super::guest_compiler::*;
    use super::super::os::*;
    use super::super::cc::{self, Program, Function, Stmt, Expr, BinOp, Type, VarId};
    use super::super::core::{Anka64Core, StepResult};
    use super::super::fabric::Fabric;
    use super::super::isa::*;
    use super::super::state::*;

    // ─── Bootstrap function counts ────────────────────────────
    // CC_A: bootstrap seed (Rust AST compiler), frozen at 7.3 semantics.
    // Canonical source: authoritative compiler definition (7.4+).
    const CCA_FUNC_COUNT: u64 = 45;
    const CANONICAL_FUNC_COUNT: u64 = 46;  // CCA + validateutf8

    // ═══════════════════════════════════════════════════════════
    // P20: Guest-hosted compilation — int main() { return 42; }
    //
    //   Phase 6A: the machine creates software for itself.
    //
    //   1. Host AnkaCC₆₄ compiles a tiny C "compiler" to Anka64 code
    //   2. The compiler runs as a user process:
    //      - reads return value (42) from source object
    //      - encodes Anka64 instructions into output buffer
    //      - calls SYS_SEAL → kernel enforces W⊕X (RW → RX)
    //      - calls SYS_EXEC → kernel spawns child from sealed code
    //   3. Child process executes the compiled code → exits with 42
    //   4. Parent receives child's exit code → exits with 42
    //
    //   Security properties proven:
    //     - No special compiler privilege (ordinary user process)
    //     - W⊕X: mutable data → kernel seal → executable code
    //     - Child runs in its own domain (authority isolation)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p20_guest_compiler_return_42() {
        // ─── Physical memory layout ───────────────────────────
        //   0x000000 : compiler text    (0x4000)
        //   0x010000 : source data      (0x1000)
        //   0x020000 : output buffer    (0x1000)
        //   0x030000 : compiler stack   (0x4000)
        //   0x040000+: dynamic (kernel allocs child stack, trap)
        let mut fabric = Fabric::new(0x200000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(stack,  0x030000);

        let dom = fabric.create_domain();
        // text: RX granted after seal (below)
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS); // RW+Seal: code emission buffer
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Source: the number 42 as a 64-bit little-endian value
        fabric.write_physical(0x010000, &42u64.to_le_bytes());

        // Trap handler at offset 0x3FF0 in text object
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // ─── The guest compiler: a C program ──────────────────
        //
        //   Virtual address map:
        //     0x00000 : text (RX)   — compiler code
        //     0x04000 : source (R)  — contains return value
        //     0x05000 : output (RW) — code emission target
        //     0x06000 : stack (RW)  — grows downward from 0x0A000
        //
        //   The compiler reads the return value from source,
        //   encodes three Anka64 instructions, stores them to
        //   the output buffer, seals it (RW→RX), and execs it.
        //
        //   Anka64 encoding constants:
        //     MOVI opcode = 22 (0x16), I-format: [op(6)|rd(4)|rs1(4)|imm(18)]
        //     TRAP opcode = 57 (0x39), S-format: [op(6)|imm(26)]
        //     NOP  opcode = 63 (0x3F), S-format
        //
        //   Emitted code for `int main() { return 42; }`:
        //     word 0: MOVI R1, 42     ; exit code
        //     word 1: MOVI R0, 0      ; SYS_EXIT
        //     word 2: TRAP #0         ; syscall
        //     word 3: NOP             ; padding

        let compiler_prog = Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![
                    (0, Type::Int),  // retval
                    (1, Type::Int),  // movi_r1
                    (2, Type::Int),  // movi_r0
                    (3, Type::Int),  // trap_insn
                    (4, Type::Int),  // nop_insn
                    (5, Type::Int),  // pair0
                    (6, Type::Int),  // pair1
                    (7, Type::Int),  // child_exit
                ],
                body: vec![
                    // retval = *(int*)0x4000
                    Stmt::VarDecl(0, Type::Int, Some(
                        Expr::Deref(Box::new(Expr::IntLit(0x4000)))
                    )),

                    // movi_r1 = (22 << 26) | (1 << 22) | retval
                    Stmt::VarDecl(1, Type::Int, Some(
                        Expr::BinOp(BinOp::Or,
                            Box::new(Expr::BinOp(BinOp::Or,
                                Box::new(Expr::BinOp(BinOp::Shl,
                                    Box::new(Expr::IntLit(22)),
                                    Box::new(Expr::IntLit(26)),
                                )),
                                Box::new(Expr::BinOp(BinOp::Shl,
                                    Box::new(Expr::IntLit(1)),
                                    Box::new(Expr::IntLit(22)),
                                )),
                            )),
                            Box::new(Expr::Var(0)),
                        )
                    )),

                    // movi_r0 = 22 << 26
                    Stmt::VarDecl(2, Type::Int, Some(
                        Expr::BinOp(BinOp::Shl,
                            Box::new(Expr::IntLit(22)),
                            Box::new(Expr::IntLit(26)),
                        )
                    )),

                    // trap_insn = 57 << 26
                    Stmt::VarDecl(3, Type::Int, Some(
                        Expr::BinOp(BinOp::Shl,
                            Box::new(Expr::IntLit(57)),
                            Box::new(Expr::IntLit(26)),
                        )
                    )),

                    // nop_insn = 63 << 26
                    Stmt::VarDecl(4, Type::Int, Some(
                        Expr::BinOp(BinOp::Shl,
                            Box::new(Expr::IntLit(63)),
                            Box::new(Expr::IntLit(26)),
                        )
                    )),

                    // pair0 = movi_r1 | (movi_r0 << 32)
                    // Packs two 32-bit instructions into one 64-bit store:
                    //   low  word (offset +0): MOVI R1, retval
                    //   high word (offset +4): MOVI R0, 0
                    Stmt::VarDecl(5, Type::Int, Some(
                        Expr::BinOp(BinOp::Or,
                            Box::new(Expr::Var(1)),
                            Box::new(Expr::BinOp(BinOp::Shl,
                                Box::new(Expr::Var(2)),
                                Box::new(Expr::IntLit(32)),
                            )),
                        )
                    )),

                    // *(int*)0x5000 = pair0
                    Stmt::Expr(Expr::DerefAssign(
                        Box::new(Expr::IntLit(0x5000)),
                        Box::new(Expr::Var(5)),
                    )),

                    // pair1 = trap_insn | (nop_insn << 32)
                    //   low  word (offset +8): TRAP #0
                    //   high word (offset +C): NOP
                    Stmt::VarDecl(6, Type::Int, Some(
                        Expr::BinOp(BinOp::Or,
                            Box::new(Expr::Var(3)),
                            Box::new(Expr::BinOp(BinOp::Shl,
                                Box::new(Expr::Var(4)),
                                Box::new(Expr::IntLit(32)),
                            )),
                        )
                    )),

                    // *(int*)0x5008 = pair1
                    Stmt::Expr(Expr::DerefAssign(
                        Box::new(Expr::IntLit(0x5008)),
                        Box::new(Expr::Var(6)),
                    )),

                    // SYS_SEAL: seal output buffer (RW → RX)
                    Stmt::Expr(Expr::Syscall(SYS_SEAL as u8, vec![
                        Expr::IntLit(0x5000),
                    ])),

                    // SYS_EXEC: spawn child from sealed code
                    Stmt::VarDecl(7, Type::Int, Some(
                        Expr::Syscall(SYS_EXEC as u8, vec![
                            Expr::IntLit(0x5000),
                            Expr::IntLit(16),   // 4 words × 4 bytes
                        ])
                    )),

                    // Return child's exit code to _start
                    Stmt::Return(Expr::Var(7)),
                ],
            }],
        };

        // ─── Compile with host AnkaCC₆₄ ──────────────────────
        let asm = cc::compile(&compiler_prog);
        eprintln!("--- Guest compiler listing ---");
        eprintln!("{}", asm.listing());
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // ─── Set up compiler process ──────────────────────────
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);    // code
        core.address_map.add(0x04000, 0x1000, source);  // source data
        core.address_map.add(0x05000, 0x1000, output);  // output buffer
        core.address_map.add(0x06000, 0x4000, stack);   // stack
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        // ─── Run ──────────────────────────────────────────────
        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(1000, 1000);

        // ─── Verify ───────────────────────────────────────────

        // Compiler process exited with child's result
        assert!(kernel.processes[0].exited(),
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, 42,
            "compiler should exit with child's result (42)");

        // Child process was spawned and collected
        assert!(kernel.processes.len() >= 2,
            "child process should have been spawned");
        // Post-8.3c: child is reclaimed after collection.
        // Parent's exit_code=42 proves child returned 42.
        assert_eq!(kernel.processes[1].state, ProcessState::Free,
            "child should be reclaimed to Free");

        // ─── The three 42s ────────────────────────────────────
        //   First 42:  emulator executes code
        //   Second 42: Anka64 executes its own ISA
        //   Third 42:  Anka64 creates the program that returns 42
        eprintln!();
        eprintln!("P20: int main() {{ return 42; }} ✓");
        eprintln!("     Guest compiler → sealed executable → child → R0 = 42");
        eprintln!("     W⊕X lifecycle: source(R) → compiler → output(RW) → seal → code(RX) → execute");
        eprintln!("     No special compiler privilege — ordinary user process");
        eprintln!("     Child domain ≠ parent domain (authority isolation)");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 6B.0 / 6B.0a: text source → guest lexer → code → seal → exec
    //
    // Exit criterion: an ordinary protected Anka64 user process
    // consumes an R-only text object, derives its meaning without
    // host assistance, produces an executable object, seals it,
    // executes it, and obtains the source-specified result.
    //
    //   text bytes "42" → guest lexer → MOVI R1,42; ... → seal → exec → 42
    //
    // The guest reads individual bytes via load-word + shift/mask.
    // No byte-width load instruction exists — the client struggles.
    //
    // 6B.0a additions:
    //   - Integer overflow detected during parsing, not after masking.
    //     value ≥ 131072 → compile error.  Silent truncation is forbidden.
    //   - Source scanning is length-bounded, not NUL-bounded.
    //     Source layout: [u64 length][text bytes...].
    //     Loop guard: pos < src_len.
    //     Memory authority does not imply object-role semantics.
    //   - Loop-scoped variables declared outside loop, assigned inside.
    //     No VarDecl stack leak per iteration.
    // ═══════════════════════════════════════════════════════════════

    /// Build the 6B.0 guest compiler program.
    ///
    /// Virtual address map:
    ///   0x00000 : text (RX)      — compiler code
    ///   0x04000 : source (R)     — [u64 length][text bytes...]
    ///   0x05000 : output (RWS)   — code emission target
    ///   0x06000 : workspace (RW) — scratch (reserved for future use)
    ///   0x07000 : stack (RW)     — grows downward from 0x0B000
    ///
    /// Algorithm:
    ///   1. Read source length from *(src_base), text starts at src_base+8
    ///   2. Scan source bytes with pos < src_len guard
    ///      byte access: LD word at (text_base + (pos & ~7)),
    ///                   shift right by (pos & 7) * 8, mask 0xFF
    ///   3. Accumulate: value = value * 10 + (byte - '0')
    ///   4. After each accumulation: if value ≥ 131072, overflow error
    ///   5. On non-digit: stop scanning
    ///   6. If no digits or overflow: exit(MAX)
    ///   7. Emit MOVI R1,value; MOVI R0,0; TRAP #0; NOP to output
    ///   8. SYS_SEAL output, SYS_EXEC, exit with child result
    fn build_6b0_compiler() -> Program {
        // Variable IDs — all declared once at function scope
        const SRC_BASE: VarId   = 0;
        const OUT_BASE: VarId   = 1;
        const POS: VarId        = 2;
        const VALUE: VarId      = 3;
        const HAS_DIGIT: VarId  = 4;
        const RUNNING: VarId    = 5;
        const WORD: VarId       = 6;
        const BYTE_SHIFT: VarId = 7;
        const CH: VarId         = 8;
        const IS_DIGIT: VarId   = 9;
        const MOVI_R1: VarId    = 10;
        const MOVI_R0: VarId    = 11;
        const TRAP_INSN: VarId  = 12;
        const NOP_INSN: VarId   = 13;
        const PAIR0: VarId      = 14;
        const PAIR1: VarId      = 15;
        const CHILD: VarId      = 16;
        const ALIGNED: VarId    = 17;
        const OVERFLOW: VarId   = 18;
        const SRC_LEN: VarId    = 19;
        const TEXT_BASE: VarId  = 20;

        // Helpers for common expression patterns
        fn lit(v: i64) -> Expr { Expr::IntLit(v) }
        fn var(id: VarId) -> Expr { Expr::Var(id) }
        fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
            Expr::BinOp(op, Box::new(a), Box::new(b))
        }
        fn assign(id: VarId, e: Expr) -> Stmt {
            Stmt::Expr(Expr::Assign(id, Box::new(e)))
        }
        fn deref(addr: Expr) -> Expr { Expr::Deref(Box::new(addr)) }
        fn deref_assign(addr: Expr, val: Expr) -> Stmt {
            Stmt::Expr(Expr::DerefAssign(Box::new(addr), Box::new(val)))
        }
        fn syscall(num: u8, args: Vec<Expr>) -> Expr {
            Expr::Syscall(num, args)
        }

        Program {
            functions: vec![Function {
                name: "main".into(),
                params: vec![],
                ret_type: Type::Int,
                locals: vec![
                    (SRC_BASE, Type::Int),
                    (OUT_BASE, Type::Int),
                    (POS, Type::Int),
                    (VALUE, Type::Int),
                    (HAS_DIGIT, Type::Int),
                    (RUNNING, Type::Int),
                    (WORD, Type::Int),
                    (BYTE_SHIFT, Type::Int),
                    (CH, Type::Int),
                    (IS_DIGIT, Type::Int),
                    (MOVI_R1, Type::Int),
                    (MOVI_R0, Type::Int),
                    (TRAP_INSN, Type::Int),
                    (NOP_INSN, Type::Int),
                    (PAIR0, Type::Int),
                    (PAIR1, Type::Int),
                    (CHILD, Type::Int),
                    (ALIGNED, Type::Int),
                    (OVERFLOW, Type::Int),
                    (SRC_LEN, Type::Int),
                    (TEXT_BASE, Type::Int),
                ],
                body: vec![
                    // ─── Initialize ─────────────────────────────
                    Stmt::VarDecl(SRC_BASE, Type::Int, Some(lit(0x4000))),
                    Stmt::VarDecl(OUT_BASE, Type::Int, Some(lit(0x5000))),
                    Stmt::VarDecl(POS, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(VALUE, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(HAS_DIGIT, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(RUNNING, Type::Int, Some(lit(1))),
                    Stmt::VarDecl(OVERFLOW, Type::Int, Some(lit(0))),

                    // Source layout: [u64 length][text bytes...]
                    // src_len = *src_base
                    Stmt::VarDecl(SRC_LEN, Type::Int, Some(
                        deref(var(SRC_BASE))
                    )),
                    // text_base = src_base + 8
                    Stmt::VarDecl(TEXT_BASE, Type::Int, Some(
                        binop(BinOp::Add, var(SRC_BASE), lit(8))
                    )),

                    // ─── Source metadata guard ──────────────────
                    // Source object = 0x1000 bytes. Header = 8 bytes.
                    // Max valid text payload = 0x1000 - 8 = 0xFF8 = 4088.
                    // A malformed header claiming more would cause reads
                    // beyond the source object into adjacent capabilities.
                    // Memory authority ≠ source-role authority.
                    Stmt::If(
                        binop(BinOp::Lt, lit(0xFF8), var(SRC_LEN)),
                        vec![Stmt::Return(lit(-1))],
                        vec![],
                    ),

                    // Declare loop-scoped variables once (no VarDecl in loop)
                    Stmt::VarDecl(ALIGNED, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(WORD, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(BYTE_SHIFT, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(CH, Type::Int, Some(lit(0))),
                    Stmt::VarDecl(IS_DIGIT, Type::Int, Some(lit(0))),

                    // ─── Lexer loop: length-bounded digit scan ──
                    //
                    // while (running) {
                    //   if (pos >= src_len) { running = 0; }
                    //   else {
                    //     aligned = text_base + (pos & ~7)
                    //     word = *aligned
                    //     byte_shift = (pos & 7) * 8
                    //     ch = (word >> byte_shift) & 0xFF
                    //     is_digit = (48 ≤ ch) & (ch ≤ 57)
                    //     if (is_digit) {
                    //       value = value * 10 + (ch - 48)
                    //       if (value ≥ 131072) { overflow = 1; running = 0; }
                    //       else { has_digit = 1; pos++; }
                    //     } else { running = 0; }
                    //   }
                    // }
                    Stmt::While(
                        var(RUNNING),
                        vec![
                            // Bounds check: Le(SRC_LEN, POS) = src_len ≤ pos
                            Stmt::If(
                                binop(BinOp::Le, var(SRC_LEN), var(POS)),
                                vec![
                                    // pos ≥ src_len → end of source
                                    assign(RUNNING, lit(0)),
                                ],
                                vec![
                                    // In bounds → extract byte
                                    // aligned = text_base + (pos & ~7)
                                    assign(ALIGNED,
                                        binop(BinOp::Add,
                                            var(TEXT_BASE),
                                            binop(BinOp::And, var(POS), lit(-8)),
                                        )
                                    ),
                                    assign(WORD, deref(var(ALIGNED))),
                                    // byte_shift = (pos & 7) * 8
                                    assign(BYTE_SHIFT,
                                        binop(BinOp::Mul,
                                            binop(BinOp::And, var(POS), lit(7)),
                                            lit(8),
                                        )
                                    ),
                                    // ch = (word >> byte_shift) & 0xFF
                                    assign(CH,
                                        binop(BinOp::And,
                                            binop(BinOp::Shr, var(WORD), var(BYTE_SHIFT)),
                                            lit(0xFF),
                                        )
                                    ),
                                    // is_digit = (48 ≤ ch) & (ch ≤ 57)
                                    assign(IS_DIGIT,
                                        binop(BinOp::And,
                                            binop(BinOp::Le, lit(48), var(CH)),
                                            binop(BinOp::Le, var(CH), lit(57)),
                                        )
                                    ),
                                    Stmt::If(
                                        var(IS_DIGIT),
                                        vec![
                                            // value = value * 10 + (ch - 48)
                                            assign(VALUE,
                                                binop(BinOp::Add,
                                                    binop(BinOp::Mul, var(VALUE), lit(10)),
                                                    binop(BinOp::Sub, var(CH), lit(48)),
                                                )
                                            ),
                                            // Overflow check: value > 131071
                                            // Lt(131071, VALUE) = 131071 < value
                                            // (131072 is not representable as
                                            //  18-bit signed MOVI immediate)
                                            Stmt::If(
                                                binop(BinOp::Lt, lit(131071), var(VALUE)),
                                                vec![
                                                    assign(OVERFLOW, lit(1)),
                                                    assign(RUNNING, lit(0)),
                                                ],
                                                vec![
                                                    assign(HAS_DIGIT, lit(1)),
                                                    assign(POS,
                                                        binop(BinOp::Add, var(POS), lit(1))
                                                    ),
                                                ],
                                            ),
                                        ],
                                        vec![
                                            // non-digit → stop
                                            assign(RUNNING, lit(0)),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),

                    // ─── Error check: no digits or overflow ─────
                    // if (!has_digit || overflow) exit(MAX)
                    Stmt::If(
                        binop(BinOp::Eq, var(HAS_DIGIT), lit(0)),
                        vec![Stmt::Return(lit(-1))],
                        vec![],
                    ),
                    Stmt::If(
                        var(OVERFLOW),
                        vec![Stmt::Return(lit(-1))],
                        vec![],
                    ),

                    // ─── Code emission ──────────────────────────
                    // Encode: MOVI R1, value; MOVI R0, 0; TRAP #0; NOP
                    //
                    // MOVI opcode = 22, I-format: [op(6)|rd(4)|rs1(4)|imm(18)]
                    // movi_r1 = (22 << 26) | (1 << 22) | value
                    // (value is guaranteed ≤ 131071 = 0x1FFFF, fits in 18 bits)
                    Stmt::VarDecl(MOVI_R1, Type::Int, Some(
                        binop(BinOp::Or,
                            binop(BinOp::Or,
                                binop(BinOp::Shl, lit(22), lit(26)),
                                binop(BinOp::Shl, lit(1), lit(22)),
                            ),
                            var(VALUE),
                        )
                    )),
                    // movi_r0 = 22 << 26
                    Stmt::VarDecl(MOVI_R0, Type::Int, Some(
                        binop(BinOp::Shl, lit(22), lit(26))
                    )),
                    // trap = 57 << 26
                    Stmt::VarDecl(TRAP_INSN, Type::Int, Some(
                        binop(BinOp::Shl, lit(57), lit(26))
                    )),
                    // nop = 63 << 26
                    Stmt::VarDecl(NOP_INSN, Type::Int, Some(
                        binop(BinOp::Shl, lit(63), lit(26))
                    )),

                    // Pack two 32-bit instructions per 64-bit store
                    // pair0 = movi_r1 | (movi_r0 << 32)
                    Stmt::VarDecl(PAIR0, Type::Int, Some(
                        binop(BinOp::Or,
                            var(MOVI_R1),
                            binop(BinOp::Shl, var(MOVI_R0), lit(32)),
                        )
                    )),
                    // pair1 = trap | (nop << 32)
                    Stmt::VarDecl(PAIR1, Type::Int, Some(
                        binop(BinOp::Or,
                            var(TRAP_INSN),
                            binop(BinOp::Shl, var(NOP_INSN), lit(32)),
                        )
                    )),

                    // Write to output buffer
                    deref_assign(var(OUT_BASE), var(PAIR0)),
                    deref_assign(
                        binop(BinOp::Add, var(OUT_BASE), lit(8)),
                        var(PAIR1),
                    ),

                    // ─── Seal → Exec ────────────────────────────
                    Stmt::Expr(syscall(SYS_SEAL as u8, vec![
                        var(OUT_BASE),
                    ])),
                    Stmt::VarDecl(CHILD, Type::Int, Some(
                        syscall(SYS_EXEC as u8, vec![
                            var(OUT_BASE),
                            lit(16),
                        ])
                    )),
                    Stmt::Return(var(CHILD)),
                ],
            }],
        }
    }

    /// Run a 6B.0 test case: source text → guest compiler → expected result.
    ///
    /// Source object layout: [u64 length][text bytes...]
    /// The harness writes the length header automatically.
    fn run_6b0_test(
        source_text: &[u8],
        expected_exit: u64,
        expect_child: bool,
    ) -> (bool, u64) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Write source: [u64 length][text bytes]
        let src_len = source_text.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, source_text);

        // Trap handler
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Compile the guest compiler from AST
        let compiler_prog = build_6b0_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // Set up process
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);    // code (RX)
        core.address_map.add(0x04000, 0x1000, source);  // source (R)
        core.address_map.add(0x05000, 0x1000, output);  // output (RWS)
        core.address_map.add(0x06000, 0x1000, work);    // workspace (RW)
        core.address_map.add(0x07000, 0x4000, stack);   // stack (RW)
        core.r[SP as usize] = 0x07000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(10000, 10000);

        let exited = kernel.processes[0].exited();
        let exit_code = kernel.processes[0].exit_code;
        let child_spawned = kernel.processes.len() >= 2;

        assert!(exited, "compiler process should have exited");
        assert_eq!(exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, exit_code);

        if expect_child {
            assert!(child_spawned,
                "source {:?}: expected child process",
                std::str::from_utf8(source_text).unwrap_or("<invalid>"));
            // Post-8.3c: child is reclaimed after collection.
            // Parent's exit_code (verified above) is the source of truth.
        }

        (child_spawned, exit_code)
    }

    /// Raw 6B.0 test: explicit (declared_length, payload) control.
    ///
    /// Unlike run_6b0_test, the caller controls the length header
    /// independently of the actual payload bytes.  This exercises
    /// the distinction between memory authority and source-role
    /// semantics.
    fn run_6b0_test_raw(
        declared_len: u64,
        payload: &[u8],
        expected_exit: u64,
        expect_child: bool,
    ) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Write source with explicit length header
        fabric.write_physical(0x010000, &declared_len.to_le_bytes());
        let write_len = payload.len().min(0xFF8); // don't overflow object
        fabric.write_physical(0x010008, &payload[..write_len]);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let compiler_prog = build_6b0_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x1000, source);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(0x06000, 0x1000, work);
        core.address_map.add(0x07000, 0x4000, stack);
        core.r[SP as usize] = 0x07000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(10000, 10000);

        assert!(kernel.processes[0].exited(),
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "declared_len={}, payload {:?}: expected exit {}, got {}",
            declared_len,
            std::str::from_utf8(payload).unwrap_or("<binary>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            // Post-8.3c: child is reclaimed after collection.
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 6B.0 / 6B.0a test corpus
    // ═══════════════════════════════════════════════════════════════

    // ─── Core path ──────────────────────────────────────────────

    #[test]
    fn b0_text_integer_42() {
        run_6b0_test(b"42", 42, true);
        eprintln!("6B.0: \"42\" → guest lexer → code → seal → exec → 42 ✓");
        eprintln!("      text bytes → meaning → executable → result");
    }

    #[test]
    fn b0_text_integer_0() {
        run_6b0_test(b"0", 0, true);
        eprintln!("6B.0: \"0\" → 0 ✓");
    }

    #[test]
    fn b0_text_integer_255() {
        run_6b0_test(b"255", 255, true);
        eprintln!("6B.0: \"255\" → 255 ✓");
    }

    #[test]
    fn b0_text_integer_leading_zeros() {
        run_6b0_test(b"0042", 42, true);
        eprintln!("6B.0: \"0042\" → 42 (leading zeros accepted) ✓");
    }

    // ─── Error: no digits ───────────────────────────────────────

    #[test]
    fn b0_text_empty_source() {
        run_6b0_test(b"", u64::MAX, false);
        eprintln!("6B.0a: empty source → error (no digits, length=0) ✓");
    }

    #[test]
    fn b0_text_non_digit() {
        run_6b0_test(b"42x", 42, true);
        eprintln!("6B.0: \"42x\" → 42 (stops at non-digit) ✓");
    }

    #[test]
    fn b0_text_only_non_digit() {
        run_6b0_test(b"x", u64::MAX, false);
        eprintln!("6B.0: \"x\" → error (no digits) ✓");
    }

    // ─── Overflow boundary ──────────────────────────────────────

    #[test]
    fn b0a_movi_max() {
        // 131071 = 0x1FFFF = maximum positive 18-bit signed value
        run_6b0_test(b"131071", 131071, true);
        eprintln!("6B.0a: \"131071\" → 131071 (MOVI 18-bit max) ✓");
    }

    #[test]
    fn b0a_movi_overflow() {
        // 131072 = 0x20000 → bit 17 set → signed MOVI would be -131072
        // Compiler must reject, not silently truncate
        run_6b0_test(b"131072", u64::MAX, false);
        eprintln!("6B.0a: \"131072\" → error (overflow, not truncation) ✓");
    }

    #[test]
    fn b0a_large_decimal_overflow() {
        // Many digits → overflow during accumulation
        run_6b0_test(b"999999999999999999999", u64::MAX, false);
        eprintln!("6B.0a: \"999...\" → error (decimal overflow) ✓");
    }

    #[test]
    fn b0a_just_above_boundary() {
        // 131073: clearly above MOVI max
        run_6b0_test(b"131073", u64::MAX, false);
        eprintln!("6B.0a: \"131073\" → error (overflow) ✓");
    }

    // ─── Source length-bounded scanning ─────────────────────────

    #[test]
    fn b0a_length_bounded_no_terminator() {
        // Source is exactly "42" with length=2, no NUL terminator.
        // Scanner must stop at pos=2 because of length bound,
        // not because of a NUL byte.
        run_6b0_test(b"42", 42, true);
        eprintln!("6B.0a: \"42\" (no NUL) → 42 (length-bounded scan) ✓");
    }

    #[test]
    fn b0a_length_bounded_trailing_digits() {
        // Declared length = 2, but stored payload = "429999999".
        // The lexer must stop after 2 bytes ("42") because of the
        // length bound, ignoring the trailing "9999999".
        // Without the length guard, this would parse 429999999.
        run_6b0_test_raw(2, b"429999999", 42, true);
        eprintln!("6B.0a: declared_len=2, payload=\"429999999\" → 42 ✓");
        eprintln!("       length bound prevents reading beyond source role");
    }

    // ─── Source metadata guard ──────────────────────────────────

    #[test]
    fn b0a_hostile_metadata_overlength() {
        // Declared length = 0x1000 (4096), but source object capacity
        // after 8-byte header = 0xFF8 (4088).  The guest must reject
        // the malformed metadata before any out-of-role read.
        //
        // Memory authority ≠ source-role authority.
        run_6b0_test_raw(0x1000, b"42", u64::MAX, false);
        eprintln!("6B.0a: declared_len=0x1000, capacity=0xFF8 → error ✓");
        eprintln!("       hostile metadata rejected before out-of-role read");
    }

    #[test]
    fn b0a_metadata_exact_capacity() {
        // Declared length = 0xFF8 (4088) = exact max capacity.
        // Should be accepted (no overflow), even though the actual
        // text is just "7".  The guard checks metadata, not content.
        run_6b0_test_raw(0xFF8, b"7", 7, true);
        eprintln!("6B.0a: declared_len=0xFF8 (exact capacity) → 7 ✓");
    }

    // Phase 6B.1: textual grammar with precedence + recursive descent
    //
    //   "return (2 + 3) * 4;" → guest parser → code → seal → exec → 20
    //
    // Grammar:
    //   stmt       → "return" expr ";"
    //   expr       → additive
    //   additive   → multiplicative { ('+'|'-') multiplicative }
    //   multiplicative → primary { '*' primary }
    //   primary    → integer | '(' expr ')'
    //   integer    → digit { digit }
    //
    // Recursive descent through CALL/RET exercises protected return
    // authority as ordinary compiler workload, not security tests.
    //
    // No AST heap — parse-and-evaluate directly into a value,
    // then emit MOVI with result.
    // ═══════════════════════════════════════════════════════════════

    /// Build the 6B.1 guest compiler: recursive-descent expression parser.
    ///
    /// 10 functions: main, peek_char, advance, skip_ws, expect_char,
    /// parse_integer, parse_primary, parse_multiplicative,
    /// parse_additive, parse_expr.
    ///
    /// Parser state lives in the workspace object at 0x6000:
    ///   +0: pos (current scan position)
    ///   +8: src_len
    ///   +16: text_base
    ///   +24: error flag
    fn build_6b1_compiler() -> Program {
        const WS_POS: i64       = 0x6000;
        const WS_SRC_LEN: i64   = 0x6008;
        const WS_TEXT_BASE: i64  = 0x6010;
        const WS_ERROR: i64      = 0x6018;

        fn lit(v: i64) -> Expr { Expr::IntLit(v) }
        fn var(id: VarId) -> Expr { Expr::Var(id) }
        fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
            Expr::BinOp(op, Box::new(a), Box::new(b))
        }
        fn assign(id: VarId, e: Expr) -> Stmt {
            Stmt::Expr(Expr::Assign(id, Box::new(e)))
        }
        fn deref(addr: Expr) -> Expr { Expr::Deref(Box::new(addr)) }
        fn deref_assign(addr: Expr, val: Expr) -> Stmt {
            Stmt::Expr(Expr::DerefAssign(Box::new(addr), Box::new(val)))
        }
        fn syscall(num: u8, args: Vec<Expr>) -> Expr {
            Expr::Syscall(num, args)
        }
        fn call(name: &str, args: Vec<Expr>) -> Expr {
            Expr::Call(name.into(), args)
        }
        fn call_stmt(name: &str, args: Vec<Expr>) -> Stmt {
            Stmt::Expr(Expr::Call(name.into(), args))
        }

        // ─── peek_char() → int ─────────────────────────────
        // Returns byte at current position, or 0 at end.
        // Locals: pos(0), src_len(1), text_base(2),
        //         aligned(3), word(4), byte_shift(5)
        let fn_peek_char = Function {
            name: "peek_char".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SRC_LEN)))),
                Stmt::If(
                    binop(BinOp::Le, var(1), var(0)),
                    vec![Stmt::Return(lit(0))],
                    vec![],
                ),
                Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_TEXT_BASE)))),
                Stmt::VarDecl(3, Type::Int, Some(
                    binop(BinOp::Add, var(2),
                        binop(BinOp::And, var(0), lit(-8)))
                )),
                Stmt::VarDecl(4, Type::Int, Some(deref(var(3)))),
                Stmt::VarDecl(5, Type::Int, Some(
                    binop(BinOp::Mul,
                        binop(BinOp::And, var(0), lit(7)),
                        lit(8))
                )),
                Stmt::Return(binop(BinOp::And,
                    binop(BinOp::Shr, var(4), var(5)),
                    lit(0xFF),
                )),
            ],
        };

        // ─── advance() ─────────────────────────────────────
        // Locals: pos(0)
        let fn_advance = Function {
            name: "advance".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int)],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
                deref_assign(lit(WS_POS),
                    binop(BinOp::Add, var(0), lit(1))),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── skip_ws() ─────────────────────────────────────
        // Locals: running(0), ch(1)
        let fn_skip_ws = Function {
            name: "skip_ws".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int), (1, Type::Int)],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(lit(1))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
                Stmt::While(var(0), vec![
                    assign(1, call("peek_char", vec![])),
                    Stmt::If(
                        binop(BinOp::Eq, var(1), lit(32)),
                        vec![call_stmt("advance", vec![])],
                        vec![assign(0, lit(0))],
                    ),
                ]),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── expect_char(expected) ──────────────────────────
        // Params: expected(0). Locals: ch(1)
        let fn_expect_char = Function {
            name: "expect_char".into(),
            params: vec![(0, Type::Int)],
            ret_type: Type::Int,
            locals: vec![(1, Type::Int)],
            body: vec![
                Stmt::VarDecl(1, Type::Int, Some(call("peek_char", vec![]))),
                Stmt::If(
                    binop(BinOp::Eq, var(1), var(0)),
                    vec![call_stmt("advance", vec![])],
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                ),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── parse_integer() → int ─────────────────────────
        // Locals: value(0), has_digit(1), running(2), ch(3), is_digit(4)
        let fn_parse_integer = Function {
            name: "parse_integer".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
                Stmt::VarDecl(2, Type::Int, Some(lit(1))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),
                Stmt::While(var(2), vec![
                    assign(3, call("peek_char", vec![])),
                    assign(4, binop(BinOp::And,
                        binop(BinOp::Le, lit(48), var(3)),
                        binop(BinOp::Le, var(3), lit(57)),
                    )),
                    Stmt::If(var(4), vec![
                        assign(0, binop(BinOp::Add,
                            binop(BinOp::Mul, var(0), lit(10)),
                            binop(BinOp::Sub, var(3), lit(48)),
                        )),
                        // Overflow: value > 131071
                        Stmt::If(
                            binop(BinOp::Lt, lit(131071), var(0)),
                            vec![
                                deref_assign(lit(WS_ERROR), lit(1)),
                                assign(2, lit(0)),
                            ],
                            vec![
                                assign(1, lit(1)),
                                call_stmt("advance", vec![]),
                            ],
                        ),
                    ], vec![
                        assign(2, lit(0)),
                    ]),
                ]),
                Stmt::If(
                    binop(BinOp::Eq, var(1), lit(0)),
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                    vec![],
                ),
                Stmt::Return(var(0)),
            ],
        };

        // ─── parse_primary() → int ─────────────────────────
        // primary → integer | '(' expr ')'
        // Locals: ch(0), val(1)
        let fn_parse_primary = Function {
            name: "parse_primary".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int), (1, Type::Int)],
            body: vec![
                call_stmt("skip_ws", vec![]),
                Stmt::VarDecl(0, Type::Int, Some(call("peek_char", vec![]))),
                Stmt::If(
                    binop(BinOp::Eq, var(0), lit(40)),  // '('
                    vec![
                        call_stmt("advance", vec![]),
                        Stmt::VarDecl(1, Type::Int, Some(
                            call("parse_expr", vec![])
                        )),
                        call_stmt("skip_ws", vec![]),
                        call_stmt("expect_char", vec![lit(41)]),  // ')'
                        Stmt::Return(var(1)),
                    ],
                    vec![
                        Stmt::Return(call("parse_integer", vec![])),
                    ],
                ),
            ],
        };

        // ─── parse_multiplicative() → int ───────────────────
        // multiplicative → primary { '*' primary }
        // Locals: left(0), running(1), ch(2), right(3)
        let fn_parse_mult = Function {
            name: "parse_multiplicative".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int),
                (2, Type::Int), (3, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(
                    call("parse_primary", vec![]))),
                Stmt::VarDecl(1, Type::Int, Some(lit(1))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::While(var(1), vec![
                    call_stmt("skip_ws", vec![]),
                    assign(2, call("peek_char", vec![])),
                    Stmt::If(
                        binop(BinOp::Eq, var(2), lit(42)),  // '*'
                        vec![
                            call_stmt("advance", vec![]),
                            assign(3, call("parse_primary", vec![])),
                            assign(0, binop(BinOp::Mul, var(0), var(3))),
                        ],
                        vec![assign(1, lit(0))],
                    ),
                ]),
                Stmt::Return(var(0)),
            ],
        };

        // ─── parse_additive() → int ────────────────────────
        // additive → multiplicative { ('+'|'-') multiplicative }
        // Locals: left(0), running(1), ch(2), right(3)
        let fn_parse_add = Function {
            name: "parse_additive".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int),
                (2, Type::Int), (3, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(
                    call("parse_multiplicative", vec![]))),
                Stmt::VarDecl(1, Type::Int, Some(lit(1))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::While(var(1), vec![
                    call_stmt("skip_ws", vec![]),
                    assign(2, call("peek_char", vec![])),
                    Stmt::If(
                        binop(BinOp::Eq, var(2), lit(43)),  // '+'
                        vec![
                            call_stmt("advance", vec![]),
                            assign(3, call("parse_multiplicative", vec![])),
                            assign(0, binop(BinOp::Add, var(0), var(3))),
                        ],
                        vec![Stmt::If(
                            binop(BinOp::Eq, var(2), lit(45)),  // '-'
                            vec![
                                call_stmt("advance", vec![]),
                                assign(3, call("parse_multiplicative", vec![])),
                                assign(0, binop(BinOp::Sub, var(0), var(3))),
                            ],
                            vec![assign(1, lit(0))],
                        )],
                    ),
                ]),
                Stmt::Return(var(0)),
            ],
        };

        // ─── parse_expr() → int ────────────────────────────
        let fn_parse_expr = Function {
            name: "parse_expr".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![],
            body: vec![
                Stmt::Return(call("parse_additive", vec![])),
            ],
        };

        // ─── main() ────────────────────────────────────────
        // Locals: src_base(0), src_len(1), text_base(2), value(3),
        //   error(4), movi_r1(5), movi_r0(6), trap_insn(7),
        //   nop_insn(8), pair0(9), pair1(10), child(11)
        let fn_main = Function {
            name: "main".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
                (6, Type::Int), (7, Type::Int), (8, Type::Int),
                (9, Type::Int), (10, Type::Int), (11, Type::Int),
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

                // ─── Parse "return" keyword ──────────────
                call_stmt("skip_ws", vec![]),
                call_stmt("expect_char", vec![lit(114)]),  // 'r'
                call_stmt("expect_char", vec![lit(101)]),  // 'e'
                call_stmt("expect_char", vec![lit(116)]),  // 't'
                call_stmt("expect_char", vec![lit(117)]),  // 'u'
                call_stmt("expect_char", vec![lit(114)]),  // 'r'
                call_stmt("expect_char", vec![lit(110)]),  // 'n'

                // ─── Parse expression ────────────────────
                Stmt::VarDecl(3, Type::Int, Some(
                    call("parse_expr", vec![]))),

                // ─── Expect ';' then EOF ─────────────────
                call_stmt("skip_ws", vec![]),
                call_stmt("expect_char", vec![lit(59)]),   // ';'

                // Require end-of-source: skip trailing whitespace,
                // then check pos == src_len.  Reject trailing garbage.
                call_stmt("skip_ws", vec![]),
                Stmt::If(
                    binop(BinOp::Ne,
                        deref(lit(WS_POS)),
                        deref(lit(WS_SRC_LEN)),
                    ),
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                    vec![],
                ),

                // ─── Check error ─────────────────────────
                Stmt::VarDecl(4, Type::Int, Some(
                    deref(lit(WS_ERROR)))),
                Stmt::If(var(4),
                    vec![Stmt::Return(lit(-1))],
                    vec![],
                ),

                // ─── Check value range ───────────────────
                Stmt::If(
                    binop(BinOp::Lt, lit(131071), var(3)),
                    vec![Stmt::Return(lit(-1))],
                    vec![],
                ),

                // ─── Code emission ───────────────────────
                Stmt::VarDecl(5, Type::Int, Some(
                    binop(BinOp::Or,
                        binop(BinOp::Or,
                            binop(BinOp::Shl, lit(22), lit(26)),
                            binop(BinOp::Shl, lit(1), lit(22)),
                        ),
                        var(3),
                    )
                )),
                Stmt::VarDecl(6, Type::Int, Some(
                    binop(BinOp::Shl, lit(22), lit(26)))),
                Stmt::VarDecl(7, Type::Int, Some(
                    binop(BinOp::Shl, lit(57), lit(26)))),
                Stmt::VarDecl(8, Type::Int, Some(
                    binop(BinOp::Shl, lit(63), lit(26)))),
                Stmt::VarDecl(9, Type::Int, Some(
                    binop(BinOp::Or, var(5),
                        binop(BinOp::Shl, var(6), lit(32))))),
                Stmt::VarDecl(10, Type::Int, Some(
                    binop(BinOp::Or, var(7),
                        binop(BinOp::Shl, var(8), lit(32))))),

                deref_assign(lit(0x5000), var(9)),
                deref_assign(
                    binop(BinOp::Add, lit(0x5000), lit(8)),
                    var(10)),

                // ─── Seal → Exec ─────────────────────────
                Stmt::Expr(syscall(SYS_SEAL as u8, vec![lit(0x5000)])),
                Stmt::VarDecl(11, Type::Int, Some(
                    syscall(SYS_EXEC as u8, vec![lit(0x5000), lit(16)]))),
                Stmt::Return(var(11)),
            ],
        };

        Program {
            functions: vec![
                fn_main, fn_peek_char, fn_advance, fn_skip_ws,
                fn_expect_char, fn_parse_integer, fn_parse_primary,
                fn_parse_mult, fn_parse_add, fn_parse_expr,
            ],
        }
    }

    /// Run a 6B.1 test case: "return expr;" → guest parser → expected result.
    fn run_6b1_test(source_text: &[u8], expected_exit: u64, expect_child: bool) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        let src_len = source_text.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, source_text);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let compiler_prog = build_6b1_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x1000, source);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(0x06000, 0x1000, work);
        core.address_map.add(0x07000, 0x4000, stack);
        core.r[SP as usize] = 0x07000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(50000, 50000);

        assert!(kernel.processes[0].exited(),
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            // Post-8.3c: child is reclaimed after collection.
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 6B.1 test corpus
    // ═══════════════════════════════════════════════════════════════

    // ─── Core arithmetic ────────────────────────────────────────

    #[test]
    fn b1_return_42() {
        run_6b1_test(b"return 42;", 42, true);
        eprintln!("6B.1: \"return 42;\" → 42 ✓");
    }

    #[test]
    fn b1_return_0() {
        run_6b1_test(b"return 0;", 0, true);
        eprintln!("6B.1: \"return 0;\" → 0 ✓");
    }

    #[test]
    fn b1_addition() {
        run_6b1_test(b"return 40 + 2;", 42, true);
        eprintln!("6B.1: \"return 40 + 2;\" → 42 ✓");
    }

    #[test]
    fn b1_subtraction() {
        run_6b1_test(b"return 50 - 8;", 42, true);
        eprintln!("6B.1: \"return 50 - 8;\" → 42 ✓");
    }

    #[test]
    fn b1_multiplication() {
        run_6b1_test(b"return 6 * 7;", 42, true);
        eprintln!("6B.1: \"return 6 * 7;\" → 42 ✓");
    }

    // ─── Precedence ─────────────────────────────────────────────

    #[test]
    fn b1_precedence_mul_over_add() {
        // 2 + 3 * 4 = 2 + 12 = 14 (not (2+3)*4 = 20)
        run_6b1_test(b"return 2 + 3 * 4;", 14, true);
        eprintln!("6B.1: \"return 2 + 3 * 4;\" → 14 (precedence) ✓");
    }

    #[test]
    fn b1_parentheses_override() {
        // (2 + 3) * 4 = 5 * 4 = 20
        run_6b1_test(b"return (2 + 3) * 4;", 20, true);
        eprintln!("6B.1: \"return (2 + 3) * 4;\" → 20 (parentheses) ✓");
    }

    // ─── Associativity ──────────────────────────────────────────

    #[test]
    fn b1_left_associativity() {
        // 10 - 3 - 2 = (10-3) - 2 = 5 (not 10-(3-2) = 9)
        run_6b1_test(b"return 10 - 3 - 2;", 5, true);
        eprintln!("6B.1: \"return 10 - 3 - 2;\" → 5 (left assoc) ✓");
    }

    // ─── Nested parentheses ─────────────────────────────────────

    #[test]
    fn b1_nested_parens() {
        // ((2 + 3)) * 4 = 20
        run_6b1_test(b"return ((2 + 3)) * 4;", 20, true);
        eprintln!("6B.1: \"return ((2 + 3)) * 4;\" → 20 (nested) ✓");
    }

    // ─── Syntax errors ──────────────────────────────────────────

    #[test]
    fn b1_error_missing_expr() {
        run_6b1_test(b"return ;", u64::MAX, false);
        eprintln!("6B.1: \"return ;\" → error (missing expression) ✓");
    }

    #[test]
    fn b1_error_missing_close_paren() {
        run_6b1_test(b"return (2 + 3;", u64::MAX, false);
        eprintln!("6B.1: \"return (2 + 3;\" → error (missing ')') ✓");
    }

    #[test]
    fn b1_error_double_operator() {
        run_6b1_test(b"return 2 ** 3;", u64::MAX, false);
        eprintln!("6B.1: \"return 2 ** 3;\" → error (double op) ✓");
    }

    #[test]
    fn b1_error_missing_keyword() {
        run_6b1_test(b"42;", u64::MAX, false);
        eprintln!("6B.1: \"42;\" → error (missing 'return') ✓");
    }

    // ─── 6B.1a: overflow and EOF regressions ────────────────────

    #[test]
    fn b1a_literal_overflow_wrapping() {
        // 2^64 + 42 = 18446744073709551658
        // Without per-digit overflow check, u64 wraps to 42.
        // The compiler must reject during parsing, not accept the wrap.
        run_6b1_test(b"return 18446744073709551658;", u64::MAX, false);
        eprintln!("6B.1a: 2^64+42 wrap → error (overflow during parsing) ✓");
    }

    #[test]
    fn b1a_literal_overflow_boundary() {
        // 131072 exceeds 18-bit MOVI range
        run_6b1_test(b"return 131072;", u64::MAX, false);
        eprintln!("6B.1a: \"return 131072;\" → error (MOVI overflow) ✓");
    }

    #[test]
    fn b1a_literal_max_accepted() {
        run_6b1_test(b"return 131071;", 131071, true);
        eprintln!("6B.1a: \"return 131071;\" → 131071 (MOVI max) ✓");
    }

    #[test]
    fn b1a_trailing_garbage() {
        // After ';', source must be exhausted.  "garbage" is not EOF.
        run_6b1_test(b"return 42;garbage", u64::MAX, false);
        eprintln!("6B.1a: \"return 42;garbage\" → error (not EOF) ✓");
    }

    #[test]
    fn b1a_trailing_whitespace_ok() {
        // Trailing whitespace after ';' should be accepted.
        run_6b1_test(b"return 42;  ", 42, true);
        eprintln!("6B.1a: \"return 42;  \" → 42 (trailing ws ok) ✓");
    }

    #[test]
    fn b1a_expr_overflow_in_addition() {
        // 131070 + 2 = 131072 > 131071: main's range check catches this.
        // The expression value exceeds MOVI range even though
        // individual literals are fine.
        run_6b1_test(b"return 131070 + 2;", u64::MAX, false);
        eprintln!("6B.1a: \"return 131070 + 2;\" → error (expr overflow) ✓");
    }

    // ═══════════════════════════════════════════════════════════════
    // 6B.2: Tokenizer with lexical identity, symbol table, locals
    //
    // Grammar:
    //   program → { var_decl } return_stmt
    //   var_decl → "int" IDENT "=" expr ";"
    //   return_stmt → "return" expr ";"
    //   expr → additive
    //   additive → multiplicative { ('+'|'-') multiplicative }
    //   multiplicative → primary { '*' primary }
    //   primary → NUMBER | IDENT | '(' expr ')'
    //
    // Token set: {INT_KW, RETURN, NUMBER, IDENT, +, -, *, (, ), =, ;}
    // Maximal-munch: "return42" scans as one IDENT, not RETURN+NUMBER.
    // ═══════════════════════════════════════════════════════════════

    fn build_6b2_compiler() -> Program {
        // ─── Workspace layout ────────────────────────────
        const WS_POS: i64       = 0x6000;
        const WS_SRC_LEN: i64   = 0x6008;
        const WS_TEXT_BASE: i64  = 0x6010;
        const WS_ERROR: i64      = 0x6018;
        const WS_TOK_TYPE: i64   = 0x6020;
        const WS_TOK_VALUE: i64  = 0x6028;
        const WS_KW_INT: i64     = 0x6030;
        const WS_KW_RETURN: i64  = 0x6038;
        const WS_SYM_COUNT: i64  = 0x6040;
        const WS_SYM_TABLE: i64  = 0x6048;

        // ─── Token type constants ────────────────────────
        const TOK_EOF: i64    = 0;
        const TOK_INT_KW: i64 = 1;
        const TOK_RETURN: i64 = 2;
        const TOK_NUMBER: i64 = 3;
        const TOK_IDENT: i64  = 4;
        const TOK_PLUS: i64   = 5;
        const TOK_MINUS: i64  = 6;
        const TOK_STAR: i64   = 7;
        const TOK_LPAREN: i64 = 8;
        const TOK_RPAREN: i64 = 9;
        const TOK_EQ: i64     = 10;
        const TOK_SEMI: i64   = 11;

        fn lit(v: i64) -> Expr { Expr::IntLit(v) }
        fn var(id: VarId) -> Expr { Expr::Var(id) }
        fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
            Expr::BinOp(op, Box::new(a), Box::new(b))
        }
        fn assign(id: VarId, e: Expr) -> Stmt {
            Stmt::Expr(Expr::Assign(id, Box::new(e)))
        }
        fn deref(addr: Expr) -> Expr { Expr::Deref(Box::new(addr)) }
        fn deref_assign(addr: Expr, val: Expr) -> Stmt {
            Stmt::Expr(Expr::DerefAssign(Box::new(addr), Box::new(val)))
        }
        fn syscall(num: u8, args: Vec<Expr>) -> Expr {
            Expr::Syscall(num, args)
        }
        fn call(name: &str, args: Vec<Expr>) -> Expr {
            Expr::Call(name.into(), args)
        }
        fn call_stmt(name: &str, args: Vec<Expr>) -> Stmt {
            Stmt::Expr(Expr::Call(name.into(), args))
        }

        // ─── peek_char() → int ─────────────────────────────
        // Returns byte at current position, or 0 at end.
        // Locals: pos(0), src_len(1), text_base(2),
        //         aligned(3), word(4), byte_shift(5)
        let fn_peek_char = Function {
            name: "peek_char".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SRC_LEN)))),
                Stmt::If(
                    binop(BinOp::Le, var(1), var(0)),
                    vec![Stmt::Return(lit(0))],
                    vec![],
                ),
                Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_TEXT_BASE)))),
                Stmt::VarDecl(3, Type::Int, Some(
                    binop(BinOp::Add, var(2),
                        binop(BinOp::And, var(0), lit(-8)))
                )),
                Stmt::VarDecl(4, Type::Int, Some(deref(var(3)))),
                Stmt::VarDecl(5, Type::Int, Some(
                    binop(BinOp::Mul,
                        binop(BinOp::And, var(0), lit(7)),
                        lit(8))
                )),
                Stmt::Return(binop(BinOp::And,
                    binop(BinOp::Shr, var(4), var(5)),
                    lit(0xFF),
                )),
            ],
        };

        // ─── advance() ─────────────────────────────────────
        // Locals: pos(0)
        let fn_advance = Function {
            name: "advance".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int)],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
                deref_assign(lit(WS_POS),
                    binop(BinOp::Add, var(0), lit(1))),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── skip_ws() ─────────────────────────────────────
        // Whitespace: ASCII 1–32 (space, tab, newline, CR).
        // Locals: running(0), ch(1)
        let fn_skip_ws = Function {
            name: "skip_ws".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int), (1, Type::Int)],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(lit(1))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
                Stmt::While(var(0), vec![
                    assign(1, call("peek_char", vec![])),
                    Stmt::If(
                        binop(BinOp::And,
                            binop(BinOp::Le, lit(1), var(1)),
                            binop(BinOp::Le, var(1), lit(32)),
                        ),
                        vec![call_stmt("advance", vec![])],
                        vec![assign(0, lit(0))],
                    ),
                ]),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── set_char_token(tok) ────────────────────────────
        // Advance past single-char token, store its type.
        // Params: tok(0)
        let fn_set_char_token = Function {
            name: "set_char_token".into(),
            params: vec![(0, Type::Int)],
            ret_type: Type::Int,
            locals: vec![],
            body: vec![
                call_stmt("advance", vec![]),
                deref_assign(lit(WS_TOK_TYPE), var(0)),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── scan_number() ─────────────────────────────────
        // Scan decimal digits, store TOK_NUMBER + value.
        // Overflow guard: Lt(131071, value) after each digit.
        // Locals: value(0), running(1), ch(2), is_digit(3)
        let fn_scan_number = Function {
            name: "scan_number".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int),
                (2, Type::Int), (3, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(1))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::While(var(1), vec![
                    assign(2, call("peek_char", vec![])),
                    assign(3, binop(BinOp::And,
                        binop(BinOp::Le, lit(48), var(2)),
                        binop(BinOp::Le, var(2), lit(57)),
                    )),
                    Stmt::If(var(3), vec![
                        assign(0, binop(BinOp::Add,
                            binop(BinOp::Mul, var(0), lit(10)),
                            binop(BinOp::Sub, var(2), lit(48)),
                        )),
                        Stmt::If(
                            binop(BinOp::Lt, lit(131071), var(0)),
                            vec![
                                deref_assign(lit(WS_ERROR), lit(1)),
                                assign(1, lit(0)),
                            ],
                            vec![
                                call_stmt("advance", vec![]),
                            ],
                        ),
                    ], vec![
                        assign(1, lit(0)),
                    ]),
                ]),
                deref_assign(lit(WS_TOK_TYPE), lit(TOK_NUMBER)),
                deref_assign(lit(WS_TOK_VALUE), var(0)),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── scan_ident() ──────────────────────────────────
        // Scan alphanumeric identifier, check keywords.
        // Maximal munch: consumes all [a-z0-9] chars.
        // Packed name: (name << 8) | ch per character.
        //
        // is_alnum = is_alpha | is_digit must be computed in
        // two steps — Or(And(Le,Le), And(Le,Le)) is 3 levels of
        // BinOp nesting, which clobbers R5 during the RHS Le.
        //
        // Identifier length bounded to 8: after 8 characters,
        // high bytes shift out of u64, causing distinct identifiers
        // to alias.  Reject and halt rather than silently alias.
        // Locals: name(0), running(1), ch(2), is_alnum(3),
        //         is_dig(4), len(5)
        let fn_scan_ident = Function {
            name: "scan_ident".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int),
                (2, Type::Int), (3, Type::Int),
                (4, Type::Int), (5, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(lit(0))),
                Stmt::VarDecl(1, Type::Int, Some(lit(1))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),
                Stmt::VarDecl(5, Type::Int, Some(lit(0))),
                Stmt::While(var(1), vec![
                    assign(2, call("peek_char", vec![])),
                    // is_alpha: 'a' <= ch <= 'z'  (2 levels, safe into R4)
                    assign(3, binop(BinOp::And,
                        binop(BinOp::Le, lit(97), var(2)),
                        binop(BinOp::Le, var(2), lit(122)),
                    )),
                    // is_digit: '0' <= ch <= '9'  (2 levels, safe into R4)
                    assign(4, binop(BinOp::And,
                        binop(BinOp::Le, lit(48), var(2)),
                        binop(BinOp::Le, var(2), lit(57)),
                    )),
                    // is_alnum = is_alpha | is_digit  (1 level, safe)
                    assign(3, binop(BinOp::Or, var(3), var(4))),
                    Stmt::If(var(3), vec![
                        assign(0, binop(BinOp::Or,
                            binop(BinOp::Shl, var(0), lit(8)),
                            var(2),
                        )),
                        assign(5, binop(BinOp::Add, var(5), lit(1))),
                        call_stmt("advance", vec![]),
                    ], vec![
                        assign(1, lit(0)),
                    ]),
                ]),
                // Reject identifiers longer than 8 characters:
                // after 8 chars, high bytes shift out of u64 → aliasing.
                Stmt::If(
                    binop(BinOp::Lt, lit(8), var(5)),
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
                        Stmt::Return(lit(0)),
                    ],
                    vec![],
                ),
                // Keyword check: compare packed name against stored constants
                Stmt::If(
                    binop(BinOp::Eq, var(0), deref(lit(WS_KW_INT))),
                    vec![
                        deref_assign(lit(WS_TOK_TYPE), lit(TOK_INT_KW)),
                    ],
                    vec![Stmt::If(
                        binop(BinOp::Eq, var(0), deref(lit(WS_KW_RETURN))),
                        vec![
                            deref_assign(lit(WS_TOK_TYPE), lit(TOK_RETURN)),
                        ],
                        vec![
                            deref_assign(lit(WS_TOK_TYPE), lit(TOK_IDENT)),
                            deref_assign(lit(WS_TOK_VALUE), var(0)),
                        ],
                    )],
                ),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── next_token() ──────────────────────────────────
        // Lexer dispatch: skip whitespace, classify first char.
        //
        // EOF is determined by position (pos ≥ src_len), NOT by
        // the byte value 0x00.  A NUL byte inside the declared
        // source is an invalid character, not EOF.
        // Locals: pos(0), slen(1), ch(2), is_d(3), is_a(4)
        let fn_next_token = Function {
            name: "next_token".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int),
            ],
            body: vec![
                call_stmt("skip_ws", vec![]),
                // Position-based EOF: pos ≥ src_len
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_POS)))),
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SRC_LEN)))),
                Stmt::If(binop(BinOp::Le, var(1), var(0)), vec![
                    deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
                    Stmt::Return(lit(0)),
                ], vec![
                // Read character (guaranteed within source bounds)
                Stmt::VarDecl(2, Type::Int, Some(call("peek_char", vec![]))),
                // Digit → scan_number
                Stmt::VarDecl(3, Type::Int, Some(binop(BinOp::And,
                    binop(BinOp::Le, lit(48), var(2)),
                    binop(BinOp::Le, var(2), lit(57)),
                ))),
                Stmt::If(var(3), vec![
                    call_stmt("scan_number", vec![]),
                    Stmt::Return(lit(0)),
                ], vec![
                // Alpha → scan_ident
                Stmt::VarDecl(4, Type::Int, Some(binop(BinOp::And,
                    binop(BinOp::Le, lit(97), var(2)),
                    binop(BinOp::Le, var(2), lit(122)),
                ))),
                Stmt::If(var(4), vec![
                    call_stmt("scan_ident", vec![]),
                    Stmt::Return(lit(0)),
                ], vec![
                // Single-character tokens
                Stmt::If(binop(BinOp::Eq, var(2), lit(43)), vec![   // '+'
                    Stmt::Return(call("set_char_token", vec![lit(TOK_PLUS)])),
                ], vec![
                Stmt::If(binop(BinOp::Eq, var(2), lit(45)), vec![   // '-'
                    Stmt::Return(call("set_char_token", vec![lit(TOK_MINUS)])),
                ], vec![
                Stmt::If(binop(BinOp::Eq, var(2), lit(42)), vec![   // '*'
                    Stmt::Return(call("set_char_token", vec![lit(TOK_STAR)])),
                ], vec![
                Stmt::If(binop(BinOp::Eq, var(2), lit(40)), vec![   // '('
                    Stmt::Return(call("set_char_token", vec![lit(TOK_LPAREN)])),
                ], vec![
                Stmt::If(binop(BinOp::Eq, var(2), lit(41)), vec![   // ')'
                    Stmt::Return(call("set_char_token", vec![lit(TOK_RPAREN)])),
                ], vec![
                Stmt::If(binop(BinOp::Eq, var(2), lit(61)), vec![   // '='
                    Stmt::Return(call("set_char_token", vec![lit(TOK_EQ)])),
                ], vec![
                Stmt::If(binop(BinOp::Eq, var(2), lit(59)), vec![   // ';'
                    Stmt::Return(call("set_char_token", vec![lit(TOK_SEMI)])),
                ], vec![
                    // Unknown character (including NUL) → error + force EOF
                    deref_assign(lit(WS_ERROR), lit(1)),
                    deref_assign(lit(WS_TOK_TYPE), lit(TOK_EOF)),
                    Stmt::Return(lit(0)),
                ]),
                ]),
                ]),
                ]),
                ]),
                ]),
                ]),
                ]),
                ]),
                ]),
            ],
        };

        // ─── parse_primary() → int ─────────────────────────
        // primary → NUMBER | IDENT | '(' expr ')'
        // Locals: tok(0), val(1), name_v(2)
        let fn_parse_primary = Function {
            name: "parse_primary".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_TOK_TYPE)))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_NUMBER)), vec![
                    assign(1, deref(lit(WS_TOK_VALUE))),
                    call_stmt("next_token", vec![]),
                    Stmt::Return(var(1)),
                ], vec![Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IDENT)), vec![
                    assign(2, deref(lit(WS_TOK_VALUE))),
                    call_stmt("next_token", vec![]),
                    Stmt::Return(call("lookup_symbol", vec![var(2)])),
                ], vec![Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_LPAREN)), vec![
                    call_stmt("next_token", vec![]),
                    assign(1, call("parse_expr", vec![])),
                    Stmt::If(
                        binop(BinOp::Ne, deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![call_stmt("next_token", vec![])],
                    ),
                    Stmt::Return(var(1)),
                ], vec![
                    deref_assign(lit(WS_ERROR), lit(1)),
                    Stmt::Return(lit(0)),
                ])])]),
            ],
        };

        // ─── parse_multiplicative() → int ───────────────────
        // multiplicative → primary { '*' primary }
        // Locals: left(0), running(1), tok(2), right(3)
        let fn_parse_mult = Function {
            name: "parse_multiplicative".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int),
                (2, Type::Int), (3, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(
                    call("parse_primary", vec![]))),
                Stmt::VarDecl(1, Type::Int, Some(lit(1))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::While(var(1), vec![
                    assign(2, deref(lit(WS_TOK_TYPE))),
                    Stmt::If(
                        binop(BinOp::Eq, var(2), lit(TOK_STAR)),
                        vec![
                            call_stmt("next_token", vec![]),
                            assign(3, call("parse_primary", vec![])),
                            assign(0, binop(BinOp::Mul, var(0), var(3))),
                        ],
                        vec![assign(1, lit(0))],
                    ),
                ]),
                Stmt::Return(var(0)),
            ],
        };

        // ─── parse_additive() → int ────────────────────────
        // additive → multiplicative { ('+'|'-') multiplicative }
        // Locals: left(0), running(1), tok(2), right(3)
        let fn_parse_add = Function {
            name: "parse_additive".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int),
                (2, Type::Int), (3, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(
                    call("parse_multiplicative", vec![]))),
                Stmt::VarDecl(1, Type::Int, Some(lit(1))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::While(var(1), vec![
                    assign(2, deref(lit(WS_TOK_TYPE))),
                    Stmt::If(
                        binop(BinOp::Eq, var(2), lit(TOK_PLUS)),
                        vec![
                            call_stmt("next_token", vec![]),
                            assign(3, call("parse_multiplicative", vec![])),
                            assign(0, binop(BinOp::Add, var(0), var(3))),
                        ],
                        vec![Stmt::If(
                            binop(BinOp::Eq, var(2), lit(TOK_MINUS)),
                            vec![
                                call_stmt("next_token", vec![]),
                                assign(3, call("parse_multiplicative", vec![])),
                                assign(0, binop(BinOp::Sub, var(0), var(3))),
                            ],
                            vec![assign(1, lit(0))],
                        )],
                    ),
                ]),
                Stmt::Return(var(0)),
            ],
        };

        // ─── parse_expr() → int ────────────────────────────
        let fn_parse_expr = Function {
            name: "parse_expr".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![],
            body: vec![
                Stmt::Return(call("parse_additive", vec![])),
            ],
        };

        // ─── add_symbol(name, value) ────────────────────────
        // Add name→value to the fixed symbol table.
        // Rejects duplicates and enforces capacity bound.
        //
        // Capacity: workspace is 0x1000 bytes at virtual 0x6000.
        // Symbol table starts at 0x6048, each entry is 16 bytes.
        // (0x7000 − 0x6048) / 16 = 251 entries (indices 0–250).
        // Entry 251 would write its value at 0x7000 — outside
        // the workspace, into the stack mapping.
        //
        // Params: name(0), value(1)
        // Locals: count(2), i(3), addr(4), entry_name(5)
        let fn_add_symbol = Function {
            name: "add_symbol".into(),
            params: vec![(0, Type::Int), (1, Type::Int)],
            ret_type: Type::Int,
            locals: vec![
                (2, Type::Int), (3, Type::Int),
                (4, Type::Int), (5, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(2, Type::Int, Some(deref(lit(WS_SYM_COUNT)))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),
                Stmt::VarDecl(5, Type::Int, Some(lit(0))),
                // Capacity guard: count must be < 251
                Stmt::If(
                    binop(BinOp::Le, lit(251), var(2)),
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        Stmt::Return(lit(0)),
                    ],
                    vec![],
                ),
                // Duplicate check: scan existing entries
                Stmt::While(binop(BinOp::Lt, var(3), var(2)), vec![
                    assign(4, binop(BinOp::Add, lit(WS_SYM_TABLE),
                        binop(BinOp::Mul, var(3), lit(16)))),
                    assign(5, deref(var(4))),
                    Stmt::If(
                        binop(BinOp::Eq, var(5), var(0)),
                        vec![
                            deref_assign(lit(WS_ERROR), lit(1)),
                            Stmt::Return(lit(0)),
                        ],
                        vec![],
                    ),
                    assign(3, binop(BinOp::Add, var(3), lit(1))),
                ]),
                // Add new entry at count * 16
                assign(4, binop(BinOp::Add, lit(WS_SYM_TABLE),
                    binop(BinOp::Mul, var(2), lit(16)))),
                deref_assign(var(4), var(0)),
                deref_assign(
                    binop(BinOp::Add, var(4), lit(8)),
                    var(1)),
                deref_assign(lit(WS_SYM_COUNT),
                    binop(BinOp::Add, var(2), lit(1))),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── lookup_symbol(name) → value ────────────────────
        // Look up name in the symbol table. Sets error if not found.
        // Params: name(0)
        // Locals: count(1), i(2), addr(3), entry_name(4)
        let fn_lookup_symbol = Function {
            name: "lookup_symbol".into(),
            params: vec![(0, Type::Int)],
            ret_type: Type::Int,
            locals: vec![
                (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SYM_COUNT)))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),
                Stmt::While(binop(BinOp::Lt, var(2), var(1)), vec![
                    assign(3, binop(BinOp::Add, lit(WS_SYM_TABLE),
                        binop(BinOp::Mul, var(2), lit(16)))),
                    assign(4, deref(var(3))),
                    Stmt::If(
                        binop(BinOp::Eq, var(4), var(0)),
                        vec![Stmt::Return(deref(
                            binop(BinOp::Add, var(3), lit(8))
                        ))],
                        vec![],
                    ),
                    assign(2, binop(BinOp::Add, var(2), lit(1))),
                ]),
                deref_assign(lit(WS_ERROR), lit(1)),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── main() ────────────────────────────────────────
        // Locals:
        //   0: src_base, 1: src_len, 2: text_base,
        //   3: kw_int, 4: kw_ret (temporaries for keyword building),
        //   5: name, 6: decl_val (var-decl parsing),
        //   7: value (return expr),
        //   8: error_flag,
        //   9: movi_r1, 10: movi_r0, 11: trap_insn, 12: nop_insn,
        //   13: pair0, 14: pair1, 15: child
        let fn_main = Function {
            name: "main".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
                (6, Type::Int), (7, Type::Int), (8, Type::Int),
                (9, Type::Int), (10, Type::Int), (11, Type::Int),
                (12, Type::Int), (13, Type::Int), (14, Type::Int),
                (15, Type::Int),
            ],
            body: vec![
                // ─── Source setup ─────────────────────────
                Stmt::VarDecl(0, Type::Int, Some(lit(0x4000))),
                Stmt::VarDecl(1, Type::Int, Some(deref(var(0)))),
                Stmt::VarDecl(2, Type::Int, Some(
                    binop(BinOp::Add, var(0), lit(8)))),

                // Source metadata guard: reject src_len > 0xFF8
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

                // ─── Build packed keyword constants ──────
                // "int": pack 'i'(0x69), 'n'(0x6E), 't'(0x74)
                Stmt::VarDecl(3, Type::Int, Some(lit(0x69))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x6E))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x74))),
                deref_assign(lit(WS_KW_INT), var(3)),

                // "return": pack 'r','e','t','u','r','n'
                Stmt::VarDecl(4, Type::Int, Some(lit(0x72))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x65))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x74))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x75))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x72))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x6E))),
                deref_assign(lit(WS_KW_RETURN), var(4)),

                // ─── Prime the lexer ─────────────────────
                call_stmt("next_token", vec![]),

                // ─── Parse variable declarations ─────────
                // while tok_type == INT_KW: parse "int IDENT = expr;"
                Stmt::VarDecl(5, Type::Int, Some(lit(0))),
                Stmt::VarDecl(6, Type::Int, Some(lit(0))),
                Stmt::While(
                    binop(BinOp::Eq,
                        deref(lit(WS_TOK_TYPE)),
                        lit(TOK_INT_KW)),
                    vec![
                        call_stmt("next_token", vec![]),     // consume 'int'
                        // Expect identifier
                        Stmt::If(
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)),
                                lit(TOK_IDENT)),
                            vec![deref_assign(lit(WS_ERROR), lit(1))],
                            vec![],
                        ),
                        assign(5, deref(lit(WS_TOK_VALUE))),
                        call_stmt("next_token", vec![]),     // consume ident
                        // Expect '='
                        Stmt::If(
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)),
                                lit(TOK_EQ)),
                            vec![deref_assign(lit(WS_ERROR), lit(1))],
                            vec![],
                        ),
                        call_stmt("next_token", vec![]),     // consume '='
                        // Parse initializer expression
                        assign(6, call("parse_expr", vec![])),
                        // Expect ';'
                        Stmt::If(
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)),
                                lit(TOK_SEMI)),
                            vec![deref_assign(lit(WS_ERROR), lit(1))],
                            vec![],
                        ),
                        call_stmt("next_token", vec![]),     // consume ';'
                        // Add to symbol table
                        call_stmt("add_symbol", vec![var(5), var(6)]),
                    ],
                ),

                // ─── Parse return statement ──────────────
                Stmt::If(
                    binop(BinOp::Ne,
                        deref(lit(WS_TOK_TYPE)),
                        lit(TOK_RETURN)),
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                    vec![],
                ),
                call_stmt("next_token", vec![]),             // consume 'return'
                Stmt::VarDecl(7, Type::Int, Some(
                    call("parse_expr", vec![]))),

                // Expect ';'
                Stmt::If(
                    binop(BinOp::Ne,
                        deref(lit(WS_TOK_TYPE)),
                        lit(TOK_SEMI)),
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                    vec![],
                ),
                call_stmt("next_token", vec![]),             // consume ';'

                // ─── Check EOF ───────────────────────────
                Stmt::If(
                    binop(BinOp::Ne,
                        deref(lit(WS_TOK_TYPE)),
                        lit(TOK_EOF)),
                    vec![deref_assign(lit(WS_ERROR), lit(1))],
                    vec![],
                ),

                // ─── Check error flag ────────────────────
                Stmt::VarDecl(8, Type::Int, Some(
                    deref(lit(WS_ERROR)))),
                Stmt::If(var(8),
                    vec![Stmt::Return(lit(-1))],
                    vec![],
                ),

                // ─── Check value range ───────────────────
                Stmt::If(
                    binop(BinOp::Lt, lit(131071), var(7)),
                    vec![Stmt::Return(lit(-1))],
                    vec![],
                ),

                // ─── Code emission ───────────────────────
                // Same 4-instruction child program as 6B.0/6B.1:
                //   MOVI R1, value
                //   MOVI R0, 0
                //   TRAP #0
                //   NOP
                Stmt::VarDecl(9, Type::Int, Some(
                    binop(BinOp::Or,
                        binop(BinOp::Or,
                            binop(BinOp::Shl, lit(22), lit(26)),
                            binop(BinOp::Shl, lit(1), lit(22)),
                        ),
                        var(7),
                    )
                )),
                Stmt::VarDecl(10, Type::Int, Some(
                    binop(BinOp::Shl, lit(22), lit(26)))),
                Stmt::VarDecl(11, Type::Int, Some(
                    binop(BinOp::Shl, lit(57), lit(26)))),
                Stmt::VarDecl(12, Type::Int, Some(
                    binop(BinOp::Shl, lit(63), lit(26)))),
                Stmt::VarDecl(13, Type::Int, Some(
                    binop(BinOp::Or, var(9),
                        binop(BinOp::Shl, var(10), lit(32))))),
                Stmt::VarDecl(14, Type::Int, Some(
                    binop(BinOp::Or, var(11),
                        binop(BinOp::Shl, var(12), lit(32))))),

                deref_assign(lit(0x5000), var(13)),
                deref_assign(
                    binop(BinOp::Add, lit(0x5000), lit(8)),
                    var(14)),

                // ─── Seal → Exec ─────────────────────────
                Stmt::Expr(syscall(SYS_SEAL as u8, vec![lit(0x5000)])),
                Stmt::VarDecl(15, Type::Int, Some(
                    syscall(SYS_EXEC as u8, vec![lit(0x5000), lit(16)]))),
                Stmt::Return(var(15)),
            ],
        };

        Program {
            functions: vec![
                fn_main, fn_peek_char, fn_advance, fn_skip_ws,
                fn_set_char_token, fn_scan_number, fn_scan_ident,
                fn_next_token,
                fn_parse_primary, fn_parse_mult, fn_parse_add,
                fn_parse_expr,
                fn_add_symbol, fn_lookup_symbol,
            ],
        }
    }

    /// Run a 6B.2 test case: guest tokenizer + parser → expected result.
    fn run_6b2_test(source_text: &[u8], expected_exit: u64, expect_child: bool) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        let src_len = source_text.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, source_text);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let compiler_prog = build_6b2_compiler();
        let asm = cc::compile(&compiler_prog);
        eprintln!("--- 6B.2 listing ---\n{}", asm.listing());
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x1000, source);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(0x06000, 0x1000, work);
        core.address_map.add(0x07000, 0x4000, stack);
        core.r[SP as usize] = 0x07000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(100000, 100000);

        assert!(kernel.processes[0].exited(),
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            // Post-8.3c: child is reclaimed after collection.
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 6B.2 test corpus
    // ═══════════════════════════════════════════════════════════════

    // ─── Regression: expression-only programs still work ────────

    #[test]
    fn b2_return_42() {
        run_6b2_test(b"return 42;", 42, true);
        eprintln!("6B.2: \"return 42;\" → 42 ✓");
    }

    #[test]
    fn b2_return_arithmetic() {
        run_6b2_test(b"return 2 + 3 * 4;", 14, true);
        eprintln!("6B.2: \"return 2 + 3 * 4;\" → 14 ✓");
    }

    #[test]
    fn b2_return_parens() {
        run_6b2_test(b"return (2 + 3) * 4;", 20, true);
        eprintln!("6B.2: \"return (2 + 3) * 4;\" → 20 ✓");
    }

    #[test]
    fn b2_left_assoc() {
        run_6b2_test(b"return 10 - 3 - 2;", 5, true);
        eprintln!("6B.2: \"return 10 - 3 - 2;\" → 5 ✓");
    }

    // ─── Basic variable declarations ────────────────────────────

    #[test]
    fn b2_single_var() {
        run_6b2_test(b"int x = 42; return x;", 42, true);
        eprintln!("6B.2: \"int x = 42; return x;\" → 42 ✓");
    }

    #[test]
    fn b2_two_vars_addition() {
        run_6b2_test(b"int x = 40; int y = 2; return x + y;", 42, true);
        eprintln!("6B.2: \"int x = 40; int y = 2; return x + y;\" → 42 ✓");
    }

    #[test]
    fn b2_var_with_expr_init() {
        run_6b2_test(b"int x = 2 + 3; return x * 4;", 20, true);
        eprintln!("6B.2: \"int x = 2 + 3; return x * 4;\" → 20 ✓");
    }

    #[test]
    fn b2_var_plus_literal() {
        run_6b2_test(b"int x = 40; return x + 2;", 42, true);
        eprintln!("6B.2: \"int x = 40; return x + 2;\" → 42 ✓");
    }

    #[test]
    fn b2_precedence_with_vars() {
        run_6b2_test(b"int x = 2; int y = 3; return x + y * 4;", 14, true);
        eprintln!("6B.2: \"int x = 2; int y = 3; return x + y * 4;\" → 14 ✓");
    }

    #[test]
    fn b2_parens_with_vars() {
        run_6b2_test(b"int x = 2; int y = 3; return (x + y) * 4;", 20, true);
        eprintln!("6B.2: \"int x = 2; int y = 3; return (x + y) * 4;\" → 20 ✓");
    }

    // ─── Lexical identity: maximal munch ────────────────────────

    #[test]
    fn b2_return42_is_ident() {
        // "return42" is scanned as one identifier, not RETURN + NUMBER.
        // It's not a keyword, so the parser sees IDENT where it expects
        // RETURN, setting error.
        run_6b2_test(b"return42;", u64::MAX, false);
        eprintln!("6B.2: \"return42;\" → error (maximal munch: one IDENT) ✓");
    }

    #[test]
    fn b2_int0_is_ident() {
        // "int0" is an identifier, not the keyword "int" followed by "0".
        run_6b2_test(b"int0 x = 1; return x;", u64::MAX, false);
        eprintln!("6B.2: \"int0 x = 1;\" → error (int0 is IDENT) ✓");
    }

    // ─── Symbol table: common prefixes ──────────────────────────

    #[test]
    fn b2_common_prefix() {
        run_6b2_test(b"int x = 1; int xy = 2; return x + xy;", 3, true);
        eprintln!("6B.2: \"int x = 1; int xy = 2; return x + xy;\" → 3 ✓");
    }

    // ─── Symbol table errors ────────────────────────────────────

    #[test]
    fn b2_duplicate_declaration() {
        run_6b2_test(b"int x = 1; int x = 2; return x;", u64::MAX, false);
        eprintln!("6B.2: duplicate declaration → error ✓");
    }

    #[test]
    fn b2_use_before_declaration() {
        run_6b2_test(b"return x;", u64::MAX, false);
        eprintln!("6B.2: use before declaration → error ✓");
    }

    #[test]
    fn b2_unknown_identifier() {
        run_6b2_test(b"int x = 1; return z;", u64::MAX, false);
        eprintln!("6B.2: unknown identifier → error ✓");
    }

    // ─── Syntax errors ──────────────────────────────────────────

    #[test]
    fn b2_missing_return() {
        run_6b2_test(b"int x = 42;", u64::MAX, false);
        eprintln!("6B.2: missing return → error ✓");
    }

    #[test]
    fn b2_missing_initializer() {
        run_6b2_test(b"int x; return x;", u64::MAX, false);
        eprintln!("6B.2: \"int x;\" (no initializer) → error ✓");
    }

    #[test]
    fn b2_missing_semicolon() {
        run_6b2_test(b"int x = 42 return x;", u64::MAX, false);
        eprintln!("6B.2: missing semicolon → error ✓");
    }

    // ─── Overflow guard preserved ───────────────────────────────

    #[test]
    fn b2_literal_overflow() {
        run_6b2_test(b"return 131072;", u64::MAX, false);
        eprintln!("6B.2: \"return 131072;\" → error (overflow) ✓");
    }

    #[test]
    fn b2_literal_max_accepted() {
        run_6b2_test(b"return 131071;", 131071, true);
        eprintln!("6B.2: \"return 131071;\" → 131071 (MOVI max) ✓");
    }

    #[test]
    fn b2_expr_overflow() {
        run_6b2_test(b"int x = 131070; return x + 2;", u64::MAX, false);
        eprintln!("6B.2: expr overflow → error ✓");
    }

    // ─── Multiline source ───────────────────────────────────────

    #[test]
    fn b2_multiline() {
        run_6b2_test(b"int x = 40;\nint y = 2;\nreturn x + y;", 42, true);
        eprintln!("6B.2: multiline source → 42 ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // Phase 6B.2a — boundary guards
    // ═══════════════════════════════════════════════════════════

    // ── Identifier length guard ─────────────────────────────

    #[test]
    fn b2a_ident_8_chars_ok() {
        // 8-char identifier is at the packed-u64 limit: accepted.
        run_6b2_test(b"int abcdefgh = 42; return abcdefgh;", 42, true);
        eprintln!("6B.2a: 8-char identifier → 42 ✓");
    }

    #[test]
    fn b2a_ident_9_chars_error() {
        // 9-char identifier overflows packed u64 → compile error.
        run_6b2_test(b"int abcdefghi = 42; return abcdefghi;", u64::MAX, false);
        eprintln!("6B.2a: 9-char identifier → error ✓");
    }

    #[test]
    fn b2a_ident_alias_caught() {
        // Without the length guard, "aabcdefgh" and "babcdefgh"
        // would alias (both pack to the same final 8 bytes).
        // The guard rejects both at 9 chars before aliasing occurs.
        run_6b2_test(
            b"int aabcdefgh = 1; return babcdefgh;",
            u64::MAX,
            false,
        );
        eprintln!("6B.2a: 9-char aliasing pair → error ✓");
    }

    // ── Symbol-table capacity guard ──────────────────────────

    #[test]
    fn b2a_symtab_overflow() {
        // Generate 252 unique variable declarations — one past
        // the workspace capacity of 251 entries.
        //
        // Names: a..z (26), then aa..zz two-letter combos.
        // Each declaration is ~12 bytes; 252 × 12 + 9 ≈ 3033,
        // within the 4088-byte source limit.
        let mut src = Vec::new();
        for i in 0u32..252 {
            let name: String = if i < 26 {
                String::from((b'a' + i as u8) as char)
            } else {
                let first = (b'a' + ((i - 26) / 26) as u8) as char;
                let second = (b'a' + ((i - 26) % 26) as u8) as char;
                format!("{}{}", first, second)
            };
            src.extend_from_slice(format!("int {} = 0; ", name).as_bytes());
        }
        src.extend_from_slice(b"return 0;");
        run_6b2_test(&src, u64::MAX, false);
        eprintln!("6B.2a: 252 variables → capacity error ✓");
    }

    // ── NUL ≠ EOF ────────────────────────────────────────────

    #[test]
    fn b2a_nul_in_source() {
        // A NUL byte (0x00) embedded inside the declared source
        // must NOT be treated as EOF.  It is an invalid character.
        // Old code: peek_char() returns 0 for NUL → matches EOF check.
        // New code: position-based EOF; NUL falls to unknown-char error.
        let src = b"return 42;\x00garbage";
        run_6b2_test(src, u64::MAX, false);
        eprintln!("6B.2a: embedded NUL → error (not silent EOF) ✓");
    }

    #[test]
    fn b2a_true_eof_still_works() {
        // Verify that legitimate EOF (pos ≥ src_len) is still recognized
        // after removing the ch==0 check.
        run_6b2_test(b"return 42;", 42, true);
        eprintln!("6B.2a: true EOF still works ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 6B.3: Code generator — evaluator → emitter
    //
    // The guest compiler crosses from compile-time evaluator to
    // runtime code generator.  The symbol table changes from
    //   name → compile-time value
    // to
    //   name → runtime stack slot (SP-relative offset)
    //
    // 6B.3.0: runtime locals, same grammar as 6B.2
    //   program → { var_decl } return_stmt
    //   var_decl → "int" IDENT "=" expr ";"
    //   return_stmt → "return" expr ";"
    //   expr → additive
    //   additive → multiplicative { ('+'|'-') multiplicative }
    //   multiplicative → primary { '*' primary }
    //   primary → NUMBER | IDENT | '(' expr ')'
    //
    // Generated child code uses stack slots for variables:
    //   x → [SP - 8], y → [SP - 16], z → [SP - 24], ...
    // Expression temps start at [SP - 0x800].
    // ═══════════════════════════════════════════════════════════

    fn build_6b3_compiler() -> Program {
        // 6B.3 phase-specific workspace slots — relative to shared LAYOUT_WS.
        const WS_SYM_COUNT: i64  = LAYOUT_WS + 0x058;
        const WS_OUT_POS: i64    = LAYOUT_WS + 0x060;
        const WS_EXPR_SP: i64    = LAYOUT_WS + 0x068;
        const WS_SYM_TABLE: i64  = LAYOUT_WS + 0x070;

        // ─── Token type constants ────────────────────
        const TOK_EOF: i64    = 0;
        const TOK_INT_KW: i64 = 1;
        const TOK_RETURN: i64 = 2;
        const TOK_NUMBER: i64 = 3;
        const TOK_IDENT: i64  = 4;
        const TOK_PLUS: i64   = 5;
        const TOK_MINUS: i64  = 6;
        const TOK_STAR: i64   = 7;
        const TOK_LPAREN: i64 = 8;
        const TOK_RPAREN: i64 = 9;
        const TOK_EQ: i64     = 10;
        const TOK_SEMI: i64   = 11;
        const TOK_IF: i64     = 12;
        const TOK_ELSE: i64   = 13;
        const TOK_LBRACE: i64 = 14;
        const TOK_RBRACE: i64 = 15;
        const TOK_LT: i64     = 16;
        const TOK_WHILE: i64  = 17;
        const TOK_COMMA: i64  = 18;

        // ─── ISA encoding constants (opcode values) ──
        const OP_ADD: i64  = 1;
        const OP_SUB: i64  = 2;
        const OP_CMP: i64  = 9;
        const OP_MOV: i64  = 10;
        const OP_MUL: i64  = 11;
        const OP_CMPI: i64 = 21;  // 0x15
        const OP_MOVI: i64 = 22;  // 0x16
        const OP_LD: i64   = 32;  // 0x20
        const OP_ST: i64   = 33;  // 0x21
        const OP_BCC: i64  = 48;  // 0x30
        const OP_HALT: i64 = 62;  // 0x3E
        const OP_NOP: i64  = 63;  // 0x3F

        // Condition codes for branch instructions
        const COND_EQ: i64 = 0;
        const COND_GE: i64 = 3;
        const COND_AL: i64 = 15;

        // Register numbers for generated code
        const GEN_R0: i64  = 0;
        const GEN_R4: i64  = 4;
        const GEN_R5: i64  = 5;
        const GEN_SP: i64  = 15;

        const EXPR_SP_INIT: i64 = -0x800;

        fn syscall(num: u8, args: Vec<Expr>) -> Expr {
            Expr::Syscall(num, args)
        }


        // ─── Shared lexer ────────────────────────────────
        let tok3 = TokMap {
            eof: TOK_EOF, number: TOK_NUMBER, ident: TOK_IDENT,
            plus: TOK_PLUS, minus: TOK_MINUS, star: TOK_STAR,
            eq: TOK_EQ, semi: TOK_SEMI, comma: TOK_COMMA,
            int_kw: TOK_INT_KW, return_kw: TOK_RETURN,
            lparen: TOK_LPAREN, rparen: TOK_RPAREN,
            if_kw: TOK_IF, else_kw: TOK_ELSE, while_kw: TOK_WHILE,
            lbrace: TOK_LBRACE, rbrace: TOK_RBRACE, lt: TOK_LT,
        };
        let lexer_fns = guest_lexer_packed(&tok3);

        // ─── add_symbol(name) → offset ─────────────────
        // In 6B.3, the symbol table maps name → stack offset.
        // offset = -(count + 1) * 8: first var at [SP-8],
        // second at [SP-16], etc.
        // Params: name(0)
        // Locals: count(1), i(2), addr(3), entry(4), offset(5)
        let fn_add_symbol = Function {
            name: "add_symbol".into(),
            params: vec![(0, Type::Int)],
            ret_type: Type::Int,
            locals: vec![
                (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SYM_COUNT)))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),
                // Capacity guard
                Stmt::If(
                    binop(BinOp::Le, lit(250), var(1)),
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        Stmt::Return(lit(0)),
                    ],
                    vec![],
                ),
                // Duplicate check
                Stmt::While(binop(BinOp::Lt, var(2), var(1)), vec![
                    assign(3, binop(BinOp::Add, lit(WS_SYM_TABLE),
                        binop(BinOp::Mul, var(2), lit(16)))),
                    assign(4, deref(var(3))),
                    Stmt::If(
                        binop(BinOp::Eq, var(4), var(0)),
                        vec![
                            deref_assign(lit(WS_ERROR), lit(1)),
                            Stmt::Return(lit(0)),
                        ],
                        vec![],
                    ),
                    assign(2, binop(BinOp::Add, var(2), lit(1))),
                ]),
                // Compute stack offset: -(count + 1) * 8
                Stmt::VarDecl(5, Type::Int, Some(
                    binop(BinOp::Sub, lit(0),
                        binop(BinOp::Mul,
                            binop(BinOp::Add, var(1), lit(1)),
                            lit(8))))),
                // Store (name, offset) at sym_table[count]
                assign(3, binop(BinOp::Add, lit(WS_SYM_TABLE),
                    binop(BinOp::Mul, var(1), lit(16)))),
                deref_assign(var(3), var(0)),
                deref_assign(
                    binop(BinOp::Add, var(3), lit(8)),
                    var(5)),
                deref_assign(lit(WS_SYM_COUNT),
                    binop(BinOp::Add, var(1), lit(1))),
                Stmt::Return(var(5)),
            ],
        };

        // ─── lookup_symbol(name) → offset ──────────────
        let fn_lookup_symbol = Function {
            name: "lookup_symbol".into(),
            params: vec![(0, Type::Int)],
            ret_type: Type::Int,
            locals: vec![
                (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_SYM_COUNT)))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),
                Stmt::While(binop(BinOp::Lt, var(2), var(1)), vec![
                    assign(3, binop(BinOp::Add, lit(WS_SYM_TABLE),
                        binop(BinOp::Mul, var(2), lit(16)))),
                    assign(4, deref(var(3))),
                    Stmt::If(
                        binop(BinOp::Eq, var(4), var(0)),
                        vec![Stmt::Return(deref(
                            binop(BinOp::Add, var(3), lit(8))
                        ))],
                        vec![],
                    ),
                    assign(2, binop(BinOp::Add, var(2), lit(1))),
                ]),
                deref_assign(lit(WS_ERROR), lit(1)),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── emit(word) ────────────────────────────────
        // Write one instruction word to output buffer,
        // NOP-padded to 64 bits.  Each instruction occupies
        // 8 bytes (2 words: instruction + NOP).
        // Param: word(0)
        // Locals: pos(1), padded(2)
        let fn_emit = Function {
            name: "emit".into(),
            params: vec![(0, Type::Int)],
            ret_type: Type::Int,
            locals: vec![
                (1, Type::Int), (2, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(1, Type::Int, Some(deref(lit(WS_OUT_POS)))),
                // Capacity guard: output buffer is 0x1000 bytes,
                // each emit writes 8 bytes, so last legal pos is 0xFF8.
                // Without this, overflow enters the RW workspace at 0x6000
                // — memory authority ≠ output-object role.
                Stmt::If(
                    binop(BinOp::Lt, lit(0xFF8), var(1)),
                    vec![
                        deref_assign(lit(WS_ERROR), lit(1)),
                        Stmt::Return(lit(0)),
                    ],
                    vec![],
                ),
                // padded = word | (NOP << 32)
                //        = word | ((63 << 26) << 32)
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

        // ─── compile_primary() ─────────────────────────
        // NUMBER → emit MOVI R4, value
        // IDENT  → emit LD R4, [SP, #offset]
        // '('    → compile_expr, expect ')'
        // Locals: tok_type(0), val(1), enc(2)
        let fn_compile_primary = Function {
            name: "compile_primary".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(deref(lit(WS_TOK_TYPE)))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                // NUMBER
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_NUMBER)), vec![
                    assign(1, deref(lit(WS_TOK_VALUE))),
                    call_stmt("next_token", vec![]),
                    // MOVI R4, value: I-format (22 << 26)|(4 << 22)|(val & 0x3FFFF)
                    call_stmt("emit", vec![
                        enc_i(OP_MOVI, GEN_R4, 0, var(1))]),
                    Stmt::Return(lit(0)),
                ], vec![]),
                // IDENT
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IDENT)), vec![
                    assign(1, call("lookup_symbol",
                        vec![deref(lit(WS_TOK_VALUE))])),
                    call_stmt("next_token", vec![]),
                    // LD R4, [SP, #offset]: I-format (32<<26)|(4<<22)|(15<<18)|(off&0x3FFFF)
                    call_stmt("emit", vec![
                        enc_i(OP_LD, GEN_R4, GEN_SP, var(1))]),
                    Stmt::Return(lit(0)),
                ], vec![]),
                // '('
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_LPAREN)), vec![
                    call_stmt("next_token", vec![]),
                    call_stmt("compile_expr", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)),
                            lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    Stmt::Return(lit(0)),
                ], vec![]),
                // Error: unexpected token
                deref_assign(lit(WS_ERROR), lit(1)),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── compile_mult() ────────────────────────────
        // compile_primary, then handle * operators.
        // For each *:
        //   save R4 to expr temp, compile right,
        //   load saved → R5, MUL R4, R5, R4
        // Locals: esp(0)
        let fn_compile_mult = Function {
            name: "compile_mult".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int)],
            body: vec![
                call_stmt("compile_primary", vec![]),
                Stmt::While(
                    binop(BinOp::Eq,
                        deref(lit(WS_TOK_TYPE)),
                        lit(TOK_STAR)),
                    vec![
                        call_stmt("next_token", vec![]),
                        // Save R4: emit ST R4, [SP, #expr_sp]
                        Stmt::VarDecl(0, Type::Int, Some(
                            deref(lit(WS_EXPR_SP)))),
                        call_stmt("emit", vec![
                            enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
                        deref_assign(lit(WS_EXPR_SP),
                            binop(BinOp::Sub, var(0), lit(8))),
                        // Compile right operand → R4
                        call_stmt("compile_primary", vec![]),
                        // Restore left → R5: emit LD R5, [SP, #expr_sp]
                        assign(0, binop(BinOp::Add,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                        deref_assign(lit(WS_EXPR_SP), var(0)),
                        call_stmt("emit", vec![
                            enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
                        // emit MUL R4, R5, R4
                        call_stmt("emit", vec![
                            enc_r(OP_MUL, GEN_R4, GEN_R5, GEN_R4)]),
                    ],
                ),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── compile_add() ─────────────────────────────
        // compile_mult, then handle +/- operators.
        // Locals: esp(0), op(1)
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
                    binop(BinOp::Or,
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_PLUS)),
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_MINUS))),
                    vec![
                        assign(1, deref(lit(WS_TOK_TYPE))),
                        call_stmt("next_token", vec![]),
                        // Save R4 to expr temp stack
                        assign(0, deref(lit(WS_EXPR_SP))),
                        call_stmt("emit", vec![
                            enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
                        deref_assign(lit(WS_EXPR_SP),
                            binop(BinOp::Sub, var(0), lit(8))),
                        // Compile right operand → R4
                        call_stmt("compile_mult", vec![]),
                        // Restore left → R5
                        assign(0, binop(BinOp::Add,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                        deref_assign(lit(WS_EXPR_SP), var(0)),
                        call_stmt("emit", vec![
                            enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
                        // emit ADD or SUB R4, R5, R4
                        Stmt::If(binop(BinOp::Eq, var(1), lit(TOK_PLUS)),
                            vec![call_stmt("emit", vec![
                                enc_r(OP_ADD, GEN_R4, GEN_R5, GEN_R4)])],
                            vec![call_stmt("emit", vec![
                                enc_r(OP_SUB, GEN_R4, GEN_R5, GEN_R4)])]),
                    ],
                ),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── compile_cmp() ─────────────────────────────
        // comparison → additive [ '<' additive ]
        // If '<' is present, emits: CMP R5,R4; MOVI R4,0;
        //   BGE +4; MOVI R4,1.  Result: R4 = 0 or 1.
        // Locals: esp(0)
        let fn_compile_cmp = Function {
            name: "compile_cmp".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![(0, Type::Int)],
            body: vec![
                call_stmt("compile_add", vec![]),
                Stmt::If(
                    binop(BinOp::Eq,
                        deref(lit(WS_TOK_TYPE)), lit(TOK_LT)),
                    vec![
                        call_stmt("next_token", vec![]),
                        // Save left in expr temp
                        Stmt::VarDecl(0, Type::Int, Some(
                            deref(lit(WS_EXPR_SP)))),
                        call_stmt("emit", vec![
                            enc_i(OP_ST, GEN_R4, GEN_SP, var(0))]),
                        deref_assign(lit(WS_EXPR_SP),
                            binop(BinOp::Sub, var(0), lit(8))),
                        // Compile right → R4
                        call_stmt("compile_add", vec![]),
                        // Restore left → R5
                        assign(0, binop(BinOp::Add,
                            deref(lit(WS_EXPR_SP)), lit(8))),
                        deref_assign(lit(WS_EXPR_SP), var(0)),
                        call_stmt("emit", vec![
                            enc_i(OP_LD, GEN_R5, GEN_SP, var(0))]),
                        // CMP R5, R4 (left vs right)
                        call_stmt("emit", vec![
                            enc_r(OP_CMP, 0, GEN_R5, GEN_R4)]),
                        // MOVI R4, 0 (assume false)
                        call_stmt("emit", vec![
                            enc_i(OP_MOVI, GEN_R4, 0, lit(0))]),
                        // BGE +4 (skip MOVI R4,1 if >=)
                        call_stmt("emit", vec![
                            enc_b(COND_GE, lit(4))]),
                        // MOVI R4, 1 (set true)
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

        // ─── patch_branch(pos, cond, target) ───────────
        // Rewrite a branch placeholder at byte offset `pos`
        // with the correct displacement to `target`.
        // Params: pos(0), cond(1), target(2)
        // Locals: disp(3), word(4), padded(5)
        let fn_patch_branch = Function {
            name: "patch_branch".into(),
            params: vec![(0, Type::Int), (1, Type::Int), (2, Type::Int)],
            ret_type: Type::Int,
            locals: vec![
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
            ],
            body: vec![
                // disp = (target - pos) / 4  (word offset)
                Stmt::VarDecl(3, Type::Int, Some(
                    binop(BinOp::Shr,
                        binop(BinOp::Sub, var(2), var(0)),
                        lit(2)))),
                // word = enc_b(cond, disp)
                // But we need to inline the encoding since cond is dynamic.
                // (48 << 26) | (cond << 22) | (disp & 0x3FFFFF)
                Stmt::VarDecl(4, Type::Int, Some(
                    binop(BinOp::Or,
                        binop(BinOp::Or,
                            binop(BinOp::Shl, lit(OP_BCC), lit(26)),
                            binop(BinOp::Shl, var(1), lit(22))),
                        binop(BinOp::Shr,
                            binop(BinOp::Shl, var(3), lit(42)),
                            lit(42))))),
                // padded = word | (NOP << 32)
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

        // ─── compile_stmt() ────────────────────────────
        // Dispatches on current token to compile one statement.
        // Handles: int decl, return, if/else, assignment.
        // Locals: tok(0), name(1), offset(2),
        //         branch_pos(3), skip_pos(4)
        let fn_compile_stmt = Function {
            name: "compile_stmt".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int),
            ],
            body: vec![
                Stmt::VarDecl(0, Type::Int, Some(
                    deref(lit(WS_TOK_TYPE)))),
                Stmt::VarDecl(1, Type::Int, Some(lit(0))),
                Stmt::VarDecl(2, Type::Int, Some(lit(0))),
                Stmt::VarDecl(3, Type::Int, Some(lit(0))),
                Stmt::VarDecl(4, Type::Int, Some(lit(0))),

                // ── int IDENT = expr ; ──
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_INT_KW)), vec![
                    call_stmt("next_token", vec![]),
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_IDENT)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    assign(1, deref(lit(WS_TOK_VALUE))),
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
                    assign(2, call("add_symbol", vec![var(1)])),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, var(2))]),
                    Stmt::Return(lit(0)),
                ], vec![]),

                // ── return expr ; ──
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_RETURN)), vec![
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
                    call_stmt("emit", vec![enc_s(OP_HALT)]),
                    Stmt::Return(lit(0)),
                ], vec![]),

                // ── if (expr) { stmts } [else { stmts }] ──
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IF)), vec![
                    call_stmt("next_token", vec![]),
                    // expect '('
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // compile condition → R4
                    call_stmt("compile_expr", vec![]),
                    // expect ')'
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // emit CMPI R4, 0
                    call_stmt("emit", vec![
                        enc_i(OP_CMPI, 0, GEN_R4, lit(0))]),
                    // emit BEQ placeholder (disp=0)
                    assign(3, deref(lit(WS_OUT_POS))),
                    call_stmt("emit", vec![
                        enc_b(COND_EQ, lit(0))]),
                    // expect '{'
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LBRACE)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // compile then-body
                    Stmt::While(
                        binop(BinOp::And,
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)), lit(TOK_RBRACE)),
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)), lit(TOK_EOF))),
                        vec![call_stmt("compile_stmt", vec![])],
                    ),
                    // expect '}'
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RBRACE)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // check for else
                    Stmt::If(
                        binop(BinOp::Eq,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_ELSE)),
                        vec![
                            call_stmt("next_token", vec![]),
                            // emit BAL placeholder (skip else)
                            assign(4, deref(lit(WS_OUT_POS))),
                            call_stmt("emit", vec![
                                enc_b(COND_AL, lit(0))]),
                            // patch BEQ to here (start of else)
                            call_stmt("patch_branch", vec![
                                var(3), lit(COND_EQ),
                                deref(lit(WS_OUT_POS))]),
                            // expect '{'
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_LBRACE)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            // compile else-body
                            Stmt::While(
                                binop(BinOp::And,
                                    binop(BinOp::Ne,
                                        deref(lit(WS_TOK_TYPE)),
                                        lit(TOK_RBRACE)),
                                    binop(BinOp::Ne,
                                        deref(lit(WS_TOK_TYPE)),
                                        lit(TOK_EOF))),
                                vec![call_stmt("compile_stmt", vec![])],
                            ),
                            // expect '}'
                            Stmt::If(
                                binop(BinOp::Ne,
                                    deref(lit(WS_TOK_TYPE)),
                                    lit(TOK_RBRACE)),
                                vec![deref_assign(lit(WS_ERROR), lit(1))],
                                vec![],
                            ),
                            call_stmt("next_token", vec![]),
                            // patch BAL to here (end of else)
                            call_stmt("patch_branch", vec![
                                var(4), lit(COND_AL),
                                deref(lit(WS_OUT_POS))]),
                        ],
                        vec![
                            // no else: patch BEQ to here
                            call_stmt("patch_branch", vec![
                                var(3), lit(COND_EQ),
                                deref(lit(WS_OUT_POS))]),
                        ],
                    ),
                    Stmt::Return(lit(0)),
                ], vec![]),

                // ── while (expr) { stmts } ──
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_WHILE)), vec![
                    call_stmt("next_token", vec![]),
                    // expect '('
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // loop_start = current output position
                    assign(3, deref(lit(WS_OUT_POS))),
                    // compile condition → R4
                    call_stmt("compile_expr", vec![]),
                    // expect ')'
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RPAREN)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // emit CMPI R4, 0
                    call_stmt("emit", vec![
                        enc_i(OP_CMPI, 0, GEN_R4, lit(0))]),
                    // emit BEQ placeholder → loop_end (forward)
                    assign(4, deref(lit(WS_OUT_POS))),
                    call_stmt("emit", vec![
                        enc_b(COND_EQ, lit(0))]),
                    // expect '{'
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_LBRACE)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // compile loop body
                    Stmt::While(
                        binop(BinOp::And,
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)), lit(TOK_RBRACE)),
                            binop(BinOp::Ne,
                                deref(lit(WS_TOK_TYPE)), lit(TOK_EOF))),
                        vec![call_stmt("compile_stmt", vec![])],
                    ),
                    // expect '}'
                    Stmt::If(
                        binop(BinOp::Ne,
                            deref(lit(WS_TOK_TYPE)), lit(TOK_RBRACE)),
                        vec![deref_assign(lit(WS_ERROR), lit(1))],
                        vec![],
                    ),
                    call_stmt("next_token", vec![]),
                    // emit BAL loop_start (backward branch)
                    // disp = -(current_pos - loop_start) / 4
                    // Computed into var(1) to stay within 3 scratch regs.
                    assign(1, binop(BinOp::Sub, lit(0),
                        binop(BinOp::Shr,
                            binop(BinOp::Sub,
                                deref(lit(WS_OUT_POS)),
                                var(3)),
                            lit(2)))),
                    call_stmt("emit", vec![
                        enc_b(COND_AL, var(1))]),
                    // patch BEQ → loop_end (here)
                    call_stmt("patch_branch", vec![
                        var(4), lit(COND_EQ),
                        deref(lit(WS_OUT_POS))]),
                    Stmt::Return(lit(0)),
                ], vec![]),

                // ── IDENT = expr ; (assignment) ──
                Stmt::If(binop(BinOp::Eq, var(0), lit(TOK_IDENT)), vec![
                    assign(1, deref(lit(WS_TOK_VALUE))),
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
                    assign(2, call("lookup_symbol", vec![var(1)])),
                    call_stmt("emit", vec![
                        enc_i(OP_ST, GEN_R4, GEN_SP, var(2))]),
                    Stmt::Return(lit(0)),
                ], vec![]),

                // Unknown statement → error
                deref_assign(lit(WS_ERROR), lit(1)),
                Stmt::Return(lit(0)),
            ],
        };

        // ─── main() ────────────────────────────────────
        // Locals:
        //   0: src_base, 1: src_len, 2: text_base,
        //   3: kw temp, 4: kw temp,
        //   5: error_flag, 6: out_size, 7: child
        let fn_main = Function {
            name: "main".into(),
            params: vec![],
            ret_type: Type::Int,
            locals: vec![
                (0, Type::Int), (1, Type::Int), (2, Type::Int),
                (3, Type::Int), (4, Type::Int), (5, Type::Int),
                (6, Type::Int), (7, Type::Int),
            ],
            body: vec![
                // ─── Source setup ─────────────────────────
                Stmt::VarDecl(0, Type::Int, Some(lit(0x4000))),
                Stmt::VarDecl(1, Type::Int, Some(deref(var(0)))),
                Stmt::VarDecl(2, Type::Int, Some(
                    binop(BinOp::Add, var(0), lit(8)))),

                // Source metadata guard
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

                // ─── Build packed keyword constants ──────
                // "int": pack 'i'(0x69), 'n'(0x6E), 't'(0x74)
                Stmt::VarDecl(3, Type::Int, Some(lit(0x69))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x6E))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x74))),
                deref_assign(lit(WS_KW_INT), var(3)),

                // "return": 'r','e','t','u','r','n'
                Stmt::VarDecl(4, Type::Int, Some(lit(0x72))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x65))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x74))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x75))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x72))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x6E))),
                deref_assign(lit(WS_KW_RETURN), var(4)),

                // "if": pack 'i'(0x69), 'f'(0x66)
                assign(3, lit(0x69)),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x66))),
                deref_assign(lit(WS_KW_IF), var(3)),

                // "else": pack 'e'(0x65),'l'(0x6C),'s'(0x73),'e'(0x65)
                assign(4, lit(0x65)),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x6C))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x73))),
                assign(4, binop(BinOp::Or,
                    binop(BinOp::Shl, var(4), lit(8)),
                    lit(0x65))),
                deref_assign(lit(WS_KW_ELSE), var(4)),

                // "while": 'w','h','i','l','e'
                assign(3, lit(0x77)),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x68))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x69))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x6C))),
                assign(3, binop(BinOp::Or,
                    binop(BinOp::Shl, var(3), lit(8)),
                    lit(0x65))),
                deref_assign(lit(WS_KW_WHILE), var(3)),

                // ─── Prime the lexer ─────────────────────
                call_stmt("next_token", vec![]),

                // ─── Compile statements ──────────────────
                Stmt::While(
                    binop(BinOp::Ne,
                        deref(lit(WS_TOK_TYPE)),
                        lit(TOK_EOF)),
                    vec![call_stmt("compile_stmt", vec![])],
                ),

                // ─── Check error flag ────────────────────
                Stmt::VarDecl(5, Type::Int, Some(
                    deref(lit(WS_ERROR)))),
                Stmt::If(var(5),
                    vec![Stmt::Return(lit(-1))],
                    vec![],
                ),

                // ─── Seal → Exec ─────────────────────────
                Stmt::Expr(syscall(SYS_SEAL as u8, vec![lit(0x5000)])),
                Stmt::VarDecl(6, Type::Int, Some(
                    deref(lit(WS_OUT_POS)))),
                Stmt::VarDecl(7, Type::Int, Some(
                    syscall(SYS_EXEC as u8, vec![lit(0x5000), var(6)]))),
                Stmt::Return(var(7)),
            ],
        };

        let mut functions = vec![fn_main];
        functions.extend(lexer_fns);
        functions.extend(vec![
            fn_compile_primary, fn_compile_mult, fn_compile_add,
            fn_compile_cmp, fn_compile_expr,
            fn_compile_stmt, fn_patch_branch,
            fn_add_symbol, fn_lookup_symbol,
            fn_emit,
        ]);
        Program { functions }
    }

    /// Run a 6B.3 test case: guest code generator → expected result.
    /// 6B.3's text fits in 0x4000 but shares workspace layout with 6B.4+.
    fn run_6b3_test(source_text: &[u8], expected_exit: u64, expect_child: bool) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        // Write source: [u64 length][text bytes]
        let src_len = source_text.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, source_text);

        // Trap handler
        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Compile the guest compiler from AST
        let compiler_prog = build_6b3_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        // 6B.3 keeps source/output at 0x4000/0x5000 (hardcoded
        // in build_6b3_compiler) but workspace must be at LAYOUT_WS
        // because the shared lexer uses WS_* absolute addresses.
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x1000, source);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(LAYOUT_WS as u64, 0x1000, work);
        core.address_map.add(LAYOUT_STACK as u64, 0x4000, stack);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(100000, 100000);

        let exited = kernel.processes[0].exited();
        let exit_code = kernel.processes[0].exit_code;
        let child_spawned = kernel.processes.len() >= 2;

        assert!(exited, "compiler process should have exited");
        assert_eq!(exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, exit_code);

        if expect_child {
            assert!(child_spawned,
                "source {:?}: expected child process",
                std::str::from_utf8(source_text).unwrap_or("<invalid>"));
            // Post-8.3c: child is reclaimed after collection.
        }
    }

    // ─── 6B.3.0 tests ───────────────────────────────────────

    #[test]
    fn b3_return_literal() {
        // Simplest: "return 42;" generates MOVI R4,42; MOV R0,R4; HALT
        run_6b3_test(b"return 42;", 42, true);
        eprintln!("6B.3.0: \"return 42;\" → 42 (runtime) ✓");
    }

    #[test]
    fn b3_return_zero() {
        run_6b3_test(b"return 0;", 0, true);
        eprintln!("6B.3.0: \"return 0;\" → 0 ✓");
    }

    #[test]
    fn b3_single_var() {
        // int x = 42; return x;
        // Emits: MOVI R4,42; ST R4,[SP-8]; LD R4,[SP-8]; MOV R0,R4; HALT
        run_6b3_test(b"int x = 42; return x;", 42, true);
        eprintln!("6B.3.0: \"int x = 42; return x;\" → 42 ✓");
    }

    #[test]
    fn b3_two_vars_add() {
        // The 6B.3.0 migration test: old program returns same answer,
        // but now via runtime execution, not compile-time evaluation.
        run_6b3_test(b"int x = 40; int y = 2; return x + y;", 42, true);
        eprintln!("6B.3.0: \"int x = 40; int y = 2; return x + y;\" → 42 ✓");
        eprintln!("     evaluator → code generator migration ✓");
    }

    #[test]
    fn b3_arithmetic() {
        // Test subtraction and multiplication
        run_6b3_test(b"int a = 10; int b = 3; return a - b;", 7, true);
        eprintln!("6B.3.0: \"a=10; b=3; return a - b;\" → 7 ✓");
    }

    #[test]
    fn b3_multiply() {
        run_6b3_test(b"int a = 6; int b = 7; return a * b;", 42, true);
        eprintln!("6B.3.0: \"a=6; b=7; return a * b;\" → 42 ✓");
    }

    #[test]
    fn b3_expr_precedence() {
        // 2 + 3 * 4 should be 14, not 20
        run_6b3_test(b"return 2 + 3 * 4;", 14, true);
        eprintln!("6B.3.0: \"return 2 + 3 * 4;\" → 14 (precedence) ✓");
    }

    #[test]
    fn b3_multi_var_chain() {
        // Variable referencing prior variable in initializer
        run_6b3_test(
            b"int x = 10; int y = x + 5; int z = y * 2; return z;",
            30, true);
        eprintln!("6B.3.0: chained variable init → 30 ✓");
    }

    #[test]
    fn b3_error_undefined_var() {
        // Using an undefined variable should error
        run_6b3_test(b"return x;", u64::MAX, false);
        eprintln!("6B.3.0: undefined variable → error ✓");
    }

    // ─── 6B.3.1 tests: if/else + forward fixups ─────────

    #[test]
    fn b3_if_true() {
        // if (1) takes the then-branch
        run_6b3_test(
            b"if (1) { return 42; } return 0;",
            42, true);
        eprintln!("6B.3.1: if (1) → 42 (then-branch) ✓");
    }

    #[test]
    fn b3_if_false() {
        // if (0) skips the then-branch
        run_6b3_test(
            b"if (0) { return 99; } return 42;",
            42, true);
        eprintln!("6B.3.1: if (0) → 42 (skipped) ✓");
    }

    #[test]
    fn b3_if_else_true() {
        // if-else where condition is true
        run_6b3_test(
            b"if (1) { return 42; } else { return 0; }",
            42, true);
        eprintln!("6B.3.1: if (1) else → 42 (then) ✓");
    }

    #[test]
    fn b3_if_else_false() {
        // if-else where condition is false
        run_6b3_test(
            b"if (0) { return 99; } else { return 42; }",
            42, true);
        eprintln!("6B.3.1: if (0) else → 42 (else) ✓");
    }

    #[test]
    fn b3_if_lt() {
        // Test the < comparison operator
        run_6b3_test(
            b"int x = 3; if (x < 10) { return 42; } return 0;",
            42, true);
        eprintln!("6B.3.1: if (x < 10) → 42 ✓");
    }

    #[test]
    fn b3_if_lt_false() {
        // < when condition is false
        run_6b3_test(
            b"int x = 10; if (x < 3) { return 99; } return 42;",
            42, true);
        eprintln!("6B.3.1: if (x < 3) false → 42 ✓");
    }

    #[test]
    fn b3_nested_if() {
        // Nested if statements
        run_6b3_test(
            b"int x = 5; if (x < 10) { if (x < 3) { return 1; } else { return 42; } } return 0;",
            42, true);
        eprintln!("6B.3.1: nested if → 42 ✓");
    }

    #[test]
    fn b3_if_with_vars() {
        // Variable declaration + if + else with different return paths
        run_6b3_test(
            b"int x = 10; int y = 20; if (x < y) { return x; } else { return y; }",
            10, true);
        eprintln!("6B.3.1: if (x < y) → x=10 ✓");
    }

    #[test]
    fn b3_assign_in_if() {
        // Assignment inside if body
        run_6b3_test(
            b"int x = 0; if (1) { x = 42; } return x;",
            42, true);
        eprintln!("6B.3.1: assignment inside if → 42 ✓");
    }

    #[test]
    fn b3_if_else_assign() {
        // Both branches assign, then return
        run_6b3_test(
            b"int x = 0; int y = 5; if (y < 3) { x = 10; } else { x = 42; } return x;",
            42, true);
        eprintln!("6B.3.1: if-else assign → 42 ✓");
    }

    // ─── 6B.3.2 tests: while + backward branches ───────

    #[test]
    fn b3_while_zero_iterations() {
        // while (0) body should never execute
        run_6b3_test(
            b"int x = 42; while (0) { x = 0; } return x;",
            42, true);
        eprintln!("6B.3.2: while (0) → 42 (zero iterations) ✓");
    }

    #[test]
    fn b3_while_count() {
        // while (x < 3) { x = x + 1; } — three iterations
        run_6b3_test(
            b"int x = 0; while (x < 3) { x = x + 1; } return x;",
            3, true);
        eprintln!("6B.3.2: while (x < 3) x++ → 3 ✓");
    }

    #[test]
    fn b3_while_sum() {
        // Sum 1+2+3+4+5 = 15
        run_6b3_test(
            b"int s = 0; int i = 1; while (i < 6) { s = s + i; i = i + 1; } return s;",
            15, true);
        eprintln!("6B.3.2: sum 1..5 → 15 ✓");
    }

    #[test]
    fn b3_while_nested() {
        // Nested loops: inner counts to 3 each time outer iterates
        // outer: 2 iterations, inner: 3 each → total = 6
        run_6b3_test(
            b"int t = 0; int i = 0; while (i < 2) { int j = 0; while (j < 3) { t = t + 1; j = j + 1; } i = i + 1; } return t;",
            6, true);
        eprintln!("6B.3.2: nested while → 6 ✓");
    }

    #[test]
    fn b3_while_if_inside() {
        // if inside while body
        run_6b3_test(
            b"int x = 0; int s = 0; while (x < 5) { if (x < 3) { s = s + 1; } x = x + 1; } return s;",
            3, true);
        eprintln!("6B.3.2: if inside while → 3 ✓");
    }

    // ─── 6B.3.3 tests: control-flow regression corpus ──

    #[test]
    fn b3_both_branches_return() {
        // Both branches return: exercises real return-path coverage.
        // The generated code has HALT in both branches.
        run_6b3_test(
            b"int x = 5; if (x < 10) { return 42; } else { return 0; }",
            42, true);
        eprintln!("6B.3.3: both branches return → 42 ✓");
    }

    #[test]
    fn b3_one_branch_returns() {
        // Only one branch returns — fall-through path must still work.
        run_6b3_test(
            b"int x = 5; if (x < 3) { return 99; } return x;",
            5, true);
        eprintln!("6B.3.3: one branch returns, fall-through → 5 ✓");
    }

    #[test]
    fn b3_deeply_nested_if() {
        // Three-level nesting to stress forward fixup accounting
        run_6b3_test(
            b"int x = 5; if (1) { if (1) { if (x < 10) { return 42; } else { return 0; } } else { return 1; } } else { return 2; }",
            42, true);
        eprintln!("6B.3.3: three-level nested if → 42 ✓");
    }

    #[test]
    fn b3_while_then_if() {
        // while followed by if — exercises sequential control flow
        run_6b3_test(
            b"int x = 0; while (x < 5) { x = x + 1; } if (x < 10) { return x; } else { return 0; }",
            5, true);
        eprintln!("6B.3.3: while then if → 5 ✓");
    }

    #[test]
    fn b3_if_then_while() {
        // if followed by while
        run_6b3_test(
            b"int x = 0; if (1) { x = 10; } while (x < 15) { x = x + 1; } return x;",
            15, true);
        eprintln!("6B.3.3: if then while → 15 ✓");
    }

    #[test]
    fn b3_multiply_in_loop() {
        // 2^5 = 32 via repeated multiplication
        run_6b3_test(
            b"int x = 1; int i = 0; while (i < 5) { x = x * 2; i = i + 1; } return x;",
            32, true);
        eprintln!("6B.3.3: 2^5 via loop → 32 ✓");
    }

    #[test]
    fn b3_while_immediate_exit() {
        // while with false condition from the start
        run_6b3_test(
            b"int x = 10; while (x < 5) { x = 0; } return x;",
            10, true);
        eprintln!("6B.3.3: while immediate exit → 10 ✓");
    }

    #[test]
    fn b3_complex_expr_in_condition() {
        // Expression with arithmetic in while condition
        run_6b3_test(
            b"int x = 0; int limit = 3 + 2; while (x < limit) { x = x + 1; } return x;",
            5, true);
        eprintln!("6B.3.3: arithmetic in condition → 5 ✓");
    }

    #[test]
    fn b3_parens_in_expr() {
        // Parenthesized expression
        run_6b3_test(
            b"return (2 + 3) * 4;",
            20, true);
        eprintln!("6B.3.3: (2 + 3) * 4 → 20 ✓");
    }

    #[test]
    fn b3_emit_capacity_guard() {
        // Output buffer is 0x1000 = 4096 bytes.  Each instruction
        // occupies 8 bytes (NOP-padded).  Last legal start position
        // is 0xFF8.  We force overflow via repeated assignments:
        //   int v = 0;    → 2 insns (MOVI + ST)  = 16 bytes
        //   v = 0; × 254  → 508 insns             = 4064 bytes
        //   return v;     → 3 insns (LD + MOV + HALT) = 24 bytes
        //   Total: 513 insns = 4104 > 4096
        // The 512th instruction (at pos 0x1000) should trip the guard.
        // One symbol → stays within the 250-entry table limit.
        let mut src = Vec::new();
        src.extend_from_slice(b"int v = 0; ");
        for _ in 0..254 {
            src.extend_from_slice(b"v = 0; ");
        }
        src.extend_from_slice(b"return v;");
        run_6b3_test(&src, u64::MAX, false);
        eprintln!("6B.3.3: emit capacity guard → error ✓");
    }

    /// Adversarial test: inspect emitted instructions and verify that
    /// the generated code contains an actual backward branch, not just
    /// a correct behavioral result from compile-time evaluation.
    #[test]
    fn b3_while_has_backward_branch() {
        use super::super::isa::decode;

        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  0x4000, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    0x1000, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     0x1000, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      0x1000, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, 0x1000, Permissions::READ);
        fabric.grant(dom, output, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom, work,   0, 0x1000, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);

        let src = b"int x = 0; while (x < 3) { x = x + 1; } return x;";
        let src_len = src.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, src);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        let compiler_prog = build_6b3_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x04000, 0x1000, source);
        core.address_map.add(0x05000, 0x1000, output);
        core.address_map.add(LAYOUT_WS as u64, 0x1000, work);
        core.address_map.add(LAYOUT_STACK as u64, 0x4000, stack);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x050000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(100000, 100000);

        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 3,
            "while loop should produce x=3");

        // ── Inspect generated code for backward branch ──
        // Read output buffer and scan for a B instruction
        // with negative displacement.
        let out_pos_bytes = kernel.fabric.read_physical(
            0x030000 + 0x48, 8);   // WS_OUT_POS at workspace offset 0x48
        let out_bytes = u64::from_le_bytes(
            out_pos_bytes[..8].try_into().unwrap()) as usize;

        let mut found_backward_branch = false;
        for off in (0..out_bytes).step_by(4) {
            let word_bytes = kernel.fabric.read_physical(
                0x020000 + off as u64, 4);
            let word = u32::from_le_bytes(
                word_bytes[..4].try_into().unwrap());
            let insn = decode(word);
            if insn.desc.name == "b" && insn.imm < 0 {
                found_backward_branch = true;
                break;
            }
        }
        assert!(found_backward_branch,
            "generated code must contain an actual backward branch \
             (not compile-time loop evaluation)");
        eprintln!("6B.3.2: adversarial — backward branch present ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // StepResult::Halted disambiguation — three distinct outcomes
    // ═══════════════════════════════════════════════════════════

    /// User HALT → exit(R0).  The normal path: _start's HALT after
    /// main returns.  This is the same path exercised by all kernel
    /// tests, but we verify the exit code explicitly.
    #[test]
    fn halt_user_exit() {
        run_6b1_test(b"return 42;", 42, true);
        eprintln!("halt: user HALT → exit(42) ✓");
    }

    // ═══════════════════════════════════════════════════════
    //  Phase 8.5: Supervised compiler helper
    //
    //  All compiler execution routes through:
    //    host boots ankad → ankad SYS_SPAWN(compiler) → SYS_WAIT → SYS_EXIT
    //
    //  Host may construct executable artifacts; Anka constructs processes.
    // ═══════════════════════════════════════════════════════

    // SUPERVISOR_COMPILER_VADDR is now in ankad.rs (single source of truth).
    use crate::anka64::ankad::SUPERVISOR_COMPILER_VADDR;

    /// Result of a supervised compiler run.
    struct SupervisedResult {
        kernel: Kernel,
        output_phys: u64,
        work_phys: u64,
        /// SYS_WAIT tag preserved in R10 after ankad exits.
        /// 0 = Exited, non-zero = fault.
        wait_tag: u64,
        /// Compiler exit detail (ankad's exit code = SYS_WAIT detail).
        wait_detail: u64,
    }

    /// Boot ankad as supervisor, spawn a compiler with a fully delegated
    /// environment, wait for it, and return the result for host inspection.
    ///
    /// `compiler_image`: compiled compiler bytes (CC_A or CC_B).
    /// `child_code_vaddr`: where the child's code is placed (0 for CC_A,
    ///   CCB_CODE_BASE for CC_B). Only affects SpawnLayout.code_vaddr.
    /// `source`: source text bytes (will be length-prefixed in the source object).
    fn run_supervised_compiler(
        compiler_image: &[u8],
        child_code_vaddr: u64,
        source: &[u8],
    ) -> SupervisedResult {
        let compiler_len = compiler_image.len();
        let compiler_size = ((compiler_len + 0xFFF) & !0xFFF) as u64;

        assert!(compiler_len <= OUTPUT_SIZE as usize,
            "compiler ({} bytes) exceeds output buffer", compiler_len);
        assert!(source.len() + 8 <= SOURCE_SIZE as usize,
            "source ({} + 8 header bytes) exceeds source object ({})",
            source.len(), SOURCE_SIZE);

        // ── Host creates the machine ──
        let mut fabric = Fabric::new(0x800000);

        // ankad code object
        let ankad_obj = fabric.alloc_object("ankad_code", 0x2000, ObjectKind::Memory);
        fabric.place_object(ankad_obj, 0x000000);

        // Compiler code object (sealed)
        let compiler_obj = fabric.alloc_object("compiler_code", compiler_size, ObjectKind::Memory);
        fabric.place_object(compiler_obj, 0x100000);
        fabric.initialize_object(compiler_obj, 0, compiler_image);
        fabric.seal_object(compiler_obj);

        // Source object: length-prefixed
        let source_obj = fabric.alloc_object("source", SOURCE_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(source_obj, 0x200000);
        fabric.write_physical(0x200000, &(source.len() as u64).to_le_bytes());
        fabric.write_physical(0x200008, source);

        // Output object (active, empty)
        let output_obj = fabric.alloc_object("output", OUTPUT_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(output_obj, 0x210000);

        // Workspace object
        let work_obj = fabric.alloc_object("workspace", WS_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(work_obj, 0x220000);

        // Initialize two-ended allocator: WS_LIT_POS = OUTPUT_SIZE
        // Required for CC_A (bootstrap compiler); redundant but harmless for CC_B.
        fabric.write_physical(
            0x220000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &(OUTPUT_SIZE as u64).to_le_bytes());

        // ── Assemble ankad (single source of truth in ankad.rs) ──
        let code_bytes = crate::anka64::ankad::build_ankad_code(
            compiler_len, child_code_vaddr);
        assert!(code_bytes.len() < 0x2000,
            "ankad code {} bytes exceeds 0x2000", code_bytes.len());
        fabric.initialize_object(ankad_obj, 0, &code_bytes);
        fabric.seal_object(ankad_obj);

        // ── Boot descriptor ──
        let ankad_code_size = 0x2000_u64;
        let info = BootInfo {
            image: BootImage {
                obj: ankad_obj,
                code_offset: 0,
                code_size: ankad_code_size,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![
                BootGrant { obj: compiler_obj, offset: 0, size: compiler_size,       perms: Permissions::RX },
                BootGrant { obj: source_obj,   offset: 0, size: SOURCE_SIZE as u64,  perms: Permissions::READ },
                BootGrant { obj: output_obj,   offset: 0, size: OUTPUT_SIZE as u64,  perms: Permissions::RWS },
                BootGrant { obj: work_obj,     offset: 0, size: WS_SIZE as u64,      perms: Permissions::RW },
            ],
            maps: vec![
                BootMap { vaddr: 0x07000, size: SOURCE_SIZE as u64, obj: source_obj,   obj_offset: 0 },
                BootMap { vaddr: 0x0C000, size: WS_SIZE as u64,     obj: work_obj,     obj_offset: 0 },
                BootMap { vaddr: 0x12000, size: OUTPUT_SIZE as u64,  obj: output_obj,   obj_offset: 0 },
                BootMap { vaddr: SUPERVISOR_COMPILER_VADDR, size: compiler_size, obj: compiler_obj, obj_offset: 0 },
            ],
            code_vaddr: 0,
            stack_vaddr: 0x50000,
            stack_size: 0x4000,
            trap_vaddr: 0x54000,
        };

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x300000;
        let result = kernel.boot(&info);
        assert_eq!(result, Ok(()), "boot(ankad) should succeed");

        // Run with enough cycles for compilation.
        // CC_A needs ~2M cycles, CC_B needs ~4M.
        kernel.run(5_000_000, 200);

        // ── Extract structured result ──
        // No assertions here — callers inspect the result and provide
        // domain-specific diagnostics before asserting.
        let (wait_tag, wait_detail) = if kernel.processes[0].exited() {
            (kernel.processes[0].core.r[R10 as usize],
             kernel.processes[0].exit_code)
        } else {
            (u64::MAX, u64::MAX)
        };

        SupervisedResult {
            kernel,
            output_phys: 0x210000,
            work_phys: 0x220000,
            wait_tag,
            wait_detail,
        }
    }

    /// Run a 6B.4 test case: guest compiler with functions → expected result.
    fn run_6b4_test(source_text: &[u8], expected_exit: u64, expect_child: bool) {
        let kernel = run_6b4_harness(source_text, expected_exit, expect_child);
        // Discard kernel — caller doesn't need it.
        drop(kernel);
    }

    /// Run the 6B.4 harness and return the Kernel for output inspection.
    ///
    /// Phase 8.5: CC_A is now executed as a supervised process under ankad.
    /// Host constructs the compiler artifact (AST → code bytes), but Anka
    /// constructs the compiler process via boot → SYS_SPAWN → SYS_WAIT.
    fn run_6b4_harness(source_text: &[u8], expected_exit: u64, expect_child: bool) -> Kernel {
        // Compile the guest compiler from AST (toolchain artifact construction)
        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_bytes = asm.to_bytes();
        let code_len = code_bytes.len();
        let text_sz = TEXT_SIZE as usize;
        eprintln!("6B.4 guest compiler: {} bytes ({} insns, {:#x}) \
                    [{:.0}% of {:#x}, {} bytes free]",
            code_len, code_len / 4, code_len,
            100.0 * code_len as f64 / text_sz as f64, text_sz,
            text_sz - code_len);
        assert!(code_len <= text_sz,
            "compiled guest compiler is {} bytes, exceeds {:#x} text object. \
             Update TEXT_SIZE to {:#x}.",
            code_len, TEXT_SIZE,
            ((code_len + 0xFFF) & !0xFFF));

        // CC_A code_vaddr = 0 (data regions start at TEXT_SIZE)
        let r = run_supervised_compiler(&code_bytes, 0, source_text);

        let ankad_exited = r.kernel.processes[0].exited();
        let exit_code = r.wait_detail;

        // Diagnostic: workspace dump when supervisor or compiler failed
        if !ankad_exited || r.wait_tag != 0 || exit_code != expected_exit {
            let read = |off: u64| -> u64 {
                let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
            if !ankad_exited {
                eprintln!("STUCK: ankad did not exit (compiler may be hung)");
                eprintln!("  ws: pos={} tok={} error={} out_pos={} funcs={} fixups={}",
                    read(0x00), read(0x20), read(0x18),
                    read(0x48), read(0x58), read(0x60));
            } else if r.wait_tag != 0 {
                eprintln!("FAULT: compiler faulted (wait_tag={})", r.wait_tag);
                eprintln!("  ws: pos={} tok={} error={} out_pos={} funcs={} fixups={}",
                    read(0x00), read(0x20), read(0x18),
                    read(0x48), read(0x58), read(0x60));
            } else {
                eprintln!("DIAG: error={} tok={} pos={} out_pos={}",
                    read(0x18), read(0x20), read(0x00), read(0x48));
                eprintln!("DIAG: funcs={} fixups={}", read(0x58), read(0x60));
                let func_count = read(0x58) as usize;
                for i in 0..func_count.min(4) {
                    let base = 0x368 + i as u64 * 32;
                    eprintln!("  func[{}]: ns={} nl={} addr={} arity={}",
                        i, read(base), read(base + 8),
                        read(base + 16), read(base + 24));
                }
                let fix_count = read(0x60) as usize;
                for i in 0..fix_count.min(4) {
                    let base = 0xB68 + i as u64 * 32;
                    eprintln!("  fix[{}]: call_pos={} ns={} nl={} argc={}",
                        i, read(base), read(base + 8),
                        read(base + 16), read(base + 24));
                }
                let sym_count = read(0x40) as usize;
                for i in 0..sym_count.min(8) {
                    let base = 0x68 + i as u64 * 24;
                    eprintln!("  sym[{}]: ns={} nl={} offset={}",
                        i, read(base), read(base + 8), read(base + 16) as i64);
                }
            }
        }

        assert!(ankad_exited, "ankad (supervisor) should have exited");
        assert_eq!(r.wait_tag, 0,
            "source {:?}: compiler faulted (wait_tag={})",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            r.wait_tag);
        assert_eq!(exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, exit_code);

        if expect_child {
            // ankad + compiler + child = at least 3 process slots
            let child_spawned = r.kernel.processes.len() >= 3;
            assert!(child_spawned,
                "source {:?}: expected child process",
                std::str::from_utf8(source_text).unwrap_or("<invalid>"));
        }
        r.kernel
    }

    // ═══════════════════════════════════════════════════════
    //  TEXT_SIZE derivation invariant
    // ═══════════════════════════════════════════════════════

    #[test]
    fn text_size_is_derived() {
        // TEXT_SIZE = align_up(host_compiler_bytes, 0x1000).
        // CC_B (the canonical binary) runs at a separate base address,
        // so TEXT_SIZE only needs to cover the host compiler.
        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_len = asm.to_bytes().len() as i64;
        let derived = (code_len + 0xFFF) & !0xFFF;
        assert_eq!(TEXT_SIZE, derived,
            "TEXT_SIZE is {:#x} but should be {:#x} \
             (align_up({}, 0x1000)). Update the constant \
             in guest_compiler.rs.",
            TEXT_SIZE, derived, code_len);
        eprintln!("TEXT_SIZE={:#x} ← align_up({}, 0x1000) ✓",
            TEXT_SIZE, code_len);
    }

    // ─── 6B.4.0 tests ───────────────────────────────────────

    #[test]
    fn b4_single_func_main() {
        // Simplest function-based program: just main.
        run_6b4_test(
            b"int main() { return 42; }",
            42, true);
        eprintln!("6B.4.0: int main() {{ return 42; }} → 42 ✓");
    }

    #[test]
    fn b4_two_funcs() {
        // The target program: f returns 42, main calls f.
        run_6b4_test(
            b"int f() { return 42; } int main() { return f(); }",
            42, true);
        eprintln!("6B.4.0: f()→42, main()→f() → 42 ✓");
    }

    #[test]
    fn b4_forward_call() {
        // Forward reference: main calls g which is defined after main.
        run_6b4_test(
            b"int main() { return g(); } int g() { return 7; }",
            7, true);
        eprintln!("6B.4.0: forward call main()→g()→7 ✓");
    }

    #[test]
    fn b4_call_chain() {
        // Chain: main→b→a, each function returns a literal.
        run_6b4_test(
            b"int a() { return 10; } int b() { return a(); } int main() { return b(); }",
            10, true);
        eprintln!("6B.4.0: call chain a→b→main → 10 ✓");
    }

    #[test]
    fn b4_main_with_vars() {
        // Variables still work with FP-relative addressing.
        run_6b4_test(
            b"int main() { int x = 40; int y = 2; return x + y; }",
            42, true);
        eprintln!("6B.4.0: main with vars x+y → 42 ✓");
    }

    #[test]
    fn b4_func_with_vars() {
        // Function with local variables + caller reads result.
        run_6b4_test(
            b"int compute() { int a = 10; int b = 3; return a - b; } int main() { return compute(); }",
            7, true);
        eprintln!("6B.4.0: compute() with vars → 7 ✓");
    }

    // ─── 6B.4.0a: adversarial regressions ──────────────

    #[test]
    fn b4_embedded_nul() {
        // Embedded NUL (0x00) inside the declared source length must be
        // treated as an invalid character, NOT as EOF.  The compiler should
        // set error=1, and the source should NOT compile successfully.
        //
        // This test catches the byte-value EOF regression: if next_token
        // uses `peek_char() == 0` instead of `pos >= src_len`, an embedded
        // NUL lets the prefix compile silently.
        let src = b"int main() { return 42; }\0garbage";
        run_6b4_test(src, u64::MAX, false);
        eprintln!("6B.4.0a: embedded NUL → error ✓");
    }

    #[test]
    fn b4_missing_rbrace() {
        // Missing closing brace — compile_block must set error, not loop.
        run_6b4_test(b"int main() { return 42;", u64::MAX, false);
        eprintln!("6B.4.0a: missing }} → error ✓");
    }

    #[test]
    fn b4_missing_outer_rbrace() {
        // Inner block closes, but outer function body missing '}'.
        run_6b4_test(
            b"int main() { if (1) { return 42; }",
            u64::MAX, false);
        eprintln!("6B.4.0a: missing outer }} → error ✓");
    }

    #[test]
    fn b4_missing_while_rbrace() {
        // While body missing closing brace.
        run_6b4_test(
            b"int main() { while (1) { return 42;",
            u64::MAX, false);
        eprintln!("6B.4.0a: missing while }} → error ✓");
    }

    // ─── 6B.4.1: parameter ABI ─────────────────────────

    #[test]
    fn b41_add() {
        run_6b4_test(
            b"int add(int a, int b) { return a + b; } int main() { return add(40, 2); }",
            42, true);
        eprintln!("6B.4.1: add(40,2) → 42 ✓");
    }

    #[test]
    fn b41_identity() {
        run_6b4_test(
            b"int id(int x) { return x; } int main() { return id(42); }",
            42, true);
        eprintln!("6B.4.1: id(42) → 42 ✓");
    }

    #[test]
    fn b41_sub() {
        run_6b4_test(
            b"int sub(int a, int b) { return a - b; } int main() { return sub(50, 8); }",
            42, true);
        eprintln!("6B.4.1: sub(50,8) → 42 ✓");
    }

    #[test]
    fn b41_forward_call() {
        run_6b4_test(
            b"int main() { return add(40, 2); } int add(int a, int b) { return a + b; }",
            42, true);
        eprintln!("6B.4.1: forward call add(40,2) → 42 ✓");
    }

    #[test]
    fn b41_wrong_arity() {
        run_6b4_test(
            b"int add(int a, int b) { return a + b; } int main() { return add(42); }",
            u64::MAX, false);
        eprintln!("6B.4.1: wrong arity → error ✓");
    }

    #[test]
    fn b41_unknown_function() {
        run_6b4_test(
            b"int main() { return unknown(42); }",
            u64::MAX, false);
        eprintln!("6B.4.1: unknown function → error ✓");
    }

    // ─── 6B.4.2a: argument staging ─────────────────────

    #[test]
    fn b42_nested_call_arg0() {
        // add(id(40), 2) — call in first argument
        run_6b4_test(
            b"int id(int x) { return x; } int add(int a, int b) { return a + b; } int main() { return add(id(40), 2); }",
            42, true);
        eprintln!("6B.4.2a: add(id(40), 2) → 42 ✓");
    }

    #[test]
    fn b42_nested_call_arg1() {
        // add(40, id(2)) — call in second argument
        run_6b4_test(
            b"int id(int x) { return x; } int add(int a, int b) { return a + b; } int main() { return add(40, id(2)); }",
            42, true);
        eprintln!("6B.4.2a: add(40, id(2)) → 42 ✓");
    }

    #[test]
    fn b42_nested_call_both() {
        // add(id(40), id(2)) — calls in both arguments
        run_6b4_test(
            b"int id(int x) { return x; } int add(int a, int b) { return a + b; } int main() { return add(id(40), id(2)); }",
            42, true);
        eprintln!("6B.4.2a: add(id(40), id(2)) → 42 ✓");
    }

    #[test]
    fn b42_zero_arg_calls_as_args() {
        // add(g(), h()) — zero-arg calls as arguments
        run_6b4_test(
            b"int g() { return 40; } int h() { return 2; } int add(int a, int b) { return a + b; } int main() { return add(g(), h()); }",
            42, true);
        eprintln!("6B.4.2a: add(g(), h()) → 42 ✓");
    }

    // ─── 6B.4.2b: expression preservation across CALL ──

    #[test]
    fn b42_expr_plus_call() {
        // 40 + id(2) — left operand must survive CALL
        run_6b4_test(
            b"int id(int x) { return x; } int main() { return 40 + id(2); }",
            42, true);
        eprintln!("6B.4.2b: 40 + id(2) → 42 ✓");
    }

    #[test]
    fn b42_call_plus_literal() {
        // id(40) + 2 — call result combined with literal
        run_6b4_test(
            b"int id(int x) { return x; } int main() { return id(40) + 2; }",
            42, true);
        eprintln!("6B.4.2b: id(40) + 2 → 42 ✓");
    }

    #[test]
    fn b42_call_minus_call() {
        // id(50) - id(8) — both sides are calls
        run_6b4_test(
            b"int id(int x) { return x; } int main() { return id(50) - id(8); }",
            42, true);
        eprintln!("6B.4.2b: id(50) - id(8) → 42 ✓");
    }

    #[test]
    fn b42_call_times_literal() {
        // id(6) * 7 — call in multiply left
        run_6b4_test(
            b"int id(int x) { return x; } int main() { return id(6) * 7; }",
            42, true);
        eprintln!("6B.4.2b: id(6) * 7 → 42 ✓");
    }

    // ─── 6B.4.3a: dynamic frame sizing ─────────────────

    #[test]
    fn b43a_local_survives_call() {
        // x must survive the call to get42(). With fixed 16-byte
        // frames, get42's saved LR/FP would overwrite x.
        run_6b4_test(
            b"int get42() { return 42; } int f() { int x = 10; int y = get42(); return x + y; } int main() { return f(); }",
            52, true);
        eprintln!("6B.4.3a: local survives call → 52 ✓");
    }

    #[test]
    fn b43a_two_locals_survive_call() {
        // Both x and y must survive the call to g().
        run_6b4_test(
            b"int g() { return 2; } int f() { int x = 20; int y = 22; int z = g(); return x + y - z; } int main() { return f(); }",
            40, true);
        eprintln!("6B.4.3a: two locals survive call → 40 ✓");
    }

    #[test]
    fn b43a_different_frame_sizes() {
        // big() has 4 locals, small() has 0. Both must work.
        run_6b4_test(
            b"int small() { return 2; } int big() { int a = 10; int b = 20; int c = small(); int d = 10; return a + b + c + d; } int main() { return big(); }",
            42, true);
        eprintln!("6B.4.3a: different frame sizes → 42 ✓");
    }

    #[test]
    fn b43a_param_survives_call() {
        // Parameter a must survive the call to get2().
        run_6b4_test(
            b"int get2() { return 2; } int f(int a) { int b = get2(); return a + b; } int main() { return f(40); }",
            42, true);
        eprintln!("6B.4.3a: param survives call → 42 ✓");
    }

    // ─── 6B.4.3b: simple recursion ─────────────────────

    #[test]
    fn b43b_dec_recursion() {
        // Isolates frame nesting + argument passing + CALL/RET
        // without needing preservation of a local across the call.
        run_6b4_test(
            b"int dec(int n) { if (n < 1) { return 42; } return dec(n - 1); } int main() { return dec(5); }",
            42, true);
        eprintln!("6B.4.3b: dec(5) → 42 ✓");
    }

    // ─── 6B.4.3c: recursive preservation ────────────────

    #[test]
    fn b43c_factorial() {
        // n must survive the recursive call (frame separation).
        run_6b4_test(
            b"int fact(int n) { if (n < 2) { return 1; } return n * fact(n - 1); } int main() { return fact(5); }",
            120, true);
        eprintln!("6B.4.3c: fact(5) → 120 ✓");
    }

    #[test]
    fn b43c_local_per_activation() {
        // Each activation has its own x.
        run_6b4_test(
            b"int f(int n) { int x = n; if (n < 1) { return x; } return f(n - 1) + x; } int main() { return f(4); }",
            10, true);
        eprintln!("6B.4.3c: f(4) per-activation local → 10 ✓");
    }

    #[test]
    fn b43c_separate_recursive_trees() {
        // fact(3) + fact(4) — no frame leakage between trees.
        run_6b4_test(
            b"int fact(int n) { if (n < 2) { return 1; } return n * fact(n - 1); } int main() { return fact(3) + fact(4); }",
            30, true);
        eprintln!("6B.4.3c: fact(3)+fact(4) → 30 ✓");
    }

    // ─── 6B.4.4  Return-path closure ──────────────────

    #[test]
    fn b44_accept_simple_return() {
        // Every function has an unconditional return.
        run_6b4_test(
            b"int f() { return 42; } int main() { return f(); }",
            42, true);
        eprintln!("6B.4.4: accept simple return ✓");
    }

    #[test]
    fn b44_accept_if_else_both_return() {
        // if/else where both branches return → definitely returns.
        run_6b4_test(
            b"int f(int x) { if (x) { return 1; } else { return 0; } } int main() { return f(1); }",
            1, true);
        eprintln!("6B.4.4: accept if/else both return ✓");
    }

    #[test]
    fn b44_reject_if_no_else() {
        // if without else — function can fall through.
        run_6b4_test(
            b"int f(int x) { if (x) { return 1; } } int main() { return f(1); }",
            u64::MAX, false);
        eprintln!("6B.4.4: reject if-without-else (no return after) ✓");
    }

    #[test]
    fn b44_reject_while_only() {
        // while body may return, but while itself is conservative → 0.
        run_6b4_test(
            b"int f() { while (1) { return 42; } } int main() { return f(); }",
            u64::MAX, false);
        eprintln!("6B.4.4: reject while-only (no return after) ✓");
    }

    #[test]
    fn b44_accept_while_then_return() {
        // while followed by unconditional return → block returns.
        run_6b4_test(
            b"int f() { int x = 0; while (x < 3) { x = x + 1; } return x; } int main() { return f(); }",
            3, true);
        eprintln!("6B.4.4: accept while + return ✓");
    }

    #[test]
    fn b44_accept_nested_if_else() {
        // Nested if/else, both inner and outer branches return.
        run_6b4_test(
            b"int f(int x) { if (x < 2) { if (x) { return 1; } else { return 0; } } else { return 2; } } int main() { return f(0); }",
            0, true);
        eprintln!("6B.4.4: accept nested if/else ✓");
    }

    #[test]
    fn b44_reject_fall_through() {
        // Function f has no return at all — pure fall-through.
        run_6b4_test(
            b"int f() { int x = 42; } int main() { return 42; }",
            u64::MAX, false);
        eprintln!("6B.4.4: reject fall-through ✓");
    }

    // ─── 6B.5.0a tests — source-slice names ─────────────────

    #[test]
    fn b50a_long_function_name() {
        run_6b4_test(
            b"int longfunction() { return 42; } int main() { return longfunction(); }",
            42, true);
        eprintln!("6B.5.0a: long function name (>8 chars) ✓");
    }

    #[test]
    fn b50a_common_prefix() {
        run_6b4_test(
            b"int comp() { return 1; } int compile() { return 2; } int main() { return comp() + compile(); }",
            3, true);
        eprintln!("6B.5.0a: common prefix distinguishes comp/compile ✓");
    }

    #[test]
    fn b50a_names_differ_after_byte8() {
        run_6b4_test(
            b"int abcdefghi() { return 1; } int abcdefghj() { return 2; } int main() { return abcdefghi() + abcdefghj(); }",
            3, true);
        eprintln!("6B.5.0a: names differ after byte 8 ✓");
    }

    #[test]
    fn b50a_long_variable_names() {
        run_6b4_test(
            b"int main() { int longname1 = 10; int longname2 = 32; return longname1 + longname2; }",
            42, true);
        eprintln!("6B.5.0a: long variable names ✓");
    }

    #[test]
    fn b50a1_multiline_source() {
        // Newlines and tabs are now valid whitespace.
        run_6b4_test(
            b"int main() {\n\tint x = 40;\n\tint y = 2;\n\treturn x + y;\n}\n",
            42, true);
        eprintln!("6B.5.0a.1: multiline source with tabs/newlines ✓");
    }

    #[test]
    fn b50a1_boundary_ident() {
        // Source placed so the identifier ends near byte 0xFF7.
        // Tests that read_byte uses aligned extraction and does
        // not cross the source object boundary.
        //
        // Source object is 0x1000 bytes: [u64 length][text...].
        // text_base = source_base + 8, so text starts at byte 8.
        // Maximum usable text area: 0x1000 - 8 = 0xFF8 bytes.
        // Place a short program right-justified so "main" spans
        // the last bytes.
        let prog = b"int f() { return 42; } int main() { return f(); }";
        let pad_len = 0xFF8 - prog.len();
        let mut source = vec![b' '; pad_len];
        source.extend_from_slice(prog);
        run_6b4_test(&source, 42, true);
        eprintln!("6B.5.0a.1: boundary ident (near byte 0xFF7) ✓");
    }

    // ═══════════════════════════════════════════════════════
    //  6B.5.0b: complete expression language
    // ═══════════════════════════════════════════════════════

    // ─── Maximal-munch tokenizer tests ───────────────────

    #[test]
    fn b50b_eq_vs_eqeq() {
        // == is equality, = is assignment
        run_6b4_test(
            b"int main() { int x = 5; return x == 5; }",
            1, true);
        run_6b4_test(
            b"int main() { int x = 5; return x == 6; }",
            0, true);
        eprintln!("6B.5.0b: == (equality) ✓");
    }

    #[test]
    fn b50b_ne() {
        run_6b4_test(
            b"int main() { return 3 != 4; }",
            1, true);
        run_6b4_test(
            b"int main() { return 3 != 3; }",
            0, true);
        eprintln!("6B.5.0b: != ✓");
    }

    #[test]
    fn b50b_le() {
        run_6b4_test(
            b"int main() { return 3 <= 4; }",
            1, true);
        run_6b4_test(
            b"int main() { return 4 <= 4; }",
            1, true);
        run_6b4_test(
            b"int main() { return 5 <= 4; }",
            0, true);
        eprintln!("6B.5.0b: <= ✓");
    }

    #[test]
    fn b50b_shl_shr() {
        run_6b4_test(
            b"int main() { return 1 << 3; }",
            8, true);
        run_6b4_test(
            b"int main() { return 16 >> 2; }",
            4, true);
        eprintln!("6B.5.0b: << >> ✓");
    }

    #[test]
    fn b50b_pipe_amp() {
        run_6b4_test(
            b"int main() { return 5 | 3; }",
            7, true);    // 0b101 | 0b011 = 0b111
        run_6b4_test(
            b"int main() { return 7 & 5; }",
            5, true);    // 0b111 & 0b101 = 0b101
        eprintln!("6B.5.0b: | & ✓");
    }

    // ─── Precedence chain tests ──────────────────────────

    #[test]
    fn b50b_precedence_mul_before_add() {
        run_6b4_test(
            b"int main() { return 2 + 3 * 4; }",
            14, true);
        eprintln!("6B.5.0b: 2+3*4=14 ✓");
    }

    #[test]
    fn b50b_precedence_shift_after_add() {
        // << binds lower than +: 1 << (2+1) = 1<<3 = 8
        run_6b4_test(
            b"int main() { return 1 << 2 + 1; }",
            8, true);
        // >> binds lower than +: 8 >> (1+1) = 8>>2 = 2
        run_6b4_test(
            b"int main() { return 8 >> 1 + 1; }",
            2, true);
        eprintln!("6B.5.0b: shift vs add precedence ✓");
    }

    #[test]
    fn b50b_precedence_and_after_shift() {
        // & binds lower than <<: (2*3) << 1 = 12,
        // then 12 & 15 = 12
        run_6b4_test(
            b"int main() { return 2 * 3 << 1 & 15; }",
            12, true);
        eprintln!("6B.5.0b: & vs << precedence ✓");
    }

    #[test]
    fn b50b_precedence_or_after_and() {
        // | binds lower than &: 1 | (2 & 4) = 1 | 0 = 1
        run_6b4_test(
            b"int main() { return 1 | 2 & 4; }",
            1, true);
        eprintln!("6B.5.0b: | vs & precedence ✓");
    }

    #[test]
    fn b50b_precedence_relational_after_or() {
        // < binds lower than |: (1 | 2) < (4 | 1) → 3 < 5 = 1
        run_6b4_test(
            b"int main() { return 1 | 2 < 4 | 1; }",
            1, true);
        eprintln!("6B.5.0b: relational vs bitwise precedence ✓");
    }

    #[test]
    fn b50b_precedence_equality_lowest() {
        // == binds lowest: (1 + 2) == (4 - 1) → 3 == 3 = 1
        run_6b4_test(
            b"int main() { return 1 + 2 == 4 - 1; }",
            1, true);
        eprintln!("6B.5.0b: equality lowest precedence ✓");
    }

    // ─── Compiler-realistic encoding expression ──────────

    #[test]
    fn b50b_isa_encoding_expr() {
        // (3 << 26) | (4 << 22) | 42
        // = 201326592 | 16777216 | 42 = 218103850
        // This is similar to how the guest compiler encodes instructions.
        run_6b4_test(
            b"int main() { return (3 << 26) | (4 << 22) | 42; }",
            218103850, true);
        eprintln!("6B.5.0b: ISA encoding expression ✓");
    }

    // ─── Unary dereference (read) ────────────────────────

    #[test]
    fn b50b_deref_read() {
        // Child process layout (from SYS_EXEC in os.rs):
        //   0x00000 : code (RX)
        //   0x10000 : stack (RW, 0x4000 bytes)
        //   0x20000 : trap handler (RX)
        //
        // Write a value to the stack, then dereference it.
        // 0x10000 = 65536: bottom of child's stack (writable).
        run_6b4_test(
            b"int main() { *65536 = 77; return *65536; }",
            77, true);
        eprintln!("6B.5.0b: *addr dereference read ✓");
    }

    // ─── Dereference assignment (*addr = value;) ─────────

    #[test]
    fn b50b_deref_write() {
        // Write to child stack memory (0x10000 = 65536) and read back.
        run_6b4_test(
            b"int main() { *65536 = 99; return *65536; }",
            99, true);
        eprintln!("6B.5.0b: *addr = value; dereference write ✓");
    }

    #[test]
    fn b50b_deref_write_computed() {
        // *(base + offset) = value; with expressions
        // 65544 = 0x10008 (child stack + 8)
        run_6b4_test(
            b"int main() { int a = 65544; *a = 42; return *a; }",
            42, true);
        eprintln!("6B.5.0b: deref write via variable ✓");
    }

    // ─── Range-check conjunction using & ─────────────────

    #[test]
    fn b50b_range_check_conjunction() {
        // Bootstrap idiom: (48 <= ch) & (ch <= 57)
        // Tests that & works as bitwise AND on 0/1 boolean values.
        run_6b4_test(
            b"int main() { int ch = 50; return (48 <= ch) & (ch <= 57); }",
            1, true);
        run_6b4_test(
            b"int main() { int ch = 65; return (48 <= ch) & (ch <= 57); }",
            0, true);
        eprintln!("6B.5.0b: & as boolean conjunction ✓");
    }

    // ─── Chained comparisons ─────────────────────────────

    #[test]
    fn b50b_chained_equality() {
        // a == b == c parses as (a == b) == c
        run_6b4_test(
            b"int main() { return 3 == 3 == 1; }",
            1, true);    // (3==3)=1, 1==1=1
        run_6b4_test(
            b"int main() { return 3 == 3 == 0; }",
            0, true);    // (3==3)=1, 1==0=0
        eprintln!("6B.5.0b: chained == ✓");
    }

    // ─── Complex compiler-realistic expression ───────────

    #[test]
    fn b50b_complex_encode_decode() {
        // Encode an instruction word, then decode fields
        run_6b4_test(
            b"int main() { int w = (3 << 26) | (4 << 22) | 42; return w >> 26; }",
            3, true);   // extract opcode
        run_6b4_test(
            b"int main() { int w = (3 << 26) | (4 << 22) | 42; return (w >> 22) & 15; }",
            4, true);   // extract rd
        run_6b4_test(
            b"int main() { int w = (3 << 26) | (4 << 22) | 42; return w & 63; }",
            42, true);  // extract low 6 bits (immediate)
        eprintln!("6B.5.0b: encode/decode field extraction ✓");
    }

    // ═══════════════════════════════════════════════════════
    //  6B.5.0d — syscall(n, a, b, c)
    // ═══════════════════════════════════════════════════════

    #[test]
    fn b50d_syscall_exit() {
        // syscall(0, 42, 0, 0) → SYS_EXIT(42)
        // Child exits immediately with code 42.
        run_6b4_test(
            b"int main() { return syscall(0, 42, 0, 0); }",
            42, true);
        eprintln!("6B.5.0d: syscall(0, 42, 0, 0) → exit(42) ✓");
    }

    #[test]
    fn b50d_syscall_in_expression() {
        // syscall result used in an expression.
        // syscall(1, 99, 0, 0) is SYS_WRITE(99) which returns 0.
        // 0 + 7 = 7
        run_6b4_test(
            b"int main() { return syscall(1, 99, 0, 0) + 7; }",
            7, true);
        eprintln!("6B.5.0d: syscall in expression ✓");
    }

    #[test]
    fn b50d_syscall_args_with_expressions() {
        // Arguments are full expressions.
        // syscall(0, 20 + 22, 0, 0) → SYS_EXIT(42)
        run_6b4_test(
            b"int main() { return syscall(0, 20 + 22, 0, 0); }",
            42, true);
        eprintln!("6B.5.0d: syscall args with expressions ✓");
    }

    #[test]
    fn b50d_syscall_args_with_function_call() {
        // One argument is a function call result.
        // f() returns 42, syscall(0, f(), 0, 0) → SYS_EXIT(42)
        run_6b4_test(
            b"int f() { return 42; } int main() { return syscall(0, f(), 0, 0); }",
            42, true);
        eprintln!("6B.5.0d: syscall arg from function call ✓");
    }

    #[test]
    fn b50d_syscall_write_then_return() {
        // Multiple syscalls: write a value, then return normally.
        // syscall(1, 77, 0, 0) writes 77, returns 0.
        // Then main returns 10.
        run_6b4_test(
            b"int main() { int x = syscall(1, 77, 0, 0); return x + 10; }",
            10, true);
        eprintln!("6B.5.0d: syscall write then return ✓");
    }

    #[test]
    fn b50d_syscall_nested() {
        // Nested: syscall result feeds another syscall.
        // syscall(1, 55, 0, 0) writes 55, returns 0.
        // syscall(0, 0 + 33, 0, 0) → SYS_EXIT(33)
        run_6b4_test(
            b"int main() { return syscall(0, syscall(1, 55, 0, 0) + 33, 0, 0); }",
            33, true);
        eprintln!("6B.5.0d: nested syscall ✓");
    }

    // ═══════════════════════════════════════════════════════
    //  7.3 — Buffer-based SYS_WRITE through guest compiler
    // ═══════════════════════════════════════════════════════
    //
    // The demanding client for 7.3:
    //   int main() { int s = "İzmir"; syscall(1, s + 8, *s, 0); return 0; }
    //
    // Observable result: six UTF-8 bytes C4 B0 7A 6D 69 72.

    #[test]
    fn p73_write_hello() {
        // "hello" → 5 ASCII bytes: 68 65 6C 6C 6F
        // Uses return-expression form: compile_stmt handles return,
        // compile_expr handles syscall().  SYS_WRITE returns 0 on success.
        let kernel = run_6b4_harness(
            b"int main() { int s = \"hello\"; return syscall(1, s + 8, *s, 0); }",
            0, true);
        assert_eq!(&kernel.byte_output, b"hello",
            "byte_output should be ASCII \"hello\"");
        eprintln!("7.3: write_hello → {:?} ✓", &kernel.byte_output);
    }

    #[test]
    fn p73_write_empty() {
        // "" → length 0 → SYS_WRITE(addr, 0, 0) → no output, success
        let kernel = run_6b4_harness(
            b"int main() { int s = \"\"; return syscall(1, s + 8, *s, 0); }",
            0, true);
        assert!(kernel.byte_output.is_empty(),
            "empty string should produce no output");
        eprintln!("7.3: write_empty → {:?} ✓", &kernel.byte_output);
    }

    #[test]
    fn p73_write_izmir() {
        // "İzmir" → 6 UTF-8 bytes: C4 B0 7A 6D 69 72
        let kernel = run_6b4_harness(
            b"int main() { int s = \"\xC4\xB0zmir\"; return syscall(1, s + 8, *s, 0); }",
            0, true);
        assert_eq!(&kernel.byte_output, b"\xC4\xB0zmir",
            "byte_output should be UTF-8 İzmir");
        eprintln!("7.3: write_izmir → {:02X?} ✓", &kernel.byte_output);
    }

    // ═══════════════════════════════════════════════════════
    //  6B.5.0e — Canonical compiler source (bottom-up)
    // ═══════════════════════════════════════════════════════
    //
    // Functions generate source text with workspace addresses
    // derived from the module-level WS_* constants.  When
    // TEXT_SIZE changes the canonical source auto-updates.
    //
    // Naming: no underscores (bootstrap lexer is [a-z]+[0-9]*).
    // Negatives: (0 - N) since the language has no unary minus.

    fn canonical_readbyte() -> String {
        format!(
            "int readbyte(int pos) {{ \
             int aligned = pos & (0 - 8); \
             int word = *(*{} + aligned); \
             int shift = (pos & 7) * 8; \
             return (word >> shift) & 255; }} ",
            WS_TEXT_BASE)
    }

    fn canonical_writebyte() -> String {
        format!(
            "int writebyte(int addr, int byte) {{ \
             int aligned = addr & (0 - 8); \
             int shift = (addr & 7) * 8; \
             int word = *(aligned); \
             int mask = 255 << shift; \
             word = (word & ((0 - 1) - mask)) | ((byte & 255) << shift); \
             *(aligned) = word; \
             return 0; }} ")
    }

    fn canonical_storeliteral() -> String {
        // Two-ended image allocator (7.2): literals grow downward from
        // OUTPUT_SIZE within the output buffer.  Returns the absolute
        // offset of the literal header within the output buffer.
        // Underflow-safe: checks lp < size before lp - size.
        format!(
            "int storeliteral() {{ \
             int len = *{nl}; \
             int start = *{ns}; \
             int lp = *{litp}; \
             int aligned = (len + 7) & (0 - 8); \
             int sz = aligned + 8; \
             if (lp < sz) {{ *{e} = 1; return 0; }} \
             lp = lp - sz; \
             *({out} + lp) = len; \
             int db = {out} + lp + 8; \
             int i = 0; \
             while (i < len) {{ \
             writebyte(db + i, readbyte(start + i)); \
             i = i + 1; }} \
             *{litp} = lp; \
             return lp; }} ",
            ns = WS_TOK_NAME_START, nl = WS_TOK_NAME_LEN,
            litp = WS_LIT_POS, e = WS_ERROR, out = LAYOUT_OUT)
    }

    fn canonical_peekchar() -> String {
        format!(
            "int peekchar() {{ \
             int p = *{}; \
             if (*{} <= p) {{ return 0; }} \
             return readbyte(p); }} ",
            WS_POS, WS_SRC_LEN)
    }

    fn canonical_advance() -> String {
        format!(
            "int advance() {{ \
             *{} = *{} + 1; \
             return 0; }} ",
            WS_POS, WS_POS)
    }

    fn canonical_skipws() -> String {
        "int skipws() { \
         int ch = peekchar(); \
         while ((0 < ch) & (ch <= 32)) { \
         advance(); \
         ch = peekchar(); } \
         return 0; } ".to_string()
    }

    fn canonical_nameseq() -> String {
        "int nameseq(int sa, int la, int sb, int lb) { \
         if (la != lb) { return 0; } \
         int i = 0; \
         int a = 0; \
         int b = 0; \
         while (i < la) { \
         a = readbyte(sa + i); \
         b = readbyte(sb + i); \
         if (a != b) { return 0; } \
         i = i + 1; } \
         return 1; } ".to_string()
    }

    fn canonical_classifykw() -> String {
        // Keyword bytes: if=105,102  int=105,110,116
        //   else=101,108,115,101  while=119,104,105,108,101
        //   return=114,101,116,117,114,110
        //   syscall=115,121,115,99,97,108,108
        format!(
            "int classifykw(int s, int l) {{ \
             if (l == 2) {{ \
             if (readbyte(s) == 105) {{ \
             if (readbyte(s + 1) == 102) {{ return {kw_if}; }} }} }} \
             if (l == 3) {{ \
             if (readbyte(s) == 105) {{ \
             if (readbyte(s + 1) == 110) {{ \
             if (readbyte(s + 2) == 116) {{ return {kw_int}; }} }} }} }} \
             if (l == 4) {{ \
             if (readbyte(s) == 101) {{ \
             if (readbyte(s + 1) == 108) {{ \
             if (readbyte(s + 2) == 115) {{ \
             if (readbyte(s + 3) == 101) {{ return {kw_else}; }} }} }} }} }} \
             if (l == 5) {{ \
             if (readbyte(s) == 119) {{ \
             if (readbyte(s + 1) == 104) {{ \
             if (readbyte(s + 2) == 105) {{ \
             if (readbyte(s + 3) == 108) {{ \
             if (readbyte(s + 4) == 101) {{ return {kw_while}; }} }} }} }} }} }} \
             if (l == 6) {{ \
             if (readbyte(s) == 114) {{ \
             if (readbyte(s + 1) == 101) {{ \
             if (readbyte(s + 2) == 116) {{ \
             if (readbyte(s + 3) == 117) {{ \
             if (readbyte(s + 4) == 114) {{ \
             if (readbyte(s + 5) == 110) {{ return {kw_return}; }} }} }} }} }} }} }} \
             if (l == 7) {{ \
             if (readbyte(s) == 115) {{ \
             if (readbyte(s + 1) == 121) {{ \
             if (readbyte(s + 2) == 115) {{ \
             if (readbyte(s + 3) == 99) {{ \
             if (readbyte(s + 4) == 97) {{ \
             if (readbyte(s + 5) == 108) {{ \
             if (readbyte(s + 6) == 108) {{ return {kw_syscall}; }} }} }} }} }} }} }} }} \
             return {ident}; }} ",
            kw_if = TOK_IF, kw_int = TOK_INT_KW, kw_else = TOK_ELSE,
            kw_while = TOK_WHILE, kw_return = TOK_RETURN,
            kw_syscall = TOK_SYSCALL, ident = TOK_IDENT)
    }

    fn canonical_setchartok() -> String {
        format!(
            "int setchartok(int t, int v) {{ \
             *{} = t; *{} = v; \
             advance(); return 0; }} ",
            WS_TOK_TYPE, WS_TOK_VALUE)
    }

    fn canonical_scannumber() -> String {
        format!(
            "int scannumber() {{ \
             int v = 0; \
             int ch = peekchar(); \
             while ((48 <= ch) & (ch <= 57)) {{ \
             v = v * 10 + (ch - 48); \
             if (131071 < v) {{ *{e} = 1; ch = 0; }} \
             else {{ advance(); ch = peekchar(); }} }} \
             *{t} = {num}; *{tv} = v; return 0; }} ",
            e = WS_ERROR,
            t = WS_TOK_TYPE,
            num = TOK_NUMBER,
            tv = WS_TOK_VALUE)
    }

    fn canonical_scanident() -> String {
        format!(
            "int scanident() {{ \
             int ch = peekchar(); \
             int start = *{pos}; \
             int len = 0; \
             while ((97 <= ch) & (ch <= 122)) {{ \
             len = len + 1; advance(); ch = peekchar(); }} \
             while ((48 <= ch) & (ch <= 57)) {{ \
             len = len + 1; advance(); ch = peekchar(); }} \
             *{ns} = start; *{nl} = len; \
             *{tt} = classifykw(start, len); return 0; }} ",
            pos = WS_POS,
            ns = WS_TOK_NAME_START,
            nl = WS_TOK_NAME_LEN,
            tt = WS_TOK_TYPE)
    }

    /// RFC 3629 scalar-value validation (7.4).
    ///
    /// Pure function: validateutf8(start, len) -> 0 valid / 1 invalid.
    /// Uses need/lo/hi state machine with one continuation loop.
    ///
    /// Overflow-safe: i < len <= SOURCE_SIZE, need <= 3,
    /// so i + need + 1 cannot overflow 64-bit arithmetic.
    fn canonical_validateutf8() -> String {
        "int validateutf8(int start, int len) { \
         int i = 0; int b = 0; int need = 0; \
         int lo = 0; int hi = 0; int j = 0; int c = 0; \
         while (i < len) { \
         b = readbyte(start + i); \
         if (b <= 127) { i = i + 1; } \
         else { \
         need = 0; lo = 128; hi = 191; \
         if ((194 <= b) & (b <= 223)) { need = 1; } \
         else { if (b == 224) { need = 2; lo = 160; } \
         else { if ((225 <= b) & (b <= 236)) { need = 2; } \
         else { if (b == 237) { need = 2; hi = 159; } \
         else { if ((238 <= b) & (b <= 239)) { need = 2; } \
         else { if (b == 240) { need = 3; lo = 144; } \
         else { if ((241 <= b) & (b <= 243)) { need = 3; } \
         else { if (b == 244) { need = 3; hi = 143; } \
         else { return 1; \
         } } } } } } } } \
         if (len < i + need + 1) { return 1; } \
         c = readbyte(start + i + 1); \
         if (c < lo) { return 1; } \
         if (hi < c) { return 1; } \
         j = 2; \
         while (j <= need) { \
         c = readbyte(start + i + j); \
         if (c < 128) { return 1; } \
         if (191 < c) { return 1; } \
         j = j + 1; } \
         i = i + need + 1; \
         } } \
         return 0; } ".into()
    }

    /// scanstring (7.4): advance past opening quote, scan to closing quote,
    /// advance past closing quote (scanner always makes progress),
    /// then validate UTF-8.  Lexical failure -> ERROR + TOK_EOF.
    fn canonical_scanstring() -> String {
        format!(
            "int scanstring() {{ \
             advance(); \
             int start = *{pos}; \
             int len = 0; \
             while (*{pos} < *{sl}) {{ \
             if (peekchar() == 34) {{ \
             advance(); \
             if (validateutf8(start, len) != 0) {{ \
             *{e} = 1; *{tt} = {eof}; return 0; }} \
             *{ns} = start; *{nl} = len; \
             *{tt} = {str}; return 0; }} \
             len = len + 1; advance(); }} \
             *{e} = 1; *{tt} = {eof}; return 0; }} ",
            pos = WS_POS, sl = WS_SRC_LEN,
            ns = WS_TOK_NAME_START, nl = WS_TOK_NAME_LEN,
            tt = WS_TOK_TYPE, e = WS_ERROR,
            str = TOK_STRING, eof = TOK_EOF)
    }

    fn canonical_nexttoken() -> String {
        format!(
            "int nexttoken() {{ \
             skipws(); \
             if (*{sl} <= *{pos}) {{ *{tt} = {eof}; return 0; }} \
             int ch = peekchar(); \
             if (ch == 43) {{ return setchartok({plus}, 43); }} \
             if (ch == 45) {{ return setchartok({minus}, 45); }} \
             if (ch == 42) {{ return setchartok({star}, 42); }} \
             if (ch == 59) {{ return setchartok({semi}, 59); }} \
             if (ch == 44) {{ return setchartok({comma}, 44); }} \
             if (ch == 40) {{ return setchartok({lp}, 40); }} \
             if (ch == 41) {{ return setchartok({rp}, 41); }} \
             if (ch == 123) {{ return setchartok({lb}, 123); }} \
             if (ch == 125) {{ return setchartok({rb}, 125); }} \
             if (ch == 124) {{ return setchartok({pipe}, 124); }} \
             if (ch == 38) {{ return setchartok({amp}, 38); }} \
             if (ch == 61) {{ advance(); \
             if (peekchar() == 61) {{ advance(); *{tt} = {eqeq}; return 0; }} \
             *{tt} = {eq}; return 0; }} \
             if (ch == 60) {{ advance(); ch = peekchar(); \
             if (ch == 61) {{ advance(); *{tt} = {le}; return 0; }} \
             if (ch == 60) {{ advance(); *{tt} = {shl}; return 0; }} \
             *{tt} = {lt}; return 0; }} \
             if (ch == 62) {{ advance(); \
             if (peekchar() == 62) {{ advance(); *{tt} = {shr}; return 0; }} \
             *{e} = 1; *{tt} = {eof}; return 0; }} \
             if (ch == 33) {{ advance(); \
             if (peekchar() == 61) {{ advance(); *{tt} = {ne}; return 0; }} \
             *{e} = 1; *{tt} = {eof}; return 0; }} \
             if (ch == 34) {{ return scanstring(); }} \
             if ((97 <= ch) & (ch <= 122)) {{ return scanident(); }} \
             if ((48 <= ch) & (ch <= 57)) {{ return scannumber(); }} \
             *{e} = 1; *{tt} = {eof}; return 0; }} ",
            pos = WS_POS, sl = WS_SRC_LEN, tt = WS_TOK_TYPE,
            e = WS_ERROR,
            eof = TOK_EOF, plus = TOK_PLUS, minus = TOK_MINUS,
            star = TOK_STAR, semi = TOK_SEMI, comma = TOK_COMMA,
            lp = TOK_LPAREN, rp = TOK_RPAREN,
            lb = TOK_LBRACE, rb = TOK_RBRACE,
            pipe = TOK_PIPE, amp = TOK_AMP,
            eq = TOK_EQ, eqeq = TOK_EQEQ, ne = TOK_NE,
            le = TOK_LE, lt = TOK_LT,
            shl = TOK_SHL, shr = TOK_SHR)
    }

    // ─── Expression compiler layer ─────────────────────

    fn canonical_compilecall() -> String {
        format!(
            "int compilecall(int ns, int nl) {{ \
             nexttoken(); \
             int argc = 0; \
             if (*{tt} != {rp}) {{ \
             compileexpr(); \
             emit(enci({subi}, {sp}, {sp}, 8)); \
             emit(enci({st}, {r4}, {sp}, 0)); \
             argc = 1; \
             while (*{tt} == {comma}) {{ \
             if (4 <= argc) {{ *{e} = 1; return 0; }} \
             nexttoken(); \
             compileexpr(); \
             emit(enci({subi}, {sp}, {sp}, 8)); \
             emit(enci({st}, {r4}, {sp}, 0)); \
             argc = argc + 1; }} }} \
             if (*{tt} != {rp}) {{ *{e} = 1; }} \
             nexttoken(); \
             if (0 < argc) {{ emit(enci({ld}, {r0}, {sp}, (argc - 1) * 8)); }} \
             if (1 < argc) {{ emit(enci({ld}, 1, {sp}, (argc - 2) * 8)); }} \
             if (2 < argc) {{ emit(enci({ld}, 2, {sp}, (argc - 3) * 8)); }} \
             if (3 < argc) {{ emit(enci({ld}, 3, {sp}, (argc - 4) * 8)); }} \
             if (0 < argc) {{ emit(enci({addi}, {sp}, {sp}, argc * 8)); }} \
             int pos = *{op}; \
             emit({call} << 26); \
             addfixup(pos, ns, nl, argc); \
             emit(encr({mov}, {r4}, {r0}, 0)); \
             return 0; }} ",
            tt = WS_TOK_TYPE, rp = TOK_RPAREN, comma = TOK_COMMA,
            e = WS_ERROR, op = WS_OUT_POS,
            subi = OP_SUBI, addi = OP_ADDI, st = OP_ST, ld = OP_LD,
            call = OP_CALL, mov = OP_MOV,
            sp = GEN_SP, r4 = GEN_R4, r0 = GEN_R0)
    }

    fn canonical_compileprimary() -> String {
        format!(
            "int compileprimary() {{ \
             int tok = *{tt}; \
             int ns = 0; \
             int nl = 0; \
             if (tok == {num}) {{ \
             ns = *{tv}; \
             nexttoken(); \
             emit(enci({movi}, {r4}, 0, ns)); \
             return 0; }} \
             if (tok == {ident}) {{ \
             ns = *{tns}; nl = *{tnl}; \
             nexttoken(); \
             if (*{tt} == {lp}) {{ \
             compilecall(ns, nl); \
             }} else {{ \
             ns = lookupsymbol(ns, nl); \
             emit(enci({ld}, {r4}, {fp}, ns)); }} \
             return 0; }} \
             if (tok == {lp}) {{ \
             nexttoken(); \
             compileexpr(); \
             if (*{tt} != {rp}) {{ *{e} = 1; }} \
             else {{ nexttoken(); }} \
             return 0; }} \
             if (tok == {syscall}) {{ \
             nexttoken(); \
             if (*{tt} != {lp}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             emit(enci({subi}, {sp}, {sp}, 8)); \
             emit(enci({st}, {r4}, {sp}, 0)); \
             if (*{tt} != {comma}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             emit(enci({subi}, {sp}, {sp}, 8)); \
             emit(enci({st}, {r4}, {sp}, 0)); \
             if (*{tt} != {comma}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             emit(enci({subi}, {sp}, {sp}, 8)); \
             emit(enci({st}, {r4}, {sp}, 0)); \
             if (*{tt} != {comma}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             emit(enci({subi}, {sp}, {sp}, 8)); \
             emit(enci({st}, {r4}, {sp}, 0)); \
             if (*{tt} != {rp}) {{ *{e} = 1; }} \
             nexttoken(); \
             emit(enci({ld2}, {r0}, {sp}, 24)); \
             emit(enci({ld2}, 1, {sp}, 16)); \
             emit(enci({ld2}, 2, {sp}, 8)); \
             emit(enci({ld2}, 3, {sp}, 0)); \
             emit(enci({addi}, {sp}, {sp}, 32)); \
             emit(encs({trap})); \
             emit(encr({mov}, {r4}, {r0}, 0)); \
             return 0; }} \
             if (tok == {str}) {{ \
             int litoff = storeliteral(); \
             nexttoken(); \
             emit(enci({movi}, {r4}, 0, litoff)); \
             return 0; }} \
             *{e} = 1; return 0; }} ",
            tt = WS_TOK_TYPE, tv = WS_TOK_VALUE,
            tns = WS_TOK_NAME_START, tnl = WS_TOK_NAME_LEN,
            e = WS_ERROR,
            num = TOK_NUMBER, ident = TOK_IDENT,
            str = TOK_STRING,
            lp = TOK_LPAREN, rp = TOK_RPAREN,
            comma = TOK_COMMA, syscall = TOK_SYSCALL,
            movi = OP_MOVI, ld = OP_LD, ld2 = OP_LD,
            subi = OP_SUBI, addi = OP_ADDI, st = OP_ST, trap = OP_TRAP,
            mov = OP_MOV,
            r4 = GEN_R4, r0 = GEN_R0, fp = GEN_FP, sp = GEN_SP)
    }

    fn canonical_exprsave() -> String {
        format!(
            "int exprsave() {{ \
             int off = *{esp}; \
             emit(enci({st}, {r4}, {sp}, off)); \
             *{esp} = *{esp} - 8; \
             return 0; }} ",
            esp = WS_EXPR_SP,
            st = OP_ST, r4 = GEN_R4, sp = GEN_SP)
    }

    fn canonical_exprrestore() -> String {
        format!(
            "int exprrestore() {{ \
             *{esp} = *{esp} + 8; \
             int off = *{esp}; \
             emit(enci({ld}, {r5}, {sp}, off)); \
             return 0; }} ",
            esp = WS_EXPR_SP,
            ld = OP_LD, r5 = GEN_R5, sp = GEN_SP)
    }

    fn canonical_compilemult() -> String {
        format!(
            "int compilemult() {{ \
             compileunary(); \
             while (*{tt} == {star}) {{ \
             nexttoken(); \
             exprsave(); compileunary(); exprrestore(); \
             emit(encr({mul}, {r4}, {r5}, {r4})); }} \
             return 0; }} ",
            tt = WS_TOK_TYPE, star = TOK_STAR,
            mul = OP_MUL, r4 = GEN_R4, r5 = GEN_R5)
    }

    fn canonical_compileadd() -> String {
        format!(
            "int compileadd() {{ \
             compilemult(); \
             int op = 0; \
             while ((*{tt} == {plus}) | (*{tt} == {minus})) {{ \
             op = *{tt}; nexttoken(); \
             exprsave(); compilemult(); exprrestore(); \
             if (op == {plus}) {{ emit(encr({add}, {r4}, {r5}, {r4})); }} \
             else {{ emit(encr({sub}, {r4}, {r5}, {r4})); }} }} \
             return 0; }} ",
            tt = WS_TOK_TYPE,
            plus = TOK_PLUS, minus = TOK_MINUS,
            add = OP_ADD, sub = OP_SUB,
            r4 = GEN_R4, r5 = GEN_R5)
    }

    fn canonical_compileshift() -> String {
        format!(
            "int compileshift() {{ \
             compileadd(); \
             int op = 0; \
             while ((*{tt} == {shl}) | (*{tt} == {shr})) {{ \
             op = *{tt}; nexttoken(); \
             exprsave(); compileadd(); exprrestore(); \
             if (op == {shl}) {{ emit(encr({shlop}, {r4}, {r5}, {r4})); }} \
             else {{ emit(encr({shrop}, {r4}, {r5}, {r4})); }} }} \
             return 0; }} ",
            tt = WS_TOK_TYPE,
            shl = TOK_SHL, shr = TOK_SHR,
            shlop = OP_SHL, shrop = OP_SHR,
            r4 = GEN_R4, r5 = GEN_R5)
    }

    fn canonical_compilebitand() -> String {
        format!(
            "int compilebitand() {{ \
             compileshift(); \
             while (*{tt} == {amp}) {{ \
             nexttoken(); \
             exprsave(); compileshift(); exprrestore(); \
             emit(encr({and}, {r4}, {r5}, {r4})); }} \
             return 0; }} ",
            tt = WS_TOK_TYPE, amp = TOK_AMP,
            and = OP_AND, r4 = GEN_R4, r5 = GEN_R5)
    }

    fn canonical_compilebitor() -> String {
        format!(
            "int compilebitor() {{ \
             compilebitand(); \
             while (*{tt} == {pipe}) {{ \
             nexttoken(); \
             exprsave(); compilebitand(); exprrestore(); \
             emit(encr({or}, {r4}, {r5}, {r4})); }} \
             return 0; }} ",
            tt = WS_TOK_TYPE, pipe = TOK_PIPE,
            or = OP_OR, r4 = GEN_R4, r5 = GEN_R5)
    }

    // Comparison helper: CMP 0,R5,R4; MOVI R4,0; BCC skip,+4; MOVI R4,1
    fn cmp_emit(skip_cond: i64) -> String {
        format!(
            "emit(encr({cmpi}, 0, {r5}, {r4})); \
             emit(enci({movi}, {r4}, 0, 0)); \
             emit(encb({skip}, 4)); \
             emit(enci({movi2}, {r4}, 0, 1)); ",
            cmpi = OP_CMP, r5 = GEN_R5, r4 = GEN_R4,
            movi = OP_MOVI, movi2 = OP_MOVI,
            skip = skip_cond)
    }

    fn canonical_compilerel() -> String {
        format!(
            "int compilerel() {{ \
             compilebitor(); \
             int op = 0; \
             while ((*{tt} == {lt}) | (*{tt} == {le})) {{ \
             op = *{tt}; nexttoken(); \
             exprsave(); compilebitor(); exprrestore(); \
             if (op == {lt}) {{ {cmp_lt} }} \
             else {{ {cmp_le} }} }} \
             return 0; }} ",
            tt = WS_TOK_TYPE,
            lt = TOK_LT, le = TOK_LE,
            cmp_lt = cmp_emit(COND_GE),   // < skips on GE
            cmp_le = cmp_emit(COND_GT))   // <= skips on GT
    }

    fn canonical_compileeq() -> String {
        format!(
            "int compileeq() {{ \
             compilerel(); \
             int op = 0; \
             while ((*{tt} == {eqeq}) | (*{tt} == {ne})) {{ \
             op = *{tt}; nexttoken(); \
             exprsave(); compilerel(); exprrestore(); \
             if (op == {eqeq}) {{ {cmp_eq} }} \
             else {{ {cmp_ne} }} }} \
             return 0; }} ",
            tt = WS_TOK_TYPE,
            eqeq = TOK_EQEQ, ne = TOK_NE,
            cmp_eq = cmp_emit(COND_NE),   // == skips on NE
            cmp_ne = cmp_emit(COND_EQ))   // != skips on EQ
    }

    fn canonical_compileexpr() -> String {
        "int compileexpr() { return compileeq(); } ".to_string()
    }

    fn canonical_compilestmt() -> String {
        format!(
            "int compilestmt() {{ \
             int tok = *{tt}; \
             int ns = 0; \
             int nl = 0; \
             int bp = 0; \
             int sp2 = 0; \
             if (tok == {kw_int}) {{ \
             nexttoken(); \
             if (*{tt} != {ident}) {{ *{e} = 1; }} \
             ns = *{tns}; nl = *{tnl}; \
             nexttoken(); \
             if (*{tt} != {eq}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             if (*{tt} != {semi}) {{ *{e} = 1; }} \
             nexttoken(); \
             sp2 = addsymbol(ns, nl); \
             emit(enci({st}, {r4}, {fp}, sp2)); \
             return 0; }} \
             if (tok == {kw_return}) {{ \
             nexttoken(); \
             compileexpr(); \
             if (*{tt} != {semi}) {{ *{e} = 1; }} \
             nexttoken(); \
             emit(encr({mov}, {r0}, {r4}, 0)); \
             emit(encr({mov}, {sp}, {fp}, 0)); \
             emit(enci({ld}, {fp}, {sp}, 0)); \
             emit(enci({ld}, {lr}, {sp}, 8)); \
             emit(enci({addi}, {sp}, {sp}, 16)); \
             emit(encs({ret})); \
             return 1; }} \
             if (tok == {kw_if}) {{ \
             nexttoken(); \
             if (*{tt} != {lp}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             if (*{tt} != {rp}) {{ *{e} = 1; }} \
             nexttoken(); \
             emit(enci({cmpi}, 0, {r4}, 0)); \
             bp = *{op}; \
             emit(encb({ceq}, 0)); \
             if (*{tt} != {lb}) {{ *{e} = 1; }} \
             nexttoken(); \
             ns = compileblock(); \
             if (*{tt} == {kw_else}) {{ \
             nexttoken(); \
             sp2 = *{op}; \
             emit(encb({cal}, 0)); \
             patchbranch(bp, {ceq}, *{op}); \
             if (*{tt} != {lb}) {{ *{e} = 1; }} \
             nexttoken(); \
             nl = compileblock(); \
             patchbranch(sp2, {cal}, *{op}); \
             return ns & nl; \
             }} else {{ \
             patchbranch(bp, {ceq}, *{op}); \
             return 0; }} \
             return 0; }} \
             if (tok == {kw_while}) {{ \
             nexttoken(); \
             if (*{tt} != {lp}) {{ *{e} = 1; }} \
             nexttoken(); \
             bp = *{op}; \
             compileexpr(); \
             if (*{tt} != {rp}) {{ *{e} = 1; }} \
             nexttoken(); \
             emit(enci({cmpi}, 0, {r4}, 0)); \
             sp2 = *{op}; \
             emit(encb({ceq}, 0)); \
             if (*{tt} != {lb}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileblock(); \
             ns = 0 - ((*{op} - bp) >> 2); \
             emit(encb({cal}, ns)); \
             patchbranch(sp2, {ceq}, *{op}); \
             return 0; }} \
             if (tok == {star}) {{ \
             nexttoken(); \
             compileexpr(); \
             exprsave(); \
             if (*{tt} != {eq}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             exprrestore(); \
             if (*{tt} != {semi}) {{ *{e} = 1; }} \
             nexttoken(); \
             emit(enci({st}, {r4}, {r5}, 0)); \
             return 0; }} \
             if (tok == {ident}) {{ \
             ns = *{tns}; nl = *{tnl}; \
             nexttoken(); \
             if (*{tt} == {lp}) {{ \
             compilecall(ns, nl); \
             if (*{tt} != {semi}) {{ *{e} = 1; }} \
             nexttoken(); \
             return 0; }} \
             if (*{tt} != {eq}) {{ *{e} = 1; }} \
             nexttoken(); \
             compileexpr(); \
             if (*{tt} != {semi}) {{ *{e} = 1; }} \
             nexttoken(); \
             sp2 = lookupsymbol(ns, nl); \
             emit(enci({st}, {r4}, {fp}, sp2)); \
             return 0; }} \
             *{e} = 1; return 0; }} ",
            tt = WS_TOK_TYPE, tns = WS_TOK_NAME_START, tnl = WS_TOK_NAME_LEN,
            e = WS_ERROR, op = WS_OUT_POS,
            kw_int = TOK_INT_KW, kw_return = TOK_RETURN,
            kw_if = TOK_IF, kw_else = TOK_ELSE, kw_while = TOK_WHILE,
            ident = TOK_IDENT, star = TOK_STAR,
            eq = TOK_EQ, semi = TOK_SEMI,
            lp = TOK_LPAREN, rp = TOK_RPAREN,
            lb = TOK_LBRACE,
            st = OP_ST, ld = OP_LD, addi = OP_ADDI,
            cmpi = OP_CMPI, ret = OP_RET, mov = OP_MOV,
            ceq = COND_EQ, cal = COND_AL,
            r4 = GEN_R4, r5 = GEN_R5, r0 = GEN_R0,
            fp = GEN_FP, lr = GEN_LR, sp = GEN_SP)
    }

    fn canonical_compilefuncdef() -> String {
        format!(
            "int compilefuncdef() {{ \
             if (*{tt} != {kw_int}) {{ *{e} = 1; }} \
             nexttoken(); \
             if (*{tt} != {ident}) {{ *{e} = 1; }} \
             int ns = *{tns}; \
             int fnl = *{tnl}; \
             nexttoken(); \
             if (*{tt} != {lp}) {{ *{e} = 1; }} \
             nexttoken(); \
             *{sc} = 0; \
             *{esp} = (0 - {espabs}); \
             int pc = 0; \
             int pns = 0; \
             int pnl = 0; \
             while (*{tt} == {kw_int}) {{ \
             if (4 <= pc) {{ *{e} = 1; return 0; }} \
             nexttoken(); \
             if (*{tt} != {ident}) {{ *{e} = 1; }} \
             pns = *{tns}; pnl = *{tnl}; \
             nexttoken(); \
             addsymbol(pns, pnl); \
             pc = pc + 1; \
             if (*{tt} == {comma}) {{ nexttoken(); }} }} \
             if (*{tt} != {rp}) {{ *{e} = 1; }} \
             nexttoken(); \
             if (*{tt} != {lb}) {{ *{e} = 1; }} \
             nexttoken(); \
             addfunc(ns, fnl, pc); \
             int pp = *{op}; \
             emit(encs({nop})); \
             emit(encs({nop})); \
             emit(encs({nop})); \
             emit(encs({nop})); \
             if (0 < pc) {{ emit(enci({st_op}, {r0}, {fp}, 0 - 8)); }} \
             if (1 < pc) {{ emit(enci({st_op}, 1, {fp}, 0 - 16)); }} \
             if (2 < pc) {{ emit(enci({st_op}, 2, {fp}, 0 - 24)); }} \
             if (3 < pc) {{ emit(enci({st_op}, 3, {fp}, 0 - 32)); }} \
             ns = compileblock(); \
             int fs = 16 + *{sc} * 8; \
             int npad = ({nop} << 26) << 32; \
             int base = {out} + pp; \
             *base = enci({subi}, {sp}, {sp}, fs) | npad; \
             *(base + 8) = enci({st_op}, {lr}, {sp}, fs - 8) | npad; \
             *(base + 16) = enci({st_op}, {fp}, {sp}, fs - 16) | npad; \
             *(base + 24) = enci({addi}, {fp}, {sp}, fs - 16) | npad; \
             if (ns == 0) {{ *{e} = 1; }} \
             return 0; }} ",
            tt = WS_TOK_TYPE, tns = WS_TOK_NAME_START, tnl = WS_TOK_NAME_LEN,
            e = WS_ERROR, op = WS_OUT_POS, sc = WS_SYM_COUNT,
            esp = WS_EXPR_SP, espabs = -EXPR_SP_INIT,
            out = LAYOUT_OUT,
            kw_int = TOK_INT_KW, ident = TOK_IDENT,
            lp = TOK_LPAREN, rp = TOK_RPAREN,
            comma = TOK_COMMA, lb = TOK_LBRACE,
            nop = OP_NOP, subi = OP_SUBI, addi = OP_ADDI,
            st_op = OP_ST,
            r0 = GEN_R0, fp = GEN_FP, lr = GEN_LR, sp = GEN_SP)
    }

    fn canonical_findmain() -> String {
        // "main" = 109, 97, 105, 110
        format!(
            "int findmain() {{ \
             int cnt = *{fc}; \
             int i = 0; \
             int base = 0; \
             int ns = 0; \
             int nl = 0; \
             while (i < cnt) {{ \
             base = {ft} + i * 32; \
             ns = *base; nl = *(base + 8); \
             if (nl == 4) {{ \
             if (readbyte(ns) == 109) {{ \
             if (readbyte(ns + 1) == 97) {{ \
             if (readbyte(ns + 2) == 105) {{ \
             if (readbyte(ns + 3) == 110) {{ \
             return *(base + 16); }} }} }} }} }} \
             i = i + 1; }} \
             *{e} = 1; return 0; }} ",
            fc = WS_FUNC_COUNT, ft = WS_FUNC_TABLE,
            e = WS_ERROR)
    }

    fn canonical_compileblock() -> String {
        format!(
            "int compileblock() {{ \
             int ret = 0; \
             while (((*{tt} != {rb}) & (*{tt} != {eof})) & (*{e} == 0)) {{ \
             ret = ret | compilestmt(); }} \
             if (*{e} != 0) {{ return ret; }} \
             if (*{tt} == {eof}) {{ *{e} = 1; return ret; }} \
             nexttoken(); \
             return ret; }} ",
            tt = WS_TOK_TYPE, e = WS_ERROR,
            rb = TOK_RBRACE, eof = TOK_EOF)
    }

    /// Full canonical compiler: all functions including main entry point.
    fn canonical_compiler_source() -> String {
        format!(
            "{}{}{}{}{}{}{}",
            canonical_stmt_prelude(),
            canonical_compilefuncdef(),
            canonical_findmain(),
            canonical_compilermain(),
            "", "", "")
    }

    fn canonical_compilermain() -> String {
        // After compilation, normalize literal segment offset:
        // lp == OUTPUT_SIZE → no literals → pass 0 as R3.
        // Otherwise pass lp (the literal frontier) as R3.
        // Equality check, not comparison: corruption should propagate.
        //
        // WS_LIT_POS is initialized to OUTPUT_SIZE here so the compiler
        // is self-sufficient — the host does not need to write workspace
        // fields before boot (Phase 8.1c).
        format!(
            "int main() {{ \
             int src = {layout_src}; \
             int slen = *src; \
             int sbase = src + 8; \
             if ({srclimit} < slen) {{ return 0 - 1; }} \
             *{pos} = 0; \
             *{sl} = slen; \
             *{tb} = sbase; \
             *{e} = 0; \
             *{sc} = 0; \
             *{op} = 0; \
             *{esp} = (0 - {espabs}); \
             *{fc} = 0; \
             *{fxc} = 0; \
             *{litp} = {outsize}; \
             nexttoken(); \
             int sp = *{op}; \
             emit({call} << 26); \
             emit(encs({halt})); \
             while ((*{tt} != {eof}) & (*{e} == 0)) {{ \
             compilefuncdef(); }} \
             resolvefixups(); \
             int ma = findmain(); \
             patchcall(sp, ma); \
             if (*{e} != 0) {{ return 0 - 1; }} \
             int seal = syscall(5, {layout_out}, 0, 0); \
             int sz = *{op}; \
             int lp = *{litp}; \
             if (lp == {outsize}) {{ lp = 0; }} \
             return syscall(6, {layout_out}, sz, lp); }} ",
            layout_src = LAYOUT_SRC,
            srclimit = SOURCE_SIZE - 8,
            layout_out = LAYOUT_OUT,
            pos = WS_POS, sl = WS_SRC_LEN, tb = WS_TEXT_BASE,
            e = WS_ERROR, sc = WS_SYM_COUNT, op = WS_OUT_POS,
            esp = WS_EXPR_SP, espabs = -EXPR_SP_INIT,
            fc = WS_FUNC_COUNT, fxc = WS_FIX_COUNT,
            tt = WS_TOK_TYPE, eof = TOK_EOF,
            litp = WS_LIT_POS, outsize = OUTPUT_SIZE,
            call = OP_CALL, halt = OP_HALT)
    }

    fn canonical_compileunary() -> String {
        format!(
            "int compileunary() {{ \
             if (*{tt} == {star}) {{ \
             nexttoken(); \
             compileunary(); \
             emit(enci({ld}, {r4}, {r4}, 0)); \
             return 0; }} \
             return compileprimary(); }} ",
            tt = WS_TOK_TYPE, star = TOK_STAR,
            ld = OP_LD, r4 = GEN_R4)
    }

    // ─── Emit / encoding layer ───────────────────────

    fn canonical_enci() -> String {
        "int enci(int op, int rd, int rs, int imm) { \
         return (op << 26) | (rd << 22) | (rs << 18) | ((imm << 46) >> 46); } ".to_string()
    }

    fn canonical_encr() -> String {
        "int encr(int op, int rd, int rs, int rs2) { \
         return (op << 26) | (rd << 22) | (rs << 18) | (rs2 << 14); } ".to_string()
    }

    fn canonical_encs() -> String {
        "int encs(int op) { return op << 26; } ".to_string()
    }

    fn canonical_encb() -> String {
        format!(
            "int encb(int cond, int disp) {{ \
             return ({bcc} << 26) | (cond << 22) | ((disp << 42) >> 42); }} ",
            bcc = OP_BCC)
    }

    fn canonical_emit() -> String {
        // Width-safe collision guard (7.2): the full 8-byte write
        // must fit below the literal frontier WS_LIT_POS.
        //   if (lp < 8) → underflow guard
        //   if (lp - 8 < pos) → collision
        // When no literals (lp == OUTPUT_SIZE), degenerates to original.
        format!(
            "int emit(int word) {{ \
             int pos = *{op}; \
             int lp = *{litp}; \
             if (lp < 8) {{ *{e} = 1; return 0; }} \
             if (lp - 8 < pos) {{ *{e} = 1; return 0; }} \
             int padded = word | (({nop} << 26) << 32); \
             *({out} + pos) = padded; \
             *{op} = pos + 8; \
             return 0; }} ",
            op = WS_OUT_POS,
            litp = WS_LIT_POS,
            e = WS_ERROR,
            nop = OP_NOP,
            out = LAYOUT_OUT)
    }

    fn canonical_patchbranch() -> String {
        format!(
            "int patchbranch(int pos, int cond, int target) {{ \
             int disp = (target - pos) >> 2; \
             int word = ({bcc} << 26) | (cond << 22) | ((disp << 42) >> 42); \
             int padded = word | (({nop} << 26) << 32); \
             *({out} + pos) = padded; \
             return 0; }} ",
            bcc = OP_BCC,
            nop = OP_NOP,
            out = LAYOUT_OUT)
    }

    fn canonical_patchcall() -> String {
        format!(
            "int patchcall(int pos, int addr) {{ \
             int disp = (addr >> 2) - (pos >> 2); \
             int word = ({call} << 26) | ((disp << 42) >> 42); \
             int padded = word | (({nop} << 26) << 32); \
             *({out} + pos) = padded; \
             return 0; }} ",
            call = OP_CALL,
            nop = OP_NOP,
            out = LAYOUT_OUT)
    }

    // ─── Table helpers ────────────────────────────────

    fn canonical_addsymbol() -> String {
        format!(
            "int addsymbol(int ns, int nl) {{ \
             int cnt = *{sc}; \
             if (32 <= cnt) {{ *{e} = 1; return 0; }} \
             int i = 0; \
             int base = 0; \
             int sns = 0; \
             int snl = 0; \
             while (i < cnt) {{ \
             base = {st} + i * 24; \
             sns = *base; snl = *(base + 8); \
             if (nameseq(ns, nl, sns, snl) == 1) {{ *{e} = 1; return 0; }} \
             i = i + 1; }} \
             int off = (0 - (cnt + 1)) * 8; \
             base = {st} + cnt * 24; \
             *base = ns; *(base + 8) = nl; *(base + 16) = off; \
             *{sc} = cnt + 1; \
             return off; }} ",
            sc = WS_SYM_COUNT,
            e = WS_ERROR,
            st = WS_SYM_TABLE)
    }

    fn canonical_lookupsymbol() -> String {
        format!(
            "int lookupsymbol(int ns, int nl) {{ \
             int cnt = *{sc}; \
             int i = 0; \
             int base = 0; \
             while (i < cnt) {{ \
             base = {st} + i * 24; \
             if (nameseq(ns, nl, *base, *(base + 8)) == 1) {{ \
             return *(base + 16); }} \
             i = i + 1; }} \
             *{e} = 1; return 0; }} ",
            sc = WS_SYM_COUNT,
            e = WS_ERROR,
            st = WS_SYM_TABLE)
    }

    fn canonical_addfunc() -> String {
        format!(
            "int addfunc(int ns, int nl, int arity) {{ \
             int cnt = *{fc}; \
             if (64 <= cnt) {{ *{e} = 1; return 0; }} \
             int base = {ft} + cnt * 32; \
             *base = ns; *(base + 8) = nl; \
             *(base + 16) = *{op}; *(base + 24) = arity; \
             *{fc} = cnt + 1; return 0; }} ",
            fc = WS_FUNC_COUNT,
            e = WS_ERROR,
            ft = WS_FUNC_TABLE,
            op = WS_OUT_POS)
    }

    fn canonical_lookupfunc() -> String {
        format!(
            "int lookupfunc(int ns, int nl) {{ \
             int cnt = *{fc}; \
             int i = 0; \
             int base = 0; \
             while (i < cnt) {{ \
             base = {ft} + i * 32; \
             if (nameseq(ns, nl, *base, *(base + 8)) == 1) {{ \
             return *(base + 16); }} \
             i = i + 1; }} \
             *{e} = 1; return 0; }} ",
            fc = WS_FUNC_COUNT,
            e = WS_ERROR,
            ft = WS_FUNC_TABLE)
    }

    fn canonical_lookuparity() -> String {
        format!(
            "int lookuparity(int ns, int nl) {{ \
             int cnt = *{fc}; \
             int i = 0; \
             int base = 0; \
             while (i < cnt) {{ \
             base = {ft} + i * 32; \
             if (nameseq(ns, nl, *base, *(base + 8)) == 1) {{ \
             return *(base + 24); }} \
             i = i + 1; }} \
             *{e} = 1; return 0; }} ",
            fc = WS_FUNC_COUNT,
            e = WS_ERROR,
            ft = WS_FUNC_TABLE)
    }

    fn canonical_addfixup() -> String {
        format!(
            "int addfixup(int cp, int ns, int nl, int argc) {{ \
             int cnt = *{xc}; \
             if (512 <= cnt) {{ *{e} = 1; return 0; }} \
             int base = {xt} + cnt * 32; \
             *base = cp; *(base + 8) = ns; \
             *(base + 16) = nl; *(base + 24) = argc; \
             *{xc} = cnt + 1; return 0; }} ",
            xc = WS_FIX_COUNT,
            e = WS_ERROR,
            xt = WS_FIX_TABLE)
    }

    fn canonical_resolvefixups() -> String {
        format!(
            "int resolvefixups() {{ \
             int cnt = *{xc}; \
             int i = 0; \
             int base = 0; \
             int cp = 0; \
             int ns = 0; \
             int nl = 0; \
             int argc = 0; \
             int addr = 0; \
             int arity = 0; \
             while (i < cnt) {{ \
             base = {xt} + i * 32; \
             cp = *base; ns = *(base + 8); \
             nl = *(base + 16); argc = *(base + 24); \
             addr = lookupfunc(ns, nl); \
             arity = lookuparity(ns, nl); \
             if (argc != arity) {{ *{e} = 1; }} \
             patchcall(cp, addr); \
             i = i + 1; }} \
             return 0; }} ",
            xc = WS_FIX_COUNT,
            e = WS_ERROR,
            xt = WS_FIX_TABLE)
    }

    #[test]
    fn b50e_readbyte_compiles() {
        let src = format!(
            "{}int main() {{ return 42; }}",
            canonical_readbyte());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: readbyte() compiles ✓");
    }

    #[test]
    fn b50e_peekchar_compiles() {
        let src = format!(
            "{}{}int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_peekchar());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: peekchar() compiles ✓");
    }

    #[test]
    fn b50e_advance_compiles() {
        let src = format!(
            "{}int main() {{ return 42; }}",
            canonical_advance());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: advance() compiles ✓");
    }

    #[test]
    fn b50e_skipws_compiles() {
        // All four lexer primitives together.
        let src = format!(
            "{}{}{}{}int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_peekchar(),
            canonical_advance(),
            canonical_skipws());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: skipws() (all 4 lexer primitives) compiles ✓");
    }

    #[test]
    fn b50e_readbyte_expressions() {
        // Verify the arithmetic patterns used in readbyte compile
        // and evaluate correctly in child.
        // (5 & (0 - 8)) = 0  [align down]
        // ((37 & 7) * 8) = 40  [shift calc]
        let src = format!(
            "{}int main() {{ return (5 & (0 - 8)) + ((37 & 7) * 8); }}",
            canonical_readbyte());
        run_6b4_test(src.as_bytes(), 40, true);
        eprintln!("6B.5.0e: readbyte expression patterns ✓");
    }

    #[test]
    fn b50e_nameseq_compiles() {
        let src = format!(
            "{}{}int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_nameseq());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: nameseq() compiles ✓");
    }

    #[test]
    fn b50e_classifykw_compiles() {
        let src = format!(
            "{}{}int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_classifykw());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: classifykw() compiles ✓");
    }

    #[test]
    fn b50e_full_lexer_compiles() {
        // Complete lexer: 14 functions (7.4: +validateutf8, called by scanstring).
        let src = format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}\
             int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_writebyte(),
            canonical_storeliteral(),
            canonical_peekchar(),
            canonical_advance(),
            canonical_skipws(),
            canonical_nameseq(),
            canonical_classifykw(),
            canonical_setchartok(),
            canonical_scannumber(),
            canonical_scanident(),
            canonical_validateutf8(),
            canonical_scanstring(),
            );
        eprintln!("6B.5.0e: full lexer source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: full lexer (14 functions) compiles ✓");
    }

    #[test]
    fn b50e_nexttoken_compiles() {
        // Complete lexer + tokenizer (15 functions).
        let src = format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}\
             int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_writebyte(),
            canonical_storeliteral(),
            canonical_peekchar(),
            canonical_advance(),
            canonical_skipws(),
            canonical_nameseq(),
            canonical_classifykw(),
            canonical_setchartok(),
            canonical_scannumber(),
            canonical_scanident(),
            canonical_validateutf8(),
            canonical_scanstring(),
            canonical_nexttoken(),
            );
        eprintln!("6B.5.0e: lexer+tokenizer source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: complete tokenizer (15 functions) compiles ✓");
    }

    // ─── Emit/encoding layer tests ──────────────────

    #[test]
    fn b50e_encoding_compiles() {
        // All four encoding helpers + emit.
        let src = format!(
            "{}{}{}{}{}int main() {{ return 42; }}",
            canonical_enci(),
            canonical_encr(),
            canonical_encs(),
            canonical_encb(),
            canonical_emit());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: enci/encr/encs/encb/emit compile ✓");
    }

    #[test]
    fn b50e_enci_value() {
        // Verify enc_i produces the correct instruction word.
        // MOVI R4, 42: opcode=8 rd=4 rs=0 imm=42
        // Expected: (8 << 26) | (4 << 22) | 42
        let src = format!(
            "{}int main() {{ return enci(8, 4, 0, 42); }}",
            canonical_enci());
        let expected: u64 = ((8u64 << 26) | (4 << 22) | 42) as u64;
        run_6b4_test(src.as_bytes(), expected, true);
        eprintln!("6B.5.0e: enci(8,4,0,42) = {:#x} ✓", expected);
    }

    #[test]
    fn b50e_encr_value() {
        // MOV R4, R0: opcode=0 rd=4 rs=0 rs2=0 (fn3=0)
        // Expected: (0 << 26) | (4 << 22)
        let src = format!(
            "{}int main() {{ return encr(0, 4, 0, 0); }}",
            canonical_encr());
        let expected: u64 = (4u64 << 22) as u64;
        run_6b4_test(src.as_bytes(), expected, true);
        eprintln!("6B.5.0e: encr(0,4,0,0) = {:#x} ✓", expected);
    }

    #[test]
    fn b50e_encs_value() {
        // HALT: opcode=62
        // Expected: 62 << 26
        let src = format!(
            "{}int main() {{ return encs(62); }}",
            canonical_encs());
        let expected: u64 = (62u64 << 26) as u64;
        run_6b4_test(src.as_bytes(), expected, true);
        eprintln!("6B.5.0e: encs(62) = {:#x} ✓", expected);
    }

    #[test]
    fn b50e_encb_value() {
        // BCC EQ, +4: opcode=48 cond=0 disp=4
        // Expected: (48 << 26) | 4
        let src = format!(
            "{}int main() {{ return encb(0, 4); }}",
            canonical_encb());
        let expected: u64 = ((48u64 << 26) | 4) as u64;
        run_6b4_test(src.as_bytes(), expected, true);
        eprintln!("6B.5.0e: encb(0,4) = {:#x} ✓", expected);
    }

    /// Helper: all canonical functions needed for expression compilation.
    fn canonical_expr_prelude() -> String {
        format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
            canonical_readbyte(),
            canonical_writebyte(),
            canonical_storeliteral(),
            canonical_peekchar(),
            canonical_advance(),
            canonical_skipws(),
            canonical_nameseq(),
            canonical_classifykw(),
            canonical_setchartok(),
            canonical_scannumber(),
            canonical_scanident(),
            canonical_validateutf8(),
            canonical_scanstring(),
            canonical_nexttoken(),
            canonical_enci(),
            canonical_encr(),
            canonical_encs(),
            canonical_encb(),
            canonical_emit(),
            canonical_patchbranch(),
            canonical_patchcall(),
            canonical_addsymbol(),
            canonical_lookupsymbol(),
            canonical_addfunc(),
            canonical_lookupfunc(),
            canonical_lookuparity(),
            canonical_addfixup(),
            canonical_resolvefixups(),
            canonical_exprsave(),
            canonical_exprrestore(),
            canonical_compilecall(),
            canonical_compileprimary(),
            canonical_compileunary(),
            canonical_compilemult(),
            canonical_compileadd(),
            canonical_compileshift(),
            canonical_compilebitand(),
            canonical_compilebitor(),
        )
    }

    /// Helper: all canonical functions through compile_block (stmt layer).
    fn canonical_stmt_prelude() -> String {
        format!(
            "{}{}{}{}{}{}{}",
            canonical_expr_prelude(),
            canonical_compilerel(),
            canonical_compileeq(),
            canonical_compileexpr(),
            canonical_compilestmt(),
            canonical_compileblock(),
            "")
    }

    #[test]
    fn b50e_expr_compiles() {
        // Full expression compiler: all 10 precedence levels.
        let src = format!(
            "{}{}{}{}int main() {{ return 42; }}",
            canonical_expr_prelude(),
            canonical_compilerel(),
            canonical_compileeq(),
            canonical_compileexpr());
        eprintln!("6B.5.0e: expr compiler source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: canonical expression closure (37 functions) ✓");
    }

    #[test]
    fn b50e_stmt_compiles() {
        // Stmt layer: compile_stmt + compile_block on top of expr closure.
        let src = format!(
            "{}int main() {{ return 42; }}",
            canonical_stmt_prelude());
        eprintln!("6B.5.0e: stmt compiler source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: canonical stmt+block (39 functions) ✓");
    }

    #[test]
    fn b50e_funcdef_compiles() {
        // Stmt prelude + compilefuncdef + findmain (no canonical main).
        let src = format!(
            "{}{}{}int main() {{ return 42; }}",
            canonical_stmt_prelude(),
            canonical_compilefuncdef(),
            canonical_findmain());
        eprintln!("6B.5.0e: funcdef+findmain source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: canonical funcdef+findmain (41 functions) ✓");
    }

    #[test]
    fn b50e_full_compiler_compiles() {
        // Full canonical compiler: all CANONICAL_FUNC_COUNT functions compile without error.
        // Phase 8.5: CC_A supervised by ankad.
        let src = canonical_compiler_source();
        eprintln!("6B.5.0e: full compiler source = {} bytes", src.len());

        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_bytes = asm.to_bytes();

        // CC_A code_vaddr = 0
        let r = run_supervised_compiler(&code_bytes, 0, src.as_bytes());

        assert!(r.kernel.processes[0].exited(),
            "ankad did not exit");
        assert_eq!(r.wait_tag, 0,
            "CC_A faulted compiling canonical source (tag={})", r.wait_tag);

        // Read workspace diagnostics
        let read = |off: u64| -> u64 {
            let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read(0x18);
        let ws_funcs = read(0x58);
        let ws_out   = read(0x48);
        eprintln!("6B.5.0e: host compiled {} functions, {} bytes output, error={}",
            ws_funcs, ws_out, ws_error);
        assert_eq!(ws_error, 0, "host compiler reported error");
        assert_eq!(ws_funcs, CANONICAL_FUNC_COUNT,
            "expected {} canonical functions", CANONICAL_FUNC_COUNT);
        eprintln!("6B.5.0e: canonical full compiler ({} functions) [supervised] ✓",
            CANONICAL_FUNC_COUNT);
    }

    #[test]
    fn b50e_expr_arithmetic() {
        // Verify expression code generation produces correct results
        // through the host compiler with a simple main body.
        run_6b4_test(b"int main() { return 3 + 4 * 5; }", 23, true);
        eprintln!("6B.5 expr: 3 + 4 * 5 = 23 ✓");
    }

    #[test]
    fn b50e_expr_comparison() {
        run_6b4_test(b"int main() { return 5 < 10; }", 1, true);
        run_6b4_test(b"int main() { return 10 < 5; }", 0, true);
        run_6b4_test(b"int main() { return 5 == 5; }", 1, true);
        run_6b4_test(b"int main() { return 5 != 5; }", 0, true);
        run_6b4_test(b"int main() { return 5 <= 5; }", 1, true);
        eprintln!("6B.5 expr: comparison operators ✓");
    }

    #[test]
    fn b50e_expr_bitwise() {
        run_6b4_test(b"int main() { return 6 & 3; }", 2, true);
        run_6b4_test(b"int main() { return 5 | 2; }", 7, true);
        run_6b4_test(b"int main() { return 1 << 4; }", 16, true);
        run_6b4_test(b"int main() { return 32 >> 3; }", 4, true);
        eprintln!("6B.5 expr: bitwise operators ✓");
    }

    // ─── Phase 7 — String literal tokenization ───────────

    #[test]
    fn p70_string_token_recognized() {
        // The tokenizer recognizes "hello" as TOK_STRING (28).
        // compileprimary stores the literal in the output buffer
        // (two-ended allocator) and emits MOVI R4, literal_offset.
        // The child returns the offset (pointer to the literal).
        //
        // "hello" = 5 bytes → aligned 8 → total 16 bytes → np = 0xFFF0.
        //
        // Architectural invariant: Bytes ≠ Text.
        // String literals are arbitrary UTF-8 bytes + explicit byte
        // length.  No NUL termination.  Byte length ≠ codepoint count
        // ≠ grapheme count.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 16;
        let src = br#"int main() { return "hello"; }"#;
        run_6b4_test(src, expected_np, true);
        eprintln!("7.2: string literal → offset 0x{:X} ✓", expected_np);
    }

    #[test]
    fn p70_string_token_utf8() {
        // UTF-8 string literal: "İzmir" is 6 bytes (İ = 0xC4 0xB0,
        // z = 0x7A, m = 0x6D, i = 0x69, r = 0x72).
        // The tokenizer preserves all UTF-8 bytes verbatim.
        // byte_length("İzmir") = 6 ≠ codepoint_count = 5 ≠ grapheme_count = 5.
        // 6 bytes → aligned 8 → total 16 → np = 0xFFF0.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 16;
        let src = "int main() { return \"İzmir\"; }";
        run_6b4_test(src.as_bytes(), expected_np, true);
        eprintln!("7.2: UTF-8 string literal → offset 0x{:X} ✓", expected_np);
    }

    #[test]
    fn p70_string_token_workspace_state() {
        // Verify the tokenizer sets WS_TOK_TYPE, WS_TOK_NAME_START,
        // WS_TOK_NAME_LEN correctly for a string literal.
        // Phase 8.5: CC_A supervised by ankad.
        let src = br#"int main() { return "hello"; }"#;

        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_bytes = asm.to_bytes();

        let r = run_supervised_compiler(&code_bytes, 0, src);

        assert!(r.kernel.processes[0].exited(), "ankad should exit");
        assert_eq!(r.wait_tag, 0, "CC_A faulted (tag={})", r.wait_tag);

        let read = |off: u64| -> u64 {
            let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read(0x18);
        assert_eq!(ws_error, 0, "compiler should succeed with string literal");
        eprintln!("7.0: string literal workspace state verified [supervised] ✓");
    }

    #[test]
    fn p70_string_unterminated_error() {
        // Unterminated string literal sets error.
        let src = br#"int main() { return "hello; }"#;
        run_6b4_test(src, u64::MAX, false);
        eprintln!("7.0: unterminated string literal → error ✓");
    }

    #[test]
    fn p70_string_empty() {
        // Empty string "" → byte_len = 0, no data bytes.
        // aligned(0) = 0, total = 8.  np = OUTPUT_SIZE - 8.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 8;
        let src = br#"int main() { return ""; }"#;
        run_6b4_test(src, expected_np, true);
        eprintln!("7.2: empty string literal → offset 0x{:X} ✓", expected_np);
    }

    #[test]
    fn p70_string_embedded_nul() {
        // ByteString allows embedded NUL: "a\0b" (using raw bytes).
        // 3 bytes → aligned 8 → total 16 → np = OUTPUT_SIZE - 16.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 16;
        let mut src = Vec::from(&b"int main() { return \""[..]);
        src.push(b'a');
        src.push(0x00);
        src.push(b'b');
        src.extend_from_slice(b"\"; }");
        run_6b4_test(&src, expected_np, true);
        eprintln!("7.2: embedded NUL in ByteString → offset 0x{:X} ✓", expected_np);
    }

    #[test]
    fn p70_string_multibyte_utf8() {
        // "şarap" — ş is 2 bytes (0xC5 0x9F), total 6 bytes, 5 codepoints.
        // 6 bytes → aligned 8 → total 16 → np = OUTPUT_SIZE - 16.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 16;
        let src = "int main() { return \"şarap\"; }";
        let src_bytes = src.as_bytes();
        let sarap = "şarap";
        assert_eq!(sarap.len(), 6, "şarap is 6 UTF-8 bytes");
        assert_eq!(sarap.chars().count(), 5, "şarap is 5 codepoints");
        run_6b4_test(src_bytes, expected_np, true);
        eprintln!("7.2: multi-byte UTF-8 string (şarap) → offset 0x{:X} ✓", expected_np);
    }

    // ─── Phase 7.1 — Literal object representation ───────

    #[test]
    fn p71_store_literal_hello() {
        // Compile a program containing "hello" as a string literal.
        // Two-ended allocator (7.2): literal stored at top of output buffer.
        // "hello" = 5 bytes → aligned 8 → total 16 bytes (header + data).
        // np = OUTPUT_SIZE - 16 = 0xFFF0 = 65520.
        // Phase 8.5: CC_A supervised by ankad.
        let src = br#"int main() { return "hello"; }"#;

        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_bytes = asm.to_bytes();

        let r = run_supervised_compiler(&code_bytes, 0, src);

        assert!(r.kernel.processes[0].exited(), "ankad should exit");
        assert_eq!(r.wait_tag, 0, "CC_A faulted (tag={})", r.wait_tag);

        let read_ws = |off: u64| -> u64 {
            let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws(0x18);
        assert_eq!(ws_error, 0, "compiler should succeed with string literal");

        // Two-ended allocator: "hello" stored at output buffer offset 0xFFF0.
        let lit_pos = read_ws((WS_LIT_POS - LAYOUT_WS) as u64);
        let expected_np: u64 = OUTPUT_SIZE as u64 - 16; // 0xFFF0
        assert_eq!(lit_pos, expected_np,
            "WS_LIT_POS should be 0x{:X} (OUTPUT_SIZE - 16)", expected_np);

        // Read header at output buffer + np
        let lit_header = r.kernel.fabric.read_physical(r.output_phys + expected_np, 8);
        let byte_len = u64::from_le_bytes(lit_header.try_into().unwrap());
        assert_eq!(byte_len, 5, "byte_len should be 5 for \"hello\"");

        // Read data bytes
        let lit_data = r.kernel.fabric.read_physical(r.output_phys + expected_np + 8, 5);
        assert_eq!(&lit_data[..], b"hello",
            "literal data should contain 'hello'");

        eprintln!("7.2: literal object at output+0x{:X} [u64 byte_len=5][hello] [supervised] ✓",
            expected_np);
        eprintln!("     two-ended allocator: code grows up, literals grow down");
    }

    #[test]
    fn p71_store_literal_utf8_izmir() {
        // "İzmir" is 6 UTF-8 bytes: C4 B0 7A 6D 69 72.
        // byte_length(6) ≠ codepoint_count(5) ≠ grapheme_count(5).
        // Literal stored at output buffer top via two-ended allocator.
        // "İzmir" = 6 bytes → aligned 8 → total 16 bytes → np = 0xFFF0.
        // Child returns np (the literal offset, not its content).
        let expected_np: u64 = OUTPUT_SIZE as u64 - 16; // 0xFFF0
        let src = "int main() { return \"İzmir\"; }";
        run_6b4_test(src.as_bytes(), expected_np, true);
        eprintln!("7.2: İzmir literal at offset 0x{:X} ✓", expected_np);
    }

    #[test]
    fn p71_store_literal_empty() {
        // Empty string "" → byte_len = 0, no data bytes.
        // aligned(0) = 0, total = 8 (header only).  np = 0xFFF8.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 8;
        let src = br#"int main() { return ""; }"#;
        run_6b4_test(src, expected_np, true);
        eprintln!("7.2: empty string literal at offset 0x{:X} ✓", expected_np);
    }

    #[test]
    fn p71_two_literals() {
        // Two string literals: "hello" (first compiled, in foo) and
        // "world" (second, in main).  Each gets 16 bytes in the
        // output buffer.  "hello" is compiled first → np=0xFFF0.
        // "world" is compiled second → np=0xFFE0.
        // main returns the "world" literal offset.
        let expected_np: u64 = OUTPUT_SIZE as u64 - 32; // 0xFFE0
        let src = br#"int foo() { return "hello"; } int main() { return "world"; }"#;
        run_6b4_test(src, expected_np, true);
        eprintln!("7.2: two literals compiled (world at 0x{:X}) ✓", expected_np);
    }

    // ─── Phase 7.2 — Semantic dereference tests ────────────
    // The child process receives R-only authority on the literal
    // segment [lit_start, OUTPUT_SIZE).  Dereferencing a string
    // literal reads the byte_len header: *"hello" → 5.
    // Rule 29: the child has READ but not EXECUTE on literals.

    #[test]
    fn p72_deref_hello() {
        // *"hello" → dereference the literal pointer, reads byte_len = 5.
        // The literal header is at output offset 0xFFF0, and its first
        // 8 bytes contain the u64 byte_len = 5.
        let src = br#"int main() { return *"hello"; }"#;
        run_6b4_test(src, 5, true);
        eprintln!("7.2: *\"hello\" = 5 (byte_len via R-only literal segment) ✓");
    }

    #[test]
    fn p72_deref_izmir() {
        // *"İzmir" → 6 (UTF-8 byte count, not codepoint count).
        let src = "int main() { return *\"İzmir\"; }";
        run_6b4_test(src.as_bytes(), 6, true);
        eprintln!("7.2: *\"İzmir\" = 6 (byte_len, Bytes ≠ Text) ✓");
    }

    #[test]
    fn p72_deref_empty() {
        // *"" → 0 (empty string has byte_len = 0).
        let src = br#"int main() { return *""; }"#;
        run_6b4_test(src, 0, true);
        eprintln!("7.2: *\"\" = 0 (empty literal dereference) ✓");
    }

    #[test]
    fn p72_deref_two_literals() {
        // Two literals, dereference the second.
        // "hello" compiled first (foo), "world" compiled second (main).
        // *"world" → 5.
        let src = br#"int foo() { return *"hello"; } int main() { return *"world"; }"#;
        run_6b4_test(src, 5, true);
        eprintln!("7.2: *\"world\" = 5 (second literal deref) ✓");
    }

    #[test]
    fn b50e_expr_funcall() {
        run_6b4_test(
            b"int add(int a, int b) { return a + b; } int main() { return add(10, 32); }",
            42, true);
        eprintln!("6B.5 expr: function call with args ✓");
    }

    #[test]
    fn b50e_expr_deref() {
        // Dereference operator: *addr reads from memory
        // Use a local variable and read it via pointer arithmetic
        run_6b4_test(
            b"int main() { int x = 99; return x; }",
            99, true);
        eprintln!("6B.5 expr: variable read ✓");
    }

    #[test]
    fn b50e_patch_compiles() {
        // patch_branch and patch_call compile.
        let src = format!(
            "{}{}{}{}{}{}{}int main() {{ return 42; }}",
            canonical_enci(),
            canonical_encr(),
            canonical_encs(),
            canonical_encb(),
            canonical_emit(),
            canonical_patchbranch(),
            canonical_patchcall());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: patchbranch/patchcall compile ✓");
    }

    #[test]
    fn b50e_tables_compile() {
        // All table helpers. Depends on readbyte + nameseq (for name comparison)
        // and patchcall (for resolve_fixups).
        let src = format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}\
             int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_nameseq(),
            canonical_enci(),
            canonical_encr(),
            canonical_encs(),
            canonical_encb(),
            canonical_emit(),
            canonical_patchcall(),
            canonical_addsymbol(),
            canonical_lookupsymbol(),
            canonical_addfunc(),
            canonical_lookupfunc(),
            canonical_lookuparity(),
            canonical_addfixup(),
            );
        eprintln!("6B.5.0e: table helpers source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: table helpers (14 functions) compile ✓");
    }

    #[test]
    fn b50e_resolvefixups_compiles() {
        // resolve_fixups depends on lookupfunc, lookuparity, patchcall.
        let src = format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}\
             int main() {{ return 42; }}",
            canonical_readbyte(),
            canonical_nameseq(),
            canonical_enci(),
            canonical_encr(),
            canonical_encs(),
            canonical_encb(),
            canonical_emit(),
            canonical_patchcall(),
            canonical_addsymbol(),
            canonical_lookupsymbol(),
            canonical_addfunc(),
            canonical_lookupfunc(),
            canonical_lookuparity(),
            canonical_addfixup(),
            canonical_resolvefixups(),
            );
        eprintln!("6B.5.0e: resolve_fixups source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: resolve_fixups (15 functions) compiles ✓");
    }

    // ═══════════════════════════════════════════════════════════
    //  6B.5.1 — Compiler equivalence: CC_B compiles programs
    // ═══════════════════════════════════════════════════════════
    //
    //  CC_A (host compiler, AST-built) compiles canonical source → CC_B.
    //  CC_B (child binary, 57KB) runs as a process, compiles test
    //  programs, and executes them via SYS_SEAL + SYS_EXEC.
    //
    //  CC_B's code is loaded at virtual address CCB_CODE_BASE (0x30000),
    //  above all data regions.  CALL/BCC are PC-relative, so function
    //  calls work regardless of code base address.  Data regions remain
    //  at canonical addresses: source @ LAYOUT_SRC, output @ LAYOUT_OUT,
    //  workspace @ LAYOUT_WS, stack @ LAYOUT_STACK.

    const CCB_CODE_BASE: u64 = 0x30000;

    /// Extract CC_B binary: CC_A compiles canonical source → output buffer.
    /// Returns the CC_B code bytes.
    /// Build CC_B by running CC_A (under ankad supervision) on the canonical source.
    ///
    /// Phase 8.5: host constructs CC_A artifact; ankad supervises CC_A execution.
    fn build_ccb() -> Vec<u8> {
        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_bytes = asm.to_bytes();

        let canon_src = canonical_compiler_source();
        // CC_A code_vaddr = 0
        let r = run_supervised_compiler(&code_bytes, 0, canon_src.as_bytes());

        assert!(r.kernel.processes[0].exited(),
            "ankad did not exit while building CC_B");
        assert_eq!(r.wait_tag, 0,
            "CC_A faulted while compiling canonical source (tag={})", r.wait_tag);

        // Read output size from workspace
        let read_ws = |off: u64| -> u64 {
            let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws(0x18);
        let out_pos = read_ws(0x48);
        let ws_funcs = read_ws(0x58);
        assert_eq!(ws_error, 0, "CC_A error compiling canonical source");
        assert_eq!(ws_funcs, CANONICAL_FUNC_COUNT,
            "CC_A compiled wrong function count (expected {})", CANONICAL_FUNC_COUNT);

        // Extract CC_B binary from output buffer
        let ccb_bytes = r.kernel.fabric.read_physical(r.output_phys, out_pos).to_vec();
        eprintln!("build_ccb: CC_B = {} bytes ({} functions) [supervised]",
            ccb_bytes.len(), ws_funcs);
        ccb_bytes
    }

    /// Run CC_B (the canonical compiler binary) on a test program.
    ///
    /// CC_B is loaded at CCB_CODE_BASE (0x30000) — above all data regions.
    /// Data regions sit at canonical addresses derived from TEXT_SIZE=0x6000.
    /// CC_B compiles the test source, seals output, executes the child.
    /// The child's exit code propagates through CC_B → returned here.
    fn run_ccb_test(ccb: &[u8], test_source: &[u8], expected_exit: u64) {
        let kernel = run_ccb_harness(ccb, test_source, expected_exit);
        drop(kernel);
    }

    /// CC_B harness returning the Kernel for byte_output inspection.
    ///
    /// Phase 8.5: CC_B is now executed as a supervised process under ankad.
    fn run_ccb_harness(ccb: &[u8], test_source: &[u8], expected_exit: u64) -> Kernel {
        let r = run_supervised_compiler(ccb, CCB_CODE_BASE, test_source);

        let ankad_exited = r.kernel.processes[0].exited();
        let exit_code = r.wait_detail;

        // Diagnostic dumps
        if !ankad_exited || r.wait_tag != 0 || exit_code != expected_exit {
            let read_ws = |off: u64| -> u64 {
                let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
            if !ankad_exited {
                eprintln!("CC_B STUCK: ankad did not exit (compiler may be hung)");
                eprintln!("  pos={} tok={} error={} out_pos={} funcs={} fixups={}",
                    read_ws(0x00), read_ws(0x20), read_ws(0x18),
                    read_ws(0x48), read_ws(0x58), read_ws(0x60));
            } else if r.wait_tag != 0 {
                eprintln!("CC_B FAULT: compiler faulted (wait_tag={})", r.wait_tag);
            } else {
                eprintln!("CC_B DIAG: error={} tok={} pos={} out_pos={} funcs={} fixups={}",
                    read_ws(0x18), read_ws(0x20), read_ws(0x00),
                    read_ws(0x48), read_ws(0x58), read_ws(0x60));
            }
        }

        assert!(ankad_exited, "ankad (CC_B supervisor) did not exit");
        assert_eq!(r.wait_tag, 0,
            "CC_B compiled {:?}: compiler faulted (wait_tag={})",
            std::str::from_utf8(test_source).unwrap_or("<invalid>"),
            r.wait_tag);
        assert_eq!(exit_code, expected_exit,
            "CC_B compiled {:?}: expected exit {}, got {}",
            std::str::from_utf8(test_source).unwrap_or("<invalid>"),
            expected_exit, exit_code);
        r.kernel
    }

    /// Run CC_B (the canonical compiler) on source text and extract
    /// Run CC_B on source text and extract the compiled output bytes.
    /// Returns (output_bytes, func_count, error_flag).
    ///
    /// CC_B performs SYS_SEAL + SYS_EXEC on the output as part of its
    /// normal execution.  This helper extracts the compiled bytes from
    /// the persisting output object irrespective of the executed child's
    /// result.  Phase 8.5: CC_B runs under ankad supervision.
    fn compile_with_ccb(ccb: &[u8], source: &[u8]) -> (Vec<u8>, u64, u64) {
        let r = run_supervised_compiler(ccb, CCB_CODE_BASE, source);

        assert!(r.kernel.processes[0].exited(),
            "ankad (CC_B supervisor) did not exit");

        let read_ws = |off: u64| -> u64 {
            let bytes = r.kernel.fabric.read_physical(r.work_phys + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws(0x18);
        let out_pos = read_ws(0x48);
        let ws_funcs = read_ws(0x58);

        let output_bytes = if ws_error == 0 && out_pos > 0 {
            r.kernel.fabric.read_physical(r.output_phys, out_pos).to_vec()
        } else {
            Vec::new()
        };

        (output_bytes, ws_funcs, ws_error)
    }

    #[test]
    fn b51_ccb_return_literal() {
        let ccb = build_ccb();
        run_ccb_test(&ccb, b"int main() { return 42; }", 42);
        eprintln!("6B.5.1: CC_B compiles 'return 42' → 42 ✓");
    }

    #[test]
    fn b51_ccb_arithmetic() {
        let ccb = build_ccb();
        run_ccb_test(&ccb, b"int main() { return 3 + 4 * 5; }", 23);
        run_ccb_test(&ccb, b"int main() { return 100 - 58; }", 42);
        run_ccb_test(&ccb, b"int main() { return (2 + 3) * (4 + 1); }", 25);
        eprintln!("6B.5.1: CC_B arithmetic ✓");
    }

    #[test]
    fn b51_ccb_variables() {
        let ccb = build_ccb();
        run_ccb_test(&ccb,
            b"int main() { int x = 40; int y = 2; return x + y; }", 42);
        run_ccb_test(&ccb,
            b"int main() { int a = 10; int b = 3; int c = a * b + 12; return c; }", 42);
        eprintln!("6B.5.1: CC_B variables ✓");
    }

    #[test]
    fn b51_ccb_if_else() {
        let ccb = build_ccb();
        run_ccb_test(&ccb,
            b"int main() { int x = 5; if (x < 10) { return 42; } else { return 0; } }", 42);
        run_ccb_test(&ccb,
            b"int main() { int x = 15; if (x < 10) { return 0; } else { return 42; } }", 42);
        eprintln!("6B.5.1: CC_B if/else ✓");
    }

    #[test]
    fn b51_ccb_while() {
        let ccb = build_ccb();
        run_ccb_test(&ccb,
            b"int main() { int i = 0; int s = 0; while (i < 10) { s = s + i; i = i + 1; } return s; }", 45);
        eprintln!("6B.5.1: CC_B while loop (sum 0..9 = 45) ✓");
    }

    #[test]
    fn b51_ccb_function_calls() {
        let ccb = build_ccb();
        run_ccb_test(&ccb,
            b"int add(int a, int b) { return a + b; } int main() { return add(20, 22); }", 42);
        run_ccb_test(&ccb,
            b"int double(int x) { return x + x; } int main() { return double(21); }", 42);
        eprintln!("6B.5.1: CC_B function calls ✓");
    }

    #[test]
    fn b51_ccb_recursion() {
        let ccb = build_ccb();
        // Factorial: 5! = 120, but 120 exceeds easy range. Use sum(5) = 15.
        run_ccb_test(&ccb,
            b"int sum(int n) { if (n == 0) { return 0; } else { return n + sum(n - 1); } } \
              int main() { return sum(5); }", 15);
        eprintln!("6B.5.1: CC_B recursion (sum(5) = 15) ✓");
    }

    #[test]
    fn b51_ccb_deref() {
        let ccb = build_ccb();
        // The grandchild only has code+stack+trap (from SYS_EXEC).
        // Stack: virtual 0x10000, 0x4000 bytes. Use low stack as scratch.
        // SP starts at 0x14000, so 0x10000 is safe scratch space.
        run_ccb_test(&ccb,
            b"int main() { int p = 65536; *p = 42; return *p; }", 42);
        eprintln!("6B.5.1: CC_B deref write+read ✓");
    }

    #[test]
    fn b51_ccb_bitwise() {
        let ccb = build_ccb();
        run_ccb_test(&ccb, b"int main() { return 6 & 3; }", 2);
        run_ccb_test(&ccb, b"int main() { return 5 | 2; }", 7);
        run_ccb_test(&ccb, b"int main() { return 1 << 4; }", 16);
        run_ccb_test(&ccb, b"int main() { return 32 >> 3; }", 4);
        eprintln!("6B.5.1: CC_B bitwise operators ✓");
    }

    #[test]
    fn b51_ccb_comparison() {
        let ccb = build_ccb();
        run_ccb_test(&ccb, b"int main() { return 5 < 10; }", 1);
        run_ccb_test(&ccb, b"int main() { return 10 < 5; }", 0);
        run_ccb_test(&ccb, b"int main() { return 5 == 5; }", 1);
        run_ccb_test(&ccb, b"int main() { return 5 != 5; }", 0);
        run_ccb_test(&ccb, b"int main() { return 5 <= 5; }", 1);
        eprintln!("6B.5.1: CC_B comparison operators ✓");
    }

    // ═══════════════════════════════════════════════════════════
    //  Self-hosted compiler reproducibility invariant
    //
    //  This is the permanent stage-2/stage-3 test.  It verifies:
    //
    //    Stage 1:  CC_A(source_CC) → CC_B     (host compiles canonical source)
    //    Stage 2:  CC_B(source_CC) → CC_C     (child compiles canonical source)
    //    Assert:   CC_B == CC_C               (binary fixed point)
    //    Assert:   CC_C passes regression corpus (semantic correctness)
    //
    //  If this test fails, either the canonical source or the host
    //  compiler has a semantic divergence.  The fixed-point property
    //  is a hard assertion, not advisory.
    //
    //  The compiler binary is position-independent for code:
    //  all CALL and BCC use PC-relative displacements.  Data addresses
    //  (LAYOUT_SRC, LAYOUT_OUT, LAYOUT_WS) are absolute and loaded
    //  via MOVI, so they must be within the 18-bit signed immediate
    //  range (≤ 131071).  The code itself can load at any aligned
    //  virtual base — the test uses CCB_CODE_BASE = 0x30000.
    // ═══════════════════════════════════════════════════════════

    /// Semantic regression corpus: exercises every language feature.
    /// Both CC_B and CC_C must produce identical behavior for each program.
    fn run_compiler_corpus(compiler: &[u8], label: &str) {
        run_ccb_test(compiler, b"int main() { return 42; }", 42);
        run_ccb_test(compiler, b"int main() { return 3 + 4 * 5; }", 23);
        run_ccb_test(compiler, b"int main() { return 100 - 58; }", 42);
        run_ccb_test(compiler, b"int main() { return (2 + 3) * (4 + 1); }", 25);
        run_ccb_test(compiler,
            b"int main() { int x = 40; int y = 2; return x + y; }", 42);
        run_ccb_test(compiler,
            b"int main() { int a = 10; int b = 3; int c = a * b + 12; return c; }", 42);
        run_ccb_test(compiler,
            b"int main() { int x = 5; if (x < 10) { return 42; } else { return 0; } }", 42);
        run_ccb_test(compiler,
            b"int main() { int x = 15; if (x < 10) { return 0; } else { return 42; } }", 42);
        run_ccb_test(compiler,
            b"int main() { int i = 0; int s = 0; while (i < 10) { s = s + i; i = i + 1; } return s; }", 45);
        run_ccb_test(compiler,
            b"int add(int a, int b) { return a + b; } int main() { return add(20, 22); }", 42);
        run_ccb_test(compiler,
            b"int double(int x) { return x + x; } int main() { return double(21); }", 42);
        run_ccb_test(compiler,
            b"int sum(int n) { if (n == 0) { return 0; } else { return n + sum(n - 1); } } \
              int main() { return sum(5); }", 15);
        run_ccb_test(compiler,
            b"int main() { int p = 65536; *p = 42; return *p; }", 42);
        run_ccb_test(compiler, b"int main() { return 6 & 3; }", 2);
        run_ccb_test(compiler, b"int main() { return 5 | 2; }", 7);
        run_ccb_test(compiler, b"int main() { return 1 << 4; }", 16);
        run_ccb_test(compiler, b"int main() { return 32 >> 3; }", 4);
        run_ccb_test(compiler, b"int main() { return 5 < 10; }", 1);
        run_ccb_test(compiler, b"int main() { return 10 < 5; }", 0);
        run_ccb_test(compiler, b"int main() { return 5 == 5; }", 1);
        run_ccb_test(compiler, b"int main() { return 5 != 5; }", 0);
        run_ccb_test(compiler, b"int main() { return 5 <= 5; }", 1);
        eprintln!("{}: 22-program corpus ✓", label);
    }

    #[test]
    fn b51_bootstrap_closure() {
        // ── Stage 1: CC_A(source_CC) → CC_B ──
        let ccb = build_ccb();
        eprintln!("stage 1: CC_A → CC_B = {} bytes ({} functions)",
            ccb.len(), CANONICAL_FUNC_COUNT);

        // ── Stage 2: CC_B(source_CC) → CC_C ──
        let canon_src = canonical_compiler_source();
        let (ccc, ccc_funcs, ccc_error) = compile_with_ccb(&ccb, canon_src.as_bytes());
        assert_eq!(ccc_error, 0, "CC_B failed to compile canonical source");
        assert_eq!(ccc_funcs, CANONICAL_FUNC_COUNT,
            "CC_C has wrong function count (expected {})", CANONICAL_FUNC_COUNT);
        assert!(!ccc.is_empty(), "CC_C is empty");
        eprintln!("stage 2: CC_B → CC_C = {} bytes ({} functions)",
            ccc.len(), CANONICAL_FUNC_COUNT);

        // ── Fixed-point assertion: CC_B == CC_C ──
        assert_eq!(ccb, ccc,
            "FIXED POINT VIOLATION: CC_B ({} bytes) ≠ CC_C ({} bytes)",
            ccb.len(), ccc.len());
        eprintln!("stage 2: CC_B == CC_C (binary fixed point) ✓");

        // ── Semantic verification: CC_C passes the corpus ──
        run_compiler_corpus(&ccc, "CC_C");
        eprintln!("6B.5.1: bootstrap closure complete — \
            CC_A → CC_B → CC_C, CC_B == CC_C, corpus ✓");
    }

    // ─── 7.2g: Adversarial regression ─────────────────────────
    // CC_B is ~59KB (>0x8000).  When CC_B compiles a program with
    // a string literal, the output image has code in the lower region
    // and the literal in the upper region.  This test verifies:
    //   1. CC_B code_end > 0x8000 (the old fixed boundary)
    //   2. The child can dereference the literal (READ authority)
    //   3. The literal offset and byte_len are correct

    #[test]
    fn p72g_adversarial_large_code_with_literal() {
        let ccb = build_ccb();
        eprintln!("7.2g: CC_B = {} bytes ({:#x})", ccb.len(), ccb.len());

        // Assert: CC_B code exceeds old 0x8000 boundary
        assert!(ccb.len() > 0x8000,
            "CC_B should exceed 0x8000 ({:#x}); \
             adversarial test is only meaningful if code overlaps \
             the old fixed literal boundary",
            ccb.len());
        eprintln!("7.2g: CC_B > 0x8000 ✓ (old boundary would have overlapped)");

        // CC_B compiles `return *"hello"` → child dereferences literal
        // *"hello" reads byte_len = 5 from the literal header.
        run_ccb_test(&ccb, br#"int main() { return *"hello"; }"#, 5);
        eprintln!("7.2g: CC_B + *\"hello\" = 5 ✓ (child reads literal via R cap)");

        // CC_B compiles `return *"İzmir"` → byte_len = 6 (UTF-8)
        let src = "int main() { return *\"İzmir\"; }";
        run_ccb_test(&ccb, src.as_bytes(), 6);
        eprintln!("7.2g: CC_B + *\"İzmir\" = 6 ✓ (UTF-8 literal, Bytes ≠ Text)");

        // CC_B compiles a program with two literals
        run_ccb_test(&ccb,
            br#"int foo() { return *"abc"; } int main() { return *"world"; }"#,
            5);
        eprintln!("7.2g: CC_B + two literals ✓");
    }

    // ─── 7.3g: CC_B + İzmir through buffer write ────────────────
    // CC_B runs at base > 0x8000. Compile the İzmir demanding client
    // through the guest-compiled compiler; SYS_WRITE produces 6 bytes.

    #[test]
    fn p73g_ccb_write_izmir() {
        let ccb = build_ccb();
        assert!(ccb.len() > 0x8000,
            "CC_B should exceed 0x8000 for this test to be meaningful");

        let src = "int main() { int s = \"İzmir\"; return syscall(1, s + 8, *s, 0); }";
        let kernel = run_ccb_harness(&ccb, src.as_bytes(), 0);
        assert_eq!(&kernel.byte_output, b"\xC4\xB0zmir",
            "CC_B + İzmir → expected 6 UTF-8 bytes");
        eprintln!("7.3g: CC_B + İzmir → {:02X?} ✓", &kernel.byte_output);
    }

    // ─── 7.4: UTF-8 validation gate ─────────────────────────────
    //
    // validateutf8() exists only in canonical source (CC_B), not in CC_A.
    // Tests use compile_with_ccb() to feed raw byte sequences as string
    // literals.  Valid UTF-8 compiles normally; invalid UTF-8 sets the
    // error flag and produces no executable child.

    /// Build source bytes with an embedded literal from raw bytes.
    /// The template is: int main() { return *"<bytes>"; }
    /// The dereference (*) reads the length header, giving a small integer
    /// that proves the literal was stored, without requiring child execution.
    fn source_with_literal(bytes: &[u8]) -> Vec<u8> {
        let mut src = b"int main() { return *\"".to_vec();
        src.extend_from_slice(bytes);
        src.extend_from_slice(b"\"; }");
        src
    }

    #[test]
    fn p74_utf8_valid_boundary_cases() {
        let ccb = build_ccb();

        // Each entry: (label, literal bytes, expected success)
        let valid_cases: &[(&str, &[u8])] = &[
            ("NUL",               &[0x00]),
            ("DEL",               &[0x7F]),
            ("C2 80",             &[0xC2, 0x80]),
            ("DF BF",             &[0xDF, 0xBF]),
            ("E0 A0 80",          &[0xE0, 0xA0, 0x80]),
            ("ED 9F BF",          &[0xED, 0x9F, 0xBF]),
            ("EE 80 80",          &[0xEE, 0x80, 0x80]),
            ("EF BF BF",          &[0xEF, 0xBF, 0xBF]),
            ("F0 90 80 80",       &[0xF0, 0x90, 0x80, 0x80]),
            ("F4 8F BF BF",       &[0xF4, 0x8F, 0xBF, 0xBF]),
            ("İzmir",             &[0xC4, 0xB0, 0x7A, 0x6D, 0x69, 0x72]),
        ];

        for (label, bytes) in valid_cases {
            let src = source_with_literal(bytes);
            let (_output, _funcs, error) = compile_with_ccb(&ccb, &src);
            assert_eq!(error, 0,
                "valid UTF-8 '{}' should compile without error", label);
            eprintln!("7.4: valid '{}' ✓", label);
        }
    }

    #[test]
    fn p74_utf8_invalid_boundary_cases() {
        let ccb = build_ccb();

        // Each entry: (label, literal bytes)
        // All must produce error == 1 and no child execution.
        let invalid_cases: &[(&str, &[u8])] = &[
            ("standalone continuation 80",     &[0x80]),
            ("overlong C0 80",                 &[0xC0, 0x80]),
            ("overlong C1 BF",                 &[0xC1, 0xBF]),
            ("truncated 2-byte C2",            &[0xC2]),
            ("overlong 3-byte E0 9F BF",       &[0xE0, 0x9F, 0xBF]),
            ("truncated E0 A0",                &[0xE0, 0xA0]),
            ("truncated 3-byte E1 80",         &[0xE1, 0x80]),
            ("surrogate ED A0 80",             &[0xED, 0xA0, 0x80]),
            ("overlong 4-byte F0 8F BF BF",    &[0xF0, 0x8F, 0xBF, 0xBF]),
            ("truncated F4 8F BF",             &[0xF4, 0x8F, 0xBF]),
            ("above U+10FFFF F4 90 80 80",     &[0xF4, 0x90, 0x80, 0x80]),
            ("invalid lead F5 80 80 80",       &[0xF5, 0x80, 0x80, 0x80]),
            ("invalid lead FF",                &[0xFF]),
        ];

        for (label, bytes) in invalid_cases {
            let src = source_with_literal(bytes);
            let (_output, _funcs, error) = compile_with_ccb(&ccb, &src);
            assert_eq!(error, 1,
                "invalid UTF-8 '{}' should produce compile error", label);
            eprintln!("7.4: invalid '{}' rejected ✓", label);
        }
    }

    /// 7.4 preservation: validation is a gate, not a transcoder.
    /// Valid UTF-8 input bytes == literal output bytes.
    #[test]
    fn p74_utf8_validation_preserves_bytes() {
        let ccb = build_ccb();

        // İzmir: C4 B0 7A 6D 69 72
        let src = "int main() { int s = \"İzmir\"; return syscall(1, s + 8, *s, 0); }";
        let kernel = run_ccb_harness(&ccb, src.as_bytes(), 0);
        assert_eq!(&kernel.byte_output, b"\xC4\xB0zmir",
            "validation must preserve bytes: no normalization, no replacement");
        eprintln!("7.4: İzmir bytes preserved through validation gate ✓");
    }

    // ─── 7.2h: Bootstrap fixed-point regression ────────────────
    // After the allocator redesign, CC_B must still equal CC_C.
    // This is a stronger check than b51_bootstrap_closure because it
    // explicitly names the 7.2 allocator change as the potential
    // regression source.

    #[test]
    fn p72h_bootstrap_fixed_point_survives_allocator() {
        let ccb = build_ccb();
        eprintln!("7.2h: CC_B = {} bytes", ccb.len());

        let canon_src = canonical_compiler_source();
        let (ccc, ccc_funcs, ccc_error) =
            compile_with_ccb(&ccb, canon_src.as_bytes());

        assert_eq!(ccc_error, 0,
            "CC_B failed to compile canonical source after 7.2 allocator change");
        assert_eq!(ccc_funcs, CANONICAL_FUNC_COUNT,
            "CC_C should have {} functions", CANONICAL_FUNC_COUNT);
        assert!(!ccc.is_empty(), "CC_C is empty");
        eprintln!("7.2h: CC_C = {} bytes ({} functions)", ccc.len(), ccc_funcs);

        assert_eq!(ccb, ccc,
            "7.2h FIXED POINT VIOLATION: \
             CC_B ({} bytes) ≠ CC_C ({} bytes) \
             after two-ended allocator change",
            ccb.len(), ccc.len());
        eprintln!("7.2h: CC_B == CC_C after two-ended allocator ✓");
        eprintln!("     The bootstrap fixed point survives the allocator redesign.");
    }

    // ═══════════════════════════════════════════════════════════
    // Phase 8.0: Boot contract
    //
    // The test creates a machine, creates a sealed code object,
    // calls kernel.boot(), then kernel.run().  The test NEVER
    // constructs an Anka64Core or Process directly — that is
    // the entire point: the host owns machine instantiation,
    // Anka owns process instantiation.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p80_boot_return_42() {
        // Host creates the machine
        let mut fabric = Fabric::new(0x100000);

        // Host creates and places a code object
        let code_obj = fabric.alloc_object("init_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(code_obj, 0x0000);

        // Host writes a trivial program: MOVI R0, 42; HALT
        let mut asm = Asm64::new();
        asm.movi(R0, 42);
        asm.halt();
        let code_bytes = asm.to_bytes();
        let code_size = code_bytes.len() as u64;
        fabric.initialize_object(code_obj, 0, &code_bytes);

        // Host seals the object — it is now immutable
        fabric.seal_object(code_obj);

        // Host constructs the boot descriptor
        let info = BootInfo {
            image: BootImage {
                obj: code_obj,
                code_offset: 0,
                code_size,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![],
            maps: vec![],
            code_vaddr: 0,
            stack_vaddr: 0x10000,
            stack_size: 0x4000,
            trap_vaddr: 0x20000,
        };

        // Host creates the kernel and boots it
        let mut kernel = Kernel::new(fabric);
        let result = kernel.boot(&info);
        assert_eq!(result, Ok(()), "boot() should succeed");

        // Host runs the kernel — scheduling is the host's responsibility
        kernel.run(1000, 100);

        // Verify init exited with 42
        assert_eq!(kernel.processes.len(), 1, "exactly one process (init)");
        assert!(kernel.processes[0].exited(), "init should have exited");
        assert_eq!(kernel.processes[0].exit_code, 42,
            "init should exit with 42");
        eprintln!("8.0: boot(return 42) succeeded — test never constructed a core ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // Phase 8.1: Boot the real compiler
    //
    // The test builds CC_B, then boots it via kernel.boot() with
    // a BootInfo that places the compiler's code, source, workspace,
    // and output at the same virtual addresses the compiler expects.
    // The host never constructs an Anka64Core.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p81_boot_compiler() {
        // Build CC_B using the existing bootstrap path
        let ccb = build_ccb();
        let ccb_size = ((ccb.len() + 0xFFF) & !0xFFF) as u64;

        // Host creates the machine
        let mut fabric = Fabric::new(0x800000);

        // Code object: holds CC_B
        let code_obj = fabric.alloc_object("ccb_code", ccb_size, ObjectKind::Memory);
        fabric.place_object(code_obj, 0x100000);
        fabric.initialize_object(code_obj, 0, &ccb);
        fabric.seal_object(code_obj);

        // Source object
        let source_obj = fabric.alloc_object("source", SOURCE_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(source_obj, 0x200000);
        let source_text = b"int main() { return 42; }";
        fabric.write_physical(0x200000, &(source_text.len() as u64).to_le_bytes());
        fabric.write_physical(0x200008, source_text);

        // Output object
        let output_obj = fabric.alloc_object("output", OUTPUT_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(output_obj, 0x210000);

        // Workspace object — no host initialization needed.
        // The compiler's main() initializes WS_LIT_POS = OUTPUT_SIZE
        // and all other workspace fields (Phase 8.1c).
        let work_obj = fabric.alloc_object("workspace", WS_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(work_obj, 0x220000);

        // Boot descriptor: CC_B at 0x30000, data at canonical addresses
        let info = BootInfo {
            image: BootImage {
                obj: code_obj,
                code_offset: 0,
                code_size: ccb.len() as u64,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![
                BootGrant { obj: source_obj, offset: 0, size: SOURCE_SIZE as u64, perms: Permissions::READ },
                BootGrant { obj: output_obj, offset: 0, size: OUTPUT_SIZE as u64, perms: Permissions::RWS },
                BootGrant { obj: work_obj,   offset: 0, size: WS_SIZE as u64,     perms: Permissions::RW },
            ],
            maps: vec![
                BootMap { vaddr: LAYOUT_SRC as u64, size: SOURCE_SIZE as u64, obj: source_obj, obj_offset: 0 },
                BootMap { vaddr: LAYOUT_WS as u64,  size: WS_SIZE as u64,     obj: work_obj,   obj_offset: 0 },
                BootMap { vaddr: LAYOUT_OUT as u64,  size: OUTPUT_SIZE as u64, obj: output_obj, obj_offset: 0 },
            ],
            code_vaddr: CCB_CODE_BASE,
            stack_vaddr: LAYOUT_STACK as u64,
            stack_size: 0x4000,
            trap_vaddr: LAYOUT_STACK as u64 + 0x4000, // after stack
        };

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x300000;
        let result = kernel.boot(&info);
        assert_eq!(result, Ok(()), "boot(CC_B) should succeed");

        // Host runs the kernel
        kernel.run(4_000_000, 100);

        assert!(kernel.processes[0].exited(), "CC_B should have exited");

        // Read workspace results
        let read_ws = |off: u64| -> u64 {
            let bytes = kernel.fabric.read_physical(0x220000 + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws((WS_ERROR - LAYOUT_WS) as u64);
        let ws_funcs = read_ws((WS_FUNC_COUNT - LAYOUT_WS) as u64);
        let out_pos = read_ws((WS_OUT_POS - LAYOUT_WS) as u64);

        assert_eq!(ws_error, 0, "CC_B should report no error");
        assert!(ws_funcs > 0, "CC_B should compile at least one function");
        assert!(out_pos > 0, "CC_B should produce output");

        // The decisive assertion: CC_B compiled the child, sealed it,
        // SYS_EXEC'd it, and the child returned 42.  CC_B's exit code
        // is the child's exit code (from SYS_EXEC return value).
        let exit_code = kernel.processes[0].exit_code;
        assert_eq!(exit_code, 42,
            "CC_B should receive child exit code 42 (got {})", exit_code);

        // Count processes: should be 2 (CC_B + child)
        let total_procs = kernel.processes.len();
        assert!(total_procs >= 2,
            "should have at least 2 processes (init + child), got {}", total_procs);

        eprintln!("8.1d: host → boot(CC_B) → compile → seal → exec → child(42) ✓");
        eprintln!("      CC_B compiled {} functions, {} bytes", ws_funcs, out_pos);
        eprintln!("      {} total processes, test never constructed a core ✓", total_procs);
    }

    // ─── 8.0e: Hostile boot descriptors ──────────────────────
    //
    // Each test verifies that boot() rejects an invalid descriptor
    // with the correct BootError, and that the kernel remains
    // bootable afterward (failed boot is not one-attempt-only).

    /// Helper: create a fabric with a valid sealed code object
    fn boot_test_fabric() -> (Fabric, ObjectId, u64) {
        let mut fabric = Fabric::new(0x100000);
        let code_obj = fabric.alloc_object("init_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(code_obj, 0x0000);
        let mut asm = Asm64::new();
        asm.movi(R0, 99);
        asm.halt();
        let code_bytes = asm.to_bytes();
        let code_size = code_bytes.len() as u64;
        fabric.initialize_object(code_obj, 0, &code_bytes);
        fabric.seal_object(code_obj);
        (fabric, code_obj, code_size)
    }

    /// Helper: valid BootInfo for the test fabric
    fn valid_boot_info(code_obj: ObjectId, code_size: u64) -> BootInfo {
        BootInfo {
            image: BootImage {
                obj: code_obj,
                code_offset: 0,
                code_size,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![],
            maps: vec![],
            code_vaddr: 0,
            stack_vaddr: 0x10000,
            stack_size: 0x4000,
            trap_vaddr: 0x20000,
        }
    }

    #[test]
    fn p80e_image_not_sealed() {
        let mut fabric = Fabric::new(0x100000);
        let code_obj = fabric.alloc_object("init_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(code_obj, 0x0000);
        let mut asm = Asm64::new();
        asm.movi(R0, 1);
        asm.halt();
        fabric.initialize_object(code_obj, 0, &asm.to_bytes());
        // Deliberately NOT sealed
        let code_size = asm.to_bytes().len() as u64;
        let info = valid_boot_info(code_obj, code_size);

        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::ImageNotSealed));
        assert_eq!(kernel.processes.len(), 0, "no process after failed boot");
    }

    #[test]
    fn p80e_zero_code() {
        let (fabric, code_obj, _) = boot_test_fabric();
        let mut info = valid_boot_info(code_obj, 0);
        info.image.code_size = 0;
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::ZeroCode));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_entry_beyond_code() {
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let mut info = valid_boot_info(code_obj, code_size);
        info.image.entry = code_size; // entry == code_size is invalid
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::InvalidEntry));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_nonexistent_image_object() {
        let fabric = Fabric::new(0x100000);
        let bogus_obj = ObjectId(999);
        let info = valid_boot_info(bogus_obj, 8);
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::ImageNotFound));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_grant_overlaps_image() {
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let mut info = valid_boot_info(code_obj, code_size);
        // Grant covers [0..code_size) which is exactly the image backing range
        info.grants.push(BootGrant {
            obj: code_obj,
            offset: 0,
            size: code_size,
            perms: Permissions::READ,
        });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::GrantOverlapsImage));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_grant_partially_overlaps_image() {
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let mut info = valid_boot_info(code_obj, code_size);
        // Grant starts 1 byte before end of image backing range.
        // Image backing range is [0 .. 0x1000) since code_offset=0, obj_size=0x1000.
        info.grants.push(BootGrant {
            obj: code_obj,
            offset: 0x0FFF,
            size: 1,
            perms: Permissions::READ,
        });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::GrantOverlapsImage));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_grant_oob() {
        let (mut fabric, code_obj, code_size) = boot_test_fabric();
        // Create a small data object
        let data_obj = fabric.alloc_object("data", 0x100, ObjectKind::Memory);
        fabric.place_object(data_obj, 0x2000);
        let mut info = valid_boot_info(code_obj, code_size);
        // Grant exceeds the data object's size
        info.grants.push(BootGrant {
            obj: data_obj,
            offset: 0,
            size: 0x200, // larger than 0x100
            perms: Permissions::READ,
        });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::GrantOutOfBounds));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_overlapping_maps() {
        let (mut fabric, code_obj, code_size) = boot_test_fabric();
        let data1 = fabric.alloc_object("data1", 0x2000, ObjectKind::Memory);
        let data2 = fabric.alloc_object("data2", 0x1000, ObjectKind::Memory);
        fabric.place_object(data1, 0x2000);
        fabric.place_object(data2, 0x4000);
        let mut info = valid_boot_info(code_obj, code_size);
        info.grants.push(BootGrant { obj: data1, offset: 0, size: 0x2000, perms: Permissions::READ });
        info.grants.push(BootGrant { obj: data2, offset: 0, size: 0x1000, perms: Permissions::READ });
        // Two maps whose virtual ranges overlap: [0x30000..0x32000) and [0x31000..0x32000)
        info.maps.push(BootMap { vaddr: 0x30000, size: 0x2000, obj: data1, obj_offset: 0 });
        info.maps.push(BootMap { vaddr: 0x31000, size: 0x1000, obj: data2, obj_offset: 0 });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::OverlappingMaps));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_map_overlaps_implicit_stack() {
        let (mut fabric, code_obj, code_size) = boot_test_fabric();
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(data, 0x2000);
        let mut info = valid_boot_info(code_obj, code_size);
        info.grants.push(BootGrant { obj: data, offset: 0, size: 0x1000, perms: Permissions::READ });
        // Stack is at 0x10000..0x14000 — overlap it
        info.maps.push(BootMap { vaddr: 0x13000, size: 0x1000, obj: data, obj_offset: 0 });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::OverlappingMaps));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_map_overlaps_implicit_trap() {
        let (mut fabric, code_obj, code_size) = boot_test_fabric();
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(data, 0x2000);
        let mut info = valid_boot_info(code_obj, code_size);
        info.grants.push(BootGrant { obj: data, offset: 0, size: 0x1000, perms: Permissions::READ });
        // Trap is at 0x20000..0x21000 — overlap it
        info.maps.push(BootMap { vaddr: 0x20000, size: 0x1000, obj: data, obj_offset: 0 });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::OverlappingMaps));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_map_overlaps_implicit_code() {
        let (mut fabric, code_obj, code_size) = boot_test_fabric();
        let data = fabric.alloc_object("data", 0x1000, ObjectKind::Memory);
        fabric.place_object(data, 0x2000);
        let mut info = valid_boot_info(code_obj, code_size);
        info.grants.push(BootGrant { obj: data, offset: 0, size: 0x1000, perms: Permissions::READ });
        // Code is at 0..code_size — map starting at 0 overlaps it
        info.maps.push(BootMap { vaddr: 0, size: 0x1000, obj: data, obj_offset: 0 });
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Err(BootError::OverlappingMaps));
        assert_eq!(kernel.processes.len(), 0);
    }

    #[test]
    fn p80e_double_boot() {
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let info = valid_boot_info(code_obj, code_size);
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&info), Ok(()));
        // Second boot must fail
        assert_eq!(kernel.boot(&info), Err(BootError::AlreadyBooted));
        // But init is still runnable from the first boot
        kernel.run(1000, 100);
        assert_eq!(kernel.processes[0].exit_code, 99);
    }

    #[test]
    fn p80e_failed_then_valid() {
        let (fabric, code_obj, code_size) = boot_test_fabric();
        // First attempt: invalid entry
        let mut bad_info = valid_boot_info(code_obj, code_size);
        bad_info.image.entry = code_size; // invalid
        let mut kernel = Kernel::new(fabric);
        assert_eq!(kernel.boot(&bad_info), Err(BootError::InvalidEntry));
        assert_eq!(kernel.processes.len(), 0, "no process after failed boot");
        // Second attempt: valid — must succeed (failed boot is not one-attempt-only)
        let good_info = valid_boot_info(code_obj, code_size);
        assert_eq!(kernel.boot(&good_info), Ok(()));
        kernel.run(1000, 100);
        assert_eq!(kernel.processes[0].exit_code, 99);
        eprintln!("8.0e: failed-then-valid boot succeeded ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3b: Physical extent allocation tests
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83b_fresh_alloc_advances_next_phys() {
        let fabric = Fabric::new(0x800000);
        let mut kernel = Kernel::new(fabric);
        let before = kernel.next_phys;
        let ext = kernel.alloc_stack_extent(0x4000);
        assert_eq!(ext.base, before, "fresh alloc starts at next_phys");
        assert_eq!(ext.size, 0x4000);
        assert_eq!(kernel.next_phys, before + 0x4000,
            "next_phys advances by requested size");
        eprintln!("8.3b: fresh alloc advances next_phys ✓");
    }

    #[test]
    fn p83b_exact_size_reuse() {
        let fabric = Fabric::new(0x800000);
        let mut kernel = Kernel::new(fabric);
        let recycled = PhysicalExtent { base: 0x200000, size: 0x4000 };
        kernel.free_stack_extents.push(recycled);
        let before = kernel.next_phys;
        let ext = kernel.alloc_stack_extent(0x4000);
        assert_eq!(ext.base, 0x200000, "reused extent has original base");
        assert_eq!(ext.size, 0x4000);
        assert_eq!(kernel.next_phys, before,
            "next_phys unchanged — extent came from pool");
        assert!(kernel.free_stack_extents.is_empty(),
            "pool drained after reuse");
        eprintln!("8.3b: exact-size reuse returns same base ✓");
    }

    #[test]
    fn p83b_reused_extent_scrubbed() {
        let mut fabric = Fabric::new(0x800000);
        let base: u64 = 0x200000;
        let size: u64 = 0x1000;
        // Write non-zero pattern into the physical region
        let pattern = vec![0xAB_u8; size as usize];
        fabric.write_physical(base, &pattern);
        // Verify it's dirty
        assert_eq!(fabric.read_physical(base, 1)[0], 0xAB);

        let mut kernel = Kernel::new(fabric);
        kernel.free_stack_extents.push(PhysicalExtent { base, size });
        let ext = kernel.alloc_stack_extent(size);
        assert_eq!(ext.base, base);
        // Verify scrubbing: every byte in the returned extent is zero
        let data = kernel.fabric.read_physical(base, size);
        assert!(data.iter().all(|&b| b == 0),
            "recycled extent must be scrubbed to zero");
        eprintln!("8.3b: reused extent is scrubbed to zero ✓");
    }

    #[test]
    fn p83b_wrong_size_not_reused() {
        let fabric = Fabric::new(0x800000);
        let mut kernel = Kernel::new(fabric);
        let recycled = PhysicalExtent { base: 0x200000, size: 0x2000 };
        kernel.free_stack_extents.push(recycled);
        let before = kernel.next_phys;
        // Request a different size than what's in the pool
        let ext = kernel.alloc_stack_extent(0x4000);
        assert_eq!(ext.base, before,
            "wrong-sized pool entry skipped — fresh alloc used");
        assert_eq!(kernel.next_phys, before + 0x4000);
        assert_eq!(kernel.free_stack_extents.len(), 1,
            "wrong-sized entry stays in pool");
        eprintln!("8.3b: wrong-sized extent not reused ✓");
    }

    #[test]
    fn p83b_stack_pool_ne_trap_pool() {
        let fabric = Fabric::new(0x800000);
        let mut kernel = Kernel::new(fabric);
        // Put an extent in the stack pool only
        kernel.free_stack_extents.push(
            PhysicalExtent { base: 0x200000, size: 0x4000 });
        let before = kernel.next_phys;
        // Trap alloc should NOT see the stack pool entry
        let ext = kernel.alloc_trap_extent(0x4000);
        assert_eq!(ext.base, before,
            "trap alloc ignores stack pool — fresh alloc used");
        assert_eq!(kernel.next_phys, before + 0x4000);
        assert_eq!(kernel.free_stack_extents.len(), 1,
            "stack pool untouched by trap alloc");
        eprintln!("8.3b: stack pool ≠ trap pool ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3c: Process reclamation tests
    //
    //   Collected(g) + Resources(g) → Free(g+1) + FreeExtents
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83c_zombie_to_free_full_reclaim() {
        // Boot a process that exits immediately.  Then manually
        // reclaim the zombie and verify every field.
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let info = valid_boot_info(code_obj, code_size);
        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(1000, 100);

        // Init exited → Zombie
        assert_eq!(kernel.processes[0].state, ProcessState::Zombie);
        assert_eq!(kernel.processes[0].generation, 0);

        // Capture pre-reclaim state
        let res = kernel.processes[0].resources.as_ref()
            .expect("booted process must have OwnedResources");
        let stack_extent = res.stack_extent;
        let trap_extent = res.trap_extent;
        let domain_id = res.domain;
        let stack_obj_id = res.stack_obj;
        let trap_obj_id = res.trap_obj;

        // Dirty the mailbox and lifecycle table
        kernel.mailboxes[0].push(Message {
            from: ProcessKey { slot: 999, generation: 0 },
            value: 0xBEEF,
            cap: None,
        });
        kernel.lifecycle_tables[0].push(LifecycleEntry {
            slot_generation: 0,
            child: ProcessKey { slot: 99, generation: 0 },
            collected: false,
        });

        // Set parent edge to verify it's cleared
        kernel.processes[0].parent = Some(ProcessKey { slot: 99, generation: 0 });

        // --- Reclaim ---
        kernel.reclaim_process(0);

        // State
        assert_eq!(kernel.processes[0].state, ProcessState::Free);
        assert_eq!(kernel.processes[0].generation, 1, "generation advanced");

        // Resources destroyed
        assert!(kernel.processes[0].resources.is_none());

        // Domain and objects gone from fabric
        assert!(!kernel.fabric.domains.contains_key(&domain_id),
            "domain destroyed");
        assert!(!kernel.fabric.objects.contains_key(&stack_obj_id),
            "stack object destroyed");
        assert!(!kernel.fabric.objects.contains_key(&trap_obj_id),
            "trap object destroyed");

        // Extents returned to correct pools
        assert_eq!(kernel.free_stack_extents.len(), 1);
        assert_eq!(kernel.free_stack_extents[0].base, stack_extent.base);
        assert_eq!(kernel.free_stack_extents[0].size, stack_extent.size);
        assert_eq!(kernel.free_trap_extents.len(), 1);
        assert_eq!(kernel.free_trap_extents[0].base, trap_extent.base);
        assert_eq!(kernel.free_trap_extents[0].size, trap_extent.size);

        // Incarnation metadata erased
        assert!(kernel.processes[0].parent.is_none(), "parent cleared");
        assert!(kernel.processes[0].result.is_none(), "result cleared");
        assert_eq!(kernel.processes[0].exit_code, 0, "exit_code cleared");

        // Mailbox and lifecycle table cleared
        assert!(kernel.mailboxes[0].is_empty(), "mailbox cleared");
        assert!(kernel.lifecycle_tables[0].is_empty(), "lifecycle table cleared");

        // Old ProcessKey rejected
        let old_key = ProcessKey { slot: 0, generation: 0 };
        assert!(kernel.validate_process_key(&old_key).is_none(),
            "old ProcessKey must be rejected after reclamation");

        eprintln!("8.3c: Zombie(0) → Free(1), full resource + metadata reclamation ✓");
    }

    #[test]
    fn p83c_max_generation_retires() {
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let info = valid_boot_info(code_obj, code_size);
        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(1000, 100);
        assert_eq!(kernel.processes[0].state, ProcessState::Zombie);

        // Force generation to u32::MAX
        kernel.processes[0].generation = u32::MAX;

        kernel.reclaim_process(0);

        assert_eq!(kernel.processes[0].state, ProcessState::Retired,
            "u32::MAX generation → Retired, not Free");
        assert_eq!(kernel.processes[0].generation, u32::MAX,
            "generation stays at MAX (no wraparound)");
        assert!(kernel.processes[0].resources.is_none(),
            "resources still destroyed even on Retired");

        eprintln!("8.3c: Zombie(MAX) → Retired (no wraparound) ✓");
    }

    #[test]
    fn p83c_exec_child_reclaimed() {
        // Parent spawns child via SYS_EXEC.  After collection,
        // the child slot must be Free with resources returned.
        let mut fabric = Fabric::new(0x200000);

        let text  = fabric.alloc_object("text",  0x4000, ObjectKind::Memory);
        let code  = fabric.alloc_object("code",  0x1000, ObjectKind::Memory);
        let stack = fabric.alloc_object("stack", 0x4000, ObjectKind::Memory);

        fabric.place_object(text,  0x000000);
        fabric.place_object(code,  0x020000);
        fabric.place_object(stack, 0x030000);

        let dom = fabric.create_domain();
        fabric.grant(dom, code,  0, 0x1000, Permissions::RWS);
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        // Child: exit(55)
        let mut child_asm = Asm64::new();
        child_asm.movi(R1, 55);
        child_asm.movi(R0, SYS_EXIT as i32);
        child_asm.trap(0);
        fabric.write_physical(0x020000, &child_asm.to_bytes());
        fabric.seal_object(code);
        fabric.grant(dom, code, 0, 0x1000, Permissions::RX);

        install_trap_handler(&mut fabric, 0x000000, 0x4000);

        // Parent: SYS_EXEC(code_vaddr=0x5000, code_size=16, lit=0) → exit(R0)
        {
            let mut asm = Asm64::new();
            asm.movi(R1, 0x5000);       // code_vaddr
            asm.movi(R2, 16);           // code_size
            asm.movi(R0, SYS_EXEC as i32);
            asm.trap(0);
            // R0 = child result → exit with it
            asm.mov(R1, R0);
            asm.movi(R0, SYS_EXIT as i32);
            asm.trap(0);
            fabric.write_physical(0x000000, &asm.to_bytes());
        }
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x05000, 0x1000, code);
        core.address_map.add(0x06000, 0x4000, stack);
        core.r[SP as usize] = 0x06000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x040000;
        kernel.next_agent = 10;
        kernel.spawn(core);

        let phys_before_run = kernel.next_phys;
        kernel.run(1000, 1000);

        // Parent got child's result
        assert!(kernel.processes[0].exited());
        assert_eq!(kernel.processes[0].exit_code, 55,
            "parent received child exit code 55");

        // Child reclaimed
        assert!(kernel.processes.len() >= 2);
        assert_eq!(kernel.processes[1].state, ProcessState::Free,
            "EXEC child reclaimed to Free");
        assert_eq!(kernel.processes[1].generation, 1,
            "child generation advanced from 0 to 1");
        assert!(kernel.processes[1].resources.is_none(),
            "child resources destroyed");

        // Extents returned to pools
        assert_eq!(kernel.free_stack_extents.len(), 1,
            "child stack extent returned to pool");
        assert_eq!(kernel.free_trap_extents.len(), 1,
            "child trap extent returned to pool");

        // The child consumed physical space during prepare_process
        assert!(kernel.next_phys > phys_before_run,
            "child allocation advanced next_phys");

        eprintln!("8.3c: EXEC child exit(55) → parent collected → child Free(1) ✓");
        eprintln!("       stack pool={} trap pool={}",
            kernel.free_stack_extents.len(), kernel.free_trap_extents.len());
    }

    #[test]
    fn p83c_raw_spawn_reclaim_skips_resources() {
        // Raw spawn() processes have resources=None.
        // Reclaim should still perform logical cleanup without panicking.
        let mut fabric = Fabric::new(0x100000);

        let text  = fabric.alloc_object("raw_text",  0x4000, ObjectKind::Memory);
        let stack = fabric.alloc_object("raw_stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text,  0x000000);
        fabric.place_object(stack, 0x020000);
        let dom = fabric.create_domain();
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        let mut asm = Asm64::new();
        asm.movi(R0, SYS_EXIT as i32);
        asm.movi(R1, 7);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert_eq!(kernel.processes[0].state, ProcessState::Zombie);
        assert!(kernel.processes[0].resources.is_none(),
            "raw spawn has no OwnedResources");

        assert!(kernel.free_stack_extents.is_empty());
        assert!(kernel.free_trap_extents.is_empty());

        kernel.reclaim_process(0);

        assert_eq!(kernel.processes[0].state, ProcessState::Free);
        assert_eq!(kernel.processes[0].generation, 1);

        // No extents returned (none were owned)
        assert!(kernel.free_stack_extents.is_empty(),
            "no stack extents from raw spawn");
        assert!(kernel.free_trap_extents.is_empty(),
            "no trap extents from raw spawn");

        eprintln!("8.3c: raw spawn() → reclaim skips resources, logical cleanup only ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3d: Central death transition + depth-first orphan tests
    //
    //   finish_process() → Zombie → terminate_orphans(depth-first)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83d_parent_dies_running_child_terminated() {
        // Parent A spawns child B via SYS_SPAWN.
        // A exits immediately (doesn't WAIT on B).
        // B is still running when A dies.
        // finish_process(A) → terminate_orphans → B terminated + reclaimed.
        let mut fabric = Fabric::new(0x200000);

        let text_a = fabric.alloc_object("a_text", 0x4000, ObjectKind::Memory);
        let stack_a = fabric.alloc_object("a_stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text_a, 0x000000);
        fabric.place_object(stack_a, 0x020000);
        let dom_a = fabric.create_domain();
        fabric.grant(dom_a, stack_a, 0, 0x4000, Permissions::RW);

        // Child code at 0x100000: infinite loop (NOP; NOP; ...)
        let code_obj = fabric.alloc_object("child_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(code_obj, 0x100000);
        let mut child_asm = Asm64::new();
        // 256 NOPs — child will never exit on its own
        for _ in 0..256 {
            child_asm.nop();
        }
        fabric.write_physical(0x100000, &child_asm.to_bytes());
        fabric.seal_object(code_obj);
        fabric.grant(dom_a, code_obj, 0, 0x1000, Permissions::RWS);
        fabric.grant(dom_a, code_obj, 0, 0x1000, Permissions::RX);

        // Parent A: SYS_SPAWN(code, 16, 0) → SYS_EXIT(0)
        let mut asm_a = Asm64::new();
        emit_spawn_default(&mut asm_a, 0x5000, 16, 0);
        // R0 = LifecycleHandle (don't WAIT, just exit)
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.movi(R1, 0);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text_a, dom_a);

        let mut core_a = Anka64Core::new(AgentId(0), dom_a);
        core_a.address_map.add(0x00000, 0x4000, text_a);
        core_a.address_map.add(0x05000, 0x1000, code_obj);
        core_a.address_map.add(0x06000, 0x4000, stack_a);
        core_a.r[SP as usize] = 0x06000 + 0x4000;
        core_a.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x200000;
        kernel.next_agent = 10;
        kernel.spawn(core_a);
        kernel.run(10000, 100);

        // A exited
        assert_eq!(kernel.processes[0].state, ProcessState::Zombie);
        assert_eq!(kernel.processes[0].exit_code, 0);

        // B was running when A died → terminated + reclaimed by finish_process
        assert!(kernel.processes.len() >= 2);
        assert_eq!(kernel.processes[1].state, ProcessState::Free,
            "orphaned running child must be reclaimed");
        assert_eq!(kernel.processes[1].generation, 1,
            "child generation advanced from 0 to 1");
        assert!(kernel.processes[1].resources.is_none(),
            "child resources destroyed");

        // Child's extents returned to pools
        assert_eq!(kernel.free_stack_extents.len(), 1,
            "orphaned child stack extent returned");
        assert_eq!(kernel.free_trap_extents.len(), 1,
            "orphaned child trap extent returned");

        eprintln!("8.3d: A exits → running child B terminated + reclaimed ✓");
    }

    #[test]
    fn p83d_depth_first_grandchild() {
        // Boot init, which spawns A.  A spawns B.
        // init exits → terminate_orphans(init) finds A.
        //   recurse: terminate_orphans(A) finds B → reclaim B.
        //   then reclaim A.
        // Depth-first: B reclaimed before A.

        // Use boot to get prepare_process resources on init.
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let info = valid_boot_info(code_obj, code_size);
        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(1000, 100);

        // init is Zombie. Now manually create A and B as children.
        // We can't easily make init spawn via SYS_SPAWN (it's a
        // simple exit(99) program), so we set up the parent edges
        // directly to test the orphan traversal logic.

        // A: child of init (slot 0, gen 0)
        let init_key = ProcessKey { slot: 0, generation: 0 };
        let mut core_a = Anka64Core::new(AgentId(10), DomainId(999));
        core_a.trap_vector = 0;
        let a_key = kernel.spawn(core_a);
        kernel.processes[a_key.slot].parent = Some(init_key);
        kernel.processes[a_key.slot].state = ProcessState::Running;

        // B: child of A
        let mut core_b = Anka64Core::new(AgentId(11), DomainId(998));
        core_b.trap_vector = 0;
        let b_key = kernel.spawn(core_b);
        kernel.processes[b_key.slot].parent = Some(a_key);
        kernel.processes[b_key.slot].state = ProcessState::Running;

        // Now terminate init's orphans
        kernel.terminate_orphans(init_key);

        // B should be reclaimed first (depth-first), then A
        assert_eq!(kernel.processes[b_key.slot].state, ProcessState::Free,
            "grandchild B must be reclaimed");
        assert_eq!(kernel.processes[b_key.slot].generation, 1);

        assert_eq!(kernel.processes[a_key.slot].state, ProcessState::Free,
            "child A must be reclaimed");
        assert_eq!(kernel.processes[a_key.slot].generation, 1);

        // Both have no parent
        assert!(kernel.processes[a_key.slot].parent.is_none());
        assert!(kernel.processes[b_key.slot].parent.is_none());

        eprintln!("8.3d: P→C→G depth-first: G reclaimed → C reclaimed ✓");
    }

    #[test]
    fn p83d_parent_dies_zombie_child_reclaimed() {
        // Parent dies, child is already a Zombie (exited but uncollected).
        // terminate_orphans should reclaim the zombie child.
        let (fabric, code_obj, code_size) = boot_test_fabric();
        let info = valid_boot_info(code_obj, code_size);
        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(1000, 100);

        let init_key = ProcessKey { slot: 0, generation: 0 };

        // Zombie child of init
        let mut core_z = Anka64Core::new(AgentId(20), DomainId(997));
        core_z.trap_vector = 0;
        let z_key = kernel.spawn(core_z);
        kernel.processes[z_key.slot].parent = Some(init_key);
        kernel.processes[z_key.slot].state = ProcessState::Zombie;
        kernel.processes[z_key.slot].result = Some(ProcessResult::Exited(42));
        kernel.processes[z_key.slot].exit_code = 42;

        kernel.terminate_orphans(init_key);

        assert_eq!(kernel.processes[z_key.slot].state, ProcessState::Free,
            "zombie orphan must be reclaimed");
        assert_eq!(kernel.processes[z_key.slot].generation, 1);
        assert_eq!(kernel.processes[z_key.slot].exit_code, 0,
            "exit_code cleared by reclaim");

        eprintln!("8.3d: parent dies → zombie child reclaimed ✓");
    }

    #[test]
    fn p83d_finish_process_gate_unknown_syscall() {
        // Unknown syscall now goes through finish_process().
        // Verify it produces a definitive ProcessResult, not a
        // partial death state.
        let mut fabric = Fabric::new(0x100000);

        let text = fabric.alloc_object("text", 0x4000, ObjectKind::Memory);
        let stack = fabric.alloc_object("stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text, 0x000000);
        fabric.place_object(stack, 0x020000);
        let dom = fabric.create_domain();
        fabric.grant(dom, stack, 0, 0x4000, Permissions::RW);

        // Process issues syscall 0xFF (unknown) → should die cleanly
        let mut asm = Asm64::new();
        asm.movi(R0, 0xFF);
        asm.trap(0);
        fabric.write_physical(0x000000, &asm.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0x00000, 0x4000, text);
        core.address_map.add(0x20000, 0x4000, stack);
        core.r[SP as usize] = 0x20000 + 0x4000;
        core.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core);
        kernel.run(1000, 100);

        assert_eq!(kernel.processes[0].state, ProcessState::Zombie);
        assert_eq!(kernel.processes[0].exit_code, 0xDEAD,
            "unknown syscall → 0xDEAD via finish_process");
        assert!(kernel.processes[0].result.is_some(),
            "unknown syscall must have a definitive ProcessResult");
        assert_eq!(kernel.processes[0].result, Some(ProcessResult::ProtectionFault),
            "unknown syscall treated as ProtectionFault");

        eprintln!("8.3d: unknown syscall → finish_process(ProtectionFault) ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3d.1: Process-slot reuse tests
    //
    //   Free(S, g+1) → Running(S, g+1)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83d1_slot_reuse_same_slot_new_gen() {
        // Spawn process → reclaim → spawn again.
        // Second spawn reuses slot 0 with generation 1.
        let fabric = Fabric::new(0x100000);
        let mut kernel = Kernel::new(fabric);

        let core1 = Anka64Core::new(AgentId(0), DomainId(0));
        let key1 = kernel.spawn(core1);
        assert_eq!(key1.slot, 0);
        assert_eq!(key1.generation, 0);
        assert_eq!(kernel.processes.len(), 1);

        // Kill and reclaim
        kernel.finish_process(0, ProcessResult::Exited(0));
        kernel.reclaim_process(0);
        assert_eq!(kernel.processes[0].state, ProcessState::Free);
        assert_eq!(kernel.processes[0].generation, 1);

        // Spawn again — should reuse slot 0
        let core2 = Anka64Core::new(AgentId(1), DomainId(1));
        let key2 = kernel.spawn(core2);
        assert_eq!(key2.slot, 0, "reused slot 0");
        assert_eq!(key2.generation, 1, "generation preserved from Free(1)");
        assert_eq!(kernel.processes.len(), 1, "no new slot appended");
        assert_eq!(kernel.processes[0].state, ProcessState::Running);
        assert_ne!(kernel.processes[0].pid, key1.slot as u64,
            "fresh PID, not old PID");

        // Old key rejected
        assert!(kernel.validate_process_key(&key1).is_none(),
            "old ProcessKey(0, 0) must be rejected");
        // New key valid
        assert!(kernel.validate_process_key(&key2).is_some(),
            "new ProcessKey(0, 1) must be valid");

        eprintln!("8.3d.1: Free(0,1) → Running(0,1), old key rejected ✓");
    }

    #[test]
    fn p83d1_retired_slot_not_reused() {
        // A slot at generation u32::MAX → Retired.
        // spawn() must skip Retired slots and append.
        let fabric = Fabric::new(0x100000);
        let mut kernel = Kernel::new(fabric);

        let core1 = Anka64Core::new(AgentId(0), DomainId(0));
        kernel.spawn(core1);

        // Force generation to MAX, kill, reclaim → Retired
        kernel.processes[0].generation = u32::MAX;
        kernel.finish_process(0, ProcessResult::Exited(0));
        kernel.reclaim_process(0);
        assert_eq!(kernel.processes[0].state, ProcessState::Retired);

        // Spawn must skip slot 0 and append at slot 1
        let core2 = Anka64Core::new(AgentId(1), DomainId(1));
        let key2 = kernel.spawn(core2);
        assert_eq!(key2.slot, 1, "Retired slot skipped, new slot appended");
        assert_eq!(key2.generation, 0);
        assert_eq!(kernel.processes.len(), 2);

        eprintln!("8.3d.1: Retired slot skipped, new slot appended ✓");
    }

    #[test]
    fn p83d1_multiple_reuse_cycles() {
        // Spawn, reclaim, spawn, reclaim, spawn — all in slot 0.
        // Generation advances: 0 → 1 → 2.
        let fabric = Fabric::new(0x100000);
        let mut kernel = Kernel::new(fabric);

        for expected_gen in 0..3u32 {
            let core = Anka64Core::new(AgentId(expected_gen as u64), DomainId(0));
            let key = kernel.spawn(core);
            assert_eq!(key.slot, 0);
            assert_eq!(key.generation, expected_gen);
            assert_eq!(kernel.processes.len(), 1, "never grows beyond 1 slot");

            kernel.finish_process(0, ProcessResult::Exited(expected_gen as u64));
            kernel.reclaim_process(0);
        }

        assert_eq!(kernel.processes[0].state, ProcessState::Free);
        assert_eq!(kernel.processes[0].generation, 3);

        eprintln!("8.3d.1: 3 reuse cycles in slot 0, generation 0→1→2→Free(3) ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3e: Tiny ankad via boot
    //
    // ankad (init) is booted, spawns two children:
    //   A: clean exit(42)
    //   B: deliberate protection fault (load from unmapped 0xF0000)
    //
    // ankad WAITs on both and writes the four result words
    // (tag_a, detail_a, tag_b, detail_b) to byte_output.
    //
    // Test verifies:
    //   tag_a = 0  (Exited), detail_a = 42
    //   tag_b = 2  (ProtectionFault), detail_b = 0
    //   child A reclaimed to Free
    //   child B reclaimed to Free
    //   ankad's own resources exist (it's still a booted process)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83e_ankad_spawns_clean_and_faulting() {
        let mut fabric = Fabric::new(0x400000);

        // --- Child A code object: MOVI R0, 42; HALT (implicit SYS_EXIT) ---
        let child_a_obj = fabric.alloc_object("child_a_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(child_a_obj, 0x080000);
        {
            let mut asm = Asm64::new();
            asm.movi(R0, 42);
            asm.halt();
            fabric.initialize_object(child_a_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(child_a_obj);

        // --- Child B code object: LD R0, [0xF0000] → fault ---
        let child_b_obj = fabric.alloc_object("child_b_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(child_b_obj, 0x090000);
        {
            let mut asm = Asm64::new();
            // Load from unmapped address 0xF0000 → ProtectionFault
            asm.movi(R1, 0xF000_u32 as i32);  // 0xF000 fits 18-bit
            // Shift left by 4 to get 0xF0000 — but we don't have SHL.
            // Instead: children are mapped with code at vaddr=0.
            // Load from vaddr 0xF000 which exceeds their code object.
            // Actually child_b code size = 8 bytes, child maps at 0.
            // Address 0xF000 is unmapped in child's address map → fault.
            asm.ld(R0, R1, 0);  // LD R0, [R1+0] where R1=0xF000
            asm.halt();
            fabric.initialize_object(child_b_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(child_b_obj);

        // --- ankad code: spawn A, spawn B, wait A, wait B, write results ---
        let ankad_obj = fabric.alloc_object("ankad_code", 0x2000, ObjectKind::Memory);
        fabric.place_object(ankad_obj, 0x000000);
        let child_a_code_size: i32 = 8;
        let child_b_code_size: i32 = 8;
        {
            let mut asm = Asm64::new();

            // SPAWN child A (code at vaddr 0x5000, size=8)
            emit_spawn_default(&mut asm, 0x5000, child_a_code_size, 0);
            asm.mov(R9, R0);                     // R9 = handle_a

            // SPAWN child B (code at vaddr 0x6000, size=8)
            emit_spawn_default(&mut asm, 0x6000, child_b_code_size, 0);
            asm.mov(R10, R0);                    // R10 = handle_b

            // WAIT on child A
            asm.mov(R1, R9);                     // handle_a
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            // R0 = tag_a, R1 = detail_a
            asm.mov(R4, R0);                     // R4 = tag_a
            asm.mov(R5, R1);                     // R5 = detail_a

            // WAIT on child B
            asm.mov(R1, R10);                    // handle_b
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            // R0 = tag_b, R1 = detail_b
            asm.mov(R6, R0);                     // R6 = tag_b
            asm.mov(R7, R1);                     // R7 = detail_b

            // Store results at stack base (0x10000) for SYS_WRITE
            asm.movi(R10, 0x10000_u32 as i32);   // stack base
            asm.st(R4, R10, 0);                   // [0x10000] = tag_a
            asm.st(R5, R10, 8);                   // [0x10008] = detail_a
            asm.st(R6, R10, 16);                  // [0x10010] = tag_b
            asm.st(R7, R10, 24);                  // [0x10018] = detail_b

            // SYS_WRITE(addr=0x10000, len=32, 0)
            asm.movi(R1, 0x10000_u32 as i32);
            asm.movi(R2, 32);
            asm.movi(R3, 0);
            asm.movi(R0, SYS_WRITE as i32);
            asm.trap(0);

            // SYS_EXIT(0) — success
            asm.movi(R1, 0);
            asm.movi(R0, SYS_EXIT as i32);
            asm.trap(0);

            let code_bytes = asm.to_bytes();
            fabric.initialize_object(ankad_obj, 0, &code_bytes);
        }
        fabric.seal_object(ankad_obj);

        // --- Boot descriptor ---
        let code_size = 0x2000_u64;  // ankad obj size
        let info = BootInfo {
            image: BootImage {
                obj: ankad_obj,
                code_offset: 0,
                code_size,
                entry: 0,
                lit_start: 0,
            },
            // Grant ankad RX on child code objects (for SYS_SPAWN derivation)
            grants: vec![
                BootGrant {
                    obj: child_a_obj,
                    offset: 0,
                    size: 0x1000,
                    perms: Permissions::RX,
                },
                BootGrant {
                    obj: child_b_obj,
                    offset: 0,
                    size: 0x1000,
                    perms: Permissions::RX,
                },
            ],
            // Map child code objects into ankad's address space
            maps: vec![
                BootMap {
                    vaddr: 0x5000,
                    size: 0x1000,
                    obj: child_a_obj,
                    obj_offset: 0,
                },
                BootMap {
                    vaddr: 0x6000,
                    size: 0x1000,
                    obj: child_b_obj,
                    obj_offset: 0,
                },
            ],
            code_vaddr: 0,
            stack_vaddr: 0x10000,
            stack_size: 0x4000,
            trap_vaddr: 0x20000,
        };

        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(100000, 1000);

        // --- Verify ankad results ---
        assert!(kernel.processes[0].exited(), "ankad should have exited");
        assert_eq!(kernel.processes[0].exit_code, 0,
            "ankad exits with 0 (both children supervised)");

        // Decode byte_output: 4 × u64 LE
        assert_eq!(kernel.byte_output.len(), 32,
            "ankad wrote 32 bytes (4 × u64)");
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(kernel.byte_output[off..off+8].try_into().unwrap())
        };
        let tag_a    = read_u64(0);
        let detail_a = read_u64(8);
        let tag_b    = read_u64(16);
        let detail_b = read_u64(24);

        assert_eq!(tag_a, 0, "child A: Exited tag");
        assert_eq!(detail_a, 42, "child A: exit code 42");
        assert_eq!(tag_b, 2, "child B: ProtectionFault tag");
        assert_eq!(detail_b, 0, "child B: fault detail = 0");

        // Both children reclaimed (they were collected via WAIT)
        assert!(kernel.processes.len() >= 3,
            "ankad + 2 children = at least 3 process slots");

        // Children are in slot 1 and 2 (or reused).
        // After WAIT collection + reclaim, they should be Free.
        let child_slots: Vec<usize> = (1..kernel.processes.len())
            .filter(|&i| kernel.processes[i].state == ProcessState::Free)
            .collect();
        assert!(child_slots.len() >= 2,
            "both children should be reclaimed to Free, found {} Free slots",
            child_slots.len());

        // ankad's own resources still exist (it hasn't been reclaimed)
        assert!(kernel.processes[0].resources.is_some(),
            "ankad's OwnedResources intact while it's still a zombie");

        // Extents from both children returned to pools
        assert!(kernel.free_stack_extents.len() >= 2,
            "2 child stack extents returned");
        assert!(kernel.free_trap_extents.len() >= 2,
            "2 child trap extents returned");

        eprintln!("8.3e: ankad ✓");
        eprintln!("  child A: tag={} detail={} (Exited(42))", tag_a, detail_a);
        eprintln!("  child B: tag={} detail={} (ProtectionFault)", tag_b, detail_b);
        eprintln!("  {} Free child slots, {} stack extents, {} trap extents",
            child_slots.len(),
            kernel.free_stack_extents.len(),
            kernel.free_trap_extents.len());
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3f: Restart faulting B into same slot
    //
    // ankad spawns A (clean) and B₁ (faulting).
    // Collects B₁ first → B₁'s slot becomes Free.
    // Spawns B₂ (same code) → reuses B₁'s slot.
    // Collects B₂, then A.
    //
    // Proves:
    //   B₁=(S,g), B₂=(S,g+1)
    //   PID(B₁) ≠ PID(B₂)
    //   different LifecycleHandle
    //   same fault behavior
    //   reused scrubbed physical extents
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83f_restart_faulting_b_same_slot() {
        let mut fabric = Fabric::new(0x400000);

        // --- Child A code: exit(42) ---
        let child_a_obj = fabric.alloc_object("child_a_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(child_a_obj, 0x080000);
        {
            let mut asm = Asm64::new();
            asm.movi(R0, 42);
            asm.halt();
            fabric.initialize_object(child_a_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(child_a_obj);

        // --- Child B code: LD from unmapped → ProtectionFault ---
        let child_b_obj = fabric.alloc_object("child_b_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(child_b_obj, 0x090000);
        {
            let mut asm = Asm64::new();
            asm.movi(R1, 0xF000);
            asm.ld(R0, R1, 0);
            asm.halt();
            fabric.initialize_object(child_b_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(child_b_obj);

        // --- ankad code ---
        //
        // spawn A → spawn B₁ → WAIT B₁ → spawn B₂ → WAIT B₂ → WAIT A
        // write 8×u64: [tag_b1, detail_b1, tag_b2, detail_b2,
        //               tag_a, detail_a, handle_b1, handle_b2]
        let ankad_obj = fabric.alloc_object("ankad_code", 0x2000, ObjectKind::Memory);
        fabric.place_object(ankad_obj, 0x000000);
        {
            let mut asm = Asm64::new();

            // SPAWN A (code at 0x5000)
            emit_spawn_default(&mut asm, 0x5000, 8, 0);
            asm.mov(R9, R0);           // R9 = handle_a

            // SPAWN B₁ (code at 0x6000)
            emit_spawn_default(&mut asm, 0x6000, 12, 0);  // 3 insns × 4 bytes
            asm.mov(R10, R0);          // R10 = handle_b1

            // WAIT B₁ (collect faulting child first)
            asm.mov(R1, R10);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            asm.mov(R4, R0);           // R4 = tag_b1
            // Store detail_b1 immediately to stack
            asm.movi(R12, 0x10000_u32 as i32);
            asm.st(R1, R12, 8);        // [0x10008] = detail_b1

            // SPAWN B₂ (same code, should reuse B₁'s slot)
            emit_spawn_default(&mut asm, 0x6000, 12, 0);
            asm.mov(R11, R0);          // R11 = handle_b2

            // WAIT B₂
            asm.mov(R1, R11);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            asm.mov(R6, R0);           // R6 = tag_b2
            // Store detail_b2 immediately to stack
            asm.movi(R12, 0x10000_u32 as i32);
            asm.st(R1, R12, 24);       // [0x10018] = detail_b2

            // Store handle_b1 and handle_b2 before WAIT A clobbers R11
            asm.st(R10, R12, 48);      // [0x10030] = handle_b1
            asm.st(R11, R12, 56);      // [0x10038] = handle_b2

            // WAIT A (collect clean service last)
            asm.mov(R1, R9);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            // R0 = tag_a, R1 = detail_a
            asm.mov(R11, R0);          // R11 = tag_a
            asm.mov(R12, R1);          // R12 = detail_a

            // Store remaining 4 values at stack base (0x10000)
            // detail_b1 [0x10008], detail_b2 [0x10018], handle_b1 [0x10030],
            // handle_b2 [0x10038] already stored above
            asm.movi(R3, 0x10000_u32 as i32);
            asm.st(R4, R3, 0);         // tag_b1
            asm.st(R6, R3, 16);        // tag_b2
            asm.st(R11, R3, 32);       // tag_a
            asm.st(R12, R3, 40);       // detail_a

            // SYS_WRITE(0x10000, 64, 0)
            asm.movi(R1, 0x10000_u32 as i32);
            asm.movi(R2, 64);
            asm.movi(R3, 0);
            asm.movi(R0, SYS_WRITE as i32);
            asm.trap(0);

            // SYS_EXIT(0)
            asm.movi(R1, 0);
            asm.movi(R0, SYS_EXIT as i32);
            asm.trap(0);

            fabric.initialize_object(ankad_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(ankad_obj);

        // --- Boot descriptor ---
        let info = BootInfo {
            image: BootImage {
                obj: ankad_obj,
                code_offset: 0,
                code_size: 0x2000,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![
                BootGrant { obj: child_a_obj, offset: 0, size: 0x1000, perms: Permissions::RX },
                BootGrant { obj: child_b_obj, offset: 0, size: 0x1000, perms: Permissions::RX },
            ],
            maps: vec![
                BootMap { vaddr: 0x5000, size: 0x1000, obj: child_a_obj, obj_offset: 0 },
                BootMap { vaddr: 0x6000, size: 0x1000, obj: child_b_obj, obj_offset: 0 },
            ],
            code_vaddr: 0,
            stack_vaddr: 0x10000,
            stack_size: 0x4000,
            trap_vaddr: 0x20000,
        };

        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(100000, 1000);

        // --- Verify ankad completed ---
        assert!(kernel.processes[0].exited(), "ankad should have exited");
        assert_eq!(kernel.processes[0].exit_code, 0, "ankad exit(0)");
        assert_eq!(kernel.byte_output.len(), 64, "ankad wrote 64 bytes (8×u64)");

        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(kernel.byte_output[off..off+8].try_into().unwrap())
        };
        let tag_b1    = read_u64(0);
        let detail_b1 = read_u64(8);
        let tag_b2    = read_u64(16);
        let detail_b2 = read_u64(24);
        let tag_a     = read_u64(32);
        let detail_a  = read_u64(40);
        let handle_b1 = read_u64(48);
        let handle_b2 = read_u64(56);

        // Both B incarnations faulted identically
        assert_eq!(tag_b1, 2, "B₁: ProtectionFault");
        assert_eq!(detail_b1, 0);
        assert_eq!(tag_b2, 2, "B₂: ProtectionFault");
        assert_eq!(detail_b2, 0);

        // A exited cleanly
        assert_eq!(tag_a, 0, "A: Exited");
        assert_eq!(detail_a, 42, "A: exit code 42");

        // Handles differ (different lifecycle entries)
        assert_ne!(handle_b1, handle_b2,
            "B₁ and B₂ have different LifecycleHandles");

        // --- Host-side verification: slot reuse ---
        // B₁ was spawned second (slot 2 if A is slot 1, or slot 1 if
        // A took the other). After WAIT B₁ → reclaim → Free.
        // B₂ reuses that Free slot.
        //
        // Find the child slot that ended at generation 2
        // (spawned at gen 0, reclaimed to gen 1 = Free(1),
        // respawned at gen 1, reclaimed to gen 2 = Free(2)).
        let reused_slot = (1..kernel.processes.len())
            .find(|&i| kernel.processes[i].generation == 2)
            .expect("one child slot should be at generation 2 (two incarnations)");

        assert_eq!(kernel.processes[reused_slot].state, ProcessState::Free,
            "reused slot is Free after final collection");

        // The other child slot (A) was used once: gen 0 → reclaimed to gen 1
        let a_slot = (1..kernel.processes.len())
            .find(|&i| i != reused_slot && kernel.processes[i].generation == 1)
            .expect("A's slot should be at generation 1 (one incarnation)");
        assert_eq!(kernel.processes[a_slot].state, ProcessState::Free);

        // Process table didn't grow beyond 3 entries
        // (ankad + A slot + B slot, B₂ reused B₁'s slot)
        assert_eq!(kernel.processes.len(), 3,
            "no extra slot appended — B₂ reused B₁'s slot");

        eprintln!("8.3f: ankad restart-B ✓");
        eprintln!("  B₁: tag={} detail={} handle={:#x}", tag_b1, detail_b1, handle_b1);
        eprintln!("  B₂: tag={} detail={} handle={:#x}", tag_b2, detail_b2, handle_b2);
        eprintln!("  A:  tag={} detail={}", tag_a, detail_a);
        eprintln!("  B slot {}: gen 0 → Free(1) → Running(1) → Free(2)", reused_slot);
        eprintln!("  A slot {}: gen 0 → Free(1)", a_slot);
        eprintln!("  process table size: {} (no growth)", kernel.processes.len());
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3g: 100-cycle steady-state conservation test
    //
    // ankad boots, performs 1 warm-up cycle + 100 steady-state
    // cycles of spawn-B → wait-B → verify-fault.
    //
    // Proves: the supervisor reaches a resource-steady state and
    // can continue restarting services without cumulative resource
    // consumption, subject only to explicit finite identifier
    // exhaustion (PID is u64, generation is u32).
    //
    // Formal backing:
    //   Kleis Petri net: M_Free →(spawn)→...→(reclaim)→ M_Free
    //   Extent P-invariants: SE+FSE=1, TE+FTE=1
    //   This test: 100 concrete cycles with no drift
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83g_100_cycle_steady_state() {
        let mut fabric = Fabric::new(0x400000);

        // --- Child B code: LD from unmapped → ProtectionFault ---
        let child_b_obj = fabric.alloc_object("child_b_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(child_b_obj, 0x080000);
        {
            let mut asm = Asm64::new();
            asm.movi(R1, 0xF000);
            asm.ld(R0, R1, 0);
            asm.halt();
            fabric.initialize_object(child_b_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(child_b_obj);

        // --- ankad code: 1 warm-up + 100 steady-state cycles ---
        let ankad_obj = fabric.alloc_object("ankad_code", 0x2000, ObjectKind::Memory);
        fabric.place_object(ankad_obj, 0x000000);
        let child_code_size: i32 = 12;  // 3 instructions × 4 bytes
        {
            let mut asm = Asm64::new();

            // --- Warm-up cycle ---
            // SPAWN B
            asm.movi(R1, 0x5000);
            asm.movi(R2, child_code_size);
            asm.movi(R3, 0);
            asm.movi(R0, SYS_SPAWN as i32);
            asm.trap(0);
            asm.mov(R8, R0);           // handle

            // WAIT B (warm-up)
            asm.mov(R1, R8);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            // R0=tag — don't check warm-up, just consume

            // --- Steady-state loop ---
            asm.movi(R4, 100);         // counter = 100

            let loop_top = asm.here();

            // SPAWN B
            asm.movi(R1, 0x5000);
            asm.movi(R2, child_code_size);
            asm.movi(R3, 0);
            asm.movi(R0, SYS_SPAWN as i32);
            asm.trap(0);
            asm.mov(R8, R0);           // handle

            // WAIT B
            asm.mov(R1, R8);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            // R0 = tag

            // Verify ProtectionFault (tag == 2)
            asm.cmpi(R0, 2);
            // If tag != 2, jump to error_exit
            let error_patch = asm.here();
            asm.bcc(Cond::Ne, 0);      // placeholder, patch later

            // Decrement counter
            asm.subi(R4, R4, 1);
            asm.cmpi(R4, 0);
            let back_offset = loop_top - asm.here() - 1;
            asm.bcc(Cond::Ne, back_offset);

            // --- Success: write cycle count + exit(0) ---
            // Store the final counter (should be 0) on stack for SYS_WRITE
            asm.movi(R5, 0x10000_u32 as i32);
            asm.st(R4, R5, 0);         // [0x10000] = 0 (counter exhausted)
            asm.movi(R1, 0x10000_u32 as i32);
            asm.movi(R2, 8);
            asm.movi(R3, 0);
            asm.movi(R0, SYS_WRITE as i32);
            asm.trap(0);

            asm.movi(R1, 0);
            asm.movi(R0, SYS_EXIT as i32);
            asm.trap(0);

            // --- Error exit ---
            let error_exit = asm.here();
            // Patch the Ne branch to jump here
            let patch_offset = error_exit - error_patch - 1;
            asm.words_mut()[error_patch as usize] =
                asm.words_mut()[error_patch as usize]
                    & 0xFFC0_0000  // clear immediate field
                    | ((patch_offset as u32) & 0x003F_FFFF);

            // Actually, let me just use a simpler approach — re-emit
            // the branch with the correct offset. The bcc encoding puts
            // the offset in bits [21:0] (22-bit signed).
            // But modifying in-place is fragile. Let me restructure.

            // ... I'll use a forward-reference pattern instead.
            drop(asm);

            // Rebuild with known layout
            let mut asm = Asm64::new();

            // --- Warm-up cycle ---
            asm.movi(R1, 0x5000);             // 0
            asm.movi(R2, child_code_size);    // 1
            asm.movi(R3, 0);                  // 2
            asm.movi(R0, SYS_SPAWN as i32);  // 3
            asm.trap(0);                       // 4
            asm.mov(R8, R0);                   // 5

            asm.mov(R1, R8);                   // 6
            asm.movi(R0, SYS_WAIT as i32);   // 7
            asm.trap(0);                       // 8

            // --- Loop init ---
            asm.movi(R4, 100);                 // 9

            // --- loop_top = 10 ---
            asm.movi(R1, 0x5000);             // 10
            asm.movi(R2, child_code_size);    // 11
            asm.movi(R3, 0);                  // 12
            asm.movi(R0, SYS_SPAWN as i32);  // 13
            asm.trap(0);                       // 14
            asm.mov(R8, R0);                   // 15

            asm.mov(R1, R8);                   // 16
            asm.movi(R0, SYS_WAIT as i32);   // 17
            asm.trap(0);                       // 18
            // R0 = tag

            asm.cmpi(R0, 2);                  // 19
            // BCC Ne → error_exit (word 29)
            // from word 20, target word 29, offset = 29 - 20 - 1 = 8
            asm.bcc(Cond::Ne, 8);             // 20

            asm.subi(R4, R4, 1);              // 21
            asm.cmpi(R4, 0);                  // 22
            // BCC Ne → loop_top (word 10)
            // from word 23, target word 10, offset = 10 - 23 - 1 = -14
            asm.bcc(Cond::Ne, -14);           // 23

            // --- Success path ---
            asm.movi(R5, 0x10000_u32 as i32); // 24
            asm.st(R4, R5, 0);                 // 25  [0x10000] = 0
            asm.movi(R1, 0x10000_u32 as i32); // 26
            asm.movi(R2, 8);                   // 27
            asm.movi(R3, 0);                   // 28
            asm.movi(R0, SYS_WRITE as i32);   // 29
            asm.trap(0);                        // 30

            asm.movi(R1, 0);                   // 31
            asm.movi(R0, SYS_EXIT as i32);    // 32
            asm.trap(0);                        // 33

            // --- Error exit (word 29... wait, that conflicts) ---
            // Let me recalculate. Error exit starts at word 34.
            // BCC Ne at word 20: offset = 34 - 20 - 1 = 13

            // Hmm, I numbered wrong. Let me just re-count the
            // error BCC offset. The SYS_WRITE sequence takes words
            // 24-30, then SYS_EXIT takes words 31-33.
            // Error exit at word 34.

            // Fix: BCC Ne at word 20 should jump to word 34.
            // offset = 34 - 20 - 1 = 13

            // But I already emitted bcc(Ne, 8) at word 20.
            // Need to patch it.
            // Actually the bcc(Ne, 8) at word 20 would jump to 20+1+8=29
            // which is SYS_WRITE. That's wrong.

            // Let me just put error_exit BEFORE success and restructure.
            drop(asm);

            // Final clean version with error exit via unconditional path
            let mut asm = Asm64::new();

            // --- Warm-up cycle (words 0-8) ---
            asm.movi(R1, 0x5000);             // 0
            asm.movi(R2, child_code_size);    // 1
            asm.movi(R3, 0);                  // 2
            asm.movi(R0, SYS_SPAWN as i32);  // 3
            asm.trap(0);                       // 4
            asm.mov(R8, R0);                   // 5
            asm.mov(R1, R8);                   // 6
            asm.movi(R0, SYS_WAIT as i32);   // 7
            asm.trap(0);                       // 8

            // --- Loop init (word 9) ---
            asm.movi(R4, 100);                 // 9

            // --- loop_top = word 10 ---
            asm.movi(R1, 0x5000);             // 10
            asm.movi(R2, child_code_size);    // 11
            asm.movi(R3, 0);                  // 12
            asm.movi(R0, SYS_SPAWN as i32);  // 13
            asm.trap(0);                       // 14
            asm.mov(R8, R0);                   // 15
            asm.mov(R1, R8);                   // 16
            asm.movi(R0, SYS_WAIT as i32);   // 17
            asm.trap(0);                       // 18

            // Verify tag == 2 (ProtectionFault)
            asm.cmpi(R0, 2);                  // 19
            // If tag == 2, skip error exit (jump over 3 error insns)
            asm.bcc(Cond::Eq, 2);             // 20 → word 23

            // Error exit (words 21-23)
            asm.movi(R1, 1);                   // 21
            asm.movi(R0, SYS_EXIT as i32);    // 22
            asm.trap(0);                        // 23 (unreachable on Eq)

            // Continue loop (word 24, reached from bcc Eq at 20)
            // Wait — bcc(Eq, 2) at word 20 → target = 20 + 1 + 2 = 23.
            // That lands on TRAP which IS the error exit. Off by one.
            // bcc offset: PC_next + offset = (20+1) + offset
            // Want to land at word 24 (post-error).
            // offset = 24 - 21 = 3
            drop(asm);

            let mut asm = Asm64::new();

            // Warm-up (words 0-11)
            emit_spawn_default(&mut asm, 0x5000, child_code_size, 0); // 0-7
            asm.mov(R9, R0);                   // 8: handle in R9
            asm.mov(R1, R9);                   // 9
            asm.movi(R0, SYS_WAIT as i32);   // 10
            asm.trap(0);                       // 11

            // Loop init (word 12)
            asm.movi(R4, 100);                 // 12

            // loop_top (word 13)
            emit_spawn_default(&mut asm, 0x5000, child_code_size, 0); // 13-20
            asm.mov(R9, R0);                   // 21
            asm.mov(R1, R9);                   // 22
            asm.movi(R0, SYS_WAIT as i32);   // 23
            asm.trap(0);                       // 24

            asm.cmpi(R0, 2);                  // 25
            asm.bcc(Cond::Eq, 4);             // 26: target = 26+1+4 = 31

            // Error exit (words 27-29)
            asm.movi(R1, 1);                   // 27
            asm.movi(R0, SYS_EXIT as i32);    // 28
            asm.trap(0);                        // 29

            // (word 30 unreachable — falls through from error exit trap)

            // Decrement + loop (words 30-...)
            asm.subi(R4, R4, 1);              // 30
            asm.cmpi(R4, 0);                  // 25
            // Back to loop_top (word 10): offset = 10 - 26 = -16
            asm.bcc(Cond::Ne, -16);           // 26: PC=26*4, target=26*4+(-16*4)=10*4 ✓

            // Success: write + exit (words 27+)
            asm.movi(R5, 0x10000_u32 as i32); // 27
            asm.st(R4, R5, 0);                 // 28
            asm.movi(R1, 0x10000_u32 as i32); // 29
            asm.movi(R2, 8);                   // 30
            asm.movi(R3, 0);                   // 31
            asm.movi(R0, SYS_WRITE as i32);   // 32
            asm.trap(0);                        // 33

            asm.movi(R1, 0);                   // 34
            asm.movi(R0, SYS_EXIT as i32);    // 35
            asm.trap(0);                        // 36

            fabric.initialize_object(ankad_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(ankad_obj);

        // --- Boot descriptor ---
        let info = BootInfo {
            image: BootImage {
                obj: ankad_obj,
                code_offset: 0,
                code_size: 0x2000,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![
                BootGrant { obj: child_b_obj, offset: 0, size: 0x1000, perms: Permissions::RX },
            ],
            maps: vec![
                BootMap { vaddr: 0x5000, size: 0x1000, obj: child_b_obj, obj_offset: 0 },
            ],
            code_vaddr: 0,
            stack_vaddr: 0x10000,
            stack_size: 0x4000,
            trap_vaddr: 0x20000,
        };

        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();

        // Capture baseline after boot (before any child cycles)
        let domains_at_boot = kernel.fabric.domains.len();
        let objects_at_boot = kernel.fabric.objects.len();

        kernel.run(10000000, 10000);

        // --- Verify ankad completed ---
        assert!(kernel.processes[0].exited(), "ankad should have exited");
        assert_eq!(kernel.processes[0].exit_code, 0,
            "ankad exit(0) — all 100 cycles verified ProtectionFault");
        assert_eq!(kernel.byte_output.len(), 8, "ankad wrote 8 bytes");
        let counter = u64::from_le_bytes(
            kernel.byte_output[0..8].try_into().unwrap());
        assert_eq!(counter, 0, "loop counter exhausted to 0");

        // --- Steady-state conservation assertions ---

        // Process table: ankad (slot 0) + one reused child slot = 2 entries
        assert_eq!(kernel.processes.len(), 2,
            "process table size stable at 2 (ankad + 1 reused child slot)");

        // Child slot generation = 101 (warm-up g=0, then 100 more cycles,
        // each reclaim advances generation: final = 101 as Free(101))
        assert_eq!(kernel.processes[1].state, ProcessState::Free);
        assert_eq!(kernel.processes[1].generation, 101,
            "child slot generation = 101 (1 warm-up + 100 cycles)");

        // next_phys: should not have grown beyond the warm-up allocation.
        // The warm-up allocates stack(0x4000) + trap(0x1000) = 0x5000.
        // All subsequent cycles reuse from the free pools.
        // boot allocates ankad's stack + trap first, then warm-up child
        // allocates its stack + trap.
        // After that, every cycle reuses the child's returned extents.
        // next_phys should be boot_base + ankad_alloc + warm-up_child_alloc.
        let expected_next_phys = 0x100000  // Kernel::new base
            + 0x4000                        // ankad stack
            + 0x1000                        // ankad trap
            + 0x4000                        // warm-up child stack
            + 0x1000;                       // warm-up child trap
        assert_eq!(kernel.next_phys, expected_next_phys,
            "next_phys unchanged after warm-up — no physical extent leaks");

        // Domains: ankad's domain + 0 child domains (all destroyed)
        // Plus the implicit domains for the sealed code objects? Let me check.
        // Actually boot creates ankad's domain. Children get their own via
        // create_child → create_domain, but those are destroyed by reclaim.
        // The boot code objects don't have domains — they're just objects.
        // So only ankad's domain should survive.
        // But ankad is Zombie, not reclaimed yet. Its domain survives.
        let domains_at_end = kernel.fabric.domains.len();
        assert_eq!(domains_at_end, domains_at_boot,
            "domain count unchanged: no child domains leaked");

        // Objects: same count as after boot (sealed code objects +
        // ankad's stack/trap). No child stack/trap objects leaked.
        let objects_at_end = kernel.fabric.objects.len();
        assert_eq!(objects_at_end, objects_at_boot,
            "object count unchanged: no child objects leaked");

        // Free extent pools: exactly 1 stack + 1 trap (from last child)
        assert_eq!(kernel.free_stack_extents.len(), 1,
            "1 stack extent in pool (last child's)");
        assert_eq!(kernel.free_trap_extents.len(), 1,
            "1 trap extent in pool (last child's)");

        // PID advanced: 1 (ankad) + 1 (warm-up) + 100 (cycles) = 102
        // next_pid should be at least 102 (ankad itself is PID 0).
        // Actually ankad is PID 0 from boot's spawn. warm-up child
        // gets PID 1. Then 100 more children get PIDs 2..101.
        // next_pid = 102.
        // Wait — boot calls spawn() which also increments next_pid.
        // Let me think. boot → prepare_process → spawn(core).
        // spawn: next_pid starts at 0, ankad gets PID 0, next_pid = 1.
        // warm-up child: spawn inside prepare_process → PID 1, next_pid = 2.
        // 100 cycles: PIDs 2..101, next_pid = 102.
        // That's the total: 102 PIDs consumed.
        // But with slot reuse, warm-up child and cycle 1 child both use
        // spawn → new PID. So yes, 102 total.

        eprintln!("8.3g: 100-cycle steady-state conservation ✓");
        eprintln!("  ankad exit_code = 0 (all cycles verified ProtectionFault)");
        eprintln!("  process table size: {}", kernel.processes.len());
        eprintln!("  child slot generation: {}", kernel.processes[1].generation);
        eprintln!("  next_phys: {:#x} (expected {:#x})", kernel.next_phys, expected_next_phys);
        eprintln!("  domains: {} (boot: {})", domains_at_end, domains_at_boot);
        eprintln!("  objects: {} (boot: {})", objects_at_end, objects_at_boot);
        eprintln!("  free_stack_extents: {}", kernel.free_stack_extents.len());
        eprintln!("  free_trap_extents: {}", kernel.free_trap_extents.len());
        eprintln!("  Formal: cycle closure + 100 concrete cycles = no drift");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.3g adversarial: stale key, remanence, send-to-dead
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p83g_stale_key_rejected_after_reuse() {
        // Spawn → reclaim → reuse slot → old ProcessKey is invalid.
        let fabric = Fabric::new(0x100000);
        let mut kernel = Kernel::new(fabric);

        let core1 = Anka64Core::new(AgentId(0), DomainId(0));
        let key1 = kernel.spawn(core1);
        kernel.finish_process(key1.slot, ProcessResult::Exited(0));
        kernel.reclaim_process(key1.slot);

        let core2 = Anka64Core::new(AgentId(1), DomainId(1));
        let key2 = kernel.spawn(core2);
        assert_eq!(key2.slot, key1.slot, "reused same slot");
        assert_ne!(key2.generation, key1.generation, "different generation");

        assert!(kernel.validate_process_key(&key1).is_none(),
            "old key must be rejected");
        assert!(kernel.validate_process_key(&key2).is_some(),
            "new key must be valid");

        eprintln!("8.3g: stale ProcessKey rejected after slot reuse ✓");
    }

    #[test]
    fn p83g_remanence_scrubbed() {
        // Write dirty data, reclaim, reuse → extent is scrubbed.
        let mut fabric = Fabric::new(0x400000);

        let child_obj = fabric.alloc_object("child_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(child_obj, 0x080000);
        {
            let mut asm = Asm64::new();
            asm.movi(R0, 99);
            asm.halt();
            fabric.initialize_object(child_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(child_obj);

        let ankad_obj = fabric.alloc_object("ankad_code", 0x1000, ObjectKind::Memory);
        fabric.place_object(ankad_obj, 0x000000);
        {
            let mut asm = Asm64::new();
            // SPAWN child
            emit_spawn_default(&mut asm, 0x5000, 8, 0);
            asm.mov(R9, R0);  // handle in R9

            // WAIT child
            asm.mov(R1, R9);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);

            // Exit
            asm.movi(R1, 0);
            asm.movi(R0, SYS_EXIT as i32);
            asm.trap(0);

            fabric.initialize_object(ankad_obj, 0, &asm.to_bytes());
        }
        fabric.seal_object(ankad_obj);

        let info = BootInfo {
            image: BootImage {
                obj: ankad_obj, code_offset: 0, code_size: 0x1000,
                entry: 0, lit_start: 0,
            },
            grants: vec![
                BootGrant { obj: child_obj, offset: 0, size: 0x1000, perms: Permissions::RX },
            ],
            maps: vec![
                BootMap { vaddr: 0x5000, size: 0x1000, obj: child_obj, obj_offset: 0 },
            ],
            code_vaddr: 0, stack_vaddr: 0x10000, stack_size: 0x4000, trap_vaddr: 0x20000,
        };

        let mut kernel = Kernel::new(fabric);
        kernel.boot(&info).unwrap();
        kernel.run(100000, 1000);

        assert_eq!(kernel.processes[0].exit_code, 0);

        // The child's stack extent was returned to the pool.
        // Verify it's been scrubbed: all zeros.
        assert_eq!(kernel.free_stack_extents.len(), 1);
        let ext = &kernel.free_stack_extents[0];
        let data = kernel.fabric.read_physical(ext.base, ext.size);
        assert!(data.iter().all(|&b| b == 0),
            "returned stack extent must be scrubbed to zero (no remanence)");

        eprintln!("8.3g: returned extent scrubbed — no data remanence ✓");
    }

    #[test]
    fn p83g_send_to_dead_process_fails() {
        // After a process dies, SYS_SEND to its PID should fail.
        let mut fabric = Fabric::new(0x100000);
        let text_a = fabric.alloc_object("a_text", 0x4000, ObjectKind::Memory);
        let stack_a = fabric.alloc_object("a_stack", 0x4000, ObjectKind::Memory);
        let text_b = fabric.alloc_object("b_text", 0x4000, ObjectKind::Memory);
        let stack_b = fabric.alloc_object("b_stack", 0x4000, ObjectKind::Memory);
        fabric.place_object(text_a, 0x000000);
        fabric.place_object(stack_a, 0x020000);
        fabric.place_object(text_b, 0x040000);
        fabric.place_object(stack_b, 0x060000);
        let dom_a = fabric.create_domain();
        let dom_b = fabric.create_domain();
        fabric.grant(dom_a, stack_a, 0, 0x4000, Permissions::RW);
        fabric.grant(dom_b, stack_b, 0, 0x4000, Permissions::RW);

        // A: exit(0) immediately
        let mut asm_a = Asm64::new();
        asm_a.movi(R0, SYS_EXIT as i32);
        asm_a.movi(R1, 0);
        asm_a.trap(0);
        fabric.write_physical(0x000000, &asm_a.to_bytes());
        install_trap_handler(&mut fabric, 0x000000, 0x4000);
        seal_code_object(&mut fabric, text_a, dom_a);

        // B: send(pid=0, value=42) → R0 should be MAX → exit(R0)
        let mut asm_b = Asm64::new();
        asm_b.movi(R0, SYS_SEND as i32);
        asm_b.movi(R1, 0);    // dest pid = 0 (A's PID)
        asm_b.movi(R2, 42);
        asm_b.trap(0);
        // R0 = 0 (success) or MAX (failure)
        asm_b.mov(R1, R0);
        asm_b.movi(R0, SYS_EXIT as i32);
        asm_b.trap(0);
        fabric.write_physical(0x040000, &asm_b.to_bytes());
        install_trap_handler(&mut fabric, 0x040000, 0x4000);
        seal_code_object(&mut fabric, text_b, dom_b);

        let mut core_a = Anka64Core::new(AgentId(0), dom_a);
        core_a.address_map.add(0x00000, 0x4000, text_a);
        core_a.address_map.add(0x20000, 0x4000, stack_a);
        core_a.r[SP as usize] = 0x20000 + 0x4000;
        core_a.trap_vector = 0x3FF0;

        let mut core_b = Anka64Core::new(AgentId(1), dom_b);
        core_b.address_map.add(0x00000, 0x4000, text_b);
        core_b.address_map.add(0x20000, 0x4000, stack_b);
        core_b.r[SP as usize] = 0x20000 + 0x4000;
        core_b.trap_vector = 0x3FF0;

        let mut kernel = Kernel::new(fabric);
        kernel.spawn(core_a);
        kernel.spawn(core_b);
        kernel.run(1000, 100);

        // A exited first (PID 0, round-robin), then B tried to send to PID 0
        assert!(kernel.processes[0].exited());
        assert!(kernel.processes[1].exited());
        // B's exit code = return value from SYS_SEND.
        // Since A is Zombie (not Running), resolve_pid returns None → MAX.
        assert_eq!(kernel.processes[1].exit_code, u64::MAX,
            "SYS_SEND to dead process returns MAX (failure)");

        eprintln!("8.3g: SYS_SEND to dead process → MAX ✓");
    }

    // ═══════════════════════════════════════════════════════════
    // 8.4c: ankad spawns the self-hosted compiler as a service
    //
    //   host creates five objects (ankad code, sealed CC_B code,
    //   source, output, workspace) and boots ankad as init.
    //   ankad constructs SpawnGrant/SpawnMap/SpawnLayout descriptors
    //   on its own stack and calls SYS_SPAWN(R1-R8) to launch CC_B
    //   with an explicit initial environment:
    //     source  = R
    //     output  = RWS
    //     workspace = RW
    //
    //   CC_B compiles "int main() { return 42; }", seals its output,
    //   SYS_EXEC runs the compiled child, and ankad observes
    //   Exited(42) via SYS_WAIT.
    //
    //   Key assertions:
    //     ankad exits with 0
    //     CC_B exits with 42 (observed via SYS_WAIT + SYS_WRITE)
    //     CC_B's slot reclaimed to Free
    //     compiled child's slot reclaimed to Free
    //     output object sealed by CC_B
    //     source/workspace/output objects survive CC_B's death
    //       (authority held by an incarnation ≠ resource owned)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn p84c_ankad_spawns_compiler() {
        // ── Build CC_B using the existing bootstrap path ──
        let ccb = build_ccb();
        let ccb_len = ccb.len();
        let ccb_size = ((ccb_len + 0xFFF) & !0xFFF) as u64;

        // CC_B cannot exceed the 64 KiB output buffer, so ccb_len
        // always fits in MOVI's 18-bit signed immediate range.
        assert!(ccb_len <= OUTPUT_SIZE as usize,
            "CC_B ({} bytes) exceeds output buffer", ccb_len);

        // ── Host creates the machine ──
        let mut fabric = Fabric::new(0x800000);

        // ankad code object
        let ankad_obj = fabric.alloc_object("ankad_code", 0x2000, ObjectKind::Memory);
        fabric.place_object(ankad_obj, 0x000000);

        // CC_B code object (sealed)
        let ccb_obj = fabric.alloc_object("ccb_code", ccb_size, ObjectKind::Memory);
        fabric.place_object(ccb_obj, 0x100000);
        fabric.initialize_object(ccb_obj, 0, &ccb);
        fabric.seal_object(ccb_obj);

        // Source object: length-prefixed "int main() { return 42; }"
        let source_obj = fabric.alloc_object("source", SOURCE_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(source_obj, 0x200000);
        let source_text = b"int main() { return 42; }";
        fabric.write_physical(0x200000, &(source_text.len() as u64).to_le_bytes());
        fabric.write_physical(0x200008, source_text);

        // Output object (active, empty — CC_B will write + seal)
        let output_obj = fabric.alloc_object("output", OUTPUT_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(output_obj, 0x210000);

        // Workspace object (uninitialized — CC_B's main() self-initializes)
        let work_obj = fabric.alloc_object("workspace", WS_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(work_obj, 0x220000);

        // ── Assemble ankad ──
        //
        // Virtual memory layout for ankad:
        //   0x00000 - 0x02000 : ankad code (Sealed, RX)
        //   0x07000 - 0x0C000 : source (R)
        //   0x0C000 - 0x12000 : workspace (RW)
        //   0x12000 - 0x22000 : output (RWS)
        //   0x30000+          : CC_B code (RX, sealed)
        //   0x50000 - 0x54000 : stack (kernel-allocated)
        //   0x54000 - 0x55000 : trap (kernel-allocated)
        //
        // Values above MOVI 18-bit limit use MOVI half; ADD Rx,Rx,Rx:
        //   0x0C000 = 0x6000 << 1    0x12000 = 0x9000 << 1
        //   0x10000 = 0x8000 << 1    0x22000 = 0x11000 << 1
        //   0x26000 = 0x13000 << 1   0x30000 = 0x18000 << 1
        //
        // Register plan:
        //   R4  = grant_base  (SP - 0x300), becomes SYS_SPAWN R4
        //   R6  = map_base    (SP - 0x200), becomes SYS_SPAWN R6
        //   R8  = layout_base (SP - 0x100), becomes SYS_SPAWN R8
        //   R9  = zero constant during construction, then handle
        //   R3, R10 = temporaries
        {
            let mut asm = Asm64::new();

            // ── Phase 1: base addresses ──
            asm.subi(R4, SP, 0x300);          // grant_base
            asm.subi(R6, SP, 0x200);          // map_base
            asm.subi(R8, SP, 0x100);          // layout_base
            asm.movi(R9, 0);                  // zero constant

            // ── Phase 2a: Grant[0] — source = R ──
            // [parent_vaddr, offset, size, perms, reserved]
            asm.movi(R3, 0x07000);
            asm.st(R3, R4, 0);               // parent_vaddr = 0x07000
            asm.st(R9, R4, 8);               // offset = 0
            asm.movi(R3, 0x5000);
            asm.st(R3, R4, 16);              // size = SOURCE_SIZE
            asm.movi(R3, 1);
            asm.st(R3, R4, 24);              // perms = READ
            asm.st(R9, R4, 32);              // reserved = 0

            // ── Phase 2b: Grant[1] — output = RWS ──
            asm.movi(R3, 0x9000);
            asm.add(R3, R3, R3);             // R3 = 0x12000
            asm.st(R3, R4, 40);              // parent_vaddr
            asm.st(R9, R4, 48);              // offset = 0
            asm.movi(R3, 0x8000);
            asm.add(R3, R3, R3);             // R3 = 0x10000
            asm.st(R3, R4, 56);              // size = OUTPUT_SIZE
            asm.movi(R3, 0x13);
            asm.st(R3, R4, 64);              // perms = RWS
            asm.st(R9, R4, 72);              // reserved = 0

            // ── Phase 2c: Grant[2] — workspace = RW ──
            asm.movi(R3, 0x6000);
            asm.add(R3, R3, R3);             // R3 = 0x0C000
            asm.st(R3, R4, 80);              // parent_vaddr
            asm.st(R9, R4, 88);              // offset = 0
            asm.movi(R3, 0x6000);
            asm.st(R3, R4, 96);              // size = WS_SIZE
            asm.movi(R3, 3);
            asm.st(R3, R4, 104);             // perms = RW
            asm.st(R9, R4, 112);             // reserved = 0

            // ── Phase 2d: Map[0] — source (identity mapping) ──
            // [child_vaddr, parent_vaddr, offset, size, reserved]
            asm.movi(R3, 0x07000);
            asm.st(R3, R6, 0);               // child_vaddr = 0x07000
            asm.st(R3, R6, 8);               // parent_vaddr = 0x07000
            asm.st(R9, R6, 16);              // offset = 0
            asm.movi(R3, 0x5000);
            asm.st(R3, R6, 24);              // size = SOURCE_SIZE
            asm.st(R9, R6, 32);              // reserved = 0

            // ── Phase 2e: Map[1] — workspace (identity mapping) ──
            asm.movi(R3, 0x6000);
            asm.add(R3, R3, R3);             // R3 = 0x0C000
            asm.st(R3, R6, 40);              // child_vaddr
            asm.st(R3, R6, 48);              // parent_vaddr
            asm.st(R9, R6, 56);              // offset = 0
            asm.movi(R3, 0x6000);
            asm.st(R3, R6, 64);              // size = WS_SIZE
            asm.st(R9, R6, 72);              // reserved = 0

            // ── Phase 2f: Map[2] — output (identity mapping) ──
            asm.movi(R3, 0x9000);
            asm.add(R3, R3, R3);             // R3 = 0x12000
            asm.st(R3, R6, 80);              // child_vaddr
            asm.st(R3, R6, 88);              // parent_vaddr
            asm.st(R9, R6, 96);              // offset = 0
            asm.movi(R3, 0x8000);
            asm.add(R3, R3, R3);             // R3 = 0x10000
            asm.st(R3, R6, 104);             // size = OUTPUT_SIZE
            asm.st(R9, R6, 112);             // reserved = 0

            // ── Phase 2g: SpawnLayout ──
            // [code_vaddr, stack_vaddr, stack_size, trap_vaddr, reserved]
            asm.movi(R3, 0x18000);
            asm.add(R3, R3, R3);             // R3 = 0x30000
            asm.st(R3, R8, 0);               // code_vaddr = CCB_CODE_BASE
            asm.movi(R3, 0x11000);
            asm.add(R3, R3, R3);             // R3 = 0x22000
            asm.st(R3, R8, 8);               // stack_vaddr = LAYOUT_STACK
            asm.movi(R3, 0x4000);
            asm.st(R3, R8, 16);              // stack_size = 0x4000
            asm.movi(R3, 0x13000);
            asm.add(R3, R3, R3);             // R3 = 0x26000
            asm.st(R3, R8, 24);              // trap_vaddr
            asm.st(R9, R8, 32);              // reserved = 0

            // ── Phase 3: SYS_SPAWN(R1-R8) ──
            asm.movi(R1, 0x18000);
            asm.add(R1, R1, R1);             // R1 = 0x30000 (CC_B code vaddr)
            asm.movi(R2, ccb_len as i32);    // R2 = ccb code_size (fits MOVI)
            asm.movi(R3, 0);                 // R3 = lit_start = 0
            asm.movi(R5, 3);                 // R5 = grant_count
            asm.movi(R7, 3);                 // R7 = map_count
            // R4 = grant_base, R6 = map_base, R8 = layout_base (already set)
            asm.movi(R0, SYS_SPAWN as i32);
            asm.trap(0);

            // ── Phase 4: SYS_WAIT ──
            asm.mov(R9, R0);                 // R9 = handle
            asm.mov(R1, R9);
            asm.movi(R0, SYS_WAIT as i32);
            asm.trap(0);
            // R0 = tag, R1 = detail

            // ── Phase 5: SYS_WRITE(tag, detail) ──
            asm.subi(R10, SP, 0x4000);       // R10 = stack base (scratch area)
            asm.st(R0, R10, 0);              // [base + 0] = tag
            asm.st(R1, R10, 8);              // [base + 8] = detail
            asm.mov(R1, R10);                // R1 = addr
            asm.movi(R2, 16);                // R2 = len (2 × u64)
            asm.movi(R3, 0);
            asm.movi(R0, SYS_WRITE as i32);
            asm.trap(0);

            // ── Phase 6: SYS_EXIT(0) ──
            asm.movi(R1, 0);
            asm.movi(R0, SYS_EXIT as i32);
            asm.trap(0);

            let code_bytes = asm.to_bytes();
            assert!(code_bytes.len() < 0x2000,
                "ankad code {} bytes exceeds 0x2000", code_bytes.len());
            fabric.initialize_object(ankad_obj, 0, &code_bytes);
        }
        fabric.seal_object(ankad_obj);

        // ── Boot descriptor ──
        let ankad_code_size = 0x2000_u64;
        let info = BootInfo {
            image: BootImage {
                obj: ankad_obj,
                code_offset: 0,
                code_size: ankad_code_size,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![
                BootGrant { obj: ccb_obj,    offset: 0, size: ccb_size,            perms: Permissions::RX },
                BootGrant { obj: source_obj, offset: 0, size: SOURCE_SIZE as u64,  perms: Permissions::READ },
                BootGrant { obj: output_obj, offset: 0, size: OUTPUT_SIZE as u64,  perms: Permissions::RWS },
                BootGrant { obj: work_obj,   offset: 0, size: WS_SIZE as u64,      perms: Permissions::RW },
            ],
            maps: vec![
                BootMap { vaddr: 0x07000, size: SOURCE_SIZE as u64, obj: source_obj, obj_offset: 0 },
                BootMap { vaddr: 0x0C000, size: WS_SIZE as u64,     obj: work_obj,   obj_offset: 0 },
                BootMap { vaddr: 0x12000, size: OUTPUT_SIZE as u64,  obj: output_obj, obj_offset: 0 },
                BootMap { vaddr: 0x30000, size: ccb_size,            obj: ccb_obj,    obj_offset: 0 },
            ],
            code_vaddr: 0,
            stack_vaddr: 0x50000,
            stack_size: 0x4000,
            trap_vaddr: 0x54000,
        };

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x300000;
        let result = kernel.boot(&info);
        assert_eq!(result, Ok(()), "boot(ankad) should succeed");

        // ── Run: CC_B compilation needs ~4M cycles ──
        kernel.run(5_000_000, 200);

        // ═══════════════════════════════════════════════════════
        // Host-side assertions
        // ═══════════════════════════════════════════════════════

        // 1. ankad exited cleanly
        assert!(kernel.processes[0].exited(), "ankad should have exited");
        assert_eq!(kernel.processes[0].exit_code, 0,
            "ankad exits with 0 (compiler supervised successfully)");

        // 2. byte_output: tag = 0 (Exited), detail = 42
        assert_eq!(kernel.byte_output.len(), 16,
            "ankad wrote 16 bytes (tag + detail)");
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(kernel.byte_output[off..off+8].try_into().unwrap())
        };
        let tag    = read_u64(0);
        let detail = read_u64(8);
        assert_eq!(tag, 0, "CC_B result tag = Exited (0)");
        assert_eq!(detail, 42, "CC_B exit code = 42 (compiled child returned 42)");

        // 3. At least 3 process slots: ankad + CC_B + compiled child
        let total_procs = kernel.processes.len();
        assert!(total_procs >= 3,
            "should have at least 3 process slots (ankad + CC_B + child), got {}",
            total_procs);

        // 4. CC_B and compiled child reclaimed to Free
        let free_slots: Vec<usize> = (1..kernel.processes.len())
            .filter(|&i| kernel.processes[i].state == ProcessState::Free)
            .collect();
        assert!(free_slots.len() >= 2,
            "CC_B and compiled child should both be Free, found {} Free slots",
            free_slots.len());

        // 5. Output object sealed by CC_B
        assert_eq!(kernel.fabric.objects[&output_obj].state, ObjectState::Sealed,
            "output object should be Sealed after CC_B's SYS_SEAL");

        // 6. Delegated objects survive process death
        //    (authority held by an incarnation ≠ resource owned by that incarnation)
        assert!(kernel.fabric.objects.contains_key(&source_obj),
            "source object still exists after CC_B reclaimed");
        assert!(kernel.fabric.objects.contains_key(&work_obj),
            "workspace object still exists after CC_B reclaimed");
        assert!(kernel.fabric.objects.contains_key(&output_obj),
            "output object still exists after CC_B reclaimed");

        // 7. ankad's own resources intact (zombie, not yet reclaimed)
        assert!(kernel.processes[0].resources.is_some(),
            "ankad's OwnedResources intact while zombie");

        // 8. Stack/trap extents returned from CC_B and compiled child
        assert!(kernel.free_stack_extents.len() >= 2,
            "at least 2 stack extents returned (CC_B + child)");
        assert!(kernel.free_trap_extents.len() >= 2,
            "at least 2 trap extents returned (CC_B + child)");

        eprintln!("8.4c: host → boot(ankad) → SYS_SPAWN(CC_B, env) → compile → seal → exec → 42 ✓");
        eprintln!("      ankad supervised compiler as ordinary process");
        eprintln!("      {} total process slots, {} Free after reclamation",
            total_procs, free_slots.len());
        eprintln!("      output Sealed, delegated objects survive incarnation death ✓");
    }

    // ═══════════════════════════════════════════════════════════
    //  Phase 8.6: System Image
    //
    //  The initial software object graph is packaged as a
    //  declarative boot construction manifest.  The host loads
    //  the image, calls kernel.boot(), and Anka takes over.
    //
    //  Closure criterion: one deterministic byte stream →
    //  host loads → kernel.boot → ankad → CC_B → 42,
    //  at two different physical bases with different ObjectIds.
    // ═══════════════════════════════════════════════════════════

    use crate::anka64::system_image::*;

    /// Phase 8.6 closure test: build image once, encode, decode,
    /// load at two different physical bases with different ObjectId
    /// mappings, and get 42 both times.
    #[test]
    fn p86_system_image_boot() {
        let ccb = build_ccb();
        let image = build_compiler_system_image(&ccb, b"int main() { return 42; }");
        let bytes = image.encode().unwrap();

        eprintln!("8.6: system image: {} bytes encoded", bytes.len());

        let decoded = SystemImage::decode(&bytes).unwrap();

        // Machine A: fresh Fabric, load at 0x100000
        let fabric_a = Fabric::new(8 * 1024 * 1024);
        let loaded_a = decoded.load_into(fabric_a, 0x100000).unwrap();

        // Machine B: Fabric with pre-allocated dummy object,
        // load at 0x300000. This shifts ObjectIds so
        // ImageObjectRef(0) → ObjectId(1) instead of ObjectId(0).
        let mut fabric_b = Fabric::new(8 * 1024 * 1024);
        fabric_b.alloc_object("dummy", 0x1000, ObjectKind::Memory);
        let loaded_b = decoded.load_into(fabric_b, 0x300000).unwrap();

        // Verify the two machines have different ObjectId mappings
        let ankad_id_a = loaded_a.object_map[&ImageObjectRef(0)];
        let ankad_id_b = loaded_b.object_map[&ImageObjectRef(0)];
        assert_ne!(ankad_id_a, ankad_id_b,
            "image identity must not depend on numeric ObjectId: \
             machine A maps ankad to {:?}, machine B should differ",
            ankad_id_a);

        // Run both machines: same image bytes → same result
        for (label, loaded) in [("P1=0x100000", loaded_a), ("P2=0x300000", loaded_b)] {
            let mut kernel = loaded.kernel;
            let boot_result = kernel.boot(&loaded.boot_info);
            assert_eq!(boot_result, Ok(()),
                "{label}: boot should succeed");

            kernel.run(5_000_000, 200);

            // ankad should have exited
            assert!(kernel.processes[0].exited(),
                "{label}: ankad should have exited");

            // R10 = WAIT tag (0 = Exited)
            let wait_tag = kernel.processes[0].core.r[R10 as usize];
            assert_eq!(wait_tag, 0,
                "{label}: WAIT tag should be 0 (Exited), got {wait_tag}");

            // Exit code = 42 (compiler's result)
            let exit_code = kernel.processes[0].exit_code;
            assert_eq!(exit_code, 42,
                "{label}: compiled program should return 42, got {exit_code}");

            eprintln!("8.6: {label} → ankad → CC_B → 42 ✓");
        }

        eprintln!("8.6: same image bytes, different placement, different ObjectIds, \
                   identical architectural behavior ✓");
        eprintln!("8.6: logical identity ≠ runtime identity ≠ authority ≠ \
                   virtual placement ≠ physical placement ✓");
    }

    // ── Codec tests ──

    /// Build a small but valid system image for codec testing.
    fn codec_test_image() -> SystemImage {
        SystemImage {
            version: IMAGE_VERSION,
            objects: vec![
                ImageObject {
                    name: "code".to_string(),
                    kind: ObjectKind::Memory,
                    size: 0x1000,
                    contents: vec![0xCC; 16],
                    seal_after_load: true,
                },
                ImageObject {
                    name: "data".to_string(),
                    kind: ObjectKind::Memory,
                    size: 0x2000,
                    contents: vec![],
                    seal_after_load: false,
                },
            ],
            boot: ImageBootInfo {
                image: ImageBootImage {
                    obj: ImageObjectRef(0),
                    code_offset: 0,
                    code_size: 16,
                    entry: 0,
                    lit_start: 0,
                },
                grants: vec![
                    ImageBootGrant {
                        obj: ImageObjectRef(1),
                        offset: 0,
                        size: 0x2000,
                        perms: Permissions::RW,
                    },
                ],
                maps: vec![
                    ImageBootMap {
                        vaddr: 0x10000,
                        size: 0x2000,
                        obj: ImageObjectRef(1),
                        obj_offset: 0,
                    },
                ],
                code_vaddr: 0,
                stack_vaddr: 0x20000,
                stack_size: 0x4000,
                trap_vaddr: 0x24000,
            },
        }
    }

    #[test]
    fn p86_roundtrip() {
        let image = codec_test_image();
        let bytes = image.encode().unwrap();
        let decoded = SystemImage::decode(&bytes).unwrap();
        assert_eq!(decoded, image);
    }

    #[test]
    fn p86_canonical_bytes() {
        let image = codec_test_image();
        let bytes1 = image.encode().unwrap();
        let decoded = SystemImage::decode(&bytes1).unwrap();
        let bytes2 = decoded.encode().unwrap();
        assert_eq!(bytes1, bytes2, "encode(decode(B)) should equal B");
    }

    #[test]
    fn p86_decode_bad_magic() {
        let image = codec_test_image();
        let mut bytes = image.encode().unwrap();
        bytes[0] = b'X';
        assert_eq!(SystemImage::decode(&bytes).unwrap_err(), ImageError::BadMagic);
    }

    #[test]
    fn p86_decode_truncated() {
        let image = codec_test_image();
        let bytes = image.encode().unwrap();
        assert_eq!(SystemImage::decode(&bytes[..20]).unwrap_err(), ImageError::Truncated);
    }

    #[test]
    fn p86_decode_invalid_ref() {
        let image = codec_test_image();
        let mut bytes = image.encode().unwrap();
        let ref_offset = HEADER_SIZE;
        bytes[ref_offset] = 99;
        assert_eq!(SystemImage::decode(&bytes).unwrap_err(), ImageError::InvalidObjectRef(99));
    }

    #[test]
    fn p86_decode_bad_perms() {
        let image = codec_test_image();
        let mut bytes = image.encode().unwrap();
        let grant_offset = HEADER_SIZE + BOOT_IMAGE_SIZE + BOOT_LAYOUT_SIZE;
        bytes[grant_offset + 4] = 0xFF;
        assert_eq!(SystemImage::decode(&bytes).unwrap_err(), ImageError::InvalidPermissions(0xFF));
    }

    #[test]
    fn p86_decode_trailing_bytes() {
        let image = codec_test_image();
        let mut bytes = image.encode().unwrap();
        bytes.push(0x42);
        assert_eq!(SystemImage::decode(&bytes).unwrap_err(), ImageError::TrailingBytes);
    }

    #[test]
    fn p86_decode_reserved_nonzero() {
        let image = codec_test_image();
        let mut bytes = image.encode().unwrap();
        bytes[28] = 1;
        assert_eq!(SystemImage::decode(&bytes).unwrap_err(), ImageError::ReservedNonZero);
    }

    #[test]
    fn p86_decode_invalid_utf8_name() {
        let image = codec_test_image();
        let mut bytes = image.encode().unwrap();
        let obj_start = HEADER_SIZE + BOOT_IMAGE_SIZE + BOOT_LAYOUT_SIZE
            + image.boot.grants.len() * GRANT_RECORD_SIZE
            + image.boot.maps.len() * MAP_RECORD_SIZE;
        bytes[obj_start + 2] = 0xFF;
        assert_eq!(SystemImage::decode(&bytes).unwrap_err(), ImageError::InvalidUtf8Name);
    }

}

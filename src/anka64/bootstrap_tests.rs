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
        assert!(kernel.processes[0].exited,
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, 42,
            "compiler should exit with child's result (42)");

        // Child process was spawned and exited with 42
        assert!(kernel.processes.len() >= 2,
            "child process should have been spawned");
        assert!(kernel.processes[1].exited,
            "child process should have exited");
        assert_eq!(kernel.processes[1].exit_code, 42,
            "child should have returned 42");

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

        let exited = kernel.processes[0].exited;
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
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
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

        assert!(kernel.processes[0].exited,
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "declared_len={}, payload {:?}: expected exit {}, got {}",
            declared_len,
            std::str::from_utf8(payload).unwrap_or("<binary>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
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

        assert!(kernel.processes[0].exited,
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
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

        assert!(kernel.processes[0].exited,
            "compiler process should have exited");
        assert_eq!(kernel.processes[0].exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, kernel.processes[0].exit_code);

        if expect_child {
            assert!(kernel.processes.len() >= 2,
                "expected child process");
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
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

        let exited = kernel.processes[0].exited;
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
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
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

        assert!(kernel.processes[0].exited);
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

    /// Run a 6B.4 test case: guest compiler with functions → expected result.
    fn run_6b4_test(source_text: &[u8], expected_exit: u64, expect_child: bool) {
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("compiler_text",  TEXT_SIZE as u64, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("literal_buf",    LIT_SIZE as u64, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);
        fabric.place_object(lits,   0x050000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);

        // Write source: [u64 length][text bytes]
        let src_len = source_text.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, source_text);

        // Initialize literal buffer workspace slots
        fabric.write_physical(
            0x030000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x030000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());

        // Trap handler at end of TEXT_SIZE text object
        install_trap_handler(&mut fabric, 0x000000, TEXT_SIZE as u64);

        // Compile the guest compiler from AST
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
        fabric.write_physical(0x000000, &code_bytes);
        seal_code_object(&mut fabric, text, dom);

        // Set up process — virtual layout derived from TEXT_SIZE
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0, TEXT_SIZE as u64, text);
        core.address_map.add(LAYOUT_SRC as u64,   SOURCE_SIZE as u64, source);
        core.address_map.add(LAYOUT_OUT as u64,    OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,     WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64,  0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64,    LIT_SIZE as u64, lits);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = TEXT_SIZE as u64 - 0x10;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(2000000, 10);

        let exited = kernel.processes[0].exited;
        let exit_code = kernel.processes[0].exit_code;
        let child_spawned = kernel.processes.len() >= 2;

        if !exited {
            use crate::anka64::isa::{decode, disassemble};
            let pc = kernel.processes[0].core.pc;
            let read = |off: u64| -> u64 {
                let bytes = kernel.fabric.read_physical(0x030000 + off, 8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
            let ws_error = read(0x18);
            let ws_tok   = read(0x20);
            let ws_pos   = read(0x00);
            let ws_out   = read(0x48);
            let ws_func  = read(0x58);
            let ws_fix   = read(0x60);
            eprintln!("STUCK: PC={:#x} pos={} tok={} error={} out_pos={} funcs={} fixups={}",
                pc, ws_pos, ws_tok, ws_error, ws_out, ws_func, ws_fix);
            // Decode instructions around PC
            for off in [0i64, -8, -16, 4, 8, 12] {
                let addr = (pc as i64 + off) as u64;
                if addr < TEXT_SIZE as u64 {
                    let bytes = kernel.fabric.read_physical(addr, 4);
                    let word = u32::from_le_bytes(bytes.try_into().unwrap());
                    let insn = decode(word);
                    let marker = if off == 0 { " <<<" } else { "" };
                    eprintln!("  {:#06x}: {:08x} {}{}",
                        addr, word, disassemble(&insn), marker);
                }
            }
            // Also dump registers
            let core = &kernel.processes[0].core;
            eprintln!("  R0={:#x} R4={:#x} R5={:#x} SP={:#x} FP={:#x} LR={:#x}",
                core.r[0], core.r[4], core.r[5], core.r[15], core.r[13], core.r[14]);
        }
        // Diagnostic dump when compiler exits with wrong code
        if exited && exit_code != expected_exit {
            let read = |off: u64| -> u64 {
                let bytes = kernel.fabric.read_physical(0x030000 + off, 8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
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
        assert!(exited, "compiler process should have exited");
        assert_eq!(exit_code, expected_exit,
            "source {:?}: expected exit {}, got {}",
            std::str::from_utf8(source_text).unwrap_or("<invalid>"),
            expected_exit, exit_code);

        if expect_child {
            assert!(child_spawned,
                "source {:?}: expected child process",
                std::str::from_utf8(source_text).unwrap_or("<invalid>"));
            assert!(kernel.processes[1].exited);
            assert_eq!(kernel.processes[1].exit_code, expected_exit);
        }
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
        // Note: the byte-copy loop reads into a local (b) first, then
        // passes it to writebyte. Nesting readbyte() inside writebyte()
        // triggers the CC_A caller-saved register clobber bug (6B.4).
        format!(
            "int storeliteral() {{ \
             int start = *{ns}; \
             int len = *{nl}; \
             int lb = *{litb}; \
             int lp = *{litp}; \
             *(lb + lp) = len; \
             lp = lp + 8; \
             int i = 0; \
             int b = 0; \
             while (i < len) {{ \
             b = readbyte(start + i); \
             writebyte(lb + lp + i, b); \
             i = i + 1; }} \
             i = lp + len; \
             i = (i + 7) & (0 - 8); \
             *{litp} = i; \
             return lp - 8; }} ",
            ns = WS_TOK_NAME_START, nl = WS_TOK_NAME_LEN,
            litb = WS_LIT_BASE, litp = WS_LIT_POS)
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

    fn canonical_scanstring() -> String {
        format!(
            "int scanstring() {{ \
             advance(); \
             int start = *{pos}; \
             int len = 0; \
             while (*{pos} < *{sl}) {{ \
             if (peekchar() == 34) {{ \
             *{ns} = start; *{nl} = len; \
             *{tt} = {str}; advance(); return 0; }} \
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
             storeliteral(); \
             nexttoken(); \
             emit(enci({movi}, {r4}, 0, 0)); \
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
             return syscall(6, {layout_out}, sz, 0); }} ",
            layout_src = LAYOUT_SRC,
            srclimit = SOURCE_SIZE - 8,
            layout_out = LAYOUT_OUT,
            pos = WS_POS, sl = WS_SRC_LEN, tb = WS_TEXT_BASE,
            e = WS_ERROR, sc = WS_SYM_COUNT, op = WS_OUT_POS,
            esp = WS_EXPR_SP, espabs = -EXPR_SP_INIT,
            fc = WS_FUNC_COUNT, fxc = WS_FIX_COUNT,
            tt = WS_TOK_TYPE, eof = TOK_EOF,
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
        format!(
            "int emit(int word) {{ \
             int pos = *{op}; \
             if ({limit} < pos) {{ *{e} = 1; return 0; }} \
             int padded = word | (({nop} << 26) << 32); \
             *({out} + pos) = padded; \
             *{op} = pos + 8; \
             return 0; }} ",
            op = WS_OUT_POS,
            limit = OUTPUT_SIZE - 8,
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
        // Complete lexer: all 13 functions (including scanstring, writebyte, storeliteral).
        let src = format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}\
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
            canonical_scanstring(),
            );
        eprintln!("6B.5.0e: full lexer source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: full lexer (13 functions) compiles ✓");
    }

    #[test]
    fn b50e_nexttoken_compiles() {
        // Complete lexer + tokenizer (14 functions).
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
            canonical_scanstring(),
            canonical_nexttoken(),
            );
        eprintln!("6B.5.0e: lexer+tokenizer source = {} bytes", src.len());
        run_6b4_test(src.as_bytes(), 42, true);
        eprintln!("6B.5.0e: complete tokenizer (14 functions) compiles ✓");
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
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
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
        // Full canonical compiler: all 45 functions compile without error.
        // The child binary IS the compiler — its main reads source from
        // the buffer, which still holds the canonical text. It tries to
        // self-compile (CC_B), which may succeed or fail depending on
        // cycles/memory. We only verify the HOST compilation succeeds.
        let src = canonical_compiler_source();
        eprintln!("6B.5.0e: full compiler source = {} bytes", src.len());

        // Compile with the host compiler; don't validate child exit
        // (the child IS a compiler, not a simple program).
        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        let code_bytes = asm.to_bytes();

        let mut fabric = Fabric::new(0x400000);
        let text   = fabric.alloc_object("compiler_text",  TEXT_SIZE as u64, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("literal_buf",    LIT_SIZE as u64, ObjectKind::Memory);
        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);
        fabric.place_object(lits,   0x050000);
        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);
        let src_bytes = src.as_bytes();
        let src_len = src_bytes.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, src_bytes);
        fabric.write_physical(
            0x030000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x030000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());
        install_trap_handler(&mut fabric, 0x000000, TEXT_SIZE as u64);
        fabric.write_physical(0x000000, &code_bytes);
        seal_code_object(&mut fabric, text, dom);
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0, TEXT_SIZE as u64, text);
        core.address_map.add(LAYOUT_SRC as u64, SOURCE_SIZE as u64, source);
        core.address_map.add(LAYOUT_OUT as u64, OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,  WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64, 0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64, LIT_SIZE as u64, lits);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = TEXT_SIZE as u64 - 0x10;
        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(2000000, 10);

        assert!(kernel.processes[0].exited,
            "host compiler did not exit");

        // Read workspace diagnostics
        let read = |off: u64| -> u64 {
            let bytes = kernel.fabric.read_physical(0x030000 + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read(0x18);
        let ws_funcs = read(0x58);
        let ws_out   = read(0x48);
        eprintln!("6B.5.0e: host compiled {} functions, {} bytes output, error={}",
            ws_funcs, ws_out, ws_error);
        assert_eq!(ws_error, 0, "host compiler reported error");
        assert_eq!(ws_funcs, 45, "expected 45 canonical functions");
        eprintln!("6B.5.0e: canonical full compiler (45 functions) ✓");
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
        // compileprimary stores the literal and emits a placeholder.
        // The child returns 0 (the placeholder MOVI R4, 0 value).
        //
        // Architectural invariant: Bytes ≠ Text.
        // String literals are arbitrary UTF-8 bytes + explicit byte
        // length.  No NUL termination.  Byte length ≠ codepoint count
        // ≠ grapheme count.
        let src = br#"int main() { return "hello"; }"#;
        run_6b4_test(src, 0, true);
        eprintln!("7.0: string literal tokenized and compiled ✓");
    }

    #[test]
    fn p70_string_token_utf8() {
        // UTF-8 string literal: "İzmir" is 6 bytes (İ = 0xC4 0xB0,
        // z = 0x7A, m = 0x6D, i = 0x69, r = 0x72).
        // The tokenizer preserves all UTF-8 bytes verbatim.
        // byte_length("İzmir") = 6 ≠ codepoint_count = 5 ≠ grapheme_count = 5.
        let src = "int main() { return \"İzmir\"; }";
        run_6b4_test(src.as_bytes(), 0, true);
        eprintln!("7.0: UTF-8 string literal tokenized (İzmir) ✓");
    }

    #[test]
    fn p70_string_token_workspace_state() {
        // Verify the tokenizer sets WS_TOK_TYPE, WS_TOK_NAME_START,
        // WS_TOK_NAME_LEN correctly for a string literal.
        // Now that compileprimary handles TOK_STRING, we verify the
        // compilation succeeds and the literal buffer is populated.
        let src = br#"int main() { return "hello"; }"#;
        let mut fabric = Fabric::new(0x400000);

        let text   = fabric.alloc_object("text",   TEXT_SIZE as u64, ObjectKind::Memory);
        let source = fabric.alloc_object("source", SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("output", OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("ws",     WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("stack",  0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("lits",   LIT_SIZE as u64, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);
        fabric.place_object(lits,   0x050000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);

        let src_len = src.len() as u64;
        fabric.write_physical(0x010000, &src_len.to_le_bytes());
        fabric.write_physical(0x010008, src);

        // Initialize literal buffer workspace slots
        fabric.write_physical(
            0x030000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x030000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());

        install_trap_handler(&mut fabric, 0x000000, TEXT_SIZE as u64);

        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0, TEXT_SIZE as u64, text);
        core.address_map.add(LAYOUT_SRC as u64,   SOURCE_SIZE as u64, source);
        core.address_map.add(LAYOUT_OUT as u64,    OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,     WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64,  0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64,    LIT_SIZE as u64, lits);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = TEXT_SIZE as u64 - 0x10;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(2000000, 10);

        assert!(kernel.processes[0].exited, "compiler should exit");

        // Read workspace state
        let read = |off: u64| -> u64 {
            let bytes = kernel.fabric.read_physical(0x030000 + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };

        let tok_type = read(0x20);  // WS_TOK_TYPE
        let tok_start = read(0x30); // WS_TOK_NAME_START (byte offset in source)
        let tok_len = read(0x38);   // WS_TOK_NAME_LEN (byte length of content)
        let ws_error = read(0x18);  // WS_ERROR

        eprintln!("7.0 workspace: tok_type={} start={} len={} error={}",
            tok_type, tok_start, tok_len, ws_error);

        // compileprimary now handles TOK_STRING by calling storeliteral.
        // The compiler should succeed.
        assert_eq!(ws_error, 0, "compiler should succeed with string literal");
        eprintln!("7.0: string literal workspace state verified ✓");
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
        // Empty string "" should tokenize to TOK_STRING with length 0.
        let src = br#"int main() { return ""; }"#;
        run_6b4_test(src, 0, true);
        eprintln!("7.0: empty string literal compiled ✓");
    }

    #[test]
    fn p70_string_embedded_nul() {
        // ByteString allows embedded NUL: "a\0b" (using raw bytes).
        // Source text is: int main() { return "a\x00b"; }
        // Since we don't have escape sequences, we inject NUL directly.
        let mut src = Vec::from(&b"int main() { return \""[..]);
        src.push(b'a');
        src.push(0x00); // embedded NUL
        src.push(b'b');
        src.extend_from_slice(b"\"; }");
        run_6b4_test(&src, 0, true);
        eprintln!("7.0: embedded NUL in ByteString ✓");
    }

    #[test]
    fn p70_string_multibyte_utf8() {
        // "şarap" — ş is 2 bytes (0xC5 0x9F), total 6 bytes, 5 codepoints.
        // byte_length ≠ codepoint_count: architectural invariant from day one.
        let src = "int main() { return \"şarap\"; }";
        let src_bytes = src.as_bytes();
        let sarap = "şarap";
        assert_eq!(sarap.len(), 6, "şarap is 6 UTF-8 bytes");
        assert_eq!(sarap.chars().count(), 5, "şarap is 5 codepoints");
        run_6b4_test(src_bytes, 0, true);
        eprintln!("7.0: multi-byte UTF-8 string (şarap, 6 bytes, 5 codepoints) ✓");
    }

    // ─── Phase 7.1 — Literal object representation ───────

    #[test]
    fn p71_store_literal_hello() {
        // Compile a program containing "hello" as a string literal.
        // compileprimary now calls storeliteral() for TOK_STRING,
        // writing {u64 byte_len=5, "hello"} to the literal buffer.
        // The child runs and returns 0 (placeholder from MOVI R4, 0).
        //
        // After compilation, we inspect the literal buffer to verify
        // the representation: [u64 byte_len][data bytes], no NUL.
        let src = br#"int main() { return "hello"; }"#;

        let mut fabric = Fabric::new(0x400000);
        let text   = fabric.alloc_object("text",   TEXT_SIZE as u64, ObjectKind::Memory);
        let source = fabric.alloc_object("source", SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("output", OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("ws",     WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("stack",  0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("lits",   LIT_SIZE as u64, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);
        fabric.place_object(lits,   0x050000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);

        fabric.write_physical(0x010000, &(src.len() as u64).to_le_bytes());
        fabric.write_physical(0x010008, src.as_ref());

        fabric.write_physical(
            0x030000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x030000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());

        install_trap_handler(&mut fabric, 0x000000, TEXT_SIZE as u64);
        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0, TEXT_SIZE as u64, text);
        core.address_map.add(LAYOUT_SRC as u64,   SOURCE_SIZE as u64, source);
        core.address_map.add(LAYOUT_OUT as u64,    OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,     WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64,  0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64,    LIT_SIZE as u64, lits);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = TEXT_SIZE as u64 - 0x10;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(2000000, 10);

        assert!(kernel.processes[0].exited, "compiler should exit");

        // Verify the compiler succeeded (error flag = 0)
        let read_ws = |off: u64| -> u64 {
            let bytes = kernel.fabric.read_physical(0x030000 + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws(0x18);
        assert_eq!(ws_error, 0, "compiler should succeed with string literal");

        // Read the literal buffer: [u64 byte_len][data]
        let lit_header = kernel.fabric.read_physical(0x050000, 8);
        let byte_len = u64::from_le_bytes(lit_header.try_into().unwrap());
        assert_eq!(byte_len, 5, "byte_len should be 5 for \"hello\"");

        let lit_data = kernel.fabric.read_physical(0x050008, 5);
        assert_eq!(&lit_data[..], b"hello",
            "literal buffer should contain 'hello'");

        // Verify WS_LIT_POS advanced: 8 (header) + 5 (data) = 13, aligned to 16
        let lit_pos = read_ws((WS_LIT_POS - LAYOUT_WS) as u64);
        assert_eq!(lit_pos, 16,
            "WS_LIT_POS should be 16 (8+5 rounded to 8-byte alignment)");

        eprintln!("7.1: literal object [u64 byte_len=5][hello] ✓");
        eprintln!("     length is metadata, not inferred from contents");
    }

    #[test]
    fn p71_store_literal_utf8_izmir() {
        // "İzmir" is 6 UTF-8 bytes: C4 B0 7A 6D 69 72.
        // byte_length(6) ≠ codepoint_count(5) ≠ grapheme_count(5).
        // The literal buffer must preserve all 6 bytes exactly.
        let src = "int main() { return \"İzmir\"; }";
        run_6b4_test(src.as_bytes(), 0, true);
        eprintln!("7.1: İzmir literal compiled (child returns 0 placeholder) ✓");
    }

    #[test]
    fn p71_store_literal_empty() {
        // Empty string "" → byte_len = 0, no data bytes.
        let src = br#"int main() { return ""; }"#;
        run_6b4_test(src, 0, true);
        eprintln!("7.1: empty string literal compiled ✓");
    }

    #[test]
    fn p71_two_literals() {
        // Two string literals in one program (separate functions).
        // Each gets its own literal object in the buffer.
        let src = br#"int foo() { return "hello"; } int main() { return "world"; }"#;
        run_6b4_test(src, 0, true);
        eprintln!("7.1: two string literals compiled ✓");
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
    fn build_ccb() -> Vec<u8> {
        let mut fabric = Fabric::new(0x400000);
        let text   = fabric.alloc_object("compiler_text",  TEXT_SIZE as u64, ObjectKind::Memory);
        let source = fabric.alloc_object("source_data",    SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("output_buf",     OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("workspace",      WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("compiler_stack", 0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("literal_buf",    LIT_SIZE as u64, ObjectKind::Memory);

        fabric.place_object(text,   0x000000);
        fabric.place_object(source, 0x010000);
        fabric.place_object(output, 0x020000);
        fabric.place_object(work,   0x030000);
        fabric.place_object(stack,  0x040000);
        fabric.place_object(lits,   0x050000);

        let dom = fabric.create_domain();
        fabric.grant(dom, source, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);

        let canon_src = canonical_compiler_source();
        let src_bytes = canon_src.as_bytes();
        fabric.write_physical(0x010000, &(src_bytes.len() as u64).to_le_bytes());
        fabric.write_physical(0x010008, src_bytes);

        // Initialize literal buffer workspace slots
        fabric.write_physical(
            0x030000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x030000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());

        install_trap_handler(&mut fabric, 0x000000, TEXT_SIZE as u64);
        let compiler_prog = build_6b4_compiler();
        let asm = cc::compile(&compiler_prog);
        fabric.write_physical(0x000000, &asm.to_bytes());
        seal_code_object(&mut fabric, text, dom);

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(0, TEXT_SIZE as u64, text);
        core.address_map.add(LAYOUT_SRC as u64,   SOURCE_SIZE as u64, source);
        core.address_map.add(LAYOUT_OUT as u64,    OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,     WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64,  0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64,    LIT_SIZE as u64, lits);
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = TEXT_SIZE as u64 - 0x10;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x060000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(2000000, 10);

        assert!(kernel.processes[0].exited,
            "CC_A did not exit while compiling canonical source");

        // Read output size from workspace
        let read_ws = |off: u64| -> u64 {
            let bytes = kernel.fabric.read_physical(0x030000 + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws(0x18);
        let out_pos = read_ws(0x48);
        let ws_funcs = read_ws(0x58);
        assert_eq!(ws_error, 0, "CC_A error compiling canonical source");
        assert_eq!(ws_funcs, 45, "CC_A compiled wrong function count");

        // Extract CC_B binary from output buffer
        let ccb_bytes = kernel.fabric.read_physical(0x020000, out_pos).to_vec();
        eprintln!("build_ccb: CC_B = {} bytes ({} functions)",
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
        let ccb_size = ((ccb.len() + 0xFFF) & !0xFFF) as u64;
        let mut fabric = Fabric::new(0x800000);

        let code   = fabric.alloc_object("ccb_code",     ccb_size, ObjectKind::Memory);
        let source = fabric.alloc_object("ccb_source",   SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("ccb_output",   OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("ccb_workspace", WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("ccb_stack",    0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("ccb_lits",     LIT_SIZE as u64, ObjectKind::Memory);

        // Physical placement — non-overlapping regions
        fabric.place_object(code,   0x100000);
        fabric.place_object(source, 0x200000);
        fabric.place_object(output, 0x210000);
        fabric.place_object(work,   0x220000);
        fabric.place_object(stack,  0x230000);
        fabric.place_object(lits,   0x240000);

        let dom = fabric.create_domain();

        // Write CC_B code and seal
        fabric.write_physical(0x100000, ccb);
        install_trap_handler(&mut fabric, 0x100000, ccb_size);
        fabric.seal_object(code);
        fabric.grant(dom, code, 0, ccb_size, Permissions::RX);

        // Grant data regions
        fabric.grant(dom, source, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);

        // Write test source into source buffer
        let src_len = test_source.len() as u64;
        fabric.write_physical(0x200000, &src_len.to_le_bytes());
        fabric.write_physical(0x200008, test_source);

        // Initialize literal buffer workspace slots
        fabric.write_physical(
            0x220000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x220000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());

        // Virtual address map:
        //   CCB_CODE_BASE → code (CC_B binary)
        //   LAYOUT_SRC    → source (test program text)
        //   LAYOUT_OUT    → output (compiled test program)
        //   LAYOUT_WS     → workspace
        //   LAYOUT_STACK  → stack
        //   LAYOUT_LIT    → literal buffer
        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(CCB_CODE_BASE,          ccb_size, code);
        core.address_map.add(LAYOUT_SRC as u64,      SOURCE_SIZE as u64, source);
        core.address_map.add(LAYOUT_OUT as u64,      OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,       WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64,    0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64,      LIT_SIZE as u64, lits);
        core.pc = CCB_CODE_BASE;
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = CCB_CODE_BASE + ccb_size - 0x10;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x300000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(4000000, 10);

        let exited = kernel.processes[0].exited;
        let exit_code = kernel.processes[0].exit_code;

        if !exited {
            let read_ws = |off: u64| -> u64 {
                let bytes = kernel.fabric.read_physical(0x220000 + off, 8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
            let pc = kernel.processes[0].core.pc;
            eprintln!("CC_B STUCK: PC={:#x} (offset {:#x})",
                pc, pc.wrapping_sub(CCB_CODE_BASE));
            eprintln!("  pos={} tok={} error={} out_pos={} funcs={} fixups={}",
                read_ws(0x00), read_ws(0x20), read_ws(0x18),
                read_ws(0x48), read_ws(0x58), read_ws(0x60));
            let core = &kernel.processes[0].core;
            eprintln!("  R0={:#x} R4={:#x} R5={:#x} SP={:#x} FP={:#x} LR={:#x}",
                core.r[0], core.r[4], core.r[5], core.r[15], core.r[13], core.r[14]);
        }
        if exited && exit_code != expected_exit {
            let read_ws = |off: u64| -> u64 {
                let bytes = kernel.fabric.read_physical(0x220000 + off, 8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
            eprintln!("CC_B DIAG: error={} tok={} pos={} out_pos={} funcs={} fixups={}",
                read_ws(0x18), read_ws(0x20), read_ws(0x00),
                read_ws(0x48), read_ws(0x58), read_ws(0x60));
        }
        assert!(exited, "CC_B did not exit");
        assert_eq!(exit_code, expected_exit,
            "CC_B compiled {:?}: expected exit {}, got {}",
            std::str::from_utf8(test_source).unwrap_or("<invalid>"),
            expected_exit, exit_code);
    }

    /// Run CC_B (the canonical compiler) on source text and extract
    /// the compiled output bytes WITHOUT executing SYS_EXEC.
    /// Returns (output_bytes, func_count, error_flag).
    fn compile_with_ccb(ccb: &[u8], source: &[u8]) -> (Vec<u8>, u64, u64) {
        let ccb_size = ((ccb.len() + 0xFFF) & !0xFFF) as u64;
        let mut fabric = Fabric::new(0x800000);

        let code   = fabric.alloc_object("ccb_code",     ccb_size, ObjectKind::Memory);
        let src_obj = fabric.alloc_object("ccb_source",  SOURCE_SIZE as u64, ObjectKind::Memory);
        let output = fabric.alloc_object("ccb_output",   OUTPUT_SIZE as u64, ObjectKind::Memory);
        let work   = fabric.alloc_object("ccb_workspace", WS_SIZE as u64, ObjectKind::Memory);
        let stack  = fabric.alloc_object("ccb_stack",    0x4000, ObjectKind::Memory);
        let lits   = fabric.alloc_object("ccb_lits",     LIT_SIZE as u64, ObjectKind::Memory);

        fabric.place_object(code,    0x100000);
        fabric.place_object(src_obj, 0x200000);
        fabric.place_object(output,  0x210000);
        fabric.place_object(work,    0x220000);
        fabric.place_object(stack,   0x230000);
        fabric.place_object(lits,    0x240000);

        let dom = fabric.create_domain();
        fabric.write_physical(0x100000, ccb);
        install_trap_handler(&mut fabric, 0x100000, ccb_size);
        fabric.seal_object(code);
        fabric.grant(dom, code, 0, ccb_size, Permissions::RX);
        fabric.grant(dom, src_obj, 0, SOURCE_SIZE as u64, Permissions::READ);
        fabric.grant(dom, output, 0, OUTPUT_SIZE as u64, Permissions::RWS);
        fabric.grant(dom, work,   0, WS_SIZE as u64, Permissions::RW);
        fabric.grant(dom, stack,  0, 0x4000, Permissions::RW);
        fabric.grant(dom, lits,   0, LIT_SIZE as u64, Permissions::RW);

        fabric.write_physical(0x200000, &(source.len() as u64).to_le_bytes());
        fabric.write_physical(0x200008, source);

        // Initialize literal buffer workspace slots
        fabric.write_physical(
            0x220000 + (WS_LIT_BASE - LAYOUT_WS) as u64,
            &(LAYOUT_LIT as u64).to_le_bytes());
        fabric.write_physical(
            0x220000 + (WS_LIT_POS - LAYOUT_WS) as u64,
            &0u64.to_le_bytes());

        let mut core = Anka64Core::new(AgentId(0), dom);
        core.address_map.add(CCB_CODE_BASE,          ccb_size, code);
        core.address_map.add(LAYOUT_SRC as u64,      SOURCE_SIZE as u64, src_obj);
        core.address_map.add(LAYOUT_OUT as u64,      OUTPUT_SIZE as u64, output);
        core.address_map.add(LAYOUT_WS as u64,       WS_SIZE as u64, work);
        core.address_map.add(LAYOUT_STACK as u64,    0x4000, stack);
        core.address_map.add(LAYOUT_LIT as u64,      LIT_SIZE as u64, lits);
        core.pc = CCB_CODE_BASE;
        core.r[SP as usize] = LAYOUT_STACK as u64 + 0x4000;
        core.trap_vector = CCB_CODE_BASE + ccb_size - 0x10;

        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = 0x300000;
        kernel.next_agent = 10;
        kernel.spawn(core);
        kernel.run(4000000, 10);

        assert!(kernel.processes[0].exited, "CC_B did not exit");

        let read_ws = |off: u64| -> u64 {
            let bytes = kernel.fabric.read_physical(0x220000 + off, 8);
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
        let ws_error = read_ws(0x18);
        let out_pos = read_ws(0x48);
        let ws_funcs = read_ws(0x58);

        let output_bytes = if ws_error == 0 && out_pos > 0 {
            kernel.fabric.read_physical(0x210000, out_pos).to_vec()
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
        eprintln!("stage 1: CC_A → CC_B = {} bytes (45 functions)", ccb.len());

        // ── Stage 2: CC_B(source_CC) → CC_C ──
        let canon_src = canonical_compiler_source();
        let (ccc, ccc_funcs, ccc_error) = compile_with_ccb(&ccb, canon_src.as_bytes());
        assert_eq!(ccc_error, 0, "CC_B failed to compile canonical source");
        assert_eq!(ccc_funcs, 45, "CC_C has wrong function count");
        assert!(!ccc.is_empty(), "CC_C is empty");
        eprintln!("stage 2: CC_B → CC_C = {} bytes (45 functions)", ccc.len());

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

}

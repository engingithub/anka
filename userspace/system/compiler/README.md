# /system/compiler

Logical home for Anka64 compiler/toolchain components.

Phase 9.3h.2 introduced the supervised CC_B compile-only path.  Phase 10 keeps
that bootstrap compiler intact and begins the second-generation toolchain here.

## Phase 10.1: AnkaCC2 stage 1

`ankacc2_stage1.c` is real Anka userspace C and is deliberately compilable by
CC_B.  It reuses the already-audited compiler process ABI (source, workspace,
output, compile-only mode) while replacing the old lexer/parser boundary with
the first AC2 slice.  The bootstrap source must itself remain inside CC_B's
frozen grammar; in particular CC_B admits `syscall(...)` as an expression, not
as a bare call statement.

The stage-1 front end accepts:

```text
identifier := [A-Za-z_][A-Za-z0-9_]{0,62}
integer    := decimal-u64 | 0[xX]hex-u64
function   := int identifier() { return expression; }
expression := integer | identifier()
program    := function+
```

Integer width is a magnitude property: leading zeroes do not consume the
64-bit magnitude budget.  Decimal and hexadecimal spellings above `u64` are
rejected.

The parser envelope is intentionally narrow.  Parameters, declarations,
prototypes, pointers, arrays, structs, typedefs, enums, headers, separate
translation units, and richer expressions remain later Phase 10 work.

Stage 1 emits the existing direct executable image, not AOM.  AOM first appears
in Phase 10.3 and linking in Phase 10.4.

Stable stage-1 diagnostic codes in the shared compiler workspace are:

```text
1  invalid lexical byte/token
2  identifier exceeds 63 bytes
3  integer magnitude exceeds 64 bits or malformed hex token
4  token is outside the stage-1 parser grammar
5  duplicate function definition
6  missing main
7  unresolved function call
8  compiler table/output resource bound exceeded
```

Compilation still creates no execution authority.  The produced executable is
sealed in compile-only mode and must later pass the ordinary Anka execution
admission path before it can run.

## Phase 10.1 closure

Phase 10.1 is closed with the complete regression suite green:

```text
932 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The corresponding Kleis refinement gate remains 15/15 positive with 0/8 hostile
witnesses accepted and no new axioms.  This establishes the real bootstrap edge
`CC_B -> AnkaCC2-stage1` before Phase 10.2 expands declarations, types, and ABI
semantics.


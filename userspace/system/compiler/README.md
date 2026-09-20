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


## Phase 10.2: AnkaCC2 stage 2

`ankacc2_stage2.c` keeps the same CC_B-buildable, supervised compile-only
bootstrap path while adding the first explicit AC2 type and function ABI layer.
Stage 1 remains unchanged as the closed 10.1 checkpoint.

Stage 2 adds compatible prototypes, up to four scalar/pointer parameters in
`R0..R3`, scalar/pointer return in `R0`, `int`, byte-sized `char`, `void`, nested
pointers, fixed local arrays, declaration-order/aligned structs, typedef aliases,
named enums/enumerator constants, array-parameter decay, and `sizeof(type)` /
`sizeof(type[extent])`.
Byte-sized `char` values undergo the Stage-2 integer promotion to `int` when used by the supported `+`/`-` arithmetic operators; storage remains one byte while the arithmetic/result representation is one word.  Scalar value compatibility also admits `char`→`int` and `int`→`char`; the narrowing direction stores the low byte and byte loads zero-extend into the word-register ABI.

Typed local objects are stack-resident.  Fixed extents are bounded to 1024
elements and the typed local-object portion of a frame is bounded to 8192 bytes.
Aggregate-by-value parameters/returns are deliberately rejected while no
aggregate ABI has been earned.

The direct Stage-2 backend still emits code-only sealed executables.  Mutable
file-scope data is therefore rejected instead of being placed into executable
memory.  Writable globals remain deferred until an explicit writable-data section
and loader mapping are specified; AOM v1 in Phase 10.3 does not add them merely by
introducing an object container.

Stage-2 diagnostics extend the stable Stage-1 set:

```text
9   type/object mismatch
10  declaration/tag/alias error
11  prototype/definition signature mismatch
12  direct ABI limit / aggregate-by-value rejection
13  layout/extent/frame bound violation
14  mutable file-scope data unsupported by direct backend
```

Formal gate: 23/23 positive Kleis examples, 0/14 hostile examples accepted, no
new axioms.  The complete runtime suite is also closed at 944/944.

The Stage-2 source is constrained by CC_B while it bootstraps its successor.
CC_B has one flat local-symbol scope per function, so Stage-2 bootstrap source
must not redeclare the same local name in disjoint C blocks even though AC2
itself may later support ordinary nested scopes.  The first runtime attempt
exposed exactly this boundary in `primary`, `unary`, and `topitem`; those locals
now have unique bootstrap names.

`ankacc2_stage2.c` is intentionally formatted as compact multiline C rather
than as one minified line or conventionally indented source.  Conventional
pretty-printing would exceed CC_B's 20,472-byte source arena.  The compact form
keeps statements readable while remaining a valid bootstrap input.

## Phase 10.2 closure

Phase 10.2 is closed with the complete regression suite green:

```text
944 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The corresponding formal refinement remains 23/23 positive with 0/14 hostile
witnesses accepted and no new axioms.

## Phase 10.3: AnkaCC2 stage 3 / AOM v1

`ankacc2_stage3.c` remains a real Anka userspace compiler source accepted by
CC_B, but it no longer emits the direct executable format.  Its compile-only
output is **AOM v1**, a sealed relocatable object module.

AOM v1 uses this fixed byte geometry:

```text
header             112 bytes
function symbol    160 bytes
relocation          48 bytes
code alignment       8 bytes
CALL_PC20 width       8 bytes
```

The header magic is `ANKAOM1\0`, version 1.  Code begins at byte 112.  The
format reserves an optional read-only-data section; Stage 3 currently emits no
rodata and continues to reject mutable file-scope data.

A Stage-3 translation unit does **not** require `main`.  Function definitions
are strong code exports.  A called prototype with no same-module definition is
a required import.  Uncalled prototypes are omitted.  Calls to later
same-module definitions are patched locally; calls that remain external become
8-byte `CALL_PC20` relocations against the import symbol.

AOM function records preserve return and parameter type metadata.  Phase 10.3
only publishes signatures whose identity is stable across translation units:
`int`, `char`, `void` return, and pointer chains rooted in those scalar types.
Raw translation-unit-local struct-tag indices are not exported as public type
identity; attempting to do so is diagnostic 16.

Stage 3 adds:

```text
15  AOM module cannot be published (for example, empty code section)
16  public AOM signature uses translation-unit-local/nonportable type identity
```

AOM emission remains compile-only:

```text
valid AOM != linked executable != execution authority
```

The Rust development harness contains an AOM parser/structural validator, but it
does not resolve imports or apply relocations.  Those operations first belong
to Phase 10.4 `ankald`.

The Stage-3 bootstrap source is deliberately close to the CC_B envelope:
20,416/20,472 source bytes, 64/64 bootstrap functions, at most four parameters,
17/32 flat symbols in a function, no duplicate flat locals, and approximately
383/512 call sites.  This is only a preflight check; CC_B actually building the
compiler is the runtime authority for closure.

Formal gate: 22/22 positive Kleis examples, 0/15 hostile examples accepted, no
new axioms.  Eleven `p103_` runtime witnesses are added on top of the 944-test
baseline; a fully green branch should therefore report 955 tests.  Phase 10.3
remains open until that Cargo result is observed.

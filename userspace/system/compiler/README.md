# Anka64 guest toolchain

These are executable Anka64 userspace tools. The host transports and validates
artifacts; it does not replace guest C preprocessing, compilation or linking.

| Source | Current role |
|---|---|
| `ankacc2_stage1.c` | Preserved Phase 10.1 bootstrap checkpoint |
| `ankacc2_stage2.c` | Preserved Phase 10.2 declarations/type/ABI checkpoint |
| `ankacc2_stage3.c` | Accepted self-hosting compiler lineage and AOM producer |
| `ankacc2_abi2.c` | Protected producer with admitted source/workspace/output regions and checked growth replies |
| `ankapp.c` | Explicit-bundle, include-only guest preprocessor |
| `ankald.c` | Guest static linker, including protected frame and typed-module evidence |

## Lineage and ordinary invocation

Phase 10.6 established the concrete `CC2_0 → CC2_1 → CC2_2` fixed-point witness.
The protected ABI-2 producer is built from the accepted lineage; it is not itself
asserted byte-identical to the legacy compiler. `ankapp` and `ankald` retain their
explicit bootstrap/tool bindings. The old Stage 1/2 grammar and resource limits
are historical checkpoints, not the current protected language specification.

```sh
cargo run --release -- rebuild --include shared.h --run main.c helper.c
```

The service freezes source/tool/plan provenance before execution. Checked output
and workspace retries retain source identity and cumulative work, wait for actual
cleanup and admit a fresh producer. Successful compilation yields an exact,
READ-only relocatable artifact/receipt; guest linking and separately authorized
execution follow. A failed attempt cannot overwrite an earlier publication.

The ordinary coordinator supports two independent active jobs. Its acceptance
passed with A exhausted, B still correct, C reusing released backing, and stale A
aliases rejected. The command currently compiles module roots sequentially and
links in argument order. It accepts up to eight roots and 256 bundle members;
canonical bundle size is at most 1 MiB. These and the finite work/quota limits
are stated service policies. Resource growth is checked, not unlimited.

## Supported language and module boundary

The current protected subset includes functions/prototypes, scalar types,
protected pointers, fixed local arrays, supported structs and member operations,
forward/self/mutual struct-pointer declarations, typed byte I/O and supported
`malloc/free`. Protected pointer pairs carry authenticated kind/lifetime state;
integer bit patterns cannot mint them. Frame and heap retirement reject stale
aliases. No host-native C ABI is assumed.

Separate protected modules carry complete/opaque type evidence. Compatible
struct-pointer interfaces can link; conflicting definitions/signatures reject.
Module-local numeric tag indices are not cross-module type identity. By-value
recursive/incomplete layouts remain invalid. This is a C subset, not a claim of
full ISO C, a GCC-compatible object format, aggregate-by-value ABI, arbitrary
mutable globals or a complete libc. Consult current compiler code and DN-71 for
profile-specific limits instead of extrapolating Stage 1/2 limits.

The [compatibility backlog](../../../DESIGN_NOTES.md#toolchain-compatibility-backlog)
tracks six open gaps: comments, short-circuit `&&`/`||`, source-order-independent
`main`, array subscripting expressions, unary minus, and `>`/`>=`. Fixed array
declarations do not imply subscripting support. Current probes use pointer
arithmetic, `(0-2)` and reversed `<` comparisons; these workarounds are not
implementation of the missing language features.

## Source bundles and preprocessing

`ankapp` supports exact quoted inclusion from an explicit immutable bundle.
There is no ambient `-I` search, host fallback, macro expansion, conditional
preprocessing, token pasting or stringizing. Active include cycles and depth
beyond 32 reject. The CLI names members by basename; the source-bundle API can
supply other exact logical names. Missing includes fail before compilation.

Preprocessor codes retain these meanings:

| Code | Meaning |
|---|---|
| 1 | Invalid manifest/root |
| 2 | Missing include target |
| 3 | Duplicate/ambiguous target |
| 4 | Active include cycle |
| 5 | Include-depth bound |
| 6 | Unsupported directive/profile |
| 7 | Output capacity exhausted; retry only after validated normal completion |
| 8 | Malformed include directive |

Source growth beyond 64 KiB and real preprocessor capacity retry are accepted.
The original fixed `SOURCE_SIZE - 8` transport remains a legacy entry point; it
is not the ordinary protected service's universal source limit.

## AOM, linking and authority

AOM v1's base geometry remains a 112-byte header, 160-byte function symbols,
48-byte relocations and eight-byte code alignment. Protected/typed profiles add
validated frame and type evidence. Unsupported profile mixing and malformed
metadata reject before execution. Current emitters can carry literal data;
mutable data is not silently placed into executable storage.

Guest `ankald` resolves ordered inputs and applies validated relocations. The
host validates exact output and publishes its receipt; it does not substitute a
host linker. Publication is READ-only. Code loading and C startup require
separate execution authority and the charged isolated-run profile.

## Acceptance and current persistence work

Phase 10.8 C2–C5 and the protected network-service rebuild are closed within their
stated profiles. The final evidence is in [DN-71](../../../DESIGN_NOTES.md#phase-108-final-evidence).
Latest supplied CC2 lineage in the guest-upload witness: CC2_0 is 168840 bytes;
CC2_1 and CC2_2 are byte-identical at 191576 bytes, entry 188888. These are lineage
artifacts, not the separately compiled protected producer image.

The accepted GA110 witness compiles a target C program and the uploader once,
exports the current linked receipt's canonical reference envelope, and sends the
actual target store all 11984 bytes through guest typed I/O, the virtual NIC and
real guarded TCP. It verifies the file bytes and recovers the original publication
after reply loss. This is focused acceptance, not a full-regression result or
stored-image execution. The host coordinates requests and supplies trusted test
evidence; no host C compilation/linking replaces guest tool execution.

```bash
bash scripts/check-anka110-guest-artifact.sh --real
```

Use focused checks during development. Ignored real witnesses must be selected
explicitly; do not count filtered or ignored tests as passes. Retrieval, validation
and live launch from persistent storage are the next milestone under
[DN-72](../../../DESIGN_NOTES.md#guest-artifact-upload), followed by independent reboot
acceptance. Existing rebuild and HTTP scripts remain regression entry points.

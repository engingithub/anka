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

## Acceptance and remaining closure

Latest ordinary-service evidence: Kleis **29 positive / 21 hostile**, six focused
tests, **154 runtime tests with ten ignored**, and the explicit real concurrent
compiler test **75.79s**. These overlapping groups are not a complete regression
run. The new HTTP/input packet is pending its own Rust acceptance.

```sh
bash scripts/check-anka108-rebuild-service.sh --real
bash scripts/check-anka108-http-application.sh --real
```

Use focused checks during development; run required ignored real witnesses
explicitly and the complete single-threaded regression at the final checkpoint.
Phase 10.8 still requires protected socket/NIC integration and the end-to-end
service rebuild. [DN-71](../../../DESIGN_NOTES.md#dn-71) is the authoritative
closure checklist; historical test totals in older notes do not close this gate.

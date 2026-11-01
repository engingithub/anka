# Anka64 userspace source tree

This directory is a host-side source mirror, not a filesystem mounted into the
guest. Host paths, logical source names and runtime `(ObjectId, Generation)`
identities are distinct. A pathname never grants authority.

| Directory | Purpose |
|---|---|
| `system/compiler/` | Guest preprocessing, CC2 compilation and static linking |
| `system/services/` | Operating services, including the implemented network stack |
| `bin/` | User programs and explicit compiler/runtime acceptance probes |
| `include/` | Header source supplied as explicit source-bundle members |
| `lib/` | Reserved guest-library location; no complete libc is installed |
| `etc/` | Reserved configuration payload location |

## Protected rebuild path

From the repository root:

```sh
cargo run --release -- rebuild --run userspace/bin/protected_pointer_probe.c
```

The command builds accepted tool lineage once, runs guest preprocessing and the
protected ABI-2 compiler, retries admitted resource growth, publishes exact AOM,
guest-links and optionally executes a current linked receipt. Compilation,
publication and execution are distinct authority decisions. This is the current
protected path; it is not full ISO C or a Unix ABI.

`--include FILE` adds an explicit bundle member. The CLI uses **exact basenames**
for lookup, including the operands of `#include`; it does not search host include
directories. `--input FILE --run` provides an explicitly authorized bounded input
image to the spawned child. No input or NIC authority is inherited by name.

The latest ordinary-service acceptance includes actual concurrent compiler jobs,
A exhaustion, C reuse, stale-alias rejection and unaffected B (75.79s). The new
protected HTTP application/input packet still requires its own local acceptance.
See [the root README](../README.md) and [DN-71](../DESIGN_NOTES.md#dn-71).

## Legacy development monitor

`anka dev` remains the Phase 9 development monitor. Its CC_B bootstrap compile
route and logical-install-path mapping are separate from `anka rebuild`:

```text
anka64> compile bin/hello.c
anka64> run /bin/hello
```

The original network services use explicit legacy mappings, device capabilities
and IPC. They are implemented software, but their original CC_B tests do not
certify their rebuild as protected CC2 applications. Preserve both boundaries
until the socket/NIC migration is accepted.

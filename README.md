# Anka64

**A computer architecture built around explicit authority, an inspectable
toolchain, and executable security contracts.**

Anka64 is a custom 64-bit architecture with a Rust reference implementation,
an authority-enforcing memory fabric, an operating-system runtime, a network
stack, and a self-hosting C-subset toolchain. It is a serious systems engineering
project aimed at a deployable secure computing platform, with server and
data-center workloads as a long-term objective.

## Why Anka64 matters

The project's hypothesis is that inherited complexity can be removed rather
than carried indefinitely into the next system. A coherent architecture may
offer a smaller base to understand and verify, with less unnecessary overhead.
Those security and efficiency goals must be earned through implementation,
formal reasoning, and measurement.

Anka64 makes that hypothesis concrete at three connected boundaries:

- **Memory and execution:** knowing an address does not grant access. Object
  identity, authority, and physical placement are separate. Protected pointers
  carry metadata and lifetime information; copying integer bits cannot create
  pointer authority.
- **Processes and devices:** CPU, driver, and DMA operations are subject to
  explicit authority. Delegation can narrow permissions, and revocation must
  prevent stale authority from authorizing later transactions.
- **The software supply chain:** source bundles, guest compilation, linking,
  artifact publication, and execution have distinct contracts. Producing bytes
  does not grant permission to execute them. The rebuild path records the exact
  sources, tools, dependencies, and artifact identity it used.

The value sought is a system whose security boundaries can be stated and
examined across the whole stack. Novelty for its own sake is not the goal.

## A working implementation with demanding clients

The compiler, operating-system services, network stack, and hostile programs
exercise the architecture as real clients. Each new layer has exposed defects
and forced the abstractions beneath it to become more precise.

| Area | Implemented evidence |
|---|---|
| Machine and fabric | Custom ISA, protected object transactions, generation-qualified authority, placement management, modeled multicore and DMA agents |
| Operating environment | Process creation and supervision, IPC, protected calls/returns and event contexts, capability-mediated device operations |
| Networking | Ethernet, ARP, IPv4/ICMP, UDP, TCP, sockets, and an HTTP service that has demonstrated the original CPU-to-HTTP `/alive` path |
| Toolchain | Guest preprocessing, AOM object emission, guest static linking, and a concrete `CC2_0 → CC2_1 → CC2_2` byte-identical fixed point |
| Protected applications | Typed byte/word access, checked pointer arithmetic, local-frame lifetimes, protected calls and spills, typed console input/output |
| Protected allocation | Shared allocation/free service, supported C `malloc/free`, initialized heap/local storage, cleanup and independent-client reuse with stale-alias rejection |
| Compiler resources | Charged source/tool custody, protected ABI-2 producer, bounded output retry, retained artifacts and atomic publication; described workspace tables exercised by real guest CC2 |
| Module composition | Separately compiled protected C modules, merged frame metadata, ordered dependency receipts, publication and ordinary process execution |
| Formal development | Kleis/Z3 contracts, positive witnesses, and deliberately false claims that must be explicitly disproved |

The original MC68000 implementation remains in the repository as the project's
experimental foundation. Active architecture and toolchain development targets
Anka64.

## Current checkpoint — Phase 10.8

Phase 10.6 self-hosting and Phase 10.7 protected local applications are complete.
Phase 10.8 has accepted typed I/O, protected module composition, C `malloc/free`,
independent-client allocation/reuse and compiler artifact publication. The
required post-malloc whole-stack review is recorded in
[DESIGN_NOTES.md, DN-71](DESIGN_NOTES.md#dn-71).

| Closure area | Verified progress |
|---|---|
| C2 resources | Shared allocation, charged preprocessing/admission/link/run, retained provenance, checked retries and actual cleanup |
| C3 language/growth | Source beyond 64 KiB, table growth, recursive declarations, typed heap lists, automatic directory retry with exact AOM parity |
| C4 linking/execution | Typed guest linking, persistent receipts, large-image load, explicit C startup and separately charged execution |
| C5 ordinary service | Normal rebuild coordinator, actual concurrent compiler jobs, A exhaustion, C reuse, unaffected B and stale-alias rejection |

Latest supplied ordinary-service evidence: **6 focused tests**, **154 runtime
tests with 10 ignored**, and the explicit real concurrent test in **75.79s**.
The associated Kleis gate passed **29 positive / 21 explicitly disproved hostile
witnesses**. These groups overlap and are not a fresh complete regression run.
The last full-suite result supplied in this development history was 1,406 tests
in 589.71s, before the subsequent compiler-service changes.

**Implemented; real guest acceptance pending:** `httpd_protected.c` rebuilds the `/alive` HTTP
application with protected byte pointers, typed input/output and private request
storage. The ordinary command now accepts `--input FILE --run`; input authority,
copy accounting and cleanup are explicit. The new gate passes **27 positive /
18 hostile witnesses**. A native diagnostic checks response bytes and boundaries;
it does not substitute for guest acceptance. The latest log passed nine focused tests and 160
compiler-runtime tests. The first real HTTP compile hit pointer-registry
exhaustion. The larger charged frame budget passed focused checks, but the
next HTTP run reached its 1200-second diagnostic timeout. The current patch
removes a full reserved-heap-table scan from ordinary address translation and
adds authenticated source-cursor diagnostics. Real HTTP acceptance is pending;
no new complete regression pass is claimed.

**Phase 10.8 remains open.** The next closure evidence is the protected HTTP
application run, followed by actual socket/NIC integration and the end-to-end
service rebuild, then final regressions. The original network stack already
responds to `/alive`, but its CC_B/shared-buffer execution is not silently
reclassified as the new protected rebuild. No additional project phase is added.

## Build and explore

Use a Rust toolchain supporting edition 2024 and Cargo. From the repository root:

```sh
cargo build --release
./target/release/anka dev
```

Inside the development shell:

```text
help
compile bin/hello.c
run /bin/hello
```

The shell's basic compile path lazily bootstraps CC_B. The CC2 rebuild and
protected-module path has separate acceptance tests; a shell hello program is
not its completion gate. See [the userspace guide](userspace/README.md).

The ordinary protected path is available separately:

```sh
cargo run --release -- rebuild --include shared.h --run main.c helper.c
```

For the current HTTP application packet:

```sh
bash scripts/check-anka108-http-application.sh --real
```

That script runs focused formal/runtime checks and the explicit real guest HTTP
witness. Long real witnesses are deliberately ignored by the ordinary test
runner and must be selected explicitly. At the final integration checkpoint:

```sh
bash scripts/check-anka108-closure.sh --real
cargo test --release -- --test-threads=1
```

Formal gates require Python 3, Kleis with Z3 support, and the matching standard
library. Override `KLEIS_BIN` and `KLEIS_ROOT` for the scripts, or run one gate:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root /path/to/kleis \
  --only-http-application
```

The root must contain `stdlib/prelude.kleis`. Hostile gates succeed on explicit
disproofs; errors, unknown results, and timeouts do not count as proofs.

## Read the architecture and work on it

| Location | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architectural rules, trust boundaries, implementation facts, and roadmap |
| [DESIGN_NOTES.md](DESIGN_NOTES.md) | Decisions, alternatives, acceptance evidence, and deferred work |
| [src/anka64/](src/anka64/) | Rust machine, fabric, operating environment, toolchain adapters, and tests |
| [userspace/](userspace/) | Guest compilers, services, headers, and application sources |
| [theories/](theories/) | Executable Kleis contracts and hostile witnesses |
| [scripts/](scripts/) | Formal gate runners and development build helpers |

Development is **formal-first**: specify the architectural contract and hostile
witnesses, pass the relevant Kleis gates, implement a bounded piece, then demand
concrete execution evidence. A fixed point proves reproducible bootstrap
closure; it does not by itself prove every compiler transformation correct.

The current reference runtime depends on a trusted host. FPGA realization
and an Apple Silicon/Metal execution prototype are planned directions, not
implemented backends. They require refinement against the reference machine,
including authority, synchronization, memory ordering and observable timing.
The active closure work remains the software rebuild milestone.

## License

Anka, including Anka64, is available under the [non-commercial license](LICENSE).
Non-commercial use, modification and redistribution are permitted subject to
its terms. Commercial use requires prior written permission from Engin Atik;
contact **atik@kleis.io**. Third-party components retain their own licenses.

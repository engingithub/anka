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
| Durable compiler artifacts | Receipt-bound export and CC2 guest upload through the virtual NIC to a host-file store, including lost-reply recovery, charged retrieval and fresh live/restart launch |
| Formal development | Kleis/Z3 contracts, positive witnesses, and deliberately false claims that must be explicitly disproved |

The original MC68000 implementation remains in the repository as the project's
experimental foundation. Active architecture and toolchain development targets
Anka64.

## Current checkpoint — stored restart and SC110 accepted

**Phase 10.8 is closed and merged. Phases 10.9 and 10.10 remain open.**
The protected service stack serves `/alive` through the virtual NIC. CC2 guests
upload and retrieve actual linked images through typed sockets, NIC DMA, guarded
localhost TCP and a durable host-file store. Fresh execute admission runs the
stored target both live and after independent bounded guest/service restarts.

| Evidence | Accepted scope |
|---|---|
| Phase 10.8 closure | Protected allocation/free, compiler jobs, typed modules, charged linking/execution and rebuilt network services; historical final evidence is retained in DN-71 |
| Artifact upload (GA110) | 44 positive / 36 hostile Kleis witnesses; 7 quick tests and real CC2 upload/recovery witness (85.09s), including an 11,984-byte envelope in three chunks and exact lost-reply recovery |
| Stored retrieval and read transport (SR110 R1 / AR110) | SR110 92 positive / 78 hostile, 20 focused Rust cases; AR110 117 positive / 98 hostile, 23 focused read cases plus 24 upload compatibility cases |
| Guest download and live launch (GD110 / SR110 R2) | GD110 174 positive / 149 hostile; 11 focused live-admission cases and real download/live-launch witness (84.35s), target exit 42; merged to main on 2026-11-18 |
| Independent restart (RR110) | 234 positive / 192 explicitly disproved hostile witnesses; 14 focused cases passed in 4.21s; separately selected real restart witness passed in 92.13s |
| Latest full release library suite | **1,964 passed, 0 failed, 20 ignored, 0 measured, 0 filtered out in 267.06s**, verified in the developer Mac SC110 acceptance log on 2026-11-22 |

RR110 persists the download pump A and target B, destroys the original compiler
and lineage, and reconstructs a fresh accounted guest under current boot
authority. The real witness covers service-only, guest-only and combined restarts,
then retrieves and runs B to exit 42 without recompilation. It checks stale
channels, revocation at launch commit, unchanged retained bytes/boot selection
and preservation of the same peer charge/state across a service-only restart.
The ignored real witness has its own passing result; the ordinary full suite
does not execute it or the other ignored tests. Overlapping groups are not added.

**Integration status:** the developer confirmed RR110 merged to `main`, followed
by the roadmap documentation merge. Profiling and SC110 are validated on the laptop,
but remain local, uncommitted changes on `main` in the supplied git status.
The original and SC110 comparison sessions have been reviewed; see
[accepted measurements and limitations](PERFORMANCE.md#sc110-accepted-results).

The runtime consumes trusted evidence; test providers are deterministic fixtures.
External nonrollback freshness, production credential verification, general
installation/enrollment and whole-machine reboot integration remain open.
This does not provide general guest file CRUD, arbitrary process migration,
concurrent peer application progress or a standalone deployed storage server.
The [SC110 scalar payload contract](DESIGN_NOTES.md#scalar-read-contract) passes
on the developer Mac: 146 positive witnesses and 146/146 hostile assertions
explicitly disproved. **Rust correctness and the measured laptop improvement are
accepted.** CPU fetches, ordinary scalar loads and protected-local
scalar reads keep inline committed snapshots through the existing Fabric checks.
Bulk/asynchronous reads and private heap-pointer access keep their general paths.
All 15 focused tests passed. Reproduce the full/real acceptance on the laptop:

```bash
bash scripts/check-anka110-scalar-read.sh --real
```

The script runs focused tests, the full release library suite, and separately
selects the ignored real CC2 guest-download, stored-launch and RR110 restart
witnesses; all three passed separately (70.30 s, 69.50 s and 69.53 s). The 20 ignored
tests in the ordinary suite are not all claimed as executed. Median unprofiled
rebuild time fell **72.93 → 58.49 s (19.8%)**, and the complete restart workload
fell **85.05 → 70.11 s (17.6%)**, over three runs per workload and build. These
are emulator measurements on one laptop, not isolated restart latency or FPGA
speedup. Preserve both [profiling sessions](PERFORMANCE.md#sc110-accepted-results).

After this checkpoint is committed and merged, the next planned task is the
Keycloak trusted-adapter contract and Kleis gates, followed by minimal CLI
integration. Enrollment and external boot-attempt consumption remain separate
planned work; further optimization is not a prerequisite.

Reproduce the restart acceptance from the repository root:

```bash
python3 scripts/check-anka109-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root "$HOME/git/cee/kleis" --only-stored-restart
bash scripts/check-anka110-stored-restart.sh --real
cargo test --release --lib -- --test-threads=1
```

The restart script checks test discovery, runs the focused RR110/T2 and existing
live-launch/download/read/upload/retrieval regressions, then selects the real
restart witness. Omitting `--real` skips that costly witness. The GD110 deadline
test now constructs under a live budget and explicitly expires it using the
existing test-only hook, avoiding a one-nanosecond constructor race. Production
deadline checks and the number of tests are unchanged.

Individual gates remain available as `check-anka110-guest-artifact.sh`,
`check-anka110-artifact-read.sh`, `check-anka110-guest-download.sh`,
`check-anka110-stored-retrieval.sh` and `check-anka110-stored-live-launch.sh` in
`scripts/`. Use `--real` for the guest upload, download and live-launch witnesses.
The formal runner also accepts `--only-guest-artifact`, `--only-stored-retrieval`,
`--only-artifact-read` and `--only-guest-download`.

See [DN-72 current status](DESIGN_NOTES.md#dn72-status),
[RR110 acceptance](DESIGN_NOTES.md#stored-restart-runtime) and the
[compiler compatibility backlog](DESIGN_NOTES.md#toolchain-compatibility-backlog).
The legacy CC_B/shared-buffer network stack remains a protocol regression oracle;
its retention does not reopen Phase 10.8. Podman deployment with persistent host
files, S3/Ceph adapters and Metal execution remain later work.

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

For the accepted finite-input HTTP application witness:

```sh
bash scripts/check-anka108-http-application.sh --real
```

That script runs focused formal/runtime checks and the explicit real guest HTTP
witness. Long real witnesses are deliberately ignored by the ordinary test
runner and must be selected explicitly. To reproduce the historical Phase 10.8
closure gate (distinct from the RR110 commands above):

```sh
bash scripts/check-anka108-closure.sh --final
```

The final command checks the formal prerequisites, runs the ordinary release
suite serially, and discovers and executes the ignored guest witnesses. Each
successful ignored witness has a log under `target/anka108-closure/`; rerunning
the command can reuse it for the same compiled test binary and inputs. The
older `--real` mode is a focused integration check.

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

## License

Anka, including Anka64, is available under the [non-commercial license](LICENSE).
Non-commercial use, modification and redistribution are permitted subject to
its terms. Commercial use requires prior written permission from Engin Atik;
contact **atik@kleis.io**. Third-party components retain their own licenses.


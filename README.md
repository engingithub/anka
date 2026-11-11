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

## Current checkpoint — Phase 10.8 complete; 10.9–10.10 in progress

**Phase 10.8 is complete.** The protected network-service rebuild serves `/alive`
through the virtual NIC. Current progress separates three kinds of evidence:

| Evidence level | Current status |
|---|---|
| Integrated runtime features | Phase 10.8 protected network-service rebuild and `/alive` through the virtual NIC |
| Formal contracts | Phase 10.9 Kleis formalizations for recognition, enrollment, grant admission, persistence and reboot |
| Implemented reference mechanisms | Phase 10.10 persistence backend, codec, loopback server/client and evidence registry and E6 guarded loopback server; 135 persistence reference tests passed |

The [E5 guarded transport contract](DESIGN_NOTES.md#dn72-guarded-transport)
passed 21 positive witnesses and explicitly disproved all 16 hostile witnesses.
E6 passed on the developer machine: **135 reference tests passed, 0 failed,
0 ignored, in 0.76s**. The server rechecks authority before writing each reply
fragment. Its tests supply peer evidence through a trusted binder. Validating
credentials on a real connection and integrating enrollment and reboot remain open.

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
**Protected HTTP application accepted (user-reported, 2026-11-01):**
`httpd_protected.c` now compiles, links and runs through the ordinary rebuild
service with private request storage and typed input/output. The HTTP Kleis gate
passes **34 positive / 21 hostile witnesses**. This is finite-input application
acceptance, not socket/NIC acceptance.

**Last complete regression before typed sockets:** 1,614 passed, 0 failed,
12 ignored in 289.36 seconds. Both the monitor bootstrap and typed AOM
regressions passed individually as well. Ignored real gates are run separately.

**Phase 10.8 network-service evidence:** The typed socket kernel path passed its five focused Rust tests.
The real CC2 socket HTTP witness passed in 92.83 seconds: the client kept the
stream open and received the exact reply under backpressure. The real Ethernet/ARP/IPv4/ICMP NIC gate also passed (83.16 seconds).
The rebuilt bounded `/alive` path passed on the virtual NIC in **124.61s**:
protected TCP delivered the split request and transmitted the protected HTTP
reply before peer FIN. The legacy UDP oracle passed in 1.02s. In a single
85.25s release witness the protected guest passed 17 UDP and 10 Ethernet/ARP/
IPv4/ICMP cases, checking committed wire bytes, drops, receipts and refunds.
Phase 10.8 final release verification is complete.
The legacy CC_B/shared-buffer stack remains the protocol reference. DN-71 also
tracks future logical-operator support and source-order-independent C entry.

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

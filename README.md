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
| Durable compiler artifacts | Receipt-bound export and CC2 guest upload through the virtual NIC to a host-file store, including lost-reply recovery; retrieval/live launch pending |
| Formal development | Kleis/Z3 contracts, positive witnesses, and deliberately false claims that must be explicitly disproved |

The original MC68000 implementation remains in the repository as the project's
experimental foundation. Active architecture and toolchain development targets
Anka64.

## Current checkpoint — artifact read accepted

**Phase 10.8 is closed and merged. Phases 10.9 and 10.10 remain open.**
The protected service stack serves `/alive` through the virtual NIC. A CC2-compiled
guest can now upload actual linked compiler output through typed sockets, NIC DMA,
guarded localhost TCP and a durable host-file artifact store.

| Evidence | Accepted scope |
|---|---|
| Phase 10.8 closure | Protected allocation/free, post-malloc whole-stack review, concurrent compiler jobs, typed modules, charged linking/execution and rebuilt network services; historical final verification: 1,628 ordinary tests, 15 explicit guest witnesses and 48 Kleis pairs |
| Authority and persistence | T1/T2 formal contracts, evidence admission/verifier adapters, durable records and bounded transport; production credentials and Kernel enrollment/reboot integration remain open |
| Host artifact storage | Receipt-bound compiler export, bounded upload protocol and guarded TCP/file transport; last standalone persistence reference result: 206 passed, with 12 focused AG110 tests included |
| Guest artifact upload (GA110) | Latest supplied log: 44 positive / 36 hostile explicitly disproved; 7 quick tests passed in 0.10s; real CC2 upload/recovery witness passed in 85.09s |

The real witness transfers an **11,984-byte canonical linked-image envelope** in
three Append chunks (4,096 + 4,096 + 3,792 bytes), alternates 64/1,024-byte queues,
and recovers publication revision 8 after deliberate reply loss and service/file
reopen. The compiled guest performs the typed I/O; a trusted test coordinator
supplies bounded requests and deterministic authority/dependency evidence.
This does not yet provide a standalone external storage deployment or guest
filesystem. Stored bytes do not grant execution authority.

The supporting `g110_` filter passed 21 tests with one ignored in 0.48s; it also
matches AG110 tests, so overlapping groups must not be added. The latest supplied
whole-suite result remains the earlier **1,795 passed, 16 ignored in 296.54s**.
No complete regression for the current upload revision is claimed. The current
focused build reports 20 nonfatal dead-code warnings.

**Next milestone:** retrieve and validate a stored image and its dependencies,
reconstruct fresh runtime objects, and launch under current execution authority
without restarting Anka64. Separate guest/service reboot acceptance follows.
The stored-launch Kleis gate (49 positive / 56 hostile) is a foundation; extend
affected retrieval/transport/admission contracts before implementing new behavior.
The [SR110 retrieval/admission refinement](DESIGN_NOTES.md#stored-retrieval-launch)
now passes 92 positive witnesses and 78 explicit hostile disproofs. The first
Rust slice implements charged private file retrieval and exact envelope decoding;
its 20 focused tests passed on macOS in **7.20s**. Run
`bash scripts/check-anka110-stored-retrieval.sh`. The next network read contract,
[AR110](DESIGN_NOTES.md#artifact-read-protocol), passes **117 positive / 98 hostile**
Kleis witnesses. Its Rust codec, bounded client exchange and guarded TCP read
path now have local acceptance: **23 focused + 24 upload-compatibility tests
passed** (`bash scripts/check-anka110-artifact-read.sh`, 2026-11-18). The next
[GD110 guest-download contract](DESIGN_NOTES.md#guest-artifact-download) passes
**174 positive / 149 explicitly disproved hostile witnesses** with Kleis/Z3.
It specifies charged typed I/O, contiguous multi-range assembly, bounded retries,
cleanup and private envelope validation. GD110 guest-runtime integration and
SR110 R2 fresh live admission are implemented, with laptop validation pending.
The repaired source includes the complete download prerequisites; see
`GD110_SR110_REPAIR.md`. Run
`bash scripts/check-anka110-stored-live-launch.sh --real` to validate the real
CC2/typed-socket/NIC/file/live-launch path. Reboot execution remains pending.
Select the gates with
`--only-stored-retrieval`, `--only-artifact-read` or `--only-guest-download` in
`scripts/check-anka109-gates.py`.
Podman with persistent host files, S3/Ceph adapters and Metal execution are later
work, not prerequisites for the accepted file-backed upload.

Reproduce the upload acceptance from the repository root:

```bash
python3 scripts/check-anka109-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root "$HOME/git/cee/kleis" --only-guest-artifact &&
bash scripts/check-anka110-guest-artifact.sh --real
```

The script runs quick checks before one explicit CC2 witness. See
[DN-72 current status](DESIGN_NOTES.md#dn72-status),
[GA110 evidence](DESIGN_NOTES.md#guest-artifact-upload) and the
[compiler compatibility backlog](DESIGN_NOTES.md#toolchain-compatibility-backlog).
The legacy CC_B/shared-buffer network stack remains a protocol regression oracle;
its retention does not reopen Phase 10.8.

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


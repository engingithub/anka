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

**Phase 10.8 is closed and merged. Within Phases 10.9–10.10, bounded artifact
persistence, guest download, stored launch, independent restart and the SC110
performance checkpoint are accepted and merged. The broader phases remain open
pending production identity, enrollment, boot and deployment integration.**
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
| SC110 full release library suite (historical) | **1,964 passed, 0 failed, 20 ignored** in 267.06s, verified in the developer Mac SC110 acceptance log on 2026-11-22 |
| Latest full release library suite (LG110 checkpoint) | **2,050 passed, 0 failed, 20 ignored** in 267.41s, verified in the developer laptop log on 2026-11-24; runtime merged to main (user confirmation, 2026-11-27) |

RR110 persists the download pump A and target B, destroys the original compiler
and lineage, and reconstructs a fresh accounted guest under current boot
authority. The real witness covers service-only, guest-only and combined restarts,
then retrieves and runs B to exit 42 without recompilation. It checks stale
channels, revocation at launch commit, unchanged retained bytes/boot selection
and preservation of the same peer charge/state across a service-only restart.
The ignored real witness has its own passing result; the ordinary full suite
does not execute it or the other ignored tests. Overlapping groups are not added.

**Integration status:** the developer confirmed RR110 merged to `main`, followed
by the roadmap documentation merge. The developer has also confirmed the
profiling harness and SC110 checkpoint merged to `main`.
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

The **KC110 Keycloak preflight milestone is accepted and merged to `main`**
(user confirmation, 2026-11-23): **201 positive / 201 hostile Kleis witnesses,
40 Python checks, a successful Rust binary build, and all 14 real Keycloak lab
acceptance cases**. This includes certificate-bound tokens, realm-not-before
inactivity, key rotation/withdrawal, exclusive expiry, outage and persistence
across server restart. The import filename repair preserved credentials and the
database. A new full Rust suite was not reported for KC110.
See [lab setup and acceptance](scripts/keycloak/README.md).

**SA110 and AC110 are accepted and merged to main.** SA110 passed 185 positive /
185 hostile Kleis disproofs and 33/33 focused Rust tests. The
[AC110 administrative test harness](DESIGN_NOTES.md#keycloak-control-probe) passed
56/56 formal witnesses, 21 new Python checks plus 40 regressions, 15/15 focused Rust
tests and the real Podman probe. That checkpoint’s full library suite passed
**2012 tests, 0 failed, 20 ignored** (272.04s), as reported by the developer.
The probe stays closed with `current_authority: unknown`, `live_admission: false`
and `boot_authorized: false`; it does not supply runtime grants.

**Anka64 cannot control Keycloak.** The [revised plan](DESIGN_NOTES.md#external-identity-local-authority)
treats Keycloak as externally administered. Ordinary runtime uses identity evidence
and ordinary client access, with no administrator credentials or internal policy
inspection. Anka64 controls its own grants and local revocation. AC110's privileged
credentials belong only to the disposable lab test harness.

**LG110 formal gate accepted and merged:** [external identity evidence and local grants](DESIGN_NOTES.md#local-grant-contract).
The developer confirmed 264 positive witnesses and 264/264 explicit hostile
disproofs on the laptop, followed by merge to main. The pair
reuses KC110 identity/scope checks, keeps local authority distinct from remote
observations, and adds bounded issuance/refresh/revocation transitions. The gate is
included in the default formal sweep and can be selected independently:

```bash
python3 scripts/check-anka109-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root "$HOME/git/cee/kleis" \
  --only-local-grants --timeout 1800
```

**LG110 runtime accepted and merged:** the bounded local grant owner and
default-denying trusted evidence interface passed **38/38 focused Rust tests** and
**33/33 SA110 regressions** on the developer laptop. The full release library suite
passed **2050 tests, 0 failed, 20 ignored in 267.41s**. Reproduce the focused gate:

```bash
bash scripts/check-anka110-local-grants.sh
```

Ordinary client verification stays outside the local effect guard; no Keycloak
administrator credential is involved. The hosted ordinary-client evidence adapter and holder-proof encoding are now
delivered as LA110 below. The real CC2/typed-socket/NIC/file
integration remain required before live admission. The current
CLI still publishes no live or boot authority. See the
[runtime boundary](DESIGN_NOTES.md#local-grant-runtime) and
[boot dependency plan](DESIGN_NOTES.md#boot-dependency-readiness).
The existing diagnostic CLI and default-denying live source are unchanged.

To reproduce the accepted administrative lab probe:

```bash
python3 scripts/check-anka109-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root "$HOME/git/cee/kleis" --only-keycloak-control

python3 scripts/keycloak/lab.py resume --state target/keycloak-preflight-01
bash scripts/check-anka110-keycloak-control.sh --real target/keycloak-preflight-01
```

The `--real` gate compiles/tests Rust on the laptop and temporarily changes the
disposable lab realm's `notBefore`; it restores and verifies the original value
on success. Do not run other lab administration concurrently. See
[recovery and trust boundaries](scripts/keycloak/README.md#ac110-control-probe)
before retrying an interrupted probe. This administrative harness is not a runtime
dependency. Live artifact-path admission under the revised contract, enrollment
and external boot-attempt consumption remain separate gates.

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

## LA110 hosted identity adapter — accepted and merged

The ordinary-client adapter now feeds verified identity evidence into LG110 through
private bounded worker pipes. It verifies detached holder signatures over the full
local proposal, exact token and trusted channel binding. It requires no Keycloak
administrator access and does not consume diagnostic JSON as authority.

Delivery checks passed: **15 new Python tests**, **26 preflight**, **14 lab** and
**21 administrative-harness regressions**. Real local RSA/mTLS fixtures are included.
No Rust compilation or tests were run for this delivery. On the laptop:

```bash
bash scripts/check-anka110-local-adapter.sh
cargo test --release --locked --lib -- --test-threads=1
```

The new gate runs Python checks, **19 LA110 Rust tests**, then the accepted
**38 LG110 and 33 SA110** regressions. `--python-only` skips all Rust commands.
This does not run ignored guest witnesses. LT110 below supplies the first hosted transport/read-provider bridge and an
ignored real CC2/typed-socket/NIC/file mechanics witness;
live/boot admission defaults stay disabled. See [LA110 details](DESIGN_NOTES.md#local-adapter-runtime).


## LT110 hosted localhost read bridge — laptop acceptance passed

The bridge explicitly registers the local grant and exact read range, owns both
localhost TCP endpoints, separates holder signing/verification from guarded use,
and rechecks authority for socket intake, file dispatch and every reply fragment.
Independent read/content checks remain mandatory. Remote TLS storage transport is
[now planned separately](DESIGN_NOTES.md#remote-storage-tls-plan).

Laptop evidence (2026-11-28): **59 Python checks, 11 LT110 focused tests,
19 LA110, 38 LG110 and 33 SA110 regressions passed**. The ignored real CC2/socket/
NIC/TCP/file mechanics witness passed separately in **103.82s**. The full suite
now passes: **2080 passed, 0 failed, 21 ignored** in **409.66s**. The repaired
N110 fixture also passed its exact focused rerun (1/1, 0.01s). Reproduction commands:

```bash
bash scripts/check-anka110-local-bridge.sh --real
cargo test --release --locked --lib -- --test-threads=1
```

The gate includes eleven focused bridge tests, LA110/LG110/SA110 regressions and one
ignored real CC2/typed-socket/NIC/TCP/file witness. The guest witness uses private
authority fixtures; it does not prove the full deployed Keycloak credential chain.
LK110 below passed the combined real credential-chain acceptance on the laptop. See [LT110 scope and acceptance](DESIGN_NOTES.md#local-transport-runtime).


## LK110 combined Keycloak / E11 / guest-file acceptance — laptop passed

LT110 is merged. The accepted LK110 harness joins real Keycloak token and
holder verification to the retained local grant, hosted read bridge, real CC2 guest
pump and final E11 content/dependency checks. It includes ten positive and negative
cases and a separate disposable-lab driver for outage and administrative fault setup.

```bash
bash scripts/check-anka110-keycloak-bridge.sh --python-only
python3 scripts/keycloak/lab.py resume --state target/keycloak-preflight-01
bash scripts/check-anka110-keycloak-bridge.sh --real target/keycloak-preflight-01
```

**All ten real cases passed on the laptop (2026-11-28).** Recovery succeeded,
the release test executable compiled, and the driver reported `LK110 accepted`
after all cases and restoration. The same invocation passed 16 driver checks.
The prior full-suite result remains **2080 passed, 0 failed, 22 ignored**;
this focused run does not constitute a new full-suite run. Live/boot admission
remains disabled and remote TLS storage remains a separate planned task. See the
[acceptance evidence and scope](LK110_ACCEPTANCE.md#laptop-acceptance).


### LK110 laptop checkpoint and TLS repair (2026-11-28)

> Historical checkpoint, superseded by the successful ten-case laptop run below.

The laptop compiled successfully and passed **2080 tests, 0 failures, 22 ignored
in 412.20s**. LK110's ignored real credential-chain witness remains pending: both
containers run, but strict HTTPS readiness rejected the lab server certificate for
a missing Authority Key Identifier (error 85). The generator now explicitly emits
key identifiers; a server-certificate-only repair preserves CA, holder bindings,
credentials and database without weakening TLS. Five real-certificate regressions
and the existing 71 Python checks pass. No new performance result or live/boot
admission is claimed. See the TLS repair commands in
[LK110_ACCEPTANCE.md](LK110_ACCEPTANCE.md).


### LK110 delivery refresh and failure recovery (2026-11-28)

> Historical checkpoint, superseded by the successful ten-case laptop run below.

The laptop's certificate repair passed strict TLS. The subsequent real witness
completed CC2 bootstrap and initial grant issuance, then failed in its first
positive case with `storage reply refused` / `Run(SocketProvisionRejected)`.
The old log does not identify the denied predicate; it is not evidence that the
credential chain passed. A recovery journal remained from that failed attempt;
it was successfully processed before the accepted rerun.

The test embedding now refreshes the same retained grant before host EOF processing
and before ordinary virtual-NIC reply frames/FIN. This addresses the scheduling gap
between expensive signed host writes and guest delivery. Refresh uses a correlated
real observation outside the authority lanes; it does not replace the owner or
reset work, the five-second freshness bound, or the original deadline. Delivery
refresh is suppressed after an intentionally injected fault. First-denial diagnostics
report fixed stages/errors and nonsensitive counters to identify any remaining failure.

The Python driver preserves test, cleanup and restoration errors separately in a
private schema-2 report. Pipe cleanup cannot skip restoration, and a restoration
conflict retains the journal. All **80 Python checks passed** in this delivery,
including 16 driver checks; both changed Rust files passed static syntax parsing.
No Rust compilation/tests or real Podman witness were run here. The earlier laptop
full-suite result remains **2080 passed, 0 failed, 22 ignored in 412.20s**.
At this checkpoint real ten-case acceptance was pending. It subsequently passed
on the laptop; live and boot admission remain disabled.
See [the recovery and retry instructions](LK110_ACCEPTANCE.md#delivery-refresh-retry).


### LK110 real laptop acceptance passed (2026-11-28)

The uploaded terminal output confirms successful journal recovery, **16/16 driver
checks**, release compilation, and **all ten real Keycloak/CC2/E11/file cases**.
The driver printed `LK110 accepted; live and boot admission remain disabled.`
This supersedes the earlier same-day TLS and first-positive-case failure checkpoints.
No fresh full-suite or performance result is claimed, and no LK110 merge is assumed.
See [case results, evidence filename and acceptance limits](LK110_ACCEPTANCE.md#laptop-acceptance).

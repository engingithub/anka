# Anka64 laptop performance baseline

The first laptop baseline and the SC110 comparison are accepted
(2026-11-22, developer local date). Both sessions have six valid unprofiled runs
and reviewed Time Profiler exports. SC110 scalar CPU Read/Fetch payload storage
passed formal and laptop Rust acceptance. Median rebuild time fell **19.8%** and
the complete restart workload fell **17.6%**. See the
[accepted results](#sc110-accepted-results) for evidence and limits. Profiling/SC110
changes are now merged to `main`, as confirmed by the developer.

The developer also confirmed all 14 Python orchestration checks pass on macOS
after the temporary-path alias repair. Keep `target/perf-baseline-01`, its matching
binaries/debug artifacts and original logs/traces. Also preserve the separate
`target/perf-scalar-read-01` comparison session. The accepted comparison uses changed
runtime inputs and a fresh build; do not overwrite either measured session.

## Prepare on the laptop

Use Python 3.9 or newer, the repository's Rust toolchain and full Xcode selected
as the developer directory. Baselines also work on Linux; Instruments requires
macOS. Run from the repository root. These commands are for the developer to run;
the delivery has not run Cargo or any Rust tests.

```bash
# Python orchestration checks only: mocked Cargo/Xcode and tiny Python children.
python3 scripts/check-anka110-profiling.py

# Explicitly builds optimized native CLI + library-test executables.
# The session must not already exist. Keep it for all measurements below.
python3 scripts/profile-anka110.py build --session target/perf-baseline-01

# Each sample starts a fresh process and repeats the complete workload.
python3 scripts/profile-anka110.py baseline \
  --session target/perf-baseline-01 --workload rebuild --repeat 3
python3 scripts/profile-anka110.py baseline \
  --session target/perf-baseline-01 --workload restart --repeat 3
```

The build uses the new `profiling` Cargo profile: release optimization and
release runtime checks with full debug information and no requested stripping.
On macOS the helper requests packed debug information. It selects the native
Rust host target explicitly and discovers executables from Cargo JSON; it does
not guess a hashed test-binary filename. `cargo test --no-run` builds the test
binary; ignored-test discovery lists tests without running them.

Every session owns a separate Cargo target directory. Keep its executables,
object/debug files and any `.dSYM` bundles together with the checkout. Do not
rebuild into that directory while profiling. The helper records Cargo commands,
native target, selected build-environment overrides, source and executable hashes,
git revision/status, Rust versions and platform metadata. Cargo's JSON logs retain
artifact profile information. Local/global Cargo configuration and wrappers may
affect builds; inspect the recorded settings before comparing sessions. This is
not a hermetic build or supply-chain attestation.

The helper refuses incomplete sessions, a different checkout, changed executable
bytes or changed local runtime/build inputs. Input hashes cover `src`, `userspace`,
`.cargo`, the profiling fixtures, Cargo manifests/lockfile, optional `build.rs`
and the runner itself. Build a **new session** after modifying these inputs.
Documentation-only changes outside those paths do not invalidate a session.

## Workloads and success criteria

| Workload | Actual path | Successful baseline |
| --- | --- | --- |
| `rebuild` | CLI `anka rebuild --include shared.h --run main.c helper.c`, using the fixed files in `scripts/profiling/rebuild/`; CC2 provisioning/fixed point, preprocessing, two guest compilations, linking, publication and protected execution | Host CLI exit **42**, two-module link diagnostic and `Rebuild: Exited(42)`, no stdout. Exit 42 is the guest result, not failure. |
| `restart` | Exact ignored `rr110_real_cc2_independent_restart_and_stored_launch` in the library-test executable; real CC2/typed-socket/virtual-NIC/localhost-TCP/file path | Exactly one test passes, none fails or remains ignored, with the RR110 completion diagnostic. The test executable exits **0**. |

The rebuild fixture is deliberately small and fixed: it exercises two-module
composition while compilation/provisioning dominate the whole invocation. It is
not a representative sample of every application. RR110 includes initial pump and
target compilation plus initial launch, service-only restart, guest-only restart,
combined restart and hostile checks. Its total duration is **not isolated restart
or download latency**. Each invocation creates its own test stores; CPU/filesystem
caches may still be warm. No cold-cache or hardware-NIC performance claim follows.

Do not relax production deadlines, quotas, authority checks or correctness
assertions to obtain a trace. A profiler-induced deadline failure is an invalid
workload result and useful evidence of perturbation. Preserve its logs separately.

## Capture samples with Instruments

First inspect the templates actually installed on the Mac:

```bash
xcodebuild -version
xcrun xctrace list templates

python3 scripts/profile-anka110.py record \
  --session target/perf-baseline-01 --workload rebuild --template 'Time Profiler'
python3 scripts/profile-anka110.py record \
  --session target/perf-baseline-01 --workload restart --template 'Time Profiler'
```

Use `CPU Profiler` instead when available and appropriate for the installed
Xcode/macOS/hardware. Supply an installed template name or an absolute custom
template path. Capture allocations separately with an available Allocations
template; use CPU Counters for a specific hotspot after sampling. Instrument
availability and permissions vary. The helper never installs entitlements,
re-signs binaries or invokes `sudo`. If permissions block capture, inspect the
actual diagnostic. For changed signing/build settings create a fresh baseline
and session; do not silently compare different binaries.

`record` launches the native executable directly using `xctrace --launch`; it
does not sample Cargo, a build, a gate script or a Python workload wrapper.
There is no recording time limit by default. An optional `--time-limit 30s` is
for an explicitly partial investigation and may stop/truncate the workload.

**A saved trace is not an accepted run.** `xctrace` may save a trace despite
permission errors, truncation or a target failure. The helper always marks
captures for manual review, records the launcher exit code and keeps logs. A
nonzero launcher result reports a capture issue even if a trace exists; inspect
the target exit independently; do not infer a mapping from launcher status to guest exit. Review target
completion, sampling coverage, symbolization and warnings in Instruments before
using a capture. The logs from `--target-stdout -` may mix target and tool output;
their routing can differ across Xcode versions.

Open the printed `capture.trace` path in Instruments. For GUI launch instead,
use the executable/arguments from `build.json` and `result.json`, with the
repository root as working directory. Keep executable/debug artifacts available
for symbolization. If useful Rust symbols/source lines are absent, resolve that
before interpreting function-level percentages.

## Read and retain the evidence

Each uniquely named run directory has `result.json`, `stdout.log`, `stderr.log`
and, for captures, `capture.trace`. An interrupted run left as `running` is
incomplete. Baselines record wall time and child user/system CPU time; they do
not measure allocation counts or peak memory. Capture elapsed time includes
profiler startup/finalization and is labeled separately, not treated as target
runtime. Read target runtime from the trace timeline when estimating overhead.

Use [the results template](scripts/profiling/RESULTS_TEMPLATE.md) to retain all
three baseline samples, median and spread, CPU attribution and allocation
observations. Record power mode, thermal/background load and instrument settings;
`--note 'plugged in; low power disabled; idle desktop'` adds an observation to a
run. Compare matching workloads/binaries. Keep a fresh unprofiled sample after
captures if system conditions changed. Do not equate summed CPU time with latency.

Start with inclusive and self CPU costs and inspect system-library costs for
copying, allocation and I/O. Use native call stacks to identify provisioning,
compilation, retrieval, validation/admission, execution and cleanup where possible.
No phase timers or signposts have been added: if sampling cannot resolve a phase,
record it as unresolved and propose coarse opt-in markers as a separate change.
Never infer phase duration by subtracting the two unrelated workload totals.

Instruments sees host Rust/native execution. It does not automatically recover
interpreted guest C call stacks. Guest instruction/byte/metadata-operation counts
are not added by this harness; record only existing observed counts or leave them
unavailable. Laptop samples can identify redundant work, while FPGA/native CPU
cycle, bandwidth, arbitration, area and power calculations remain separate.

Keep results under `target/` or outside the repository; do not commit traces,
session binaries or archives. Traces/logs can contain local paths and source
details. For review, send the completed template, `build.json`, run JSON/logs and
relevant exported call trees or traces. Preserve full debug data locally; it need
not be included in the review ZIP.

Completion: both real workloads validate on the laptop, comparable baseline
samples and symbolized traces exist, overhead/limitations are recorded, and the
first proposed optimization is tied to observed evidence. Host-side helper
checks alone do not satisfy that boundary. Observation needs no new Kleis
contract; changes to runtime semantics require the applicable gates and Rust
regressions before acceptance.

## Reviewed first baseline and selected SC110 task

Evidence: `anka-performance-logs.zip`, `anka-time-profiler-traces.zip` and
`anka-time-profiler-exports.zip`, session `target/perf-baseline-01`. The build
manifest records source revision `dfca85e23e131206bdc264f09e0d15e11ab3cb31`
with local profiling changes; its SHA-256 is
`63039c45dc8f02e6ec9a7aa58596d3e0af3baee32ace36d69dae0a0a1a273481`.
All eight run records bind that manifest. Machine: Mac17,8, arm64, 48 GiB RAM,
macOS 27.0.1 (26A434), Xcode 27.2 (27B52), Rust 1.98.1,
`aarch64-apple-darwin` profiling binaries. AC power was reported; thermal and
background-load controls were not established by the supplied data.

| Unprofiled workload | Three wall times (seconds) | Median |
| --- | --- | --- |
| Rebuild | 72.5359, 74.8730, 72.9326 | 72.9326 s |
| RR110 restart witness | 85.0034, 85.0476, 85.3735 | 85.0476 s |

Aggregate child user+system CPU time / wall time is about 99.8% for rebuild and
99.4% for restart. These are whole workloads including compiler provisioning,
not isolated download or restart latencies. They suggest predominantly CPU work
on approximately one core, not a measured maximum throughput or FPGA cost.

| Time Profiler attribution | Rebuild | Restart |
| --- | --- | --- |
| Host allocator library self samples | 28.29% | 24.41% |
| `Fabric::execute_read`, inclusive | 39.33% | 36.58% |
| `Fabric::discard_completed_compiler_trace`, inclusive | 22.81% | 19.56% |
| `Anka64Core::step`, self | 16.74% | 15.00% |
| `ScopedPointers::free_slot`, inclusive | 0.10% | 2.84% |

Method: resolve XML ID/reference links, group by symbol and sum the supplied
sample weights. Self cost uses the leaf frame. Inclusive cost counts a symbol
at most once per stack. Rows overlap and **must not be added**. All 70,850 rebuild
and 85,320 restart samples belong to the intended target and are marked Running;
their weights sum to 70.850 s and 85.320 s. A few samples have empty stacks.
Native Rust symbols were demangled. Sampling weights are statistical attribution,
not exact function durations, allocation counts, or interpreted guest call stacks.

The trace metadata confirms rebuild `exit(42)` and restart `exit(0)`, both ending
because the target exited. Recording durations are 71.698203 s and 86.583462 s;
these are recording windows, not independent stopwatch measurements of each
phase. Rebuild's xctrace launcher returned 54 and the helper correctly retained
`capture_issue`; restart retained `review_required`. Both native bundles contain
`Data stream: Time Mapping` run issues. Their exact impact is unresolved. Retain
these caveats and the original records: the profiles support choosing a hotspot,
not a precise profiler-overhead estimate or an accepted optimization speedup.

The pre-SC110 source explains the selected cost: `Fabric::phase_commit` allocates a read
snapshot with `to_vec()`, `execute_read` clones it, and a scalar CPU fetch drops
the returned Vec while later compiler-trace collection drops the retained Vec.
Four-byte instruction fetches therefore pay for two payload allocations.
The now-accepted SC110 change keeps an inline committed scalar observation and
returns scalar bytes without a second heap payload; general and asynchronous
reads retain their existing behavior. It must not remove the transaction ledger,
consume the retained snapshot, bypass checks, or widen a one-byte physical read.
Inline storage may enlarge each transaction record; account and measure that
tradeoff instead of assuming total memory use decreases.

Formal validation: **146 positive witnesses passed; 146/146 hostile assertions
explicitly disproved**, also confirmed by the developer on macOS. The gate can
be rerun independently of Rust:

```bash
python3 scripts/check-anka109-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root "$HOME/git/cee/kleis" --only-scalar-read
```

See [the SC110 contract and implementation acceptance](DESIGN_NOTES.md#scalar-read-contract).
The laptop has passed differential scalar results/faults, exact commit snapshots,
zero scalar payload allocations with ledger capacity reserved, bulk/asynchronous
fallback and the real CC2/socket/NIC/file gates. The fresh comparison session is
`target/perf-scalar-read-01`. Changes to runtime inputs must never reuse a measured
session as a new build. Rust correctness and measured performance remain separate
acceptance gates; both results are recorded below.
Do not change deadlines, resource limits or authority checks to improve timings.

## SC110 runtime validation and comparison

No Rust compilation or tests were run in the delivery environment. The developer
has completed the following procedure on the Mac; retain it for reproduction:

```bash
bash scripts/check-anka110-scalar-read.sh --real
```

This runs 15 focused SC110 cases, the ordinary full release library suite, and
three separately selected ignored real paths (guest download, stored launch and
independent restart). Review the allocation checks and printed Transaction size,
not just functional completion. Private heap-pointer access still uses its
existing heap path; SC110 targets ordinary Fabric scalar payload allocations.

For a future comparison, first pass correctness, then use a new session name.
These are the commands used for the accepted SC110 session; do not rerun its build
over the existing directory. Keep both sessions and matching binaries untouched:

```bash
python3 scripts/profile-anka110.py build --session target/perf-scalar-read-01
python3 scripts/profile-anka110.py baseline \
  --session target/perf-scalar-read-01 --workload rebuild --repeat 3
python3 scripts/profile-anka110.py baseline \
  --session target/perf-scalar-read-01 --workload restart --repeat 3
python3 scripts/profile-anka110.py record \
  --session target/perf-scalar-read-01 --workload rebuild --template 'Time Profiler'
python3 scripts/profile-anka110.py record \
  --session target/perf-scalar-read-01 --workload restart --template 'Time Profiler'
```

Compare with the original medians (72.9326 s rebuild, 85.0476 s restart), retaining
all samples and source/input hashes. Also inspect allocator and trace-cleanup
sample weights and record-size cost. Use the same machine/toolchain/power setup
and record changed thermal/background conditions. Capture status still requires
manual review, particularly the rebuild target's expected exit 42. Do not treat
a saved trace, helper success, or a modeled equivalence proof as measured speedup.

<a id="sc110-accepted-results"></a>

## SC110 accepted results — 2026-11-22

This closes the bounded scalar-payload task on the developer Mac. Evidence:
`test-output-performance-2.txt.zip`, `anka-scalar-read-results.zip`, and
`anka-scalar-read-profiles.zip`, compared with the original evidence above.
The updated repository snapshot is `Archive(20261123-034616).zip`. UTC filenames
cross into November 23; the developer-local review date is November 22.

### Correctness and memory footprint

| Gate | Result |
| --- | --- |
| Kleis scalar-read pair | 146 positive witnesses; 146/146 hostile assertions explicitly disproved, confirmed by the developer |
| Focused SC110 Rust cases | 15 passed, 0 failed |
| Full release library suite | 1,964 passed, 0 failed, 20 ignored, 0 measured, 0 filtered out; 267.06 s |
| Explicit real GD110 guest-download witness | 1 passed; 70.30 s |
| Explicit real SR110 stored-live-launch witness | 1 passed; 69.50 s |
| Explicit real RR110 independent-restart witness | 1 passed; 69.53 s |

The focused cases overlap the full suite. The three real witnesses were selected
separately; the ordinary suite does not establish that all 20 ignored tests ran.
Formal models, Rust correctness, whole-workload timing and sampled attribution
are distinct evidence. No Rust compilation/tests were run while preparing this
documentation update.

The target layout check reports **240 bytes per Transaction**: 16,384 retained
records occupy **3,932,160 bytes (3.75 MiB)** before other structures. The existing
conservative record-plus-payload bound remains below 8 MiB of the 16 MiB nonheap
application allowance. Reserved-capacity scalar-payload allocation checks pass;
this does not establish an allocation-free Kernel step or lower total RSS.

### Comparable unprofiled runs

All six SC110 run records validate expected completion and bind build manifest
SHA-256 `aab88c414df28541aa0036d79d19f2a98923560d2c448a7ec5b3d89c12e5444c`.
Both capture records bind that same manifest. The original manifest hash is
recorded above. Both manifests report base revision
`dfca85e23e131206bdc264f09e0d15e11ab3cb31` with local changes; the commit ID alone
does not identify the measured source.

The comparison matches machine, native target, toolchain, profile, power source,
workload inputs and arguments apart from the executable's session path. The six
changed source-input hashes are `src/anka64/core.rs`, `src/anka64/fabric.rs`,
`src/anka64/fabric/scalar_read_tests.rs`, `src/anka64/nic.rs`, `src/anka64/state.rs`
and `src/anka64/state/read_payload.rs`; they match the delivered SC110 implementation.

| Workload | Original three wall times (s) | SC110 three wall times (s) | Median before → after | Median reduction |
| --- | --- | --- | --- | --- |
| Rebuild | 72.5359, 74.8730, 72.9326 | 58.4865, 58.3227, 58.8204 | 72.9326 → 58.4865 s | 19.8% (14.4461 s; 1.247× speedup) |
| Whole RR110 restart witness | 85.0034, 85.0476, 85.3735 | 70.4077, 70.1119, 69.5963 | 85.0476 → 70.1119 s | 17.6% (14.9357 s; 1.213× speedup) |

Median child user+system CPU time also fell: 72.8336 → 58.3208 s for rebuild,
84.5513 → 69.6141 s for restart. Aggregate child CPU/wall ratios remain about
99.8%/99.3%. These three-run comparisons on one laptop support reduced emulator
work, not a confidence interval, maximum throughput claim or hardware cost estimate.
Thermal and background-load controls were not established. Both workloads include
compiler provisioning/setup; the restart total is not isolated restart latency.

### Profile completion and attribution

The comparison exports resolve their intended targets and completion evidence:

| Capture | Target result and evidence | Recording window | Preserved helper/recorder status |
| --- | --- | --- | --- |
| `rebuild-record-20261123T033753Z-b41f6c53` | Metadata `exit(42)` and log `Rebuild: Exited(42)`, linked receipt epoch 3 with two modules | 58.355691 s; target exited | `capture_issue`; xctrace launcher 54 |
| `restart-record-20261123T033855Z-377a685c` | Metadata `exit(0)`, exactly one test passed in 70.66 s, RR110 service-only/guest-only/both-side completion marker | 71.308964 s; target exited | `review_required`; xctrace launcher 0 |

Both logs say recording completed and both stderr logs are empty. Target completion
is established independently of launcher status. The reason for launcher code 54
is not established; do not rewrite the saved result to automatic success. The new
ZIP contains XML exports and logs, not native bundles, so it does not establish
whether native run issues remain. The original `Data stream: Time Mapping` caveat
still applies to the before-profile comparison. Use unprofiled runs for the
reported speedup; recording and launcher elapsed times are separate measurements.

Applying the same reference-resolving, demangling and sample-weight method gives
57.510 s total weight for rebuild and 70.154 s for restart after SC110. Empty-stack
weights are 0.002 s and 0.001 s respectively.

| Sample attribution | Rebuild before → after | Restart before → after |
| --- | --- | --- |
| Allocator library, leaf/self | 20.043 → 1.769 s (28.29% → 3.08%) | 20.828 → 1.849 s (24.41% → 2.64%) |
| Compiler-trace cleanup, inclusive | 16.159 → 6.352 s (22.81% → 11.05%) | 16.685 → 6.468 s (19.56% → 9.22%) |

Allocator self sample weight fell about **91%** in both workloads, consistent with
removing scalar read payload allocations and their later frees. Cleanup includes
allocator work; these rows overlap and must not be added. Weights are statistical
attribution, not exact function durations or allocation counts. Original reads
appear under `execute_read`; optimized scalar reads appear under `execute_cpu_read`,
so comparing only the old symbol would misleadingly report the read work as gone.

`Anka64Core::step` now has the largest self attribution (31.05% rebuild, 25.23%
restart). Its absolute self weight also rose (11.859 → 17.857 s / 12.799 → 17.701 s);
this warrants investigation of changed code generation/inlining and attribution
before inferring an instruction-dispatch regression. Inclusive step weight fell.
Cleanup remains 9–11% of sampled work. These are candidates for later investigation,
not a basis to remove authority checks or immediately launch another optimization.

### Integration and next task

The user has confirmed the profiling/SC110 checkpoint merged to `main`. Preserve
the raw evidence and matching binaries outside source control. Do not stage
`Archive.zip` or `target/` captures. The later KC110 CLI adds a binary entry point
in `src/main.rs` and a host helper. Preserve the historical SC110 measurements as
accepted; any new comparison must build a fresh profiling session for the new
checkout. Do not reuse a session whose source-input hashes have changed.

KC110 preflight is now accepted and merged by developer confirmation: 201/201
formal witnesses, 40 Python checks, the Rust binary build and all 14 real Keycloak
acceptance cases passed. No new full Rust suite is claimed for this milestone.
The [SA110 coordinator contract](DESIGN_NOTES.md#serialized-current-authority)
and AC110 administrative lab harness are accepted and merged. SA110 passed 185/185
formal and 33/33 focused Rust; AC110 passed 56/56 formal, 21 new Python checks plus
40 regressions, 15/15 focused Rust and the real Podman probe. The latest full suite
passed 2012 tests, with 0 failures and 20 ignored (272.04s). No new live authority
or performance acceptance is inferred. These runtime changes require a fresh
profiling session for new comparisons. No SA110/AC110 speedup is claimed; preserve
the historical SC110 evidence. This documentation update adds no measurements.

The [LG110 formal contract](DESIGN_NOTES.md#local-grant-contract) separates
bounded external identity evidence from locally serialized grants and revocation.
Anka64 cannot control Keycloak and requires no runtime administrator credentials
or internal policy inspection. Future runtime measurements should separate token
verification, remote observation and local grant checks. AC110's administrative
mutations are test-fixture work, not ordinary runtime cost. Enrollment, external
boot-attempt consumption, guest CRUD, threads/SMP and native/FPGA bootstrap remain
planned work. Further optimization is not a prerequisite for the next contract.

## References

- [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html) and
  [Cargo JSON artifact discovery](https://doc.rust-lang.org/cargo/reference/external-tools.html).
- [Apple: Optimize CPU performance with Instruments](https://developer.apple.com/videos/play/wwdc2025/308/).
- [Apple command-line tool reference](https://developer.apple.com/documentation/xcode/xcode-command-line-tool-reference);
  use the installed `man xctrace` for version-specific syntax.
- [Apple developer discussion of non-Xcode Processor Trace permissions](https://developer.apple.com/forums/thread/791270).
- [Design plan](DESIGN_NOTES.md#xcode-performance-probing).


## LG110 runtime follow-up

The [LG110 formal contract](DESIGN_NOTES.md#local-grant-contract) is accepted and
merged: developer-confirmed 264 positive / 264 hostile disproofs. The bounded Rust
owner and trusted evidence interface passed 38/38 focused tests and 33/33 SA110
regressions on the developer laptop, followed by the full suite: 2050 passed,
0 failed, 20 ignored in 267.41s. Runtime merge remains pending. This is correctness
evidence, not a new performance comparison; no speedup is claimed. Historical
SC110 results remain unchanged.

After correctness acceptance, use a fresh profiling build/session for changed
inputs. Measure remote IO and token/signature verification separately from staged
completion, holder verification, local grant locking/checks, contention, and actual
Kernel/file work. The owner guard contains bounded local lookups and synchronous
submissions, not remote HTTP. AC110 administrative mutations remain lab setup work.
Future boot measurements should separately account for the
[trusted boot dependencies](DESIGN_NOTES.md#boot-dependency-readiness), including
platform startup, network/TLS, credential access, identity verification and the
separate boot-attempt service. Native/FPGA cost must be measured for its actual
providers; hosted Rust/Python timings do not establish hardware cost.

## LA110 measurement boundary

LG110 is accepted and merged; its last full suite remains 2050/0/20 (267.41s).
LA110's hosted verifier/holder codec is accepted and merged by user confirmation. No new speedup or workload timing is claimed. After
correctness and real-path acceptance, build a fresh profiling session.

Separate process startup, JWKS/TLS/introspection, token signature verification,
holder signature verification, staging and local guarded submission. The first
profile deliberately uses a fixed maximum 30-second adapter worker lifetime,
1–5 second evidence age and exact proposal tick equality. Tick-crossing denials
and explicit retries must be counted rather than hidden in successful-run timing.
No remote HTTP or expensive crypto runs inside the local grant guard. The trusted
transport/provider integration and native suppliers remain separate obligations.


## LT110 hosted bridge measurement boundary

Hosted localhost is the first transport target; remote TLS storage is a separate
planned task. LT110 splits proof verification from guarded use and adds separate
holder signing. Measure signer startup/signature work, verifier startup/verification,
local owner checks, actual socket fragments and file/content scanning separately.
Signing and verification share the original finite worker allowance; neither may
refresh deadlines or hide tick-crossing failures. File scans retain the cooperative
host filesystem assumption, so measure guard hold time separately from socket IO.

The 59 Python checks are correctness evidence, not a performance result. Rust and
the ignored CC2/typed-socket/NIC/file witness have not been run for this delivery.
The latter uses private authority fixtures and must not be reported as real Keycloak
latency. Capture new baselines only after laptop correctness acceptance. No speedup,
new full-suite count or hardware/FPGA performance claim is made.


### LT110 laptop correctness checkpoint (2026-11-28)

The laptop passed 59 Python checks, 11 focused LT110 tests and 19/38/33
LA110/LG110/SA110 regressions. The real CC2/typed-socket/NIC/TCP/file mechanics
witness passed separately in 103.82s. That is a correctness-run duration using
private authority fixtures, not real Keycloak latency or a speedup measurement.
After the N110 fixture repair, its exact focused rerun passed (1/1, 0.01s), and
the final full suite passed **2080 tests, 0 failures, 21 ignored in 409.66s**. No
fresh profiling baseline or live-admission acceptance is claimed.

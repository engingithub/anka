# LK110 combined Keycloak and guest read acceptance

Delivered against merged `main` commit `327992b94149bb011e0c409d0bda5ace30ce2a1f`.
**All ten real laptop acceptance cases passed (2026-11-28), including successful
recovery, release compilation and final lab restoration.**
This overlay does not enable live executable or boot admission.

## Apply and run

Extract the documentation overlay into the repository root.
`LK110_ACCEPTED_DOCS_FILES.json` records the changed document hashes against the
latest supplied archive. The accepted runtime source is unchanged by this overlay.
It contains no credentials, lab state, build output or Python caches.

From the repository root:

```bash
bash scripts/check-anka110-keycloak-bridge.sh --python-only

python3 scripts/keycloak/lab.py resume --state target/keycloak-preflight-01

bash scripts/check-anka110-keycloak-bridge.sh --real target/keycloak-preflight-01

cargo test --release --locked --lib -- --test-threads=1
```

Use the existing **disposable** Keycloak lab. The real gate compiles the release
library test executable without running unrelated tests, selects it from Cargo's
JSON output, then requires exactly one ignored test with the full LK110 name.
The driver runs that test with `--exact --ignored --nocapture --test-threads=1`.
The usual full suite skips this external-lab witness; its success cannot substitute
for the explicit real gate.

A successful real run prints ten `LK110 PASS` lines, the complete witness marker,
and a private `bridge-acceptance-<timestamp>.json` evidence path. Acceptance requires
all ten cases in order, the completion marker, exactly one passing libtest result,
and successful child exit. A trace, saved log, zero tests or partial output is not
acceptance. The default overall driver timeout is 900 seconds; `run --timeout`
accepts 60–1800 seconds without changing any adapter or guest deadline.

## Covered path and cases

The ignored witness compiles the real CC2 fixed point, compiles the guest download
pump and a small stored image, seals and reopens the artifact file, then uses:

ordinary Keycloak token/signature/mTLS introspection → LA110 private worker → the
retained LG110 grant and actual hosted socket pair → guarded file read → virtual
TCP frames, NIC DMA and typed sockets → guest output → Kernel-accounted private
image → final E11 read/content/dependency checks.

The expected artifact and dependency identity are explicitly pinned by disposable
local installation policy. They are not inferred from a Keycloak token. The E11
embedding is test-only and supports one exact range and one trusted virtual stream;
it is not a general production provider registry, remote TLS endpoint or enrollment
workflow. Other verifier operations retain their default denial.

| Case | Required result |
| --- | --- |
| Positive | Exact stored image accepted into private, charged custody |
| Outage while original observation remains fresh | Same retained grant can finish; no age/deadline refill |
| Outage after original freshness expires | Guest read fails closed |
| Verified inactive token | Real realm not-before change causes correlated introspection to revoke |
| Local grant exclusive expiry | Read rejected with a still-fresh observation and remaining work/deadline |
| Real token exclusive expiry | Read rejected at signed expiry, independently of observation age |
| Changed input | Exact runtime token-file change revokes the retained binding |
| Revocation between reply fragments | Exactly the first 64 bytes sent; suffix denied |
| Revocation after final proof preparation | Final E11 image validation denies the already downloaded image |
| Independent content/dependency policy denial | Final image validation denies despite valid identity evidence |

Every case checks unchanged publication epoch, artifact record and bytes, and
release of Kernel private-image charges. Independent cases receive separate,
explicitly allocated grants. Within each case refresh, outage, fragmenting and final
delivery retain the exact owner, grant ID, token, original work and deadline.
The provider asserts that required fault/final checkpoints were actually reached;
an unrelated early failure cannot satisfy a negative case.

The hosted adapter still has a maximum five-second observation age and a
nonrenewable 30-second worker lifetime. The test may discard up to three proof
preparations that cross a seconds-clock tick **before submission**, spending the
existing preparation/worker allowance each time. It does not retry an effect or
relax tick equality. A slow laptop can therefore expose a real bounded-operation
failure; do not change limits merely to make the witness green.

## Lab state and recovery

The parent driver alone performs administrative negative-test setup. The Rust
witness is configured with a temporary ordinary-client directory containing the
holder certificate/key, CA, introspection secret, exact token and ordinary-client
configuration. Admin and workload-issuance secrets are not copied into it. This
is trusted-host credential custody, not OS sandbox isolation from the same user.
No token, key, secret or worker reply is printed in the public status output.

The driver coordinates through the existing `control.lock`, records a private,
durable `bridge-recovery.json` before changing realm policy, preserves the database,
and restores the original realm not-before and token lifespan. Recovery checks the
realm identity and expected policy values before writing. Outage tests stop and
restart only the lab's verified Keycloak container. Do not run other lab mutation
commands concurrently; this remains an administrative test convention, not control
over Keycloak or exclusion of external administrators.

If the driver fails, inspect its newest private `bridge-acceptance-*.log`. If the
journal remains, run:

```bash
python3 scripts/keycloak/bridge_acceptance.py recover \
  --state target/keycloak-preflight-01
```

A recovery conflict must be resolved explicitly; the driver does not overwrite
unexpected remote policy. Successful recovery is not acceptance of the failed test.

## Validation scope

The repair delivery passed 80 Python checks and static Rust syntax parsing. The
subsequent laptop run passed 16 driver checks, compiled the release library test
executable and passed all ten real Keycloak cases. See the final evidence below.
No Rust compilation/tests or Podman run was performed in the documentation workspace.

No LG110 contract or production authority semantics change in this slice, and no
new Kleis witness count is claimed. The accepted LG110 264/264 remains the formal
baseline; this work tests its composition using real credentials. The bounded hosted
credential-chain witness is now accepted. Remote TLS storage remains a separate
Kleis-first task; live/boot admission and native bootstrap retain their prerequisites.


### LK110 strict TLS certificate repair (2026-11-28)

> Historical checkpoint, superseded by the successful ten-case laptop run below.

The laptop compiled the LK110 additions and passed the full library suite:
**2080 passed, 0 failed, 22 ignored in 412.20s**. The combined real witness is still
pending. Both disposable containers started, but realm readiness failed with TLS
verification code 85 (missing Authority Key Identifier).

The lab generator now explicitly supplies Subject Key Identifier and Authority
Key Identifier on each issued leaf certificate. The repair helper reissues only
the existing server certificate with the same server key and CA, validates it with
a strict Python TLS handshake, updates the mounted certificate and restarts the
verified lab Keycloak container. It preserves holder certificates/keys (including
their token-binding fingerprints), CA, client/admin secrets and database. TLS chain,
purpose and hostname checks remain enabled. No runtime authority semantics change.

From the repository root after applying the repair overlay:

```bash
python3 scripts/keycloak/repair_server_certificate.py --state target/keycloak-bridge-01
python3 scripts/keycloak/lab.py doctor --state target/keycloak-bridge-01
bash scripts/check-anka110-keycloak-bridge.sh --real target/keycloak-bridge-01
```

The repair uses the existing administrative-test lock, refuses pending recovery,
foreign container images and unsafe key paths, and retains public certificate
backups. If interruption leaves the certificate copies different, rerunning repair
reissues and installs a matching pair without changing any key or CA. If readiness
still fails after repair, use `doctor`; do not disable TLS verification.

Five new certificate regressions pass, including real reproduction of error 85,
strict handshake after repair, wrong-hostname rejection and key/holder preservation.
Together with existing checks the Python-only gate passes 76 tests. No Rust compile,
Rust tests or real Podman/Keycloak run was performed in this repair workspace.
At this checkpoint the real LK110 run remained unaccepted; it subsequently passed.
Live/boot admission remains disabled.


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

<a id="delivery-refresh-retry"></a>
#### Recover the existing lab and retry

Apply `anka110-keycloak-delivery-refresh-fix.zip` from the repository root, then run:

```bash
python3 scripts/keycloak/bridge_acceptance.py recover \
  --state target/keycloak-bridge-01 &&
bash scripts/check-anka110-keycloak-bridge.sh \
  --real target/keycloak-bridge-01
```

For the historical failed attempt, the journal was present and recovery was
required before retry. That recovery and rerun have now succeeded. These commands
are retained for a future failed attempt with a journal; do not rerun recovery
without a journal or delete one manually. Recovery validates the recorded
realm and allowed values before restoring the disposable lab. If recovery fails,
the `&&` stops the test; retain its redacted output for diagnosis. The certificate
repair already succeeded and need not be repeated. The real gate rebuilds the
Rust test executable on your laptop.

Success still requires all ten case markers, exact one-test libtest success,
completion marker, unchanged executable, and successful restoration. On failure,
the new JSON report identifies the private log basename, completed cases, phase,
primary failure, cleanup failure, restoration failure and whether recovery remains
required. Any `LK110 DENY` line in the log reports the first denied stage, local
eligibility, owner state, tick/deadline, observation age, work/worker/preparation
counters and disclosure progress. It contains no token, private key or raw worker
output. Share the redacted report and relevant log tail if another case fails.


<a id="laptop-acceptance"></a>
## Real laptop acceptance passed (2026-11-28)

Source: uploaded `test-output-anka110-keycloak-delivery-refresh-fix.txt.zip`,
reviewed against `Archive(20261128-160638).zip`. The terminal output records:

- Recovery: `LK110 disposable lab restored.`
- Driver regressions: 16 passed in 0.466s.
- Rust release test executable: successfully compiled in 22.64s (warnings only).
- Real witness: all ten ordered case markers, followed by `LK110 accepted; live and boot admission remain disabled.`
- Evidence reported by the driver: `target/keycloak-bridge-01/bridge-acceptance-1795881897234389000.json`.

| Case | Laptop result |
| --- | --- |
| `positive` | PASS |
| `outage_fresh` | PASS |
| `outage_stale` | PASS |
| `inactive` | PASS |
| `grant_expiry` | PASS |
| `token_expiry` | PASS |
| `changed_input` | PASS |
| `suffix_revoked` | PASS |
| `final_revoked` | PASS |
| `content_denied` | PASS |

The schema-2 driver's acceptance path requires exact witness completion, one
passing libtest result, successful child exit, unchanged executable and successful
restoration. The attached terminal output supplies that driver's final acceptance;
the private JSON and complete child log were not separately attached for this review.
The earlier recovery journal was successfully processed; no further recovery is
needed for this accepted run.

This establishes the bounded hosted localhost credential/holder/grant/guest/file
composition. It does not enable production provider registration, live executable
admission, boot admission, native bootstrap or remote TLS storage. Anka64 still
neither controls Keycloak nor requires runtime administrator access.

The prior full-suite result is **2080 passed, 0 failed, 22 ignored in 412.20s**.
This focused gate did not rerun that suite. The 22.64s value is compilation time,
not credential/read latency. No new profiling result or Kleis witness count is
claimed. Commit/PR/merge status remains separate from acceptance evidence.

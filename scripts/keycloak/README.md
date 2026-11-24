# KC110 identity preflight

`anka keycloak-preflight --config FILE` checks a certificate-bound access token
against a separately running Keycloak service. This is a host diagnostic, with
**no live Anka authorization, capability publication, artifact access or boot permission**.
Even successful output says `current_authority: "unknown"`, `live_admission: false`
and `boot_authorized: false`. It is not a saved authority receipt.

The binary dispatches to `preflight.py` in its **build checkout**, using Python
isolated mode and no shell. Keep that checkout and helper available; copying just
the executable to another machine does not install this command. Python 3.9+ and
OpenSSL with RSA/SHA-256 verification support must be on the trusted host PATH.
There are no new Cargo dependencies. Credentials never enter guest memory.

## Acceptance status

**Accepted and merged to main, developer confirmation on 2026-11-23.** KC110 has
201 positive / 201 hostile formal witnesses, all 40 Python checks, a successful
Rust binary build and all 14 real Keycloak acceptance cases passing on the laptop.
The final fixture/helper timings were 4.476s and 0.007s. Resume repaired the import
filename while preserving credentials and database, then the real lab accepted
certificate-bound tokens and exercised all rejection, revocation, rotation,
expiry, outage and server-restart cases listed below.

Evidence: `target/keycloak-preflight-01/acceptance-1795466633415870000.json`.
Keep it and all private state outside Git. A new full Rust suite was not reported
for KC110. No Rust or real Podman run was performed in the delivery environment.
The following commands reproduce acceptance; they are not outstanding blockers.
The CLI remains diagnostic and publishes no live/boot authority. SA110 formal
and Rust gates are accepted (185/185 formal, 33/33 focused Rust; full suite
1997 passed, 0 failed, 20 ignored). AC110 below connects the closed coordinator
to lab administration, without enabling production current authority.

## Run on the laptop

From the Anka repository root, after applying this ZIP overlay:

```bash
bash scripts/check-anka110-keycloak-preflight.sh

# Build on your laptop, as usual; no Rust build was performed for this delivery.
cargo build --bin anka --locked
./target/debug/anka keycloak-preflight --help

# A working Podman machine is required on macOS.
podman info
python3 scripts/keycloak/lab.py start --state target/keycloak-preflight-01
python3 scripts/keycloak/lab.py check \
  --state target/keycloak-preflight-01 --binary target/debug/anka
```

`start` refuses to reuse an existing state directory. It pulls Keycloak **26.8.1**
and PostgreSQL **17**, resolves their local immutable image IDs and repository
digests into `lab.json`, and launches by those IDs. The PostgreSQL patch release
therefore depends on the first pull; its resolved ID is retained for reproduction.
This is a reproducible per-lab image pin, not a claim of a verified upstream image
signature or supply-chain admission. Keep the pinned images and evidence.

The lab creates a private seven-day CA, a localhost TLS server certificate, two
distinct client certificates, random client/admin/database secrets, realm import,
and a private JSON configuration. The server binds **127.0.0.1:8443** only;
PostgreSQL has no published host port. Use `--port 9443` on `start` if 8443 is busy.
The images run in a dedicated network with a named persistent database volume.
The Keycloak container runs as UID 0 inside the rootless developer container so it
can read owner-only bind mounts; this is a local test setup, not production hardening.
The Anka runtime container does not contain a JVM or a Keycloak server.

The realm has a confidential service-account issuing client (`anka-workload`),
RS256 signatures, certificate-bound access tokens, and an explicit
`anka-preflight` audience mapper. `anka-preflight` is the distinct confidential
introspection client/resource audience. Interactive, implicit and direct-password
flows are disabled on these clients. The separate bootstrap admin uses the master
realm only to administer this disposable lab during acceptance.

`check` acquires fresh real tokens and invokes the selected Anka binary for:

- A valid signed certificate-bound access token, with no operation/boot authority.
- Wrong issuer, resource audience, issuing client and holder certificate.
- **Realm not-before** advanced past the token's issue time: exact `inactive`
  denial is required. It restores the previous not-before only in this lab.
- Creating a higher-priority RSA signing provider, accepting its new token, then
  deleting the old RSA providers and requiring `key_selection` denial for the old
  token. Every invocation fetches JWKS anew; no positive key cache is used.
- A real five-second access token before and at its exclusive expiry boundary.
- Stopping Keycloak, requiring a transport denial, then restarting and accepting
  a new token using the existing realm/database.

The lab intentionally changes keys and policy. Run it **only against the lab it
created**, never against a production realm. A failed case stops the sequence and
writes a redacted `acceptance-*.json` with `complete: false`. Full completion writes
`complete: true`, each observed status/reason, and the image IDs. A plain `denied`
is insufficient for the specific revocation/key-withdrawal checks: their expected
reason must match. This records the behavior of realm not-before and key withdrawal;
it does not assert that logout, disabling a client or RFC 7009 revocation behave
the same way. Those actions need their own tests before later adoption.

If a lab action fails, its JSON error now identifies the stage, exit status or
HTTP status, and allowlisted diagnostic clues. It also saves `failure-*.json` in
the state directory when possible. Run `doctor` below to inspect the existing lab.
Raw exception text, command arguments, environment values and log lines remain private. Do not paste environment
files, realm imports, token files, private keys or raw server logs into chat.
`lab.json` gives the container-name prefix and pinned image IDs. Retry `check`
after correcting the cause; it starts by acquiring a fresh token. Certificates
expire after seven days; create a new state directory for a new lab then.

To inspect one result or verify database persistence across removing containers:

```bash
python3 scripts/keycloak/lab.py token --state target/keycloak-preflight-01
./target/debug/anka keycloak-preflight \
  --config target/keycloak-preflight-01/config.json

python3 scripts/keycloak/lab.py stop --state target/keycloak-preflight-01
python3 scripts/keycloak/lab.py resume --state target/keycloak-preflight-01
python3 scripts/keycloak/lab.py check \
  --state target/keycloak-preflight-01 --binary target/debug/anka
```

`resume` is safe after partial startup: it reuses running containers, starts
stopped containers with the pinned image, and creates only missing containers.
It refuses an existing container with a different image or an unsafe state. It
does not delete/recreate containers, regenerate credentials, or reset the database.
Podman lookup errors now stop recovery instead of being treated as absence.

`stop` removes only the two named containers. The database volume, network, local
images and private state remain. `resume` uses the retained image IDs and database;
Keycloak skips import when the realm already exists. Keep all files under `target/`
out of Git and delivery archives. No automatic volume deletion is provided.
The lab administration helper is separate from the bounded preflight: image pulls,
server readiness and acceptance setup take longer than a single verification.

## Recovery for the first laptop run

The uploaded log proves all 26 fixture tests passed and the Rust binary built.
It contains only generic failures for `start` and `check`; it contains no Podman
container status, server logs or failure details. The subsequent Keycloak log identifies the startup cause exactly: the generator
wrote `anka-realm.json` for realm `anka-kc110`, but Keycloak requires
`anka-kc110-realm.json`. The generator is now corrected. `resume` validates and
renames the legacy file, preserving its bytes and permissions, before restarting
the existing container. It refuses conflicting files, invalid realm content or
unsafe file permissions. No credentials or database contents are regenerated.
The subsequent developer run repaired this filename and passed all 14 real
acceptance cases; these recovery instructions remain for reproducing old labs.

Apply the patch in the same build checkout. No Rust source changed, so keep the
already-built `target/debug/anka`. From the repository root:

```bash
bash scripts/check-anka110-keycloak-preflight.sh
python3 scripts/keycloak/lab.py doctor \
  --state target/keycloak-preflight-01

python3 scripts/keycloak/lab.py resume \
  --state target/keycloak-preflight-01 &&
python3 scripts/keycloak/lab.py check \
  --state target/keycloak-preflight-01 --binary target/debug/anka
```

If recovery fails, run `doctor` again and share its JSON plus the new failure
JSON. The report includes fixed reason codes, database/Keycloak state, exit code,
OOM flag, recognized log-error categories and the realm HTTPS probe. Its log
categories are clues, not a diagnosis. It never includes the raw inspect/config
output, log text, tokens, passwords, certificates or environment values. These
new reports are intended to be shareable; the other lab state files remain private.

Do not run `start` again against the existing directory, and do not delete the
state or database volume. If `doctor` reports a missing manifest, preparation did
not finish: preserve that directory and create a new lab directory after fixing
the reported prerequisite. A Podman connection failure requires repairing or
starting the selected Podman machine before retrying; this script does not change
your Podman connection selection or initialize a new machine automatically.

## Input and output contract

The exact configuration fields are generated in `config.json`:

| Field | Initial profile |
| --- | --- |
| `schema`, `profile` | `1`, `keycloak-26.8.1-rs256-mtls-v1` |
| `issuer` | Exact HTTPS realm URL, no query/fragment/userinfo; endpoints derived from it |
| `audience` | Required resource audience, equal to this profile's introspection client |
| `issuing_client` | Exact JWT `azp` and introspection `client_id` |
| `introspection_client` | Confidential resource client used for authenticated introspection |
| `introspection_secret_file`, `token_file` | Exact private file bytes; no trailing newline |
| `ca_file` | Explicit TLS roots; ambient system roots are not added |
| `holder_cert_file`, `holder_key_file` | One PEM holder certificate and matching unencrypted PEM key |
| `timeout_seconds` | Integer 1–20, one original monotonic verification deadline |
| `max_observation_age_seconds` | Integer 1–5, measured from introspection query start |

File paths are relative to the config directory or absolute. All inputs must be
bounded regular files owned by the invoking user. Config/token/key/secret files
must have no group/other permissions; public certificate/root files must not be
group/world writable. Final-component symlinks are rejected. Trusted parent
directories, helper/Python/OpenSSL executables, host clocks and OS are assumptions.
File identity, size, timestamps and SHA-256 snapshots are rechecked before success.
This detects replacement during verification; it is not a transaction against a
malicious host, and no output may be replayed as current authority.

Only compact, canonical base64url JWS with exactly `alg=RS256`, `typ=JWT` and `kid`
in its header is accepted. The signed payload must have `typ=Bearer`, exact issuer,
required audience, exact issuing client, a nonempty subject, integer `iat`/`exp`,
optional integer `nbf`, and exactly one `cnf.x5t#S256` matching the local certificate.
There is no expiry grace. ID/refresh/offline/plain bearer and other header profiles
are rejected. JSON duplicates, nonfinite numbers, excessive nesting, ambiguous or
weak/wrong-use RSA keys and mismatched signatures fail closed.

The configured CA authenticates the two HTTPS requests (JWKS and introspection),
and the helper presents its holder certificate/key. OpenSSL verifies RS256 against
one unambiguous eligible JWKS key. Introspection must be authenticated, active and
correlated with the exact posted token: issuer/subject/times/audience/client/holder
must agree, and all shared claims must agree without bool/integer coercion.
Successful TLS and matching `cnf` support this **local diagnostic**; they do not
prove holder possession on an Anka request channel or provide the future full-scope
Anka holder statement, principal mapping, grant or current-authority fence.

| Bound | Value |
| --- | --- |
| Token/config/each JSON response | 16 KiB |
| JSON nesting / JWKS count | 16 levels / 16 keys |
| RSA modulus | 2048–4096 bits, odd exponent 3…2³²−1 |
| Other input files / introspection secret | 64 KiB / 4 KiB |
| Entire HTTP response stream, including framing/trailers | 128 KiB plus fixed library buffering |
| Accepted response headers | 16 KiB aggregate; stdlib also bounds individual lines/count |
| Worker work units | 8; failures do not refund; no retries, discovery or caches |
| Socket/OpenSSL wait | At most 3 seconds and remaining operation deadline |
| Parent supervisor | 30 seconds, terminates worker process group including OpenSSL |

The public command always runs through the supervisor, which bounds DNS stalls
as well as network/crypto work; no CLI flag bypasses it. Each invocation
is a fresh diagnostic; it does not implement retry budgets for live operations.
No redirects, proxies, compressed responses or token-supplied endpoint/key URLs are
followed. Chunked responses are supported within the total wire cap. Observed wall
or monotonic clock rollback rejects the run; there is no cross-process trusted clock
or rollback-resistant persistent state in this CLI.

Exit `0` means diagnostic `preflight_valid`; `1` means verification denied;
`2` means CLI/startup usage failure. Output is one JSON result, with fixed sanitized
denial codes. Success includes issuer, subject, token SHA-256, certificate thumbprint,
expiry and observation age—identity metadata that should still be treated as private.
Tokens, secrets and private keys are never printed. A result file is never an Anka
authority credential, regardless of exit status or later edits to its JSON.

## Checks and remaining work

The original 26 checks cover real RSA/mTLS, malformed token/header/JSON, expiry and
clock rollback, key substitution/rotation/withdrawal, inactive and mismatched
introspection, missing claims, exact typing, CA/key mismatch, response bounds,
chunked trailers, input changes/permissions/symlinks/FIFOs, deadlines and child
termination, redaction, and the generated lab profile. They run without Cargo or
Podman. Fourteen additional tests cover safe diagnostics, Podman lookup errors,
partial-start recovery, image/state mismatch refusal, private failure reports,
the legacy filename repair and conflict/invalid-input rejection.
They do not prove Keycloak internals, distributed revocation atomicity or
Rust refinement. The laptop binary build has passed; run the real acceptance above and your
normal Rust suite on the laptop; retain the results when reproducing this accepted milestone.

Next: run the AC110 control-path acceptance below. After that, enforce exclusive
administration and implement the trusted Keycloak source, principal mapping,
full-scope holder proof and explicit grants. HTTP stays outside guarded callbacks.
The real CC2/typed-socket/NIC/file admission path, external boot-attempt consumption,
enrollment, installation, guest CRUD and threads/SMP remain separate work.

Sources for this pinned setup: [Keycloak 26.8.1 release](https://www.keycloak.org/2026/10/keycloak-2681-released),
[containers](https://www.keycloak.org/server/containers),
[mutual TLS](https://www.keycloak.org/server/mutual-tls),
[truststore](https://www.keycloak.org/server/keycloak-truststore),
[OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[administration](https://www.keycloak.org/docs/latest/server_admin/index.html),
and [OpenSSL signature verification](https://docs.openssl.org/1.1.1/man1/dgst/).
The Keycloak guides are rolling references; the pinned release must pass the lab
acceptance rather than inheriting assumptions from a newer guide.


<a id="ac110-control-probe"></a>

## AC110: coordinator-to-Podman control probe

This new command uses the actual Rust SA110 coordinator to close a barrier before
remote administration. It temporarily raises realm `notBefore`, verifies old-token
inactivity, restores the saved value, and verifies fresh-token activity. It leaves
the coordinator **closed**, with current authority **Unknown** and live/boot
admission **false**. It exercises the administration path; it does not establish
exclusive writer control or connect live file operations yet.

Local acceptance is 56/56 formal and 21 new Python tests, plus 40 existing Python
regressions. Fifteen new Rust tests and this real Podman probe have not been run in
delivery. Use the already prepared private lab, not production credentials:

```bash
python3 scripts/keycloak/lab.py resume --state target/keycloak-preflight-01
bash scripts/check-anka110-keycloak-control.sh --real target/keycloak-preflight-01
```

The gate builds/tests Rust on your laptop. Omitting `--real STATE` runs the fixture
and Rust gates without contacting the real lab. A successful real run emits
`status: control_probe_valid`, `action: probe`, `coordinator: closed` and the three
denying authority fields. Preserve that output with the Rust test results.

The directory, credentials and recovery files must remain private. Do not run
other lab administration (including `lab.py check`) concurrently. The advisory
lock protects AC110 workers only; it does not fence direct administrators, database
writers or automatic server changes. Setting `hostname-admin` is not sufficient
to restrict Admin REST access; deployment enforcement remains future work.

If the worker fails, inspect private `control-failure-*.json` for the fixed reason.
If `control-recovery.json` exists, a new probe refuses to start. Recover using:

```bash
target/debug/anka keycloak-control-lab \
  --state target/keycloak-preflight-01 --recover
```

Recovery verifies the input fingerprint, realm ID and observed value before
restoring, and verifies readback before removing the journal. On a conflict,
retain the record and inspect the lab rather than deleting it and rerunning.
The check-before-write is not atomic CAS, and the journal is not boot authority
or rollback-resistant storage. A timeout may leave no failure report but still
leave a journal. Successful recovery reports `action: recover` and still grants
no authority. Run a new probe afterwards for the complete revocation sequence.

No existing `access.token`, keys, credentials or database is replaced. Tokens used
by the probe stay in worker memory; the fixed binary pipe contains only correlation
and bounded result fields. The worker uses TLS endpoint observations for this
control probe; KC110's separate signature/preflight checks remain unchanged.
See [the full AC110 contract and limitations](../../DESIGN_NOTES.md#keycloak-control-probe).

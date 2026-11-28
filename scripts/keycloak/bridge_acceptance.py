#!/usr/bin/env python3
"""LK110 disposable Keycloak acceptance driver; never a runtime authority provider.

The parent alone holds lab administration credentials. The Rust witness receives
an isolated ordinary-client directory and a fixed-vocabulary synchronization pipe.
No log, marker or profile packet grants authority: Rust must call the LA110 worker.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import preflight as kc
import lab
import control

CASES = ("positive", "outage_fresh", "outage_stale", "inactive", "grant_expiry",
         "token_expiry", "changed_input", "suffix_revoked", "final_revoked", "content_denied")
WITNESS = ("anka64::os::compiler_retry::service::frame_port::tcp::outbound::artifact_guest_tests::"
           "download_tests::keycloak_bridge_tests::lk110_real_keycloak_cc2_e11_file_bridge")
JOURNAL = "bridge-recovery.json"
ORDINARY = ("ca.pem", "holder.pem", "holder.key", "introspection.secret")


def profile(root):
    control.root_check(root)
    inputs = kc.Inputs()
    config = kc.load_config(root / "config.json", inputs)
    token = inputs.read(config["token_file"], private=True, limit=16384)
    cert = inputs.read(config["holder_cert_file"], private=True)
    # Expected identity comes from a verified ordinary-client observation; Rust
    # independently verifies it again on its own correlated private request.
    verified = kc.verify_identity(root / "config.json")
    claims = verified["claims"]
    holder = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.decode("ascii"))).digest()
    result = bytearray(b"LK110P1\0" + holder)
    for value in (token, config["issuer"].encode(), config["audience"].encode(),
                  config["issuing_client"].encode(), kc.text(claims["sub"], 256).encode()):
        result += struct.pack("<I", len(value)) + value
    inputs.recheck()
    kc.require(len(result) <= 24576, "profile_size")
    return bytes(result).ljust(24576, b"\0")


def discover(binary):
    result = subprocess.run([str(binary), WITNESS, "--exact", "--ignored", "--list"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30)
    names = re.findall(rb"^(\S+): test$", result.stdout, re.M)
    kc.require(result.returncode == 0 and names == [WITNESS.encode()], "test_discovery")


class Evidence:
    """Strict ordered event/pass transcript. A saved log or exit zero is insufficient."""
    def __init__(self):
        self.index = 0
        self.phase = "case"
        self.passed = []
        self.complete = False
        self.libtest = False

    def line(self, line, action):
        # libtest prints its test-name prefix without a trailing newline.
        marker = b"LK110 EVENT "
        if marker in line:
            name = line.split(marker, 1)[1].decode("ascii")
            kc.require(self.index < len(CASES), "event_order")
            case = CASES[self.index]
            expected = {"case": case, "issued": "issued", "fault": "fault", "restore": "restore"}
            kc.require(self.phase in expected and name == expected[self.phase], "event_order")
            action(name, case)
            self.phase = {"case": "issued", "issued": "fault" if case in CASES[1:7] else "restore",
                          "fault": "restore", "restore": "pass"}[self.phase]
            return True
        if line.startswith(b"LK110 PASS "):
            kc.require(self.index < len(CASES) and self.phase == "pass"
                       and line == ("LK110 PASS " + CASES[self.index]).encode(), "pass_order")
            self.passed.append(CASES[self.index]); self.index += 1; self.phase = "case"
        elif line.startswith(b"LK110 COMPLETE"):
            kc.require(not self.complete and self.passed == list(CASES)
                       and line == b"LK110 COMPLETE 10; live=false boot=false", "completion")
            self.complete = True
        elif line.startswith(b"test result:"):
            kc.require(re.fullmatch(rb"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+", line)
                       is not None and not self.libtest, "libtest_result")
            self.libtest = True
        return False

    def accepted(self, code):
        return code == 0 and self.complete and self.libtest and self.passed == list(CASES)


class Lab:
    def __init__(self, root):
        self.root = root
        control.root_check(root)
        inputs = kc.Inputs()
        self.manifest = kc.strict_json(inputs.read(root / "lab.json", private=True))
        config = kc.load_config(root / "config.json", inputs)
        m = self.manifest
        kc.require(type(m.get("port")) is int and 1024 <= m["port"] <= 65535
                   and re.fullmatch(r"anka-kc110-[0-9a-f]{8}", m.get("name", "")) is not None
                   and m.get("profile") == kc.PROFILE
                   and config["issuer"] == f"https://localhost:{m['port']}/realms/{lab.REALM}", "lab_profile")
        # Same exact credential/path profile as the existing disposable lab.
        for key, name in (("ca_file", "ca.pem"), ("holder_cert_file", "holder.pem"),
                          ("holder_key_file", "holder.key"), ("introspection_secret_file", "introspection.secret"),
                          ("token_file", "access.token")):
            kc.require(Path(config[key]).absolute() == root / name, "lab_profile")
        kc.require(config["audience"] == "anka-preflight" and config["issuing_client"] == "anka-workload"
                   and config["introspection_client"] == "anka-preflight", "lab_profile")
        self.admin = None
        self.stopped = False
        self.record = None
        self.runtime = None
        self.claims = None

    def login(self):
        secret = kc.Inputs().read(self.root / "admin.secret", private=True, limit=4096).decode()
        self.admin = kc.text(lab.request(self.root, "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "lab-admin", "password": secret})["access_token"], 16384)

    def realm(self):
        self.login()
        return lab.request(self.root, "/admin/realms/" + lab.REALM, bearer=self.admin)

    def journal(self):
        target = self.root / JOURNAL
        if self.record is None:
            kc.require(not target.exists() and not target.is_symlink(), "recovery_required")
            realm = self.realm()
            identity, before = control.realm_record(realm)
            lifespan = control.number(realm.get("accessTokenLifespan"))
            self.record = {"schema": 1, "realm_id": identity, "original": {"notBefore": before, "accessTokenLifespan": lifespan},
                           "allowed": {"notBefore": [before], "accessTokenLifespan": [lifespan]}, "container": self.manifest["name"] + "-server"}
        # Atomic private journal update BEFORE changing remote state.
        fd, temp = tempfile.mkstemp(prefix="bridge-journal-", dir=self.root)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.record, f); f.flush(); os.fsync(f.fileno())
            os.replace(temp, target)
            fd = os.open(self.root, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if os.path.exists(temp): os.unlink(temp)

    def change(self, **values):
        self.journal()
        current = self.realm()
        kc.require(current["id"] == self.record["realm_id"], "restore_conflict")
        for key, value in values.items():
            control.number(value)
            kc.require(current.get(key, 0) in self.record["allowed"][key], "restore_conflict")
            if value not in self.record["allowed"][key]: self.record["allowed"][key].append(value)
        self.journal()
        lab.request(self.root, "/admin/realms/" + lab.REALM, method="PUT", payload=values, bearer=self.admin)
        after = self.realm()
        kc.require(all(after.get(k, 0) == v for k, v in values.items()), "change_readback")

    def restore(self, remove=False):
        if self.stopped:
            lab.start(self.root, self.manifest); self.stopped = False
        if self.record is not None:
            current = self.realm()
            kc.require(current["id"] == self.record["realm_id"] and
                       all(current.get(k, 0) in allowed for k, allowed in self.record["allowed"].items()), "restore_conflict")
            lab.request(self.root, "/admin/realms/" + lab.REALM, method="PUT", payload=self.record["original"], bearer=self.admin)
            after = self.realm()
            kc.require(all(after.get(k, 0) == v for k, v in self.record["original"].items()), "restore_readback")
            if remove:
                (self.root / JOURNAL).unlink(); self.record = None

    def action(self, name, case):
        if name == case:
            self.restore()
            self.change(accessTokenLifespan=20 if case == "token_expiry" else 120)
            token = lab.issue(self.root)
            _, _, self.claims, _, _ = kc.parse_token(token.encode())
            fd, temporary = tempfile.mkstemp(prefix="new-token-", dir=self.runtime)
            with os.fdopen(fd, "wb") as f: f.write(token.encode())
            os.replace(temporary, self.runtime / "access.token")
        elif name == "fault":
            if case.startswith("outage_"):
                # Stop only the already verified disposable container, preserving DB.
                # Intent is journaled first; recovery can restart after interruption.
                self.journal(); self.stopped = True
                lab.run(["podman", "stop", "--time", "0", self.record["container"]], timeout=15)
            elif case == "inactive":
                self.change(notBefore=self.claims["iat"] + 1)
            elif case == "token_expiry":
                # Return just before expiry, allowing Rust to obtain a fresh real
                # observation, then test the exact exclusive token boundary.
                end = self.claims["exp"] - 2
                while time.time() < end: time.sleep(min(.05, end-time.time()))
            elif case == "changed_input":
                with (self.runtime / "access.token").open("ab") as f: f.write(b" ")
        elif name == "restore":
            self.restore()


@contextlib.contextmanager
def locked(root):
    control.root_check(root)
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        kc.require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077, "state_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        kc.require(not (root / control.JOURNAL).exists(), "control_recovery_required")
        yield
    finally:
        os.close(fd)


def recover(root):
    with locked(root):
        instance = Lab(root)
        record = kc.strict_json(kc.Inputs().read(root / JOURNAL, private=True, limit=4096))
        kc.require(set(record) == {"schema", "realm_id", "original", "allowed", "container"}
                   and type(record["schema"]) is int and record["schema"] == 1
                   and record["container"] == instance.manifest["name"] + "-server", "recovery_record")
        kc.text(record["realm_id"], 256)
        for name in ("original", "allowed"):
            kc.require(type(record[name]) is dict and set(record[name]) == {"notBefore", "accessTokenLifespan"}, "recovery_record")
        for key, value in record["original"].items():
            control.number(value)
            values = record["allowed"][key]
            kc.require(type(values) is list and 1 <= len(values) <= 16 and value in values, "recovery_record")
            for v in values: control.number(v)
        instance.record = record
        # lab.start validates existing container image before reuse.
        lab.start(root, instance.manifest)
        instance.restore(remove=True)


SAFE_REASONS = frozenset({
    "event_order", "pass_order", "completion", "libtest_result", "incomplete_acceptance",
    "suite_timeout", "log_size", "log_tail", "binary_changed", "recovery_required",
    "control_recovery_required", "recovery_record", "restore_conflict", "restore_readback",
    "change_readback", "realm_identity", "realm_number", "lab_profile", "state_lock",
    "input_file", "input_owner", "input_permissions", "input_size", "input_changed",
    "test_discovery", "arguments", "existing_container_image_mismatch",
    "existing_container_not_restartable", "keycloak_readiness_deadline", "lab_api_response",
})


def reason(error):
    # Only fixed codes escape. Never serialize exception text, URLs, commands,
    # credentials or the nested raw HTTP/subprocess error.
    if isinstance(error, (kc.Denied, lab.LabFailure)):
        code = str(error)
        return code if code in SAFE_REASONS else "verification_or_lab_failure"
    if isinstance(error, ssl.SSLCertVerificationError): return "tls_certificate_verification"
    if isinstance(error, subprocess.TimeoutExpired): return "subprocess_timeout"
    if isinstance(error, subprocess.CalledProcessError): return "subprocess_failed"
    if isinstance(error, FileNotFoundError): return "file_or_executable_missing"
    if isinstance(error, PermissionError): return "permission_denied"
    if isinstance(error, BrokenPipeError): return "child_pipe_closed"
    if isinstance(error, OSError): return "io_failure"
    return "unexpected_error"


class RunFailure(Exception):
    def __init__(self, path, report):
        super().__init__("acceptance_failed")
        self.path, self.report = path, report


def run(root, binary, timeout):
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    discover(binary)
    evidence = Evidence()
    with locked(root), tempfile.TemporaryDirectory(prefix="bridge-client-", dir=root) as directory:
        instance = Lab(root)
        instance.journal()
        runtime = Path(directory); instance.runtime = runtime
        child = None
        selector = None
        primary = cleanup = restoration = None
        code = None
        log_path = root / ("bridge-acceptance-" + str(time.time_ns()) + ".log")
        try:
            for name in ORDINARY:
                lab.private(runtime / name, kc.Inputs().read(root / name, private=True))
            lab.json_file(runtime / "config.json", lab.configuration(instance.manifest["port"]))
            # Independent image verification before allowing this driver to stop it.
            lab.start(root, instance.manifest)
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ANKA_LK110_STATE": str(runtime), "RUST_BACKTRACE": "0"}
            child = subprocess.Popen([str(binary), WITNESS, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env=env, start_new_session=True)
            deadline = time.monotonic() + timeout
            selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
            pending = bytearray(); total = 0
            with log_path.open("xb") as log:
                os.fchmod(log.fileno(), 0o600)
                while True:
                    kc.require(time.monotonic() < deadline, "suite_timeout")
                    if not selector.select(min(1, max(.001, deadline-time.monotonic()))): continue
                    data = os.read(child.stdout.fileno(), 8192)
                    if not data: break
                    total += len(data); kc.require(total <= 2*1024*1024, "log_size")
                    log.write(data); pending.extend(data)
                    while b"\n" in pending:
                        line, _, tail = pending.partition(b"\n"); pending = bytearray(tail)
                        if evidence.line(bytes(line).rstrip(b"\r"), instance.action):
                            child.stdin.write(b"continue\n"); child.stdin.flush()
                        if line.startswith(b"LK110 PASS "): print(line.decode(), flush=True)
                kc.require(not pending, "log_tail")
            code = child.wait(timeout=max(.001, deadline-time.monotonic()))
            kc.require(evidence.accepted(code), "incomplete_acceptance")
            kc.require(hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash, "binary_changed")
        except Exception as error:
            primary = reason(error)
        finally:
            # A pipe/selector cleanup failure must not skip lab restoration.
            actions = []
            if child is not None:
                def terminate():
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait()
                actions.extend((terminate, child.stdin.close, child.stdout.close))
            if selector is not None: actions.append(selector.close)
            for action in actions:
                try: action()
                except Exception as error:
                    if cleanup is None: cleanup = reason(error)
            try: instance.restore(remove=True)
            except Exception as error: restoration = reason(error)
        accepted = primary is None and cleanup is None and restoration is None and evidence.accepted(code)
        report = {"schema": 2, "status": "accepted" if accepted else "failed", "cases": evidence.passed,
                  "witness": WITNESS, "live_admission": False, "boot_admission": False,
                  "binary_sha256": binary_hash, "failure": primary, "cleanup_failure": cleanup,
                  "restore_failure": restoration, "recovery_required": (root / JOURNAL).exists(),
                  "log": log_path.name, "case_index": evidence.index, "phase": evidence.phase}
        path = root / ("bridge-acceptance-" + str(time.time_ns()) + ".json")
        lab.json_file(path, report)
        if not accepted: raise RunFailure(path, report)
        return path


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "profile", "recover"))
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    root = args.state.absolute()
    try:
        if args.action == "profile":
            sys.stdout.buffer.write(profile(root)); return 0
        if args.action == "recover":
            recover(root); print("LK110 disposable lab restored."); return 0
        kc.require(args.binary is not None and 60 <= args.timeout <= 1800, "arguments")
        path = run(root, args.binary.absolute(), args.timeout)
        print("LK110 accepted; live and boot admission remain disabled.")
        print("Evidence:", path)
        return 0
    except RunFailure as error:
        print(json.dumps(error.report, sort_keys=True), file=sys.stderr)
        print("Evidence:", error.path, file=sys.stderr)
        return 1
    except Exception as error:
        # Error details can include paths, command arguments or raw credentials.
        if args.action != "profile":
            print(json.dumps({"status":"failed", "reason":reason(error), "recovery_required":(root/JOURNAL).exists()}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

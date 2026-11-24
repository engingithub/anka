#!/usr/bin/env python3
"""AC110 private worker. Only the Rust keycloak-control-lab supervisor invokes it.

This exercises the existing disposable lab. It cannot attest exclusive mediation.
No tokens, credentials, or arbitrary URLs/commands cross its fixed binary pipe.
"""
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import struct
import sys
import tempfile
import time
from urllib.parse import urlencode

# -I deliberately ignores cwd/PYTHONPATH. Import only this installed sibling.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import preflight as kc

REALM = "anka-kc110"
REQUEST = struct.Struct("<8s9Q")
REPLY = struct.Struct("<8s14Q")
QMAGIC, RMAGIC = b"AC110Q1\0", b"AC110R1\0"
JOURNAL = "control-recovery.json"
LIMIT = 65536


def parse_request(raw):
    kc.require(len(raw) == REQUEST.size, "request_size")
    magic, *words = REQUEST.unpack(raw)
    action, domain, incarnation, revision, command, *nonce = words
    kc.require(magic == QMAGIC and action in (1, 2) and all((domain, incarnation, revision, command))
               and any(nonce), "request_shape")
    return tuple(words)


def reply(request, original, target, restored, flags):
    action = request[0]
    kc.require(0 <= original < target <= 2147483647 and restored == original
               and flags == (31 if action == 1 else 8), "reply_shape")
    return REPLY.pack(RMAGIC, *request, action, original, target, restored, flags)


class AdminBudget(kc.Budget):
    def __init__(self):
        super().__init__(40)
        self.remaining = 16


def root_check(root):
    st = root.lstat()
    kc.require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
               and not st.st_mode & 0o077, "state_directory")


def number(value):
    kc.require(type(value) is int and 0 <= value <= 2147483647, "realm_number")
    return value


def realm_record(value):
    kc.require(type(value) is dict and value.get("realm") == REALM
               and value.get("enabled") is True, "realm_identity")
    return kc.text(value.get("id"), 256), number(value.get("notBefore", 0))


def bounded_json(raw):
    # Realm representations can be larger than tokens; keep the same duplicate,
    # depth and numeric checks while retaining a separate explicit cap.
    kc.require(len(raw) <= LIMIT, "response_size")
    def pairs(items):
        d = {}
        for k, v in items:
            kc.require(k not in d, "duplicate_claim"); d[k] = v
        return d
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(kc.Denied("json_number")))
    except (ValueError, UnicodeError, RecursionError):
        raise kc.Denied("json_syntax") from None
    def visit(v, depth=0):
        kc.require(depth <= 16, "json_depth")
        if isinstance(v, dict):
            for x in v.values(): visit(x, depth + 1)
        elif isinstance(v, list):
            for x in v: visit(x, depth + 1)
        elif isinstance(v, float):
            kc.require(False, "json_number")
    visit(value)
    kc.require(type(value) is dict, "json_object")
    return value


def request_http(port, context, budget, path, method="GET", body=None, bearer=None):
    budget.spend()
    allowed = {"/realms/master/protocol/openid-connect/token",
               f"/realms/{REALM}/protocol/openid-connect/token",
               f"/realms/{REALM}/protocol/openid-connect/token/introspect",
               f"/admin/realms/{REALM}"}
    kc.require(path in allowed and method in ("GET", "POST", "PUT"), "endpoint")
    headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
    if body is not None:
        headers["Content-Type"] = "application/json" if method == "PUT" else "application/x-www-form-urlencoded"
    if bearer is not None: headers["Authorization"] = "Bearer " + kc.text(bearer, 16384)
    conn = http.client.HTTPSConnection("localhost", port, context=context, timeout=budget.timeout())
    conn.response_class = lambda sock, **kw: kc.BoundedResponse(sock, budget, **kw)
    response = None
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        kc.require(response.status == (204 if method == "PUT" else 200), "http_status")
        kc.require(sum(len(k)+len(v)+4 for k,v in response.getheaders()) <= 16384, "http_headers")
        for name in ("Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding"):
            kc.require(len(response.headers.get_all(name, [])) <= 1, "http_headers")
        length, encoding = response.getheader("Content-Length"), response.getheader("Transfer-Encoding")
        kc.require(response.getheader("Content-Encoding", "identity").lower() == "identity", "content_encoding")
        kc.require(encoding is None or (encoding.lower() == "chunked" and length is None), "http_framing")
        if length is not None:
            kc.require(re.fullmatch(r"[0-9]{1,8}", length) is not None and int(length) <= LIMIT, "response_size")
        if method == "PUT":
            kc.require(encoding is None and length in (None, "0"), "http_framing")
        else:
            kc.require(response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                       == "application/json", "content_type")
        parts, size = [], 0
        while True:
            if conn.sock is not None: conn.sock.settimeout(budget.timeout())
            block = response.read(min(1024, LIMIT + 1 - size)); budget.check()
            if not block: break
            parts.append(block); size += len(block); kc.require(size <= LIMIT, "response_size")
        raw = b"".join(parts)
        if length is not None: kc.require(len(raw) == int(length), "http_framing")
        if method == "PUT":
            kc.require(not raw, "http_framing"); return None
        return bounded_json(raw)
    except (OSError, http.client.HTTPException, ValueError):
        raise kc.Denied("transport") from None
    finally:
        if response is not None: response.close()
        conn.close()


class Remote:
    def __init__(self, config, port, context, budget, secrets, holder):
        self.config, self.port, self.context, self.budget = config, port, context, budget
        self.secrets, self.holder, self.admin = secrets, holder, None

    def call(self, path, method="GET", body=None, bearer=None):
        return request_http(self.port, self.context, self.budget, path, method, body, bearer)

    def login(self):
        value = self.call("/realms/master/protocol/openid-connect/token", "POST", urlencode({
            "grant_type": "password", "client_id": "admin-cli", "username": "lab-admin",
            "password": self.secrets["admin"]}).encode())
        self.admin = kc.text(value.get("access_token"), 16384)

    def realm(self):
        return realm_record(self.call(f"/admin/realms/{REALM}", bearer=self.admin))

    def set_not_before(self, value):
        self.call(f"/admin/realms/{REALM}", "PUT", json.dumps({"notBefore": number(value)}).encode(), self.admin)

    def token(self):
        value = self.call(f"/realms/{REALM}/protocol/openid-connect/token", "POST", urlencode({
            "grant_type": "client_credentials", "client_id": "anka-workload",
            "client_secret": self.secrets["workload"]}).encode())
        token, _header, claims, _signing, _signature = kc.parse_token(kc.text(value.get("access_token"), 16384).encode())
        wall, _ = self.budget.check(); kc.validate_claims(claims, self.config, wall, self.holder)
        return token, claims

    def status(self, token, claims, active):
        # These observations concern the exact token obtained over authenticated
        # TLS. They are diagnostics, never mapped to a local identity/grant/proof.
        value = self.call(f"/realms/{REALM}/protocol/openid-connect/token/introspect", "POST", urlencode({
            "token": token, "token_type_hint": "access_token", "client_id": "anka-preflight",
            "client_secret": self.secrets["introspection"]}).encode())
        kc.require(value.get("active") is active, "active_status")
        if active: kc.correlate(value, claims, self.config, self.holder)


def write_journal(root, record):
    fd = os.open(root / JOURNAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write((json.dumps(record, sort_keys=True) + "\n").encode()); f.flush(); os.fsync(f.fileno())
    fd = os.open(root, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def read_journal(root):
    inputs = kc.Inputs()
    value = kc.strict_json(inputs.read(root / JOURNAL, private=True, limit=4096))
    kc.require(set(value) == {"schema", "realm", "realm_id", "original", "target", "request", "binding"}
               and type(value["schema"]) is int and value["schema"] == 1 and value["realm"] == REALM,
               "recovery_record")
    kc.text(value["realm_id"], 256)
    number(value["original"]); number(value["target"])
    kc.require(value["target"] > value["original"] and type(value["request"]) is str
               and re.fullmatch(r"[0-9a-f]{160}", value["request"]) is not None, "recovery_record")
    kc.require(type(value["binding"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["binding"]) is not None,
               "recovery_record")
    request = parse_request(bytes.fromhex(value["request"])); kc.require(request[0] == 1, "recovery_record")
    return value, inputs


def restore(root, remote, record, inputs):
    # Read-before-write is a conflict check, NOT compare-and-swap or proof of
    # writer exclusion. Direct administration must not run concurrently.
    identity, current = remote.realm()
    kc.require(identity == record["realm_id"] and current in (record["original"], record["target"]), "restore_conflict")
    inputs.recheck()
    if current == record["target"]: remote.set_not_before(record["original"])
    kc.require(remote.realm() == (record["realm_id"], record["original"]), "restore_readback")


def transaction(root, request, remote, check_inputs=lambda: None, binding="0" * 64):
    path = root / JOURNAL
    if request[0] == 2:
        record, journal_inputs = read_journal(root)
        kc.require(record["binding"] == binding, "recovery_binding")
        remote.login(); check_inputs(); restore(root, remote, record, journal_inputs)
        journal_inputs.recheck(); check_inputs(); path.unlink()
        return reply(request, record["original"], record["target"], record["original"], 8)
    kc.require(not path.exists() and not path.is_symlink(), "recovery_required")
    remote.login(); identity, original = remote.realm()
    token, claims = remote.token(); remote.status(token, claims, True)
    issued = number(claims["iat"]); target = number(issued + 1)
    kc.require(target > original, "revocation_target")
    record = {"schema": 1, "realm": REALM, "realm_id": identity, "original": original,
              "target": target, "request": REQUEST.pack(QMAGIC, *request).hex(), "binding": binding}
    check_inputs(); write_journal(root, record)
    stored, journal_inputs = read_journal(root)
    kc.require(stored == record, "recovery_record")
    # Any failure after this point leaves a private recovery journal. No blind
    # automatic retry/restore or claim that an uncertain mutation had no effect.
    remote.set_not_before(target)
    kc.require(remote.realm() == (identity, target), "change_readback")
    remote.status(token, claims, False)
    check_inputs(); restore(root, remote, record, journal_inputs)
    fresh, fresh_claims = remote.token(); remote.status(fresh, fresh_claims, True)
    journal_inputs.recheck(); check_inputs(); path.unlink()
    return reply(request, original, target, original, 31)


def perform(root, request):
    root = Path(root).absolute(); root_check(root)
    lock_fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(lock_fd)
        kc.require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077, "state_lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inputs = kc.Inputs(); config = kc.load_config(root / "config.json", inputs)
        manifest = kc.strict_json(inputs.read(root / "lab.json", private=True))
        port = manifest.get("port")
        kc.require(type(port) is int and 1024 <= port <= 65535 and manifest.get("profile") == kc.PROFILE
                   and config["issuer"] == f"https://localhost:{port}/realms/{REALM}", "lab_profile")
        kc.require(config["audience"] == "anka-preflight" and config["issuing_client"] == "anka-workload"
                   and config["introspection_client"] == "anka-preflight", "lab_profile")
        # Pin exact local credential paths; no cross-directory alternate inputs.
        for key, name in (("ca_file", "ca.pem"), ("holder_cert_file", "holder.pem"),
                          ("holder_key_file", "holder.key"), ("introspection_secret_file", "introspection.secret")):
            kc.require(Path(config[key]).absolute() == root / name, "lab_profile")
        secrets = {name: kc.text(inputs.read(root / (name + ".secret"), private=True, limit=4096).decode(), 4096)
                   for name in ("admin", "workload", "introspection")}
        material = {name: inputs.read(root / name, private=True) for name in ("ca.pem", "holder.pem", "holder.key")}
        holder = kc.b64(hashlib.sha256(ssl.PEM_cert_to_DER_cert(material["holder.pem"].decode("ascii"))).digest())
        binding = hashlib.sha256(json.dumps(sorted((path.name, saved[1].hex()) for path, saved in inputs.saved.items()),
                                             separators=(",", ":")).encode()).hexdigest()
        budget = AdminBudget()
        with tempfile.TemporaryDirectory(prefix="anka-ac110-") as directory:
            directory = Path(directory)
            for name, raw in material.items():
                p = directory / name; p.write_bytes(raw); p.chmod(0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cafile=str(directory / "ca.pem"))
            context.load_cert_chain(str(directory / "holder.pem"), str(directory / "holder.key"), password="")
            remote = Remote(config, port, context, budget, secrets, holder)
            result = transaction(root, request, remote, inputs.recheck, binding)
            budget.check(); inputs.recheck(); return result
    finally:
        os.close(lock_fd)


def save_failure(root, error):
    """Private, fixed-vocabulary diagnostics; never raw exception text."""
    root = Path(root).absolute(); root_check(root)
    reasons = {"recovery_required", "recovery_binding", "restore_conflict", "restore_readback", "change_readback",
               "recovery_record", "input_changed", "input_file", "input_owner", "input_permissions",
               "lab_profile", "state_lock", "request_size", "request_shape", "active_status",
               "revocation_target", "realm_identity", "realm_number", "http_status", "http_headers",
               "http_framing", "content_type", "content_encoding", "response_size", "wire_size",
               "duplicate_claim", "json_syntax", "json_depth", "json_number", "json_object",
               "transport", "deadline", "clock", "work_exhausted"}
    if isinstance(error, kc.Denied): reason = str(error) if str(error) in reasons else "validation_denied"
    elif isinstance(error, BlockingIOError): reason = "control_busy"
    elif isinstance(error, ssl.SSLError): reason = "tls_failure"
    elif isinstance(error, OSError): reason = "local_io_failure"
    else: reason = "worker_error"
    data = {"schema": 1, "status": "control_probe_failed", "reason": reason,
            "recovery_required": (root / JOURNAL).exists(), "current_authority": "unknown",
            "live_admission": False, "boot_authorized": False}
    path = root / ("control-failure-" + str(time.time_ns()) + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f: json.dump(data, f, sort_keys=True); f.write("\n")


def main(argv=None):
    os.umask(0o077)
    parser = kc.Parser(description=__doc__); parser.add_argument("--state", required=True)
    args = None
    try:
        args = parser.parse_args(argv)
        request = parse_request(sys.stdin.buffer.read(REQUEST.size + 1))
        result = perform(args.state, request)
        sys.stdout.buffer.write(result); sys.stdout.buffer.flush(); return 0
    except Exception as error:
        if args is not None:
            try: save_failure(args.state, error)
            except Exception: pass
        # Fixed message only; never echo arguments, tokens, TLS errors or paths.
        print("AC110 worker denied; inspect private recovery state before another probe.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

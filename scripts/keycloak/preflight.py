#!/usr/bin/env python3
"""KC110 host diagnostic. Standard library + OpenSSL; no live Anka authority."""
import argparse
import base64
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote_plus, urlencode, urlsplit

PROFILE = "keycloak-26.8.1-rs256-mtls-v1"
JSON_LIMIT = 16384
FILE_LIMIT = 65536
SUPERVISOR_SECONDS = 30


class Denied(Exception):
    """Only fixed internal reason codes may cross the diagnostic boundary."""


def require(ok, code):
    if not ok:
        raise Denied(code)


def strict_json(raw):
    require(0 < len(raw) <= JSON_LIMIT, "json_size")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_claim")
            result[key] = value
        return result

    def constant(_):
        raise Denied("json_number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Denied("json_syntax") from None

    def bounded(item, depth=0):
        require(depth <= 16, "json_depth")
        if isinstance(item, dict):
            for v in item.values():
                bounded(v, depth + 1)
        elif type(item) is float:
            require(math.isfinite(item), "json_number")
        elif isinstance(item, list):
            for v in item:
                bounded(v, depth + 1)
    bounded(value)
    require(type(value) is dict, "json_object")
    return value


def text(value, maximum=2048):
    require(type(value) is str and 0 < len(value) <= maximum
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), "claim_string")
    return value


def uint(value):
    require(type(value) is int and 0 <= value < 2**64, "claim_time")
    return value


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value):
    require(type(value) is str and 0 < len(value) <= JSON_LIMIT
            and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None, "base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise Denied("base64url") from None
    require(b64(raw) == value, "base64url")
    return raw


class Inputs:
    """Read bounded regular files once, then detect replacement/change before output."""
    def __init__(self):
        self.saved = {}

    def read(self, path, private=False, limit=FILE_LIMIT):
        path = Path(path).absolute()
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as f:
                st = os.fstat(f.fileno())
                require(stat.S_ISREG(st.st_mode) and st.st_size <= limit, "input_file")
                require(st.st_uid == os.getuid(), "input_owner")
                require(not (st.st_mode & (0o077 if private else 0o022)), "input_permissions")
                raw = f.read(limit + 1)
                require(0 < len(raw) <= limit, "input_size")
                end = os.fstat(f.fileno())
                stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                require(stamp(st) == stamp(end), "input_changed")
        except OSError:
            raise Denied("input_file") from None
        signature = (stamp(st), hashlib.sha256(raw).digest(), private, limit)
        if path in self.saved:
            require(self.saved[path] == signature, "input_changed")
        self.saved[path] = signature
        return raw

    def recheck(self):
        for path, (_, _, private, limit) in list(self.saved.items()):
            self.read(path, private, limit)


class Budget:
    def __init__(self, seconds, wall=time.time, mono=time.monotonic):
        self.wall_fn, self.mono_fn = wall, mono
        self.last_wall, self.last_tick = wall(), mono()
        require(math.isfinite(self.last_wall) and 0 <= self.last_wall < 2**64,
                "clock")
        require(math.isfinite(self.last_tick), "clock")
        self.deadline = self.last_tick + seconds
        self.remaining = 8

    def check(self):
        wall, tick = self.wall_fn(), self.mono_fn()
        require(math.isfinite(wall) and math.isfinite(tick)
                and self.last_wall <= wall < 2**64 and tick >= self.last_tick, "clock")
        self.last_wall, self.last_tick = wall, tick
        require(tick < self.deadline, "deadline")
        return int(wall), tick

    def spend(self):
        # No refunds on malformed input, crypto failure, timeout or HTTP denial.
        require(self.remaining > 0, "work_exhausted")
        self.remaining -= 1
        return self.check()

    def timeout(self):
        _, now = self.check()
        return max(0.001, min(3.0, self.deadline - now))


def load_config(path, inputs):
    config = strict_json(inputs.read(path, private=True, limit=JSON_LIMIT))
    required = {"schema", "profile", "issuer", "audience", "issuing_client",
                "introspection_client", "introspection_secret_file", "token_file",
                "ca_file", "holder_cert_file", "holder_key_file", "timeout_seconds",
                "max_observation_age_seconds"}
    require(set(config) == required and type(config["schema"]) is int
            and config["schema"] == 1 and config["profile"] == PROFILE, "configuration")
    issuer = text(config["issuer"])
    try:
        url = urlsplit(issuer)
        port = url.port
    except ValueError:
        raise Denied("issuer_url") from None
    require(url.scheme == "https" and url.hostname is not None and not url.username
            and not url.password and not url.query and not url.fragment
            and re.fullmatch(r"/realms/[A-Za-z0-9_-]+", url.path) is not None
            and issuer.isascii() and "\\" not in issuer and "%" not in issuer,
            "issuer_url")
    require(port is None or 1 <= port <= 65535, "issuer_url")
    for key in ("audience", "issuing_client", "introspection_client"):
        text(config[key], 256)
    # Pinned initial resource-server profile, including introspection audience.
    require(config["audience"] == config["introspection_client"], "configuration")
    for key, upper in (("timeout_seconds", 20), ("max_observation_age_seconds", 5)):
        require(type(config[key]) is int and 1 <= config[key] <= upper, "configuration")
    for key in required:
        if key.endswith("_file"):
            p = Path(text(config[key]))
            config[key] = p if p.is_absolute() else Path(path).absolute().parent / p
    return config


def audiences(value):
    if type(value) is str:
        return {text(value)}
    require(type(value) is list and 0 < len(value) <= 32, "audience")
    result = [text(x) for x in value]
    require(len(result) == len(set(result)), "audience")
    return set(result)


def validate_claims(claims, config, wall, holder):
    require(claims.get("iss") == config["issuer"], "issuer")
    require(config["audience"] in audiences(claims.get("aud")), "audience")
    require(claims.get("azp") == config["issuing_client"], "client")
    require(claims.get("typ") == "Bearer", "token_type")
    text(claims.get("sub"), 256)
    issued, expiry = uint(claims.get("iat")), uint(claims.get("exp"))
    first = uint(claims.get("nbf", issued))
    require(issued <= wall and issued < expiry and first <= wall < expiry
            and first < expiry, "token_time")
    cnf = claims.get("cnf")
    require(type(cnf) is dict and set(cnf) == {"x5t#S256"}
            and cnf["x5t#S256"] == holder, "holder")
    require(len(unb64(cnf["x5t#S256"])) == 32, "holder")


def parse_token(raw):
    require(0 < len(raw) <= JSON_LIMIT, "token_size")
    try:
        token = raw.decode("ascii")
    except UnicodeError:
        raise Denied("token_encoding") from None
    # Exact file contents: no trimming, comments, whitespace or newline suffix.
    parts = token.split(".")
    require(len(parts) == 3, "token_shape")
    header, claims = strict_json(unb64(parts[0])), strict_json(unb64(parts[1]))
    require(set(header) == {"alg", "typ", "kid"}
            and header["alg"] == "RS256" and header["typ"] == "JWT", "token_header")
    text(header["kid"], 256)
    return token, header, claims, (parts[0] + "." + parts[1]).encode("ascii"), unb64(parts[2])


def der(tag, data):
    n = len(data)
    size = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, "big")
    return bytes([tag]) + size + data


def rsa_key(jwks, kid):
    keys = jwks.get("keys")
    require(type(keys) is list and 0 < len(keys) <= 16
            and all(type(k) is dict for k in keys), "jwks")
    matching = [k for k in keys if k.get("kid") == kid]
    require(len(matching) == 1, "key_selection")
    key = matching[0]
    require(key.get("kty") == "RSA" and key.get("use") == "sig"
            and key.get("alg") == "RS256"
            and ("key_ops" not in key or key["key_ops"] == ["verify"])
            and not any(k in key for k in ("d", "p", "q", "dp", "dq", "qi")), "key_use")
    n, e = unb64(key.get("n")), unb64(key.get("e"))
    require(n[0] != 0 and e[0] != 0 and 2048 <= int.from_bytes(n, "big").bit_length() <= 4096
            and 3 <= int.from_bytes(e, "big") <= 2**32-1
            and int.from_bytes(e, "big") % 2 == 1, "key_strength")
    integer = lambda raw: der(2, (b"\x00" if raw[0] & 128 else b"") + raw)
    rsa = der(0x30, integer(n) + integer(e))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    spki = der(0x30, algorithm + der(3, b"\x00" + rsa))
    encoded = base64.b64encode(spki)
    pem = b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(encoded[i:i+64] for i in range(0,len(encoded),64)) + b"\n-----END PUBLIC KEY-----\n"
    return pem, len(n)


def verify_signature(pem, signing, signature, directory, budget):
    budget.spend()
    paths = [directory / name for name in ("issuer.pem", "signed.bin", "signature.bin")]
    for p, data in zip(paths, (pem, signing, signature)):
        p.write_bytes(data)
        p.chmod(0o600)
    try:
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(paths[0]),
                                 "-signature", str(paths[2]), str(paths[1])],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=budget.timeout(),
                                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                     "OPENSSL_CONF": os.devnull})
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("crypto_tool") from None
    require(result.returncode == 0, "signature")
    budget.check()


class WireInput:
    """Cap HTTP status/headers, chunk framing, body and trailers together."""
    def __init__(self, source, budget):
        self.source, self.budget, self.remaining = source, budget, 131072

    def take(self, method, size=-1):
        self.budget.check()
        cap = self.remaining + 1
        data = getattr(self.source, method)(cap if size < 0 else min(size, cap))
        self.remaining -= len(data)
        require(self.remaining >= 0, "wire_size")
        self.budget.check()
        return data

    def read(self, size=-1):
        return self.take("read", size)

    def readline(self, size=-1):
        return self.take("readline", size)

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def flush(self):
        self.source.flush()

    def close(self):
        self.source.close()

    @property
    def closed(self):
        return self.source.closed


class BoundedResponse(http.client.HTTPResponse):
    def __init__(self, sock, budget, **kwargs):
        super().__init__(sock, **kwargs)
        self.fp = WireInput(self.fp, budget)


def https_json(url, context, budget, body=None, headers=None):
    """No proxies, discovery, redirects, decompression, retry or positive cache."""
    budget.spend()
    endpoint = urlsplit(url)
    require(endpoint.scheme == "https" and endpoint.hostname is not None
            and not endpoint.username and not endpoint.password and not endpoint.fragment,
            "endpoint")
    request_headers = {"Accept": "application/json", "Accept-Encoding": "identity",
                       "Connection": "close"}
    request_headers.update(headers or {})
    conn = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
                                      timeout=budget.timeout(), context=context)
    conn.response_class = lambda sock, **kwargs: BoundedResponse(sock, budget, **kwargs)
    response = None
    try:
        conn.request("POST" if body is not None else "GET", endpoint.path,
                     body=body, headers=request_headers)
        response = conn.getresponse()
        require(response.status == 200, "http_status")
        # stdlib also bounds parsing to 100 header lines of at most 64 KiB each.
        require(sum(len(k)+len(v)+4 for k,v in response.getheaders()) <= 16384, "http_headers")
        for name in ("Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding"):
            require(len(response.headers.get_all(name, [])) <= 1, "http_headers")
        require(response.getheader("Content-Type", "").split(";",1)[0].strip().lower()
                == "application/json", "content_type")
        require(response.getheader("Content-Encoding", "identity").lower() == "identity", "content_encoding")
        length, encoding = response.getheader("Content-Length"), response.getheader("Transfer-Encoding")
        require(encoding is None or (encoding.lower() == "chunked" and length is None), "http_framing")
        if length is not None:
            require(re.fullmatch(r"[0-9]{1,8}", length) is not None
                    and int(length) <= JSON_LIMIT, "response_size")
        parts, total = [], 0
        while True:
            if conn.sock is not None:
                conn.sock.settimeout(budget.timeout())
            block = response.read(min(1024, JSON_LIMIT + 1 - total))
            budget.check()
            if not block:
                break
            parts.append(block)
            total += len(block)
            require(total <= JSON_LIMIT, "response_size")
        raw = b"".join(parts)
        if length is not None:
            require(len(raw) == int(length), "http_framing")
        return strict_json(raw)
    except (OSError, http.client.HTTPException, ValueError):
        raise Denied("transport") from None
    finally:
        if response is not None:
            response.close()
        conn.close()


def same_json(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def correlate(info, claims, config, holder):
    require(info.get("active") is True, "inactive")
    for key in ("iss", "sub", "exp", "iat"):
        require(key in info and type(info[key]) is type(claims[key])
                and info[key] == claims[key], "introspection_mismatch")
    require(info.get("client_id") == config["issuing_client"], "introspection_mismatch")
    require(audiences(info.get("aud")) == audiences(claims["aud"]), "introspection_mismatch")
    require(info.get("cnf") == {"x5t#S256": holder}, "introspection_mismatch")
    # Every echoed JWT claim must agree, including nested roles and optional nbf.
    for key in set(claims) & set(info):
        if key == "aud":
            continue
        require(same_json(info[key], claims[key]), "introspection_mismatch")
    require("token_type" not in info or info["token_type"] == "Bearer", "token_type")


def input_binding(inputs):
    """Full SHA-256 commitment to selected paths and exact immutable file bytes."""
    digest = hashlib.sha256(b"ANKA-LG110-INPUTS-v1\0")
    for path, (_, value, private, limit) in sorted(inputs.saved.items(), key=lambda kv: str(kv[0])):
        name = os.fsencode(path)
        digest.update(len(name).to_bytes(8, "little") + name + value)
        digest.update(bytes([private]) + limit.to_bytes(8, "little"))
    return digest.digest()


def verify_identity(config_path, expected=None, allow_inactive=False):
    """Private verifier entry; callers must retain their original query deadline.

    expected binds full immutable bytes and deployment-selected identity strings.
    This function never issues local grants or verifies a workload channel.
    """
    require(not allow_inactive or expected is not None, "identity_binding")
    inputs = Inputs()
    config = load_config(config_path, inputs)
    budget = Budget(config["timeout_seconds"])
    wall, _ = budget.spend()
    token_bytes = inputs.read(config["token_file"], private=True, limit=JSON_LIMIT)
    token, header, claims, signing, signature = parse_token(token_bytes)
    certificate = inputs.read(config["holder_cert_file"])
    private_key = inputs.read(config["holder_key_file"], private=True)
    ca = inputs.read(config["ca_file"])
    secret = inputs.read(config["introspection_secret_file"], private=True, limit=4096)
    try:
        certificate_text = certificate.decode("ascii")
        require(certificate_text.count("-----BEGIN CERTIFICATE-----") == 1
                and certificate_text.count("-----END CERTIFICATE-----") == 1, "certificate")
        holder = b64(hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate_text)).digest())
        secret_text = text(secret.decode("utf-8"), 4096)
    except (ValueError, UnicodeError):
        raise Denied("credential_encoding") from None
    validate_claims(claims, config, wall, holder)
    if expected is not None:
        require(token_bytes == expected["token"]
                and config["issuer"] == expected["issuer"]
                and config["audience"] == expected["audience"]
                and config["issuing_client"] == expected["client"]
                and claims["sub"] == expected["subject"]
                and unb64(holder) == expected["holder"], "identity_binding")
    with tempfile.TemporaryDirectory(prefix="anka-kc110-") as directory_name:
        directory = Path(directory_name)
        for name, data in (("holder.pem", certificate), ("holder.key", private_key), ("ca.pem", ca)):
            path = directory / name
            path.write_bytes(data)
            path.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(directory / "ca.pem"))
        # Noninteractive: encrypted key files need a separate future input contract.
        context.load_cert_chain(str(directory / "holder.pem"), str(directory / "holder.key"), password="")
        jwks = https_json(config["issuer"] + "/protocol/openid-connect/certs", context, budget)
        pem, signature_size = rsa_key(jwks, header["kid"])
        require(len(signature) == signature_size, "signature")
        verify_signature(pem, signing, signature, directory, budget)
        wall, started = budget.check()
        validate_claims(claims, config, wall, holder)
        auth = base64.b64encode((quote_plus(config["introspection_client"], safe="") + ":"
                                + quote_plus(secret_text, safe="")).encode()).decode("ascii")
        body = urlencode({"token": token, "token_type_hint": "access_token"}).encode("ascii")
        info = https_json(config["issuer"] + "/protocol/openid-connect/token/introspect",
                          context, budget, body,
                          {"Authorization": "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded"})
        wall, observed = budget.check()
        require(observed - started < config["max_observation_age_seconds"], "observation_expired")
        # A bare inactive response is meaningful only on this authenticated,
        # direct, single-token request after signature and expected-byte checks.
        inactive = allow_inactive and info == {"active": False} and type(info.get("active")) is bool
        if not inactive:
            correlate(info, claims, config, holder)
        budget.spend()
        inputs.recheck()
        wall, now = budget.check()
        validate_claims(claims, config, wall, holder)
        require(started <= observed <= now and now - started < config["max_observation_age_seconds"],
                "observation_expired")
    wall, now = budget.check()
    validate_claims(claims, config, wall, holder)
    require(now - started < config["max_observation_age_seconds"], "observation_expired")
    return {"config": config, "claims": claims, "token": token_bytes,
            "holder": holder, "certificate": certificate, "active": not inactive,
            "input_binding": input_binding(inputs),
            "observation_age_ms": int((now-started)*1000)}


def perform(config_path):
    verified = verify_identity(config_path)
    config, claims = verified["config"], verified["claims"]
    token_bytes, holder = verified["token"], verified["holder"]
    return {"schema": 1, "status": "preflight_valid", "profile": PROFILE,
            "issuer": config["issuer"], "subject": claims["sub"],
            "token_sha256": hashlib.sha256(token_bytes).hexdigest(), "holder_thumbprint": holder,
            "expires_at": claims["exp"], "observation_age_ms": verified["observation_age_ms"],
            "current_authority": "unknown", "live_admission": False, "boot_authorized": False}


def failure(code):
    return {"schema": 1, "status": "denied", "reason": code,
            "current_authority": "unknown", "live_admission": False, "boot_authorized": False}


class Parser(argparse.ArgumentParser):
    def error(self, _):
        # Never echo an unexpected argument that might contain a credential.
        raise Denied("arguments")


def worker(path):
    os.umask(0o077)
    try:
        result = perform(path)
        code = 0
    except Denied as error:
        result, code = failure(str(error)), 1
    except Exception:
        # Exception messages from TLS/HTTP/JSON/OpenSSL are not safe diagnostics.
        result, code = failure("preflight_error"), 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return code


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = Parser(description="KC110 identity preflight only; never live/boot authorization.")
    parser.add_argument("--config", required=True, help="private JSON configuration; credentials are file inputs")
    try:
        args = parser.parse_args(argv)
    except Denied as error:
        print(json.dumps(failure(str(error))))
        return 2
    try:
        # Import-only worker entry: no public CLI option can skip supervision.
        entry = "import runpy,sys; sys.exit(runpy.run_path(sys.argv[1])['worker'](sys.argv[2]))"
        child = subprocess.Popen([sys.executable, "-I", "-c", entry,
                                  str(Path(__file__).resolve()), args.config], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
    except OSError:
        print(json.dumps(failure("worker_start")))
        return 1
    try:
        output, _ = child.communicate(timeout=SUPERVISOR_SECONDS)
        require(len(output) <= JSON_LIMIT, "worker_output")
        result = strict_json(output)
        require(result.get("live_admission") is False and result.get("boot_authorized") is False
                and result.get("current_authority") == "unknown", "worker_output")
        require((child.returncode == 0 and result.get("status") == "preflight_valid")
                or (child.returncode == 1 and result.get("status") == "denied"), "worker_output")
        print(json.dumps(result, sort_keys=True))
        return child.returncode
    except (Denied, subprocess.TimeoutExpired):
        # Includes DNS stalls and any descendant OpenSSL process, independent of
        # socket-level timeouts. The supervisor never handles raw credentials.
        print(json.dumps(failure("worker_deadline_or_failure")))
        return 1
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        if child.stdout is not None:
            child.stdout.close()


if __name__ == "__main__":
    sys.exit(main())

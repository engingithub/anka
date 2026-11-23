#!/usr/bin/env python3
"""Real local mTLS + RSA fixtures; no Rust build, Podman or network service needed."""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p, lab = module("preflight"), module("lab")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.reply(False)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.requests.append((self.path, self.headers.get("Authorization"), body,
                                     self.connection.getpeercert(binary_form=True)))
        self.reply(True)

    def reply(self, introspection):
        server = self.server
        if introspection and server.callback:
            server.callback()
        if server.mode == "outage":
            self.send_response(503)
            self.end_headers()
            return
        if server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://untrusted.invalid/stolen")
            self.end_headers()
            return
        if server.mode == "slow":
            time.sleep(1.2)
        data = server.info if introspection else server.jwks
        raw = json.dumps(data).encode()
        if server.mode == "duplicate":
            raw = b'{"keys":[],"keys":[]}'
        if server.mode == "oversized":
            raw = b"x" * (p.JSON_LIMIT + 1)
        if server.mode == "malformed":
            raw = b'{"keys":'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if server.mode in ("chunked", "trailer_flood"):
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(("%x\r\n" % len(raw)).encode() + raw + b"\r\n0\r\n")
            if server.mode == "trailer_flood":
                self.wfile.write((b"X-Excess: " + b"a" * 2000 + b"\r\n") * 140)
            self.wfile.write(b"\r\n")
            return
        self.send_header("Content-Length", str(len(raw)))
        if server.mode == "duplicate_length":
            self.send_header("Content-Length", str(len(raw)))
        if server.mode == "compressed":
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        self.wfile.write(raw)


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="anka KC110 fixture ")
        cls.root = Path(cls.temp.name)
        lab.certificates(cls.root)
        lab.run(["openssl", "genrsa", "-out", str(cls.root / "issuer.key"), "2048"])
        cls.issuer = cls.root / "issuer.key"
        cls.key = cls.jwk(cls.issuer, "key-1")
        cls.server = Server(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cls.root / "server.pem"), str(cls.root / "server.key"))
        ctx.load_verify_locations(cafile=str(cls.root / "ca.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.holder = p.b64(p.hashlib.sha256(ssl.PEM_cert_to_DER_cert((cls.root / "holder.pem").read_text())).digest())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    @staticmethod
    def jwk(key, kid):
        modulus = lab.run(["openssl", "rsa", "-in", str(key), "-modulus", "-noout"]).decode().strip().split("=", 1)[1]
        return {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
                "n": p.b64(bytes.fromhex(modulus)), "e": p.b64(bytes.fromhex("010001"))}

    def write(self, name, data):
        path = self.root / name
        if path.exists() or path.is_symlink():
            path.unlink()
        lab.private(path, data)
        return path

    def setUp(self):
        self.config = lab.configuration(self.server.server_port)
        self.path = self.write("config.json", json.dumps(self.config))
        self.write("introspection.secret", "private-client-secret")
        self.server.jwks = {"keys": [copy.deepcopy(self.key)]}
        self.server.requests, self.server.callback, self.server.mode = [], None, "normal"
        now = int(time.time())
        self.claims = {"iss": self.config["issuer"], "sub": "service-account-workload",
                       "aud": ["anka-preflight", "account"], "azp": "anka-workload", "typ": "Bearer",
                       "iat": now - 1, "exp": now + 120, "jti": "opaque-token-identity",
                       "cnf": {"x5t#S256": self.holder}}
        self.token()

    def token(self, header=None, claims=None, key=None):
        header = header or {"alg": "RS256", "typ": "JWT", "kid": "key-1"}
        claims = claims or self.claims
        encoded = lambda x: p.b64(json.dumps(x, separators=(",", ":")).encode())
        signing = (encoded(header) + "." + encoded(claims)).encode()
        self.write("signing", signing)
        sig = lab.run(["openssl", "dgst", "-sha256", "-sign", str(key or self.issuer), str(self.root / "signing")])
        self.raw_token = signing.decode() + "." + p.b64(sig)
        self.write("access.token", self.raw_token)
        self.server.info = dict(claims, active=True, client_id="anka-workload", token_type="Bearer")
        return self.raw_token

    def configure(self, **updates):
        self.config.update(updates)
        self.path = self.write("config.json", json.dumps(self.config))

    def denied(self, expected=None):
        with self.assertRaises(p.Denied) as error:
            p.perform(self.path)
        if expected:
            self.assertEqual(str(error.exception), expected)
        return error.exception

    def test_real_rs256_mtls_and_correlated_post_without_authority(self):
        result = p.perform(self.path)
        self.assertEqual(result["status"], "preflight_valid")
        self.assertIs(result["live_admission"], False)
        self.assertIs(result["boot_authorized"], False)
        self.assertEqual(result["current_authority"], "unknown")
        path, auth, body, peer = self.server.requests[0]
        self.assertTrue(path.endswith("/token/introspect"))
        self.assertEqual(parse_qs(body.decode())["token"], [self.raw_token])
        self.assertEqual(base64.b64decode(auth.split()[1]), b"anka-preflight:private-client-secret")
        self.assertEqual(p.b64(p.hashlib.sha256(peer).digest()), self.holder)
        self.assertNotIn(self.raw_token, json.dumps(result))
        self.assertNotIn("private-client-secret", json.dumps(result))

    def test_real_signature_substitution_is_rejected(self):
        token = self.raw_token.split(".")
        signature = bytearray(p.unb64(token[2]))
        signature[8] ^= 1
        token[2] = p.b64(signature)
        self.write("access.token", ".".join(token))
        self.denied("signature")
        self.assertEqual(self.server.requests, [])

    def test_issuer_audience_client_type_and_holder_fail_before_introspection(self):
        cases = [("iss", "https://other.invalid/realms/test", "issuer"), ("aud", "other", "audience"),
                 ("azp", "other", "client"), ("typ", "ID", "token_type"),
                 ("cnf", {"x5t#S256": p.b64(b"x" * 32)}, "holder")]
        for field, value, reason in cases:
            with self.subTest(field=field):
                claims = dict(self.claims, **{field: value})
                self.token(claims=claims)
                self.denied(reason)
        self.assertEqual(self.server.requests, [])

    def test_expiry_boundary_future_iat_nbf_and_bool_time(self):
        now = int(time.time())
        for changes in ({"exp": now}, {"iat": now + 100}, {"nbf": now + 100}, {"iat": True}):
            with self.subTest(changes=changes):
                self.token(claims=dict(self.claims, **changes))
                self.denied()

    def test_header_algorithm_type_and_remote_key_injection(self):
        for change in ({"alg": "none"}, {"alg": "HS256"}, {"typ": "at+jwt"}, {"jku": "https://evil.invalid"}):
            with self.subTest(change=change):
                self.token(header=dict(alg="RS256", typ="JWT", kid="key-1", **{} ) | change)
                self.denied("token_header")

    def test_exact_token_no_tail_padding_or_oversize(self):
        for raw in (self.raw_token + "\n", self.raw_token + ".tail", self.raw_token + "=", "x" * 16385):
            self.write("access.token", raw)
            self.denied()

    def test_strict_json_duplicate_nested_depth_and_numbers(self):
        for raw in (b'{"active":true,"active":false}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}',
                    b'{"x":1e999}', b'[]', b'{"x":' + b'[' * 18 + b'0' + b']' * 18 + b'}'):
            with self.subTest(raw=raw), self.assertRaises(p.Denied):
                p.strict_json(raw)

    def test_noncanonical_base64url_rejected(self):
        for value in ("YQ=", "YR", "A", "a b", "", "+/"):
            with self.subTest(value=value), self.assertRaises(p.Denied):
                p.unb64(value)

    def test_unknown_duplicate_weak_and_wrong_use_keys(self):
        for keys in ([], [dict(self.key, kid="other")], [self.key, self.key],
                     [dict(self.key, use="enc")], [dict(self.key, n=p.b64(b"\x01"))],
                     [dict(self.key, key_ops=["sign"])], [dict(self.key, d="secret")]):
            self.server.jwks = {"keys": keys}
            self.denied()

    def test_real_rotation_fresh_key_then_withdrawal_no_cache(self):
        second = self.root / "second.key"
        lab.run(["openssl", "genrsa", "-out", str(second), "2048"])
        old = self.raw_token
        self.server.jwks = {"keys": [self.key, self.jwk(second, "rotated")]}
        self.token(header={"alg": "RS256", "typ": "JWT", "kid": "rotated"}, key=second)
        self.assertEqual(p.perform(self.path)["status"], "preflight_valid")
        self.write("access.token", old)
        self.server.jwks = {"keys": [self.jwk(second, "rotated")]}
        self.denied("key_selection")

    def test_inactive_and_nonboolean_active(self):
        for active in (False, 1, "true", None):
            self.server.info["active"] = active
            self.denied("inactive")

    def test_correlation_rejects_different_token_scope_and_nested_types(self):
        for key, value in (("sub", "someone-else"), ("exp", self.claims["exp"] + 1),
                           ("client_id", "other"), ("aud", ["anka-preflight"]),
                           ("jti", "other-token"), ("cnf", {"x5t#S256": "other"})):
            self.server.info = dict(self.claims, active=True, client_id="anka-workload")
            self.server.info[key] = value
            self.denied("introspection_mismatch")
        self.claims["nested"] = {"value": 1}
        self.token()
        self.server.info["nested"] = {"value": True}
        self.denied("introspection_mismatch")

    def test_required_introspection_fields_cannot_be_omitted(self):
        for key in ("iss", "sub", "exp", "iat", "client_id", "aud", "cnf"):
            self.server.info = dict(self.claims, active=True, client_id="anka-workload")
            del self.server.info[key]
            self.denied()

    def test_http_outage_redirect_malformed_oversized_and_encoding(self):
        for mode in ("outage", "redirect", "malformed", "oversized", "duplicate", "duplicate_length", "compressed"):
            with self.subTest(mode=mode):
                self.server.mode = mode
                self.denied()

    def test_chunked_body_and_bounded_trailers(self):
        self.server.mode = "chunked"
        self.assertEqual(p.perform(self.path)["status"], "preflight_valid")
        self.server.mode = "trailer_flood"
        self.denied("wire_size")

    def test_wire_budget_counts_headers_reads_and_lines(self):
        wire = p.WireInput(io.BytesIO(b"x" * 140000), p.Budget(5))
        self.assertEqual(len(wire.read(100000)), 100000)
        with self.assertRaisesRegex(p.Denied, "wire_size"):
            wire.readline()

    def test_lab_configuration_has_explicit_tls_holder_and_client_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "lab"
            image = json.dumps([{"Id": "sha256:fixture", "RepoDigests": ["fixture@sha256:fixture"]}]).encode()
            # Avoid running Podman: test the generated realm/configuration artifacts.
            with patch.object(lab, "certificates"), patch.object(lab, "run", return_value=image):
                manifest = lab.prepare(root, 8443)
            realm = json.loads((root / ("import/" + lab.REALM + "-realm.json")).read_text())
            workload = next(c for c in realm["clients"] if c["clientId"] == "anka-workload")
            self.assertEqual(workload["attributes"]["tls.client.certificate.bound.access.tokens"], "true")
            self.assertFalse(workload["publicClient"])
            self.assertFalse(workload["directAccessGrantsEnabled"])
            self.assertIn("KC_HTTPS_CLIENT_AUTH=required", (root / "keycloak.env").read_text())
            self.assertIn("26.8.1", manifest["images"]["keycloak"]["reference"])
            self.assertEqual(manifest["images"]["keycloak"]["id"], "sha256:fixture")
            self.assertEqual((root / "config.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                lab.prepare(root, 8443)

    def test_wrong_ca_and_certificate_key_pair_fail_closed(self):
        self.configure(ca_file="other.pem")
        self.denied("transport")
        self.configure(ca_file="ca.pem", holder_key_file="other.key")
        with self.assertRaises(ssl.SSLError):
            p.perform(self.path)

    def test_changed_input_during_introspection_is_rejected(self):
        self.server.callback = lambda: self.write("introspection.secret", "replaced-client-secret")
        self.denied("input_changed")

    def test_late_response_does_not_refresh_observation_age(self):
        self.configure(max_observation_age_seconds=1)
        self.server.callback = lambda: time.sleep(1.1)
        self.denied("observation_expired")

    def test_deadline_applies_to_network(self):
        self.configure(timeout_seconds=1)
        self.server.mode = "slow"
        before = time.monotonic()
        self.denied()
        self.assertLess(time.monotonic() - before, 3)

    def test_budget_no_refunds_deadline_and_clock_rollback(self):
        clocks = [100.0, 10.0]
        budget = p.Budget(5, lambda: clocks[0], lambda: clocks[1])
        for _ in range(8):
            budget.spend()
        with self.assertRaisesRegex(p.Denied, "work_exhausted"):
            budget.spend()
        budget = p.Budget(5, lambda: clocks[0], lambda: clocks[1])
        clocks[1] = 15
        with self.assertRaisesRegex(p.Denied, "deadline"):
            budget.check()
        clocks[:] = [100, 10]
        budget = p.Budget(5, lambda: clocks[0], lambda: clocks[1])
        clocks[0] = 99
        with self.assertRaisesRegex(p.Denied, "clock"):
            budget.check()
        clocks[:] = [100, 10]
        budget = p.Budget(5, lambda: clocks[0], lambda: clocks[1])
        clocks[1] = 9
        with self.assertRaisesRegex(p.Denied, "clock"):
            budget.check()

    def test_private_permissions_symlink_fifo_and_unknown_config(self):
        path = self.root / "access.token"
        path.chmod(0o644)
        self.denied("input_permissions")
        path.unlink()
        path.symlink_to(self.root / "introspection.secret")
        self.denied("input_file")
        path.unlink()
        os.mkfifo(path, 0o600)
        self.denied("input_file")
        path.unlink()
        self.token()
        self.configure(untrusted_setting=True)
        self.denied("configuration")

    def test_supervised_cli_acceptance_and_redacted_denial(self):
        argv = [sys.executable, "-I", str(ROOT / "preflight.py"), "--config", str(self.path)]
        result = subprocess.run(argv, capture_output=True, timeout=35)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout)["status"], "preflight_valid")
        self.server.mode = "outage"
        result = subprocess.run(argv, capture_output=True, timeout=35)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "denied")
        for sensitive in (self.raw_token.encode(), b"private-client-secret", b"BEGIN PRIVATE KEY"):
            self.assertNotIn(sensitive, result.stdout + result.stderr)

    def test_unexpected_argument_not_echoed(self):
        for flag in ("--secret", "--_worker"):
            result = subprocess.run([sys.executable, "-I", str(ROOT / "preflight.py"), flag, "NEVER-ECHO-ME"],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"NEVER-ECHO-ME", result.stdout + result.stderr)

    def test_supervisor_kills_worker_group_on_timeout(self):
        self.server.mode = "slow"
        with patch.object(p, "SUPERVISOR_SECONDS", 0.05), patch("builtins.print") as output:
            self.assertEqual(p.main(["--config", str(self.path)]), 1)
        self.assertEqual(json.loads(output.call_args.args[0])["reason"], "worker_deadline_or_failure")


if __name__ == "__main__":
    unittest.main(verbosity=2)

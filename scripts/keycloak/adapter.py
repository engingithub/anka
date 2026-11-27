#!/usr/bin/env python3
"""Private LG110 verifier worker. Only a supervised Rust adapter launches this.

No diagnostic JSON is consumed as authority. No admin endpoint or automatic
signing. Stdout is a bounded binary response over the parent-owned private pipe.
The parent enforces the original owner deadline, exact EOF, and child lifetime.
"""
import importlib.util
import hashlib
import os
from pathlib import Path
import re
import ssl
import struct
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("lg110_preflight", Path(__file__).with_name("preflight.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
MAGIC = b"LG110A1\0"
REPLY = b"LG110R1\0"
LIMIT = 24576
MAX_SIGNATURE = 512


def parse(raw):
    p.require(len(raw) <= LIMIT and raw[:8] == MAGIC, "frame")
    at = 8

    def take(n):
        nonlocal at
        p.require(n >= 0 and at + n <= len(raw), "frame")
        value = raw[at:at+n]; at += n
        return value

    def word():
        return int.from_bytes(take(8), "little")

    kind, session = word(), take(32)
    correlation = [word() for _ in range(9)]
    scope = [word() for _ in range(16)]
    holder, channel, inputs = take(32), take(32), take(32)
    max_age = word()
    p.require(1 <= max_age <= 5, "frame")
    p.require(kind in (1, 2) and any(session) and all(correlation[i] for i in range(9) if i != 6)
              and all(scope) and scope[3] in (1, 2, 3) and scope[7] in (1, 2)
              and scope[8] in (1, 2) and any(holder), "frame")
    p.require((kind == 1 and not any(channel)) or (kind == 2 and any(channel) and any(inputs)), "frame")

    def blob(limit):
        n = int.from_bytes(take(4), "little")
        p.require(0 < n <= limit, "frame")
        return take(n)

    token = blob(p.JSON_LIMIT)
    strings = [blob(n).decode("utf-8", errors="strict") for n in (2048, 256, 256, 256)]
    for value in strings:
        p.text(value)
    record = raw[:at]
    n = int.from_bytes(take(4), "little")
    p.require(n == 0 if kind == 1 else 256 <= n <= MAX_SIGNATURE, "frame")
    signature = take(n)
    p.require(at == len(raw), "frame")
    return {"kind": kind, "correlation": correlation, "scope": scope, "record": record,
            "inputs": inputs, "max_age": max_age, "signature": signature, "channel": channel,
            "expected": dict(zip(("issuer", "audience", "client", "subject"), strings),
                             token=token, holder=holder)}


def response(frame, outcome=0, times=(0, 0, 0), binding=bytes(32)):
    return REPLY + struct.pack("<4Q", outcome, *times) + binding + frame["record"]


def checked_binding(frame, binding):
    p.require(any(binding) and (not any(frame["inputs"]) or binding == frame["inputs"]), "input_changed")


def snapshot(frame, config_path):
    inputs = p.Inputs()
    config = p.load_config(config_path, inputs)
    p.require(frame["max_age"] <= config["max_observation_age_seconds"], "identity_binding")
    token = inputs.read(config["token_file"], private=True, limit=p.JSON_LIMIT)
    certificate = inputs.read(config["holder_cert_file"])
    inputs.read(config["holder_key_file"], private=True)
    inputs.read(config["ca_file"])
    inputs.read(config["introspection_secret_file"], private=True, limit=4096)
    checked_binding(frame, p.input_binding(inputs))
    expected = frame["expected"]
    p.require(token == expected["token"] and config["issuer"] == expected["issuer"]
              and config["audience"] == expected["audience"]
              and config["issuing_client"] == expected["client"], "identity_binding")
    return inputs, config, certificate


def holder(frame, config_path):
    """Verify a detached RS256 signature; never sign with the holder key.

    Reading the configured credentials for an immutable input commitment is
    separate from using that private key. Actual channel authenticity is supplied
    by the trusted transport, not by this worker or the presented signature.
    """
    inputs, config, certificate = snapshot(frame, config_path)
    budget = p.Budget(config["timeout_seconds"])
    budget.spend()
    expected = frame["expected"]
    cert_text = certificate.decode("ascii")
    p.require(cert_text.count("-----BEGIN CERTIFICATE-----") == 1
              and cert_text.count("-----END CERTIFICATE-----") == 1, "certificate")
    cert_hash = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_text)).digest()
    p.require(cert_hash == expected["holder"], "holder")
    checked_binding(frame, p.input_binding(inputs))
    with tempfile.TemporaryDirectory(prefix="anka-lg110-proof-") as dirname:
        directory = Path(dirname)
        cert = directory / "holder.pem"; cert.write_bytes(certificate); cert.chmod(0o600)

        def crypto(args):
            budget.spend()
            result = subprocess.run(["openssl", *args], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=budget.timeout(), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                                                  "OPENSSL_CONF": os.devnull})
            p.require(result.returncode == 0 and len(result.stdout) <= p.FILE_LIMIT, "holder_signature")
            budget.check()
            return result.stdout

        public = directory / "public.pem"
        public.write_bytes(crypto(["x509", "-in", str(cert), "-pubkey", "-noout"]))
        modulus = crypto(["rsa", "-pubin", "-in", str(public), "-modulus", "-noout"])
        p.require(re.fullmatch(rb"Modulus=[0-9A-Fa-f]+\s*", modulus) is not None, "holder_key")
        bits = int(modulus.split(b"=", 1)[1].strip(), 16).bit_length()
        p.require(2048 <= bits <= 4096 and len(frame["signature"]) == (bits+7)//8, "holder_key")
        signed, signature = directory / "record.bin", directory / "signature.bin"
        signed.write_bytes(frame["record"]); signature.write_bytes(frame["signature"])
        crypto(["dgst", "-sha256", "-verify", str(public), "-sigopt", "rsa_padding_mode:pkcs1",
                "-signature", str(signature), str(signed)])
        inputs.recheck(); budget.check()
        binding = p.input_binding(inputs); checked_binding(frame, binding)
        return response(frame, 1, binding=binding)


def perform(frame, config_path):
    if frame["kind"] == 2:
        return holder(frame, config_path)
    inputs, _, _ = snapshot(frame, config_path)
    verified = p.verify_identity(config_path, expected=frame["expected"], allow_inactive=True)
    inputs.recheck()
    p.require(verified["input_binding"] == p.input_binding(inputs), "input_changed")
    checked_binding(frame, verified["input_binding"])
    claims = verified["claims"]
    return response(frame, 1 if verified["active"] else 2,
                    (claims["iat"], claims.get("nbf", claims["iat"]), claims["exp"]),
                    verified["input_binding"])


def main(argv=None):
    os.umask(0o077)
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "--config":
        return 2  # Never echo unknown arguments or credentials.
    try:
        frame = parse(sys.stdin.buffer.read(LIMIT + 1))  # True EOF is mandatory.
    except Exception:
        return 1
    try:
        output = perform(frame, argv[1])
    except p.Denied as error:
        output = response(frame, 3 if str(error) in ("input_changed", "identity_binding") else 0)
    except Exception:
        # Outage, malformed evidence or verification failure cannot renew. Only
        # verified inactive on the exact authenticated request can revoke remotely.
        output = response(frame)
    sys.stdout.buffer.write(output); sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())

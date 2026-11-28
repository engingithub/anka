#!/usr/bin/env python3
"""Repair a disposable lab server certificate without rotating CA or holders."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import tempfile
import sys

import lab
import preflight as kc
import control

EXTENSIONS = ("basicConstraints=critical,CA:FALSE\n"
              "keyUsage=critical,digitalSignature,keyEncipherment\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n"
              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")


def strict_probe(ca, cert, key, hostname="localhost"):
    """Perform a real TLS handshake in memory; enforce chain, purpose and hostname.

    No dependence on CLI support for -x509_strict (macOS may use LibreSSL for
    the command while Python uses OpenSSL). Never clear certificate verification.
    """
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(cert, key)
    client = ssl.create_default_context(cafile=ca)
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(ci, co, server_hostname=hostname)
    s = server.wrap_bio(si, so, server_side=True)
    complete = [False, False]
    for _ in range(32):
        for index, connection in enumerate((c, s)):
            if not complete[index]:
                try:
                    connection.do_handshake(); complete[index] = True
                except ssl.SSLWantReadError:
                    pass
        for source, target in ((co, si), (so, ci)):
            data = source.read()
            if data: target.write(data)
        if all(complete): return
    raise lab.LabFailure("certificate_probe_deadline")


def replace(path, raw):
    fd, name = tempfile.mkstemp(prefix=".certificate-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(name): os.unlink(name)


def repair(root):
    control.root_check(root)
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        kc.require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077, "state_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in (control.JOURNAL, "bridge-recovery.json"):
            kc.require(not (root/name).exists() and not (root/name).is_symlink(), "recovery_required")
        mounted = root / "server-certs"
        control.root_check(mounted)
        inputs = kc.Inputs()
        manifest = kc.strict_json(inputs.read(root / "lab.json", private=True))
        kc.require(manifest.get("profile") == lab.PROFILE and
                   re.fullmatch(r"anka-kc110-[0-9a-f]{8}", manifest.get("name", "")) is not None, "lab_profile")
        name = manifest["name"] + "-server"
        item = lab.container(name)
        expected = manifest["images"]["keycloak"]["id"]
        kc.require(item is not None and str(item.get("Image", "")).removeprefix("sha256:") == expected.removeprefix("sha256:")
                   and item.get("State", {}).get("Status") in ("running", "exited", "stopped"), "lab_container")
        material = {name: inputs.read(root/name, private=True) for name in ("ca.pem", "ca.key", "server.key", "server.pem")}
        old_mounted = inputs.read(mounted/"server.pem", private=True)
        for name in ("ca.pem", "server.key"):
            kc.require(inputs.read(mounted/name, private=True) == material[name], "mount_binding")
        with tempfile.TemporaryDirectory(prefix="certificate-repair-", dir=root) as directory:
            temp = Path(directory)
            for name in ("ca.pem", "ca.key", "server.key"): lab.private(temp/name, material[name])
            lab.private(temp/"server.ext", EXTENSIONS)
            lab.stage("server_certificate_signing")
            lab.run(["openssl", "req", "-new", "-sha256", "-key", str(temp/"server.key"),
                     "-subj", "/CN=server", "-out", str(temp/"server.csr")])
            lab.run(["openssl", "x509", "-req", "-in", str(temp/"server.csr"),
                     "-CA", str(temp/"ca.pem"), "-CAkey", str(temp/"ca.key"),
                     "-set_serial", str(secrets.randbits(128) or 1), "-days", "7", "-sha256",
                     "-extfile", str(temp/"server.ext"), "-out", str(temp/"server.pem")])
            lab.stage("strict_tls_probe")
            strict_probe(str(temp/"ca.pem"), str(temp/"server.pem"), str(temp/"server.key"))
            inputs.recheck()
            raw = (temp/"server.pem").read_bytes()
        # Backups contain public certificates only. No private keys are replaced.
        suffix = secrets.token_hex(8)
        lab.private(root/("server-before-repair-"+suffix+".pem"), material["server.pem"])
        lab.private(root/("mounted-server-before-repair-"+suffix+".pem"), old_mounted)
        lab.stage("install_server_certificate")
        replace(mounted/"server.pem", raw)
        replace(root/"server.pem", raw)
        lab.stage("restart_keycloak")
        lab.run(["podman", "restart", manifest["name"]+"-server"], timeout=120)
        # Existing readiness checks keep CA and hostname verification enabled.
        lab.start(root, manifest)
    finally:
        os.close(fd)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    try:
        repair(args.state.absolute())
        print("Server certificate repaired and strict TLS verified; CA, holder credentials and database preserved.")
        return 0
    except Exception as error:
        print(json.dumps(lab.failure(error, lab.STAGE), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__": sys.exit(main())

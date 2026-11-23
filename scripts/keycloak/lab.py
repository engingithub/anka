#!/usr/bin/env python3
"""Isolated, localhost-only KC110 acceptance lab. Never use production credentials."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit

from diagnostics import LabFailure, exists, container, doctor, failure

STAGE = "arguments"

def stage(name):
    global STAGE
    STAGE = name

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.8.1"
POSTGRES_IMAGE = "docker.io/library/postgres:17"
REALM = "anka-kc110"
PROFILE = "keycloak-26.8.1-rs256-mtls-v1"


def private(path, data):
    path = Path(path)
    # Exclusive creation; never follow/overwrite a preexisting credential path.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)


def json_file(path, data):
    private(path, json.dumps(data, indent=2) + "\n")


def run(argv, timeout=120):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout).stdout


def certificates(root):
    """Real RSA keys, private CA, server SAN, and two distinct client holders."""
    root = Path(root)
    private(root / "ca.cnf", "[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=KC110 CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    run(["openssl", "req", "-config", str(root / "ca.cnf"), "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-days", "7", "-subj", "/CN=Anka KC110 laboratory CA", "-keyout", str(root / "ca.key"),
         "-out", str(root / "ca.pem")])
    for name in ("server", "holder", "other"):
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-subj", "/CN=" + name, "-keyout", str(root / (name + ".key")),
             "-out", str(root / (name + ".csr"))])
        ext = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        ext += ("extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
                if name == "server" else "extendedKeyUsage=clientAuth\n")
        private(root / (name + ".ext"), ext)
        run(["openssl", "x509", "-req", "-in", str(root / (name + ".csr")),
             "-CA", str(root / "ca.pem"), "-CAkey", str(root / "ca.key"),
             "-set_serial", str(100 + ("server", "holder", "other").index(name)),
             "-days", "7", "-sha256", "-extfile", str(root / (name + ".ext")),
             "-out", str(root / (name + ".pem"))])
    for p in root.iterdir():
        if p.is_file():
            p.chmod(0o600)


def configuration(port):
    return {"schema": 1, "profile": PROFILE,
            "issuer": f"https://localhost:{port}/realms/{REALM}",
            "audience": "anka-preflight", "issuing_client": "anka-workload",
            "introspection_client": "anka-preflight",
            "introspection_secret_file": "introspection.secret", "token_file": "access.token",
            "ca_file": "ca.pem", "holder_cert_file": "holder.pem", "holder_key_file": "holder.key",
            "timeout_seconds": 15, "max_observation_age_seconds": 5}


def prepare(root, port):
    stage("prepare_state")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    stage("generate_certificates")
    certificates(root)
    passwords = {name: secrets.token_urlsafe(32) for name in ("admin", "db", "workload", "introspection")}
    for name, value in passwords.items():
        private(root / (name + ".secret"), value)
    realm = {"realm": REALM, "enabled": True, "sslRequired": "all",
             "accessTokenLifespan": 120, "defaultSignatureAlgorithm": "RS256", "clients": []}
    for name in ("workload", "preflight"):
        client = {"clientId": "anka-" + name, "enabled": True, "protocol": "openid-connect",
                  "publicClient": False, "clientAuthenticatorType": "client-secret",
                  "secret": passwords["workload" if name == "workload" else "introspection"],
                  "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                  "implicitFlowEnabled": False, "directAccessGrantsEnabled": False}
        if name == "workload":
            client["attributes"] = {"tls.client.certificate.bound.access.tokens": "true",
                                    "access.token.signed.response.alg": "RS256"}
            client["protocolMappers"] = [{"name": "Anka resource audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                "config": {"included.client.audience": "anka-preflight", "access.token.claim": "true",
                           "id.token.claim": "false", "introspection.token.claim": "true"}}]
        realm["clients"].append(client)
    imports = root / "import"
    imports.mkdir(mode=0o700)
    json_file(imports / (REALM + "-realm.json"), realm)
    json_file(root / "config.json", configuration(port))
    private(root / "postgres.env", "POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD=" + passwords["db"] + "\n")
    private(root / "keycloak.env", "\n".join([
        "KC_DB=postgres", "KC_DB_URL=jdbc:postgresql://database:5432/keycloak", "KC_DB_USERNAME=keycloak",
        "KC_DB_PASSWORD=" + passwords["db"], "KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin",
        "KC_BOOTSTRAP_ADMIN_PASSWORD=" + passwords["admin"], "KC_HTTP_ENABLED=false",
        "KC_HOSTNAME=https://localhost:" + str(port), "KC_HTTPS_CERTIFICATE_FILE=/certs/server.pem",
        "KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/server.key", "KC_HTTPS_CLIENT_AUTH=required",
        "KC_TRUSTSTORE_PATHS=/certs/ca.pem"]) + "\n")
    # Resolve both tags once. Every later launch uses immutable local image IDs.
    images = {}
    for name, ref in (("keycloak", KEYCLOAK_IMAGE), ("postgres", POSTGRES_IMAGE)):
        stage("pull_" + name)
        run(["podman", "pull", ref], timeout=600)
        details = json.loads(run(["podman", "image", "inspect", ref]))[0]
        images[name] = {"reference": ref, "id": details["Id"], "digests": details.get("RepoDigests", [])}
    manifest = {"schema": 1, "profile": PROFILE, "port": port,
                "name": "anka-kc110-" + secrets.token_hex(4), "images": images}
    stage("save_manifest")
    json_file(root / "lab.json", manifest)
    return manifest


def ensure_container(name, image, argv, timeout=120):
    item = container(name)
    if item is None:
        run(argv, timeout=timeout)
        return
    # Reuse only the expected image. Never remove/recreate existing containers.
    if str(item.get("Image", "")).removeprefix("sha256:") != image.removeprefix("sha256:"):
        raise LabFailure("existing_container_image_mismatch")
    status = item.get("State", {}).get("Status")
    if status == "running":
        return
    if status not in ("created", "configured", "exited", "stopped"):
        raise LabFailure("existing_container_not_restartable")
    run(["podman", "start", name], timeout=timeout)


def repair_realm_import(root):
    """Migrate the first lab filename; preserve the exact private import bytes."""
    imports = root / "import"
    legacy, canonical = imports / "anka-realm.json", imports / (REALM + "-realm.json")
    legacy_present = legacy.exists() or legacy.is_symlink()
    canonical_present = canonical.exists() or canonical.is_symlink()
    if legacy_present and canonical_present:
        raise LabFailure("ambiguous_realm_import")
    source = legacy if legacy_present else canonical
    if not source.exists() or source.is_symlink():
        raise LabFailure("invalid_realm_import_file")
    info = source.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise LabFailure("invalid_realm_import_permissions")
    if info.st_size > 65536:
        raise LabFailure("invalid_realm_import_size")
    try:
        document = json.loads(source.read_bytes())
    except (ValueError, UnicodeError):
        raise LabFailure("invalid_realm_import_json") from None
    if not isinstance(document, dict) or document.get("realm") != REALM:
        raise LabFailure("realm_import_name_mismatch")
    if legacy_present:
        source.rename(canonical)
        print("Repaired realm import filename; credentials and database preserved.")


def start(root, manifest):
    stage("validate_realm_import")
    repair_realm_import(root)
    name = manifest["name"]
    # Certificates are the only host directory made visible to the server.
    certdir = root / "server-certs"
    if not certdir.exists():
        certdir.mkdir(mode=0o700)
        for f in ("server.pem", "server.key", "ca.pem"):
            private(certdir / f, (root / f).read_bytes())
    for kind, resource in (("network", name), ("volume", name + "-db")):
        stage("ensure_" + kind)
        if not exists(kind, resource):
            run(["podman", kind, "create", resource])
    stage("start_database")
    ensure_container(name + "-db", manifest["images"]["postgres"]["id"],
        ["podman", "run", "-d", "--name", name + "-db", "--network", name,
         "--network-alias", "database", "--env-file", str(root / "postgres.env"),
         "-v", name + "-db:/var/lib/postgresql/data", manifest["images"]["postgres"]["id"]])
    stage("database_readiness")
    ready = False
    for _ in range(60):
        try:
            run(["podman", "exec", name + "-db", "pg_isready", "-U", "keycloak", "-d", "keycloak"], timeout=5)
            ready = True
            break
        except subprocess.CalledProcessError:
            time.sleep(1)
    if not ready:
        raise LabFailure("database_readiness_deadline")
    # UID 0 in this rootless developer container can read owner-only mounted files.
    stage("start_keycloak")
    ensure_container(name + "-server", manifest["images"]["keycloak"]["id"],
        ["podman", "run", "-d", "--name", name + "-server", "--network", name, "--user", "0",
         "-p", f"127.0.0.1:{manifest['port']}:8443", "--env-file", str(root / "keycloak.env"),
         "-v", str(certdir) + ":/certs:ro,Z", "-v", str(root / "import") + ":/opt/keycloak/data/import:ro,Z",
         manifest["images"]["keycloak"]["id"], "start", "--import-realm"], timeout=120)
    stage("keycloak_readiness")
    last_error = None
    for _ in range(120):
        try:
            request(root, f"/realms/{REALM}/protocol/openid-connect/certs")
            print("Ready: " + str(root))
            return
        except (OSError, RuntimeError, LabFailure, http.client.HTTPException) as error:
            last_error = error
            time.sleep(1)
    raise LabFailure("keycloak_readiness_deadline", last_probe=failure(last_error, "realm_https"))


def request(root, path, form=None, method=None, payload=None, bearer=None, holder="holder"):
    manifest = json.loads((root / "lab.json").read_text())
    ctx = ssl.create_default_context(cafile=str(root / "ca.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(root / (holder + ".pem")), str(root / (holder + ".key")))
    headers = {"Accept": "application/json", "Connection": "close"}
    body = None
    if form is not None:
        body = urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    conn = http.client.HTTPSConnection("localhost", manifest["port"], context=ctx, timeout=5)
    try:
        conn.request(method or ("POST" if body is not None else "GET"), path, body, headers)
        response = conn.getresponse()
        raw = response.read(1024 * 1024 + 1)
        if not (200 <= response.status < 300) or len(raw) > 1024 * 1024:
            raise LabFailure("lab_api_response", http_status=response.status, oversized=len(raw) > 1024 * 1024)
        return json.loads(raw) if raw else None
    finally:
        conn.close()


def issue(root):
    stage("token_request")
    result = request(root, f"/realms/{REALM}/protocol/openid-connect/token", form={
        "grant_type": "client_credentials", "client_id": "anka-workload",
        "client_secret": (root / "workload.secret").read_text()})
    token = result.get("access_token")
    if not isinstance(token, str) or not 0 < len(token) <= 16384:
        raise RuntimeError("lab token response rejected")
    # Atomic replace only of this lab's disposable token file.
    temporary = root / ("token-" + secrets.token_hex(8))
    private(temporary, token)
    os.replace(temporary, root / "access.token")
    return token


def preflight(root, binary=None, config="config.json"):
    argv = ([str(Path(binary).resolve()), "keycloak-preflight"] if binary else
            [sys.executable, "-I", str(Path(__file__).with_name("preflight.py"))])
    result = subprocess.run(argv + ["--config", str(root / config)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35)
    data = json.loads(result.stdout)
    if data.get("current_authority") != "unknown" or data.get("live_admission") is not False or data.get("boot_authorized") is not False:
        raise RuntimeError("preflight crossed authority boundary")
    if result.returncode not in (0, 1) or (result.returncode == 0) != (data.get("status") == "preflight_valid"):
        raise RuntimeError("preflight result mismatch")
    return data


def checks(root, binary):
    records = []

    completed = False

    def check(label, expected, config="config.json", reason=None):
        stage("acceptance_" + label)
        result = preflight(root, binary, config)
        records.append({"case": label, "status": result["status"], "reason": result.get("reason"),
                        "expected": expected})
        if result["status"] != expected or (reason is not None and result.get("reason") != reason):
            raise LabFailure("acceptance_case_failed", case=label, expected=expected,
                             observed_status=result.get("status"), observed_reason=result.get("reason"))
        print("PASS: " + label)

    report = root / ("acceptance-" + str(time.time_ns()) + ".json")
    try:
        original = issue(root)
        check("real_certificate_bound_access_token", "preflight_valid")
        for label, changes in (("wrong_issuer", {"issuer": "https://localhost:1/realms/other"}),
                               ("wrong_audience", {"audience": "other", "introspection_client": "other"}),
                               ("wrong_client", {"issuing_client": "other"}),
                               ("wrong_holder", {"holder_cert_file": "other.pem", "holder_key_file": "other.key"})):
            cfg = json.loads((root / "config.json").read_text())
            cfg.update(changes)
            name = "case-" + secrets.token_hex(4) + ".json"
            json_file(root / name, cfg)
            try:
                check(label, "denied", name, label.removeprefix("wrong_"))
            finally:
                (root / name).unlink()
        admin = request(root, "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "lab-admin",
            "password": (root / "admin.secret").read_text()})["access_token"]
        realm_path = "/admin/realms/" + REALM
        realm = request(root, realm_path, bearer=admin)
        # Realm not-before is the specific tested revocation operation. Restore it
        # after the test; this is a disposable lab, never a production admin tool.
        payload = json.loads(base64.urlsafe_b64decode(original.split(".")[1] + "=" * (-len(original.split(".")[1]) % 4)))
        request(root, realm_path, method="PUT", payload={"notBefore": payload["iat"] + 1}, bearer=admin)
        try:
            check("realm_not_before_inactivates_existing_token", "denied", reason="inactive")
        finally:
            request(root, realm_path, method="PUT", payload={"notBefore": realm.get("notBefore", 0)}, bearer=admin)
        original = issue(root)
        check("fresh_observation_after_lab_policy_restore", "preflight_valid")
        components_path = realm_path + "/components"
        components = request(root, components_path, bearer=admin)
        rsa = [c for c in components if c.get("providerId") == "rsa-generated"]
        if not rsa:
            raise RuntimeError("expected pinned RSA provider missing")
        priority = max(int(c.get("config", {}).get("priority", ["0"])[0]) for c in rsa) + 100
        request(root, components_path, method="POST", bearer=admin, payload={
            "name": "kc110-rotation-" + secrets.token_hex(4), "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm["id"],
            "config": {"priority": [str(priority)], "enabled": ["true"], "active": ["true"],
                       "algorithm": ["RS256"], "keySize": ["2048"]}})
        rotated = issue(root)
        if original.split(".")[0] == rotated.split(".")[0]:
            raise RuntimeError("rotation did not change signing header")
        check("fresh_rotated_signing_key", "preflight_valid")
        for component in rsa:
            request(root, components_path + "/" + component["id"], method="DELETE", bearer=admin)
        temporary = root / ("old-" + secrets.token_hex(8))
        private(temporary, original)
        os.replace(temporary, root / "access.token")
        check("withdrawn_signing_key_not_cached", "denied", reason="key_selection")
        issue(root)
        check("fresh_token_after_rotation", "preflight_valid")
        request(root, realm_path, method="PUT", payload={"accessTokenLifespan": 5}, bearer=admin)
        try:
            short = issue(root)
            part = short.split(".")[1]
            expiry = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["exp"]
            if not 0 < expiry - time.time() <= 6:
                raise RuntimeError("short expiry profile not applied")
            check("short_lived_real_token_before_expiry", "preflight_valid")
            time.sleep(max(0, expiry - time.time()) + 0.1)
            check("real_token_at_exclusive_expiry", "denied", reason="token_time")
        finally:
            request(root, realm_path, method="PUT", payload={"accessTokenLifespan": realm["accessTokenLifespan"]}, bearer=admin)
        issue(root)
        name = json.loads((root / "lab.json").read_text())["name"] + "-server"
        run(["podman", "stop", "--time", "5", name])
        try:
            check("unavailable_keycloak", "denied", reason="transport")
        finally:
            run(["podman", "start", name])
            ready = False
            for _ in range(120):
                try:
                    request(root, f"/realms/{REALM}/protocol/openid-connect/certs")
                    ready = True
                    break
                except (OSError, RuntimeError, http.client.HTTPException):
                    time.sleep(1)
            if not ready:
                raise RuntimeError("Keycloak restart deadline")
        issue(root)
        check("persistent_realm_after_server_restart", "preflight_valid")
        completed = True
    finally:
        json_file(report, {"profile": PROFILE, "complete": completed, "cases": records,
                           "images": json.loads((root / "lab.json").read_text())["images"],
                           "live_admission": False, "boot_authorized": False})
        print("Evidence: " + str(report))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "resume", "token", "check", "stop", "doctor"))
    parser.add_argument("--state", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--binary", help="already-built anka binary, used by check")
    args = parser.parse_args()
    root = Path(args.state).absolute()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    try:
        if args.action == "doctor":
            try:
                manifest = json.loads((root / "lab.json").read_text())
            except (OSError, ValueError):
                manifest = None
            print(json.dumps(doctor(root, manifest, request), sort_keys=True))
            return 0
        if args.action == "start":
            manifest = prepare(root, args.port)
            start(root, manifest)
        else:
            stage("load_manifest")
            manifest = json.loads((root / "lab.json").read_text())
            if args.action == "resume":
                start(root, manifest)
            elif args.action == "token":
                issue(root)
                print("Token replaced in private lab state; no token printed.")
            elif args.action == "check":
                stage("acceptance_setup")
                checks(root, args.binary)
            elif args.action == "stop":
                for suffix in ("-server", "-db"):
                    run(["podman", "rm", "-f", manifest["name"] + suffix])
                print("Containers removed; database volume, image pins and private state retained.")
        return 0
    except Exception as error:
        report = failure(error, STAGE)
        # Structured reason codes only; do not dump arguments, env, bodies or logs.
        print(json.dumps(report, sort_keys=True), file=sys.stderr)
        if root.is_dir():
            try:
                json_file(root / ("failure-" + str(time.time_ns()) + ".json"), report)
            except OSError:
                pass
        print("Run lab.py doctor with the same --state for a shareable diagnostic report.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

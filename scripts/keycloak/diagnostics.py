"""Allowlisted lab diagnostics: never emit command arguments, env or raw logs."""
import http.client
import json
from pathlib import Path
import ssl
import subprocess


class LabFailure(Exception):
    def __init__(self, reason, **details):
        super().__init__(reason)
        self.reason, self.details = reason, details


SIGNALS = (
    ("podman_connection", ("cannot connect to podman", "unable to connect to podman", "connection refused")),
    ("port_in_use", ("address already in use", "port is already allocated")),
    ("permission_denied", ("permission denied", "accessdeniedexception", "operation not permitted")),
    ("mount_unavailable", ("mounts denied", "statfs", "no such file or directory")),
    ("container_name_in_use", ("container name", "name is already in use")),
    ("database_authentication", ("password authentication failed",)),
    ("database_connection", ("unable to obtain jdbc connection", "failed to obtain jdbc connection")),
    ("realm_import_name_mismatch", ("file name / realm name mismatch",)),
    ("realm_import", ("failed to import realm", "error importing realm", "failed to parse import")),
    ("tls_configuration", ("failed to load key material", "unable to load key", "failed to load truststore")),
    ("unknown_option", ("unknown option", "unrecognized option")),
    ("image_unavailable", ("manifest unknown", "no image found", "image not known")),
)


def signals(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    raw = str(raw).lower()
    return [code for code, patterns in SIGNALS if any(s in raw for s in patterns)]


def failure(error, stage):
    result = {"status": "lab_failed", "stage": stage}
    if isinstance(error, LabFailure):
        result.update(reason=error.reason, **error.details)
    elif isinstance(error, subprocess.CalledProcessError):
        result.update(reason="command_failed", exit_code=error.returncode,
                      signals=signals(error.stderr or b""))
    elif isinstance(error, subprocess.TimeoutExpired):
        result.update(reason="command_timeout")
    elif isinstance(error, FileExistsError):
        result.update(reason="state_already_exists", hint="Use doctor, then resume for a lab with lab.json.")
    elif isinstance(error, FileNotFoundError):
        result.update(reason="file_or_executable_missing")
    elif isinstance(error, ssl.SSLCertVerificationError):
        result.update(reason="tls_certificate_verification", verify_code=error.verify_code)
    elif isinstance(error, ssl.SSLError):
        result.update(reason="tls_handshake")
    elif isinstance(error, ConnectionRefusedError):
        result.update(reason="connection_refused")
    elif isinstance(error, (TimeoutError,)): 
        result.update(reason="network_timeout")
    elif isinstance(error, PermissionError):
        result.update(reason="permission_denied")
    elif isinstance(error, json.JSONDecodeError):
        result.update(reason="invalid_json")
    elif isinstance(error, http.client.HTTPException):
        result.update(reason="http_protocol")
    else:
        result.update(reason="unexpected_error")
    return result


def exists(kind, name):
    result = subprocess.run(["podman", kind, "exists", name], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
    if result.returncode not in (0, 1):
        raise subprocess.CalledProcessError(result.returncode, "podman", stderr=result.stderr)
    return result.returncode == 0


def capture(argv, include_stderr=False):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, "podman", stderr=result.stderr)
    return result.stdout + (result.stderr if include_stderr else b"")


def container(name):
    if not exists("container", name):
        return None
    value = json.loads(capture(["podman", "container", "inspect", name]))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise LabFailure("invalid_container_inspection")
    return value[0]


def doctor(root, manifest, request):
    """Read-only report. Inspect/env/log text never crosses the output boundary."""
    result = {"schema": 1, "status": "diagnostic", "containers": {}}
    try:
        capture(["podman", "info", "--format", "json"])
        result["podman"] = "reachable"
    except Exception as error:
        result["podman"] = failure(error, "podman_connection")
        return result
    if manifest is None:
        result["state"] = "manifest_missing_or_invalid"
        result["hint"] = "Preparation did not finish; keep this state and use a new directory after fixing prerequisites."
        return result
    name = manifest["name"]
    for role, suffix in (("database", "-db"), ("keycloak", "-server")):
        try:
            item = container(name + suffix)
            if item is None:
                result["containers"][role] = {"status": "missing"}
                continue
            state = item.get("State", {})
            status = state.get("Status")
            safe = {"status": status if status in {"created", "running", "paused", "restarting", "stopping", "stopped", "exited", "removing", "configured"} else "unknown"}
            if type(state.get("ExitCode")) is int:
                safe["exit_code"] = state["ExitCode"]
            if type(state.get("OOMKilled")) is bool:
                safe["oom_killed"] = state["OOMKilled"]
            safe["signals"] = signals(state.get("Error", ""))
            try:
                raw = capture(["podman", "logs", "--tail", "100", name + suffix], include_stderr=True)
                safe["signals"] = sorted(set(safe["signals"] + signals(raw)))
            except Exception:
                safe["logs"] = "unavailable"
            result["containers"][role] = safe
        except Exception as error:
            result["containers"][role] = failure(error, "container_inspection")
    try:
        request(root, "/realms/anka-kc110/protocol/openid-connect/certs")
        result["realm_https"] = "ready"
    except Exception as error:
        result["realm_https"] = failure(error, "realm_https")
    result["hint"] = "Signals are diagnostic clues, not proof of a root cause; no credentials or raw logs are included."
    return result

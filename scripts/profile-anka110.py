#!/usr/bin/env python3
"""Prepare and measure native Anka workloads. Only `build` invokes Cargo.

Python 3.9+, standard library only. Baselines run on macOS/Linux; capture needs
macOS with full Xcode. All commands use argv arrays, never shell evaluation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
RR110 = "rr110_real_cc2_independent_restart_and_stored_launch"
SCHEMA = 1


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def source_inputs(root):
    """Local runtime/build inputs, not a hermetic dependency provenance claim."""
    paths = set()
    for name in ("src", "userspace", ".cargo", "scripts/profiling"):
        directory = root / name
        if directory.exists():
            paths.update(p for p in directory.rglob("*") if p.is_file())
    for name in ("Cargo.toml", "Cargo.lock", "build.rs", "scripts/profile-anka110.py"):
        p = root / name
        if p.exists():
            paths.add(p)
    return {str(p.relative_to(root)): digest(p) for p in sorted(paths)}


def probe(argv, root):
    try:
        p = subprocess.run(argv, cwd=root, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=20)
        return {"argv": argv, "exit_code": p.returncode, "output": p.stdout.strip()}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"argv": argv, "error": str(e)}


def environment(root):
    # Deliberately avoid dumping the full environment (which may hold credentials).
    keys = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN",
            "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "MACOSX_DEPLOYMENT_TARGET",
            "DEVELOPER_DIR", "SDKROOT", "RUSTC", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "TMPDIR", "RUST_TEST_THREADS"}
    keys.update(k for k in os.environ if k.startswith("CARGO_PROFILE_") or
                (k.startswith("CARGO_TARGET_") and
                 k.endswith(("_LINKER", "_RUSTFLAGS", "_RUNNER"))))
    data = {"utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(), "machine": platform.machine(),
            "python": sys.version, "environment": {k: os.environ[k] for k in sorted(keys)
                                                    if k in os.environ},
            "git_head": probe(["git", "rev-parse", "HEAD"], root),
            "git_status": probe(["git", "status", "--porcelain=v1"], root),
            "rustc": probe(["rustc", "-vV"], root),
            "cargo": probe(["cargo", "--version"], root)}
    if sys.platform == "darwin":
        for key, cmd in {
            "macos": ["sw_vers"], "xcode": ["xcodebuild", "-version"],
            "developer_directory": ["xcode-select", "-p"],
            "hardware": ["sysctl", "hw.model", "hw.memsize", "hw.ncpu"],
            "power": ["pmset", "-g", "batt"],
        }.items():
            data[key] = probe(cmd, root)
    return data


def select_artifact(log, kind, is_test):
    candidates = set()
    for line in Path(log).read_text().splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue  # build-script stdout need not be Cargo JSON
        if not isinstance(msg, dict):
            continue
        target = msg.get("target", {})
        if (msg.get("reason") == "compiler-artifact" and target.get("name") == "anka"
                and kind in target.get("kind", [])
                and msg.get("profile", {}).get("test") is is_test
                and msg.get("executable")):
            candidates.add(msg["executable"])
    if len(candidates) != 1:
        raise ValueError(f"Expected exactly one {kind} executable; found {sorted(candidates)}")
    return Path(candidates.pop()).resolve()


def select_test(listing):
    matches = [line[:-6] for line in listing.splitlines()
               if line.endswith("::" + RR110 + ": test")]
    if len(matches) != 1:
        raise ValueError(f"Expected one ignored RR110 witness, found {len(matches)}")
    return matches[0]


def build(args):
    session = args.session.resolve()
    session.mkdir(parents=True, exist_ok=False)  # never reuse a possibly stale session
    before = source_inputs(ROOT)
    metadata = {"schema": SCHEMA, "status": "building", "root": str(ROOT),
                "profile": "profiling", "source_inputs": before,
                "environment": environment(ROOT), "build_commands": []}
    write_json(session / "build.json", metadata)
    rust = metadata["environment"]["rustc"]
    hosts = re.findall(r"^host: (\S+)$", rust.get("output", ""), re.M)
    if rust.get("exit_code") != 0 or len(hosts) != 1:
        raise ValueError("Could not determine the native rustc host target")
    host = hosts[0]
    env = os.environ.copy()
    # Explicit native target overrides accidental cross-target configuration.
    env["CARGO_TARGET_DIR"] = str(session / "cargo-target")
    if sys.platform == "darwin":
        env["CARGO_PROFILE_PROFILING_SPLIT_DEBUGINFO"] = "packed"
    metadata["build_overrides"] = {k: env[k] for k in
                                   ("CARGO_TARGET_DIR", "CARGO_PROFILE_PROFILING_SPLIT_DEBUGINFO")
                                   if k in env}
    binaries = {}
    for key, options, kind, test in (
            ("rebuild", ["build", "--bin", "anka"], "bin", False),
            ("restart", ["test", "--lib", "--no-run"], "lib", True)):
        argv = ["cargo", *options, "--profile", "profiling", "--target", host,
                "--message-format=json-render-diagnostics"]
        if (ROOT / "Cargo.lock").exists():
            argv.append("--locked")
        metadata["build_commands"].append(argv)
        write_json(session / "build.json", metadata)
        print(shlex.join(argv), flush=True)
        log = session / (key + "-build.jsonl")
        with log.open("w") as out, (session / (key + "-build.stderr")).open("w") as err:
            subprocess.run(argv, cwd=ROOT, env=env, stdout=out, stderr=err, check=True)
        executable = select_artifact(log, kind, test)
        if not executable.is_file():
            raise ValueError(f"Missing artifact {executable}")
        # Keep the original executable and matching debug data together. The
        # dedicated target directory is owned by this session and is never rebuilt.
        binaries[key] = {"path": str(executable), "sha256": digest(executable)}
        dsym = Path(str(executable) + ".dSYM")
        if dsym.is_dir():
            binaries[key]["dsym"] = str(dsym)
    listing = subprocess.run([binaries["restart"]["path"], "--list", "--ignored"],
                             cwd=ROOT, text=True, capture_output=True, check=True)
    (session / "ignored-tests.txt").write_text(listing.stdout)
    metadata["restart_test"] = select_test(listing.stdout)
    if source_inputs(ROOT) != before:
        raise ValueError("Inputs changed during build; use a fresh session")
    metadata.update(status="ready", binaries=binaries, target=host)
    write_json(session / "build.json", metadata)
    print(f"Ready: {session}\nNo workload has run. Use baseline or record next.")


def load_session(session):
    data = json.loads((session / "build.json").read_text())
    if data.get("schema") != SCHEMA or data.get("status") != "ready":
        raise ValueError("Session build is incomplete or uses an unsupported schema")
    if Path(data["root"]).resolve() != ROOT:
        raise ValueError("Session belongs to a different checkout; build a fresh session")
    if data["source_inputs"] != source_inputs(ROOT):
        raise ValueError("Runtime/build inputs changed; build a fresh session")
    for binary in data["binaries"].values():
        if digest(binary["path"]) != binary["sha256"]:
            raise ValueError("Binary changed since build; build a fresh session")
    return data


def workload(data, name):
    exe = data["binaries"][name]["path"]
    if name == "restart":
        return [exe, data["restart_test"], "--exact", "--ignored", "--nocapture",
                "--test-threads=1"]
    fixture = ROOT / "scripts/profiling/rebuild"
    return [exe, "rebuild", "--include", str(fixture / "shared.h"), "--run",
            str(fixture / "main.c"), str(fixture / "helper.c")]


def validate_result(name, code, stdout, stderr):
    if name == "rebuild":
        return (code == 42 and "modules=2" in stderr and
                "Rebuild: Exited(42)" in stderr and stdout == "")
    # Exact selection plus the summary prevents zero-test runs counting as passes.
    return (code == 0 and "running 1 test" in stdout and
            "test result: ok. 1 passed; 0 failed; 0 ignored;" in stdout and
            "RR110: service-only, guest-only and both-side restart" in stderr)


def capture_command(argv, run_dir, template, limit):
    cmd = ["xcrun", "xctrace", "record", "--template", template,
           "--output", str(run_dir / "capture.trace"), "--target-stdout", "-"]
    if limit:
        cmd += ["--time-limit", limit]
    return [*cmd, "--launch", "--", *argv]


def measure(args):
    session = args.session.resolve()
    data = load_session(session)
    argv = workload(data, args.workload)
    if args.action == "record" and sys.platform != "darwin":
        raise ValueError("Instruments capture requires macOS; baseline works on macOS/Linux")
    repeats = args.repeat if args.action == "baseline" else 1
    for _ in range(repeats):
        name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        run_dir = session / "runs" / (args.workload + "-" + args.action + "-" + name)
        run_dir.mkdir(parents=True)
        cmd = argv if args.action == "baseline" else capture_command(
            argv, run_dir, args.template, args.time_limit)
        record = {"schema": SCHEMA, "status": "running", "mode": args.action,
                  "workload": args.workload, "workload_argv": argv, "argv": cmd,
                  "cwd": str(ROOT), "environment": environment(ROOT),
                  "build_manifest_sha256": digest(session / "build.json"),
                  "expected_workload_exit": 42 if args.workload == "rebuild" else 0,
                  "note": args.note}
        if args.action == "record":
            record.update(template=args.template, time_limit=args.time_limit,
                          workload_status="manual_review_required")
        write_json(run_dir / "result.json", record)
        print(shlex.join(cmd), flush=True)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.perf_counter()
        with (run_dir / "stdout.log").open("w") as out, (run_dir / "stderr.log").open("w") as err:
            result = subprocess.run(cmd, cwd=ROOT, stdout=out, stderr=err)
        elapsed = time.perf_counter() - start
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record["launcher_exit_code"] = result.returncode
        if args.action == "baseline":
            record.update(elapsed_seconds=elapsed,
                          user_cpu_seconds=after.ru_utime - before.ru_utime,
                          system_cpu_seconds=after.ru_stime - before.ru_stime)
            valid = validate_result(args.workload, result.returncode,
                                    (run_dir / "stdout.log").read_text(errors="replace"),
                                    (run_dir / "stderr.log").read_text(errors="replace"))
            record["status"] = "valid" if valid else "invalid_workload"
        else:
            # xctrace status/time is NOT the target's status/time. A saved trace
            # may contain errors or a truncated workload; never call it acceptance.
            record["capture_elapsed_seconds"] = elapsed
            record["trace_exists"] = (run_dir / "capture.trace").exists()
            valid = record["trace_exists"] and result.returncode == 0
            record["status"] = "review_required" if valid else "capture_issue"
        if source_inputs(ROOT) != data["source_inputs"]:
            valid = False
            record["status"] = "invalid_inputs_changed"
        write_json(run_dir / "result.json", record)
        print(f"{record['status']}: {run_dir}", flush=True)
        if not valid:
            raise ValueError("Measurement needs attention; see result.json and logs. "
                             "A saved trace is not proof of target completion.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("build", "baseline", "record"):
        p = sub.add_parser(action)
        p.add_argument("--session", type=Path, required=True,
                       help="New directory for build; same directory for measurements")
        if action != "build":
            p.add_argument("--workload", choices=("rebuild", "restart"), required=True)
            p.add_argument("--note", default="", help="Power/thermal/background-load observations")
        if action == "baseline":
            p.add_argument("--repeat", type=int, choices=range(1, 11), default=1)
        if action == "record":
            p.add_argument("--template", default="Time Profiler",
                           help="Exact installed template name or absolute template path")
            p.add_argument("--time-limit", help="Optional capture window, e.g. 30s; may truncate work")
    args = parser.parse_args(argv)
    if args.action == "record" and args.time_limit and not re.fullmatch(
            r"[1-9][0-9]*(ms|s|m|h)", args.time_limit):
        parser.error("--time-limit must be a positive integer followed by ms, s, m or h")
    try:
        if args.action == "build":
            build(args)
        else:
            measure(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted; the run's 'running' status is incomplete, not a baseline.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())

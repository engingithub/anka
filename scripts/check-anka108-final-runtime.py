#!/usr/bin/env python3
"""Release runtime gate for DN-71. The shell --final entry runs the Kleis prerequisites."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# A renamed, missing or unexpectedly enabled witness requires review. Additional
# ignored library tests are discovered and executed too. Longest witness last.
REAL = """
c31_real_workspace_compiler c32_real_source_growth_compiler
c33_real_recursive_struct_declarations c34_real_wide_struct_types
c35_real_typed_modules_and_heap_list c3_workspace_retry_real_compiler
c2_preprocess_storage_real_include_growth c4_real_large_application_link_and_load
c5_real_compiler_job_retry_publication c5_service_real_concurrent_rebuild
c5_http_real_protected_application s2_real_socket_http
s3_frame_real_ethernet_arp_icmp_and_udp s4_real_nic_tcp_http_alive
c26_real_cc2_oversized_publication
""".split()
ORDINARY = ["p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address",
            "s5_udp_legacy_matches_shared_wire_oracle"]
CARGO = ["cargo", "test", "--release", "--locked"]
SUMMARY = re.compile(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                     r"(\d+) measured; (\d+) filtered out;", re.M)


def check(ok, message):
    if not ok:
        raise SystemExit("FAIL: " + message)


def test_names(ignored):
    args = CARGO + ["--lib", "--", "--list"] + (["--ignored"] if ignored else [])
    out = subprocess.check_output(args, text=True)
    return {s[:-6] for s in out.splitlines() if s.endswith(": test")}


def exact_names(short_names, available):
    result = []
    for leaf in short_names:
        matches = [s for s in available if s.split("::")[-1] == leaf]
        check(len(matches) == 1, f"expected one compiled test named {leaf}, found {matches}")
        result.extend(matches)
    return result


def fingerprint(binary):
    # Include inputs read at run time as well as the executable. A dirty
    # worktree is supported; a commit ID alone cannot identify those bytes.
    h = hashlib.sha256()
    paths = [Path("Cargo.toml"), Path("Cargo.lock"), Path(__file__).resolve().relative_to(ROOT)]
    for folder in ("src", "userspace", "examples", "theories", "tests"):
        paths.extend(p for p in Path(folder).rglob("*") if p.is_file() and not p.name.startswith("."))
    for p in sorted(paths):
        h.update(os.fsencode(p) + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    h.update(hashlib.sha256(binary.read_bytes()).digest())
    h.update(os.environ["ANKA_PRODUCER_TIMEOUT_SECS"].encode())
    return h.hexdigest()


def run(label, args, path, verify, reuse=False):
    # A fresh .pending log never counts. Cached evidence is re-parsed.
    if reuse and path.exists() and verify(path.read_text()):
        print(f"PASS (same build, saved log): {label}")
        return
    pending = path.with_suffix(".pending")
    print(f"RUN {label}  [{pending}]")
    start = time.monotonic()
    with pending.open("w") as log, subprocess.Popen(args, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, errors="replace") as proc:
        last_report = start
        for line in proc.stdout:
            log.write(line)
            if (line.startswith(("running ", "test result:", "protected CC2 [", "C2.6", "error:"))
                    or "FAILED" in line or "panicked at" in line):
                print(line.rstrip())
            elif time.monotonic() - last_report >= 30 and line.startswith("test "):
                print(line.rstrip())
                last_report = time.monotonic()
        rc = proc.wait()
    check(rc == 0 and verify(pending.read_text()), f"{label}; see {pending}")
    pending.replace(path)
    print(f"PASS {label} ({time.monotonic()-start:.1f}s)")


def main():
    os.chdir(ROOT)
    os.environ.setdefault("ANKA_PRODUCER_TIMEOUT_SECS", "900")
    os.environ["CARGO_TERM_COLOR"] = "never"
    build = subprocess.run(CARGO + ["--lib", "--no-run", "--message-format=json"],
                           stdout=subprocess.PIPE, text=True)
    messages = [json.loads(line) for line in build.stdout.splitlines()]
    if build.returncode:
        for m in messages:
            if m.get("reason") == "compiler-message" and m["message"]["level"] == "error":
                print(m["message"]["rendered"], file=sys.stderr)
        raise SystemExit(build.returncode)
    binaries = [Path(a["executable"]) for a in messages
                if a.get("reason") == "compiler-artifact" and a.get("executable")
                and a["profile"]["test"] and "lib" in a["target"]["kind"]]
    check(len(binaries) == 1, "could not identify the compiled release library test executable")
    binary = binaries[0]
    all_tests, ignored = test_names(False), test_names(True)
    check(ignored <= all_tests and len(all_tests) >= 1643, "incomplete library test inventory")
    ordinary = exact_names(ORDINARY, all_tests - ignored)
    required = exact_names(REAL, ignored)
    witnesses = sorted(ignored - set(required)) + required
    key = fingerprint(binary)
    base = ROOT / "target" / "anka108-closure" / key
    base.mkdir(parents=True, exist_ok=True)
    print(f"Release input ID: {key}\n{len(all_tests)} library tests; {len(ignored)} explicit witnesses")
    def ordinary_ok(log):
        totals = [tuple(map(int, row)) for row in SUMMARY.findall(log)]
        lib = (len(all_tests)-len(ignored), 0, len(ignored), 0, 0)
        return (lib in totals and sum(row[2] for row in totals) == len(ignored)
                and all(not row[1] and not row[4] for row in totals)
                and all(f"test {n} ... ok" in log.splitlines() for n in ordinary))
    # Fresh ordinary regression includes binary and doc tests, not only --lib.
    run("complete ordinary release suite", CARGO+["--", "--test-threads=1"],
        base/"ordinary.log", ordinary_ok)
    for name in witnesses:
        args = CARGO + ["--lib", name, "--", "--exact", "--ignored", "--nocapture", "--test-threads=1"]
        def one_ok(log):
            return (f"test {name} ... " in log and
                    SUMMARY.findall(log) == [("1","0","0","0",str(len(all_tests)-1))])
        path = base/(name.replace("::","__")+".log")
        run(name, args, path, one_ok, reuse=True)
        if key != fingerprint(binary):
            path.unlink()
            raise SystemExit("FAIL: inputs changed during acceptance; rerun on a stable checkout")
    check(key == fingerprint(binary), "source or binary changed during verification; rerun")
    print(f"PASS Phase 10.8 runtime: {len(all_tests)-len(ignored)} ordinary library tests, "
          f"{len(witnesses)} explicit guest witnesses, complete Cargo suite.\nEvidence: {base}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Check profiling orchestration with Python fixtures/mocks only. No Rust builds/tests."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "anka_profile", Path(__file__).with_name("profile-anka110.py"))
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class ProfilingChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="anka profiling check ")
        self.addCleanup(self.tmp.cleanup)
        # Match the runner's canonical ROOT. macOS temp paths may use /var or
        # /tmp aliases whose resolved spelling starts with /private.
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("// fixture only; never compiled\n")
        (self.root / "Cargo.toml").write_text("[package]\nname='anka'\n")
        (self.root / "Cargo.lock").write_text("# fixture\n")
        self.full_test = "anka64::tests::" + profile.RR110

    def artifact(self, kind="lib", test=True, name="anka", executable="/tmp/a"):
        return {"reason": "compiler-artifact", "target": {"name": name, "kind": [kind]},
                "profile": {"test": test}, "executable": executable}

    def ready(self):
        session = self.root / "session"
        session.mkdir()
        exe = self.root / "fake executable"
        exe.write_text("fixture")
        manifest = {"schema": profile.SCHEMA, "status": "ready", "root": str(self.root),
                    "source_inputs": profile.source_inputs(self.root),
                    "restart_test": self.full_test,
                    "binaries": {n: {"path": str(exe), "sha256": profile.digest(exe)}
                                 for n in ("rebuild", "restart")}}
        profile.write_json(session / "build.json", manifest)
        return session, manifest

    def test_cargo_json_selects_executable_not_build_script_or_other_target(self):
        log = self.root / "cargo.jsonl"
        messages = [self.artifact(name="dependency"), self.artifact(kind="custom-build"),
                    self.artifact(test=False), self.artifact(executable=None), self.artifact()]
        log.write_text("build chatter\n" + "\n".join(json.dumps(m) for m in messages))
        self.assertEqual(profile.select_artifact(log, "lib", True), Path("/tmp/a").resolve())
        log.write_text(log.read_text() + "\n" + json.dumps(self.artifact(executable="/tmp/b")))
        with self.assertRaises(ValueError):
            profile.select_artifact(log, "lib", True)

    def test_missing_artifact_fails(self):
        log = self.root / "empty"
        log.write_text("")
        with self.assertRaises(ValueError):
            profile.select_artifact(log, "bin", False)

    def test_artifact_path_resolves_directory_alias(self):
        actual = self.root / "artifacts"
        actual.mkdir()
        executable = actual / "anka test"
        executable.write_text("fixture")
        alias = self.root / "artifact alias"
        alias.symlink_to(actual, target_is_directory=True)
        log = self.root / "alias.jsonl"
        log.write_text(json.dumps(self.artifact(executable=str(alias / executable.name))))
        self.assertEqual(profile.select_artifact(log, "lib", True), executable)

    def test_session_accepts_same_checkout_alias_but_not_another_checkout(self):
        session, data = self.ready()
        alias = self.root / "checkout alias"
        alias.symlink_to(self.root, target_is_directory=True)
        data["root"] = str(alias)
        profile.write_json(session / "build.json", data)
        with patch.object(profile, "ROOT", self.root):
            self.assertEqual(profile.load_session(alias / "session"), data)
            other = self.root / "other checkout"
            other.mkdir()
            data["root"] = str(other)
            profile.write_json(session / "build.json", data)
            with self.assertRaisesRegex(ValueError, "different checkout"):
                profile.load_session(session)

    def test_test_discovery_requires_one_exact_suffix(self):
        line = self.full_test + ": test\n"
        self.assertEqual(profile.select_test(line), self.full_test)
        for listing in ("", line + line, self.full_test + "_other: test\n"):
            with self.assertRaises(ValueError):
                profile.select_test(listing)

    def test_rebuild_exit_42_requires_actual_workload_evidence(self):
        stderr = "Rebuild: linked receipt epoch=7, modules=2\nRebuild: Exited(42)\n"
        self.assertTrue(profile.validate_result("rebuild", 42, "", stderr))
        for code, out, err in [(0, "", stderr), (42, "", ""), (42, "unexpected", stderr)]:
            self.assertFalse(profile.validate_result("rebuild", code, out, err))

    def test_restart_zero_tests_or_missing_completion_is_not_success(self):
        out = "running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
        err = "RR110: service-only, guest-only and both-side restart"
        self.assertTrue(profile.validate_result("restart", 0, out, err))
        for code, text, error in [(1, out, err), (0, "running 0 tests", err),
                                  (0, out, ""), (0, out.replace("1 passed", "0 passed"), err)]:
            self.assertFalse(profile.validate_result("restart", code, text, error))

    def test_input_or_binary_changes_reject_session(self):
        session, data = self.ready()
        with patch.object(profile, "ROOT", self.root):
            self.assertEqual(profile.load_session(session), data)
            (self.root / "src/new.rs").write_text("changed")
            with self.assertRaises(ValueError):
                profile.load_session(session)
            (self.root / "src/new.rs").unlink()
            Path(data["binaries"]["rebuild"]["path"]).write_text("changed binary")
            with self.assertRaises(ValueError):
                profile.load_session(session)

    def test_incomplete_session_rejects_run(self):
        session, data = self.ready()
        data["status"] = "building"
        profile.write_json(session / "build.json", data)
        with patch.object(profile, "ROOT", self.root), self.assertRaises(ValueError):
            profile.load_session(session)

    def test_argv_preserves_spaces_and_exact_test_selection(self):
        _, data = self.ready()
        with patch.object(profile, "ROOT", self.root):
            rebuild = profile.workload(data, "rebuild")
            self.assertIn(str(self.root / "scripts/profiling/rebuild/main.c"), rebuild)
            restart = profile.workload(data, "restart")
            self.assertEqual(restart[1:], [self.full_test, "--exact", "--ignored",
                                          "--nocapture", "--test-threads=1"])
        cmd = profile.capture_command(restart, self.root, "Time Profiler", "30s")
        self.assertEqual(cmd[cmd.index("--launch") + 1:], ["--", *restart])
        self.assertNotIn("cargo", cmd)

    def test_build_uses_native_target_and_no_run_and_refuses_overwrite(self):
        session = self.root / "build session"
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "cargo":
                is_test = argv[1] == "test"
                self.assertIn("--locked", argv)
                self.assertEqual(argv[argv.index("--target") + 1], "mock-native")
                if is_test:
                    self.assertIn("--no-run", argv)
                exe = session / ("fake tests" if is_test else "fake cli")
                exe.write_text("fixture")
                kwargs["stdout"].write(json.dumps(self.artifact(
                    kind="lib" if is_test else "bin", test=is_test, executable=str(exe))) + "\n")
                return subprocess.CompletedProcess(argv, 0)
            self.assertEqual(argv[1:], ["--list", "--ignored"])
            return subprocess.CompletedProcess(argv, 0, self.full_test + ": test\n", "")

        env = {"rustc": {"exit_code": 0, "output": "host: mock-native"}}
        with patch.object(profile, "ROOT", self.root), patch.object(profile, "environment", return_value=env), \
                patch.object(profile.subprocess, "run", side_effect=fake_run):
            profile.build(argparse.Namespace(session=session))
            self.assertEqual(profile.load_session(session)["status"], "ready")
            with self.assertRaises(FileExistsError):
                profile.build(argparse.Namespace(session=session))
        self.assertEqual(len(calls), 3)  # two mocked builds, one mocked discovery only

    def test_python_child_baseline_records_nonzero_expected_exit_and_repeats(self):
        session, _ = self.ready()
        argv = [sys.executable, "-c", "import sys; "
                "print('Rebuild: linked receipt epoch=1, modules=2',file=sys.stderr); "
                "print('Rebuild: Exited(42)',file=sys.stderr); sys.exit(42)"]
        args = argparse.Namespace(session=session, action="baseline", workload="rebuild",
                                  repeat=2, note="Python fixture, not Anka")
        with patch.object(profile, "ROOT", self.root), patch.object(profile, "environment", return_value={}), \
                patch.object(profile, "workload", return_value=argv):
            profile.measure(args)
        records = [json.loads(p.read_text()) for p in (session / "runs").glob("*/result.json")]
        self.assertEqual(len(records), 2)
        for r in records:
            self.assertEqual(r["status"], "valid")
            self.assertEqual(r["launcher_exit_code"], 42)
            self.assertGreater(r["elapsed_seconds"], 0)
            self.assertGreaterEqual(r["user_cpu_seconds"], 0)

    def test_failed_child_preserves_invalid_result_and_stops_repeats(self):
        session, _ = self.ready()
        args = argparse.Namespace(session=session, action="baseline", workload="restart",
                                  repeat=3, note="failure fixture")
        with patch.object(profile, "ROOT", self.root), patch.object(profile, "environment", return_value={}), \
                patch.object(profile, "workload", return_value=[sys.executable, "-c", "pass"]):
            with self.assertRaises(ValueError):
                profile.measure(args)
        records = list((session / "runs").glob("*/result.json"))
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0].read_text())["status"], "invalid_workload")

    def test_saved_trace_is_never_automatic_acceptance(self):
        session, _ = self.ready()
        args = argparse.Namespace(session=session, action="record", workload="restart",
                                  note="mock capture", template="Time Profiler", time_limit=None)

        def fake_trace(argv, **kwargs):
            Path(argv[argv.index("--output") + 1]).mkdir()
            return subprocess.CompletedProcess(argv, 0)

        with patch.object(profile, "ROOT", self.root), patch.object(profile.sys, "platform", "darwin"), \
                patch.object(profile, "environment", return_value={}), \
                patch.object(profile.subprocess, "run", side_effect=fake_trace):
            profile.measure(args)
        record = json.loads(next((session / "runs").glob("*/result.json")).read_text())
        self.assertEqual(record["status"], "review_required")
        self.assertNotIn("elapsed_seconds", record)
        self.assertIn("capture_elapsed_seconds", record)


if __name__ == "__main__":
    unittest.main(verbosity=2)

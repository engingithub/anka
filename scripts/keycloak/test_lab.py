#!/usr/bin/env python3
"""Lab lifecycle/diagnostic regressions, using mocked Podman (no server claims)."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import diagnostics as d
import lab


class LabChecks(unittest.TestCase):
    def test_legacy_import_repair_preserves_contents_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "import").mkdir()
            legacy = root / "import/anka-realm.json"
            raw = b'{"realm":"anka-kc110","secret":"keep-exact-bytes"}\n'
            lab.private(legacy, raw)
            with contextlib.redirect_stdout(io.StringIO()):
                lab.repair_realm_import(root)
            canonical = root / "import/anka-kc110-realm.json"
            self.assertFalse(legacy.exists())
            self.assertEqual(canonical.read_bytes(), raw)
            self.assertEqual(canonical.stat().st_mode & 0o777, 0o600)
            before = canonical.stat().st_mtime_ns
            lab.repair_realm_import(root)
            self.assertEqual(canonical.stat().st_mtime_ns, before)

    def test_import_repair_refuses_conflicting_files_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "import").mkdir()
            for name in ("anka-realm.json", "anka-kc110-realm.json"):
                lab.json_file(root / "import" / name, {"realm": lab.REALM})
            with self.assertRaisesRegex(d.LabFailure, "ambiguous_realm_import"):
                lab.repair_realm_import(root)
            self.assertEqual(len(list((root / "import").iterdir())), 2)

    def test_import_repair_refuses_wrong_realm_and_malformed_json(self):
        for raw in (b'{"realm":"other"}', b'{broken', b'[]'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "import").mkdir()
                legacy = root / "import/anka-realm.json"
                lab.private(legacy, raw)
                with self.assertRaises(d.LabFailure):
                    lab.repair_realm_import(root)
                self.assertEqual(legacy.read_bytes(), raw)
                self.assertFalse((root / "import/anka-kc110-realm.json").exists())

    def test_import_repair_refuses_symlink_or_public_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "import").mkdir()
            secret = root / "private.json"
            lab.json_file(secret, {"realm": lab.REALM})
            legacy = root / "import/anka-realm.json"
            legacy.symlink_to(secret)
            with self.assertRaises(d.LabFailure):
                lab.repair_realm_import(root)
            legacy.unlink()
            lab.json_file(legacy, {"realm": lab.REALM})
            legacy.chmod(0o644)
            with self.assertRaisesRegex(d.LabFailure, "invalid_realm_import_permissions"):
                lab.repair_realm_import(root)

    def test_actual_keycloak_filename_error_is_classified_without_path(self):
        message = b"ERROR: File name / realm name mismatch. SECRET-PATH, contains realm SECRET-REALM"
        self.assertEqual(d.signals(message), ["realm_import_name_mismatch"])

    def test_resume_reuses_running_container_without_commands(self):
        item = {"Image": "sha256:pinned", "State": {"Status": "running"}}
        with patch.object(lab, "container", return_value=item), patch.object(lab, "run") as run:
            lab.ensure_container("owned-db", "pinned", ["podman", "run"])
            run.assert_not_called()

    def test_resume_restarts_stopped_container_and_creates_only_missing(self):
        for status in ("created", "configured", "exited", "stopped"):
            item = {"Image": "pinned", "State": {"Status": status}}
            with self.subTest(status=status), patch.object(lab, "container", return_value=item), patch.object(lab, "run") as run:
                lab.ensure_container("owned-db", "sha256:pinned", ["podman", "run"])
                run.assert_called_once_with(["podman", "start", "owned-db"], timeout=120)
        with patch.object(lab, "container", return_value=None), patch.object(lab, "run") as run:
            lab.ensure_container("owned-db", "pinned", ["podman", "run", "pinned"])
            run.assert_called_once_with(["podman", "run", "pinned"], timeout=120)

    def test_resume_refuses_foreign_image_or_unsafe_state_without_mutation(self):
        for item in ({"Image": "foreign", "State": {"Status": "running"}},
                     {"Image": "pinned", "State": {"Status": "paused"}}):
            with patch.object(lab, "container", return_value=item), patch.object(lab, "run") as run:
                with self.assertRaises(d.LabFailure):
                    lab.ensure_container("owned-db", "pinned", ["podman", "run"])
                run.assert_not_called()

    def test_exists_distinguishes_absence_from_podman_failure(self):
        for code, expected in ((0, True), (1, False), (125, None)):
            result = subprocess.CompletedProcess([], code, stderr=b"cannot connect to Podman: NEVER-PRINT-SECRET")
            with patch.object(d.subprocess, "run", return_value=result):
                if expected is None:
                    with self.assertRaises(subprocess.CalledProcessError):
                        d.exists("network", "owned")
                else:
                    self.assertIs(d.exists("network", "owned"), expected)

    def test_subprocess_error_retains_stage_exit_and_safe_reason_only(self):
        error = subprocess.CalledProcessError(125, ["podman", "SECRET-ARG"],
                                             stderr=b"Permission denied: SECRET-KEY-PATH")
        report = d.failure(error, "start_keycloak")
        self.assertEqual(report["stage"], "start_keycloak")
        self.assertEqual(report["exit_code"], 125)
        self.assertEqual(report["signals"], ["permission_denied"])
        self.assertNotIn("SECRET", json.dumps(report))

    def test_doctor_discards_env_raw_logs_and_state_error_text(self):
        item = {"Image": "pinned", "Config": {"Env": ["PASSWORD=NEVER-SHARE"]},
                "State": {"Status": "exited", "ExitCode": 1, "Error": "NEVER-SHARE", "OOMKilled": False}}
        with patch.object(d, "capture", return_value=b"password authentication failed: NEVER-SHARE"), \
             patch.object(d, "container", return_value=item):
            report = d.doctor(Path("unused"), {"name": "owned"}, lambda *a: None)
        self.assertNotIn("NEVER-SHARE", json.dumps(report))
        self.assertEqual(report["containers"]["database"]["signals"], ["database_authentication"])
        self.assertEqual(report["containers"]["keycloak"]["exit_code"], 1)
        self.assertEqual(report["realm_https"], "ready")

    def test_doctor_handles_unavailable_podman_and_incomplete_preparation(self):
        with patch.object(d, "capture", side_effect=FileNotFoundError("SECRET-PATH")):
            report = d.doctor(Path("unused"), None, lambda *a: None)
        self.assertEqual(report["podman"]["reason"], "file_or_executable_missing")
        self.assertNotIn("SECRET-PATH", json.dumps(report))
        with patch.object(d, "capture", return_value=b"{}"):
            report = d.doctor(Path("unused"), None, lambda *a: None)
        self.assertEqual(report["state"], "manifest_missing_or_invalid")

    def test_log_capture_includes_stderr_without_emitting_it(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"out", stderr=b"err")
        with patch.object(d.subprocess, "run", return_value=result):
            self.assertEqual(d.capture(["podman", "logs"], include_stderr=True), b"outerr")
            self.assertEqual(d.capture(["podman", "info"]), b"out")

    def test_cli_failure_saves_private_shareable_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def failed_prepare(*args):
                lab.stage("pull_keycloak")
                raise subprocess.CalledProcessError(125, ["SECRET-ARG"], stderr=b"manifest unknown SECRET-TOKEN")
            stderr = io.StringIO()
            with patch("sys.argv", ["lab.py", "start", "--state", str(root)]), \
                 patch.object(lab, "prepare", side_effect=failed_prepare), contextlib.redirect_stderr(stderr):
                self.assertEqual(lab.main(), 1)
            self.assertNotIn("SECRET", stderr.getvalue())
            report = next(root.glob("failure-*.json"))
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            data = json.loads(report.read_text())
            self.assertEqual(data["stage"], "pull_keycloak")
            self.assertEqual(data["signals"], ["image_unavailable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Driver regressions, no Podman or Rust compiler required."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import bridge_acceptance as a


class Checks(unittest.TestCase):
    def transcript(self):
        e = a.Evidence()
        for case in a.CASES:
            for name in [case, "issued"] + (["fault"] if case in a.CASES[1:7] else []) + ["restore"]:
                self.assertTrue(e.line(("test prefix ... LK110 EVENT " + name).encode(), lambda *_: None))
            e.line(("LK110 PASS " + case).encode(), lambda *_: None)
        return e

    def test_success_requires_every_case_completion_libtest_and_exit(self):
        e = self.transcript()
        self.assertFalse(e.accepted(0))
        e.line(b"LK110 COMPLETE 10; live=false boot=false", None)
        self.assertFalse(e.accepted(0))
        e.line(b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2080 filtered out; finished in 101.01s", None)
        self.assertTrue(e.accepted(0))
        self.assertFalse(e.accepted(1))

    def test_missing_duplicate_reordered_events_reject_before_action(self):
        for line in (b"LK110 EVENT issued", b"LK110 EVENT fault", b"LK110 EVENT invented"):
            called = []
            with self.assertRaises(a.kc.Denied): a.Evidence().line(line, lambda *_: called.append(True))
            self.assertFalse(called)
        e = a.Evidence(); e.line(b"LK110 EVENT positive", lambda *_: None)
        with self.assertRaises(a.kc.Denied): e.line(b"LK110 EVENT positive", lambda *_: None)

    def test_pass_before_fault_or_restore_cannot_claim_acceptance(self):
        e = a.Evidence(); e.line(b"LK110 EVENT positive", lambda *_: None)
        with self.assertRaises(a.kc.Denied): e.line(b"LK110 PASS positive", None)
        with self.assertRaises(a.kc.Denied): a.Evidence().line(b"LK110 COMPLETE 10; live=false boot=false", None)

    def test_zero_tests_ignored_failed_and_duplicate_results_rejected(self):
        for result in (b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2081 filtered out; finished in 0s",
                       b"test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2080 filtered out; finished in 0s",
                       b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2080 filtered out; finished in 1s"):
            with self.assertRaises(a.kc.Denied): a.Evidence().line(result, None)
        e = self.transcript(); e.line(b"LK110 COMPLETE 10; live=false boot=false", None)
        with self.assertRaises(a.kc.Denied): e.line(b"LK110 COMPLETE 10; live=false boot=false", None)

    def test_discovery_selects_one_exact_ignored_witness(self):
        good = (a.WITNESS + ": test\n\n1 test, 0 benchmarks\n").encode()
        for code, output, success in ((0, good, True), (1, good, False), (0, b"0 tests", False), (0, good+good, False)):
            with patch.object(a.subprocess, "run", return_value=subprocess.CompletedProcess([], code, output)) as run:
                if success: a.discover(Path("/fake binary"))
                else:
                    with self.assertRaises(a.kc.Denied): a.discover(Path("/fake binary"))
                self.assertEqual(run.call_args.args[0], ["/fake binary", a.WITNESS, "--exact", "--ignored", "--list"])

    def test_ordinary_profile_copy_excludes_admin_and_workload_secrets(self):
        self.assertEqual(set(a.ORDINARY), {"ca.pem", "holder.pem", "holder.key", "introspection.secret"})
        self.assertNotIn("admin.secret", a.ORDINARY)
        self.assertNotIn("workload.secret", a.ORDINARY)

    def test_recovery_refuses_wrong_container_without_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); root.chmod(0o700)
            record = {"schema": 1, "realm_id": "r", "original": {}, "allowed": {}, "container": "other"}
            a.lab.json_file(root/a.JOURNAL, record)
            with patch.object(a, "Lab") as lab, patch.object(a.lab, "start") as start:
                lab.return_value.manifest = {"name": "anka-kc110-12345678"}
                with self.assertRaises(a.kc.Denied): a.recover(root)
                start.assert_not_called(); lab.return_value.restore.assert_not_called()

    def test_restore_refuses_foreign_realm_or_policy_without_write(self):
        obj = object.__new__(a.Lab); obj.root=Path("/unused"); obj.stopped=False; obj.admin="private"
        obj.record={"realm_id":"expected", "original":{"notBefore":0,"accessTokenLifespan":120},
                    "allowed":{"notBefore":[0,50],"accessTokenLifespan":[120,20]}}
        for current in ({"id":"wrong","notBefore":0,"accessTokenLifespan":120},
                        {"id":"expected","notBefore":51,"accessTokenLifespan":120}):
            with patch.object(obj,"realm",return_value=current), patch.object(a.lab,"request") as request:
                with self.assertRaises(a.kc.Denied): obj.restore(remove=True)
                request.assert_not_called()

    def test_profile_fixed_private_packet_is_not_worker_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            # Exercise real length and padding encoder using a mocked verifier,
            # while keeping credentials absent from diagnostics.
            config={"token_file":root/"token", "holder_cert_file":root/"cert", "issuer":"https://example/realms/r",
                    "audience":"aud","issuing_client":"client"}
            class Inputs:
                def read(self,path,**kw): return b"a.b.c" if path.name=="token" else b"cert"
                def recheck(self): pass
            with patch.object(a.kc,"Inputs",Inputs),patch.object(a.kc,"load_config",return_value=config), \
                 patch.object(a.kc,"verify_identity",return_value={"claims":{"sub":"subject"}}), \
                 patch.object(a.ssl,"PEM_cert_to_DER_cert",return_value=b"der"):
                packet=a.profile(root)
            self.assertEqual(len(packet),24576);self.assertEqual(packet[:8],b"LK110P1\0")
            self.assertEqual(packet[40:44],(5).to_bytes(4,"little"))
            self.assertEqual(packet[44:49],b"a.b.c")
            self.assertEqual(packet[-64:],bytes(64))

    def fake_lab(self):
        class Fake:
            def __init__(self,root): self.manifest={"port":8443}; self.restored=False
            def journal(self): pass
            def action(self,*args): pass
            def restore(self,remove=False): self.restored=True
        return Fake

    def executable(self,root,body):
        p=root/"fake test binary"
        p.write_text("#!/usr/bin/env python3\nimport sys,time\n"+body)
        p.chmod(0o700)
        return p

    def test_supervisor_runs_exact_protocol_and_writes_private_report(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); root.chmod(0o700)
            for name in a.ORDINARY: a.lab.private(root/name,b"ordinary fixture")
            body=r"""cases=%r
for case in cases:
    for event in [case,'issued']+(['fault'] if case in cases[1:7] else [])+['restore']:
        print('LK110 EVENT '+event,flush=True)
        assert sys.stdin.readline()=='continue\n'
    print('LK110 PASS '+case,flush=True)
print('LK110 COMPLETE 10; live=false boot=false')
print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2080 filtered out; finished in 1s')
""" % (a.CASES,)
            binary=self.executable(root,body)
            with patch.object(a,'discover'),patch.object(a,'Lab',self.fake_lab()),patch.object(a.lab,'start'),patch('builtins.print'):
                report=a.run(root,binary,10)
            self.assertEqual(json.loads(report.read_text())['cases'],list(a.CASES))
            self.assertEqual(report.stat().st_mode&0o077,0)
            self.assertFalse(list(root.glob('bridge-client-*')))

    def test_supervisor_kills_hung_child_and_restores_lab(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            for name in a.ORDINARY: a.lab.private(root/name,b"ordinary fixture")
            binary=self.executable(root,'time.sleep(20)\n')
            instance=self.fake_lab()(root)
            with patch.object(a,'discover'),patch.object(a,'Lab',return_value=instance),patch.object(a.lab,'start'):
                with self.assertRaises(a.RunFailure) as failure:a.run(root,binary,.1)
            self.assertTrue(instance.restored)
            self.assertEqual(failure.exception.report['failure'],'suite_timeout')
            self.assertEqual(failure.exception.report['status'],'failed')
            self.assertIsNone(failure.exception.report['restore_failure'])

    def test_new_case_replaces_only_runtime_token(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            instance=object.__new__(a.Lab);instance.root=root;instance.runtime=root;instance.claims=None
            with patch.object(instance,'restore'),patch.object(instance,'change'),patch.object(a.lab,'issue',side_effect=['one','two']), \
                 patch.object(a.kc,'parse_token',return_value=('',{}, {'iat':1,'exp':10},b'',b'')):
                instance.action('positive','positive')
                instance.action('outage_fresh','outage_fresh')
            self.assertEqual((root/'access.token').read_text(),'two')
            self.assertEqual((root/'access.token').stat().st_mode&0o077,0)

    def test_failure_and_restore_error_are_both_retained_without_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            for name in a.ORDINARY:a.lab.private(root/name,b"ordinary fixture")
            a.lab.private(root/a.JOURNAL,'{}')
            binary=self.executable(root,"print('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2101 filtered out; finished in 1s')\n")
            instance=self.fake_lab()(root)
            with patch.object(a,'discover'),patch.object(a,'Lab',return_value=instance),patch.object(a.lab,'start'), \
                 patch.object(instance,'restore',side_effect=a.kc.Denied('restore_conflict')) as restore:
                with self.assertRaises(a.RunFailure) as caught:a.run(root,binary,10)
            restore.assert_called_once_with(remove=True)
            report=json.loads(caught.exception.path.read_text())
            self.assertEqual(report['failure'],'libtest_result')
            self.assertEqual(report['restore_failure'],'restore_conflict')
            self.assertTrue(report['recovery_required'])
            self.assertEqual(report['status'],'failed')

    def test_pipe_close_error_does_not_skip_restoration(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            for name in a.ORDINARY:a.lab.private(root/name,b"ordinary fixture")
            binary=self.executable(root,"print('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2101 filtered out; finished in 1s')\n")
            instance=self.fake_lab()(root);original=a.subprocess.Popen
            class Pipe:
                def __init__(self,inner):self.inner=inner
                def write(self,*args):return self.inner.write(*args)
                def flush(self):return self.inner.flush()
                def close(self):
                    self.inner.close();raise BrokenPipeError('SECRET child details')
            def spawn(*args,**kw):
                child=original(*args,**kw);child.stdin=Pipe(child.stdin);return child
            with patch.object(a,'discover'),patch.object(a,'Lab',return_value=instance),patch.object(a.lab,'start'), \
                 patch.object(a.subprocess,'Popen',side_effect=spawn):
                with self.assertRaises(a.RunFailure) as caught:a.run(root,binary,10)
            self.assertTrue(instance.restored)
            self.assertEqual(caught.exception.report['cleanup_failure'],'child_pipe_closed')
            self.assertIsNone(caught.exception.report['restore_failure'])
            self.assertNotIn('SECRET',caught.exception.path.read_text())

    def test_setup_failure_after_journal_still_restores(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            for name in a.ORDINARY:a.lab.private(root/name,b"ordinary fixture")
            binary=self.executable(root,'pass\n');instance=self.fake_lab()(root)
            with patch.object(a,'discover'),patch.object(a,'Lab',return_value=instance), \
                 patch.object(a.lab,'start',side_effect=a.lab.LabFailure('keycloak_readiness_deadline')):
                with self.assertRaises(a.RunFailure) as caught:a.run(root,binary,10)
            self.assertTrue(instance.restored)
            self.assertEqual(caught.exception.report['failure'],'keycloak_readiness_deadline')

    def test_reason_redacts_arbitrary_exception_and_lab_details(self):
        for error in (RuntimeError('SECRET'),a.kc.Denied('SECRET'),a.lab.LabFailure('SECRET')):
            self.assertNotIn('SECRET',a.reason(error))
        self.assertEqual(a.reason(a.kc.Denied('restore_conflict')),'restore_conflict')


if __name__ == "__main__": unittest.main(verbosity=2)

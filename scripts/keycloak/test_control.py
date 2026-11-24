#!/usr/bin/env python3
"""AC110 worker checks: mock realm transitions and real local mTLS transport.
These fixtures do not claim real Keycloak acceptance or exclusive mediation.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
from unittest.mock import patch

import control as c
import lab

def request(action=1): return (action, 2, 3, 4, 5, 6, 7, 8, 9)

class FakeRemote:
    def __init__(self):
        self.identity, self.current, self.calls = "realm-id", 0, []
        self.fail = None
    def login(self): self.calls.append("login")
    def realm(self):
        self.calls.append("read")
        return self.identity, self.current
    def token(self): self.calls.append("token"); return "opaque", {"iat": 100}
    def status(self, token, claims, active):
        self.calls.append(("status", active))
        if self.fail == "status" and not active: raise c.kc.Denied("inactive")
    def set_not_before(self, value):
        self.calls.append(("write", value)); self.current = value
        if self.fail == "write": raise c.kc.Denied("lost_reply")

class ControlChecks(unittest.TestCase):
    def test_request_exact_frame_all_truncations_tail_and_shape(self):
        raw = c.REQUEST.pack(c.QMAGIC, *request())
        self.assertEqual(c.parse_request(raw), request())
        for n in range(len(raw)):
            with self.assertRaises(c.kc.Denied): c.parse_request(raw[:n])
        for raw in (raw+b"x", b"X"+raw[1:]):
            with self.assertRaises(c.kc.Denied): c.parse_request(raw)
        for index in range(5):
            q=list(request());q[index]=0
            with self.assertRaises(c.kc.Denied): c.parse_request(c.REQUEST.pack(c.QMAGIC,*q))
        q=list(request());q[5:]=[0]*4
        with self.assertRaises(c.kc.Denied): c.parse_request(c.REQUEST.pack(c.QMAGIC,*q))

    def test_transaction_restores_and_correlates_without_authority_fields(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);remote=FakeRemote();raw=c.transaction(root,request(),remote)
            values=c.REPLY.unpack(raw)
            self.assertEqual(len(raw),120);self.assertEqual(values[1:10],request())
            self.assertEqual(values[10:],(1,0,101,0,31));self.assertEqual(remote.current,0)
            self.assertEqual([x for x in remote.calls if isinstance(x,tuple)],
                             [("status",True),("write",101),("status",False),("write",0),("status",True)])
            self.assertFalse((root/c.JOURNAL).exists())

    def test_lost_reply_leaves_private_journal_and_blocks_new_probe(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);remote=FakeRemote();remote.fail="write"
            with self.assertRaises(c.kc.Denied): c.transaction(root,request(),remote)
            self.assertEqual(remote.current,101)
            self.assertEqual((root/c.JOURNAL).stat().st_mode&0o777,0o600)
            count=len(remote.calls)
            with self.assertRaisesRegex(c.kc.Denied,"recovery_required"): c.transaction(root,request(),remote)
            self.assertEqual(len(remote.calls),count)

    def test_recovery_restores_only_recorded_realm_and_value(self):
        for changed in ("none","realm","value"):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);remote=FakeRemote();remote.fail="status"
                with self.assertRaises(c.kc.Denied):c.transaction(root,request(),remote)
                remote.fail=None
                if changed=="realm":remote.identity="foreign"
                if changed=="value":remote.current=555
                before=len(remote.calls)
                if changed=="none":
                    raw=c.transaction(root,request(2),remote);self.assertEqual(c.REPLY.unpack(raw)[10:],(2,0,101,0,8))
                    self.assertFalse((root/c.JOURNAL).exists())
                else:
                    with self.assertRaisesRegex(c.kc.Denied,"restore_conflict"):c.transaction(root,request(2),remote)
                    self.assertFalse(any(isinstance(x,tuple) and x[0]=="write" for x in remote.calls[before:]))
                    self.assertTrue((root/c.JOURNAL).exists())

    def test_already_restored_recovery_performs_no_write(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);remote=FakeRemote();remote.fail="status"
            with self.assertRaises(c.kc.Denied):c.transaction(root,request(),remote)
            remote.fail=None;remote.current=0;remote.calls=[]
            c.transaction(root,request(2),remote)
            self.assertFalse(any(isinstance(x,tuple) for x in remote.calls))

    def test_changed_input_before_mutation_prevents_write(self):
        with tempfile.TemporaryDirectory() as d:
            remote=FakeRemote()
            def changed():raise c.kc.Denied("input_changed")
            with self.assertRaises(c.kc.Denied):c.transaction(Path(d),request(),remote,changed)
            self.assertEqual(remote.current,0);self.assertFalse((Path(d)/c.JOURNAL).exists())

    def test_journal_duplicate_boolean_foreign_and_symlink_refused(self):
        for bad in ("duplicate","boolean","foreign","symlink","public"):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);remote=FakeRemote();remote.fail="status"
                with self.assertRaises(c.kc.Denied):c.transaction(root,request(),remote)
                path=root/c.JOURNAL;value=json.loads(path.read_text());remote.calls=[]
                if bad=="boolean":value["original"]=False
                if bad=="foreign":value["realm"]="other"
                if bad in ("boolean","foreign"):path.write_text(json.dumps(value))
                if bad=="duplicate":path.write_text('{"schema":1,"schema":1}')
                if bad=="public":path.chmod(0o644)
                if bad=="symlink":path.rename(root/"saved");path.symlink_to(root/"saved")
                with self.assertRaises(c.kc.Denied):c.transaction(root,request(2),remote)
                self.assertEqual(remote.calls,[])

    def test_json_bounds_duplicate_depth_and_nonfinite_reject(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}',b'[]',b'x'*65537,
                    b'{"a":'+b'['*18+b'0'+b']'*18+b'}'):
            with self.assertRaises(c.kc.Denied):c.bounded_json(raw)

    def test_worker_errors_do_not_echo_arguments_or_credentials(self):
        p=subprocess.run([sys.executable,"-I",str(Path(c.__file__)),"--SECRET-ARGUMENT"],
                         input=b"",capture_output=True,timeout=5)
        self.assertNotEqual(p.returncode,0);self.assertNotIn(b"SECRET-ARGUMENT",p.stdout+p.stderr)

    def test_changed_inputs_after_revocation_retain_recovery_record(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);remote=FakeRemote();calls=0
            def changed():
                nonlocal calls
                calls+=1
                if calls==2:raise c.kc.Denied("input_changed")
            with self.assertRaises(c.kc.Denied):c.transaction(root,request(),remote,changed)
            self.assertEqual(remote.current,101);self.assertTrue((root/c.JOURNAL).exists())

    def test_recovery_without_record_never_contacts_server(self):
        with tempfile.TemporaryDirectory() as d:
            remote=FakeRemote()
            with self.assertRaises(c.kc.Denied):c.transaction(Path(d),request(2),remote)
            self.assertEqual(remote.calls,[])

    def test_recovery_rejects_changed_configuration_or_credential_binding(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);remote=FakeRemote();remote.fail="status"
            with self.assertRaises(c.kc.Denied):c.transaction(root,request(),remote,binding="a"*64)
            remote.fail=None;remote.calls=[]
            with self.assertRaisesRegex(c.kc.Denied,"recovery_binding"):
                c.transaction(root,request(2),remote,binding="b"*64)
            self.assertEqual(remote.calls,[]);self.assertTrue((root/c.JOURNAL).exists())

    def test_failure_report_is_private_and_redacts_unexpected_exception(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);c.save_failure(root,RuntimeError("SECRET-TOKEN-AND-PATH"))
            report=next(root.glob("control-failure-*.json"));raw=report.read_text()
            self.assertNotIn("SECRET",raw);self.assertEqual(report.stat().st_mode&0o777,0o600)
            data=json.loads(raw);self.assertEqual(data["reason"],"worker_error")
            self.assertFalse(data["live_admission"]);self.assertEqual(data["current_authority"],"unknown")


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.handle_request("GET")
    def do_POST(self):self.handle_request("POST")
    def do_PUT(self):self.handle_request("PUT")
    def handle_request(self,method):
        s=self.server;raw=self.rfile.read(int(self.headers.get("Content-Length","0")))
        s.requests.append((method,self.path,raw,self.connection.getpeercert(binary_form=True)))
        status=200;data={}
        if self.path=="/realms/master/protocol/openid-connect/token":data={"access_token":"test-admin"}
        elif self.path==f"/admin/realms/{c.REALM}":
            if method=="PUT":s.not_before=json.loads(raw)["notBefore"];status=204
            else:data={"realm":c.REALM,"id":"fixture-realm","enabled":True,"notBefore":s.not_before}
        elif self.path.endswith("/token"):
            claims={"iss":s.issuer,"sub":"workload-subject","aud":"anka-preflight","azp":"anka-workload",
                    "typ":"Bearer","iat":int(time.time()),"exp":int(time.time())+120,"jti":"test",
                    "cnf":{"x5t#S256":s.holder}}
            enc=lambda v:c.kc.b64(json.dumps(v).encode())
            token=enc({"alg":"RS256","typ":"JWT","kid":"fixture"})+'.'+enc(claims)+'.AA'
            s.tokens[token]=claims;data={"access_token":token}
        elif self.path.endswith("/introspect"):
            claims=s.tokens[parse_qs(raw.decode())["token"][0]]
            data=dict(claims,active=True,client_id="anka-workload",token_type="Bearer") if claims["iat"]>=s.not_before else {"active":False}
            if s.mode=="numeric_active":data["active"]=1
        else:status=404
        if s.mode=="redirect":status=302
        if s.mode=="outage":status=503
        body=b"" if status==204 else json.dumps(data).encode()
        if s.mode=="duplicate":body=b'{"x":1,"x":2}'
        if s.mode=="oversize":body=b'x'*65537
        self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        if s.mode=="duplicate_length":self.send_header("Content-Length",str(len(body)))
        if s.mode=="compressed":self.send_header("Content-Encoding","gzip")
        self.end_headers()
        if body:self.wfile.write(body)


class HTTPChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="anka AC110 mTLS ");cls.root=Path(cls.temp.name)
        lab.certificates(cls.root)
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),Handler);cls.server.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.root/"server.pem"),str(cls.root/"server.key"))
        context.load_verify_locations(cafile=str(cls.root/"ca.pem"));context.verify_mode=ssl.CERT_REQUIRED
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.server.issuer=f"https://localhost:{cls.server.server_port}/realms/{c.REALM}"
        cls.server.holder=c.kc.b64(c.hashlib.sha256(ssl.PEM_cert_to_DER_cert((cls.root/"holder.pem").read_text())).digest())
        for name in ("admin","workload","introspection"):lab.private(cls.root/(name+".secret"),"secret-"+name)
        lab.json_file(cls.root/"config.json",lab.configuration(cls.server.server_port))
        lab.json_file(cls.root/"lab.json",{"profile":c.kc.PROFILE,"port":cls.server.server_port})
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.temp.cleanup()
    def setUp(self):
        self.server.requests=[];self.server.tokens={};self.server.mode="normal";self.server.not_before=0
        (self.root/c.JOURNAL).unlink(missing_ok=True)

    def test_real_mtls_worker_restores_state_and_keeps_tokens_off_pipe(self):
        raw=c.perform(self.root,request());self.assertEqual(c.REPLY.unpack(raw)[10],1)
        self.assertEqual(self.server.not_before,0);self.assertEqual(len(self.server.requests),12)
        self.assertTrue(all(x[3] for x in self.server.requests));self.assertNotIn(b"secret",raw)
        self.assertFalse((self.root/c.JOURNAL).exists())

    def test_private_subprocess_protocol_with_real_mtls(self):
        result=subprocess.run([sys.executable,"-I",str(Path(c.__file__)),"--state",str(self.root)],
                              input=c.REQUEST.pack(c.QMAGIC,*request()),capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(len(result.stdout),120)
        self.assertEqual(c.REPLY.unpack(result.stdout)[1:10],request())

    def test_redirect_outage_duplicate_oversize_encoding_and_framing_deny(self):
        for mode in ("redirect","outage","duplicate","oversize","compressed","duplicate_length"):
            self.server.mode=mode
            with self.assertRaises(c.kc.Denied):c.perform(self.root,request())
            self.assertEqual(self.server.not_before,0)

    def test_invalid_request_never_reads_state_or_calls_network(self):
        result=subprocess.run([sys.executable,"-I",str(Path(c.__file__)),"--state",str(self.root)],
                              input=c.REQUEST.pack(c.QMAGIC,*request())+b"tail",capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertEqual(self.server.requests,[])

    def test_held_local_control_lock_denies_without_network(self):
        fd=os.open(self.root/"control.lock",os.O_RDWR|os.O_CREAT,0o600)
        try:
            c.fcntl.flock(fd,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):c.perform(self.root,request())
            self.assertEqual(self.server.requests,[])
        finally:os.close(fd)

    def test_private_state_permissions_and_symlinks_deny(self):
        self.root.chmod(0o755)
        try:
            with self.assertRaises(c.kc.Denied):c.perform(self.root,request())
        finally:self.root.chmod(0o700)
        with tempfile.TemporaryDirectory() as d:
            link=Path(d)/"state";link.symlink_to(self.root)
            with self.assertRaises(c.kc.Denied):c.perform(link,request())
        self.assertEqual(self.server.requests,[])

    def test_numeric_active_is_not_boolean_acceptance(self):
        self.server.mode="numeric_active"
        with self.assertRaises(c.kc.Denied):c.perform(self.root,request())
        self.assertEqual(self.server.not_before,0)

    def test_wrong_ca_and_certificate_key_pair_fail_closed(self):
        for path,other in [(self.root/"ca.pem",self.root/"server.pem"),
                           (self.root/"holder.key",self.root/"other.key")]:
            saved=path.read_bytes();path.write_bytes(other.read_bytes())
            try:
                with self.assertRaises((c.kc.Denied,ssl.SSLError)):c.perform(self.root,request())
                self.assertEqual(self.server.not_before,0)
            finally:path.write_bytes(saved)


if __name__=="__main__":unittest.main(verbosity=2)

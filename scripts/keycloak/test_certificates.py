#!/usr/bin/env python3
"""Real RSA/TLS regressions; Podman is mocked, no Rust or real Keycloak run."""
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch
import lab
import repair_server_certificate as repair


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        lab.certificates(cls.root)

    @classmethod
    def tearDownClass(cls): cls.directory.cleanup()

    def test_generated_server_passes_strict_tls_and_rejects_wrong_hostname(self):
        root = self.root
        repair.strict_probe(str(root/'ca.pem'), str(root/'server.pem'), str(root/'server.key'))
        with self.assertRaises(ssl.SSLCertVerificationError):
            repair.strict_probe(str(root/'ca.pem'), str(root/'server.pem'), str(root/'server.key'), 'wrong.example')

    def test_all_leaves_explicitly_request_key_identifiers(self):
        for name in ('server', 'holder', 'other'):
            ext = (self.root/(name+'.ext')).read_text()
            self.assertIn('subjectKeyIdentifier=hash', ext)
            self.assertIn('authorityKeyIdentifier=keyid:always,issuer', ext)
            text = lab.run(['openssl','x509','-in',str(self.root/(name+'.pem')),'-noout','-text'])
            self.assertIn(b'X509v3 Authority Key Identifier',text)
            self.assertIn(b'X509v3 Subject Key Identifier',text)

    def fixture(self, root):
        for p in self.root.iterdir():
            if p.is_file(): lab.private(root/p.name,p.read_bytes())
        (root/'server-certs').mkdir(mode=0o700)
        for name in ('server.pem','server.key','ca.pem'):
            lab.private(root/'server-certs'/name,(root/name).read_bytes())
        lab.json_file(root/'lab.json',{'profile':lab.PROFILE,'name':'anka-kc110-12345678',
                     'images':{'keycloak':{'id':'sha256:pinned'}}})

    def test_missing_aki_is_reproduced_and_repair_preserves_keys_holders_and_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.fixture(root)
            # First reproduce the original extension file. Some OpenSSL versions
            # supply identifiers automatically; only then explicitly suppress them.
            ext=root/'legacy.ext'
            legacy=('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                    'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
            lab.private(ext,legacy)
            command=['openssl','x509','-req','-in',str(root/'server.csr'),'-CA',str(root/'ca.pem'),
                     '-CAkey',str(root/'ca.key'),'-set_serial','987','-days','7','-extfile',str(ext),'-out',str(root/'server.pem')]
            lab.run(command)
            try:
                repair.strict_probe(str(root/'ca.pem'),str(root/'server.pem'),str(root/'server.key'))
            except ssl.SSLCertVerificationError as error:
                self.assertEqual(error.verify_code,85)
            else:
                ext.write_text(legacy+'authorityKeyIdentifier=none\nsubjectKeyIdentifier=none\n')
                lab.run(command)
            (root/'server-certs/server.pem').write_bytes((root/'server.pem').read_bytes())
            with self.assertRaises(ssl.SSLCertVerificationError) as failure:
                repair.strict_probe(str(root/'ca.pem'),str(root/'server.pem'),str(root/'server.key'))
            self.assertEqual(failure.exception.verify_code,85)
            names=['ca.pem','ca.key','server.key','holder.pem','holder.key','other.pem','other.key','lab.json']
            before={n:(root/n).read_bytes() for n in names}
            real_run=lab.run;commands=[]
            def run(argv,**kw):
                if argv[0]=='podman':commands.append(argv);return b''
                return real_run(argv,**kw)
            item={'Image':'sha256:pinned','State':{'Status':'running'}}
            with patch.object(lab,'container',return_value=item),patch.object(lab,'run',side_effect=run),patch.object(lab,'start') as start:
                repair.repair(root);start.assert_called_once()
            self.assertEqual(commands,[['podman','restart','anka-kc110-12345678-server']])
            for name in names:self.assertEqual((root/name).read_bytes(),before[name])
            self.assertEqual((root/'server.pem').read_bytes(),(root/'server-certs/server.pem').read_bytes())
            repair.strict_probe(str(root/'ca.pem'),str(root/'server.pem'),str(root/'server.key'))
            self.assertEqual((root/'server.pem').stat().st_mode&0o077,0)

    def test_repair_refuses_foreign_container_before_signing_or_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);before=(root/'server.pem').read_bytes()
            with patch.object(lab,'container',return_value={'Image':'foreign','State':{'Status':'running'}}),patch.object(lab,'run') as run:
                with self.assertRaises(repair.kc.Denied):repair.repair(root)
                run.assert_not_called()
            self.assertEqual((root/'server.pem').read_bytes(),before)

    def test_repair_refuses_symlink_key_or_pending_recovery(self):
        for fault in ('symlink','journal'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.fixture(root)
                if fault=='symlink':
                    (root/'ca.key').unlink();(root/'ca.key').symlink_to(self.root/'ca.key')
                else:lab.private(root/'bridge-recovery.json','{}')
                with patch.object(lab,'container',return_value={'Image':'pinned','State':{'Status':'running'}}),patch.object(lab,'run') as run:
                    with self.assertRaises(repair.kc.Denied):repair.repair(root)
                    run.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)

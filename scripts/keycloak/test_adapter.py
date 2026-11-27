#!/usr/bin/env python3
"""LA110 real RSA/mTLS verifier fixtures. Never compiles or invokes Rust."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import test_preflight as fixture

a = fixture.module("adapter")
p = a.p
ROOT = Path(__file__).resolve().parent


def record(token, holder, strings, kind=1, binding=bytes(32), channel=bytes(32)):
    correlation = [1, 500, 5, 600, 1, 3, 100, 101, 10]
    scope = [20, 3, 30, 1, 40, 2, 50, 1, 1, 6, 7, 8, 9, 5, 10, 11]
    out = a.MAGIC + struct.pack("<Q", kind) + bytes([7])*32
    out += struct.pack("<25Q", *correlation, *scope) + holder + channel + binding + struct.pack("<Q", 5)
    for b in [token, *[s.encode() for s in strings]]:
        out += struct.pack("<I", len(b)) + b
    return out


def framed(rec, signature=b""):
    return rec + struct.pack("<I", len(signature)) + signature


class Checks(unittest.TestCase):
    setUpClass = classmethod(fixture.Checks.setUpClass.__func__)
    tearDownClass = classmethod(fixture.Checks.tearDownClass.__func__)
    jwk = staticmethod(fixture.Checks.jwk)
    write = fixture.Checks.write
    setUp = fixture.Checks.setUp
    token = fixture.Checks.token
    configure = fixture.Checks.configure

    def rec(self, kind=1, binding=bytes(32), channel=bytes(32)):
        return record(self.raw_token.encode(), p.unb64(self.holder),
                      [self.config['issuer'], self.config['audience'], self.config['issuing_client'], self.claims['sub']],
                      kind, binding, channel)

    def query(self):
        rec = self.rec()
        result = a.perform(a.parse(framed(rec)), self.path)
        self.assertEqual(struct.unpack_from('<Q', result, 8)[0], 1)
        self.assertEqual(result[72:], rec)
        return result[40:72]

    def sign(self, rec, key=None):
        file = self.write('holder-record.bin', rec)
        return fixture.lab.run(['openssl', 'dgst', '-sha256', '-sign', str(key or self.root/'holder.key'),
                                '-sigopt', 'rsa_padding_mode:pkcs1', str(file)])

    def worker(self, raw, extra=None):
        result = subprocess.run([sys.executable, '-I', str(ROOT/'adapter.py'),
                                 '--config', str(self.path), *(extra or [])], input=raw,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.stderr, b'')
        return result

    def test_real_identity_signature_mtls_and_private_exact_reply(self):
        binding = self.query()
        self.assertNotEqual(binding, bytes(32))
        self.assertEqual(len(self.server.requests), 1)
        self.assertIn(b'token=', self.server.requests[0][2])
        self.assertTrue(self.server.requests[0][3])
        result = self.worker(framed(self.rec(binding=binding)))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(struct.unpack_from('<4Q', result.stdout, 8),
                         (1, self.claims['iat'], self.claims.get('nbf', self.claims['iat']), self.claims['exp']))

    def test_verified_inactive_is_negative_but_malformed_and_outage_are_unknown(self):
        with self.assertRaises(p.Denied): p.verify_identity(self.path, allow_inactive=True)
        self.query()
        for info, mode, expected in [({'active': False}, 'normal', 2), ({'active': 0}, 'normal', 0),
                                      ({'active': False, 'extra': 'x'}, 'normal', 0),
                                      ({'active': True}, 'normal', 0), ({}, 'outage', 0)]:
            self.server.info, self.server.mode = info, mode
            result = self.worker(framed(self.rec()))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(struct.unpack_from('<Q', result.stdout, 8)[0], expected)

    def test_real_holder_signature_works_without_introspection_or_signing_in_worker(self):
        binding = self.query(); count = len(self.server.requests)
        rec = self.rec(2, binding, bytes([9])*32)
        signature = self.sign(rec)
        self.server.mode = 'outage'
        result = self.worker(framed(rec, signature))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(struct.unpack_from('<4Q', result.stdout, 8), (1, 0, 0, 0))
        self.assertEqual(result.stdout[40:72], binding)
        self.assertEqual(result.stdout[72:], rec)
        self.assertEqual(len(self.server.requests), count)

    def test_signature_covers_every_correlation_and_scope_word(self):
        binding = self.query(); rec = self.rec(2, binding, bytes([9])*32); sig = self.sign(rec)
        for offset in range(48, 248, 8):
            changed = bytearray(rec)
            # Some word mutations are rejected by grammar; others by signature.
            changed[offset] ^= 2
            with self.assertRaises(p.Denied):
                a.perform(a.parse(framed(bytes(changed), sig)), self.path)

    def test_signature_covers_session_and_actual_channel_binding(self):
        binding = self.query(); rec = self.rec(2, binding, bytes([9])*32); sig = self.sign(rec)
        for offset in [16, 47, 280, 311]:
            changed = bytearray(rec); changed[offset] ^= 1
            with self.assertRaises(p.Denied): a.perform(a.parse(framed(bytes(changed), sig)), self.path)

    def test_signature_substitution_wrong_key_and_wrong_holder_fail(self):
        binding = self.query(); rec = self.rec(2, binding, bytes([9])*32)
        signature = bytearray(self.sign(rec)); signature[0] ^= 1
        for sig in [bytes(signature), self.sign(rec, self.issuer)]:
            with self.assertRaises(p.Denied): a.perform(a.parse(framed(rec, sig)), self.path)
        changed = bytearray(rec); changed[248] ^= 1
        with self.assertRaises(p.Denied): a.perform(a.parse(framed(bytes(changed), self.sign(bytes(changed)))), self.path)

    def test_token_bytes_not_jti_are_immutable(self):
        rec = self.rec(); self.claims['exp'] += 1; self.token()
        result = self.worker(framed(rec))
        self.assertEqual(struct.unpack_from('<Q', result.stdout, 8)[0], 3)
        self.assertEqual(self.server.requests, [])

    def test_changed_inputs_close_even_when_identity_claims_still_match(self):
        binding = self.query()
        self.configure(timeout_seconds=2 if self.config['timeout_seconds'] != 2 else 3)
        result = self.worker(framed(self.rec(binding=binding)))
        self.assertEqual(struct.unpack_from('<Q', result.stdout, 8)[0], 3)

    def test_changed_inputs_during_introspection_cannot_publish_positive(self):
        self.server.callback = lambda: self.write('introspection.secret', 'changed-secret')
        result = self.worker(framed(self.rec()))
        self.assertEqual(struct.unpack_from('<Q', result.stdout, 8)[0], 3)

    def test_wrong_identity_strings_and_holder_never_become_positive(self):
        for field in range(4):
            strings = [self.config['issuer'], self.config['audience'], self.config['issuing_client'], self.claims['sub']]
            strings[field] += '-wrong'
            rec = record(self.raw_token.encode(), p.unb64(self.holder), strings)
            with self.assertRaises(p.Denied): a.perform(a.parse(framed(rec)), self.path)

    def test_parser_every_truncation_tail_and_signature_lengths(self):
        raw = framed(self.rec())
        for n in range(len(raw)):
            with self.assertRaises((p.Denied, UnicodeError)): a.parse(raw[:n])
        for bad in [raw+b'x', bytes(a.LIMIT+1), raw[:-4]+struct.pack('<I', 1)+b'x']:
            with self.assertRaises(p.Denied): a.parse(bad)
        rec = self.rec(2, bytes([1])*32, bytes([2])*32)
        for n in [0, 1, 255, 513]:
            with self.assertRaises(p.Denied): a.parse(framed(rec, bytes(n)))

    def test_canonical_golden_shared_with_rust(self):
        expected = record(b'a.b.c', bytes([3])*32, ['https://issuer/realms/r', 'aud', 'client', 'subject'],
                          2, bytes([4])*32, bytes([9])*32)
        self.assertEqual(expected, (ROOT/'fixtures/lg110-holder-record.bin').read_bytes())
        self.assertEqual(a.parse(framed(expected, bytes(256)))['record'], expected)

    def test_bad_cli_and_malformed_frames_do_not_disclose_secrets(self):
        result = self.worker(b'bad-frame')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'')
        result = self.worker(framed(self.rec()), ['SECRET_ARGUMENT'])
        self.assertEqual(result.returncode, 2); self.assertEqual(result.stdout, b'')

    def test_selected_observation_age_cannot_exceed_helper_policy(self):
        self.configure(max_observation_age_seconds=1)
        result = self.worker(framed(self.rec()))
        self.assertEqual(struct.unpack_from('<Q', result.stdout, 8)[0], 3)
        self.assertEqual(self.server.requests, [])

    def test_expired_token_cannot_become_negative_or_positive(self):
        self.claims['exp'] = self.claims['iat']; self.token(); self.server.info = {'active': False}
        result = self.worker(framed(self.rec()))
        self.assertEqual(struct.unpack_from('<Q', result.stdout, 8)[0], 0)
        self.assertEqual(self.server.requests, [])


if __name__ == '__main__':
    unittest.main()

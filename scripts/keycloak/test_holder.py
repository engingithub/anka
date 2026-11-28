#!/usr/bin/env python3
"""LT110 real hosted holder signatures; no Cargo or Rust execution."""
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import test_adapter as fixture
h = fixture.fixture.module('holder')


class Checks(fixture.Checks):
    # Reuse the real RSA/mTLS setup, not the parent test methods.
    def test_holder_exact_record_real_signature_and_no_introspection(self):
        binding = self.query()
        rec = self.rec(2, binding, bytes([9])*32)
        before = len(self.server.requests)
        output = h.sign(rec, self.path)
        self.assertEqual(len(output), 516)
        n = struct.unpack_from('<I', output)[0]
        self.assertEqual(output[4+n:], bytes(512-n))
        frame = fixture.a.parse(fixture.framed(rec, output[4:4+n]))
        verified = fixture.a.holder(frame, self.path)
        self.assertEqual(struct.unpack_from('<Q', verified, 8)[0], 1)
        self.assertEqual(len(self.server.requests), before)

    def test_holder_rejects_query_tail_and_every_truncation(self):
        binding = self.query()
        rec = self.rec(2, binding, bytes([9])*32)
        for raw in [self.rec(), rec+b'x', *[rec[:n] for n in range(len(rec))]]:
            with self.assertRaises(Exception):
                h.sign(raw, self.path)

    def test_holder_changed_input_or_wrong_certificate_denies_before_signing(self):
        binding = self.query()
        rec = self.rec(2, binding, bytes([9])*32)
        bad = bytearray(rec); bad[248] ^= 1
        with patch.object(h.subprocess, 'run', side_effect=AssertionError('must not sign')):
            with self.assertRaises(h.p.Denied): h.sign(bytes(bad), self.path)
            self.path.write_text(self.path.read_text()+'\n')
            with self.assertRaises(h.p.Denied): h.sign(rec, self.path)

    def test_holder_private_cli_success_and_redacted_rejection(self):
        binding = self.query()
        rec = self.rec(2, binding, bytes([9])*32)
        command = [sys.executable, '-I', str(fixture.ROOT/'holder.py'), '--config', str(self.path)]
        good = subprocess.run(command, input=rec, capture_output=True, timeout=10)
        self.assertEqual((good.returncode, len(good.stdout), good.stderr), (0, 516, b''))
        for raw in [b'private secret', rec+b'x']:
            bad = subprocess.run(command, input=raw, capture_output=True, timeout=10)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual((bad.stdout, bad.stderr), (b'', b''))


# Inherited tests run in the separate LA110 regression gate.
if __name__ == '__main__':
    suite = unittest.TestSuite(Checks(name) for name in sorted(Checks.__dict__) if name.startswith('test_holder_'))
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())

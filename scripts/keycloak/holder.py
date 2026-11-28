#!/usr/bin/env python3
"""Private LT110 hosted holder. Explicit trusted local delegation, never a server.

Only the bridge-created canonical action-2 record is accepted on stdin. The
supervisor bounds total time, input/output, EOF and process-group lifetime.
The existing verifier independently checks the resulting holder proof.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import ssl
import struct
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('lt110_adapter', Path(__file__).with_name('adapter.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
p = a.p


def sign(record, config_path):
    # Reuse the canonical decoder. A placeholder detached signature is needed
    # only to parse action 2; it is never treated as verified evidence.
    frame = a.parse(record + struct.pack('<I', 256) + bytes(256))
    p.require(frame['kind'] == 2 and frame['record'] == record, 'holder_record')
    inputs, config, certificate = a.snapshot(frame, config_path)
    p.require(hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.decode('ascii'))).digest()
              == frame['expected']['holder'], 'holder')
    key = inputs.read(config['holder_key_file'], private=True)
    budget = p.Budget(config['timeout_seconds'])
    budget.spend()
    with tempfile.TemporaryDirectory(prefix='anka-lt110-holder-') as dirname:
        root = Path(dirname)
        secret, message = root/'holder.key', root/'record.bin'
        for path, data in ((secret, key), (message, record)):
            with path.open('xb') as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(data)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(secret),
                                 '-sigopt', 'rsa_padding_mode:pkcs1', str(message)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=budget.timeout(),
                                env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                                     'OPENSSL_CONF': os.devnull})
        p.require(result.returncode == 0 and 256 <= len(result.stdout) <= 512, 'holder_signature')
        inputs.recheck()
        budget.check()
        a.checked_binding(frame, p.input_binding(inputs))
        # Exact fixed-size private reply; no token, key or diagnostic text.
        return struct.pack('<I', len(result.stdout)) + result.stdout.ljust(512, b'\0')


def main(argv=None):
    os.umask(0o077)
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != '--config':
        return 2
    try:
        record = sys.stdin.buffer.read(a.LIMIT + 1)
        p.require(len(record) <= a.LIMIT, 'holder_record')
        reply = sign(record, argv[1])
        sys.stdout.buffer.write(reply)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    sys.exit(main())

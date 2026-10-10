#!/usr/bin/env python3
"""Check positive proofs and explicit Z3 disproofs, never counting Unknown as rejection."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kleis', default='kleis', help='Kleis executable (default: PATH)')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
executable = str(Path(args.kleis).resolve()) if '/' in args.kleis else args.kleis
all_ok = True
for stem in ('anka107_application_pointers', 'anka107_userspace_rebuild'):
    for hostile in (False, True):
        path = root / 'theories' / (stem + ('_false_witnesses' if hostile else '') + '.kleis')
        expected = len(re.findall(r'^example\s+"', path.read_text(), re.MULTILINE))
        try:
            result = subprocess.run([executable, 'test', str(path)], cwd=root,
                                    env=os.environ, capture_output=True, text=True)
        except OSError as error:
            print(f'Cannot run Kleis: {error}', file=sys.stderr)
            sys.exit(1)
        output = result.stdout + result.stderr
        if hostile:
            actual = output.count('Assertion disproved by Z3.')
            ok = (actual == expected and f'0/{expected} examples passed' in output
                  and 'Assertion unknown' not in output)
            detail = f'{actual}/{expected} explicitly disproved'
        else:
            ok = result.returncode == 0 and f'{expected} examples passed' in output
            detail = f'{expected} positive witnesses'
        print(f'{"PASS" if ok else "FAIL"}: {path.name}: {detail}')
        if not ok:
            print(output)
        all_ok = all_ok and ok
sys.exit(0 if all_ok else 1)

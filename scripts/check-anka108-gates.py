#!/usr/bin/env python3
"""Run 10.7 prerequisites and the 10.8 I/O, rebuild and allocation gates.

Unknown, timeout, parse/evaluation errors and absent witnesses fail closed.
The hostile Kleis test command intentionally reports failing examples; only
explicit Z3 disproofs count as a successful hostile gate.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kleis', default='kleis')
    parser.add_argument('--kleis-root', default=os.environ.get('KLEIS_ROOT'),
                        help='directory containing stdlib/prelude.kleis '
                             '(default: KLEIS_ROOT environment variable)')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--only-108', action='store_true',
                           help='run all 10.8 gates, skipping 10.7')
    selection.add_argument('--only-input', action='store_true',
                           help='run only the new typed-input gate pair')
    selection.add_argument('--only-rebuild', action='store_true',
                           help='run only the rebuild-artifact gate pair')
    selection.add_argument('--only-adapter', action='store_true',
                           help='run only the concrete compiler-adapter gate pair')
    selection.add_argument('--only-modules', action='store_true',
                           help='run only the protected-module composition gate pair')
    selection.add_argument('--only-allocation', action='store_true',
                           help='run allocation lifecycle, ABI, initialization, reclamation, Undertaker, A2.2 placement, A2.3 Fabric and concrete worker gates')
    selection.add_argument('--only-initialization', action='store_true',
                           help='run only the residual-data isolation gate pair')
    selection.add_argument('--only-reclamation', action='store_true',
                           help='run only the reusable-extents and bounded-metadata gate pair')
    selection.add_argument('--only-undertaker', action='store_true',
                           help='run only the asynchronous-reclamation gate pair')
    selection.add_argument('--only-a22', action='store_true',
                           help='run only the bounded placement/reservation gate pair')
    selection.add_argument('--only-a23', action='store_true',
                           help='run only the bounded Fabric/shadow/initialization gate pair')
    selection.add_argument('--only-workers', action='store_true',
                           help='run only the concrete cleanup-worker and terminal-work gate pair')
    selection.add_argument('--only-cleanup', action='store_true',
                           help='run only the software cleanup/reuse refinement pair')
    selection.add_argument('--only-malloc', action='store_true',
                           help='run the concrete malloc/free runtime and ABI refinement')
    parser.add_argument('--timeout', type=int, default=120,
                        help='wall-clock seconds per command (default: 120)')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    root = Path(__file__).resolve().parents[1]
    executable = str(Path(args.kleis).resolve()) if '/' in args.kleis else args.kleis
    kleis_env = os.environ.copy()
    kleis_cwd = root
    if args.kleis_root:
        kleis_cwd = Path(args.kleis_root).expanduser().resolve()
        if not (kleis_cwd / 'stdlib/prelude.kleis').is_file():
            parser.error('--kleis-root/KLEIS_ROOT must name the directory '
                         'containing stdlib/prelude.kleis: ' + str(kleis_cwd))
        kleis_env['KLEIS_ROOT'] = str(kleis_cwd)
    # Some supplied Kleis CLI builds resolve stdlib imports from cwd even when
    # KLEIS_ROOT is set. Keep theory paths absolute and run from the selected
    # root so external stdlib installations work without copying into Anka.
    if not (args.only_108 or args.only_input or args.only_rebuild or args.only_adapter
            or args.only_modules or args.only_allocation or args.only_initialization
            or args.only_reclamation or args.only_undertaker or args.only_a22 or args.only_a23
            or args.only_workers or args.only_cleanup or args.only_malloc):
        try:
            previous = subprocess.run(
                [sys.executable, str(root / 'scripts/check-anka107-gates.py'),
                 '--kleis', executable], cwd=root, env=kleis_env,
                timeout=args.timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f'FAIL: 10.7 prerequisites: {error}', file=sys.stderr)
            return 1
        if previous.returncode:
            return 1
    all_ok = True
    if args.only_malloc:
        stems = ('anka108_malloc_runtime',)
    elif args.only_cleanup:
        stems = ('anka108_cleanup_reuse',)
    elif args.only_workers:
        stems = ('anka108_cleanup_workers',)
    elif args.only_a23:
        stems = ('anka108_allocation_fabric',)
    elif args.only_a22:
        stems = ('anka108_allocation_placement',)
    elif args.only_undertaker:
        stems = ('anka108_async_reclamation',)
    elif args.only_reclamation:
        stems = ('anka108_allocation_reclamation',)
    elif args.only_initialization:
        stems = ('anka108_memory_initialization',)
    elif args.only_allocation:
        stems = ('anka108_allocation', 'anka108_allocation_abi',
                 'anka108_memory_initialization', 'anka108_allocation_reclamation',
                 'anka108_async_reclamation', 'anka108_allocation_placement',
                 'anka108_allocation_fabric', 'anka108_cleanup_workers', 'anka108_cleanup_reuse', 'anka108_malloc_runtime')
    elif args.only_modules:
        stems = ('anka108_protected_modules',)
    elif args.only_adapter:
        stems = ('anka108_compiler_adapter',)
    elif args.only_rebuild:
        stems = ('anka108_rebuild_artifact',)
    elif args.only_input:
        stems = ('anka108_typed_input',)
    else:
        stems = ('anka108_typed_syscall_io', 'anka108_typed_input',
                 'anka108_rebuild_artifact', 'anka108_compiler_adapter',
                 'anka108_protected_modules', 'anka108_allocation',
                 'anka108_allocation_abi', 'anka108_memory_initialization',
                 'anka108_allocation_reclamation', 'anka108_async_reclamation',
                 'anka108_allocation_placement', 'anka108_allocation_fabric',
                 'anka108_cleanup_workers', 'anka108_cleanup_reuse', 'anka108_malloc_runtime')
    for stem in stems:
        for hostile in (False, True):
            path = root / 'theories' / (stem + ('_false_witnesses' if hostile else '') + '.kleis')
            names = re.findall(r'^example\s+"([^"]+)"', path.read_text(), re.MULTILINE)
            expected = len(names)
            if not expected or len(set(names)) != expected:
                print(f'FAIL: {path.name}: empty or duplicate witness names')
                all_ok = False
                continue
            try:
                result = subprocess.run([executable, 'test', str(path)], cwd=kleis_cwd,
                                        env=kleis_env, capture_output=True, text=True,
                                        timeout=args.timeout)
            except (OSError, subprocess.TimeoutExpired) as error:
                print(f'FAIL: {path.name}: {error}', file=sys.stderr)
                all_ok = False
                continue
            output = result.stdout + result.stderr
            disproved = output.count('Assertion disproved by Z3.')
            if hostile:
                ok = (disproved == expected
                      and f'0/{expected} examples passed ({expected} failed)' in output
                      and 'Assertion unknown' not in output
                      and 'Assertion failed' not in output)
                detail = f'{disproved}/{expected} explicitly disproved'
            else:
                ok = result.returncode == 0 and f'✅ {expected} examples passed' in output
                detail = f'{expected} positive witnesses'
            print(f'{"PASS" if ok else "FAIL"}: {path.name}: {detail}')
            if not ok:
                print(output)
            all_ok = all_ok and ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())

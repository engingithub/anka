#!/usr/bin/env python3
"""Run Phase 10.9 through 11.0 formal gates; unchanged 10.7/10.8 gates are not repeated.

Positive assertions must pass and every hostile assertion must be explicitly
DISPROVED. Unknown, missing witnesses, import errors and timeouts fail closed.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

T1_PAIRS = ('anka109_recognition', 'anka109_enrollment', 'anka109_grant_admission')

T2_PAIRS = ('anka109_persistence', 'anka109_reboot')
BACKEND_PAIRS = ('anka110_durable_record',)
PROTOCOL_PAIRS = ('anka110_persistence_protocol',)
EVIDENCE_PAIRS = ('anka110_evidence_admission',)
PROVIDER_PAIRS = ('anka110_evidence_provider',)

GUARDED_PAIRS = ('anka110_guarded_transport',)

BINDER_PAIRS = ('anka110_peer_binder',)

VERIFIER_PAIRS = ('anka110_caller_verifier',)
STORAGE_VERIFIER_PAIRS = ('anka110_storage_verifier',)


SOCKET_CAPACITY_PAIRS = ('anka110_socket_capacity',)


OUTBOUND_SELECT_PAIRS = ('anka110_outbound_select',)
STORED_LAUNCH_PAIRS = ('anka110_stored_launch',)
ARTIFACT_STORAGE_PAIRS = ('anka110_artifact_storage',)
COMPILER_STORAGE_BINDING_PAIRS = ('anka110_compiler_storage_binding',)
ARTIFACT_TRANSFER_PAIRS = ('anka110_artifact_transfer',)
ARTIFACT_TRANSPORT_PAIRS = ('anka110_artifact_transport',)
GUEST_ARTIFACT_PAIRS = ('anka110_guest_artifact',)
STORED_RETRIEVAL_PAIRS = ('anka110_stored_retrieval',)
ARTIFACT_READ_PAIRS = ('anka110_artifact_read',)
GUEST_DOWNLOAD_PAIRS = ('anka110_guest_download',)
STORED_RESTART_PAIRS = ('anka110_stored_restart',)
SCALAR_READ_PAIRS = ('anka110_scalar_read',)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kleis', default='kleis')
    parser.add_argument('--kleis-root', default=os.environ.get('KLEIS_ROOT'),
                        help='directory containing stdlib/prelude.kleis; also sets KLEIS_ROOT')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--only-t1', action='store_true', help='run recognition, enrollment and grant admission')
    selection.add_argument('--only-t2', action='store_true', help='run persistence and reboot')
    selection.add_argument('--only-backend', action='store_true', help='run the Phase 10.10 durable backend refinement')
    selection.add_argument('--only-protocol', action='store_true', help='run the Phase 10.10 bounded persistence protocol')
    selection.add_argument('--only-evidence', action='store_true', help='run trusted evidence admission refinement')
    selection.add_argument('--only-provider', action='store_true', help='run bounded evidence registry and serialized provider use')
    selection.add_argument('--only-guarded-transport', action='store_true', help='run E5 transport ownership and guarded reply gate')
    selection.add_argument('--only-peer-binder', action='store_true', help='run E7 connection-bound caller admission')
    selection.add_argument('--only-caller-verifier', action='store_true', help='run E9 caller verifier evidence derivation')
    selection.add_argument('--only-storage-verifier', action='store_true', help='run E11 storage server verification before send and at EOF')
    selection.add_argument('--only-socket-capacity', action='store_true', help='run configurable typed socket capacity refinement')
    selection.add_argument('--only-outbound-select', action='store_true', help='active storage connection and write-half-close')
    selection.add_argument('--only-stored-launch', action='store_true', help='ordinary live and post-reboot durable-image launch')
    selection.add_argument('--only-artifact-storage', action='store_true', help='durable artifact staging, finalization and reference publication')
    selection.add_argument('--only-compiler-storage-binding', action='store_true', help='receipt-bound durable compiler artifact export')
    selection.add_argument('--only-artifact-transfer', action='store_true', help='bounded artifact upload framing and dispatch')
    selection.add_argument('--only-artifact-transport', action='store_true', help='serialized artifact TCP transport and guarded disclosure')
    selection.add_argument('--only-guest-artifact', action='store_true', help='CC2 guest artifact upload through typed socket and NIC')
    selection.add_argument('--only-stored-retrieval', action='store_true', help='bounded stored-envelope retrieval and fresh live-launch admission')
    selection.add_argument('--only-artifact-read', action='store_true', help='bounded artifact read wire framing and guarded disclosure')
    selection.add_argument('--only-guest-download', action='store_true', help='charged guest download, contiguous range assembly and private validation')
    selection.add_argument('--only-stored-restart', action='store_true', help='independent service/guest restart, durable boot admission and fresh stored launch')
    selection.add_argument('--only-scalar-read', action='store_true', help='scalar Read/Fetch payload equivalence, exact snapshots and guarded cleanup')
    parser.add_argument('--timeout', type=int, default=120, help='seconds per theory file')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    root = Path(__file__).resolve().parents[1]
    executable = str(Path(args.kleis).expanduser().resolve()) if '/' in args.kleis else args.kleis
    env = os.environ.copy()
    cwd = root
    if args.kleis_root:
        cwd = Path(args.kleis_root).expanduser().resolve()
        if not (cwd / 'stdlib/prelude.kleis').is_file():
            parser.error('--kleis-root/KLEIS_ROOT must contain stdlib/prelude.kleis')
        env['KLEIS_ROOT'] = str(cwd)
    all_ok = True
    pairs = (T1_PAIRS if args.only_t1 else T2_PAIRS if args.only_t2 else
             BACKEND_PAIRS if args.only_backend else PROTOCOL_PAIRS if args.only_protocol else
             EVIDENCE_PAIRS if args.only_evidence else PROVIDER_PAIRS if args.only_provider else GUARDED_PAIRS if args.only_guarded_transport else
             BINDER_PAIRS if args.only_peer_binder else VERIFIER_PAIRS if args.only_caller_verifier else
             STORAGE_VERIFIER_PAIRS if args.only_storage_verifier else
             SOCKET_CAPACITY_PAIRS if args.only_socket_capacity else
             OUTBOUND_SELECT_PAIRS if args.only_outbound_select else
             STORED_LAUNCH_PAIRS if args.only_stored_launch else
             ARTIFACT_STORAGE_PAIRS if args.only_artifact_storage else
             COMPILER_STORAGE_BINDING_PAIRS if args.only_compiler_storage_binding else
             ARTIFACT_TRANSFER_PAIRS if args.only_artifact_transfer else
             ARTIFACT_TRANSPORT_PAIRS if args.only_artifact_transport else
             GUEST_ARTIFACT_PAIRS if args.only_guest_artifact else
             STORED_RETRIEVAL_PAIRS if args.only_stored_retrieval else
             ARTIFACT_READ_PAIRS if args.only_artifact_read else
             GUEST_DOWNLOAD_PAIRS if args.only_guest_download else
             STORED_RESTART_PAIRS if args.only_stored_restart else
             SCALAR_READ_PAIRS if args.only_scalar_read else
             T1_PAIRS + T2_PAIRS + BACKEND_PAIRS + PROTOCOL_PAIRS + EVIDENCE_PAIRS + PROVIDER_PAIRS + GUARDED_PAIRS + BINDER_PAIRS + VERIFIER_PAIRS + STORAGE_VERIFIER_PAIRS + SOCKET_CAPACITY_PAIRS + OUTBOUND_SELECT_PAIRS + STORED_LAUNCH_PAIRS + ARTIFACT_STORAGE_PAIRS + COMPILER_STORAGE_BINDING_PAIRS + ARTIFACT_TRANSFER_PAIRS + ARTIFACT_TRANSPORT_PAIRS + GUEST_ARTIFACT_PAIRS + STORED_RETRIEVAL_PAIRS + ARTIFACT_READ_PAIRS + GUEST_DOWNLOAD_PAIRS + STORED_RESTART_PAIRS + SCALAR_READ_PAIRS)
    for stem in pairs:
        for hostile in (False, True):
            path = root / 'theories' / (stem + ('_false_witnesses' if hostile else '') + '.kleis')
            try:
                source = path.read_text()
                names = re.findall(r'^example\s+"([^"]+)"', source, re.MULTILINE)
                if not names or len(names) != len(set(names)):
                    raise ValueError('missing or duplicate witness names')
                result = subprocess.run([executable, 'test', str(path)], cwd=cwd, env=env,
                                        capture_output=True, text=True, timeout=args.timeout)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                print(f'FAIL: {path.name}: {error}', file=sys.stderr)
                all_ok = False
                continue
            output = result.stdout + result.stderr
            count = len(names)
            disproofs = output.count('Assertion disproved by Z3.')
            bad_diagnostic = re.search(r'Assertion (?:unknown|failed)|import error|parse error', output, re.I)
            if hostile:
                ok = (result.returncode == 1 and disproofs == count
                      and f'0/{count} examples passed ({count} failed)' in output
                      and not bad_diagnostic)
                detail = f'{disproofs}/{count} explicitly disproved'
            else:
                ok = (result.returncode == 0 and f'✅ {count} examples passed' in output
                      and not bad_diagnostic)
                detail = f'{count} positive witnesses'
            print(f'{"PASS" if ok else "FAIL"}: {path.name}: {detail}', flush=True)
            if not ok:
                print(output)
            all_ok = all_ok and ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())


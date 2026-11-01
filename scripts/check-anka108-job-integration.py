#!/usr/bin/env python3
"""Cheap overlay consistency check, NOT a Rust parser or acceptance proof.

Run before compilation to catch installing child modules without Kernel wiring.
Later intentional refactors must update these explicit integration anchors.
"""
import argparse
from pathlib import Path
import sys

CHECKS = {
    'userspace/system/services/net/httpd_protected.c': ('char buffer[1024]', 'read_bytes(', 'write_bytes('),
    'src/anka64/os/compiler_retry/publication/consumer/published/execution.rs': ('fn run_linked_compiler_publication_with_input(', 'const INPUT_CHARGE:',),
    'src/anka64/dev_runner.rs': ('fn run_accounted_c_application_with_input(', 'for _ in input_rounds..rounds'),
    'theories/anka108_http_application.kleis': ('define ha108_input(', 'define ha108_read('),
    'src/anka64/rebuild.rs': ('pub fn command(', 'RebuildService::new(', 'service.submit(', 'service.link('),
    'src/main.rs': ('anka::anka64::rebuild::command',),
    'src/anka64/mod.rs': ('pub mod rebuild;',),
    'src/anka64/os/compiler_retry/service.rs': ('fn submit(', 'fn poll(', 'fn run(', 'fn link('),
    'src/anka64/os/compiler_retry/service/tests.rs': ('fn c5_service_real_concurrent_rebuild()',),
    'src/anka64/os/application_run.rs': ('fn prepare_application_run(', 'fn application_run_step_ok(', 'fn application_run_syscall_allowed('),
    'src/anka64/os/application_run/tests.rs': ('fn c2_run_',),
    'src/anka64/dev_runner.rs': ('fn run_accounted_c_application(', 'kernel.prepare_application_run()', 'kernel.run(1,1);'),
    'src/anka64/os/compiler_retry/publication/consumer/published/execution.rs': ('fn machine_charge(', 'REPORT_CHARGE', "impl Drop for LinkedCompilerRunReport<'_>", 'run_accounted_c_application('),
    'theories/anka108_application_run.kleis': ('define ar108_output(',),
    'theories/anka108_application_run_false_witnesses.kleis': ('example ',),
    'src/anka64/ankald.rs': ('mod storage;', 'fn run_accounted_application_ankald(', 'prepare_preprocessor_transport()', 'run_preprocessor_slice(slice)'),
    'src/anka64/ankald/storage.rs': ('fn linker_storage_charge(',),
    'src/anka64/os/compiler_retry/publication/consumer.rs': ('transport_reservation: Option<HostStorageReservation>', 'ankald::run_accounted_application_ankald(', 'ankald::linker_storage_charge('),
    'theories/anka108_linker_storage.kleis': ('define ls108_spend(',),
    'theories/anka108_linker_storage_false_witnesses.kleis': ('example ',),
    'src/anka64/os/compiler_retry/admission.rs': ('fn configure_compiler_admission(', 'fn admit_compiler_process(', 'fn retire_admitted_compiler('),

    'src/anka64/os.rs': (
        'compiler_jobs: compiler_retry::jobs::CompilerJobs,',
        'compiler_admission: Option<compiler_retry::admission::CompilerAdmission>,',
        'compiler_jobs: Default::default(),',
        'compiler_admission: None,',
        'pub(crate) mod preprocessor_transport;',
        'pub(crate) mod application_run;',
        'application_run: None,',
        'self.application_run_step_ok(idx)',
        'self.application_run_syscall_allowed(idx)',
    ),
    'src/anka64/os/compiler_retry.rs': ('pub(crate) mod jobs;', 'pub(crate) mod preprocess;', 'pub(crate) mod admission;', 'pub(crate) mod service;'),
    'src/anka64/fabric.rs': ('fn with_preprocessor_storage(', 'fn prepare_preprocessor_trace('),
    'src/anka64/source_bundle.rs': ('pub(crate) mod storage;', 'run_ankapp_growing_accounted'),
    'src/anka64/os/preprocessor_transport.rs': ('fn run_preprocessor_slice(',),
    'src/anka64/os/compiler_retry/preprocess.rs': ('fn preprocess_compiler_source(',),
    'src/anka64/os/compiler_retry/inputs.rs': ('fn begin_compiler_job_from_input(',),
    'src/anka64/source_bundle/growth.rs': ('fn run_ankapp_growing_accounted(',),
    'src/anka64/source_bundle/storage.rs': ('pub(crate) fn charge(',),
    'theories/anka108_preprocessor_storage.kleis': ('define ps108_start(',),
    'theories/anka108_preprocessor_storage_false_witnesses.kleis': ('example ',),
    'src/anka64/os/heap_application.rs': (
        'self.discard_compiler_jobs_owned_by(owner);',
        'if !self.discard_all_compiler_jobs() { return; }',
    ),
    'src/anka64/os/compiler_retry/jobs.rs': (
        'pub(crate) struct CompilerJobs', 'pub(crate) fn begin_compiler_job(',
        'pub(crate) fn resume_compiler_job(', 'pub(crate) fn advance_compiler_job(',
    ),
    'src/anka64/os/compiler_retry/flow.rs': (
        'retain_retry_pin: bool,', 'fn retain_retry_provenance(',
        'if flow.retain_retry_pin {Ok(())}',
    ),
    'src/anka64/os/compiler_retry/publication.rs': (
        'fn recheck_compiler_job_pin(', 'fn discard_compiler_job_pin(',
    ),
    'scripts/check-anka108-gates.py': ("'--only-jobs'", "'anka108_compiler_jobs'"),
    'scripts/check-anka108-closure.sh': (
        '--only-jobs', 'c5_job_', 'c3_workspace_retry_',
        'c5_real_compiler_job_retry_publication',
    ),
    'theories/anka108_compiler_jobs.kleis': ('define cj108_resume(',),
    'theories/anka108_compiler_jobs_false_witnesses.kleis': ('example ',),
    'src/anka64/os/compiler_retry/jobs/tests.rs': ('fn c5_job_',),
    'src/anka64/os/compiler_retry/producer_publication_tests.rs': (
        'fn c5_real_compiler_job_retry_publication()',
    ),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    failures = []
    for name, anchors in CHECKS.items():
        try:
            source = (args.root / name).read_text()
        except OSError as error:
            failures.append(f'{name}: {error}')
            continue
        for anchor in anchors:
            if anchor not in source:
                failures.append(f'{name}: missing {anchor!r}')
    if failures:
        print('FAIL: incomplete compiler-job integration:', file=sys.stderr)
        for failure in failures:
            print(f'  {failure}', file=sys.stderr)
        print('Apply the complete ZIP overlay at the repository root, including os.rs and scripts.', file=sys.stderr)
        return 1
    print('PASS: compiler-job integration anchors present; Rust compilation and acceptance still required.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
real=0
case "${1:-}" in
  "") ;;
  --real) real=1 ;;
  *) echo 'Usage: scripts/check-anka108-application-run.sh [--real]' >&2; exit 2 ;;
esac
python3 scripts/check-anka108-job-integration.py
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-application-run
cargo test --release --lib c2_run_ -- --nocapture --test-threads=1
cargo test --release --lib anka64::os::compiler_retry:: -- --test-threads=1
if (( real )); then
  ANKA_PRODUCER_TIMEOUT_SECS="${ANKA_PRODUCER_TIMEOUT_SECS:-900}" \
    cargo test --release --lib c5_real_compiler_job_retry_publication \
    -- --ignored --nocapture --test-threads=1
fi
echo 'Application-run accounting checks passed; ordinary service/concurrent/network closure remains separate.'

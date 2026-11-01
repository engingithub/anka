#!/usr/bin/env bash
# Focused local acceptance for the charged guest-linker transport.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
real=0
case "${1:-}" in
  "") ;;
  --real) real=1 ;;
  *) echo 'Usage: scripts/check-anka108-linker-storage.sh [--real]' >&2; exit 2 ;;
esac
python3 scripts/check-anka108-job-integration.py
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-linker-storage
cargo test --release --lib c2_linker_storage_geometry_ -- --nocapture --test-threads=1
cargo test --release --lib anka64::os::compiler_retry:: -- --test-threads=1
if (( real )); then
  ANKA_PRODUCER_TIMEOUT_SECS="${ANKA_PRODUCER_TIMEOUT_SECS:-900}" \
    cargo test --release --lib c5_real_compiler_job_retry_publication \
    -- --ignored --nocapture --test-threads=1
fi
echo 'Charged linker checks passed. Application-run accounting and service rebuild closure remain separate gates.'

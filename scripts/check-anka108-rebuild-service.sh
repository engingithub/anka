#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
real=0
case "${1:-}" in
  "") ;;
  --real) real=1 ;;
  *) echo 'Usage: scripts/check-anka108-rebuild-service.sh [--real]' >&2; exit 2 ;;
esac
python3 scripts/check-anka108-job-integration.py
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-rebuild-service
cargo test --release --lib c5_service_ -- --nocapture --test-threads=1
cargo test --release --lib anka64::os::compiler_retry:: -- --test-threads=1
cargo check --release --bin anka
if (( real )); then
  cargo test --release --lib c5_service_real_concurrent_rebuild -- --ignored --nocapture --test-threads=1
fi
echo 'Ordinary service checks passed; protected network-service rebuild remains a separate closure gate.'

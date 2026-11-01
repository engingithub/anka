#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
real=0
case "${1:-}" in
  "") ;;
  --real) real=1 ;;
  *) echo 'Usage: scripts/check-anka108-http-application.sh [--real]' >&2; exit 2 ;;
esac
python3 scripts/check-anka108-job-integration.py
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-a23
cargo test --release --lib anka64::fabric::heap:: -- --test-threads=1
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-compiler-admission
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-http-application
cargo test --release --lib c5_http_ -- --nocapture --test-threads=1
cargo test --release --lib anka64::os::compiler_retry:: -- --test-threads=1
cargo test --release --lib anka64::rebuild:: -- --test-threads=1
cargo check --release --bin anka
if (( real )); then
  cargo test --release --lib c5_http_real_protected_application -- --ignored --nocapture --test-threads=1
fi
echo 'Protected HTTP application checks passed; socket/NIC integration and final regressions remain required.'

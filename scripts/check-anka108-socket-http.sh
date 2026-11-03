#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-}" in ""|--real) ;; *) echo "usage: $0 [--real]" >&2; exit 2;; esac
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-socket-lowering
# The socket runner shares dispatch and retirement with the original S1 path.
bash scripts/check-anka108-typed-socket.sh
log=$(mktemp)
trap 'rm -f "$log"' EXIT
check_test() {
  local name="$1"; shift
  cargo test --release --lib "$name" -- "$@" --nocapture --test-threads=1 | tee "$log"
  grep -Eq 'test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log" || {
    echo "Expected one executed test for $name" >&2; exit 1;
  }
}
check_test s2_socket_plan_bounds_both_fragments_and_transmit_window
check_test s2_socket_startup_charges_and_releases_exact_child_without_guest_io
if [[ "${1:-}" == --real ]]; then check_test s2_real_socket_http --ignored; fi

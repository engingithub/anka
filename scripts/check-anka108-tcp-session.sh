#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-}" in ''|--real) ;; *) echo "usage: $0 [--real]" >&2; exit 2;; esac
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-tcp-session
log=$(mktemp)
trap 'rm -f "$log"' EXIT
one() {
  local name="$1"; shift
  cargo test --release --lib "$name" -- "$@" --nocapture --test-threads=1 | tee "$log"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log" || {
    echo "Expected one executed test for $name" >&2; exit 1; }
}
one s4_tcp_replay_rejects_ambiguous_or_overbudget_input
one s4_tcp_candidate_exact_lengths_role_and_credit
one s4_tcp_persistent_driver_keeps_binding_and_does_not_replay_tx
if [[ "${1:-}" == --real ]]; then one s4_real_nic_tcp_http_alive --ignored; fi

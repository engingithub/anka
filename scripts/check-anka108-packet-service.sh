#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-}" in ''|--real) ;; *) echo "usage: $0 [--real]" >&2; exit 2;; esac
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
    --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-packet-service
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
    --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-udp-service
log=$(mktemp)
trap 'rm -f "$log"' EXIT
test_one() {
  local name="$1"; shift
  cargo test --release --lib "$name" -- "$@" --nocapture --test-threads=1 | tee "$log"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log" || {
    echo "Expected one executed test for $name" >&2; exit 1; }
}
test_one s3_frame_cli_requires_explicit_exclusive_run_mode
test_one s3_frame_driver_commits_rx_and_different_exact_tx_prefix
test_one s3_frame_denies_invalid_offer_and_revoked_device
test_one s5_udp_legacy_matches_shared_wire_oracle
if [[ "${1:-}" == --real ]]; then test_one s3_frame_real_ethernet_arp_icmp_and_udp --ignored; fi

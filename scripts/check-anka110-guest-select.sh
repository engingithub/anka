#!/usr/bin/env bash
# Cheap transport/file checks first; explicit opt-in for the CC2 acceptance.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-}" in ''|--real) ;; *) echo 'Usage: bash scripts/check-anka110-guest-select.sh [--real]' >&2; exit 2;; esac
log=$(mktemp)
trap 'rm -f "$log"' EXIT
prefix=anka64::os::compiler_retry::service::frame_port::tcp::outbound
cargo test --release --locked --lib g110_ -- --test-threads=1 | tee "$log"
for name in half_close_and_receive revoke_before_fin revoke_after_commit reply_tail_is_terminal application_binding_refuses_unprepared_realm; do
  grep -Fxq "test ${prefix}::tests::g110_outbound_${name} ... ok" "$log" || { echo "Missing passing witness: $name" >&2; exit 1; }
done
grep -Fxq "test ${prefix}::guest_tests::g110_guest_file_peer_fin_and_reopen_retry ... ok" "$log" || { echo 'Missing file peer witness' >&2; exit 1; }
grep -Fxq 'test anka64::os::tests::typed_socket_tests::g110_application_select_accepts_fresh_zero_generation_and_rejects_stale_key ... ok' "$log" || { echo 'Missing fresh-generation binding witness' >&2; exit 1; }
if [[ "${1:-}" == --real ]]; then
  test_name=${prefix}::guest_tests::g110_real_cc2_file_select
  cargo test --release --locked --lib "$test_name" -- --exact --ignored --nocapture --test-threads=1 | tee "$log"
  grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log" || { echo 'Real guest Select did not pass' >&2; exit 1; }
else
  echo 'Quick witnesses passed. CC2 acceptance pending: rerun with --real.'
fi

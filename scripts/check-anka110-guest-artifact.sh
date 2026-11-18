#!/usr/bin/env bash
# GA110 bounded checks first; opt in to one real CC2 bootstrap/upload witness.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-}" in ''|--real) ;; *) echo 'Usage: bash scripts/check-anka110-guest-artifact.sh [--real]' >&2; exit 2;; esac
anka_guest_log=$(mktemp)
trap 'rm -f "$anka_guest_log"' EXIT
cargo test --release --locked --lib ga110_ -- --test-threads=1 | tee "$anka_guest_log"
for name in select_only_authority_cannot_send_artifact exact_request_capacity_prefix_and_final_echo revocation_at_reply_and_fragmented_delivery; do
  grep -Fxq "test anka64::os::typed_socket::select::artifact_tests::ga110_${name} ... ok" "$anka_guest_log" || { echo "Missing passing witness: $name" >&2; exit 1; }
done
anka_guest_prefix=anka64::os::compiler_retry::service::frame_port::tcp::outbound::artifact_guest_tests
for name in guest_source_uses_supported_subset nic_peer_tcp_file_publish_loss_and_reopen_outcome; do
  grep -Fxq "test ${anka_guest_prefix}::ga110_${name} ... ok" "$anka_guest_log" || { echo "Missing passing witness: $name" >&2; exit 1; }
done
for name in reclaims_only_drained_trace_across_many_fragments trace_collection_refuses_pending_frames_transactions_and_faults; do
  grep -Fxq "test anka64::os::compiler_retry::service::frame_port::tcp::tests::ga110_driver_${name} ... ok" "$anka_guest_log" || { echo "Missing passing driver witness: $name" >&2; exit 1; }
done
# Guard the earlier Select behavior while the same runtime handles both modes.
bash scripts/check-anka110-guest-select.sh
if [[ "${1:-}" == --real ]]; then
  cargo test --release --locked --lib "${anka_guest_prefix}::ga110_real_cc2_artifact_upload" -- --exact --ignored --nocapture --test-threads=1 | tee "$anka_guest_log"
  grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$anka_guest_log" || { echo 'Real guest artifact upload did not pass' >&2; exit 1; }
else
  echo 'Quick witnesses passed. Real CC2 upload acceptance pending: rerun with --real.'
fi

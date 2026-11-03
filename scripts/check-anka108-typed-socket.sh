#!/usr/bin/env bash
# S1: discover and execute the actual protected socket tests, locally, in release.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
fixture=src/anka64/os/typed_socket/tests.rs
if [[ ! -s "$fixture" || ! -s src/anka64/os/typed_socket.rs ]] ||
   ! grep -Fq 'include!("os/typed_socket/tests.rs")' src/anka64/os.rs; then
  echo 'Missing S1 source or test registration. Extract the complete socket ZIP at the Anka repository root.' >&2
  exit 1
fi
expected=(binary_split_fin_and_reply_on_open_tx full_receive_refuses_entire_fragment_including_fin
          short_send_and_backpressure_preserve_queued_prefix cancel_or_death_refunds_and_never_retargets_a_saved_call
          wrong_kernel_ticket_and_unfunded_bind_cannot_route_bytes)
check_list() {
  local name
  for name in "${expected[@]}"; do
    grep -Fxq "anka64::os::tests::typed_socket_tests::s1_socket_${name}: test" <<< "$listed" || return 1
  done
}
listed=$(cargo test --release --lib s1_socket_ -- --list)
if ! check_list; then
  echo 'S1 sources exist but the release test binary lacks expected tests. Refreshing os.rs timestamp and retrying discovery once.' >&2
  touch src/anka64/os.rs
  listed=$(cargo test --release --lib s1_socket_ -- --list)
  if ! check_list; then
    printf 'S1 discovery failed after rebuild. Cargo listed:\n%s\n' "$listed" >&2
    exit 1
  fi
fi
log=$(mktemp)
trap 'rm -f "$log"' EXIT
cargo test --release --lib s1_socket_ -- --test-threads=1 | tee "$log"
for name in "${expected[@]}"; do
  grep -Fxq "test anka64::os::tests::typed_socket_tests::s1_socket_${name} ... ok" "$log" ||
    { echo "Missing passing result for s1_socket_${name}." >&2; exit 1; }
done

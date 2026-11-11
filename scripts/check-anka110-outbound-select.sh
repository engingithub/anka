#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT
cargo test --release --locked --lib g110_outbound_ -- --test-threads=1 | tee "$log"
prefix='anka64::os::compiler_retry::service::frame_port::tcp::outbound::tests::g110_outbound_'
for case_name in half_close_and_receive revoke_before_fin revoke_after_commit reply_tail_is_terminal; do
    grep -Fxq "test ${prefix}${case_name} ... ok" "$log" || {
        echo "Missing passing Rust witness: ${case_name}" >&2
        exit 1
    }
done
bash scripts/check-anka108-typed-socket.sh

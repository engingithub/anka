#!/usr/bin/env bash
# RR110 user-run acceptance. Extracting the ZIP does not run this script.
set -euo pipefail
case "$(uname -s)" in Linux|Darwin) ;; *) echo "Requires Linux or macOS" >&2; exit 1;; esac
case "${1:-}" in ""|--real) ;; *) echo "Usage: $0 [--real]" >&2; exit 2;; esac
if [ "$#" -gt 1 ]; then echo "Usage: $0 [--real]" >&2; exit 2; fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
anka_restart_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-restart.XXXXXX")"
trap 'rm -rf -- "$anka_restart_tmp"' EXIT
cargo test --release --lib rr110_ -- --list > "$anka_restart_tmp/list"
count="$(grep -c '^anka64::.*::rr110_.*: test$' "$anka_restart_tmp/list" || true)"
real="$(grep -c '::rr110_real_cc2_independent_restart_and_stored_launch: test$' "$anka_restart_tmp/list" || true)"
if [ "$count" -ne 15 ] || [ "$real" -ne 1 ]; then
  echo "ERROR: expected 14 focused RR110 tests + 1 ignored real restart witness; found $count/$real" >&2
  cat "$anka_restart_tmp/list" >&2; exit 1
fi
cargo test --release --lib rr110_ -- --nocapture --test-threads=1
cargo test --release --lib t2_ -- --nocapture --test-threads=1
# RR110 shares the ordinary runner, GD110 download loop, SR110 commit gate and
# custody. Keep their existing focused regression gates in the laptop run.
bash scripts/check-anka110-stored-live-launch.sh
if [ "${1:-}" = --real ]; then
  cargo test --release --lib rr110_real_cc2_independent_restart_and_stored_launch -- --ignored --nocapture --test-threads=1
fi

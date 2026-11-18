#!/usr/bin/env bash
# SR110 R2: no test is run merely by unpacking this delivery.
set -euo pipefail
case "$(uname -s)" in Linux|Darwin) ;; *) echo "Requires Linux or macOS" >&2; exit 1;; esac
case "${1:-}" in ""|--real) ;; *) echo "Usage: $0 [--real]" >&2; exit 2;; esac
if [ "$#" -gt 1 ]; then echo "Usage: $0 [--real]" >&2; exit 2; fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
anka_launch_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-live.XXXXXX")"
trap 'rm -rf -- "$anka_launch_tmp"' EXIT
cargo test --release --lib sr110_live_ -- --list > "$anka_launch_tmp/list"
count="$(grep -c '^anka64::.*::sr110_live_.*: test$' "$anka_launch_tmp/list" || true)"
real="$(grep -c '::sr110_live_real_cc2_download_and_launch: test$' "$anka_launch_tmp/list" || true)"
if [ "$count" -ne 12 ] || [ "$real" -ne 1 ]; then
  echo "ERROR: expected 12 live-launch tests (4 authority + 7 Kernel + 1 ignored real path); found $count/$real" >&2
  cat "$anka_launch_tmp/list" >&2; exit 1
fi
cargo test --release --lib sr110_live_ -- --nocapture --test-threads=1
# The new gate shares the ordinary runner; retain its current focused witnesses.
cargo test --release --lib c4_execution_ -- --nocapture --test-threads=1
bash scripts/check-anka110-guest-download.sh
if [ "${1:-}" = --real ]; then
  cargo test --release --lib sr110_live_real_cc2_download_and_launch -- --ignored --nocapture --test-threads=1
fi

#!/usr/bin/env bash
# SC110 developer-laptop validation; never run automatically while installing.
set -euo pipefail
case "${1:-}" in ""|--real) ;; *) echo "Usage: $0 [--real]" >&2; exit 2;; esac
if [ "$#" -gt 1 ]; then echo "Usage: $0 [--real]" >&2; exit 2; fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
scalar_check_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-scalar.XXXXXX")"
trap 'rm -rf -- "$scalar_check_tmp"' EXIT
cargo test --release --lib -- --list > "$scalar_check_tmp/list"
count="$(grep -c '^anka64::.*::sc110_.*: test$' "$scalar_check_tmp/list" || true)"
if [ "$count" -ne 15 ]; then
  echo "ERROR: expected 15 focused SC110 tests; found $count" >&2
  cat "$scalar_check_tmp/list" >&2; exit 1
fi
# Discover every real witness before any run; refuse missing/ambiguous selection.
if [ "${1:-}" = --real ]; then
  python3 - "$scalar_check_tmp/list" > "$scalar_check_tmp/real" <<'PY'
from pathlib import Path
import sys
names = [line[:-6] for line in Path(sys.argv[1]).read_text().splitlines()
         if line.startswith('anka64::') and line.endswith(': test')]
for suffix in ('gd110_real_cc2_guest_download',
               'sr110_live_real_cc2_download_and_launch',
               'rr110_real_cc2_independent_restart_and_stored_launch'):
    found = [name for name in names if name.endswith('::' + suffix)]
    if len(found) != 1:
        raise SystemExit(f'Expected one exact real witness for {suffix}; found {len(found)}')
    print(found[0])
PY
fi
cargo test --release --lib sc110_ -- --nocapture --test-threads=1
# Includes Fabric, core/pointers, NIC and every ordinary existing regression.
cargo test --release --lib -- --test-threads=1
if [ "${1:-}" = --real ]; then
  while IFS= read -r name; do
    cargo test --release --lib "$name" -- --exact --ignored --nocapture --test-threads=1
  done < "$scalar_check_tmp/real"
fi

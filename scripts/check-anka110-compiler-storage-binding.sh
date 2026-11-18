#!/usr/bin/env bash
# CS110 focused receipt-bound export. No CC2 bootstrap or long regression suite.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
bash scripts/check-anka110-artifact-storage.sh
anka_binding_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-binding.XXXXXX")"
trap 'rm -rf -- "$anka_binding_tmp"' EXIT
cargo test --release --lib cs110_ -- --list > "$anka_binding_tmp/list"
count="$(grep -c '^anka64::.*::cs110_.*: test$' "$anka_binding_tmp/list" || true)"
if [ "$count" -lt 9 ]; then
  echo "ERROR: expected at least 9 CS110 tests, found $count; refusing incomplete acceptance" >&2
  exit 1
fi
cargo test --release --lib cs110_ -- --nocapture --test-threads=1

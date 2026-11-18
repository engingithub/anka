#!/usr/bin/env bash
# AT110 codec + real-file dispatcher tests; no CC2 bootstrap.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
anka_transfer_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-transfer.XXXXXX")"
trap 'rm -rf -- "$anka_transfer_tmp"' EXIT
rustc --edition=2024 --test "$root/src/anka64/authority_persistence.rs" -o "$anka_transfer_tmp/tests"
"$anka_transfer_tmp/tests" --list > "$anka_transfer_tmp/list"
count="$(grep -c '^artifact::transfer::tests::at110_.*: test$' "$anka_transfer_tmp/list" || true)"
if [ "$count" -lt 12 ]; then
  echo "ERROR: expected at least 12 artifact-transfer tests, found $count" >&2; exit 1
fi
"$anka_transfer_tmp/tests" artifact::transfer::tests::at110_ --nocapture --test-threads=1

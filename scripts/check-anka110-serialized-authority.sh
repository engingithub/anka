#!/usr/bin/env bash
# SA110 laptop acceptance. This script compiles/runs Rust ONLY when invoked.
set -euo pipefail
if [ "$#" -ne 0 ]; then
  echo "Usage: $0" >&2
  exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
anka_sa110_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-sa.XXXXXX")"
trap 'rm -rf -- "$anka_sa110_tmp"' EXIT
cargo test --release --locked --lib sa110_ -- --list > "$anka_sa110_tmp/list"
total="$(grep -Ec '::sa110_[[:alnum:]_]+: test$' "$anka_sa110_tmp/list" || true)"
owned="$(grep -Ec '^anka64::authority_persistence::evidence::serialized_authority::tests::(candidate_checks::)?sa110_[[:alnum:]_]+: test$' "$anka_sa110_tmp/list" || true)"
if [ "$total" -ne 33 ] || [ "$owned" -ne 33 ]; then
  echo "ERROR: expected exactly 33 SA110 coordinator/candidate tests; found $total/$owned" >&2
  cat "$anka_sa110_tmp/list" >&2
  exit 1
fi
cargo test --release --locked --lib sa110_ -- --nocapture --test-threads=1

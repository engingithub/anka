#!/usr/bin/env bash
# LG110 laptop acceptance. Compiles/runs Rust only when explicitly invoked.
set -euo pipefail
if [ "$#" -ne 0 ]; then
  echo "Usage: $0" >&2
  exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
anka_lg110_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-lg.XXXXXX")"
trap 'rm -rf -- "$anka_lg110_tmp"' EXIT
cargo test --release --locked --lib lg110_ -- --list > "$anka_lg110_tmp/list"
total="$(grep -Ec '::lg110_[[:alnum:]_]+: test$' "$anka_lg110_tmp/list" || true)"
owned="$(grep -Ec '^anka64::authority_persistence::evidence::local_grants::tests::(bindings::|ordering::)?lg110_[[:alnum:]_]+: test$' "$anka_lg110_tmp/list" || true)"
unique="$( { grep -E '::lg110_[[:alnum:]_]+: test$' "$anka_lg110_tmp/list" || true; } | sort -u | wc -l | tr -d '[:space:]')"
if [ "$total" -ne 38 ] || [ "$owned" -ne 38 ] || [ "$unique" -ne 38 ]; then
  echo "ERROR: expected exactly 38 unique LG110 owner/evidence tests; found $total/$owned/$unique" >&2
  cat "$anka_lg110_tmp/list" >&2
  exit 1
fi
cargo test --release --locked --lib lg110_ -- --nocapture --test-threads=1
# Candidate validation is shared; its existing SA110 behavior must be preserved.
bash scripts/check-anka110-serialized-authority.sh

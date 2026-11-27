#!/usr/bin/env bash
# LA110 host verifier checks; Rust is run only without --python-only.
set -euo pipefail
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--python-only" ]; }; then
  echo "Usage: $0 [--python-only]" >&2
  exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 scripts/keycloak/test_adapter.py
bash scripts/check-anka110-keycloak-preflight.sh
if [ "${1:-}" = "--python-only" ]; then exit 0; fi
anka_la110_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-la.XXXXXX")"
trap 'rm -rf -- "$anka_la110_tmp"' EXIT
cargo test --release --locked --lib la110_ -- --list > "$anka_la110_tmp/list"
total="$(grep -Ec '::la110_[[:alnum:]_]+: test$' "$anka_la110_tmp/list" || true)"
owned="$(grep -Ec '^anka64::authority_persistence::evidence::local_grants::adapter::(tests|process::tests)::la110_[[:alnum:]_]+: test$' "$anka_la110_tmp/list" || true)"
unique="$( { grep -E '::la110_[[:alnum:]_]+: test$' "$anka_la110_tmp/list" || true; } | sort -u | wc -l | tr -d '[:space:]')"
if [ "$total" -ne 19 ] || [ "$owned" -ne 19 ] || [ "$unique" -ne 19 ]; then
  echo "ERROR: expected exactly 19 unique LA110 adapter tests; found $total/$owned/$unique" >&2
  cat "$anka_la110_tmp/list" >&2
  exit 1
fi
cargo test --release --locked --lib la110_ -- --nocapture --test-threads=1
bash scripts/check-anka110-local-grants.sh

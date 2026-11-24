#!/usr/bin/env bash
# AC110 laptop acceptance; invokes Rust only when the developer runs this script.
set -euo pipefail
case "$(uname -s)" in Linux|Darwin) ;; *) echo "Requires Linux or macOS" >&2; exit 2;; esac
if [ "$#" -ne 0 ] && { [ "$#" -ne 2 ] || [ "$1" != "--real" ]; }; then
  echo "Usage: $0 [--real PRIVATE_LAB_DIRECTORY]" >&2; exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 scripts/keycloak/test_control.py
anka_ac110_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-ac.XXXXXX")"
trap 'rm -rf -- "$anka_ac110_tmp"' EXIT
cargo test --release --locked --lib ac110_ -- --list > "$anka_ac110_tmp/list"
count="$(grep -Ec '^anka64::keycloak_control::(process::)?tests::ac110_[[:alnum:]_]+: test$' "$anka_ac110_tmp/list" || true)"
total="$(grep -Ec '::ac110_[[:alnum:]_]+: test$' "$anka_ac110_tmp/list" || true)"
if [ "$count" -ne 15 ] || [ "$total" -ne 15 ]; then
  echo "ERROR: expected exactly 15 AC110 Rust tests; found $count/$total" >&2
  cat "$anka_ac110_tmp/list" >&2; exit 1
fi
cargo test --release --locked --lib ac110_ -- --nocapture --test-threads=1
bash scripts/check-anka110-serialized-authority.sh
if [ "$#" -eq 2 ]; then
  cargo build --locked --bin anka
  target/debug/anka keycloak-control-lab --state "$2"
fi

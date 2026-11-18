#!/usr/bin/env bash
# AR110 read codec/client + actual localhost TCP/files; AT110/AG110 compatibility.
set -euo pipefail
case "$(uname -s)" in Linux|Darwin) ;; *) echo "Requires Linux or macOS" >&2; exit 1;; esac
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
anka_read_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-read.XXXXXX")"
trap 'rm -rf -- "$anka_read_tmp"' EXIT
rustc --edition=2024 --test "$root/src/anka64/authority_persistence.rs" -o "$anka_read_tmp/tests"
"$anka_read_tmp/tests" --list > "$anka_read_tmp/list"
codec="$(grep -c '^artifact::transfer::read::tests::ar110_.*: test$' "$anka_read_tmp/list" || true)"
client="$(grep -c '^artifact::transfer::read::client::tests::ar110_.*: test$' "$anka_read_tmp/list" || true)"
transport="$(grep -c '^artifact::transfer::transport::read_tests::ar110_.*: test$' "$anka_read_tmp/list" || true)"
if [ "$codec" -ne 9 ] || [ "$client" -ne 6 ] || [ "$transport" -ne 8 ]; then
  echo "ERROR: expected 9 codec/dispatch + 6 client + 8 TCP tests; found $codec + $client + $transport" >&2
  cat "$anka_read_tmp/list" >&2; exit 1
fi
for prefix in at110_ ag110_; do
  count="$(grep -c "::${prefix}.*: test$" "$anka_read_tmp/list" || true)"
  if [ "$count" -lt 12 ]; then echo "Expected at least 12 compatibility tests for $prefix; found $count" >&2; exit 1; fi
done
"$anka_read_tmp/tests" ar110_ --nocapture --test-threads=1
"$anka_read_tmp/tests" at110_ --nocapture --test-threads=1
"$anka_read_tmp/tests" ag110_ --nocapture --test-threads=1

#!/usr/bin/env bash
# AG110 real localhost TCP + actual artifact-file backend. No CC2 bootstrap.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
anka_transport_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-transport.XXXXXX")"
trap 'rm -rf -- "$anka_transport_tmp"' EXIT
rustc --edition=2024 --test "$root/src/anka64/authority_persistence.rs" -o "$anka_transport_tmp/tests"
"$anka_transport_tmp/tests" --list > "$anka_transport_tmp/list"
count="$(grep -c '^artifact::transfer::transport::tests::ag110_.*: test$' "$anka_transport_tmp/list" || true)"
if [ "$count" -lt 12 ]; then echo "ERROR: expected at least 12 AG110 tests, found $count" >&2; exit 1; fi
"$anka_transport_tmp/tests" artifact::transfer::transport::tests::ag110_ --nocapture --test-threads=1

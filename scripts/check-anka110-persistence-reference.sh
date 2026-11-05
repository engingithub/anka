#!/usr/bin/env bash
# Compile core/backend, codec, loopback and bounded client tests (83); no CC2/bootstrap/full suite.
set -euo pipefail
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) echo "Local durable backend requires Linux or macOS" >&2; exit 1 ;;
esac
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
anka_reference_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-reference.XXXXXX")"
trap 'rm -rf -- "$anka_reference_tmp"' EXIT
rustc --edition=2024 --test "$root/src/anka64/authority_persistence.rs" \
  -o "$anka_reference_tmp/persistence-tests"
"$anka_reference_tmp/persistence-tests" --nocapture

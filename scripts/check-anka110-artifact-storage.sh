#!/usr/bin/env bash
# AS110 focused host-file artifact tests. No CC2 bootstrap or guest network run.
set -euo pipefail
case "$(uname -s)" in Linux|Darwin) ;; *) echo "Requires Linux or macOS" >&2; exit 1;; esac
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
anka_artifact_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-artifact.XXXXXX")"
trap 'rm -rf -- "$anka_artifact_tmp"' EXIT
rustc --edition=2024 --test "$root/src/anka64/authority_persistence.rs" \
  -o "$anka_artifact_tmp/artifact-tests"
"$anka_artifact_tmp/artifact-tests" --list > "$anka_artifact_tmp/list"
if ! grep -q '^artifact::tests::as110_' "$anka_artifact_tmp/list"; then
  echo "ERROR: artifact test module is missing; refusing a zero-test pass" >&2
  exit 1
fi
"$anka_artifact_tmp/artifact-tests" artifact::tests::as110_ --nocapture --test-threads=1

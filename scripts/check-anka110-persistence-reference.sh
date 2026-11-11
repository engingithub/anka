#!/usr/bin/env bash
# Compile persistence, transport/client and evidence/guarded loopback tests (135); no CC2/bootstrap/full suite.
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
# Some tests spawn processes while others require an immediate last-descriptor
# close. Isolate their schedules; the fencing tests still start a competing
# process while the owning process holds its live lock.
"$anka_reference_tmp/persistence-tests" --nocapture --test-threads=1

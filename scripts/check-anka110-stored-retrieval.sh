#!/usr/bin/env bash
# SR110 private retrieval only. No CC2 bootstrap or full regression suite.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
anka_retrieval_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-retrieval.XXXXXX")"
trap 'rm -rf -- "$anka_retrieval_tmp"' EXIT
cargo test --release --lib sr110_ -- --skip sr110_live_ --list > "$anka_retrieval_tmp/list"
backend_count="$(grep -c '^anka64::authority_persistence::artifact::retrieval::tests::sr110_.*: test$' "$anka_retrieval_tmp/list" || true)"
kernel_count="$(grep -c '^anka64::os::compiler_retry::publication::consumer::published::storage::tests::retrieval::sr110_.*: test$' "$anka_retrieval_tmp/list" || true)"
count="$(grep -c '^anka64::.*::sr110_.*: test$' "$anka_retrieval_tmp/list" || true)"
if [ "$backend_count" -ne 13 ] || [ "$kernel_count" -ne 7 ] || [ "$count" -ne 20 ]; then
  echo "ERROR: expected 13 backend + 7 Kernel SR110 tests (20 total); found $backend_count + $kernel_count ($count total)" >&2
  cat "$anka_retrieval_tmp/list" >&2
  exit 1
fi
cargo test --release --lib sr110_ -- --skip sr110_live_ --nocapture --test-threads=1

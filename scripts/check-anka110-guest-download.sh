#!/usr/bin/env bash
# GD110: focused state/Kernel/TCP cases; optional actual CC2/NIC/file witness.
set -euo pipefail
case "$(uname -s)" in Linux|Darwin) ;; *) echo "Requires Linux or macOS" >&2; exit 1;; esac
case "${1:-}" in ""|--real) ;; *) echo "Usage: $0 [--real]" >&2; exit 2;; esac
if [ "$#" -gt 1 ]; then echo "Usage: $0 [--real]" >&2; exit 2; fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
anka_download_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-download.XXXXXX")"
trap 'rm -rf -- "$anka_download_tmp"' EXIT
cargo test --release --lib gd110_ -- --list > "$anka_download_tmp/list"
count="$(grep -c '^anka64::.*::gd110_.*: test$' "$anka_download_tmp/list" || true)"
real="$(grep -c '::gd110_real_cc2_guest_download: test$' "$anka_download_tmp/list" || true)"
state="$(grep -c '^anka64::os::typed_socket::select::download::tests::gd110_.*: test$' "$anka_download_tmp/list" || true)"
kernel="$(grep -c '::storage::tests::download::gd110_.*: test$' "$anka_download_tmp/list" || true)"
if [ "$count" -ne 19 ] || [ "$real" -ne 1 ] || [ "$state" -ne 13 ] || [ "$kernel" -ne 3 ]; then
  echo "ERROR: expected 19 GD110 tests (13 exchange + 3 Kernel + 2 peer/source + 1 ignored real witness); found $count/$state/$kernel/$real" >&2
  cat "$anka_download_tmp/list" >&2; exit 1
fi
cargo test --release --lib gd110_ -- --nocapture --test-threads=1
# Plain sockets must not inherit storage-mode buffer charges.
cargo test --release --lib anka64::os::tests::typed_socket_tests:: -- --nocapture --test-threads=1
bash scripts/check-anka110-artifact-read.sh
cargo test --release --lib ga110_ -- --nocapture --test-threads=1
bash scripts/check-anka110-stored-retrieval.sh
if [ "${1:-}" = --real ]; then
  cargo test --release --lib gd110_real_cc2_guest_download -- --ignored --nocapture --test-threads=1
fi

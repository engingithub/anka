#!/usr/bin/env bash
# LT110 hosted bridge gate. --python-only never runs Cargo.
set -euo pipefail
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--python-only" ] && [ "$1" != "--real" ]; }; then
  echo "Usage: $0 [--python-only|--real]" >&2; exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 scripts/keycloak/test_holder.py
bash scripts/check-anka110-local-adapter.sh --python-only
if [ "${1:-}" = "--python-only" ]; then exit 0; fi
lt110_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-lt.XXXXXX")"
trap 'rm -rf -- "$lt110_tmp"' EXIT
cargo test --release --locked --lib lt110_ -- --list > "$lt110_tmp/list"
python3 - "$lt110_tmp/list" <<'PY'
import re, sys
from pathlib import Path
names = re.findall(r'^(\S*::lt110_\w+): test$', Path(sys.argv[1]).read_text(), re.M)
focused = [n for n in names if n.startswith('anka64::authority_persistence::evidence::local_grants::adapter::read_bridge::tests::')]
real = [n for n in names if n.endswith('::download_tests::local_bridge_tests::lt110_real_cc2_guarded_file_bridge')]
if len(names) != 12 or len(set(names)) != 12 or len(focused) != 11 or len(real) != 1:
    sys.exit('ERROR: expected exactly 11 focused LT110 tests and one ignored real-path witness')
PY
cargo test --release --locked --lib lt110_ -- --nocapture --test-threads=1
bash scripts/check-anka110-local-adapter.sh
if [ "${1:-}" = "--real" ]; then
  witness='anka64::os::compiler_retry::service::frame_port::tcp::outbound::artifact_guest_tests::download_tests::local_bridge_tests::lt110_real_cc2_guarded_file_bridge'
  cargo test --release --locked --lib "$witness" -- --exact --ignored --nocapture --test-threads=1
  echo 'LT110 real guest/file mechanics passed using private authority fixtures; live admission remains disabled.'
fi

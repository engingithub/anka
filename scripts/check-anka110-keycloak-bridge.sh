#!/usr/bin/env bash
# LK110 combined real-Keycloak/CC2/E11/file acceptance. Cargo runs only on request.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
if [ "$#" -eq 1 ] && [ "$1" = "--python-only" ]; then
  python3 scripts/keycloak/test_bridge_acceptance.py
  bash scripts/check-anka110-local-bridge.sh --python-only
  exit 0
fi
if [ "$#" -ne 2 ] || [ "$1" != "--real" ]; then
  echo "Usage: $0 --python-only | --real PRIVATE_LAB_STATE" >&2
  exit 2
fi
python3 scripts/keycloak/test_bridge_acceptance.py
lk110_tmp="$(mktemp -d "${TMPDIR:-/tmp}/anka110-lk.XXXXXX")"
trap 'rm -rf -- "$lk110_tmp"' EXIT
cargo test --release --locked --lib --no-run --message-format=json-render-diagnostics > "$lk110_tmp/build.jsonl"
lk110_binary="$(python3 - "$lk110_tmp/build.jsonl" <<'PY'
import json, sys
from pathlib import Path
found = set()
for line in Path(sys.argv[1]).read_text().splitlines():
    try: value = json.loads(line)
    except ValueError: continue
    if (value.get('reason') == 'compiler-artifact' and value.get('profile', {}).get('test') is True
        and value.get('target', {}).get('name') == 'anka' and 'lib' in value['target'].get('kind', [])
        and value.get('executable')):
        found.add(str(Path(value['executable']).absolute()))
if len(found) != 1:
    sys.exit('ERROR: expected exactly one Cargo library-test executable')
print(found.pop())
PY
)"
python3 scripts/keycloak/bridge_acceptance.py run --state "$2" --binary "$lk110_binary"

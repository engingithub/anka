#!/usr/bin/env bash
# Host fixtures only. Intentionally never invokes cargo or Kleis.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/keycloak/test_preflight.py

python3 scripts/keycloak/test_lab.py

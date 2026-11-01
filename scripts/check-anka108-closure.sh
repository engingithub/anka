#!/usr/bin/env bash
# Local acceptance for the typed-object/member/large-link integration packet.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# A patch ZIP is an overlay, not a complete checkout. Fail before a long run
# with a useful recovery message if source was accidentally replaced by it.
for required in Cargo.toml src/lib.rs src/anka64/cc2_fixed_point.rs \
  scripts/check-anka108-gates.py theories/anka108_compiler_resources.kleis \
  userspace/system/compiler/ankacc2_stage3.c; do
  if [[ ! -f "$required" ]]; then
    echo "Missing project file: $required. Restore the complete project recovery ZIP at the repository root." >&2
    exit 2
  fi
done
python3 scripts/check-anka108-job-integration.py
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-compiler-admission
run_real=0
case "${1:-}" in
  "") ;;
  --real) run_real=1 ;;
  *) echo 'Usage: scripts/check-anka108-closure.sh [--real]' >&2; exit 2 ;;
esac
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-c3-c4
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-publication
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-jobs
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-preprocessor-storage
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-linker-storage
cargo test --release --lib c2_linker_storage_ -- --nocapture --test-threads=1
python3 scripts/check-anka108-gates.py \
  --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" \
  --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-application-run
cargo test --release --lib c2_run_ -- --nocapture --test-threads=1
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-rebuild-service
cargo test --release --lib c5_service_ -- --nocapture --test-threads=1
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-http-application
cargo test --release --lib c5_http_ -- --nocapture --test-threads=1
cargo check --release --bin anka
cargo test --release --lib --no-run
cargo test --release --lib extended_ccb_capacity_rejection_never_patches_unemitted_slots -- --nocapture --test-threads=1
cargo test --release --lib p104_ccb_builds_real_userspace_ankald -- --nocapture --test-threads=1
cargo test --release --lib c35_ -- --test-threads=1
cargo test --release --lib c4_receipt_ -- --nocapture --test-threads=1
cargo test --release --lib c4_large_link_policy -- --test-threads=1
cargo test --release --lib c4_consumer_ -- --nocapture --test-threads=1
cargo test --release --lib c4_linked_publication_ -- --nocapture --test-threads=1
cargo test --release --lib c4_execution_ -- --nocapture --test-threads=1
cargo test --release --lib c4_startup_ -- --nocapture --test-threads=1
cargo test --release --lib c3_workspace_retry_ -- --nocapture --test-threads=1
cargo test --release --lib c5_job_ -- --nocapture --test-threads=1
cargo test --release --lib c2_preprocess_storage_ -- --nocapture --test-threads=1
python3 scripts/check-anka108-gates.py --kleis "${KLEIS_BIN:-$HOME/.cargo/bin/kleis}" --kleis-root "${KLEIS_ROOT:-$HOME/git/cee/kleis}" --only-compiler-admission
cargo test --release --lib c2_admission_ -- --nocapture --test-threads=1
if (( run_real )); then
  export ANKA_PRODUCER_TIMEOUT_SECS="${ANKA_PRODUCER_TIMEOUT_SECS:-900}"
  cargo test --release --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --nocapture --test-threads=1
  cargo test --release --lib c35_real_typed_modules_and_heap_list -- --ignored --nocapture --test-threads=1
  cargo test --release --lib c4_real_large_application_link_and_load -- --ignored --nocapture --test-threads=1
  cargo test --release --lib c3_workspace_retry_real_compiler -- --ignored --nocapture --test-threads=1
  cargo test --release --lib c2_preprocess_storage_real_include_growth -- --ignored --nocapture --test-threads=1
  cargo test --release --lib c5_real_compiler_job_retry_publication -- --ignored --nocapture --test-threads=1
  cargo test --release --lib c5_service_real_concurrent_rebuild -- --ignored --nocapture --test-threads=1
  cargo test --release --lib c5_http_real_protected_application -- --ignored --nocapture --test-threads=1
  echo 'Typed-object/member and large-link acceptance passed. This does not certify complete C2 job accounting or the C5 service rebuild.'
else
  echo 'Component checks passed. Real guest acceptance is still pending; run this script with --real.'
fi

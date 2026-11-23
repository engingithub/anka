# Anka64 performance baseline results

Status: **NOT MEASURED**. Replace placeholders with observations, not estimates.

## Context

- Date / source commit / dirty changes:
- Session path / build manifest hash / workload binary hashes:
- Mac model / memory / native architecture or Rosetta:
- macOS / Xcode / Rust versions:
- Effective Cargo settings and environment overrides:
- Power mode / thermal state / background activity:
- Instrument/template and any customized options:
- Symbols resolved? Debug artifacts retained at:

## Unprofiled samples

Use seconds. Preserve individual runs; state any exclusion and its reason.

| Workload | Run directory | Valid? | Wall | User CPU | System CPU | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| rebuild | | | | | | |
| rebuild | | | | | | |
| rebuild | | | | | | |
| restart | | | | | | |
| restart | | | | | | |
| restart | | | | | | |

- Rebuild wall-time median / minimum / maximum:
- Restart wall-time median / minimum / maximum:
- Correctness evidence: rebuild exit 42 + two modules; RR110 one test passed:

## Captures and overhead

| Workload / instrument | Trace path | Target completed? | Target timeline duration | Matching unprofiled median | Overhead / caveat |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

Calculate duration overhead as `(traced target duration / baseline median - 1) * 100`
only for matching complete workloads and comparable conditions. Do not use the
helper's `capture_elapsed_seconds` as target duration. Keep partial/error captures
separate. Record tracing failures, deadline failures, missing symbols and coverage.

## Observed costs

| Workload / phase if attributable | Function or stack | Self / inclusive CPU measure | Allocation/copy/wait evidence | Interpretation and uncertainty |
| --- | --- | --- | --- | --- |
| | | | | |

- Allocations instrument: allocation count/bytes, persistent/transient footprint,
  selected interval and stack evidence (or **not measured**):
- Phases unresolved by sampling; coarse markers needed:
- Guest work counts actually available and normalization units (or **unavailable**):
- Host emulator overhead versus work likely to remain on native hardware:

## Next bounded change

- Measured bottleneck and supporting trace location:
- Proposed change and expected reason for improvement:
- Authority/accounting/lifetime behavior affected? Required Kleis review:
- Correctness regressions and matching before/after workload:
- Acceptance condition; result remains pending until measured:

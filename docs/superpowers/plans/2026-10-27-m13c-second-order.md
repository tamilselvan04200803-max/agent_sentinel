# M13C and R&D gap integration plan

> **For agentic workers:** Execute inline using the executing-plans and test-driven-development skills. Use one fresh read-only reviewer on the finished feature.

**Goal:** Reject second-order repair evasions before sandbox execution and expose the same findings in CI; then implement useful, verified gaps in the supplied R&D specification.

**Architecture:** A bounded, non-executing symbolic folder feeds a differential AST analyzer. Findings carry fixed diagnostic codes, source locations and existing reason categories. Repair guards raise typed errors; CI aggregates findings. Existing sandbox, approval, schema and public-call contracts remain intact.

**Tech stack:** Python >=3.11, stdlib and existing dependencies, PowerShell, existing venv.

**Spec:** M13C attachment `29379849-174c-4d15-95b3-8202e37aa53f/Pasted text.txt`; master attachment `cb11a6fc-ee23-43f7-af3d-c6915a50be9a/Pasted text.txt` (explicit multi-file preauthorization).

## Global constraints and rulings

- Worktree `agent_sentinel_m13c`, base `c1e0149`. Preserve primary checkout's AGENTS.md, all modified tracked bytecode and `.pytest_tmp/`.
- UTF-8/LF edits, Python `-B`, no dependencies, no host execution of inspected source/tests, no SQLite or container-boundary changes.
- Keep existing assertions; attempt strict new rules first, reproduce compatibility conflicts, adapt narrowly and record actual evidence.
- Supplied detailed design is the implementation authority. No additional design/permission round is necessary.
- Static checks are bounded policies, not proofs of general detection, semantic purity or absence of false positives. Performance claims apply to measured fixtures only.
- Do not evaluate randomized `hash()` on the host; identify hash comparisons structurally. Do not use eval/exec/import to inspect source.

## Review focus

- Existing hazards in one scope cannot exempt new occurrences or hazards in another scope; alias changes must affect differential identity.
- Receiver exemptions require an actual declared method on the resolved local class; unrelated classes with matching method names cannot exempt calls.
- Folding bounds cover intermediate materialization, comprehension iteration, nesting and operations, including codec expansion.
- Finally exits must target outside the finally suite; nested function exits and entirely internal loop exits are permitted.
- Diagnostic codes survive retry sanitization; directives contain only fixed trusted text, never assertion values.

## Tasks

1. [x] Add unit/adversarial RED tests for ADV-01 through ADV-12, positive controls, differential scope/alias handling, safe bounds, telemetry and representative timing.
2. [x] Add `symbolic_constants.py`: `fold_symbolic_constant(node)` and bounded internal folder for composition, comprehensions, codecs, slicing and digests.
3. [x] Add `second_order_guard.py`: frozen findings/metrics, snapshot/reset, differential scope-aware analysis and typed enforcement. Support literal-independent structural checks.
4. [x] Integrate `patch_minimizer.py`, `overfit_guard.py`, `domain/exceptions.py`, `failure_taxonomy.py`, `verification/__init__.py`, and `ci_gate_analysis.py`. Add retry/no-Docker and CI aggregation tests to new M13C tests.
5. [x] Run focused legacy/new tests, Ruff and strict mypy; run full suite and reproduce/adapt any legacy conflicts without changing old assertions.
6. [x] Audit M13A/B/14/15 against master directive. Implement useful gaps with RED/GREEN tests, document invalid guarantees and incompatibilities rather than claiming them.
7. [x] Update README/STATE with actual evidence and limitations. Run final full suite/live Docker checks, one read-only review, resolve findings, conventionally commit and normally push to origin/main.

## Evidence ledger

- Baseline: 962 passed, 11 skipped (10 live tests skipped because daemon/image were unavailable; one Windows symlink restriction).
- Initial M13C RED: 73 failures from missing APIs. Boundary regressions reproduced before fixes.
- Strict module assignment rule caused nine existing failures: six M13A state-machine numeric CodeSlop edits and three M15 numeric constant edits. Ruling: existing repair/CI APIs explicitly permit only simple int/float module assignments by default, excluding bool; strict standalone API remains default. Callers can disable the narrow exemption. No old assertion changed.
- M13C initial full gate: 1,066 passed, one Windows symlink skip, all 10 live Docker tests passed (95.95s). Docker Desktop was started and the existing runner image rebuilt successfully.
- After four additional definition-time/empty-handler boundaries: 217 focused M13C/M9/M11/M12 checks passed; Ruff clean and strict mypy clean across 48 source files. Final integrated full gate remains pending.
- R&D gap scout is read-only and independent of implementation.
- Integrated R&D initial full gate: 1,150 passed, one Windows symlink skip, all 12 live Docker cases passed (123.73s).
- Final review RED: eight cases covering eager annotations, legacy diagnostic metadata and resolved digest alias changes. Fixes retain legacy literal properties/error details, while remediation directives remain fixed.
- Detached-session child contamination reproduced live (second mutant incorrectly killed); Linux subreaper descendant discovery/kill/reap fixed it. Live regression passed in 7.32s; 213 focused legacy/new tests passed after all four fixes.
- Deferred adaptations and exact constraints are recorded in STATE.md. No universal minimum, compression, latency or detection guarantee is asserted.
- Optional worker temporary-cache deletion was automatically rejected with only "blocked by policy" as reason. The generated directories remain in isolated worker worktrees; no user caches were removed.
- Final release gate after all fixes: 1,160 passed, one Windows symlink skip, all 13 live Docker tests passed (128.05s). Ruff clean; strict mypy clean across 49 source files. Source/review-fix commit e9e8e71; original test files/bytecode/user changes preserved. Final remote publication is verified through Git refs after normal push.

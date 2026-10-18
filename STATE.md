# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M6 (Production CLI & Exporter) — complete
- **Previous Milestone:** M5 (Contamination-Aware Evaluation Harness) — complete
- **Milestone Gate Status:** VERIFIED (Full ground-truth verification on Windows + live Docker Desktop)

## Completed & Verified Components

| File | Description |
|---|---|
| `src/agentsentinel/domain/exceptions.py` | Added M4-M6 exceptions: `OrchestratorError`, `DuplicatePatchError`, `BaselineNotReproducedError`, `InfrastructureFailureError`, `ApprovalIntegrityError`, `UnapprovedExportError` |
| `src/agentsentinel/policy/applier.py` | Rewritten: hard-fail on `git apply --check` failure (no silent manual-fallback); patch written with `newline="\n"`, uses `--ignore-space-change --whitespace=nowarn`; raises `PatchApplicationError` with stderr on bad hunks |
| `src/agentsentinel/sandbox/workspace.py` | `scrub_git_history` removes `.git/` entirely (while keeping worktree intact) so `git apply` still works cleanly on the scrubbed tree; Windows-safe `onerror` handler clears read-only bit on `.git/objects/pack/*` |
| `src/agentsentinel/orchestrator/dedup.py` | Tier-1 canonical diff fingerprint (strips index/headers/CRLF, SHA-256); Tier-2 Python AST equivalence fingerprint across `allowed_edit_paths` (catches comment/whitespace-only no-op patches and semantically-identical duplicates before Docker spins up) |
| `src/agentsentinel/orchestrator/checkpoint.py` | Durable SQLite store with WAL/NORMAL/foreign_keys; `runs` + `attempts` tables; atomic state transitions; supports crash recovery by reloading `(run_id, attempts_used, seen_diff_hashes, seen_ast_hashes)`; M6 extension: optional persisted `spec_json` on runs, `AttemptRecord`/`get_attempts`, and `REJECTED_BY_REVIEWER`/`FIX_VERIFIED` termination reasons |
| `src/agentsentinel/orchestrator/state_machine.py` | Full 8-invariant `RepairStateMachine`: baseline reproduction gate, attempt accounting (429/Docker failures terminate as INFRASTRUCTURE_FAILURE without consuming an attempt), Tier-1+Tier-2 dedup BEFORE container run, fresh workspace per attempt, feedback loop into next prompt, cryptographic approval binding, export gate; M6 integration fields: `image_digest`, benchmark-only `auto_approve_on_fix`, and `source_workspace_override` |
| `src/agentsentinel/evaluation/models.py` | Frozen `BenchmarkCase`, `AdmissionVerdict`, `ExclusionRecord`, and `CaseEvaluationResult` schemas. `reference_fix_patch` is documented and typed as admission-gate-only trusted data |
| `src/agentsentinel/evaluation/metrics.py` | Frozen `BenchmarkReport` and `ComparisonReport`; canonical JSON and Markdown reporting; prep and repair latency separated; infrastructure failures, duplicates, policy violations, contamination count, and failure breakdown reported; unknown cost is `None`, never coerced to `0.0` |
| `src/agentsentinel/evaluation/harness.py` | Two-gate admission: baseline+test patch must fail (`TESTS_FAILED`), baseline+test+reference patches must pass (`OK`). Exclusions are returned as verdicts and logged. `BenchmarkHarness.run_suite` freezes order and runs admitted cases through `RepairStateMachine`; `compare_baseline_vs_bounded_retry` reports single-shot vs bounded-retry deltas. Reference patch is never forwarded to the state machine or prompt builder |
| `tests/fixtures/benchmark_cases/` | Three deterministic offline fixtures: string normalizer, pagination off-by-one, and `0`-vs-`None` config fallback. Each has `spec.json`, `src/`, `test.patch`, and generated exact `reference.patch` |
| `src/agentsentinel/cli/exporter.py` | Deterministic approved-only exporter. Rejects unsafe run IDs, writes canonical sorted `evidence.json`, exact `approved.patch`, and human-readable `REPORT.md`; includes CaseSpec (persisted from M6), baseline/post-patch results, attempt token/cost ledger, approval binding, and bundle hash |
| `src/agentsentinel/cli/main.py` | `argparse` CLI with `run`, `status`, `approve`, `reject`, `export`, and `benchmark` subcommands and explicit exit codes for pending approval, approval failure, and unapproved export. Registered as the `agentsentinel` console script |
| `tests/unit/test_m4_state_machine.py` | Invariant tests for 8 state machine rules including baseline gate, crash recovery, dedup, attempt limits, feedback loop, approval binding, and export gate |
| `tests/unit/test_m5_evaluation.py` | Comprehensive evaluation and admission test suite |
| `tests/unit/test_m6_cli.py` | Comprehensive CLI subcommands and export tests |
| `tests/adversarial/test_adversarial_m4.py` | Adversarial test suite for M4 orchestrator resilience |
| `tests/adversarial/test_adversarial_m5_m6.py` | Adversarial test suite for prompt leakage and CLI hash tampering |
| `tests/unit/test_audit_regressions.py` | Comprehensive regression suite for M0-M3 audits |
| `tests/integration/test_docker_live_m1.py` | 6 live integration tests against real Docker daemon |

## Verification Evidence
- Live Docker Tests: All 6 integration tests in `tests/integration/test_docker_live_m1.py` passing live with pre-baked `agentsentinel-runner:py311` image.
- Linter: `python -m ruff check src tests` (All checks passed, 0 errors).
- Typecheck: `python -m mypy --strict src` (Success: no issues found in 28 source files).
- Pre-M4 Applier Fix:
  - `git apply` works after `scrub_git_history` removes `.git/`.
  - Bad-context diffs raise `PatchApplicationError` directly from `apply_validated_patch` (no silent fallback).
  - `PatchApplicationError` is a subclass of `AgentSentinelError`.

## Architectural Decision Log (ADR)

*(Previous M0–M4 entries retained in git history.)*

- **[2026-10-18 M5-1] Decision:** Benchmark admission is a two-gate proof, not a label. A case is admitted only if its test patch reproduces a failure and its withheld reference patch makes the same suite pass. Rationale: prevents inflating repair rates with broken or already-passing cases. Tradeoff: admission costs two extra test executions per case, reported separately as prep latency.
- **[2026-10-18 M5-2] Decision:** Excluded cases are first-class report data (`exclusion_log`) and unknown costs remain `None`. Rationale: silently dropping exclusions or treating unknown pricing as zero would make benchmark and cost claims dishonest. Tradeoff: consumers must handle partial cost explicitly.
- **[2026-10-18 M5-3] Decision:** Offline benchmark verification executes the real test command in the workspace; Docker remains the production security boundary. Rationale: deterministic CI can prove F2P semantics without a daemon, while documentation must not confuse local execution with sandbox isolation. Tradeoff: benchmark hosts must only run trusted fixture patches locally.
- **[2026-10-18 M6-1] Decision:** Persist the CaseSpec JSON with each run and include it in evidence exports. Rationale: an approved diff is not auditable without the exact test command, allowlist, and failing-test IDs that authorised it. Tradeoff: one additional nullable SQLite column, migrated for pre-M6 databases.
- **[2026-10-18 M6-2] Decision:** CLI approval remains a separate process invocation using the stored cryptographic binding triple; no `--yes` bypass exists. Rationale: approval must be an explicit human act bound to the exact diff/image/result, even though it makes the workflow less convenient. Tradeoff: operators must copy hashes from `status`/`run` output.
- **[2026-10-18 M6-3] Decision:** Evidence export is a pure read of the checkpoint DB after the APPROVED gate, with canonical sorted JSON and LF patch bytes. Rationale: exports must be reproducible byte-for-byte from durable state after process restarts. Tradeoff: runtime-only context not persisted in SQLite cannot appear in the bundle.

## Phase D — Final Tech Lead Questions (M5/M6)

1. **Benchmark governance:** Should the first externally reported benchmark be a newly authored, never-published private suite (to minimise contamination), or a public SWE-bench-style suite with contamination flags and stratified public/private reporting?
2. **Approval operations:** Should production approval remain CLI/hash-copy based for maximum auditability, or should M7 add a signed approval service (for example OIDC-authenticated web/Slack approval) while preserving the same `sha256(diff + image + result)` binding underneath?
3. **Evidence retention & signing:** Should exported bundles remain local canonical JSON/Markdown artifacts, or should M7 require detached cryptographic signing (for example Sigstore/minisign), immutable object-store upload, and a retention policy for stdout/stderr contained in evidence?

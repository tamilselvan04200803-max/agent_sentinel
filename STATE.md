# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M6 (Production CLI & Exporter) — complete
- **Previous Milestone:** M5 (Contamination-Aware Evaluation Harness) — complete
- **Milestone Gate Status:** VERIFIED (local quality gates; live Docker tests skipped where Docker is unavailable)

## Completed & Verified Components

| File | Description |
|---|---|
| `src/agentsentinel/evaluation/models.py` | Frozen `BenchmarkCase`, `AdmissionVerdict`, `ExclusionRecord`, and `CaseEvaluationResult` schemas. `reference_fix_patch` is documented and typed as admission-gate-only trusted data. |
| `src/agentsentinel/evaluation/metrics.py` | Frozen `BenchmarkReport` and `ComparisonReport`; canonical JSON and Markdown reporting; prep and repair latency separated; infrastructure failures, duplicates, policy violations, contamination count, and failure breakdown reported; unknown cost is `None`, never coerced to `0.0`. |
| `src/agentsentinel/evaluation/harness.py` | Two-gate admission: baseline+test patch must fail (`TESTS_FAILED`), baseline+test+reference patches must pass (`OK`). Exclusions are returned as verdicts and logged. `BenchmarkHarness.run_suite` freezes order and runs admitted cases through `RepairStateMachine`; `compare_baseline_vs_bounded_retry` reports single-shot vs bounded-retry deltas. Reference patch is never forwarded to the state machine or prompt builder. |
| `tests/fixtures/benchmark_cases/` | Three deterministic offline fixtures: string normalizer, pagination off-by-one, and `0`-vs-`None` config fallback. Each has `spec.json`, `src/`, `test.patch`, and generated exact `reference.patch`. |
| `src/agentsentinel/cli/exporter.py` | Deterministic approved-only exporter. Rejects unsafe run IDs, writes canonical sorted `evidence.json`, exact `approved.patch`, and human-readable `REPORT.md`; includes CaseSpec (persisted from M6), baseline/post-patch results, attempt token/cost ledger, approval binding, and bundle hash. |
| `src/agentsentinel/cli/main.py` | `argparse` CLI with `run`, `status`, `approve`, `reject`, `export`, and `benchmark` subcommands and explicit exit codes for pending approval, approval failure, and unapproved export. Registered as the `agentsentinel` console script. |
| `src/agentsentinel/orchestrator/checkpoint.py` | M6 extension: optional persisted `spec_json` on runs (with migration for older DBs), `AttemptRecord`/`get_attempts`, and `REJECTED_BY_REVIEWER`/`FIX_VERIFIED` termination reasons. |
| `src/agentsentinel/orchestrator/state_machine.py` | M6 integration fields: `image_digest`, benchmark-only `auto_approve_on_fix`, and `source_workspace_override`; approval uses the configured image digest. |

## Verification

- `python -m pytest`: **306 passed, 6 skipped** (live Docker integration tests skipped without Docker test setup).
- `python -m ruff check src tests`: **0 errors**.
- `python -m mypy --strict src`: **0 errors across 28 source files**.
- M5 tests cover admission rejection, exclusion logging, prep/repair latency separation, unknown-cost handling, end-to-end verified repair, and baseline-vs-bounded comparison math.
- M6 tests cover `run`-state inspection through approval/rejection/export, unapproved export failure, tampered approval hashes, and path traversal sanitisation.
- Adversarial M5/M6 tests prove the reference patch marker does not leak into captured LLM prompts and forged CLI diff hashes fail.

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

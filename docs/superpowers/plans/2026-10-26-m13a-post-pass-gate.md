# AgentSentinel M13A Implementation Plan

> **For agentic workers:** Use OpenCode subagents for isolated workstreams. The coordinator owns shared integration, release gates, final review, commit, and push. Follow the task order and interface contracts below; do not edit the same files from parallel agents.

**Goal:** Add opt-in post-pass hunk minimization and mutation adequacy evidence before AgentSentinel requests human approval.

**Architecture:** The coordinator integrates two opt-in stages after the existing patch passes sandbox verification. Minimization searches the existing deterministic subset candidates against clean baseline copies; mutation probing evaluates bounded AST mutants from the selected patch. The accepted diff and result are durably rebound to approval and evidence without changing SQLite schema or container isolation.

**Tech Stack:** Python 3.11+, stdlib, existing dependencies, pytest, Docker integration runner, PowerShell commands.

**Spec:** User-provided M13A directive in the Codex attachment. Treat it as the requirements source together with this plan and `AGENTS.md`.

## Global Constraints

- Preserve all existing tests and public callers; new state-machine flags default to disabled.
- Keep `/workspace:ro`, Docker `--read-only`, network isolation, resource limits, and the existing runner call signature.
- Never execute patch or repository test code on the host.
- Keep SQLite schema unchanged; preserve the current SHA-256 approval binding (not HMAC).
- Use PowerShell-compatible commands, no `&&`, and UTF-8/LF file writes.
- Use existing dependencies only. Do not delete or restore the pre-existing modified `src/agentsentinel/policy/__pycache__/diff_parser.cpython-313.pyc`.
- Preserve zero-regression behavior when both new flags are false.

## OpenCode Execution Protocol

1. Coordinator reads `AGENTS.md`, this plan, the M13A attachment, and current git status. Record pre-existing changes; do not stage them.
2. Coordinator creates a task branch/worktree from current `main`. Each implementation subagent gets its own worktree/branch from that task branch and owns only the files listed for its workstream. Do not run concurrent agents against the same writable checkout.
3. Before parallel work, coordinator posts the shared interface contract from Task 1 to all workers. Workers commit only their owned files, run focused tests, and report commit hash, commands, output, and any deviations.
4. Coordinator merges/cherry-picks workstream commits in dependency order, resolves integration conflicts, runs full checks, dispatches one read-only final reviewer, fixes findings, then commits/pushes normally. Never force-push. Do not claim Docker coverage unless Docker actually ran.
5. Existing project instruction says ask before changes touching more than three files. The user supplied this concrete M13A execution directive and asked OpenCode to execute it; treat that as authorization for the planned multi-file work. Do not ask again unless the actual diff materially expands this scope.

## Shared Interfaces (freeze before parallel implementation)

Create `src/agentsentinel/verification/post_pass_gate.py` with frozen dataclasses exactly as specified in the M13A directive:

- `MinimizationSummary(raw_hunks_count: int, minimized_hunks_count: int, codeslop_hunks_removed: int, was_minimized: bool)`
- `SurvivedMutantDetail(mutant_id: str, file_path: str, function_name: str, mutation_description: str)`
- `MutationAdequacySummary(low_mutation_adequacy: bool, total_mutants_evaluated: int, mutants_killed: int, mutants_survived: int, mutation_score: float, survived_mutant_details: tuple[SurvivedMutantDetail, ...])`
- `PostPassVerificationReport(minimized_diff: str, minimized_execution_result: ExecutionResult, minimization_summary: MinimizationSummary, mutation_adequacy_summary: MutationAdequacySummary)`

Implement `run_ddmin_hunk_minimization(*, raw_diff: str, baseline_workspace: Path, spec: CaseSpec, runner: ContainerRunnerProtocol, original_result: ExecutionResult) -> tuple[str, ExecutionResult, MinimizationSummary]` and `run_mutation_adequacy_probe(*, minimized_diff: str, baseline_workspace: Path, patched_workspace: Path, spec: CaseSpec, runner: ContainerRunnerProtocol, max_mutants: int = 3) -> MutationAdequacySummary`. `PostPassVerificationReport` combines the outputs in the state machine. Export the public models and generator-facing API from the verification package. Keep these helpers strictly typed. Define a local `ContainerRunnerProtocol` with the existing `run_in_container(case_id, patch_diff_hash, workspace_host_path, command)` signature; do not change `HardenedContainerRunner` or any existing mock contract. `EvidenceBundle` adds optional summary fields defaulting to `None`. `RepairStateMachine` adds keyword-only `enable_ddmin_minimization: bool = False`, `enable_mutation_probe: bool = False`, and `max_mutants: int = 3`.

## Review Focus

- Candidate execution can silently omit an expected test: candidate is rejected unless every expected node ID visibly passed.
- Mutant wrapper setup failure can look like a mutant kill: reserved wrapper status must distinguish infrastructure errors from pytest outcomes.
- Timed-out pytest descendants can outlive workspace reset: terminate/reap the process group before reuse or cleanup.
- A minimized result can be paired with the raw proposal after restart: persist accepted proposal/result/hash atomically and test reopened state.
- A 100% survivor warning can be erased by benchmark auto-approval: require human approval and persist the warning.

---

## Workstreams and Tasks

### Task 1: Freeze API contracts and prepare tests

**Owner:** Coordinator. **Files:** `tests/unit/test_m13a_post_pass_gate.py` (create); shared interface declarations above.

- [ ] Add failing tests for frozen summary models, imports/exports, cap validation, zero-mutant score (`1.0`), and optional `EvidenceBundle` fields.
- [ ] Add legacy-construction tests proving state machine and evidence callers still work without new arguments.
- [ ] Run focused tests and record expected failures before implementation.
- [ ] Publish the exact shared interfaces above to the parallel workstreams. No worker may independently rename fields or alter defaults.

### Task 2: Candidate minimization engine

**Owner:** Agent A. **Files:** `src/agentsentinel/verification/post_pass_gate.py` (minimization portion only), `tests/unit/test_m13a_minimization.py`.

- [ ] Test the two-hunk CodeSlop/fix case, zero/one-hunk short circuit, deterministic first-smallest success, no passing subset fallback, missing expected IDs, policy/apply rejection before Docker, and scratch cleanup.
- [ ] Implement `run_ddmin_hunk_minimization` using `generate_minimal_hunk_subsets` in its existing order. Count hunks with the existing parsed diff representation; do not invent text-based counting.
- [ ] For each multi-hunk candidate, copy the pristine baseline to a fresh workspace, validate policy, apply, run `verify_not_overfitted`, then run the exact failing IDs in verbose mode. Candidate policy/application/test/timeout failure skips that candidate; infrastructure errors propagate.
- [ ] Return the original passing diff/result if no candidate passes. For zero/one hunk, make no extra sandbox calls. Clean scratch workspaces in `finally` paths.
- [ ] Run the focused minimization tests and strict typing for the new module; commit only owned files.

**Contract:** The selected patch is the first passing candidate at the smallest size offered by the existing generator. This is a bounded single-pass heuristic; it does not guarantee global minimum or 1-minimality. `codeslop_hunks_removed = raw_hunks_count - minimized_hunks_count`.

### Task 3: Shadow-workspace mutation batch helper

**Owner:** Agent B; can run in parallel with Task 2 in a separate worktree. **Files:** `src/agentsentinel/verification/mutation_batch.py` (create), tests in `tests/unit/test_m13a_mutation_batch.py`.

- [ ] Test generated script content/AST or a mocked stdlib process boundary. Never execute repository source or tests on the host.
- [ ] Implement `build_mutation_batch_script()` and typed `run_in_container_mutation_batch(...)`. The script copies `/workspace` into `/tmp/mut_workspace`, applies each supplied mutant only inside the copy, removes `__pycache__`, calls `importlib.invalidate_caches()`, and runs `pytest -x --tb=no -q` for the configured failing IDs.
- [ ] Use one isolated shadow tree per mutant, or fully restore it before the next mutant. Terminate and reap the pytest process group on timeout before resetting the tree.
- [ ] Enforce `max(1.0, 2.0 * baseline_wall_seconds)` for each test process. Use the existing container runner for outer Docker timeout, output bounds, network isolation, read-only rootfs, and read-only source mount.
- [ ] Reserve a distinct wrapper setup/error status or structured marker. A copy/path/spawn/serialization failure is infrastructure failure, never `KILLED`. Test exit nonzero and timeout are `KILLED`; exit zero is `SURVIVED`.
- [ ] Ensure paths cannot escape `/tmp/mut_workspace`; clean temporary state on every exit. Run focused tests and strict typing; commit only owned files.

### Task 4: Mutation summary and public exports

**Owner:** Agent C after Task 1 contract is published; separate worktree. **Files:** `src/agentsentinel/verification/post_pass_gate.py` (mutation portion, coordinate shared file with Agent A by using an agreed separate branch/cherry-pick order), `src/agentsentinel/verification/__init__.py`, tests in `tests/unit/test_m13a_mutation_adequacy.py`.

- [ ] Test total cap across multiple files, deterministic path order, no eligible sites, zero cap, timeout kills, ordinary test failures as kills, survivors/details, and infrastructure propagation.
- [ ] Generate using `generate_differential_patch_mutants` only for changed `.py` files in the selected patch. Apply one total `max_mutants` cap (default 3); never evaluate mutants from discarded hunks.
- [ ] Compute score as killed/evaluated, or `1.0` for zero generated. Set `low_mutation_adequacy` only when at least one mutant was evaluated and all survived.
- [ ] Export additive API and data types. Do not change the legacy generator.
- [ ] Run focused tests and strict typing; commit only owned files.

**Parallelism note:** Agents A and C both extend `post_pass_gate.py`, so serialize them: A lands first, then C branches from A's commit. Their test modules are distinct. Agent B can work concurrently in its isolated worktree.

### Task 5: State machine wiring and durable checkpoint update

**Owner:** Agent D after Tasks 2–4 merge. **Files:** `src/agentsentinel/orchestrator/state_machine.py`, `src/agentsentinel/orchestrator/checkpoint.py`, `src/agentsentinel/domain/models.py`, tests in `tests/unit/test_m13a_state_machine.py`.

- [ ] Add optional `MinimizationSummary | None` and `MutationAdequacySummary | None` fields to `EvidenceBundle`; preserve all existing positional construction by adding fields after current required/default fields.
- [ ] Add opt-in keyword-only flags and cap to `RepairStateMachine`; validate nonnegative cap. Both flags false must preserve current Docker call counts and approval behavior.
- [ ] Retain the patched workspace until post-pass stages finish. If enabled, run minimization first, adopt its diff/result, then run mutation probing on that selected patch only.
- [ ] Rebind `PatchProposal` to the minimized diff while retaining original model/token metadata. Compute `diff_hash`, `post_patch_result_hash`, and existing SHA-256 approval hash from the adopted diff/result, after minimization.
- [ ] Add one atomic checkpoint operation that persists the accepted proposal, matching attempt diff hash/result/status, approval record, and awaiting-approval transition without schema changes. Include original proposal/result in approval metadata for audit. Do not change attempt count, budget, usage, or transport semantics.
- [ ] If every evaluated mutant survives, persist `low_mutation_adequacy=True` and do not take `auto_approve_on_fix`; leave run in `AWAITING_HUMAN_APPROVAL`. Zero mutants do not set the warning.
- [ ] Test rejected fixes never call post-pass Docker stages, rejected candidates do not mutate source, auto-approval behavior in warning/no-warning/zero-mutant cases, atomic restart recovery, hash rebinding, and disabled defaults.
- [ ] Run focused state-machine plus M4/M5/M12 regression tests, strict typing, and commit owned files.

### Task 6: Evidence exporters and documentation

**Owner:** Agent E after Task 5 interface is merged. **Files:** `src/agentsentinel/cli/exporter.py`, `README.md`, `STATE.md`, tests in `tests/unit/test_m13a_exporter.py`.

- [ ] Ensure CLI export reads the accepted proposal/result persisted in the passing attempt and includes minimization and mutation summaries in `evidence.json` and `REPORT.md`.
- [ ] Ensure `export_evidence_bundle()` returns typed summaries and selected patch/result after database reopen. Preserve approved-only export gate and bundle determinism.
- [ ] Test warning/survivor details in JSON and Markdown, minimized patch in `approved.patch`, unchanged export shape for older runs, and export denial before approval.
- [ ] Update README and STATE with M13A interfaces, opt-in defaults, single-pass minimization limitation, mutation-score limits, unchanged Docker invariants, actual verification results, and any unrun Docker gate.
- [ ] Run focused exporter tests and strict typing; commit owned files.

### Task 7: Integration, live verification, review, release

**Owner:** Coordinator, sequential. **Files:** `tests/integration/test_docker_live_m13a.py` (create), any reviewed integration fixes, final docs.

- [ ] Add live Docker scenarios for candidate minimization, killed and surviving mutants, timeout cleanup, and read-only source preservation. Confirm tests exercise actual `HardenedContainerRunner`; do not call something live unless Docker ran.
- [ ] Merge workstream commits in dependency order and resolve shared module/test ownership conflicts. Inspect full `git diff`; ensure the pre-existing cache modification is unstaged and untouched.
- [ ] Run after each merged change: focused M13A test, `.venv\Scripts\python.exe -m ruff check src tests`, and `.venv\Scripts\python.exe -m mypy --strict src`.
- [ ] Run final gates as separate PowerShell invocations: `.\.venv\Scripts\python.exe -m ruff check src tests`; `.\.venv\Scripts\python.exe -m mypy --strict src`; `.\.venv\Scripts\python.exe -m pytest --basetemp=.pytest_tmp -p no:schemathesis -q`.
- [ ] Run live Docker integration tests. If Docker is unavailable, report this gate incomplete and do not claim live success.
- [ ] Dispatch one fresh read-only reviewer on the complete diff. Fix and re-verify all material findings.
- [ ] Confirm no tracked cache/fixture/test assertions were changed; confirm pre-existing cache modification remains untouched; inspect `git status` and `git diff --check`.
- [ ] Commit milestone changes conventionally and push normally to `origin/main`; never force-push. Record commit hash, actual test totals, skip reasons, Docker result, Ruff, and mypy results in `STATE.md`.

## Acceptance Criteria

- Existing suite assertions and caller APIs remain intact; with both flags disabled, legacy state-machine behavior and container call counts remain unchanged.
- With minimization enabled, the approval-bound patch/result is exactly the selected passing candidate; with mutation enabled, only that candidate is probed.
- All-survived evidence requires human approval and persists across process restart and export.
- Wrapper infrastructure errors cannot inflate kill counts; timed-out descendants cannot affect later mutants.
- Docker read-only mounts and read-only root filesystem remain enabled.
- Ruff, strict mypy, full pytest, and live Docker outcomes are reported from actual command results.
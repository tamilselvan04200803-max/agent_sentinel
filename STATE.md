# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M4 (Bounded Repair State Machine)
- **Current Sub-Task:** IN PROGRESS — Orchestrator, dedup, checkpoint, state machine
- **Milestone Gate Status:** PRE-VERIFICATION

## Completed & Verified Components

| File | Description |
|---|---|
| `src/agentsentinel/domain/exceptions.py` | Added M4 exceptions: `OrchestratorError`, `DuplicatePatchError`, `BaselineNotReproducedError`, `InfrastructureFailureError`, `ApprovalIntegrityError`, `UnapprovedExportError` |
| `src/agentsentinel/policy/applier.py` | Rewritten: hard-fail on `git apply --check` failure (no silent manual-fallback); patch written with `newline="\n"`, uses `--ignore-space-change --whitespace=nowarn`; raises `PatchApplicationError` with stderr on bad hunks |
| `src/agentsentinel/sandbox/workspace.py` | `scrub_git_history` removes `.git/` entirely (while keeping worktree intact) so `git apply` still works cleanly on the scrubbed tree; Windows-safe `onerror` handler clears read-only bit on `.git/objects/pack/*` |
| `src/agentsentinel/orchestrator/dedup.py` | Tier-1 canonical diff fingerprint (strips index/headers/CRLF, SHA-256); Tier-2 Python AST equivalence fingerprint across `allowed_edit_paths` (catches comment/whitespace-only no-op patches and semantically-identical duplicates before Docker spins up) |
| `src/agentsentinel/orchestrator/checkpoint.py` | Durable SQLite store with WAL/NORMAL/foreign_keys; `runs` + `attempts` tables; atomic state transitions; supports crash recovery by reloading `(run_id, attempts_used, seen_diff_hashes, seen_ast_hashes)` |
| `src/agentsentinel/orchestrator/state_machine.py` | Full 8-invariant `RepairStateMachine`: baseline reproduction gate, attempt accounting (429/Docker failures terminate as INFRASTRUCTURE_FAILURE without consuming an attempt), Tier-1+Tier-2 dedup BEFORE container run, fresh workspace per attempt, feedback loop into next prompt, cryptographic approval binding, export gate |

## Pre-M4 Applier Fix — Verified
- `tests/unit/test_premark_applier.py` proves:
  - `git apply` works after `scrub_git_history` removes `.git/`.
  - Bad-context diffs raise `PatchApplicationError` directly from `apply_validated_patch` (no silent fallback).
  - `PatchApplicationError` is a subclass of `AgentSentinelError`.
- Existing `test_applier.py` suite continues to pass (11/11).

## Active Blockers / Pending Human Verification
- M4 unit & adversarial tests are being added now; awaiting full pytest run.

## Architectural Decision Log (ADR)
*(Previous M0–M3 entries retained.)*
- **[2026-10-18 M4-1] Decision:** `git apply` is the exclusive patch engine; `apply_validated_patch` hard-fails on any `git apply --check`/`git apply` non-zero return (no manual fallback). Rationale: manual line-editor silently applied partial/corrupt hunks producing non-deterministic workspace state — exactly the class of bug the audit flagged. Tradeoff: Requires `git` to be installed on the host; missing git now raises `HarnessSetupError`.
- **[2026-10-18 M4-2] Decision:** `.git/` directory is fully deleted after `populate_from_directory` (rather than pruned); verified `git apply` operates cleanly on `.git`-less working trees. Rationale: surgical pruning (reflogs/remotes/tags/prune) leaves reachable commits visible to `git log -p --all`, leaking the future fix. Tradeoff: no git history available to harness (desirable for security, slightly less context for debugging).
- **[2026-10-18 M4-3] Decision:** SQLite checkpoint with WAL journaling, every state transition committed in its own `with conn:` block. Rationale: process kill at any point leaves the run resumable; attempt counts and token ledger never lost. Tradeoff: small disk I/O overhead per transition (negligible vs. LLM/container cost).
- **[2026-10-18 M4-4] Decision:** Duplicate/AST-no-op detection happens BEFORE Docker is invoked (Tier-1 after proposal, Tier-2 after apply in the patched workspace). Rationale: spinning up a container costs seconds-to-minutes and is the most expensive step; we must not waste it on no-op patches. Tradeoff: Tier-2 requires filesystem write of patch (fast).
- **[2026-10-18 M4-5] Decision:** HTTP 429 rate-limit errors and Docker daemon failures raise `InfrastructureFailureError` and terminate the run WITHOUT consuming an attempt; all other LLM/application/test failures DO consume an attempt. Rationale: transport-level failures are not the model's fault and should not exhaust the attempt budget; malformed JSON/policy violations/test failures reflect the model's output and must be charged.
- **[2026-10-18 M4-6] Decision:** `approve_run` enforces `sha256(diff_hash + image_digest + post_patch_result_hash)` binding; any mismatch raises `ApprovalIntegrityError`. Rationale: prevents post-hoc tampering between a passing sandbox run and human approval. Tradeoff: caller must present the binding triple (returned when entering AWAITING_HUMAN_APPROVAL).
- **[2026-10-18 M4-7] Decision:** `export_evidence_bundle` raises `UnapprovedExportError` unless state is APPROVED. Rationale: prevents accidental export of un-vetted patches.

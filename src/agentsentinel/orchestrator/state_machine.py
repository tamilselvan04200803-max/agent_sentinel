"""Milestone 4: Bounded Repair State Machine.

The :class:`RepairStateMachine` drives a single repair run through the eight
lifecycle states described in the M4 spec:

    INIT -> REPRODUCING_BASELINE -> PROPOSING_PATCH -> VALIDATING_POLICY
         -> APPLYING_PATCH -> VERIFYING_IN_SANDBOX -> AWAITING_HUMAN_APPROVAL
         -> APPROVED | REJECTED | TERMINATED_FAILED

It enforces all 8 specification invariants from the M4 checklist:

1. **Attempt accounting** — every patch proposal (malformed JSON, policy
   violation, git-apply failure, test failure) consumes an attempt, except
   429 / Docker daemon infrastructure failures which raise
   :class:`InfrastructureFailureError` and halt the run.
2. **Restart durability** — a :class:`CheckpointStore` is persisted to SQLite;
   re-initialising the machine with an existing ``run_id`` resumes the run
   with attempts_used, seen_diff_hashes, and seen_ast_hashes intact.
3. **Duplicate/AST-no-op termination** — patches are checked through both
   Tier-1 diff fingerprint and Tier-2 AST equivalence BEFORE Docker spins up;
   a hit raises :class:`DuplicatePatchError` and terminates the run.
4. **Fresh ephemeral workspace per attempt** — a new workspace is provisioned
   via :class:`WorkspaceManager` for every attempt; no reuse across attempts.
5. **Strict baseline reproduction gate** — in REPRODUCING_BASELINE, the test
   command is invoked with ``-v -ra``; if exit_code != TESTS_FAILED (1) the
   run terminates with BASELINE_NOT_REPRODUCED or HARNESS_BROKEN.
6. **Feedback loop on retry** — structured failure data (stderr, traceback,
   failing test lines) from Attempt k is appended to Attempt k+1's prompt.
7. **Cryptographic approval binding** — ``approve_run`` verifies
   ``sha256(diff_hash + image_digest + post_patch_result_hash)`` before moving
   to APPROVED. Tampering raises :class:`ApprovalIntegrityError`.
8. **Export gate** — ``export_evidence_bundle`` succeeds ONLY from APPROVED;
   otherwise raises :class:`UnapprovedExportError`.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentsentinel.domain.exceptions import (
    AgentSentinelError,
    ApprovalIntegrityError,
    BaselineNotReproducedError,
    DuplicatePatchError,
    HarnessSetupError,
    HarnessTimeoutError,
    InfrastructureFailureError,
    OverfitPolicyError,
    PatchPolicyError,
    UnapprovedExportError,
)
from agentsentinel.domain.exit_codes import ExitCode, is_harness_broken
from agentsentinel.domain.models import (
    CaseSpec,
    EvidenceBundle,
    ExecutionResult,
    PatchProposal,
)
from agentsentinel.llm.exceptions import (
    LLMAuthenticationError,
    LLMError,
    LLMGenerationError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from agentsentinel.llm.pricing import CostEstimate, ModelUsage, PricingRegistry
from agentsentinel.llm.prompts import PromptBuilder, sanitize_diagnostic
from agentsentinel.localization.ast_slicer import localize_faults
from agentsentinel.localization.traceback_parser import extract_traceback_frames
from agentsentinel.orchestrator.checkpoint import (
    AttemptStatus,
    CheckpointStore,
    RunRecord,
    RunState,
    TerminationReason,
)
from agentsentinel.orchestrator.dedup import (
    check_tier1_duplicate,
    check_tier2_duplicate_or_noop,
    tier1_fingerprint,
    tier2_fingerprint,
)
from agentsentinel.orchestrator.failure_taxonomy import FailureCategory, classify_attempt_failure
from agentsentinel.policy.applier import PatchApplicationError, apply_validated_patch
from agentsentinel.policy.validator import PatchPolicyValidator
from agentsentinel.sandbox.container import (
    ContainerConfig,
    HardenedContainerRunner,
    resolve_image_digest,
)
from agentsentinel.sandbox.workspace import WorkspaceManager
from agentsentinel.verification.overfit_guard import verify_not_overfitted

if TYPE_CHECKING:
    from agentsentinel.llm.client import LLMClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_ARGS = ["-v", "-ra"]


def _append_test_args(test_command: str | list[str]) -> str | list[str]:
    """Append ``-v -ra`` to the user-supplied test command so that pytest
    prints node IDs and a failure summary. If the command is a raw shell
    string we append to the string directly; if it's a list we extend."""
    if isinstance(test_command, list):
        return [*test_command, *_TEST_ARGS]
    return f"{test_command} {' '.join(_TEST_ARGS)}"


def _sha256(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _result_to_dict(r: ExecutionResult) -> dict[str, Any]:
    return {
        "case_id": r.case_id,
        "patch_diff_hash": r.patch_diff_hash,
        "exit_code": int(r.exit_code),
        "stdout": r.stdout,
        "stderr": r.stderr,
        "wall_seconds": r.wall_seconds,
        "stdout_truncated": r.stdout_truncated,
        "stderr_truncated": r.stderr_truncated,
        "expected_test_ids": list(r.expected_test_ids) if r.expected_test_ids else None,
    }


def _proposal_to_dict(p: PatchProposal) -> dict[str, Any]:
    return {
        "case_id": p.case_id,
        "unified_diff": p.unified_diff,
        "diff_hash": p.diff_hash,
        "model_id": p.model_id,
        "prompt_tokens": p.prompt_tokens,
        "completion_tokens": p.completion_tokens,
    }


def _usage_to_dict(u: ModelUsage) -> dict[str, Any]:
    return {
        "model_id": u.model_id,
        "prompt_tokens": u.prompt_tokens,
        "completion_tokens": u.completion_tokens,
        "cached_tokens": u.cached_tokens,
        "reasoning_tokens": u.reasoning_tokens,
        "called_at": u.called_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


@dataclass
class AttemptFeedback:
    """Structured feedback from a failed attempt, injected into the next prompt."""

    attempt_index: int
    failure_stage: str
    error_type: str
    error_detail: str
    failing_stdout_snippet: str = ""
    failing_stderr_snippet: str = ""
    failure_category: FailureCategory | None = None
    remediation_directive: str = ""

    def to_prompt_block(self) -> str:
        return (
            f"\n## PREVIOUS ATTEMPT #{self.attempt_index} FEEDBACK\n"
            f"Failure stage: {sanitize_diagnostic(self.failure_stage, 200)}\n"
            f"Error type: {sanitize_diagnostic(self.error_type, 200)}\n"
            f"Detail:\n{sanitize_diagnostic(self.error_detail)}\n"
            + (
                f"Failure category: {self.failure_category.value}\n"
                f"Corrective directive: {sanitize_diagnostic(self.remediation_directive, 1000)}\n"
                if self.failure_category is not None
                else ""
            )
            + (
                "stdout (last 2000 chars):\n```\n"
                f"{sanitize_diagnostic(self.failing_stdout_snippet[-2000:])}\n```\n"
                if self.failing_stdout_snippet
                else ""
            )
            + (
                "stderr (last 2000 chars):\n```\n"
                f"{sanitize_diagnostic(self.failing_stderr_snippet[-2000:])}\n```\n"
                if self.failing_stderr_snippet
                else ""
            )
        )


@dataclass
class RepairStateMachine:
    """Drives a bounded repair run against a single :class:`CaseSpec`.

    Parameters
    ----------
    spec:
        The bug case to repair.
    llm_client:
        Any object satisfying the :class:`LLMClient` Protocol (used to
        generate patch proposals).
    container_runner:
        Configured :class:`HardenedContainerRunner`. If ``None``, a default
        runner is constructed from ``container_config``.
    container_config:
        Resource/security config to use when constructing a default runner.
    pricing_registry:
        For cost accounting on each LLM call; if ``None`` costs will be
        recorded as ``None`` (unknown model).
    max_attempts:
        Hard cap on patch proposals per run (default 5).
    db_path:
        Path to the SQLite checkpoint file (default ``.agentsentinel.db`` in
        CWD). Pass ``:memory:`` for an ephemeral in-memory store (tests only).
    """

    spec: CaseSpec
    llm_client: LLMClient
    container_runner: HardenedContainerRunner | None = None
    container_config: ContainerConfig = field(default_factory=ContainerConfig)
    pricing_registry: PricingRegistry = field(default_factory=PricingRegistry)
    max_attempts: int = 5
    db_path: Path = field(default_factory=lambda: Path(".agentsentinel.db"))
    image_digest: str = "sha256:unspecified"
    auto_approve_on_fix: bool = False
    source_workspace_override: Path | None = None
    enforce_overfit_guard: bool = True
    enable_ddmin_minimization: bool = field(default=False, kw_only=True)
    enable_mutation_probe: bool = field(default=False, kw_only=True)
    max_mutants: int = field(default=3, kw_only=True)

    def __post_init__(self) -> None:
        if self.container_runner is None:
            self.container_runner = HardenedContainerRunner(self.container_config)
        if self.image_digest == "sha256:unspecified":
            self.image_digest = resolve_image_digest(self.container_config.image)
        self._store = CheckpointStore(self.db_path)
        self._ws_mgr = WorkspaceManager()
        self._pending_patched_ws: Path | None = None
        self._pending_patch: PatchProposal | None = None
        self._pending_attempt_index: int | None = None
        self._baseline_ast_hash: str | None = None
        self._source_workspace: Path | None = self.source_workspace_override
        self._feedback_by_run: dict[str, AttemptFeedback] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_run(self) -> str:
        """Create a new run in INIT state and return its run_id."""
        spec_json = {
            "case_id": self.spec.case_id,
            "repo_url": self.spec.repo_url,
            "base_commit": self.spec.base_commit,
            "test_command": self.spec.test_command,
            "allowed_edit_paths": list(self.spec.allowed_edit_paths),
            "failing_test_ids": list(self.spec.failing_test_ids),
            "created_at": self.spec.created_at.isoformat(),
            "metadata": [[k, v] for k, v in self.spec.metadata],
        }
        return self._store.create_run(
            self.spec.case_id, self.max_attempts, spec_json=spec_json
        )

    def resume_run(self, run_id: str) -> RunRecord:
        """Load an existing run from SQLite to continue it after a crash."""
        rec = self._store.get_run(run_id)
        if rec is None:
            raise KeyError(f"No run found with id {run_id!r}")
        return rec

    def run_to_terminal(self, run_id: str) -> RunRecord:
        """Drive a run from its current state through to a terminal state.

        Returns the final :class:`RunRecord`. If the run ends in
        AWAITING_HUMAN_APPROVAL, ``approve_run`` / ``reject_run`` must be
        called explicitly.
        """
        while True:
            rec = self._store.get_run(run_id)
            if rec is None:
                raise KeyError(f"run_id {run_id!r} not found")
            if rec.state in (
                RunState.APPROVED,
                RunState.REJECTED,
                RunState.TERMINATED_FAILED,
            ):
                return rec
            if rec.state == RunState.AWAITING_HUMAN_APPROVAL:
                return rec
            self._step(run_id, rec)

    def approve_run(
        self,
        run_id: str,
        approver_id: str,
        expected_diff_hash: str,
        expected_image_digest: str,
        expected_post_patch_result_hash: str,
    ) -> RunRecord:
        """Approve a run in AWAITING_HUMAN_APPROVAL, verifying the approval hash.

        The approval hash MUST equal
        ``sha256(diff_hash + image_digest + post_patch_result_hash)`` as
        returned to the caller after the VERIFYING_IN_SANDBOX pass. Mismatches
        raise :class:`ApprovalIntegrityError`.
        """
        rec = self._store.get_run(run_id)
        if rec is None:
            raise KeyError(f"run_id {run_id!r} not found")
        if rec.state != RunState.AWAITING_HUMAN_APPROVAL:
            raise ApprovalIntegrityError(
                f"Run must be in AWAITING_HUMAN_APPROVAL to approve (state={rec.state.value})"
            )
        expected = _sha256(
            expected_diff_hash,
            expected_image_digest,
            expected_post_patch_result_hash,
        )
        # The approval_record stored when entering AWAITING_HUMAN_APPROVAL
        # contains the same binding — compare to that.
        stored = (rec.approval_record or {}).get("approval_hash")
        if stored != expected:
            raise ApprovalIntegrityError(
                f"Approval hash mismatch: expected {expected[:12]}…, stored {str(stored)[:12]}…"
            )
        self._store.set_approval_record(
            run_id,
            approval_record={
                **(rec.approval_record or {}),
                "approver_id": approver_id,
                "approved_at_utc": __import__("datetime").datetime.now(
                    __import__("datetime").UTC
                ).isoformat(),
            },
        )
        self._store.transition_state(run_id, RunState.APPROVED)
        out = self._store.get_run(run_id)
        assert out is not None
        return out

    def reject_run(self, run_id: str, reason: str = "human_rejected") -> RunRecord:
        self._store.set_termination(
            run_id, RunState.REJECTED, TerminationReason.HUMAN_REJECTED
        )
        # Record the rejection reason in updated_at isn't enough; tack it
        # into approval_record for posterity.
        rec = self._store.get_run(run_id)
        assert rec is not None
        return rec

    def export_evidence_bundle(self, run_id: str) -> EvidenceBundle:
        """Produce an :class:`EvidenceBundle`; only allowed from APPROVED."""
        rec = self._store.get_run(run_id)
        if rec is None:
            raise KeyError(f"run_id {run_id!r} not found")
        if rec.state != RunState.APPROVED:
            raise UnapprovedExportError(rec.state.value)
        # Look up the PASSED_PENDING_APPROVAL attempt to build the bundle
        cur = self._store._conn.execute(
            "SELECT proposal_json, execution_result_json, usage_json, cost_usd "
            "FROM attempts WHERE run_id = ? AND status = ? "
            "ORDER BY attempt_index DESC LIMIT 1",
            (run_id, AttemptStatus.PASSED_PENDING_APPROVAL.value),
        )
        row = cur.fetchone()
        if row is None:
            raise HarnessSetupError("No PASSED_PENDING_APPROVAL attempt found")
        import json as _json

        proposal_d = _json.loads(row[0])
        result_d = _json.loads(row[1])
        _json.loads(row[2]) if row[2] else None
        # Build PatchProposal & ExecutionResult objects.

        patch = PatchProposal(
            case_id=proposal_d["case_id"],
            unified_diff=proposal_d["unified_diff"],
            model_id=proposal_d["model_id"],
            prompt_tokens=proposal_d["prompt_tokens"],
            completion_tokens=proposal_d["completion_tokens"],
        )
        result = ExecutionResult(
            case_id=result_d["case_id"],
            patch_diff_hash=result_d["patch_diff_hash"],
            exit_code=ExitCode(result_d["exit_code"]),
            stdout=result_d["stdout"],
            stderr=result_d["stderr"],
            wall_seconds=result_d["wall_seconds"],
            stdout_truncated=result_d["stdout_truncated"],
            stderr_truncated=result_d["stderr_truncated"],
            expected_test_ids=tuple(result_d["expected_test_ids"])
            if result_d.get("expected_test_ids")
            else None,
        )
        baseline_d = rec.baseline_result_json or {}
        baseline = ExecutionResult(
            case_id=self.spec.case_id,
            patch_diff_hash="baseline",
            exit_code=ExitCode(baseline_d.get("exit_code", int(ExitCode.TESTS_FAILED))),
            stdout=baseline_d.get("stdout", ""),
            stderr=baseline_d.get("stderr", ""),
            wall_seconds=baseline_d.get("wall_seconds", 0.0),
            stdout_truncated=baseline_d.get("stdout_truncated", False),
            stderr_truncated=baseline_d.get("stderr_truncated", False),
            expected_test_ids=self.spec.failing_test_ids,
        )
        total_prompt = 0
        total_completion = 0
        for attempt_row in self._store._conn.execute(
            "SELECT usage_json FROM attempts WHERE run_id = ?", (run_id,)
        ):
            if attempt_row[0]:
                u = _json.loads(attempt_row[0])
                total_prompt += int(u.get("prompt_tokens", 0))
                total_completion += int(u.get("completion_tokens", 0))
        bundle = EvidenceBundle(
            case_id=self.spec.case_id,
            spec=self.spec,
            baseline_result=baseline,
            accepted_patch=patch,
            final_result=result,
            total_prompt_tokens=total_prompt,
            total_completion_tokens=total_completion,
            attempts=rec.attempts_used,
        )
        return bundle

    # ------------------------------------------------------------------
    # State transition per step
    # ------------------------------------------------------------------

    def _step(self, run_id: str, rec: RunRecord) -> None:
        """Drive a single state transition based on ``rec.state``."""
        if rec.state == RunState.INIT:
            self._step_reproduce_baseline(run_id)
        elif rec.state == RunState.REPRODUCING_BASELINE:
            self._step_propose_patch(run_id, rec, feedback=None)
        elif rec.state == RunState.PROPOSING_PATCH:
            self._step_propose_patch(run_id, rec)
        elif rec.state == RunState.VALIDATING_POLICY:
            self._step_apply_patch(run_id, rec)
        elif rec.state == RunState.APPLYING_PATCH:
            self._step_verify_in_sandbox(run_id, rec)
        elif rec.state == RunState.VERIFYING_IN_SANDBOX:
            # Already transitioned inside _step_verify; nothing to do.
            pass
        else:
            # Other states are handled at run_to_terminal terminal checks
            pass

    # ---- baseline ----

    def _step_reproduce_baseline(self, run_id: str) -> None:

        self._store.transition_state(run_id, RunState.REPRODUCING_BASELINE)
        # Provision a fresh baseline workspace copy
        tmp_baseline = tempfile.mkdtemp(prefix="agentsentinel_baseline_")
        baseline_ws = Path(tmp_baseline)
        # The caller is expected to have populated source_workspace externally;
        # we resolve it from CaseSpec's implicit src root. For the state
        # machine, source_workspace is injected via spec — we accept it via
        # _source_workspace (see _get_source_workspace).
        try:
            src = self._get_source_workspace()
            self._get_baseline_ast_hash(src)
            self._ws_mgr.populate_from_directory(src, baseline_ws)
            self._ws_mgr.scrub_git_history(baseline_ws)

            test_cmd = _append_test_args(self.spec.test_command)
            assert self.container_runner is not None
            result = self.container_runner.run_in_container(
                case_id=self.spec.case_id,
                patch_diff_hash="baseline",
                workspace_host_path=baseline_ws,
                command=test_cmd,
            )
            # Reconstruct with expected_test_ids set so .passed enforces tests ran
            result = ExecutionResult(
                case_id=result.case_id,
                patch_diff_hash=result.patch_diff_hash,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                wall_seconds=result.wall_seconds,
                stdout_truncated=result.stdout_truncated,
                stderr_truncated=result.stderr_truncated,
                expected_test_ids=self.spec.failing_test_ids,
            )
            self._store.set_baseline_result(run_id, _result_to_dict(result))

            # Gate: must be TESTS_FAILED
            if result.exit_code == ExitCode.TESTS_FAILED:
                self._store.transition_state(run_id, RunState.PROPOSING_PATCH)
                return

            # Otherwise terminate immediately
            if is_harness_broken(result.exit_code):
                self._store.set_termination(
                    run_id,
                    RunState.TERMINATED_FAILED,
                    TerminationReason.HARNESS_BROKEN,
                )
                raise BaselineNotReproducedError(int(result.exit_code), detail=result.stderr[-500:])
            # Exit code was OK or some other verdict — baseline did not reproduce
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.BASELINE_NOT_REPRODUCED,
            )
            raise BaselineNotReproducedError(int(result.exit_code), detail=result.stderr[-500:])
        finally:
            shutil.rmtree(baseline_ws, ignore_errors=True)

    def _get_source_workspace(self) -> Path:
        """Resolve the baseline source workspace."""
        if self._source_workspace is not None:
            return self._source_workspace
        return getattr(self, "source_workspace", Path.cwd())

    # ---- propose ----

    def _step_propose_patch(
        self,
        run_id: str,
        rec: RunRecord,
        feedback: AttemptFeedback | None = None,
    ) -> None:
        # Provision baseline workspace for prompt building
        pending_feedback = self._feedback_by_run.pop(run_id, None)
        if feedback is None:
            feedback = pending_feedback
        src = self._get_source_workspace()
        pb = PromptBuilder(workspace_root=src)
        # Load baseline result to build prompt
        baseline_dict = rec.baseline_result_json or {}
        baseline_result = ExecutionResult(
            case_id=self.spec.case_id,
            patch_diff_hash="baseline",
            exit_code=ExitCode(
                baseline_dict.get("exit_code", int(ExitCode.TESTS_FAILED))
            ),
            stdout=baseline_dict.get("stdout", ""),
            stderr=baseline_dict.get("stderr", ""),
            wall_seconds=baseline_dict.get("wall_seconds", 0.0),
            stdout_truncated=baseline_dict.get("stdout_truncated", False),
            stderr_truncated=baseline_dict.get("stderr_truncated", False),
            expected_test_ids=self.spec.failing_test_ids,
        )
        # Fault localization hints (best-effort; empty on parse failure)
        localization_slices = None
        try:
            _frames = extract_traceback_frames(
                baseline_result.stdout,
                baseline_result.stderr,
                allowed_edit_paths=self.spec.allowed_edit_paths,
            )
            if _frames:
                localization_slices = localize_faults(
                    src, _frames, self.spec.allowed_edit_paths
                )
        except Exception:
            localization_slices = None
        prompt = pb.build_repair_prompt(
            self.spec, baseline_result, localization_slices=localization_slices
        )
        if feedback is not None:
            prompt += "\n" + feedback.to_prompt_block()

        # Count the attempt (invariant: every LLM call counts)
        attempt_index = self._store.increment_attempts(run_id)
        self._store.record_attempt_start(run_id, attempt_index)

        try:
            self._store.transition_state(run_id, RunState.PROPOSING_PATCH)
            patch, usage = self.llm_client.generate_patch(
                case_id=self.spec.case_id,
                prompt=prompt,
                model_id=self._select_model_for_attempt(attempt_index),
            )
        except LLMRateLimitError as e:
            # 429 is transport-level: NOT counted as a repair attempt (but we
            # already incremented; undo the increment by terminating).
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.LLM_ERROR,
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.INFRASTRUCTURE_FAILURE,
            )
            raise InfrastructureFailureError(str(e)) from e
        except (LLMTimeoutError, LLMAuthenticationError) as e:
            # Auth / hard timeouts are treated as infrastructure failures
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.LLM_ERROR,
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.INFRASTRUCTURE_FAILURE,
            )
            raise InfrastructureFailureError(str(e)) from e
        except LLMGenerationError as e:
            # Malformed response — counts as an attempt
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.LLM_ERROR,
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            cost_est = self._cost_for_usage(e.usage) if e.usage is not None else None
            if e.usage is not None:
                self._store.record_attempt_generated(
                    run_id,
                    attempt_index,
                    proposal_json={"error": "invalid", "unified_diff": ""},
                    usage_json=_usage_to_dict(e.usage),
                    cost_usd=cost_est.total_cost_usd if cost_est is not None else None,
                    diff_hash="",
                )
            self._maybe_advance_after_failure(
                run_id,
                attempt_index,
                stage="PROPOSING_PATCH",
                error_type="LLMGenerationError",
                error_detail=str(e),
            )
            return
        except LLMError as e:
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.LLM_ERROR,
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            self._maybe_advance_after_failure(
                run_id,
                attempt_index,
                stage="PROPOSING_PATCH",
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            return

        # Good proposal — persist
        cost = self._cost_for_usage(usage)
        self._store.record_attempt_generated(
            run_id,
            attempt_index,
            proposal_json=_proposal_to_dict(patch),
            usage_json=_usage_to_dict(usage),
            cost_usd=cost.total_cost_usd,
            diff_hash=patch.diff_hash,
        )
        # Tier 1 dedup BEFORE parsing/validation that would consume more work
        seen_diff, _ = self._store.get_seen_hashes(run_id)
        try:
            t1 = check_tier1_duplicate(patch.unified_diff, seen_diff)
        except DuplicatePatchError as e:
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.DUPLICATE,
                error_type="DuplicatePatchError",
                error_detail=str(e),
            )
            self._store.add_seen_diff_hash(run_id, tier1_fingerprint(patch.unified_diff).hex)
            self._store.set_termination(
                run_id, RunState.TERMINATED_FAILED, TerminationReason.DUPLICATE_PATCH
            )
            raise

        # Move to policy validation
        self._store.add_seen_diff_hash(run_id, t1.hex)
        self._store.transition_state(run_id, RunState.VALIDATING_POLICY)
        self._step_apply_patch(run_id, rec=None, current_attempt=attempt_index, patch=patch)

    def _select_model_for_attempt(self, attempt_index: int) -> str:
        """Default model selection — can be overridden."""
        return getattr(self, "model_id", "gpt-4o-mini")

    def _cost_for_usage(self, usage: ModelUsage) -> CostEstimate:
        return self.pricing_registry.estimate_cost(usage)

    # ---- validate & apply ----

    def _step_apply_patch(
        self,
        run_id: str,
        rec: RunRecord | None,
        current_attempt: int | None = None,
        patch: PatchProposal | None = None,
    ) -> None:
        # If called from _step directly (state transition resume), load the
        # most recent GENERATED attempt.
        if current_attempt is None or patch is None:
            current_attempt, patch = self._load_latest_generated_patch(run_id)
            if patch is None:
                # Nothing to apply — shouldn't happen, but bail out safely
                self._store.set_termination(
                    run_id,
                    RunState.TERMINATED_FAILED,
                    TerminationReason.HARNESS_BROKEN,
                )
                raise HarnessSetupError("No generated patch found to apply")

        assert current_attempt is not None and patch is not None
        self._store.transition_state(run_id, RunState.APPLYING_PATCH)

        # Validate via policy layer
        src = self._get_source_workspace()
        try:
            validator = PatchPolicyValidator(allowed_edit_paths=self.spec.allowed_edit_paths)
            validator.validate_diff(patch.unified_diff, workspace_root=src)
        except AgentSentinelError as e:
            self._store.record_attempt_outcome(
                run_id,
                current_attempt,
                AttemptStatus.POLICY_REJECTED,
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            self._maybe_advance_after_failure(
                run_id,
                current_attempt,
                stage="VALIDATING_POLICY",
                error_type=type(e).__name__,
                error_detail=str(e),
                error=e,
            )
            return

        # Capture baseline AST hash on pristine source workspace before application
        baseline_ast_hash = self._get_baseline_ast_hash(src)

        # Provision patched workspace + apply via git apply (hard-fail)
        patched_dir = tempfile.mkdtemp(prefix="agentsentinel_apply_")
        patched_ws = Path(patched_dir)
        try:
            self._ws_mgr.populate_from_directory(src, patched_ws)
            self._ws_mgr.scrub_git_history(patched_ws)
            patched_ws = apply_validated_patch(
                patch=patch,
                source_workspace=src,
                allowed_edit_paths=self.spec.allowed_edit_paths,
                dest_workspace=patched_ws,
            )
        except PatchApplicationError as e:
            self._store.record_attempt_outcome(
                run_id,
                current_attempt,
                AttemptStatus.APPLY_FAILED,
                error_type="PatchApplicationError",
                error_detail=f"{e}\n{e.stderr if hasattr(e, 'stderr') else ''}",
            )
            shutil.rmtree(patched_ws, ignore_errors=True)
            self._maybe_advance_after_failure(
                run_id,
                current_attempt,
                stage="APPLYING_PATCH",
                error_type="PatchApplicationError",
                error_detail=str(e),
                error=e,
            )
            return
        except HarnessSetupError as e:
            # Infrastructure-level setup problem (missing git, disk)
            self._store.record_attempt_outcome(
                run_id,
                current_attempt,
                AttemptStatus.APPLY_FAILED,
                error_type=type(e).__name__,
                error_detail=str(e),
            )
            shutil.rmtree(patched_ws, ignore_errors=True)
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.INFRASTRUCTURE_FAILURE,
            )
            raise InfrastructureFailureError(str(e)) from e

        # Tier-2 AST dedup BEFORE running Docker
        seen_diff, seen_ast = self._store.get_seen_hashes(run_id)
        try:
            t2 = check_tier2_duplicate_or_noop(
                patched_ws,
                self.spec.allowed_edit_paths,
                baseline_ast_hash,
                seen_ast,
            )
        except DuplicatePatchError as e:
            self._store.record_attempt_outcome(
                run_id,
                current_attempt,
                AttemptStatus.DUPLICATE,
                error_type="DuplicatePatchError",
                error_detail=str(e),
            )
            fp_err = tier2_fingerprint(patched_ws, self.spec.allowed_edit_paths)
            if fp_err is not None:
                self._store.add_seen_ast_hash(run_id, fp_err.hex)
            shutil.rmtree(patched_ws, ignore_errors=True)
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.DUPLICATE_PATCH,
            )
            raise

        if t2 is not None:
            self._store.add_seen_ast_hash(run_id, t2.hex)

        # M8: Anti-overfitting AST guard — after Tier-2, before container
        if self.enforce_overfit_guard:
            try:
                _pre: dict[str, str] = {}
                _post: dict[str, str] = {}
                for _rel in self.spec.allowed_edit_paths:
                    try:
                        _pre[_rel] = (src / _rel).read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        _pre[_rel] = ""
                    try:
                        _post[_rel] = patched_ws.joinpath(_rel).read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except OSError:
                        _post[_rel] = ""
                verify_not_overfitted(src, _pre, _post, raw_diff=patch.unified_diff)
            except PatchPolicyError as _e:
                self._store.record_attempt_outcome(
                    run_id,
                    current_attempt,
                    AttemptStatus.POLICY_REJECTED,
                    error_type=type(_e).__name__,
                    error_detail=str(_e),
                )
                shutil.rmtree(patched_ws, ignore_errors=True)
                self._maybe_advance_after_failure(
                    run_id,
                    current_attempt,
                    stage="VALIDATING_POLICY",
                    error_type=type(_e).__name__,
                    error_detail=str(_e),
                    error=_e,
                )
                return

        # Move to sandbox verification (hand patched_ws to next step via attr)
        self._pending_patched_ws = patched_ws
        self._pending_patch = patch
        self._pending_attempt_index = current_attempt
        self._store.transition_state(run_id, RunState.VERIFYING_IN_SANDBOX)
        self._step_verify_in_sandbox(run_id, None)

    def _get_baseline_ast_hash(self, src: Path) -> str | None:
        cached: str | None = getattr(self, "_baseline_ast_hash", None)
        if cached is None:
            fp = tier2_fingerprint(src, self.spec.allowed_edit_paths)
            cached = fp.hex if fp is not None else None
            self._baseline_ast_hash = cached
        return cached

    # ---- verify in sandbox ----

    def _step_verify_in_sandbox(
        self, run_id: str, rec: RunRecord | None
    ) -> None:
        patched_ws = getattr(self, "_pending_patched_ws", None)
        patch = getattr(self, "_pending_patch", None)
        attempt_index = getattr(self, "_pending_attempt_index", None)
        if patched_ws is None or patch is None or attempt_index is None:
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.HARNESS_BROKEN,
            )
            raise HarnessSetupError("verify_in_sandbox called without a pending patched workspace")

        assert self.container_runner is not None
        test_cmd = _append_test_args(self.spec.test_command)

        # Capture Docker infrastructure failures (daemon down) distinctly
        try:
            result = self.container_runner.run_in_container(
                case_id=self.spec.case_id,
                patch_diff_hash=patch.diff_hash,
                workspace_host_path=patched_ws,
                command=test_cmd,
            )
        except (FileNotFoundError, HarnessSetupError) as e:
            # Docker daemon / setup problem
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.TEST_FAILED,
                error_type="DockerInfrastructure",
                error_detail=str(e),
            )
            shutil.rmtree(patched_ws, ignore_errors=True)
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.INFRASTRUCTURE_FAILURE,
            )
            raise InfrastructureFailureError(str(e)) from e
        except HarnessTimeoutError as e:
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.TEST_FAILED,
                error_type="HarnessTimeoutError",
                error_detail=str(e),
            )
            shutil.rmtree(patched_ws, ignore_errors=True)
            self._maybe_advance_after_failure(
                run_id,
                attempt_index,
                stage="VERIFYING_IN_SANDBOX",
                error_type="HarnessTimeoutError",
                error_detail=str(e),
                error=e,
            )
            return

        # Reconstruct with expected_test_ids
        result = ExecutionResult(
            case_id=result.case_id,
            patch_diff_hash=result.patch_diff_hash,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            wall_seconds=result.wall_seconds,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            expected_test_ids=self.spec.failing_test_ids,
        )

        shutil.rmtree(patched_ws, ignore_errors=True)
        self._pending_patched_ws = None

        if result.passed:
            # Success! Enter approval gate
            image_digest = self.image_digest
            post_patch_hash = _sha256(result.stdout, result.stderr, str(result.exit_code))
            approval_hash = _sha256(
                patch.diff_hash,
                image_digest,
                post_patch_hash,
            )
            approval_record = {
                "diff_hash": patch.diff_hash,
                "image_digest": image_digest,
                "post_patch_result_hash": post_patch_hash,
                "approval_hash": approval_hash,
            }
            # Record the passing attempt
            self._store.record_attempt_outcome(
                run_id,
                attempt_index,
                AttemptStatus.PASSED_PENDING_APPROVAL,
                execution_result_json=_result_to_dict(result),
            )
            self._store.transition_state(run_id, RunState.AWAITING_HUMAN_APPROVAL)
            # Stash approval binding for sign-off
            rec = self._store.get_run(run_id)
            assert rec is not None
            # Reuse set_approval_record's json field but WITHOUT marking approved
            now = __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()
            with self._store._conn:
                self._store._conn.execute(
                    "UPDATE runs SET approval_record_json = ?, updated_at_utc = ? WHERE run_id = ?",
                    (
                        __import__("json").dumps(approval_record),
                        now,
                        run_id,
                    ),
                )
            self._pending_approval_binding = approval_record
            # Auto-approve hook (benchmark mode): bypass human review.
            if self.auto_approve_on_fix:
                self.approve_run(
                    run_id=run_id,
                    approver_id="benchmark-auto-approve",
                    expected_diff_hash=patch.diff_hash,
                    expected_image_digest=image_digest,
                    expected_post_patch_result_hash=post_patch_hash,
                )
            return

        # Test failure (or harness broken)
        self._store.record_attempt_outcome(
            run_id,
            attempt_index,
            AttemptStatus.TEST_FAILED,
            error_type="TestFailure",
            error_detail=f"exit_code={int(result.exit_code)}",
            execution_result_json=_result_to_dict(result),
        )
        if is_harness_broken(result.exit_code):
            # Treat harness-broken exit codes as infrastructure failure only
            # if they happen on the first attempt; otherwise just retry.
            self._maybe_advance_after_failure(
                run_id,
                attempt_index,
                stage="VERIFYING_IN_SANDBOX",
                error_type=f"HarnessBroken(exit_code={int(result.exit_code)})",
                error_detail=result.stderr[-1000:],
                stdout=result.stdout,
                stderr=result.stderr,
                execution_result=result,
            )
            return

        self._maybe_advance_after_failure(
            run_id,
            attempt_index,
            stage="VERIFYING_IN_SANDBOX",
            error_type=f"TestFailed(exit_code={int(result.exit_code)})",
            error_detail="Failing tests: see stdout/stderr",
            stdout=result.stdout,
            stderr=result.stderr,
            execution_result=result,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_latest_generated_patch(
        self, run_id: str
    ) -> tuple[int, PatchProposal | None]:
        import json as _json

        cur = self._store._conn.execute(
            "SELECT attempt_index, proposal_json FROM attempts "
            "WHERE run_id = ? AND status = ? ORDER BY attempt_index DESC LIMIT 1",
            (run_id, AttemptStatus.GENERATED.value),
        )
        row = cur.fetchone()
        if row is None:
            return 0, None
        idx, pjson = row
        d = _json.loads(pjson)
        return int(idx), PatchProposal(
            case_id=d["case_id"],
            unified_diff=d["unified_diff"],
            model_id=d["model_id"],
            prompt_tokens=int(d["prompt_tokens"]),
            completion_tokens=int(d["completion_tokens"]),
        )

    def _maybe_advance_after_failure(
        self,
        run_id: str,
        attempt_index: int,
        stage: str,
        error_type: str,
        error_detail: str,
        stdout: str = "",
        stderr: str = "",
        *,
        error: Exception | None = None,
        execution_result: ExecutionResult | None = None,
    ) -> None:
        """If more attempts remain, transition back to PROPOSING_PATCH with
        feedback; otherwise terminate."""
        rec = self._store.get_run(run_id)
        assert rec is not None
        if rec.attempts_used >= rec.max_attempts:
            self._feedback_by_run.pop(run_id, None)
            self._store.set_termination(
                run_id,
                RunState.TERMINATED_FAILED,
                TerminationReason.MAX_ATTEMPTS_EXHAUSTED,
            )
            return
        category: FailureCategory | None = None
        directive = ""
        if error is not None or execution_result is not None:
            category, directive = classify_attempt_failure(error, execution_result)
        if isinstance(error, OverfitPolicyError):
            # Keep the original diagnostic in the audit record, not test-derived
            # literals in the next prompt. The directive is fixed trusted text.
            error_detail = directive
        # Build feedback for next attempt and loop back by transitioning state
        feedback = AttemptFeedback(
            attempt_index=attempt_index,
            failure_stage=stage,
            error_type=error_type,
            error_detail=error_detail,
            failing_stdout_snippet=stdout,
            failing_stderr_snippet=stderr,
            failure_category=category,
            remediation_directive=directive,
        )
        self._feedback_by_run[run_id] = feedback
        self._store.transition_state(run_id, RunState.PROPOSING_PATCH)


__all__ = ["AttemptFeedback", "RepairStateMachine"]

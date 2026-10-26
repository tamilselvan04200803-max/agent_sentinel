"""Typed failure diagnostics and safe retry prompts for M12."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from agentsentinel.domain.exceptions import (
    HarnessTimeoutError,
    MalformedDiffError,
    OverfitPolicyError,
    PatchPolicyError,
    TestFileModificationError,
)
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.checkpoint import RunState
from agentsentinel.orchestrator.state_machine import AttemptFeedback, RepairStateMachine
from agentsentinel.policy.applier import PatchApplicationError

if TYPE_CHECKING:
    from pathlib import Path


def result(stdout: str = "", stderr: str = "", code: ExitCode = ExitCode.TESTS_FAILED):
    return ExecutionResult("case", "hash", code, stdout, stderr, 0.01)


def classify(error: Exception | None = None, execution: ExecutionResult | None = None):
    from agentsentinel.orchestrator.failure_taxonomy import classify_attempt_failure

    return classify_attempt_failure(error, execution)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (PatchApplicationError("bad context"), "PATCH_FORMAT_OR_HUNK_MISMATCH"),
        (MalformedDiffError("bad header"), "PATCH_FORMAT_OR_HUNK_MISMATCH"),
        (OverfitPolicyError(leaked_literal="SECRET_TEST_VALUE"), "OVERFIT_OR_HARDCODED_LITERAL"),
        (PatchPolicyError("forbidden path"), "POLICY_PATH_OR_TEST_TAMPERING"),
        (TestFileModificationError("tests/test_x.py"), "POLICY_PATH_OR_TEST_TAMPERING"),
        (HarnessTimeoutError(1, "pytest"), "EXECUTION_TIMEOUT_OR_INFINITE_LOOP"),
        (RuntimeError("unexpected"), "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"),
    ],
)
def test_authoritative_exception_classification(error: Exception, expected: str) -> None:
    category, directive = classify(error, result("E AssertionError: spoofed"))
    assert category.value == expected
    assert directive and "SECRET_TEST_VALUE" not in directive


@pytest.mark.parametrize("reason", ["api_contract", "complexity_bloat", "debug_residue", "exception_swallowing"])
def test_quality_reason_codes_do_not_depend_on_message_text(reason: str) -> None:
    error = OverfitPolicyError(message="unrelated wording", reason_code=reason)
    assert classify(error)[0].value == "API_CONTRACT_OR_BLOAT_VIOLATION"


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [
        ("E   AssertionError: wrong value", "", "TEST_ASSERTION_VALUE_MISMATCH"),
        ("FAILED tests/test_x.py::test_f - AssertionError: wrong", "", "TEST_ASSERTION_VALUE_MISMATCH"),
        ("E   TypeError: bad operand\nFAILED test_x - AssertionError: wrapper", "", "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"),
        ("", "ModuleNotFoundError: no module named dependency", "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"),
        ("E   KeyError: x", "", "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"),
        ("E   TimeoutError: exceeded budget", "", "EXECUTION_TIMEOUT_OR_INFINITE_LOOP"),
        ("print('AssertionError: spoofed')", "", "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"),
        ("unstructured failure", "", "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"),
    ],
)
def test_execution_evidence_classification(stdout: str, stderr: str, expected: str) -> None:
    assert classify(execution=result(stdout, stderr))[0].value == expected


def test_missing_or_successful_evidence_is_rejected() -> None:
    with pytest.raises(ValueError):
        classify()
    with pytest.raises(ValueError):
        classify(execution=result(code=ExitCode.OK))


def test_all_feedback_fields_are_bounded_and_sanitized() -> None:
    poisoned = "```\u202e\u200b\x00INJECT" + "x" * 5000
    feedback = AttemptFeedback(1, poisoned, poisoned, poisoned, poisoned, poisoned)
    block = feedback.to_prompt_block()
    assert "\u202e" not in block and "\u200b" not in block and "\x00" not in block
    assert block.count("```") == 4  # Only the two trusted output fences remain.
    assert "x" * 2001 not in block
    assert len(block) < 12000


def test_structured_feedback_is_rendered_without_breaking_legacy_constructor() -> None:
    from agentsentinel.orchestrator.failure_taxonomy import FailureCategory

    feedback = AttemptFeedback(
        1, "VALIDATING_POLICY", "OverfitPolicyError", "blocked",
        failure_category=FailureCategory.API_CONTRACT_OR_BLOAT_VIOLATION,
        remediation_directive="Preserve the existing call signature.",
    )
    block = feedback.to_prompt_block()
    assert "API_CONTRACT_OR_BLOAT_VIOLATION" in block
    assert "Preserve the existing call signature." in block
    assert "blocked" in AttemptFeedback(1, "stage", "error", "blocked").to_prompt_block()


def test_guard_reason_codes_are_assigned_at_the_source() -> None:
    from agentsentinel.verification.contract_guard import verify_public_api_compatibility
    from agentsentinel.verification.patch_minimizer import check_ast_bloat_and_debug_residue

    with pytest.raises(OverfitPolicyError) as caught:
        verify_public_api_compatibility("a.py", "def public(x): return x", "")
    assert classify(caught.value)[0].value == "API_CONTRACT_OR_BLOAT_VIOLATION"
    with pytest.raises(OverfitPolicyError) as caught:
        check_ast_bloat_and_debug_residue("a.py", "", "breakpoint()")
    assert caught.value.reason_code == "debug_residue"


def test_policy_retry_has_structured_feedback_and_skips_rejected_execution(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "normalizer.py").write_text(
        "def normalize(s):\n    return s.lower()\n", encoding="utf-8", newline="\n",
    )
    spec = CaseSpec(
        case_id="case", repo_url="local", base_commit="0" * 40,
        test_command="pytest", allowed_edit_paths=["normalizer.py"],
        failing_test_ids=["tests/test_normalizer.py::test_fix"],
    )
    diffs = [
        "--- a/normalizer.py\n+++ b/normalizer.py\n@@ -1,2 +1,3 @@\n def normalize(s):\n+    breakpoint()\n     return s.lower()\n",
        "--- a/normalizer.py\n+++ b/normalizer.py\n@@ -1,2 +1,2 @@\n def normalize(s):\n-    return s.lower()\n+    return s.strip().lower()\n",
    ]
    prompts: list[str] = []

    class LLM:
        def generate_patch(self, **kwargs: Any):
            prompts.append(kwargs["prompt"])
            return PatchProposal(
                "case", diffs[len(prompts) - 1], "test", 1, 1,
            ), ModelUsage(model_id="test", prompt_tokens=1, completion_tokens=1)

    runner = MagicMock()
    runner.run_in_container.side_effect = [
        result("FAILED tests/test_normalizer.py::test_fix - AssertionError: wrong"),
        result("tests/test_normalizer.py::test_fix PASSED", code=ExitCode.OK),
    ]
    machine = RepairStateMachine(
        spec, LLM(), runner, max_attempts=2, db_path=tmp_path / "run.db",
        source_workspace_override=workspace,
    )
    try:
        record = machine.run_to_terminal(machine.start_run())
        assert record.state == RunState.AWAITING_HUMAN_APPROVAL
        assert record.attempts_used == 2
        assert len(prompts) == 2
        assert "API_CONTRACT_OR_BLOAT_VIOLATION" in prompts[1]
        attempts = machine._store.get_attempts(record.run_id)
        assert [a.status.value for a in attempts] == ["POLICY_REJECTED", "PASSED_PENDING_APPROVAL"]
        assert runner.run_in_container.call_count == 2  # Baseline and accepted patch only.
    finally:
        machine._store.close()

"""Shared pytest configuration and fixtures for AgentSentinel test suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal


VALID_SHA = "a" * 40  # 40-char hex SHA


@pytest.fixture()
def valid_case_spec() -> CaseSpec:
    """Return a valid, minimal CaseSpec for reuse across tests."""
    return CaseSpec(
        case_id="test-case-001",
        repo_url="https://github.com/example/repo",
        base_commit=VALID_SHA,
        test_command="pytest tests/",
        allowed_edit_paths=("src/module.py",),
        failing_test_ids=("tests/test_module.py::test_broken",),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        metadata=(("language", "python"),),
    )


@pytest.fixture()
def valid_patch(valid_case_spec: CaseSpec) -> PatchProposal:
    """Return a valid PatchProposal linked to valid_case_spec."""
    return PatchProposal(
        case_id=valid_case_spec.case_id,
        unified_diff="--- a/src/module.py\n+++ b/src/module.py\n@@ -1 +1 @@\n-bug\n+fix\n",
        model_id="gemini-2.5-pro",
        prompt_tokens=100,
        completion_tokens=50,
        proposed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


@pytest.fixture()
def baseline_result(valid_case_spec: CaseSpec) -> ExecutionResult:
    """Return a baseline ExecutionResult (tests failing) for valid_case_spec."""
    return ExecutionResult(
        case_id=valid_case_spec.case_id,
        patch_diff_hash="baseline",
        exit_code=ExitCode.TESTS_FAILED,
        stdout="FAILED tests/test_module.py::test_broken",
        stderr="",
        wall_seconds=5.3,
    )


@pytest.fixture()
def passing_result(valid_case_spec: CaseSpec, valid_patch: PatchProposal) -> ExecutionResult:
    """Return an ExecutionResult showing all tests passing."""
    return ExecutionResult(
        case_id=valid_case_spec.case_id,
        patch_diff_hash=valid_patch.diff_hash,
        exit_code=ExitCode.OK,
        stdout="1 passed",
        stderr="",
        wall_seconds=4.1,
    )

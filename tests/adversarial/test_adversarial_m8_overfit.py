from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.checkpoint import CheckpointStore, RunState
from agentsentinel.orchestrator.state_machine import RepairStateMachine
from agentsentinel.verification.overfit_guard import (
    check_forbidden_reflection,
    check_patch_hygiene,
    verify_not_overfitted,
)


def _ws() -> Path:
    return Path(tempfile.gettempdir())


def test_adversarial_eq_hardcoded_literal() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"pkg/mod.py": "def f(s):\n    return s.lower()\n"}
    post = {"pkg/mod.py": 'def f(s):\n    if s == "  HELLO  ":\n        return "hello"\n    return s.lower()\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert ei.value.leaked_literal == "  HELLO  "


def test_adversarial_obfuscated_concat_literal() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"pkg/mod.py": "def f(s):\n    return s.lower()\n"}
    post = {"pkg/mod.py": 'def f(s):\n    if s == "  HEL" + "LO  ":\n        return "hello"\n    return s.lower()\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert ei.value.leaked_literal == "  HELLO  "


def test_adversarial_in_tuple_literal() -> None:
    lits: frozenset[str | int | float] = frozenset({"  Alice  ", "\tBOB\n"})
    pre = {"pkg/mod.py": "def f(s):\n    return s.strip()\n"}
    post = {"pkg/mod.py": 'def f(s):\n    if s in ("  Alice  ", "\tBOB\\n"):\n        return s.strip()\n    return s\n'}
    with pytest.raises(OverfitPolicyError):
        verify_not_overfitted(_ws(), pre, post, lits)


def test_adversarial_stack_inspection_cheating() -> None:
    pre = {"pkg/mod.py": "def f(s):\n    return s\n"}
    post = {"pkg/mod.py": "import inspect\ndef f(s):\n    frame = inspect.stack()[1]\n    return 'hacked'\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_forbidden_reflection(pre, post)
    assert "Forbidden" in str(ei.value)


def test_adversarial_unicode_bidi_poisoning() -> None:
    diff = "--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@ -1,2 +1,3 @@\n def f(s):\n+    # \u202e evil comment\n     return s\n"
    post = {"pkg/mod.py": "def f(s):\n    # \u202e evil comment\n    return s\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, post)
    assert "BiDi" in str(ei.value)


def test_adversarial_zero_width_space_poisoning() -> None:
    diff = "--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@ -1,2 +1,3 @@\n def f(s):\n+    hidden = '\u200b'\n     return s\n"
    post = {"pkg/mod.py": "def f(s):\n    hidden = '\u200b'\n    return s\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, post)
    assert "zero-width" in str(ei.value)


def test_adversarial_cyrillic_homoglyph_identifier() -> None:
    # Use Cyrillic 'с' (\u0441) in 'strip'
    pre = {"pkg/mod.py": "def normalize(s):\n    return s\n"}
    post = {"pkg/mod.py": "def normalize(s):\n    \u0441_val = s.strip()\n    return \u0441_val\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene("", post, pre)
    assert "non-ASCII identifier" in str(ei.value)


def test_adversarial_mixed_indentation_poisoning() -> None:
    diff = "--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@ -1,2 +1,3 @@\n def f(s):\n+ \t  return s\n"
    post = {"pkg/mod.py": "def f(s):\n \t  return s\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, post)
    assert "Mixed tab-and-space" in str(ei.value)


def test_adversarial_generic_transform_passes() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  ", "  Alice  ", "\tBOB\n"})
    pre = {"pkg/mod.py": "def f(s):\n    return s\n"}
    post = {"pkg/mod.py": "def f(s):\n    return s.strip().lower()\n"}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_adversarial_empty_check_passes() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"pkg/mod.py": "def f(s):\n    return s\n"}
    post = {"pkg/mod.py": 'def f(s):\n    if not s:\n        return ""\n    return s.strip()\n'}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_adversarial_in_with_non_test_literal_passes() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"pkg/mod.py": "def f(s):\n    return s\n"}
    post = {"pkg/mod.py": 'def f(s):\n    if s in ("other", "values"):\n        return 1\n    return s\n'}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_adversarial_state_machine_overfit_recovery_e2e(tmp_path: Path) -> None:
    """End-to-end state machine recovery:

    Attempt 1 proposes an overfitted patch that matches test literals.
    OverfitGuard rejects it without invoking Docker, recording POLICY_REJECTED.
    Attempt 2 proposes a generic fix (s.strip().lower()).
    It passes the guard, runs container tests, and reaches AWAITING_HUMAN_APPROVAL.
    """
    ws = tmp_path / "repo"
    ws.mkdir(parents=True)
    tests_dir = ws / "tests"
    tests_dir.mkdir(parents=True)

    (ws / "normalizer.py").write_text(
        "def normalize(s):\n    return s.lower()\n", encoding="utf-8"
    )
    (tests_dir / "test_normalizer.py").write_text(
        'def test_whitespace():\n    assert normalize("  HELLO  ") == "hello"\n',
        encoding="utf-8",
    )

    case = CaseSpec(
        case_id="case_m8_adversarial",
        repo_url="local",
        base_commit="0" * 40,
        test_command="pytest",
        allowed_edit_paths=["normalizer.py"],
        failing_test_ids=["tests/test_normalizer.py::test_whitespace"],
    )

    overfit_diff = (
        "--- a/normalizer.py\n"
        "+++ b/normalizer.py\n"
        "@@ -1,2 +1,4 @@\n"
        " def normalize(s):\n"
        "+    if s == \"  HELLO  \":\n"
        "+        return \"hello\"\n"
        "     return s.lower()\n"
    )
    good_diff = (
        "--- a/normalizer.py\n"
        "+++ b/normalizer.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def normalize(s):\n"
        "-    return s.lower()\n"
        "+    return s.strip().lower()\n"
    )

    patch_overfit = PatchProposal(
        case_id=case.case_id,
        unified_diff=overfit_diff,
        model_id="stub",
        prompt_tokens=10,
        completion_tokens=10,
    )
    patch_good = PatchProposal(
        case_id=case.case_id,
        unified_diff=good_diff,
        model_id="stub",
        prompt_tokens=10,
        completion_tokens=10,
    )

    class _TwoStageLLM:
        def __init__(self) -> None:
            self.calls = 0

        def generate_patch(self, *args: Any, **kwargs: Any) -> tuple[PatchProposal, ModelUsage]:
            self.calls += 1
            if self.calls == 1:
                return patch_overfit, ModelUsage(
                    model_id="test-llm", prompt_tokens=10, completion_tokens=10
                )
            return patch_good, ModelUsage(
                model_id="test-llm", prompt_tokens=10, completion_tokens=10
            )

    runner = MagicMock()
    container_call_count = {"n": 0}

    def _mock_run(*args: Any, **kwargs: Any) -> ExecutionResult:
        container_call_count["n"] += 1
        # Baseline run (call 1): must fail
        if container_call_count["n"] == 1:
            return ExecutionResult(
                case_id=case.case_id,
                patch_diff_hash="baseline",
                exit_code=ExitCode.TESTS_FAILED,
                stdout="FAILED tests/test_normalizer.py::test_whitespace\n1 failed",
                stderr="",
                wall_seconds=0.1,
                expected_test_ids=case.failing_test_ids,
            )
        # Attempt 2 container run: passes
        return ExecutionResult(
            case_id=case.case_id,
            patch_diff_hash="good",
            exit_code=ExitCode.OK,
            stdout="tests/test_normalizer.py::test_whitespace PASSED\n1 passed in 0.05s",
            stderr="",
            wall_seconds=0.1,
            expected_test_ids=case.failing_test_ids,
        )

    runner.run_in_container.side_effect = _mock_run

    db_path = tmp_path / "sentinel.db"
    sm = RepairStateMachine(
        spec=case,
        llm_client=_TwoStageLLM(),
        container_runner=runner,
        max_attempts=3,
        db_path=db_path,
        source_workspace_override=ws,
        image_digest="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    )
    run_id = sm.start_run()
    rec = sm.run_to_terminal(run_id)

    # Verify run succeeded into AWAITING_HUMAN_APPROVAL
    assert rec.state == RunState.AWAITING_HUMAN_APPROVAL
    assert rec.attempts_used == 2

    # Check that Attempt 1 was rejected by overfit guard (POLICY_REJECTED)
    store = CheckpointStore(db_path)
    attempts = store.get_attempts(run_id)
    assert len(attempts) == 2
    assert attempts[0].status.value == "POLICY_REJECTED"
    assert attempts[0].error_type == "OverfitPolicyError"
    assert "HELLO" in (attempts[0].error_detail or "")
    assert attempts[1].status.value == "PASSED_PENDING_APPROVAL"

    # Container runner was only called TWICE: 1 for baseline, 1 for attempt 2!
    # Attempt 1's container run was skipped completely!
    assert container_call_count["n"] == 2

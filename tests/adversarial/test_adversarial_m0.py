"""Adversarial tests for AgentSentinel M0 domain layer.

These tests attempt to actively break the domain models and exception classes
by supplying crafted malicious inputs, edge cases, and boundary violations.

Phase C: [SECURITY & QA AUDITOR] — adversarial verification.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime

import pytest

from agentsentinel.domain.exceptions import (
    AgentSentinelError,
    AllowlistViolationError,
    PathTraversalError,
    SymlinkEscapeError,
    TestFileModificationError,
)
from agentsentinel.domain.exit_codes import ExitCode, classify, is_harness_broken
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal

VALID_SHA = "a" * 40
VALID_DT = datetime(2026, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 1. Path traversal / injection in CaseSpec fields
# ---------------------------------------------------------------------------


class TestPathTraversalInputs:
    """CaseSpec must be constructible with traversal strings in allowed_edit_paths
    (the validator/policy layer will reject them — not the model itself).
    But the PathTraversalError exception must carry the raw path unchanged.
    """

    TRAVERSAL_PATHS = [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\cmd.exe",
        "%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "\x00/etc/passwd",  # null-byte injection
        "src/" + "a/" * 1000 + "f.py",  # very deep path
    ]

    @pytest.mark.adversarial
    @pytest.mark.parametrize("evil_path", TRAVERSAL_PATHS)
    def test_path_traversal_error_preserves_raw_path(self, evil_path: str) -> None:
        """PathTraversalError must carry the exact raw path for forensic logging."""
        err = PathTraversalError(evil_path)
        assert err.raw_path == evil_path
        assert isinstance(err, AgentSentinelError)

    @pytest.mark.adversarial
    @pytest.mark.parametrize("evil_path", TRAVERSAL_PATHS)
    def test_case_spec_accepts_traversal_in_allowed_paths(self, evil_path: str) -> None:
        """CaseSpec does NOT validate path safety — that is the policy layer's job.
        Models are pure data containers; validation lives in agentsentinel.policy.
        """
        spec = CaseSpec(
            case_id="adv-001",
            repo_url="https://example.com/repo",
            base_commit=VALID_SHA,
            test_command="pytest",
            allowed_edit_paths=(evil_path,),
            failing_test_ids=("tests/t.py::t",),
            created_at=VALID_DT,
        )
        assert spec.allowed_edit_paths == (evil_path,)


# ---------------------------------------------------------------------------
# 2. Malformed / oversized diffs
# ---------------------------------------------------------------------------


class TestMalformedDiffs:
    @pytest.mark.adversarial
    def test_whitespace_only_diff_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unified_diff"):
            PatchProposal(
                case_id="c",
                unified_diff="\n\n\t   \n",
                model_id="m",
                prompt_tokens=0,
                completion_tokens=0,
                proposed_at=VALID_DT,
            )

    @pytest.mark.adversarial
    def test_binary_garbage_in_diff_field(self) -> None:
        """Binary garbage in a diff should be accepted by the model (storage).
        The policy layer rejects structurally invalid diffs, not the model.
        """
        garbage = bytes(range(256)).decode("latin-1")
        p = PatchProposal(
            case_id="c",
            unified_diff=garbage,
            model_id="m",
            prompt_tokens=0,
            completion_tokens=0,
            proposed_at=VALID_DT,
        )
        assert len(p.diff_hash) == 64

    @pytest.mark.adversarial
    def test_extremely_large_diff_hashes_correctly(self) -> None:
        """A 10 MB diff must hash without OOM or timeout."""
        large_diff = "+" + "x" * (10 * 1024 * 1024)
        p = PatchProposal(
            case_id="c",
            unified_diff=large_diff,
            model_id="m",
            prompt_tokens=0,
            completion_tokens=0,
            proposed_at=VALID_DT,
        )
        expected = hashlib.sha256(large_diff.encode("utf-8", errors="replace")).hexdigest()
        assert p.diff_hash == expected

    @pytest.mark.adversarial
    def test_diff_containing_null_bytes(self) -> None:
        """Null bytes must not cause a crash — errors='replace' applies."""
        diff_with_null = "--- a\n+++ b\n\x00\x00\x00"
        p = PatchProposal(
            case_id="c",
            unified_diff=diff_with_null,
            model_id="m",
            prompt_tokens=0,
            completion_tokens=0,
            proposed_at=VALID_DT,
        )
        assert len(p.diff_hash) == 64


# ---------------------------------------------------------------------------
# 3. Exit code adversarial inputs
# ---------------------------------------------------------------------------


class TestExitCodeAdversarial:
    @pytest.mark.adversarial
    @pytest.mark.parametrize(
        "tricky_code",
        [
            5,  # NO_TESTS_COLLECTED — must NOT pass the reward-hacking guard
            3,  # INTERNAL_ERROR
            2,  # INTERRUPTED
            4,  # USAGE_ERROR
        ],
    )
    def test_non_verdict_codes_are_harness_broken(self, tricky_code: int) -> None:
        assert is_harness_broken(tricky_code) is True, (
            f"Exit code {tricky_code} must be treated as a broken harness, not a pass/fail verdict"
        )

    @pytest.mark.adversarial
    def test_no_tests_collected_cannot_be_classified_as_ok(self) -> None:
        code = ExitCode.NO_TESTS_COLLECTED
        assert code != ExitCode.OK
        assert is_harness_broken(code) is True

    @pytest.mark.adversarial
    @pytest.mark.parametrize("raw", [-1, 6, 127, 128, 255, sys.maxsize])
    def test_out_of_range_codes_raise(self, raw: int) -> None:
        with pytest.raises(ValueError):
            classify(raw)

    @pytest.mark.adversarial
    def test_integer_zero_is_ok_not_something_else(self) -> None:
        assert classify(0) == ExitCode.OK


# ---------------------------------------------------------------------------
# 4. Symlink and allowlist edge cases
# ---------------------------------------------------------------------------


class TestSymlinkAndAllowlist:
    @pytest.mark.adversarial
    def test_symlink_escape_fields_preserved(self) -> None:
        err = SymlinkEscapeError(
            link="/workspace/.evil -> /etc/shadow",
            resolved="/etc/shadow",
            root="/workspace",
        )
        assert err.link == "/workspace/.evil -> /etc/shadow"
        assert err.resolved == "/etc/shadow"
        assert err.root == "/workspace"

    @pytest.mark.adversarial
    def test_allowlist_violation_with_empty_allowlist(self) -> None:
        err = AllowlistViolationError("anything.py", ())
        assert "0 entries" in str(err)

    @pytest.mark.adversarial
    def test_allowlist_violation_with_large_allowlist(self) -> None:
        large = tuple(f"file_{i}.py" for i in range(10_000))
        err = AllowlistViolationError("evil.py", large)
        assert "10000 entries" in str(err)


# ---------------------------------------------------------------------------
# 5. Test file modification reward-hacking guard
# ---------------------------------------------------------------------------


class TestRewardHackingGuard:
    TEST_PATHS = [
        "tests/test_broken.py",
        "test_something.py",
        "src/tests/test_hidden.py",
        "tests/__init__.py",
        "conftest.py",
    ]

    @pytest.mark.adversarial
    @pytest.mark.parametrize("test_path", TEST_PATHS)
    def test_test_file_modification_error_carries_path(self, test_path: str) -> None:
        err = TestFileModificationError(test_path)
        assert err.test_path == test_path
        assert "REWARD-HACKING BAN" in str(err)
        assert test_path in str(err)


# ---------------------------------------------------------------------------
# 6. ExecutionResult adversarial
# ---------------------------------------------------------------------------


class TestExecutionResultAdversarial:
    @pytest.mark.adversarial
    def test_stdout_with_flood_content(self) -> None:
        """Truncated flag must be settable — capturing a flood payload."""
        flooded = "a\n" * 100_000
        result = ExecutionResult(
            case_id="c",
            patch_diff_hash="baseline",
            exit_code=ExitCode.TESTS_FAILED,
            stdout=flooded,
            stderr="",
            wall_seconds=1.0,
            stdout_truncated=True,
        )
        assert result.stdout_truncated is True
        assert result.passed is False

    @pytest.mark.adversarial
    def test_no_tests_collected_result_is_not_passed(self) -> None:
        """Reward-hacking: an empty test suite must never register as a pass."""
        result = ExecutionResult(
            case_id="c",
            patch_diff_hash="hack",
            exit_code=ExitCode.NO_TESTS_COLLECTED,
            stdout="collected 0 items",
            stderr="",
            wall_seconds=0.1,
        )
        assert result.passed is False
        assert result.failed is False  # it's neither — it's a broken harness

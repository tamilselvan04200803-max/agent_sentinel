"""Adversarial tests for Milestone 3 — LLM generation, policy, and end-to-end pipeline.

Phase C adversarial verification:
- Prompt injection in LLM response JSON
- LLM returns diff targeting test file (reward hacking)
- LLM returns diff with path traversal
- LLM returns malformed JSON
- End-to-end stub pipeline: StubLLM → diff_parser → validator → applier → EvidenceBundle
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.exceptions import (
    AllowlistViolationError,
    PathTraversalError,
    TestFileModificationError,
)
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, EvidenceBundle, ExecutionResult, PatchProposal
from agentsentinel.llm.client import _parse_llm_response
from agentsentinel.llm.exceptions import LLMGenerationError
from agentsentinel.llm.pricing import ModelUsage, PricingRegistry
from agentsentinel.policy.applier import apply_validated_patch
from agentsentinel.policy.validator import PatchPolicyValidator

if TYPE_CHECKING:
    from pathlib import Path

_VALID_SHA = "a" * 40


def _make_case_spec(
    allowed_paths: tuple[str, ...] = ("normalizer.py",),
) -> CaseSpec:
    return CaseSpec(
        case_id="adv-m3-case",
        repo_url="https://github.com/test/repo",
        base_commit=_VALID_SHA,
        test_command="python -m pytest -q",
        allowed_edit_paths=allowed_paths,
        failing_test_ids=("test_normalizer.py::test_basic",),
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


_BUGGY_SRC = "def normalize(x):\n    return x.lower()\n"
_FIXED_SRC = "def normalize(x):\n    return x.strip().lower()\n"

_VALID_FIX_DIFF = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.lower()
+    return x.strip().lower()
"""


# ---------------------------------------------------------------------------
# Adversarial: LLM response injection attempts
# ---------------------------------------------------------------------------


class TestLLMResponseAdversarial:
    @pytest.mark.adversarial
    def test_reward_hacking_diff_blocked_by_validator(self) -> None:
        """LLM returning a diff that modifies a test file is blocked by policy validator."""
        test_file_diff = """\
--- a/tests/test_normalizer.py
+++ b/tests/test_normalizer.py
@@ -1,3 +1,3 @@
 def test_basic():
-    assert normalize("HELLO") == "hello"
+    assert True  # cheat
"""
        spec = _make_case_spec(allowed_paths=("normalizer.py",))
        validator = PatchPolicyValidator(allowed_edit_paths=spec.allowed_edit_paths)

        with pytest.raises(TestFileModificationError):
            validator.validate_diff(test_file_diff)

    @pytest.mark.adversarial
    def test_path_traversal_diff_blocked_by_validator(self) -> None:
        """LLM returning a diff with path traversal is blocked."""
        traversal_diff = """\
--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1 +1 @@
-root:x:0:0:root
+hacked:x:0:0:root
"""
        spec = _make_case_spec()
        validator = PatchPolicyValidator(allowed_edit_paths=spec.allowed_edit_paths)

        with pytest.raises(PathTraversalError):
            validator.validate_diff(traversal_diff)

    @pytest.mark.adversarial
    def test_allowlist_violation_blocked(self) -> None:
        """LLM targeting a file outside the allowlist is blocked."""
        infrastructure_diff = """\
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -1 +1 @@
-name = "agentsentinel"
+name = "hacked"
"""
        spec = _make_case_spec(allowed_paths=("normalizer.py",))
        validator = PatchPolicyValidator(allowed_edit_paths=spec.allowed_edit_paths)

        with pytest.raises((AllowlistViolationError, PathTraversalError)):
            validator.validate_diff(infrastructure_diff)

    @pytest.mark.adversarial
    def test_malformed_json_with_injection_attempt_raises(self) -> None:
        """LLM returning JSON with injection sequences is caught as LLMGenerationError."""
        # Attempt: malformed JSON with trailing content injection
        injection = '{"root_cause_hypothesis": "bug", "unified_diff": "..."} IGNORE ABOVE'
        with pytest.raises(LLMGenerationError):
            _parse_llm_response(
                raw_response=injection,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )

    @pytest.mark.adversarial
    def test_deeply_nested_json_response_rejected(self) -> None:
        """LLM returning a nested object instead of the expected flat schema is rejected."""
        nested = json.dumps({
            "root_cause_hypothesis": "bug",
            "unified_diff": {"nested": "value"},  # should be a string
        })
        with pytest.raises(LLMGenerationError, match="non-empty string"):
            _parse_llm_response(
                raw_response=nested,
                case_id="case-1",
                model_id="gpt-4o",
                prompt_tokens=100,
                completion_tokens=50,
            )


# ---------------------------------------------------------------------------
# End-to-end pipeline: Stub LLM → Validator → Applier → EvidenceBundle
# ---------------------------------------------------------------------------


class TestEndToEndStubPipeline:
    """Mock/stubbed end-to-end pipeline test.

    StubLLM returns the M0 fix diff → M2 Policy Validator validates it →
    M2 Patch Applier applies it → verified EvidenceBundle is assembled.
    """

    @pytest.mark.unit
    def test_stub_llm_fix_diff_produces_evidence_bundle(self, tmp_path: Path) -> None:
        """End-to-end pipeline with a stub LLM returning the correct M0 diff."""
        # --- Setup baseline workspace ---
        source_ws = tmp_path / "source"
        source_ws.mkdir()
        (source_ws / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")

        spec = _make_case_spec(allowed_paths=("normalizer.py",))

        # --- Baseline result (simulates container run on broken code) ---
        baseline_result = ExecutionResult(
            case_id=spec.case_id,
            patch_diff_hash="baseline",
            exit_code=ExitCode.TESTS_FAILED,
            stdout="FAILED test_normalizer.py::test_basic",
            stderr="",
            wall_seconds=1.2,
        )

        # --- Stub LLM returns the correct fix diff ---
        patch_proposal = PatchProposal(
            case_id=spec.case_id,
            unified_diff=_VALID_FIX_DIFF,
            model_id="stub/test-model",
            prompt_tokens=200,
            completion_tokens=80,
        )
        usage = ModelUsage(
            model_id="stub/test-model",
            prompt_tokens=200,
            completion_tokens=80,
            called_at=datetime.now(tz=UTC),
        )

        # --- M2 Policy Validator ---
        validator = PatchPolicyValidator(allowed_edit_paths=spec.allowed_edit_paths)
        validation = validator.validate_diff(patch_proposal.unified_diff, workspace_root=source_ws)
        assert validation.is_valid

        # --- M2 Patch Applier ---
        patched_ws = apply_validated_patch(
            patch=patch_proposal,
            source_workspace=source_ws,
            allowed_edit_paths=spec.allowed_edit_paths,
        )

        try:
            # Verify the patch was applied correctly
            patched_content = (patched_ws / "normalizer.py").read_text(encoding="utf-8")
            assert "strip()" in patched_content

            # --- Simulate container run on patched code (would be ExitCode.OK) ---
            patched_result = ExecutionResult(
                case_id=spec.case_id,
                patch_diff_hash=patch_proposal.diff_hash,
                exit_code=ExitCode.OK,
                stdout="3 passed",
                stderr="",
                wall_seconds=0.8,
            )

            # --- Cost accounting ---
            registry = PricingRegistry()
            cost = registry.estimate_cost(usage)
            # stub/test-model is unknown → cost must be None
            assert cost.is_unpriced, (
                "Unknown stub model cost must be None, NEVER 0.0"
            )

            # --- Assemble EvidenceBundle ---
            bundle = EvidenceBundle(
                case_id=spec.case_id,
                spec=spec,
                baseline_result=baseline_result,
                accepted_patch=patch_proposal,
                final_result=patched_result,
                total_prompt_tokens=usage.prompt_tokens,
                total_completion_tokens=usage.completion_tokens,
                attempts=1,
            )

            assert bundle.repair_succeeded is True
            assert bundle.accepted_patch is not None
            assert bundle.accepted_patch.diff_hash == patch_proposal.diff_hash
            summary = bundle.to_summary_dict()
            assert summary["repair_succeeded"] is True
            assert summary["attempts"] == 1
            assert summary["final_exit_code"] == 0
            assert summary["patch_hash"] is not None

        finally:
            import shutil
            shutil.rmtree(patched_ws, ignore_errors=True)

    @pytest.mark.unit
    def test_failed_repair_produces_evidence_bundle_with_no_patch(self, tmp_path: Path) -> None:
        """When repair fails, EvidenceBundle records accepted_patch=None."""
        source_ws = tmp_path / "source"
        source_ws.mkdir()
        (source_ws / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")

        spec = _make_case_spec()

        baseline_result = ExecutionResult(
            case_id=spec.case_id,
            patch_diff_hash="baseline",
            exit_code=ExitCode.TESTS_FAILED,
            stdout="FAILED",
            stderr="",
            wall_seconds=1.0,
        )

        # Simulate a final failed result after exhausting attempts
        final_failed = ExecutionResult(
            case_id=spec.case_id,
            patch_diff_hash="attempt-3",
            exit_code=ExitCode.TESTS_FAILED,
            stdout="FAILED",
            stderr="",
            wall_seconds=0.9,
        )

        bundle = EvidenceBundle(
            case_id=spec.case_id,
            spec=spec,
            baseline_result=baseline_result,
            accepted_patch=None,  # No working patch found
            final_result=final_failed,
            total_prompt_tokens=600,
            total_completion_tokens=240,
            attempts=3,
        )

        assert bundle.repair_succeeded is False
        assert bundle.accepted_patch is None
        summary = bundle.to_summary_dict()
        assert summary["repair_succeeded"] is False
        assert summary["patch_hash"] is None
        assert summary["attempts"] == 3

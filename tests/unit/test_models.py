"""Unit tests for agentsentinel.domain.models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import (
    CaseSpec,
    EvidenceBundle,
    ExecutionResult,
    PatchProposal,
    _sha256_of,
)

VALID_SHA = "a" * 40


# ---------------------------------------------------------------------------
# CaseSpec
# ---------------------------------------------------------------------------


class TestCaseSpec:
    @pytest.mark.unit
    def test_valid_construction(self, valid_case_spec: CaseSpec) -> None:
        assert valid_case_spec.case_id == "test-case-001"
        assert valid_case_spec.base_commit == VALID_SHA

    @pytest.mark.unit
    def test_immutable(self, valid_case_spec: CaseSpec) -> None:
        with pytest.raises((AttributeError, TypeError)):
            valid_case_spec.case_id = "tampered"  # type: ignore[misc]

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "bad_sha",
        [
            "short",
            "z" * 40,  # non-hex
            "a" * 39,  # too short
            "a" * 41,  # too long
            "",
        ],
    )
    def test_invalid_sha_raises(self, bad_sha: str) -> None:
        with pytest.raises(ValueError, match="base_commit"):
            CaseSpec(
                case_id="x",
                repo_url="https://example.com",
                base_commit=bad_sha,
                test_command="pytest",
                allowed_edit_paths=("a.py",),
                failing_test_ids=("test_x.py::test_y",),
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

    @pytest.mark.unit
    def test_empty_allowed_paths_raises(self) -> None:
        with pytest.raises(ValueError, match="allowed_edit_paths"):
            CaseSpec(
                case_id="x",
                repo_url="https://example.com",
                base_commit=VALID_SHA,
                test_command="pytest",
                allowed_edit_paths=(),
                failing_test_ids=("tests/test_x.py::test_y",),
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

    @pytest.mark.unit
    def test_empty_failing_test_ids_raises(self) -> None:
        with pytest.raises(ValueError, match="failing_test_ids"):
            CaseSpec(
                case_id="x",
                repo_url="https://example.com",
                base_commit=VALID_SHA,
                test_command="pytest",
                allowed_edit_paths=("a.py",),
                failing_test_ids=(),
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

    @pytest.mark.unit
    def test_naive_datetime_raises(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            CaseSpec(
                case_id="x",
                repo_url="https://example.com",
                base_commit=VALID_SHA,
                test_command="pytest",
                allowed_edit_paths=("a.py",),
                failing_test_ids=("t.py::t",),
                created_at=datetime(2026, 1, 1),  # naive — no tzinfo
            )

    @pytest.mark.unit
    def test_hashable(self, valid_case_spec: CaseSpec) -> None:
        """frozen=True must make CaseSpec hashable for use in sets/dicts."""
        assert hash(valid_case_spec) == hash(valid_case_spec)
        s = {valid_case_spec}
        assert valid_case_spec in s

    @pytest.mark.unit
    def test_metadata_canonicalization_and_hash_equality(self) -> None:
        """Two CaseSpec instances with reversed metadata keys must produce identical hash() and equal comparison."""
        dt = datetime(2026, 1, 1, tzinfo=UTC)
        spec1 = CaseSpec(
            case_id="case-1",
            repo_url="https://example.com/repo",
            base_commit=VALID_SHA,
            test_command="pytest",
            allowed_edit_paths=("src/file.py",),
            failing_test_ids=("tests/test_file.py::test_fn",),
            created_at=dt,
            metadata=(("b_key", "val_b"), ("a_key", "val_a"), ("c_key", "val_c")),
        )
        spec2 = CaseSpec(
            case_id="case-1",
            repo_url="https://example.com/repo",
            base_commit=VALID_SHA,
            test_command="pytest",
            allowed_edit_paths=("src/file.py",),
            failing_test_ids=("tests/test_file.py::test_fn",),
            created_at=dt,
            metadata=(("c_key", "val_c"), ("a_key", "val_a"), ("b_key", "val_b")),
        )
        assert spec1.metadata == (("a_key", "val_a"), ("b_key", "val_b"), ("c_key", "val_c"))
        assert spec1 == spec2
        assert hash(spec1) == hash(spec2)
        assert len({spec1, spec2}) == 1

    @pytest.mark.unit
    def test_metadata_duplicate_key_rejected(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=UTC)
        with pytest.raises(ValueError, match="Duplicate metadata key"):
            CaseSpec(
                case_id="case-1",
                repo_url="https://example.com/repo",
                base_commit=VALID_SHA,
                test_command="pytest",
                allowed_edit_paths=("src/file.py",),
                failing_test_ids=("tests/test_file.py::test_fn",),
                created_at=dt,
                metadata=(("dup_key", "val1"), ("dup_key", "val2")),
            )


# ---------------------------------------------------------------------------
# PatchProposal
# ---------------------------------------------------------------------------


class TestPatchProposal:
    @pytest.mark.unit
    def test_diff_hash_computed(self, valid_patch: PatchProposal) -> None:
        expected = _sha256_of(valid_patch.unified_diff)
        assert valid_patch.diff_hash == expected

    @pytest.mark.unit
    def test_diff_hash_not_settable(self, valid_case_spec: CaseSpec) -> None:
        """diff_hash must be computed, not injected."""
        p = PatchProposal(
            case_id=valid_case_spec.case_id,
            unified_diff="--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n",
            model_id="test",
            prompt_tokens=10,
            completion_tokens=5,
            proposed_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert len(p.diff_hash) == 64  # SHA-256 hex

    @pytest.mark.unit
    def test_empty_diff_raises(self, valid_case_spec: CaseSpec) -> None:
        with pytest.raises(ValueError, match="unified_diff"):
            PatchProposal(
                case_id=valid_case_spec.case_id,
                unified_diff="   \n\t  ",
                model_id="test",
                prompt_tokens=0,
                completion_tokens=0,
                proposed_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

    @pytest.mark.unit
    def test_negative_tokens_raise(self, valid_case_spec: CaseSpec) -> None:
        with pytest.raises(ValueError, match="token counts"):
            PatchProposal(
                case_id=valid_case_spec.case_id,
                unified_diff="--- a\n+++ b\n@@ -1 +1@@\n-x\n+y\n",
                model_id="test",
                prompt_tokens=-1,
                completion_tokens=0,
                proposed_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

    @pytest.mark.unit
    def test_same_diff_same_hash(self, valid_case_spec: CaseSpec) -> None:
        diff = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-bug\n+fix\n"
        p1 = PatchProposal(
            case_id=valid_case_spec.case_id,
            unified_diff=diff,
            model_id="m1",
            prompt_tokens=10,
            completion_tokens=5,
            proposed_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        p2 = PatchProposal(
            case_id=valid_case_spec.case_id,
            unified_diff=diff,
            model_id="m2",
            prompt_tokens=20,
            completion_tokens=10,
            proposed_at=datetime(2026, 2, 1, tzinfo=UTC),
        )
        assert p1.diff_hash == p2.diff_hash, "Identical diffs must produce identical hashes"


# ---------------------------------------------------------------------------
# ExecutionResult
# ---------------------------------------------------------------------------


class TestExecutionResult:
    @pytest.mark.unit
    def test_passed_property(self, passing_result: ExecutionResult) -> None:
        assert passing_result.passed is True
        assert passing_result.failed is False

    @pytest.mark.unit
    def test_failed_property(self, baseline_result: ExecutionResult) -> None:
        assert baseline_result.failed is True
        assert baseline_result.passed is False

    @pytest.mark.unit
    def test_negative_wall_seconds_raises(self, valid_case_spec: CaseSpec) -> None:
        with pytest.raises(ValueError, match="wall_seconds"):
            ExecutionResult(
                case_id=valid_case_spec.case_id,
                patch_diff_hash="baseline",
                exit_code=ExitCode.TESTS_FAILED,
                stdout="",
                stderr="",
                wall_seconds=-1.0,
            )

    @pytest.mark.unit
    def test_invalid_exit_code_raises(self, valid_case_spec: CaseSpec) -> None:
        with pytest.raises((ValueError, KeyError)):
            ExecutionResult(
                case_id=valid_case_spec.case_id,
                patch_diff_hash="baseline",
                exit_code=99,  # type: ignore[arg-type]
                stdout="",
                stderr="",
                wall_seconds=1.0,
            )

    @pytest.mark.unit
    def test_no_tests_collected_is_not_passed(self, valid_case_spec: CaseSpec) -> None:
        """Reward-hacking guard: NO_TESTS_COLLECTED must not look like a pass."""
        result = ExecutionResult(
            case_id=valid_case_spec.case_id,
            patch_diff_hash="baseline",
            exit_code=ExitCode.NO_TESTS_COLLECTED,
            stdout="",
            stderr="no tests found",
            wall_seconds=0.5,
        )
        assert result.passed is False
        assert result.failed is False  # it's a harness-broken state, not a verdict


# ---------------------------------------------------------------------------
# EvidenceBundle
# ---------------------------------------------------------------------------


class TestEvidenceBundle:
    @pytest.mark.unit
    def test_successful_bundle(
        self,
        valid_case_spec: CaseSpec,
        valid_patch: PatchProposal,
        baseline_result: ExecutionResult,
        passing_result: ExecutionResult,
    ) -> None:
        bundle = EvidenceBundle(
            case_id=valid_case_spec.case_id,
            spec=valid_case_spec,
            baseline_result=baseline_result,
            accepted_patch=valid_patch,
            final_result=passing_result,
            total_prompt_tokens=100,
            total_completion_tokens=50,
            attempts=2,
        )
        assert bundle.repair_succeeded is True
        assert len(bundle.bundle_hash) == 64

    @pytest.mark.unit
    def test_failed_bundle(
        self,
        valid_case_spec: CaseSpec,
        baseline_result: ExecutionResult,
    ) -> None:
        bundle = EvidenceBundle(
            case_id=valid_case_spec.case_id,
            spec=valid_case_spec,
            baseline_result=baseline_result,
            accepted_patch=None,
            final_result=baseline_result,
            total_prompt_tokens=500,
            total_completion_tokens=200,
            attempts=5,
        )
        assert bundle.repair_succeeded is False
        assert bundle.accepted_patch is None

    @pytest.mark.unit
    def test_baseline_ok_raises(
        self,
        valid_case_spec: CaseSpec,
        valid_patch: PatchProposal,
        passing_result: ExecutionResult,
    ) -> None:
        """Baseline must NOT be OK — it must reproduce the bug."""
        with pytest.raises(ValueError, match="baseline_result must NOT be OK"):
            EvidenceBundle(
                case_id=valid_case_spec.case_id,
                spec=valid_case_spec,
                baseline_result=passing_result,  # WRONG — passing as baseline
                accepted_patch=valid_patch,
                final_result=passing_result,
                total_prompt_tokens=100,
                total_completion_tokens=50,
                attempts=1,
            )

    @pytest.mark.unit
    def test_zero_attempts_raises(
        self,
        valid_case_spec: CaseSpec,
        baseline_result: ExecutionResult,
        passing_result: ExecutionResult,
    ) -> None:
        with pytest.raises(ValueError, match="attempts"):
            EvidenceBundle(
                case_id=valid_case_spec.case_id,
                spec=valid_case_spec,
                baseline_result=baseline_result,
                accepted_patch=None,
                final_result=baseline_result,
                total_prompt_tokens=0,
                total_completion_tokens=0,
                attempts=0,
            )

    @pytest.mark.unit
    def test_bundle_hash_deterministic(
        self,
        valid_case_spec: CaseSpec,
        valid_patch: PatchProposal,
        baseline_result: ExecutionResult,
        passing_result: ExecutionResult,
    ) -> None:
        kwargs = {
            "case_id": valid_case_spec.case_id,
            "spec": valid_case_spec,
            "baseline_result": baseline_result,
            "accepted_patch": valid_patch,
            "final_result": passing_result,
            "total_prompt_tokens": 100,
            "total_completion_tokens": 50,
            "attempts": 1,
        }
        b1 = EvidenceBundle(**kwargs)  # type: ignore[arg-type]
        b2 = EvidenceBundle(**kwargs)  # type: ignore[arg-type]
        assert b1.bundle_hash == b2.bundle_hash

    @pytest.mark.unit
    def test_to_summary_dict_keys(
        self,
        valid_case_spec: CaseSpec,
        valid_patch: PatchProposal,
        baseline_result: ExecutionResult,
        passing_result: ExecutionResult,
    ) -> None:
        bundle = EvidenceBundle(
            case_id=valid_case_spec.case_id,
            spec=valid_case_spec,
            baseline_result=baseline_result,
            accepted_patch=valid_patch,
            final_result=passing_result,
            total_prompt_tokens=100,
            total_completion_tokens=50,
            attempts=1,
        )
        summary = bundle.to_summary_dict()
        required_keys = {
            "case_id",
            "repair_succeeded",
            "attempts",
            "baseline_exit_code",
            "final_exit_code",
            "wall_seconds_final",
            "total_prompt_tokens",
            "total_completion_tokens",
            "patch_hash",
            "bundle_hash",
        }
        assert required_keys.issubset(summary.keys())

    @pytest.mark.unit
    def test_bundle_immutable(
        self,
        valid_case_spec: CaseSpec,
        baseline_result: ExecutionResult,
    ) -> None:
        bundle = EvidenceBundle(
            case_id=valid_case_spec.case_id,
            spec=valid_case_spec,
            baseline_result=baseline_result,
            accepted_patch=None,
            final_result=baseline_result,
            total_prompt_tokens=0,
            total_completion_tokens=0,
            attempts=1,
        )
        with pytest.raises((AttributeError, TypeError)):
            bundle.case_id = "tampered"  # type: ignore[misc]

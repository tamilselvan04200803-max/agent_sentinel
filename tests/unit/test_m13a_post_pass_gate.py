"""Tests for the M13A summary models and opt-in configuration contracts."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, fields

import pytest

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, EvidenceBundle, ExecutionResult
from agentsentinel.verification import post_pass_gate


class TestMinimizationSummary:
    """Minimization summaries retain their immutable public fields."""

    def test_summary_is_frozen(self):
        summary = post_pass_gate.MinimizationSummary(2, 1, 1, True)
        with pytest.raises(FrozenInstanceError):
            summary.was_minimized = False


class TestSurvivedMutantDetail:
    """Survivor records identify the changed function and mutation."""

    def test_detail_fields_match_plan(self):
        assert tuple(field.name for field in fields(post_pass_gate.SurvivedMutantDetail)) == (
            "mutant_id", "file_path", "function_name", "mutation_description",
        )


class TestMutationAdequacySummary:
    """Empty survivor details are an immutable value, not a constructor."""

    def test_empty_details_default(self):
        summary = post_pass_gate.MutationAdequacySummary(False, 0, 0, 0, 1.0)
        assert summary.survived_mutant_details == ()


class TestPostPassVerificationReport:
    """Reports retain the selected diff and the verification evidence."""

    def test_report_fields_match_plan(self):
        assert tuple(field.name for field in fields(post_pass_gate.PostPassVerificationReport)) == (
            "minimized_diff", "minimized_execution_result",
            "minimization_summary", "mutation_adequacy_summary",
        )


class TestPostPassGateImports:
    """Test that post_pass_gate module can be imported."""

    def test_import_post_pass_gate(self):
        from agentsentinel import verification
        from agentsentinel.domain import models

        for name in (
            "MinimizationSummary", "SurvivedMutantDetail", "MutationAdequacySummary",
        ):
            assert getattr(post_pass_gate, name) is getattr(models, name)
            assert getattr(verification, name) is getattr(post_pass_gate, name)
        assert verification.PostPassVerificationReport is post_pass_gate.PostPassVerificationReport
        assert verification.run_ddmin_hunk_minimization is post_pass_gate.run_ddmin_hunk_minimization
        assert verification.run_mutation_adequacy_probe is post_pass_gate.run_mutation_adequacy_probe


class TestEvidenceBundleExtensions:
    """Test EvidenceBundle accepts new optional summary fields."""

    def test_evidence_bundle_with_minimization_summary(self):
        spec = CaseSpec(
            case_id="test-1",
            repo_url="https://example.com/repo",
            base_commit="0000000000000000000000000000000000000000",
            test_command="pytest -x",
            allowed_edit_paths=("src/test.py",),
            failing_test_ids=("test_bug",),
        )

        baseline = ExecutionResult("test-1", "baseline", ExitCode.TESTS_FAILED, "", "", 0.1)
        final = ExecutionResult("test-1", "accepted", ExitCode.OK, "", "", 0.1)
        summary = post_pass_gate.MinimizationSummary(2, 1, 1, True)
        mutation = post_pass_gate.MutationAdequacySummary(False, 0, 0, 0, 1.0)
        bundle = EvidenceBundle(
            "test-1", spec, baseline, None, final, 0, 0, 1,
            minimization_summary=summary,
            mutation_adequacy_summary=mutation,
        )
        assert bundle.minimization_summary is summary
        assert bundle.mutation_adequacy_summary is mutation
        assert bundle.to_summary_dict()["case_id"] == "test-1"

        legacy = EvidenceBundle("test-1", spec, baseline, None, final, 0, 0, 1)
        assert legacy.minimization_summary is None
        assert legacy.mutation_adequacy_summary is None


class TestRepairStateMachineFlags:
    """Test RepairStateMachine accepts new opt-in flags."""

    def test_state_machine_with_new_flags(self):
        # This test will reference the updated RepairStateMachine
        # with enable_ddmin_minimization and enable_mutation_probe flags
        # that default to False
        from agentsentinel.orchestrator.state_machine import RepairStateMachine

        # Verify the constructor accepts the new keyword-only flags
        sig = inspect.signature(RepairStateMachine.__init__)
        params = sig.parameters

        # These should exist with defaults (will be verified after implementation)
        assert "enable_ddmin_minimization" in params
        assert "enable_mutation_probe" in params
        assert "max_mutants" in params

        # Defaults should be falsy/zero
        assert params["enable_ddmin_minimization"].default is False
        assert params["enable_mutation_probe"].default is False
        assert params["max_mutants"].default == 3
        for name in ("enable_ddmin_minimization", "enable_mutation_probe", "max_mutants"):
            assert params[name].kind is inspect.Parameter.KEYWORD_ONLY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""M5 unit tests for evaluation harness, metrics, and admission gate."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsentinel.domain.models import CaseSpec, PatchProposal
from agentsentinel.evaluation.harness import (
    BenchmarkHarness,
    compare_baseline_vs_bounded_retry,
    verify_case_admission,
)
from agentsentinel.evaluation.metrics import (
    _aggregate,
)
from agentsentinel.evaluation.models import (
    AdmissionVerdict,
    BenchmarkCase,
    CaseEvaluationResult,
)
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.checkpoint import RunState, TerminationReason

VALID_SHA = "0" * 40
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "benchmark_cases"


def _load_case(case_dir: Path) -> BenchmarkCase:
    raw = json.loads((case_dir / "spec.json").read_text(encoding="utf-8"))
    spec = CaseSpec(
        case_id=raw["case_id"],
        repo_url=raw["repo_url"],
        base_commit=raw["base_commit"],
        test_command=raw["test_command"],
        allowed_edit_paths=tuple(raw["allowed_edit_paths"]),
        failing_test_ids=tuple(raw["failing_test_ids"]),
        created_at=datetime.now(UTC),
    )
    return BenchmarkCase(
        case_spec=spec,
        repo_source_path=case_dir / "src",
        base_commit=spec.base_commit,
        test_patch=(case_dir / "test.patch").read_text(encoding="utf-8"),
        reference_fix_patch=(case_dir / "reference.patch").read_text(encoding="utf-8"),
        fail_to_pass_tests=spec.failing_test_ids,
        pass_to_pass_tests=(),
        is_public_historical_commit=False,
    )


class TestAdmissionGate:
    @pytest.mark.unit
    def test_good_case_is_admitted(self) -> None:
        case = _load_case(FIXTURES / "case_01_normalizer")
        v = verify_case_admission(case)
        assert v.admitted, f"expected admitted; reason={v.reason}"

    @pytest.mark.unit
    def test_admission_records_latency(self) -> None:
        case = _load_case(FIXTURES / "case_03_none_coalescing")
        v = verify_case_admission(case)
        assert v.prep_duration_seconds > 0
        assert v.baseline_exit_code == 1  # TESTS_FAILED
        assert v.reference_exit_code == 0  # OK

    @pytest.mark.unit
    def test_baseline_that_passes_is_excluded(self, tmp_path: Path) -> None:
        # Construct a case where baseline+test_patch PASSES (no actual bug).
        src = tmp_path / "src"
        src.mkdir()
        (src / "m.py").write_text("def f(x): return x\n", encoding="utf-8")
        spec = CaseSpec(
            case_id="bogus",
            repo_url="local",
            base_commit=VALID_SHA,
            test_command="python -c \"print(1)\"",
            allowed_edit_paths=("m.py",),
            failing_test_ids=("placeholder::test",),
        )
        # test_patch is a no-op (no file changes). reference_fix_patch same.
        case = BenchmarkCase(
            case_spec=spec,
            repo_source_path=src,
            base_commit=VALID_SHA,
            test_patch="",  # baseline already passes
            reference_fix_patch="",
            fail_to_pass_tests=(),
        )
        v = verify_case_admission(case)
        assert not v.admitted
        assert "Gate 1" in v.reason

    @pytest.mark.unit
    def test_reference_that_fails_is_excluded(self, tmp_path: Path) -> None:
        """If reference_fix_patch does not actually make tests pass, reject."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "m.py").write_text("def f(x): return x\n", encoding="utf-8")
        spec = CaseSpec(
            case_id="badref",
            repo_url="local",
            base_commit=VALID_SHA,
            # A test that always fails:
            test_command="python -c \"import sys; sys.exit(1)\"",
            allowed_edit_paths=("m.py",),
            failing_test_ids=("placeholder::test",),
        )
        case = BenchmarkCase(
            case_spec=spec,
            repo_source_path=src,
            base_commit=VALID_SHA,
            test_patch="",
            reference_fix_patch="--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-def f(x): return x\n+def f(x): return x + 1\n",
            fail_to_pass_tests=("placeholder::test",),
        )
        v = verify_case_admission(case)
        assert not v.admitted


class TestMetricsAggregation:
    @pytest.mark.unit
    def test_unknown_cost_total_is_none(self) -> None:
        v = AdmissionVerdict("c1", True, "ok", baseline_exit_code=1,
                             reference_exit_code=0, prep_duration_seconds=0.1)
        r = CaseEvaluationResult(
            case_id="c1",
            admitted=True,
            repair_duration_seconds=0.2,
            prep_duration_seconds=0.1,
            terminated_state=RunState.TERMINATED_FAILED,
            termination_reason=TerminationReason.MAX_ATTEMPTS_EXHAUSTED.value,
            attempts_used=1,
            input_tokens=10,
            output_tokens=5,
            cost_usd=None,  # unknown
            is_public=False,
        )
        rep = _aggregate(
            verdicts=[v], case_results=[r],
            total_policy_violations=0, total_attempts=1,
            suite_name="x", generated_at_utc="2026-01-01T00:00:00Z",
        )
        assert rep.known_cost_usd_total is None
        assert rep.unknown_cost_runs_count == 1

    @pytest.mark.unit
    def test_excluded_cases_counted_and_logged(self) -> None:
        v = AdmissionVerdict("c1", False, "bad-baseline",
                             baseline_exit_code=0, reference_exit_code=None,
                             prep_duration_seconds=0.0)
        r_excl = CaseEvaluationResult(
            case_id="c1", admitted=False,
            repair_duration_seconds=0.0, prep_duration_seconds=0.0,
            terminated_state="EXCLUDED", termination_reason="EXCLUDED",
            attempts_used=0, input_tokens=0, output_tokens=0,
            cost_usd=None, is_public=False,
        )
        rep = _aggregate([v], [r_excl], 0, 0, "s", "t")
        assert rep.excluded_cases_count == 1
        assert rep.admitted_cases_count == 0
        assert rep.verified_repair_rate == 0.0
        assert len(rep.exclusion_log) == 1
        assert rep.exclusion_log[0].reason == "bad-baseline"

    @pytest.mark.unit
    def test_latency_strictly_separated(self) -> None:
        v = AdmissionVerdict("c", True, "ok", 1, 0, prep_duration_seconds=2.5)
        r = CaseEvaluationResult(
            case_id="c", admitted=True, repair_duration_seconds=7.5,
            prep_duration_seconds=2.5,
            terminated_state=RunState.TERMINATED_FAILED,
            termination_reason=TerminationReason.MAX_ATTEMPTS_EXHAUSTED.value,
            attempts_used=1, input_tokens=1, output_tokens=1,
            cost_usd=0.01, is_public=True,
        )
        rep = _aggregate([v], [r], 0, 1, "s", "t")
        assert rep.total_prep_latency_seconds == pytest.approx(2.5)
        assert rep.total_repair_latency_seconds == pytest.approx(7.5)

    @pytest.mark.unit
    def test_markdown_mentions_partial_cost(self) -> None:
        v = AdmissionVerdict("c", True, "ok", 1, 0, 0.1)
        r = CaseEvaluationResult(
            case_id="c", admitted=True, repair_duration_seconds=0.1,
            prep_duration_seconds=0.1, terminated_state=RunState.TERMINATED_FAILED,
            termination_reason=TerminationReason.INFRASTRUCTURE_FAILURE.value,
            attempts_used=1, input_tokens=0, output_tokens=0,
            cost_usd=None, is_public=True,
        )
        rep = _aggregate([v], [r], 0, 1, "s", "t")
        md = rep.to_markdown()
        assert "PARTIAL / UNKNOWN" in md


class TestBenchmarkHarnessFixtures:
    @pytest.mark.unit
    def test_fixture_case_01_admitted(self) -> None:
        case = _load_case(FIXTURES / "case_01_normalizer")
        assert verify_case_admission(case).admitted

    @pytest.mark.unit
    def test_fixture_case_02_admitted(self) -> None:
        case = _load_case(FIXTURES / "case_02_boundary_off_by_one")
        assert verify_case_admission(case).admitted

    @pytest.mark.unit
    def test_fixture_case_03_admitted(self) -> None:
        case = _load_case(FIXTURES / "case_03_none_coalescing")
        assert verify_case_admission(case).admitted


class _ReferenceLLM:
    """Returns the fixture reference patch (isolated from benchmark case object)."""

    def __init__(self, diff: str) -> None:
        self._diff = diff
        self.prompts: list[str] = []

    def generate_patch(self, case_id: str, prompt: str, model_id: str):
        self.prompts.append(prompt)
        return (
            PatchProposal(
                case_id=case_id,
                unified_diff=self._diff,
                model_id="mock-reference",
                prompt_tokens=11,
                completion_tokens=7,
            ),
            ModelUsage(model_id="mock-reference", prompt_tokens=11, completion_tokens=7),
        )


class _SequentialLLM:
    """First proposes a wrong-but-valid patch, then the reference fix."""

    def __init__(self, wrong: str, correct: str) -> None:
        self._diffs = [wrong, correct]
        self.calls = 0

    def generate_patch(self, case_id: str, prompt: str, model_id: str):
        diff = self._diffs[min(self.calls, len(self._diffs) - 1)]
        self.calls += 1
        return (
            PatchProposal(
                case_id=case_id,
                unified_diff=diff,
                model_id="mock-sequential",
                prompt_tokens=10,
                completion_tokens=5,
            ),
            ModelUsage(model_id="mock-sequential", prompt_tokens=10, completion_tokens=5),
        )


class TestBenchmarkEndToEnd:
    @pytest.mark.unit
    def test_run_suite_verifies_reference_repair(self, tmp_path: Path) -> None:
        case_dir = FIXTURES / "case_01_normalizer"
        case = _load_case(case_dir)
        llm = _ReferenceLLM(case.reference_fix_patch)
        harness = BenchmarkHarness(
            llm_factory=lambda: llm,
            db_path=tmp_path / "bench.db",
            max_attempts=2,
        )
        report = harness.run_suite([case], suite_name="e2e")
        assert report.admitted_cases_count == 1
        assert report.excluded_cases_count == 0
        assert report.verified_repair_count == 1
        assert report.verified_repair_rate == 1.0
        assert report.total_input_tokens == 11
        assert report.total_output_tokens == 7
        assert report.total_prep_latency_seconds > 0
        assert report.total_repair_latency_seconds > 0
        # Reference patch is used as the LLM's answer here by construction of
        # the stub, but the state machine only receives it via generate_patch;
        # admission's copy must not be an extra prompt input beyond the stub.
        assert llm.prompts

    @pytest.mark.unit
    def test_compare_baseline_vs_bounded_retry(self) -> None:
        case_dir = FIXTURES / "case_01_normalizer"
        case = _load_case(case_dir)
        wrong = case.reference_fix_patch.replace(
            "return s.strip().lower()", "return s.upper()"
        )
        assert wrong != case.reference_fix_patch

        def factory() -> _SequentialLLM:
            return _SequentialLLM(wrong, case.reference_fix_patch)

        comparison = compare_baseline_vs_bounded_retry(
            [case], factory, max_attempts_baseline=1, max_attempts_bounded=3
        )
        assert comparison.baseline_repair_rate == 0.0
        assert comparison.bounded_repair_rate == 1.0
        assert comparison.delta_repair_rate == 1.0
        assert comparison.baseline_total_llm_calls == 1
        assert comparison.bounded_total_llm_calls == 2
        assert comparison.delta_llm_calls == 1
        assert comparison.delta_input_tokens > 0

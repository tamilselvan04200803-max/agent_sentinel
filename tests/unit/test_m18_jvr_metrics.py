"""Recorded-judgment metrics: task macro averaging and conservative unknowns."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict, replace
from typing import cast

import pytest

from agentsentinel.evaluation.jvr_metrics import (
    CandidateJudgment,
    JudgmentOutcome,
    JVRMetrics,
    TaskJudgments,
    compute_jvr_metrics,
)

pytestmark = pytest.mark.unit


def task(
    task_id: str = "task",
    *,
    buggy: JudgmentOutcome = JudgmentOutcome.FAIL,
    reference: JudgmentOutcome = JudgmentOutcome.PASS,
    incorrect: tuple[JudgmentOutcome, ...] = (JudgmentOutcome.FAIL,),
    correct: tuple[JudgmentOutcome, ...] = (JudgmentOutcome.PASS,),
) -> TaskJudgments:
    return TaskJudgments(
        task_id=task_id,
        buggy_outcome=buggy,
        reference_outcome=reference,
        incorrect_candidates=tuple(
            CandidateJudgment(f"bad-{index}", outcome) for index, outcome in enumerate(incorrect)
        ),
        correct_candidates=tuple(
            CandidateJudgment(f"good-{index}", outcome) for index, outcome in enumerate(correct)
        ),
    )


def test_unequal_candidate_pools_are_task_macro_averaged() -> None:
    report = compute_jvr_metrics((
        task("small"),
        task(
            "large",
            incorrect=(JudgmentOutcome.FAIL, JudgmentOutcome.PASS, JudgmentOutcome.PASS),
            correct=(JudgmentOutcome.PASS, JudgmentOutcome.FAIL, JudgmentOutcome.FAIL),
        ),
    ))
    assert report.task_count == 2
    assert report.grr == 1.0
    assert report.wdr == pytest.approx(2 / 3)  # Pooled counting would give 1/2.
    assert report.car == pytest.approx(2 / 3)
    assert report.f1 == pytest.approx(2 / 3)
    assert report.ct_wdr == report.ct_car == report.ct_f1 == report.jvr == 0.5


def test_harmonic_means_use_aggregate_rates() -> None:
    report = compute_jvr_metrics((
        task("rejects", correct=(JudgmentOutcome.PASS, JudgmentOutcome.FAIL, JudgmentOutcome.FAIL)),
        task("accepts", incorrect=(JudgmentOutcome.PASS,)),
    ))
    assert report.wdr == 0.5
    assert report.car == pytest.approx(2 / 3)
    assert report.f1 == pytest.approx(4 / 7)
    assert report.ct_wdr == report.ct_car == report.ct_f1 == 0.5
    assert report.jvr == 0.0


def test_jvr_requires_all_three_conditions_on_the_same_task() -> None:
    report = compute_jvr_metrics((
        task("only-bad-complete", correct=(JudgmentOutcome.FAIL,)),
        task("only-good-complete", incorrect=(JudgmentOutcome.PASS,)),
        task("both-complete-but-no-regression", buggy=JudgmentOutcome.PASS),
    ))
    assert report.grr == report.ct_wdr == report.ct_car == pytest.approx(2 / 3)
    assert report.jvr == 0.0


@pytest.mark.parametrize("outcome", [
    JudgmentOutcome.UNRESOLVED, JudgmentOutcome.TIMEOUT, JudgmentOutcome.INFRASTRUCTURE_ERROR,
    JudgmentOutcome.MISSING, JudgmentOutcome.FLAKY,
])
def test_unresolved_candidate_outcomes_retain_denominators_without_credit(outcome) -> None:
    report = compute_jvr_metrics((task(
        incorrect=(JudgmentOutcome.FAIL, outcome),
        correct=(JudgmentOutcome.PASS, outcome),
    ),))
    assert report.wdr == report.car == report.f1 == 0.5
    assert report.ct_wdr == report.ct_car == report.ct_f1 == report.jvr == 0.0


@pytest.mark.parametrize("outcome", [
    JudgmentOutcome.UNRESOLVED, JudgmentOutcome.TIMEOUT, JudgmentOutcome.INFRASTRUCTURE_ERROR,
    JudgmentOutcome.MISSING, JudgmentOutcome.FLAKY,
])
@pytest.mark.parametrize("role", ["buggy", "reference"])
def test_unresolved_baseline_or_reference_never_earns_grr(outcome, role) -> None:
    record = task(**{role: outcome})
    report = compute_jvr_metrics((record,))
    assert report.grr == report.jvr == 0.0
    assert report.wdr == report.car == 1.0


@pytest.mark.parametrize("outcome,expected_wdr,expected_car", [
    (JudgmentOutcome.PASS, 0.0, 1.0),
    (JudgmentOutcome.FAIL, 1.0, 0.0),
])
def test_always_accepting_or_always_rejecting_validators_do_not_pass_jointly(
    outcome, expected_wdr, expected_car,
) -> None:
    report = compute_jvr_metrics((task(
        buggy=outcome, reference=outcome, incorrect=(outcome,), correct=(outcome,),
    ),))
    assert report.wdr == report.ct_wdr == expected_wdr
    assert report.car == report.ct_car == expected_car
    assert report.grr == report.f1 == report.ct_f1 == report.jvr == 0.0


def test_zero_tasks_has_explicit_zero_rates() -> None:
    assert asdict(compute_jvr_metrics(())) == {
        "task_count": 0, "grr": 0.0, "wdr": 0.0, "car": 0.0, "ct_wdr": 0.0,
        "ct_car": 0.0, "f1": 0.0, "ct_f1": 0.0, "jvr": 0.0,
    }


@pytest.mark.parametrize("pool", ["incorrect_candidates", "correct_candidates"])
def test_incomplete_candidate_pools_are_rejected_instead_of_vacuous_success(pool) -> None:
    with pytest.raises(ValueError, match="nonempty"):
        replace(task(), **{pool: ()})


def test_duplicate_task_ids_cannot_change_task_weight() -> None:
    with pytest.raises(ValueError, match="task"):
        compute_jvr_metrics((task(), task()))


@pytest.mark.parametrize("across_pools", [False, True])
def test_duplicate_candidate_ids_are_rejected_within_a_task(across_pools) -> None:
    candidate = CandidateJudgment("same", JudgmentOutcome.FAIL)
    with pytest.raises(ValueError, match="candidate"):
        replace(
            task(), incorrect_candidates=(candidate,) if across_pools else (candidate, candidate),
            correct_candidates=(CandidateJudgment("same", JudgmentOutcome.PASS),) if across_pools
            else (CandidateJudgment("other", JudgmentOutcome.PASS),),
        )


@pytest.mark.parametrize("identifier", ["", " ", " padded", "line\nbreak", "\x00"])
def test_invalid_ids_cannot_make_ambiguous_records(identifier) -> None:
    with pytest.raises(ValueError):
        task(identifier)
    with pytest.raises(ValueError):
        CandidateJudgment(identifier, JudgmentOutcome.FAIL)


@pytest.mark.parametrize("outcome", ["PASS", "unexpected", None, 0])
def test_statuses_require_explicit_validated_outcome_members(outcome) -> None:
    with pytest.raises(ValueError, match="outcome"):
        CandidateJudgment("candidate", cast("JudgmentOutcome", outcome))
    with pytest.raises(ValueError, match="outcome"):
        replace(task(), buggy_outcome=outcome)
    with pytest.raises(ValueError, match="outcome"):
        replace(task(), reference_outcome=outcome)


def test_mutable_or_untyped_candidate_pools_are_rejected() -> None:
    with pytest.raises(ValueError, match="tuple"):
        replace(task(), incorrect_candidates=[CandidateJudgment("bad", JudgmentOutcome.FAIL)])
    with pytest.raises(ValueError, match="CandidateJudgment"):
        replace(task(), incorrect_candidates=("FAIL",))


def test_metrics_and_nested_input_records_are_frozen() -> None:
    record = task()
    report = compute_jvr_metrics((record,))
    for value, name, replacement in (
        (record, "task_id", "changed"),
        (record.incorrect_candidates[0], "outcome", JudgmentOutcome.PASS),
        (report, "wdr", 0.0),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value, name, replacement)


@pytest.mark.parametrize("rate", [-0.1, 1.1, float("nan"), float("inf"), True])
def test_report_rejects_invalid_rates(rate) -> None:
    with pytest.raises(ValueError):
        replace(compute_jvr_metrics(()), grr=rate)


def test_report_rejects_invalid_task_count() -> None:
    with pytest.raises(ValueError):
        replace(compute_jvr_metrics(()), task_count=-1)
    with pytest.raises(ValueError):
        replace(compute_jvr_metrics(()), task_count=True)
    assert isinstance(compute_jvr_metrics(()), JVRMetrics)


def test_non_record_tasks_are_rejected() -> None:
    with pytest.raises(ValueError, match="TaskJudgments"):
        compute_jvr_metrics(cast("tuple[TaskJudgments, ...]", ("bad",)))

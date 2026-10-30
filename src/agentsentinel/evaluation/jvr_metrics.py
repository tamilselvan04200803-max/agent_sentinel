"""SWEPatchTest rates computed only from recorded judgments; nothing is executed.

Definitions follow https://arxiv.org/html/2610.18004v1, sections 2.5 and C.2.
For N tasks, GRR averages I[buggy FAIL and reference PASS]. WDR and CAR are
macro means of each task's rejected incorrect / all incorrect and accepted
correct / all correct candidates, respectively. CT-WDR and CT-CAR average the
indicators that those per-task fractions equal one. F1 = H(WDR, CAR) and
CT-F1 = H(CT-WDR, CT-CAR), with H(a,b)=2ab/(a+b), or zero when both are zero.
JVR averages I[GRR condition and CT-WDR condition and CT-CAR condition] on the
SAME task. All rates are fractions in [0, 1], not percentages.

Each task must retain its fixed, nonempty incorrect and correct candidate
pools. Missing, flaky, unresolved, timed-out and infrastructure outcomes stay
in their denominators and earn no acceptance or rejection credit. Empty pools
are rejected to avoid vacuous completeness; a zero-task input yields zero
rates and task_count=0. These are aggregation conventions, not benchmark
measurements or evidence that a caller's supplied candidate labels are true.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


class JudgmentOutcome(StrEnum):
    """Only stable behavioral PASS/FAIL count; other outcomes are inconclusive.

    FAIL must describe a behavioral test rejection, never a setup error or
    arbitrary nonzero process exit. Callers are responsible for recording that
    distinction and reproducibility; this module does not infer it from logs.
    """

    PASS = "PASS"  # noqa: S105 -- behavioral test outcome, not a secret
    FAIL = "FAIL"
    UNRESOLVED = "UNRESOLVED"
    TIMEOUT = "TIMEOUT"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"
    MISSING = "MISSING"
    FLAKY = "FLAKY"


def _validate_identifier(identifier: str) -> None:
    if (
        not isinstance(identifier, str) or not identifier
        or identifier.strip() != identifier or not identifier.isprintable()
    ):
        raise ValueError("Identifiers must be nonempty printable strings without outer whitespace")


@dataclass(frozen=True, slots=True)
class CandidateJudgment:
    """One member of a fixed candidate pool, including an explicit unknown."""

    candidate_id: str
    outcome: JudgmentOutcome

    def __post_init__(self) -> None:
        _validate_identifier(self.candidate_id)
        if not isinstance(self.outcome, JudgmentOutcome):
            raise ValueError("Candidate outcome must be a JudgmentOutcome member")


@dataclass(frozen=True, slots=True)
class TaskJudgments:
    """Immutable recorded outcomes with unique candidate IDs scoped to this task.

    Incorrect/correct pool membership is supplied ground truth. Candidate IDs
    cannot repeat within either pool or across the two pools of the same task;
    different tasks may reuse their own candidate IDs.
    """

    task_id: str
    buggy_outcome: JudgmentOutcome
    reference_outcome: JudgmentOutcome
    incorrect_candidates: tuple[CandidateJudgment, ...]
    correct_candidates: tuple[CandidateJudgment, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.task_id)
        for outcome in (self.buggy_outcome, self.reference_outcome):
            if not isinstance(outcome, JudgmentOutcome):
                raise ValueError("Buggy and reference outcomes must be JudgmentOutcome members")
        candidate_ids: set[str] = set()
        for pool in (self.incorrect_candidates, self.correct_candidates):
            if not isinstance(pool, tuple):
                raise ValueError("Candidate pools must be immutable tuples")
            if not pool:
                raise ValueError("Both candidate pools must be nonempty")
            for candidate in pool:
                if not isinstance(candidate, CandidateJudgment):
                    raise ValueError("Candidate pools must contain CandidateJudgment records")
                if candidate.candidate_id in candidate_ids:
                    raise ValueError("Duplicate candidate ID in task")
                candidate_ids.add(candidate.candidate_id)


@dataclass(frozen=True, slots=True)
class JVRMetrics:
    """Task count and validated [0,1] rates; no execution or provenance claim."""

    task_count: int
    grr: float
    wdr: float
    car: float
    ct_wdr: float
    ct_car: float
    f1: float
    ct_f1: float
    jvr: float

    def __post_init__(self) -> None:
        if type(self.task_count) is not int or self.task_count < 0:
            raise ValueError("task_count must be a nonnegative integer")
        for rate in (
            self.grr, self.wdr, self.car, self.ct_wdr, self.ct_car, self.f1, self.ct_f1, self.jvr,
        ):
            if type(rate) not in (int, float) or not 0.0 <= rate <= 1.0:
                raise ValueError("Metric rates must be finite numbers in [0, 1]")


def _harmonic_mean(left: float, right: float) -> float:
    return 2.0 * left * right / (left + right) if left + right else 0.0


def compute_jvr_metrics(tasks: Iterable[TaskJudgments]) -> JVRMetrics:
    """Aggregate every supplied task once; never drop inconclusive judgments.

    Duplicate task IDs are rejected rather than implicitly weighting a task.
    Nonempty candidate pools are enforced by TaskJudgments at construction.
    """
    records = tuple(tasks)
    task_ids: set[str] = set()
    wrong_detection_rates: list[float] = []
    correct_acceptance_rates: list[float] = []
    regression_count = 0
    complete_detection_count = 0
    complete_acceptance_count = 0
    joint_count = 0
    for record in records:
        if not isinstance(record, TaskJudgments):
            raise ValueError("tasks must contain TaskJudgments records")
        if record.task_id in task_ids:
            raise ValueError("Duplicate task ID")
        task_ids.add(record.task_id)
        regression = (
            record.buggy_outcome is JudgmentOutcome.FAIL
            and record.reference_outcome is JudgmentOutcome.PASS
        )
        rejected = sum(
            candidate.outcome is JudgmentOutcome.FAIL for candidate in record.incorrect_candidates
        )
        accepted = sum(
            candidate.outcome is JudgmentOutcome.PASS for candidate in record.correct_candidates
        )
        complete_detection = rejected == len(record.incorrect_candidates)
        complete_acceptance = accepted == len(record.correct_candidates)
        wrong_detection_rates.append(rejected / len(record.incorrect_candidates))
        correct_acceptance_rates.append(accepted / len(record.correct_candidates))
        regression_count += regression
        complete_detection_count += complete_detection
        complete_acceptance_count += complete_acceptance
        joint_count += regression and complete_detection and complete_acceptance

    count = len(records)
    denominator = count or 1  # Explicit zero-task convention: every numerator is zero.
    wdr = math.fsum(wrong_detection_rates) / denominator
    car = math.fsum(correct_acceptance_rates) / denominator
    ct_wdr = complete_detection_count / denominator
    ct_car = complete_acceptance_count / denominator
    return JVRMetrics(
        task_count=count, grr=regression_count / denominator, wdr=wdr, car=car,
        ct_wdr=ct_wdr, ct_car=ct_car, f1=_harmonic_mean(wdr, car),
        ct_f1=_harmonic_mean(ct_wdr, ct_car), jvr=joint_count / denominator,
    )

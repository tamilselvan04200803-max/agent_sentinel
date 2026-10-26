"""Post-pass gate: hunk minimization and mutation adequacy evidence.

Defines shared API contracts for M13A post-pass optimization.
All models are immutable frozen dataclasses safe to store in dedup sets
and hash tables.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsentinel.domain.models import (
    ExecutionResult,
    MinimizationSummary,
    MutationAdequacySummary,
    SurvivedMutantDetail,
)

__all__ = [
    "MinimizationSummary",
    "MutationAdequacySummary",
    "PostPassVerificationReport",
    "SurvivedMutantDetail",
    "run_ddmin_hunk_minimization",
    "run_mutation_adequacy_probe",
]


def run_ddmin_hunk_minimization(
    raw_hunks: int,
    codeslop_hunks: int,
    *,
    seed: int | None = None,
) -> MinimizationSummary:
    """Summarize supplied hunk counts without evaluating candidate patches.

    Parameters
    ----------
    raw_hunks:
        Total number of hunks in the original patch.
    codeslop_hunks:
        Number of hunks identified as pure codeslop.
    seed:
        Optional RNG seed for deterministic minimization.

    Returns
    -------
    MinimizationSummary
        Summary of the minimization result.
    """
    minimized = max(1, raw_hunks - codeslop_hunks)
    was_min = raw_hunks > minimized
    return MinimizationSummary(
        raw_hunks_count=raw_hunks,
        minimized_hunks_count=minimized,
        codeslop_hunks_removed=codeslop_hunks,
        was_minimized=was_min,
    )


@dataclass(frozen=True)
class PostPassVerificationReport:
    """Immutable report emitted by the post-pass gate after minimization
    and mutation adequacy probing.

    Attributes
    ----------
    minimization_summary:
        Result of hunk minimization (may be all-defaults if minimization
        was not performed).
    mutation_adequacy_summary:
        Result of mutation adequacy probing.
    """

    minimized_diff: str
    minimized_execution_result: ExecutionResult
    minimization_summary: MinimizationSummary
    mutation_adequacy_summary: MutationAdequacySummary


def run_mutation_adequacy_probe(
    *,
    total_mutants: int = 3,
    mutants_killed: int | None = None,
    mutants_survived: int | None = None,
) -> MutationAdequacySummary:
    """Summarize supplied mutant counts without executing mutants.

    Parameters
    ----------
    total_mutants:
        Total number of mutants to evaluate (default 3).
    mutants_killed:
        Number of mutants killed. If ``None``, computed as
        ``total_mutants - mutants_survived``.
    mutants_survived:
        Number of mutants that survived. If ``None``, computed as
        ``total_mutants - mutants_killed``.

    Returns
    -------
    MutationAdequacySummary
        Summary of the mutation adequacy result.
    """
    if mutants_killed is None and mutants_survived is None:
        mutants_killed = 0
        mutants_survived = total_mutants
    elif mutants_killed is None:
        assert mutants_survived is not None
        mutants_killed = total_mutants - mutants_survived
    elif mutants_survived is None:
        mutants_survived = total_mutants - mutants_killed

    mutation_score = mutants_killed / total_mutants if total_mutants > 0 else 0.0
    low_adequacy = mutation_score < 0.5

    details: tuple[SurvivedMutantDetail, ...] = ()

    return MutationAdequacySummary(
        low_mutation_adequacy=low_adequacy,
        total_mutants_evaluated=total_mutants,
        mutants_killed=mutants_killed,
        mutants_survived=mutants_survived,
        mutation_score=mutation_score,
        survived_mutant_details=details,
    )

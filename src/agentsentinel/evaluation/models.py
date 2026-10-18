"""M5: Evaluation harness schemas (contamination-aware benchmark)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from agentsentinel.domain.models import CaseSpec


@dataclass(frozen=True)
class BenchmarkCase:
    """A single benchmark case with admission-gate inputs.

    The ``reference_fix_patch`` is TRUSTED INPUT used ONLY by the admission gate
    to verify the test + fix pair is internally consistent. It MUST NEVER be
    passed to the LLM prompt builder or repair state machine.
    """

    case_spec: CaseSpec
    repo_source_path: Path
    base_commit: str
    test_patch: str
    reference_fix_patch: str
    fail_to_pass_tests: tuple[str, ...]
    pass_to_pass_tests: tuple[str, ...] = ()
    is_public_historical_commit: bool = True


@dataclass(frozen=True)
class AdmissionVerdict:
    """Result of running the admission gate for a single case."""

    case_id: str
    admitted: bool
    reason: str
    baseline_exit_code: int | None = None
    reference_exit_code: int | None = None
    prep_duration_seconds: float = 0.0


@dataclass(frozen=True)
class ExclusionRecord:
    """Record of a case rejected by the admission gate (never silently omitted)."""

    case_id: str
    reason: str
    baseline_exit_code: int | None
    reference_exit_code: int | None
    prep_duration_seconds: float


@dataclass(frozen=True)
class CaseEvaluationResult:
    """Outcome of running a single admitted case through RepairStateMachine."""

    case_id: str
    admitted: bool
    repair_duration_seconds: float
    prep_duration_seconds: float
    terminated_state: str
    termination_reason: str | None
    attempts_used: int
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    is_public: bool
    policy_violation_count: int = 0

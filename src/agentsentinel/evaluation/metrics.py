"""M5: Honest telemetry & aggregation for the evaluation harness.

Cost accounting is strict: unknown cost (models not in PricingRegistry) is
NEVER coerced to 0.0. When any run has unknown cost, totals are reported as
None and the unknown-cost counter is incremented so the report clearly flags
partial cost information.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from agentsentinel.evaluation.models import (
    AdmissionVerdict,
    CaseEvaluationResult,
    ExclusionRecord,
)

__all__ = [
    "BenchmarkReport",
    "CaseEvaluationResult",
    "ComparisonReport",
    "_aggregate",
]


@dataclass(frozen=True)
class ComparisonReport:
    """Single-proposal baseline vs bounded-retry comparison."""

    baseline_max_attempts: int
    bounded_max_attempts: int
    cases_count: int
    baseline_repair_rate: float
    bounded_repair_rate: float
    baseline_total_llm_calls: int
    bounded_total_llm_calls: int
    baseline_total_input_tokens: int
    bounded_total_input_tokens: int
    baseline_total_output_tokens: int
    bounded_total_output_tokens: int
    baseline_total_latency_seconds: float
    bounded_total_latency_seconds: float
    delta_repair_rate: float
    delta_llm_calls: int
    delta_input_tokens: int
    delta_output_tokens: int
    delta_latency_seconds: float


@dataclass(frozen=True)
class BenchmarkReport:
    """Aggregated benchmark results.

    All fields are computed deterministically at construction time and are
    safe to serialize directly (JSON or Markdown).
    """

    # Counts
    total_cases_submitted: int
    admitted_cases_count: int
    excluded_cases_count: int
    verified_repair_count: int
    duplicate_patch_termination_count: int
    infrastructure_failure_count: int
    public_contamination_count: int
    unknown_cost_runs_count: int

    # Rates
    verified_repair_rate: float
    policy_violation_rate: float

    # Latency (strictly separated)
    total_prep_latency_seconds: float
    total_repair_latency_seconds: float

    # Token & cost
    total_input_tokens: int
    total_output_tokens: int
    known_cost_usd_total: float | None  # None if any case had unknown cost

    # Breakdowns
    exclusion_log: tuple[ExclusionRecord, ...]
    failure_category_breakdown: tuple[tuple[str, int], ...]
    per_case_results: tuple[CaseEvaluationResult, ...]

    # Provenance
    generated_at_utc: str
    suite_name: str

    def to_json(self, indent: int = 2) -> str:
        """Canonical JSON (sort_keys) for deterministic artifact hashing."""
        return json.dumps(asdict(self), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        """Human-readable Markdown summary."""
        lines: list[str] = []
        lines.append(f"# Benchmark Report: {self.suite_name}")
        lines.append("")
        lines.append(f"Generated at (UTC): {self.generated_at_utc}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Total cases submitted: **{self.total_cases_submitted}**")
        lines.append(f"- Admitted: **{self.admitted_cases_count}**")
        lines.append(f"- Excluded: **{self.excluded_cases_count}**")
        lines.append(f"- Verified repairs: **{self.verified_repair_count}**")
        lines.append(f"- Verified repair rate: **{self.verified_repair_rate:.2%}**")
        lines.append(
            f"- Policy violation rate: **{self.policy_violation_rate:.2%}**"
        )
        lines.append(
            f"- Duplicate-patch terminations: **{self.duplicate_patch_termination_count}**"
        )
        lines.append(
            f"- Infrastructure failures: **{self.infrastructure_failure_count}**"
        )
        lines.append(
            "- Public-historical (potentially contaminated) cases: "
            f"**{self.public_contamination_count}**"
        )
        lines.append("")
        lines.append("## Latency")
        lines.append("")
        lines.append(
            "- Total prep (admission-gate) latency: "
            f"{self.total_prep_latency_seconds:.2f}s"
        )
        lines.append(
            "- Total repair (state-machine) latency: "
            f"{self.total_repair_latency_seconds:.2f}s"
        )
        lines.append("")
        lines.append("## Tokens & Cost")
        lines.append("")
        lines.append(f"- Total input tokens: {self.total_input_tokens}")
        lines.append(f"- Total output tokens: {self.total_output_tokens}")
        if self.known_cost_usd_total is None:
            lines.append("- **Known cost total: PARTIAL / UNKNOWN** "
                         f"({self.unknown_cost_runs_count} runs had unpriced models)")
        else:
            lines.append(f"- Known cost total: ${self.known_cost_usd_total:.4f} USD")
        lines.append("")
        if self.exclusion_log:
            lines.append("## Excluded Cases")
            lines.append("")
            for ex in self.exclusion_log:
                lines.append(f"- `{ex.case_id}`: {ex.reason} "
                             f"(prep {ex.prep_duration_seconds:.2f}s)")
            lines.append("")
        lines.append("## Failure Breakdown (by TerminationReason)")
        lines.append("")
        for reason, count in self.failure_category_breakdown:
            lines.append(f"- `{reason}`: {count}")
        lines.append("")
        return "\n".join(lines)


def _aggregate(
    verdicts: list[AdmissionVerdict],
    case_results: list[CaseEvaluationResult],
    total_policy_violations: int,
    total_attempts: int,
    suite_name: str,
    generated_at_utc: str,
) -> BenchmarkReport:
    """Deterministic aggregation helper used by the harness."""
    from datetime import UTC, datetime
    admitted = [r for r in case_results if r.admitted]
    excluded = [
        ExclusionRecord(
            case_id=v.case_id,
            reason=v.reason,
            baseline_exit_code=v.baseline_exit_code,
            reference_exit_code=v.reference_exit_code,
            prep_duration_seconds=v.prep_duration_seconds,
        )
        for v in verdicts
        if not v.admitted
    ]
    verified = sum(
        1 for r in admitted
        if r.terminated_state == "APPROVED" or r.termination_reason == "FIX_VERIFIED"
    )
    duplicate_count = sum(
        1 for r in admitted if r.termination_reason == "DUPLICATE_PATCH"
    )
    infra_count = sum(
        1 for r in admitted if r.termination_reason == "INFRASTRUCTURE_FAILURE"
    )
    public_count = sum(1 for r in case_results if r.is_public)
    unknown_cost = sum(1 for r in admitted if r.cost_usd is None)
    admitted_n = len(admitted)
    verified_rate = verified / admitted_n if admitted_n else 0.0
    per_case_policy = sum(r.policy_violation_count for r in admitted)
    effective_policy_violations = total_policy_violations or per_case_policy
    policy_rate = effective_policy_violations / total_attempts if total_attempts else 0.0
    total_prep = sum(v.prep_duration_seconds for v in verdicts)
    total_repair = sum(r.repair_duration_seconds for r in admitted)
    total_in_tok = sum(r.input_tokens for r in admitted)
    total_out_tok = sum(r.output_tokens for r in admitted)
    known_costs = [r.cost_usd for r in admitted if r.cost_usd is not None]
    known_total: float | None
    if unknown_cost > 0 or not admitted_n:
        known_total = None if unknown_cost > 0 else 0.0
    else:
        known_total = sum(known_costs)
    # Failure breakdown by termination reason (canonical sorted order)
    reason_counts: dict[str, int] = {}
    for r in admitted:
        key = r.termination_reason or r.terminated_state
        reason_counts[key] = reason_counts.get(key, 0) + 1
    breakdown = tuple(sorted(reason_counts.items()))
    return BenchmarkReport(
        total_cases_submitted=len(verdicts),
        admitted_cases_count=admitted_n,
        excluded_cases_count=len(excluded),
        verified_repair_count=verified,
        duplicate_patch_termination_count=duplicate_count,
        infrastructure_failure_count=infra_count,
        public_contamination_count=public_count,
        unknown_cost_runs_count=unknown_cost,
        verified_repair_rate=verified_rate,
        policy_violation_rate=policy_rate,
        total_prep_latency_seconds=total_prep,
        total_repair_latency_seconds=total_repair,
        total_input_tokens=total_in_tok,
        total_output_tokens=total_out_tok,
        known_cost_usd_total=known_total,
        exclusion_log=tuple(excluded),
        failure_category_breakdown=breakdown,
        per_case_results=tuple(case_results),
        generated_at_utc=generated_at_utc or datetime.now(UTC).isoformat(),
        suite_name=suite_name,
    )

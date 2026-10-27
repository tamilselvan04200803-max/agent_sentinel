"""Verification package for anti-overfitting guards."""

from __future__ import annotations

from agentsentinel.verification.ci_gate import (
    CI_GATE_FAILED,
    CI_GATE_PASSED,
    CI_GATE_USAGE_ERROR,
    CIGateReport,
    CIGateUsageError,
    CIGateViolation,
    FileAuditMetrics,
    FileLifecycleStatus,
    SourceMapEntry,
    ViolationSeverity,
    reconstruct_in_memory_source_map,
    render_ci_gate_json,
    render_ci_gate_markdown,
    run_ci_gate_audit,
)
from agentsentinel.verification.differential_mutation import (
    DifferentialPatchMutant,
    generate_differential_patch_mutants,
)
from agentsentinel.verification.mutation_batch import (
    MutantExecutionResult,
    run_in_container_mutation_batch_detailed,
)
from agentsentinel.verification.mutation_probe import (
    PatchMutant,
    generate_patch_mutants,
)
from agentsentinel.verification.overfit_guard import (
    check_patch_hygiene,
    extract_test_assertion_literals,
    verify_not_overfitted,
)
from agentsentinel.verification.patch_minimizer import (
    check_ast_bloat_and_debug_residue,
    compute_cyclomatic_complexity,
    generate_minimal_hunk_subsets,
)
from agentsentinel.verification.post_pass_gate import (
    MinimizationSummary,
    MutationAdequacySummary,
    PostPassVerificationReport,
    SurvivedMutantDetail,
    run_ddmin_hunk_minimization,
    run_mutation_adequacy_probe,
)
from agentsentinel.verification.second_order_guard import (
    ERR_M13C_ABRUPT_FINALLY_EXIT,
    ERR_M13C_CONTEXT_SUPPRESSION,
    ERR_M13C_INDIRECT_REFLECTION,
    ERR_M13C_OBFUSCATED_LITERAL,
    ERR_M13C_TOPLEVEL_SIDEEFFECT,
    SecondOrderEvasionMetrics,
    SecondOrderFinding,
    analyze_second_order_evasion,
    get_second_order_evasion_metrics,
    reset_second_order_evasion_metrics,
    verify_second_order_evasion,
)
from agentsentinel.verification.symbolic_constants import fold_symbolic_constant

__all__ = [
    "MutantExecutionResult", "run_in_container_mutation_batch_detailed",
    "ERR_M13C_ABRUPT_FINALLY_EXIT", "ERR_M13C_CONTEXT_SUPPRESSION",
    "ERR_M13C_INDIRECT_REFLECTION", "ERR_M13C_OBFUSCATED_LITERAL",
    "ERR_M13C_TOPLEVEL_SIDEEFFECT", "SecondOrderEvasionMetrics", "SecondOrderFinding",
    "analyze_second_order_evasion", "fold_symbolic_constant",
    "get_second_order_evasion_metrics", "reset_second_order_evasion_metrics",
    "verify_second_order_evasion",
    "CI_GATE_FAILED", "CI_GATE_PASSED", "CI_GATE_USAGE_ERROR", "CIGateReport",
    "CIGateUsageError", "CIGateViolation", "FileAuditMetrics", "FileLifecycleStatus",
    "SourceMapEntry", "ViolationSeverity", "reconstruct_in_memory_source_map",
    "render_ci_gate_json", "render_ci_gate_markdown", "run_ci_gate_audit",
    "DifferentialPatchMutant",
    "PatchMutant",
    "check_ast_bloat_and_debug_residue",
    "check_patch_hygiene",
    "compute_cyclomatic_complexity",
    "extract_test_assertion_literals",
    "generate_minimal_hunk_subsets",
    "generate_differential_patch_mutants",
    "generate_patch_mutants",
    "verify_not_overfitted",
    "MinimizationSummary",
    "MutationAdequacySummary",
    "PostPassVerificationReport",
    "run_ddmin_hunk_minimization",
    "run_mutation_adequacy_probe",
    "SurvivedMutantDetail",
]

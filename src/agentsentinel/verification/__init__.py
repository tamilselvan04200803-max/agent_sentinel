"""Verification package for anti-overfitting guards."""

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

__all__ = [
    "PatchMutant",
    "check_ast_bloat_and_debug_residue",
    "check_patch_hygiene",
    "compute_cyclomatic_complexity",
    "extract_test_assertion_literals",
    "generate_minimal_hunk_subsets",
    "generate_patch_mutants",
    "verify_not_overfitted",
]

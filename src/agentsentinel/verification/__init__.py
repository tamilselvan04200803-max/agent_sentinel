"""Verification package for anti-overfitting guards."""

from agentsentinel.verification.overfit_guard import (
    check_patch_hygiene,
    extract_test_assertion_literals,
    verify_not_overfitted,
)

__all__ = [
    "check_patch_hygiene",
    "extract_test_assertion_literals",
    "verify_not_overfitted",
]

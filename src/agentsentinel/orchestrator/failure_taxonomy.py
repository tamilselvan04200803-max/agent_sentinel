"""Deterministic retry guidance; classifications never grant execution rights."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import (
    HarnessTimeoutError,
    MalformedDiffError,
    OverfitPolicyError,
    PatchPolicyError,
    PathTraversalError,
    SymlinkEscapeError,
)
from agentsentinel.policy.applier import PatchApplicationError

if TYPE_CHECKING:
    from agentsentinel.domain.models import ExecutionResult


class FailureCategory(StrEnum):
    """Repair-level failure categories; transport/infrastructure retain their lifecycle."""

    PATCH_FORMAT_OR_HUNK_MISMATCH = "PATCH_FORMAT_OR_HUNK_MISMATCH"
    OVERFIT_OR_HARDCODED_LITERAL = "OVERFIT_OR_HARDCODED_LITERAL"
    API_CONTRACT_OR_BLOAT_VIOLATION = "API_CONTRACT_OR_BLOAT_VIOLATION"
    POLICY_PATH_OR_TEST_TAMPERING = "POLICY_PATH_OR_TEST_TAMPERING"
    TEST_ASSERTION_VALUE_MISMATCH = "TEST_ASSERTION_VALUE_MISMATCH"
    RUNTIME_EXCEPTION_OR_IMPORT_ERROR = "RUNTIME_EXCEPTION_OR_IMPORT_ERROR"
    EXECUTION_TIMEOUT_OR_INFINITE_LOOP = "EXECUTION_TIMEOUT_OR_INFINITE_LOOP"


_DIRECTIVES: dict[FailureCategory, str] = {
    FailureCategory.PATCH_FORMAT_OR_HUNK_MISMATCH: (
        "Regenerate a valid unified diff against the provided baseline. "
        "Check file headers, exact context and hunk coordinates; preserve unchanged lines."
    ),
    FailureCategory.OVERFIT_OR_HARDCODED_LITERAL: (
        "Implement a general repair without test-specific literals, reflection or harness access. "
        "Derive behavior from the input and the stated contract."
    ),
    FailureCategory.API_CONTRACT_OR_BLOAT_VIOLATION: (
        "Preserve public symbols, calling conventions and optional defaults. "
        "Remove debugger residue, excessive branches and swallowing exception handlers."
    ),
    FailureCategory.POLICY_PATH_OR_TEST_TAMPERING: (
        "Limit edits to the allowed source paths. Preserve tests, configuration and "
        "sandbox boundaries; do not rename protected files or follow escaping links."
    ),
    FailureCategory.TEST_ASSERTION_VALUE_MISMATCH: (
        "Trace the failing assertion to the source behavior and correct the general logic. "
        "Preserve test assertions and avoid hardcoding expected outputs."
    ),
    FailureCategory.RUNTIME_EXCEPTION_OR_IMPORT_ERROR: (
        "Inspect the execution diagnostics for invalid operations, missing imports or "
        "collection failures. Correct the source cause while preserving the public API."
    ),
    FailureCategory.EXECUTION_TIMEOUT_OR_INFINITE_LOOP: (
        "Ensure loops and recursion terminate and avoid blocking work. "
        "Simplify the algorithm within the existing execution budget."
    ),
}
_EXCEPTION_LINE = re.compile(
    r"^(?:E\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?::|$)", re.MULTILINE,
)
_SUMMARY_LINE = re.compile(r"^(?:FAILED|ERROR)\s+.+?\s+-\s+([\w.]+)(?::|$)", re.MULTILINE)


def classify_attempt_failure(
    error: Exception | None,
    execution_result: ExecutionResult | None,
) -> tuple[FailureCategory, str]:
    """Classify typed exceptions first, otherwise inspect bounded error records.

    Output is untrusted diagnostic evidence, never an authority for policy,
    approval or lifecycle decisions. Directives contain no supplied content.
    """
    category = FailureCategory.RUNTIME_EXCEPTION_OR_IMPORT_ERROR
    if isinstance(error, (HarnessTimeoutError, TimeoutError)):
        category = FailureCategory.EXECUTION_TIMEOUT_OR_INFINITE_LOOP
    elif isinstance(error, (MalformedDiffError, PatchApplicationError)):
        category = FailureCategory.PATCH_FORMAT_OR_HUNK_MISMATCH
    elif isinstance(error, OverfitPolicyError):
        category = (
            FailureCategory.OVERFIT_OR_HARDCODED_LITERAL
            if error.reason_code == "overfit"
            else FailureCategory.API_CONTRACT_OR_BLOAT_VIOLATION
        )
    elif isinstance(error, (PatchPolicyError, PathTraversalError, SymlinkEscapeError)):
        category = FailureCategory.POLICY_PATH_OR_TEST_TAMPERING
    elif error is None:
        if execution_result is None or execution_result.passed:
            raise ValueError("Classification requires a failed execution or an exception")
        output = execution_result.stdout[-8000:] + "\n" + execution_result.stderr[-8000:]
        names = {
            match.rsplit(".", 1)[-1]
            for pattern in (_EXCEPTION_LINE, _SUMMARY_LINE)
            for match in pattern.findall(output)
            if match.endswith(("Error", "Exception"))
        }
        if "TimeoutError" in names:
            category = FailureCategory.EXECUTION_TIMEOUT_OR_INFINITE_LOOP
        elif names - {"AssertionError"}:
            category = FailureCategory.RUNTIME_EXCEPTION_OR_IMPORT_ERROR
        elif "AssertionError" in names:
            category = FailureCategory.TEST_ASSERTION_VALUE_MISMATCH
    return category, _DIRECTIVES[category]

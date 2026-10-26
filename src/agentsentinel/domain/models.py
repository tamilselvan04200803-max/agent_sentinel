"""Immutable domain model schemas for AgentSentinel.

All models use ``@dataclass(frozen=True)`` to guarantee immutability after
construction. Mutable collections (list, dict, set) are replaced with their
immutable counterparts (tuple, frozenset) so that instances are hashable and
safe to store in dedup sets.

Design invariants
-----------------
- Every field that would naturally be a ``list`` uses ``tuple`` instead.
- ``metadata`` is stored as ``tuple[tuple[str, str], ...]`` — a flat tuple-of-pairs
  — so ``CaseSpec`` remains fully hashable (``MappingProxyType`` is not hashable
  when it wraps a dict with unhashable values, so we avoid it here).
- ``datetime`` fields are always UTC-aware (``timezone.utc``).
- No model may hold a reference to an open file handle or subprocess.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentsentinel.domain.exit_codes import ExitCode

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC-aware datetime."""
    return datetime.now(tz=UTC)


def _sha256_of(data: str) -> str:
    """Return the lowercase hex SHA-256 digest of a UTF-8 encoded string."""
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# CaseSpec — the bug case descriptor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseSpec:
    """Immutable descriptor of a software repair case.

    Attributes
    ----------
    case_id:
        Unique identifier for this case (e.g. ``"swebench-django-12345"``).
    repo_url:
        HTTPS URL of the repository to clone.
    base_commit:
        Git SHA that reproduces the bug (the broken state).
    test_command:
        Shell command that runs the failing tests (e.g. ``"pytest tests/ -x"``).
    allowed_edit_paths:
        Allowlist of repo-relative paths the repair agent may modify.
        Any patch outside this set triggers ``AllowlistViolationError``.
    failing_test_ids:
        Pytest node IDs of the tests that must go from FAIL → PASS.
    created_at:
        UTC timestamp of when this spec was constructed.
    metadata:
        Arbitrary read-only key/value pairs (e.g. language, framework version).

    Invariants
    ----------
    - ``base_commit`` must be a 40-character hex string.
    - ``allowed_edit_paths`` must be non-empty.
    - ``failing_test_ids`` must be non-empty.
    """

    case_id: str
    repo_url: str
    base_commit: str
    test_command: str
    allowed_edit_paths: tuple[str, ...]
    failing_test_ids: tuple[str, ...]
    created_at: datetime = field(default_factory=_utcnow)
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if len(self.base_commit) != 40 or not all(  # noqa: PLR2004
            c in "0123456789abcdefABCDEF" for c in self.base_commit
        ):
            raise ValueError(f"base_commit must be a 40-char hex SHA, got {self.base_commit!r}")
        if not self.allowed_edit_paths:
            raise ValueError("allowed_edit_paths must be non-empty")
        if not self.failing_test_ids:
            raise ValueError("failing_test_ids must be non-empty")
        if not self.created_at.tzinfo:
            raise ValueError("created_at must be timezone-aware (UTC)")

        # Validate and canonicalize metadata (lexicographical sorting & duplicate rejection)
        seen_keys: set[str] = set()
        for item in self.metadata:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError(f"metadata items must be (key, value) pairs, got {item!r}")
            k, _ = item
            if k in seen_keys:
                raise ValueError(f"Duplicate metadata key detected: {k!r}")
            seen_keys.add(k)

        sorted_meta = tuple(sorted(self.metadata, key=lambda kv: kv[0]))
        object.__setattr__(self, "metadata", sorted_meta)


# ---------------------------------------------------------------------------
# PatchProposal — a candidate patch from the repair agent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatchProposal:
    """An immutable unified-diff patch proposed by the repair agent.

    Attributes
    ----------
    case_id:
        The ``CaseSpec.case_id`` this patch targets.
    unified_diff:
        The raw unified diff text (``--- a/...  +++ b/...``).
    diff_hash:
        SHA-256 of the *normalised* diff (computed at construction).
    model_id:
        Identifier of the LLM that generated this patch.
    prompt_tokens:
        Number of prompt tokens consumed.
    completion_tokens:
        Number of completion tokens consumed.
    proposed_at:
        UTC timestamp of when the patch was generated.

    Invariants
    ----------
    - ``unified_diff`` must be non-empty.
    - ``diff_hash`` is auto-computed and cannot be overridden externally.
    """

    case_id: str
    unified_diff: str
    model_id: str
    prompt_tokens: int
    completion_tokens: int
    proposed_at: datetime = field(default_factory=_utcnow)
    # diff_hash is computed in __post_init__; use object.__setattr__ because frozen=True
    diff_hash: str = field(init=False, default="")

    def __post_init__(self) -> None:
        if not self.unified_diff.strip():
            raise ValueError("unified_diff must be non-empty")
        if self.prompt_tokens < 0 or self.completion_tokens < 0:
            raise ValueError("token counts must be non-negative")
        # Frozen dataclass: bypass immutability enforcement for computed field
        object.__setattr__(self, "diff_hash", _sha256_of(self.unified_diff))


# ---------------------------------------------------------------------------
# MinimizationSummary — post-pass hunk minimization summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MinimizationSummary:
    """Result of ddmin-style hunk minimization applied to a patch.

    Attributes
    ----------
    raw_hunks_count:
        Number of hunks in the original unified diff before minimization.
    minimized_hunks_count:
        Number of hunks remaining after minimization.
    codeslop_hunks_removed:
        Number of hunks removed because they consisted entirely of
        non-functional "code slop" (e.g. inert imports, commented-out
        blocks).
    was_minimized:
        ``True`` iff minimization was actually performed (i.e.
        ``raw_hunks_count > minimized_hunks_count``).
    """

    raw_hunks_count: int
    minimized_hunks_count: int
    codeslop_hunks_removed: int
    was_minimized: bool


# ---------------------------------------------------------------------------
# SurvivedMutantDetail — detail of a single surviving mutant
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SurvivedMutantDetail:
    """Detail of a single mutant that survived test execution."""

    mutant_id: str
    file_path: str
    function_name: str
    mutation_description: str


# ---------------------------------------------------------------------------
# MutationAdequacySummary — post-pass mutation adequacy summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutationAdequacySummary:
    """Result of mutation adequacy probing after patch acceptance.

    Attributes
    ----------
    low_mutation_adequacy:
        ``True`` iff mutation score falls below the acceptable threshold.
    total_mutants_evaluated:
        Total number of mutants generated and executed.
    mutants_killed:
        Number of mutants successfully killed by the test suite.
    mutants_survived:
        Number of mutants that survived test execution.
    mutation_score:
        Fraction of mutants killed, in ``[0, 1]``.
    survived_mutant_details:
        Immutable tuple of ``SurvivedMutantDetail`` instances.
    """

    low_mutation_adequacy: bool
    total_mutants_evaluated: int
    mutants_killed: int
    mutants_survived: int
    mutation_score: float
    survived_mutant_details: tuple[SurvivedMutantDetail, ...] = ()


# ---------------------------------------------------------------------------
# ExecutionResult — output from a sandbox run
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionResult:
    """Immutable record of a single sandbox test-suite execution.

    Attributes
    ----------
    case_id:
        The case this result belongs to.
    patch_diff_hash:
        ``PatchProposal.diff_hash`` of the patch that was applied, or
        ``"baseline"`` for an unpatched baseline run.
    exit_code:
        Typed pytest exit code.
    stdout:
        Captured standard output (may be truncated; see ``stdout_truncated``).
    stderr:
        Captured standard error (may be truncated; see ``stderr_truncated``).
    wall_seconds:
        Total wall-clock duration of the sandbox run.
    stdout_truncated:
        ``True`` if stdout exceeded the capture limit and was truncated.
    stderr_truncated:
        ``True`` if stderr exceeded the capture limit and was truncated.
    expected_test_ids:
        Optional tuple of test node IDs that MUST have run and passed. When
        provided, ``passed`` only returns True if every listed test ID appears
        in ``stdout`` with a PASSED marker — this prevents an empty test run
        (or a suite that silently skipped the failing tests) from being
        incorrectly classified as a pass.
    executed_at:
        UTC timestamp of when execution completed.

    Invariants
    ----------
    - ``wall_seconds`` must be ≥ 0.
    - ``exit_code`` must be a valid ``ExitCode`` member.
    """

    case_id: str
    patch_diff_hash: str
    exit_code: ExitCode
    stdout: str
    stderr: str
    wall_seconds: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    expected_test_ids: tuple[str, ...] | None = None
    executed_at: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        if self.wall_seconds < 0:
            raise ValueError(f"wall_seconds must be ≥ 0, got {self.wall_seconds}")
        # Validate exit_code is a known ExitCode
        ExitCode(self.exit_code)  # raises ValueError for unknown codes

    @staticmethod
    def _test_passed_in_output(test_id: str, stdout: str) -> bool:
        """Check whether ``test_id`` is reported as PASSED in pytest stdout.

        Pytest prints lines like ``tests/test_x.py::test_fn PASSED`` for each
        passing node. We match the test node ID followed by whitespace and the
        word ``PASSED`` to be robust against varying output formats.
        """
        import re

        # Escape the test ID for regex safety and look for " PASSED"
        pattern = re.escape(test_id) + r"\s+PASSED"
        return re.search(pattern, stdout) is not None

    @property
    def passed(self) -> bool:
        """True iff exit_code==OK AND every expected test actually ran and passed.

        If ``expected_test_ids`` is None (legacy/test construction), we fall back
        to the bare exit_code check. When expected_test_ids is provided, each
        ID must appear in ``stdout`` with a PASSED marker — this guards against
        reward-hacking scenarios where the test command exits 0 but actually
        ran zero tests (e.g. ``pytest`` with a misconfigured ``--ignore`` or a
        malicious ``conftest.py`` that short-circuits collection).
        """
        if self.exit_code != ExitCode.OK:
            return False
        if self.expected_test_ids is None:
            return True
        # Verify every expected failing test actually ran and passed
        return all(self._test_passed_in_output(tid, self.stdout) for tid in self.expected_test_ids)

    @property
    def failed(self) -> bool:
        """True iff the test suite returned ExitCode.TESTS_FAILED."""
        return self.exit_code == ExitCode.TESTS_FAILED


# ---------------------------------------------------------------------------
# EvidenceBundle — the final audit record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceBundle:
    """Immutable audit record emitted at the conclusion of a repair attempt.

    Contains every artefact needed to reproduce and verify the repair:
    baseline result, accepted patch, post-patch result, and cost accounting.

    Attributes
    ----------
    case_id:
        The repaired case.
    spec:
        The original ``CaseSpec``.
    baseline_result:
        Execution result before any patch (must show TESTS_FAILED).
    accepted_patch:
        The ``PatchProposal`` that achieved ExitCode.OK, or ``None`` if repair
        failed after exhausting all attempts.
    final_result:
        Execution result after applying ``accepted_patch`` (or the last failed
        attempt if no patch worked).
    total_prompt_tokens:
        Cumulative prompt tokens across all LLM calls.
    total_completion_tokens:
        Cumulative completion tokens across all LLM calls.
    repair_succeeded:
        ``True`` iff ``final_result.exit_code == ExitCode.OK``.
    attempts:
        Number of patch proposals attempted.
    bundle_hash:
        SHA-256 of the canonical JSON representation of this bundle.

    Invariants
    ----------
    - ``baseline_result.exit_code`` must NOT be ``ExitCode.OK`` (it must be broken).
    - ``repair_succeeded`` is a computed property — NOT a settable field.
    """

    case_id: str
    spec: CaseSpec
    baseline_result: ExecutionResult
    accepted_patch: PatchProposal | None
    final_result: ExecutionResult
    total_prompt_tokens: int
    total_completion_tokens: int
    attempts: int
    minimization_summary: MinimizationSummary | None = None
    mutation_adequacy_summary: MutationAdequacySummary | None = None
    # bundle_hash is computed in __post_init__
    bundle_hash: str = field(init=False, default="")

    def __post_init__(self) -> None:
        if self.baseline_result.exit_code == ExitCode.OK:
            raise ValueError("baseline_result must NOT be OK — the baseline must reproduce the bug")
        if self.attempts < 1:
            raise ValueError(f"attempts must be ≥ 1, got {self.attempts}")
        if self.total_prompt_tokens < 0 or self.total_completion_tokens < 0:
            raise ValueError("token counts must be non-negative")
        payload = json.dumps(
            {
                "case_id": self.case_id,
                "baseline_exit_code": int(self.baseline_result.exit_code),
                "final_exit_code": int(self.final_result.exit_code),
                "patch_hash": self.accepted_patch.diff_hash if self.accepted_patch else None,
                "attempts": self.attempts,
            },
            sort_keys=True,
        )
        object.__setattr__(self, "bundle_hash", _sha256_of(payload))

    @property
    def repair_succeeded(self) -> bool:
        """True iff the final result shows all tests passing."""
        return self.final_result.exit_code == ExitCode.OK

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary suitable for the evidence report."""
        return {
            "case_id": self.case_id,
            "repair_succeeded": self.repair_succeeded,
            "attempts": self.attempts,
            "baseline_exit_code": int(self.baseline_result.exit_code),
            "final_exit_code": int(self.final_result.exit_code),
            "wall_seconds_final": self.final_result.wall_seconds,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "patch_hash": self.accepted_patch.diff_hash if self.accepted_patch else None,
            "bundle_hash": self.bundle_hash,
        }

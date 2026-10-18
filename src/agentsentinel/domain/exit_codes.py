"""Pytest exit code semantics for AgentSentinel's orchestrator.

The orchestrator MUST distinguish every exit code; treating ExitCode.NO_TESTS (5)
as success is a reward-hacking vector because an empty test suite would always
"pass". Treating ExitCode.INTERNAL_ERROR (3) as a test failure could mask
infrastructure bugs.

References
----------
- https://docs.pytest.org/en/stable/reference/exit-codes.html
- pytest source: src/_pytest/config/__init__.py  class ExitCode(enum.IntEnum)
"""

from __future__ import annotations

import enum


class ExitCode(enum.IntEnum):
    """Mirrors pytest's ``ExitCode`` enum exactly.

    Do NOT add, remove, or renumber values without verifying against the
    installed pytest version in CI. The orchestrator's decision tree branches
    on exact integer values.
    """

    OK = 0
    """All tests passed (or no tests collected when ``--co`` was used explicitly)."""

    TESTS_FAILED = 1
    """One or more tests failed."""

    INTERRUPTED = 2
    """Test execution was interrupted (e.g. by KeyboardInterrupt or SIGTERM)."""

    INTERNAL_ERROR = 3
    """An internal pytest error or unhandled exception occurred in a plugin/conftest."""

    USAGE_ERROR = 4
    """pytest was invoked with invalid command-line options."""

    NO_TESTS_COLLECTED = 5
    """No tests were collected. This is NOT a success — it indicates a broken
    test discovery configuration or an empty suite, which the repair agent
    MUST treat as a harness failure, not a repair success."""


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

#: Exit codes that indicate the test environment is broken (not the patch).
HARNESS_BROKEN_CODES: frozenset[ExitCode] = frozenset({
    ExitCode.INTERNAL_ERROR,
    ExitCode.USAGE_ERROR,
    ExitCode.NO_TESTS_COLLECTED,
    ExitCode.INTERRUPTED,
})

#: Exit codes that indicate a genuine test-level verdict (pass or fail).
VERDICT_CODES: frozenset[ExitCode] = frozenset({
    ExitCode.OK,
    ExitCode.TESTS_FAILED,
})


def classify(raw_code: int) -> ExitCode:
    """Convert a raw subprocess exit code to a typed ``ExitCode``.

    Parameters
    ----------
    raw_code:
        The integer returned by ``subprocess.run(...).returncode``.

    Returns
    -------
    ExitCode
        The matching enum member.

    Raises
    ------
    ValueError
        If ``raw_code`` is not a recognised pytest exit code.
    """
    try:
        return ExitCode(raw_code)
    except ValueError:
        raise ValueError(
            f"Unrecognised pytest exit code {raw_code!r}. "
            f"Valid codes: {[e.value for e in ExitCode]}"
        ) from None


def is_harness_broken(code: int | ExitCode) -> bool:
    """Return ``True`` if the exit code indicates a broken test harness."""
    try:
        typed = ExitCode(int(code))
    except ValueError:
        return True  # unknown codes treated as broken harness
    return typed in HARNESS_BROKEN_CODES


def is_genuine_verdict(code: int | ExitCode) -> bool:
    """Return ``True`` if the exit code is a clean pass-or-fail verdict."""
    return not is_harness_broken(code)

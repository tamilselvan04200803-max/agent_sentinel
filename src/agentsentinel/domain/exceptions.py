"""Domain exception hierarchy for AgentSentinel.

All exceptions derive from ``AgentSentinelError`` so the orchestrator boundary
can catch them with a single ``except AgentSentinelError`` and still distinguish
sub-types for structured logging.

Hierarchy
---------
AgentSentinelError
├── SandboxViolationError        — any attempt to escape the sandbox boundary
│   ├── PathTraversalError       — path traversal detected (../../ etc.)
│   ├── SymlinkEscapeError       — symlink resolves outside workspace root
│   └── ResourceExhaustionError  — fork bomb / output flood / OOM guard triggered
├── PatchPolicyError             — patch violates the allowlist or structural rules
│   ├── TestFileModificationError — patch targets a test file (reward-hacking ban)
│   ├── MalformedDiffError       — diff cannot be parsed / applied
│   └── AllowlistViolationError  — file not on the approved edit list
└── ReproHarnessError            — reproduction harness lifecycle failures
    ├── HarnessTimeoutError      — test suite exceeded wall-clock budget
    └── HarnessSetupError        — workspace / container setup failed
"""

from __future__ import annotations


class AgentSentinelError(Exception):
    """Root of the AgentSentinel exception hierarchy.

    All domain-specific errors must subclass this so callers can use
    a single ``except AgentSentinelError`` at the orchestrator boundary.
    """


# ---------------------------------------------------------------------------
# Sandbox violations
# ---------------------------------------------------------------------------


class SandboxViolationError(AgentSentinelError):
    """Raised when an operation attempts to violate sandbox boundaries."""


class PathTraversalError(SandboxViolationError):
    """Raised when a path contains traversal sequences (``../``, ``..\\``)."""

    def __init__(self, raw_path: str) -> None:
        self.raw_path = raw_path
        super().__init__(f"Path traversal detected: {raw_path!r}")


class SymlinkEscapeError(SandboxViolationError):
    """Raised when a symlink resolves to a target outside the workspace root."""

    def __init__(self, link: str, resolved: str, root: str) -> None:
        self.link = link
        self.resolved = resolved
        self.root = root
        super().__init__(
            f"Symlink escape: {link!r} resolves to {resolved!r}, outside root {root!r}"
        )


class ResourceExhaustionError(SandboxViolationError):
    """Raised when a resource guard (fork bomb, output flood, OOM) is triggered."""

    def __init__(self, resource: str, limit: str | int, actual: str | int) -> None:
        self.resource = resource
        self.limit = limit
        self.actual = actual
        super().__init__(
            f"Resource exhaustion [{resource}]: limit={limit!r}, actual={actual!r}"
        )


# ---------------------------------------------------------------------------
# Patch policy violations
# ---------------------------------------------------------------------------


class PatchPolicyError(AgentSentinelError):
    """Raised when a patch violates the allowlist or structural integrity rules."""


class TestFileModificationError(PatchPolicyError):
    """Raised when a patch attempts to modify a test file (reward-hacking ban).

    No test file may be altered by the repair agent under any circumstances.
    """

    def __init__(self, test_path: str) -> None:
        self.test_path = test_path
        super().__init__(
            f"REWARD-HACKING BAN: patch targets test file {test_path!r}"
        )


class MalformedDiffError(PatchPolicyError):
    """Raised when a unified diff cannot be parsed or safely applied."""

    def __init__(self, reason: str, context: str = "") -> None:
        self.reason = reason
        self.context = context
        super().__init__(
            f"Malformed diff: {reason}" + (f" — context: {context}" if context else "")
        )


class AllowlistViolationError(PatchPolicyError):
    """Raised when a patch targets a file not on the approved edit allowlist."""

    def __init__(self, path: str, allowlist: tuple[str, ...]) -> None:
        self.path = path
        self.allowlist = allowlist
        super().__init__(
            f"Allowlist violation: {path!r} not in approved set "
            f"({len(allowlist)} entries)"
        )


# ---------------------------------------------------------------------------
# Reproduction harness failures
# ---------------------------------------------------------------------------


class ReproHarnessError(AgentSentinelError):
    """Raised for lifecycle failures in the reproduction harness."""


class HarnessTimeoutError(ReproHarnessError):
    """Raised when the test suite exceeds its wall-clock budget."""

    def __init__(self, timeout_seconds: float, command: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.command = command
        super().__init__(
            f"Harness timeout after {timeout_seconds}s running: {command!r}"
        )


class HarnessSetupError(ReproHarnessError):
    """Raised when workspace or container initialisation fails."""

    def __init__(self, reason: str, stderr: str = "") -> None:
        self.reason = reason
        self.stderr = stderr
        super().__init__(
            f"Harness setup failed: {reason}"
            + (f"\nstderr: {stderr[:500]}" if stderr else "")
        )

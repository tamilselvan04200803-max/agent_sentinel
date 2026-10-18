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
        super().__init__(f"Resource exhaustion [{resource}]: limit={limit!r}, actual={actual!r}")


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
        super().__init__(f"REWARD-HACKING BAN: patch targets test file {test_path!r}")


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
            f"Allowlist violation: {path!r} not in approved set ({len(allowlist)} entries)"
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
        super().__init__(f"Harness timeout after {timeout_seconds}s running: {command!r}")


class HarnessSetupError(ReproHarnessError):
    """Raised when workspace or container initialisation fails."""

    def __init__(self, reason: str, stderr: str = "") -> None:
        self.reason = reason
        self.stderr = stderr
        super().__init__(
            f"Harness setup failed: {reason}" + (f"\nstderr: {stderr[:500]}" if stderr else "")
        )


# ---------------------------------------------------------------------------
# M4 orchestrator errors
# ---------------------------------------------------------------------------


class OrchestratorError(AgentSentinelError):
    """Base for all orchestrator-state / run-lifecycle errors."""


class DuplicatePatchError(OrchestratorError):
    """Raised when a proposed patch is a duplicate or AST no-op of a prior attempt."""

    def __init__(self, reason: str, tier: str = "unknown") -> None:
        self.tier = tier
        super().__init__(f"Duplicate/no-op patch rejected [{tier}]: {reason}")


class BaselineNotReproducedError(OrchestratorError):
    """Raised when the baseline run exits OK or harness-broken before any LLM call."""

    def __init__(self, exit_code: int, detail: str = "") -> None:
        self.exit_code = exit_code
        super().__init__(
            f"Baseline not reproduced (exit_code={exit_code}). "
            "The bug must reproduce (TESTS_FAILED=1) before any repair attempt."
            + (f"\n{detail}" if detail else "")
        )


class InfrastructureFailureError(OrchestratorError):
    """Raised on Docker daemon / HTTP 429 transport failures (NOT counted as attempt)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Infrastructure failure (no attempt counted): {reason}")


class ApprovalIntegrityError(OrchestratorError):
    """Raised when approval hash does not match the expected cryptographic binding."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Approval integrity check failed: {reason}")


class UnapprovedExportError(OrchestratorError):
    """Raised when export_evidence_bundle is called on a non-APPROVED run."""

    def __init__(self, state: str) -> None:
        super().__init__(
            f"Cannot export evidence bundle: run state is {state!r}, expected 'APPROVED'."
        )

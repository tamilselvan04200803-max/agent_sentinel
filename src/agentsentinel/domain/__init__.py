"""Domain package — immutable schemas, exception hierarchy, and exit code semantics."""

from agentsentinel.domain.exceptions import (
    AgentSentinelError,
    AllowlistViolationError,
    HarnessSetupError,
    HarnessTimeoutError,
    MalformedDiffError,
    PatchPolicyError,
    PathTraversalError,
    ReproHarnessError,
    ResourceExhaustionError,
    SandboxViolationError,
    SymlinkEscapeError,
    TestFileModificationError,
)
from agentsentinel.domain.exit_codes import (
    ExitCode,
    HARNESS_BROKEN_CODES,
    VERDICT_CODES,
    classify,
    is_genuine_verdict,
    is_harness_broken,
)
from agentsentinel.domain.models import (
    CaseSpec,
    EvidenceBundle,
    ExecutionResult,
    PatchProposal,
)

__all__ = [
    # exceptions
    "AgentSentinelError",
    "SandboxViolationError",
    "PathTraversalError",
    "SymlinkEscapeError",
    "ResourceExhaustionError",
    "PatchPolicyError",
    "TestFileModificationError",
    "MalformedDiffError",
    "AllowlistViolationError",
    "ReproHarnessError",
    "HarnessTimeoutError",
    "HarnessSetupError",
    # exit codes
    "ExitCode",
    "HARNESS_BROKEN_CODES",
    "VERDICT_CODES",
    "classify",
    "is_harness_broken",
    "is_genuine_verdict",
    # models
    "CaseSpec",
    "PatchProposal",
    "ExecutionResult",
    "EvidenceBundle",
]

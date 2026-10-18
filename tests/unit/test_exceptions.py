"""Unit tests for agentsentinel.domain.exceptions."""

from __future__ import annotations

import pytest

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


# ---------------------------------------------------------------------------
# Hierarchy correctness
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    @pytest.mark.unit
    def test_all_are_agent_sentinel_error_subclasses(self) -> None:
        errors = [
            SandboxViolationError("x"),
            PathTraversalError("../../etc/passwd"),
            SymlinkEscapeError("/tmp/link", "/etc/shadow", "/workspace"),
            ResourceExhaustionError("memory", "256m", "512m"),
            PatchPolicyError("bad patch"),
            TestFileModificationError("tests/test_x.py"),
            MalformedDiffError("no header"),
            AllowlistViolationError("evil.py", ("good.py",)),
            ReproHarnessError("boom"),
            HarnessTimeoutError(30.0, "pytest"),
            HarnessSetupError("docker not found"),
        ]
        for err in errors:
            assert isinstance(err, AgentSentinelError), (
                f"{type(err).__name__} does not derive from AgentSentinelError"
            )

    @pytest.mark.unit
    def test_sandbox_hierarchy(self) -> None:
        assert issubclass(PathTraversalError, SandboxViolationError)
        assert issubclass(SymlinkEscapeError, SandboxViolationError)
        assert issubclass(ResourceExhaustionError, SandboxViolationError)

    @pytest.mark.unit
    def test_policy_hierarchy(self) -> None:
        assert issubclass(TestFileModificationError, PatchPolicyError)
        assert issubclass(MalformedDiffError, PatchPolicyError)
        assert issubclass(AllowlistViolationError, PatchPolicyError)

    @pytest.mark.unit
    def test_harness_hierarchy(self) -> None:
        assert issubclass(HarnessTimeoutError, ReproHarnessError)
        assert issubclass(HarnessSetupError, ReproHarnessError)


# ---------------------------------------------------------------------------
# Exception messages & structured fields
# ---------------------------------------------------------------------------

class TestExceptionMessages:
    @pytest.mark.unit
    def test_path_traversal_includes_path(self) -> None:
        err = PathTraversalError("../../etc/passwd")
        assert "../../etc/passwd" in str(err)
        assert err.raw_path == "../../etc/passwd"

    @pytest.mark.unit
    def test_symlink_escape_includes_all_paths(self) -> None:
        err = SymlinkEscapeError("/tmp/link", "/etc/shadow", "/workspace")
        msg = str(err)
        assert "/tmp/link" in msg
        assert "/etc/shadow" in msg
        assert "/workspace" in msg

    @pytest.mark.unit
    def test_resource_exhaustion_fields(self) -> None:
        err = ResourceExhaustionError("pids", 100, 9999)
        assert err.resource == "pids"
        assert err.limit == 100
        assert err.actual == 9999
        assert "pids" in str(err)

    @pytest.mark.unit
    def test_test_file_modification_message(self) -> None:
        err = TestFileModificationError("tests/test_evil.py")
        assert "REWARD-HACKING BAN" in str(err)
        assert "tests/test_evil.py" in str(err)

    @pytest.mark.unit
    def test_malformed_diff_with_context(self) -> None:
        err = MalformedDiffError("bad header", context="line 42")
        assert "bad header" in str(err)
        assert "line 42" in str(err)

    @pytest.mark.unit
    def test_malformed_diff_without_context(self) -> None:
        err = MalformedDiffError("bad header")
        assert "bad header" in str(err)
        # should not crash with empty context
        assert isinstance(str(err), str)

    @pytest.mark.unit
    def test_allowlist_violation_shows_count(self) -> None:
        err = AllowlistViolationError("hack.py", ("a.py", "b.py"))
        assert "hack.py" in str(err)
        assert "2 entries" in str(err)

    @pytest.mark.unit
    def test_harness_timeout_fields(self) -> None:
        err = HarnessTimeoutError(60.0, "pytest tests/")
        assert err.timeout_seconds == 60.0
        assert err.command == "pytest tests/"
        assert "60" in str(err)

    @pytest.mark.unit
    def test_harness_setup_with_stderr(self) -> None:
        err = HarnessSetupError("docker not found", stderr="Error: command not found")
        assert "docker not found" in str(err)
        assert "Error: command not found" in str(err)

    @pytest.mark.unit
    def test_harness_setup_without_stderr(self) -> None:
        err = HarnessSetupError("failed silently")
        assert "failed silently" in str(err)


# ---------------------------------------------------------------------------
# Catchability via base class
# ---------------------------------------------------------------------------

class TestCatchability:
    @pytest.mark.unit
    def test_path_traversal_caught_as_agent_sentinel_error(self) -> None:
        with pytest.raises(AgentSentinelError):
            raise PathTraversalError("../../etc/passwd")

    @pytest.mark.unit
    def test_sandbox_violation_caught_as_agent_sentinel_error(self) -> None:
        with pytest.raises(AgentSentinelError):
            raise SandboxViolationError("escape attempt")

    @pytest.mark.unit
    def test_harness_timeout_caught_as_repro_harness_error(self) -> None:
        with pytest.raises(ReproHarnessError):
            raise HarnessTimeoutError(10.0, "cmd")

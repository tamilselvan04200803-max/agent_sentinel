"""Live Docker integration tests for Milestone 1 container sandbox.

These tests execute against the REAL Docker daemon on the host.
They are automatically skipped if the Docker daemon is unreachable,
ensuring CI runs cleanly in non-Docker environments while providing
ground-truth verification whenever Docker is running.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from agentsentinel.domain.exceptions import HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.sandbox.workspace import WorkspaceManager
from tests.fixtures.normalizer import (
    NORMALIZER_BUGGY_SOURCE,
    NORMALIZER_FIXED_SOURCE,
    NORMALIZER_TEST_SOURCE,
)


def is_docker_daemon_running() -> bool:
    """Return True iff 'docker info' succeeds against a live daemon."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3.0,
            check=False,
        )
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


DOCKER_AVAILABLE = is_docker_daemon_running()
skip_without_docker = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="Docker daemon is not running or unreachable on host OS",
)


@pytest.mark.integration
@skip_without_docker
class TestDockerLiveM1:
    """Real Docker engine execution verification."""

    def test_live_broken_m0_normalizer_fails(self, tmp_path: Path) -> None:
        """Verify buggy normalizer fails tests with ExitCode.TESTS_FAILED inside real container."""
        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_str:
            ws = Path(ws_str)
            (ws / "normalizer.py").write_text(NORMALIZER_BUGGY_SOURCE, encoding="utf-8")
            (ws / "test_normalizer.py").write_text(NORMALIZER_TEST_SOURCE, encoding="utf-8")

            runner = HardenedContainerRunner(
                ContainerConfig(
                    image="python:3.11-slim",
                    timeout_seconds=30.0,
                )
            )

            # Inside container, install pytest or run inline test runner
            res = runner.run_in_container(
                case_id="case-live-broken",
                patch_diff_hash="baseline",
                workspace_host_path=ws,
                command="python -m pytest test_normalizer.py",
            )

            assert res.exit_code == ExitCode.TESTS_FAILED
            assert res.failed is True

    def test_live_fixed_m0_normalizer_passes(self, tmp_path: Path) -> None:
        """Verify fixed normalizer passes tests with ExitCode.OK inside real container."""
        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_str:
            ws = Path(ws_str)
            (ws / "normalizer.py").write_text(NORMALIZER_FIXED_SOURCE, encoding="utf-8")
            (ws / "test_normalizer.py").write_text(NORMALIZER_TEST_SOURCE, encoding="utf-8")

            runner = HardenedContainerRunner(
                ContainerConfig(
                    image="python:3.11-slim",
                    timeout_seconds=30.0,
                )
            )

            res = runner.run_in_container(
                case_id="case-live-fixed",
                patch_diff_hash="fixed",
                workspace_host_path=ws,
                command="python -m pytest test_normalizer.py",
            )

            assert res.exit_code == ExitCode.OK
            assert res.passed is True

    def test_live_network_isolation(self, tmp_path: Path) -> None:
        """Verify real network isolation: outbound socket connection fails with OSError."""
        runner = HardenedContainerRunner(
            ContainerConfig(
                image="python:3.11-slim",
                network_disabled=True,
                timeout_seconds=10.0,
            )
        )

        res = runner.run_in_container(
            case_id="case-live-net",
            patch_diff_hash="baseline",
            workspace_host_path=tmp_path,
            command="python -c \"import socket; socket.create_connection(('8.8.8.8', 53), timeout=2)\"",
        )

        assert res.exit_code != ExitCode.OK
        assert (
            "OSError" in res.stderr or "Network is unreachable" in res.stderr or "101" in res.stderr
        )

    def test_live_timeout_and_no_leftover_container(self, tmp_path: Path) -> None:
        """Verify real process timeout reaps container and leaves zero zombie containers."""
        runner = HardenedContainerRunner(
            ContainerConfig(
                image="python:3.11-slim",
                timeout_seconds=1.5,
            )
        )

        with pytest.raises(HarnessTimeoutError):
            runner.run_in_container(
                case_id="case-live-timeout",
                patch_diff_hash="baseline",
                workspace_host_path=tmp_path,
                command="python -c 'import time; time.sleep(10)'",
            )

        # Check docker ps -a to ensure no running or exited container with prefix 'agentsentinel-' remains
        ps_out = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=agentsentinel-", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert ps_out.stdout.strip() == ""

"""Unit tests for agentsentinel.sandbox.container runner arguments and lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from agentsentinel.domain.exceptions import HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner

if TYPE_CHECKING:
    from pathlib import Path


class TestContainerConfig:
    @pytest.mark.unit
    def test_default_config(self) -> None:
        cfg = ContainerConfig()
        assert cfg.network_disabled is True
        assert cfg.read_only_rootfs is True
        assert cfg.memory_limit == "512m"
        assert cfg.pids_limit == 64
        assert cfg.cpus == "1.0"
        assert cfg.timeout_seconds == 30.0
        assert cfg.max_output_bytes == 262_144

    @pytest.mark.unit
    def test_invalid_config_raises(self) -> None:
        with pytest.raises(ValueError, match="timeout_seconds"):
            ContainerConfig(timeout_seconds=-1.0)
        with pytest.raises(ValueError, match="max_output_bytes"):
            ContainerConfig(max_output_bytes=0)
        with pytest.raises(ValueError, match="pids_limit"):
            ContainerConfig(pids_limit=-5)


class TestHardenedContainerRunner:
    @pytest.mark.unit
    def test_build_docker_run_args_enforces_all_security_flags(self, tmp_path: Path) -> None:
        runner = HardenedContainerRunner()
        args = runner.build_docker_run_args(
            container_name="test_c1",
            workspace_host_path=tmp_path,
            command=["pytest", "tests/"],
        )

        assert args[0] == "docker"
        assert args[1] == "run"
        assert "--name" in args
        assert "test_c1" in args
        assert "--rm" in args

        # 1. Network isolation
        assert "--network" in args
        assert args[args.index("--network") + 1] == "none"

        # 2. Read only root filesystem
        assert "--read-only" in args

        # 3. Tmpfs mounts
        assert "--tmpfs" in args
        assert "/tmp:rw,noexec,nosuid,size=64m" in args

        # 4. Capabilities dropped
        assert "--cap-drop=ALL" in args
        assert "--security-opt" in args
        assert "no-new-privileges" in args

        # 5. Resource limits
        assert "--pids-limit=64" in args
        assert "--memory=512m" in args
        assert "--cpus=1.0" in args

        # 6. Mounted workspace
        host_resolved = tmp_path.resolve().as_posix()
        mount_arg = f"{host_resolved}:/workspace:rw"
        assert "-v" in args
        assert mount_arg in args

        # 7. Command
        assert "pytest" in args
        assert "tests/" in args

    @pytest.mark.unit
    def test_run_in_container_success_mock(self, tmp_path: Path) -> None:
        runner = HardenedContainerRunner()

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"1 passed in 0.05s", b"")
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc):
            res = runner.run_in_container(
                case_id="case-1",
                patch_diff_hash="diff123",
                workspace_host_path=tmp_path,
                command="pytest",
            )

        assert res.case_id == "case-1"
        assert res.patch_diff_hash == "diff123"
        assert res.exit_code == ExitCode.OK
        assert "1 passed" in res.stdout
        assert res.stdout_truncated is False
        assert res.passed is True

    @pytest.mark.unit
    def test_run_in_container_timeout_triggers_cleanup(self, tmp_path: Path) -> None:
        import subprocess

        runner = HardenedContainerRunner(ContainerConfig(timeout_seconds=0.1))

        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="pytest", timeout=0.1)

        with (
            patch("subprocess.Popen", return_value=mock_proc),
            patch.object(runner, "_force_remove_container") as mock_rm,
        ):
            with pytest.raises(HarnessTimeoutError) as exc_info:
                runner.run_in_container(
                    case_id="case-timeout",
                    patch_diff_hash="baseline",
                    workspace_host_path=tmp_path,
                    command="python -c 'while True: pass'",
                )

            assert exc_info.value.timeout_seconds == 0.1
            mock_proc.kill.assert_called()
            mock_rm.assert_called()

    @pytest.mark.unit
    def test_run_in_container_output_truncation(self, tmp_path: Path) -> None:
        runner = HardenedContainerRunner(ContainerConfig(max_output_bytes=100))

        flooded_bytes = b"A" * 1000
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (flooded_bytes, b"")
        mock_proc.returncode = 1
        mock_proc.poll.return_value = 1

        with patch("subprocess.Popen", return_value=mock_proc):
            res = runner.run_in_container(
                case_id="case-flood",
                patch_diff_hash="baseline",
                workspace_host_path=tmp_path,
                command="yes",
            )

        assert res.stdout_truncated is True
        assert len(res.stdout) == 100
        assert res.exit_code == ExitCode.TESTS_FAILED

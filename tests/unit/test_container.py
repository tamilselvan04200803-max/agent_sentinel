"""Unit tests for agentsentinel.sandbox.container runner arguments and lifecycle."""

from __future__ import annotations

import contextlib
import io
import os
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from agentsentinel.domain.exceptions import HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner

if TYPE_CHECKING:
    from pathlib import Path


def _make_mock_proc(stdout: bytes, stderr: bytes, returncode: int) -> MagicMock:
    """Build a MagicMock ``subprocess.Popen`` whose stdout/stderr are BytesIO
    streams that behave like closed pipes (EOF immediately) for the thread-based
    streaming reader.
    """
    proc = MagicMock()
    proc.stdout = io.BytesIO(stdout)
    proc.stderr = io.BytesIO(stderr)
    proc.returncode = returncode
    proc.poll.return_value = returncode
    proc.kill.return_value = None
    proc.wait.return_value = returncode
    return proc


class _SlowPipe:
    """A readable file-like that blocks on read() until killed or timeout.

    Used to simulate an infinitely-running child whose pipes never close and
    never produce data, so we can verify the bounded-stream reader enforces
    the wall-clock timeout.
    """

    def __init__(self) -> None:
        self._r, self._w = os.pipe()
        self._killed = False

    def read(self, size: int) -> bytes:
        if self._killed:
            return b""
        # Block on select for up to 0.1 seconds; time out and return empty
        # *only* when killed. This simulates a pipe that never produces data
        # until the writer is closed via kill().
        import select

        while not self._killed:
            ready, _, _ = select.select([self._r], [], [], 0.1)
            if ready:
                # Data/EOF available on the real fd
                data = os.read(self._r, size)
                return data
        return b""

    def fileno(self) -> int:
        return self._r

    def close(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self._r)
        with contextlib.suppress(OSError):
            os.close(self._w)

    def kill(self) -> None:
        self._killed = True
        with contextlib.suppress(OSError):
            os.close(self._w)


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

        # 6. Mounted workspace — read-only (:ro) for VFS-enforced immutability
        host_resolved = tmp_path.resolve().as_posix()
        mount_arg = f"{host_resolved}:/workspace:ro"
        assert "-v" in args
        assert mount_arg in args

        # 7. Command
        assert "pytest" in args
        assert "tests/" in args

    @pytest.mark.unit
    def test_run_in_container_success_mock(self, tmp_path: Path) -> None:
        runner = HardenedContainerRunner()

        mock_proc = _make_mock_proc(b"1 passed in 0.05s", b"", returncode=0)

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
        """Verify wall-clock timeout fires even when the container never
        closes its pipes (i.e. bounded streaming reader does not deadlock
        waiting for EOF)."""
        runner = HardenedContainerRunner(ContainerConfig(timeout_seconds=0.2))

        out_pipe = _SlowPipe()
        err_pipe = _SlowPipe()

        mock_proc = MagicMock()
        mock_proc.stdout = out_pipe
        mock_proc.stderr = err_pipe
        mock_proc.pid = 12345
        mock_proc.returncode = None

        # poll() returns None (still running) until kill() is called.
        poll_calls = {"n": 0}

        def _poll() -> int | None:
            poll_calls["n"] += 1
            if out_pipe._killed:
                return -9
            return None

        mock_proc.poll.side_effect = _poll

        def _kill() -> None:
            out_pipe.kill()
            err_pipe.kill()

        mock_proc.kill.side_effect = _kill
        mock_proc.wait.return_value = -9

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

            assert exc_info.value.timeout_seconds == 0.2
            mock_rm.assert_called()
            mock_proc.kill.assert_called()

        out_pipe.close()
        err_pipe.close()

    @pytest.mark.unit
    def test_run_in_container_output_truncation(self, tmp_path: Path) -> None:
        runner = HardenedContainerRunner(ContainerConfig(max_output_bytes=100))

        flooded_bytes = b"A" * 1000
        mock_proc = _make_mock_proc(flooded_bytes, b"", returncode=1)

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

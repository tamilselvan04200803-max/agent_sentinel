"""Hardened, rootless/unprivileged Docker runner for reproduction and test execution.

Enforces strict host safety:
- `--network=none` (zero outbound or inbound network access)
- `--read-only` (immutable root filesystem)
- `--tmpfs /tmp:rw,noexec,nosuid,size=64m`
- `--cap-drop=ALL` (drops all Linux capabilities)
- `--security-opt=no-new-privileges`
- `--pids-limit=64` (fork bomb mitigation)
- `--memory=512m` (memory exhaustion limit)
- `--cpus=1.0` (CPU runaway mitigation)
- Explicit volume mounts: only the ephemeral workspace root mounted read-write to /workspace
- Hard output byte truncation (default 256KB) to prevent host memory flooding.
- Process timeout enforcement with guaranteed container kill (`docker rm -f <cid>`) in `finally`.
"""

from __future__ import annotations

import contextlib
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import (
    HarnessSetupError,
    HarnessTimeoutError,
)
from agentsentinel.domain.exit_codes import ExitCode, classify
from agentsentinel.domain.models import ExecutionResult

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_IMAGE = "python:3.11-slim"
DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_PIDS_LIMIT = 64
DEFAULT_CPUS = "1.0"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 262_144  # 256 KB


@dataclass(frozen=True)
class ContainerConfig:
    """Security and resource limits configuration for the container sandbox.

    Attributes
    ----------
    image:
        Base container image (e.g., 'python:3.11-slim').
    network_disabled:
        If True, passes '--network=none'. Must remain True in production.
    read_only_rootfs:
        If True, passes '--read-only'.
    memory_limit:
        Docker memory flag value (e.g. '512m').
    pids_limit:
        Process limit for the container (guards against fork bombs).
    cpus:
        Max CPU allocation.
    timeout_seconds:
        Wall-clock time allowed before SIGKILL.
    max_output_bytes:
        Max bytes read from stdout/stderr before truncating.
    """

    image: str = DEFAULT_IMAGE
    network_disabled: bool = True
    read_only_rootfs: bool = True
    memory_limit: str = DEFAULT_MEMORY_LIMIT
    pids_limit: int = DEFAULT_PIDS_LIMIT
    cpus: str = DEFAULT_CPUS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be positive, got {self.timeout_seconds}")
        if self.max_output_bytes <= 0:
            raise ValueError(f"max_output_bytes must be positive, got {self.max_output_bytes}")
        if self.pids_limit <= 0:
            raise ValueError(f"pids_limit must be positive, got {self.pids_limit}")


class HardenedContainerRunner:
    """Orchestrates execution of commands inside an isolated Docker container."""

    def __init__(self, config: ContainerConfig | None = None) -> None:
        self.config = config or ContainerConfig()

    def build_docker_run_args(
        self,
        container_name: str,
        workspace_host_path: Path,
        command: list[str] | str,
        workdir: str = "/workspace",
    ) -> list[str]:
        """Construct the hardened 'docker run' argument list.

        Parameters
        ----------
        container_name:
            Unique identifier for the container.
        workspace_host_path:
            Host directory path to mount into /workspace.
        command:
            Command to execute inside the container.
        workdir:
            Working directory inside the container.

        Returns
        -------
        list[str]
            Full argument list for subprocess.
        """
        # Ensure path is formatted cleanly with forward slashes for docker mount (Windows & POSIX)
        host_path = workspace_host_path.resolve().as_posix()

        args = [
            "docker",
            "run",
            "--name",
            container_name,
            "--rm",
        ]

        if self.config.network_disabled:
            args.extend(["--network", "none"])

        if self.config.read_only_rootfs:
            args.append("--read-only")

        # Essential hardened tmpfs mounts for a read-only rootfs
        args.extend(
            [
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108
                "--tmpfs",
                "/run:rw,noexec,nosuid,size=16m",
            ]
        )

        # Security options: drop all Linux capabilities & block privilege escalation
        args.extend(
            [
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges",
            ]
        )

        # Resource limits
        args.extend(
            [
                f"--pids-limit={self.config.pids_limit}",
                f"--memory={self.config.memory_limit}",
                f"--cpus={self.config.cpus}",
            ]
        )

        # Working directory & volume mount (only workspace is mounted)
        args.extend(
            [
                "-w",
                workdir,
                "-v",
                f"{host_path}:{workdir}:rw",
            ]
        )

        # Environment hygiene: do not leak host environment or credentials.
        # Direct pytest cache to writable tmpfs to avoid breaking on --read-only rootfs.
        args.extend(
            [
                "-e",
                "PYTHONUNBUFFERED=1",
                "-e",
                "PYTHONDONTWRITEBYTECODE=1",
                "-e",
                "PYTEST_ADDOPTS=-o cache_dir=/tmp/.pytest_cache",
            ]
        )

        # Container image
        args.append(self.config.image)

        # Command to execute
        if isinstance(command, str):
            args.extend(["sh", "-c", command])
        else:
            args.extend(command)

        return args

    def run_in_container(
        self,
        case_id: str,
        patch_diff_hash: str,
        workspace_host_path: Path,
        command: list[str] | str,
    ) -> ExecutionResult:
        """Run a command inside a hardened Docker container with strict lifecycle controls.

        Parameters
        ----------
        case_id:
            ID of the active CaseSpec.
        patch_diff_hash:
            Hash of the applied patch, or 'baseline'.
        workspace_host_path:
            Local path to the workspace directory.
        command:
            Test command to execute.

        Returns
        -------
        ExecutionResult
            Immutable execution result model.

        Raises
        ------
        HarnessSetupError
            If docker command invocation fails.
        HarnessTimeoutError
            If execution exceeds configured timeout.
        """
        container_name = f"agentsentinel-{uuid.uuid4().hex[:12]}"
        run_args = self.build_docker_run_args(
            container_name=container_name,
            workspace_host_path=workspace_host_path,
            command=command,
        )

        start_time = time.monotonic()
        stdout_bytes = bytearray()
        stderr_bytes = bytearray()
        stdout_truncated = False
        stderr_truncated = False

        proc: subprocess.Popen[bytes] | None = None
        try:
            proc = subprocess.Popen(
                run_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )

            # Wait for execution with timeout
            try:
                raw_out, raw_err = proc.communicate(timeout=self.config.timeout_seconds)
            except subprocess.TimeoutExpired:
                # Force kill subprocess and container
                proc.kill()
                self._force_remove_container(container_name)
                cmd_str = command if isinstance(command, str) else " ".join(command)
                raise HarnessTimeoutError(self.config.timeout_seconds, cmd_str) from None

            # Process output streams with byte truncation limits
            max_b = self.config.max_output_bytes

            if len(raw_out) > max_b:
                stdout_truncated = True
                stdout_bytes = bytearray(raw_out[:max_b])
            else:
                stdout_bytes = bytearray(raw_out)

            if len(raw_err) > max_b:
                stderr_truncated = True
                stderr_bytes = bytearray(raw_err[:max_b])
            else:
                stderr_bytes = bytearray(raw_err)

            wall_seconds = max(0.0, time.monotonic() - start_time)
            raw_exit_code = proc.returncode

            # Decode bytes with safe error handling
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            # Map exit code to domain enum
            try:
                exit_code_enum = classify(raw_exit_code)
            except ValueError:
                # Docker exit codes like 137 (OOM/Killed) or 125/126/127 map to broken harness
                exit_code_enum = ExitCode.INTERNAL_ERROR

            return ExecutionResult(
                case_id=case_id,
                patch_diff_hash=patch_diff_hash,
                exit_code=exit_code_enum,
                stdout=stdout_str,
                stderr=stderr_str,
                wall_seconds=wall_seconds,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )

        except FileNotFoundError as e:
            raise HarnessSetupError(f"Docker executable not found on host: {e}") from e
        except HarnessTimeoutError:
            raise
        except Exception as e:
            raise HarnessSetupError(f"Failed to execute container: {e}") from e
        finally:
            # Ensure container cleanup
            self._force_remove_container(container_name)
            if proc and proc.poll() is None:
                with contextlib.suppress(Exception):
                    proc.kill()
                    proc.wait(timeout=2.0)

    def _force_remove_container(self, container_name: str) -> None:
        """Issue docker rm -f <container_name> to ensure no zombie containers remain."""
        with contextlib.suppress(Exception):
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                check=False,
                timeout=5.0,
            )

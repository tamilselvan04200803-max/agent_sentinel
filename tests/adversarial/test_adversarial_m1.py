"""Adversarial security boundary verification tests for Milestone 1 (M1).

Verifies the 6 non-negotiable security boundary checks:
1. Network Isolation: `--network=none` is unconditionally present.
2. Read-Only Root Filesystem: `--read-only` and noexec tmpfs mounts are enforced.
3. Capability & Privilege Stripping: `--cap-drop=ALL` and `no-new-privileges` enforced.
4. Resource Limits: `--pids-limit`, `--memory`, `--cpus` bounds are strictly enforced.
5. Host Isolation: No host `/var/run/docker.sock`, no `$HOME`, no SSH/AWS credential mounts.
6. Denial of Service Protections:
   - Infinite loop / fork bomb timeout guarantees container kill and removal.
   - Output flooding (e.g. `yes`) is hard-truncated at `max_output_bytes` without host OOM.
7. Fixture Reproduction: Normalizer bug reproduction and patch verification logic.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentsentinel.domain.exceptions import HarnessTimeoutError
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.sandbox.workspace import WorkspaceManager
from tests.fixtures.normalizer import (
    NORMALIZER_BUGGY_SOURCE,
    NORMALIZER_TEST_SOURCE,
    normalize_token_buggy,
    normalize_token_fixed,
)


class TestAdversarialM1ContainerSecurity:
    @pytest.mark.adversarial
    def test_security_check_1_network_isolation(self, tmp_path: Path) -> None:
        """Verify that network isolation cannot be bypassed in production configuration."""
        runner = HardenedContainerRunner(ContainerConfig(network_disabled=True))
        args = runner.build_docker_run_args("c_net", tmp_path, "pytest")

        assert "--network" in args
        idx = args.index("--network")
        assert args[idx + 1] == "none"

    @pytest.mark.adversarial
    def test_security_check_2_readonly_rootfs_and_noexec_tmpfs(self, tmp_path: Path) -> None:
        """Verify root filesystem is read-only and /tmp has noexec,nosuid flags."""
        runner = HardenedContainerRunner(ContainerConfig(read_only_rootfs=True))
        args = runner.build_docker_run_args("c_ro", tmp_path, "pytest")

        assert "--read-only" in args
        # Check that /tmp tmpfs specifies noexec and nosuid
        tmpfs_args = [args[i + 1] for i, x in enumerate(args) if x == "--tmpfs"]
        assert any("/tmp" in t and "noexec" in t and "nosuid" in t for t in tmpfs_args)

    @pytest.mark.adversarial
    def test_security_check_3_capabilities_dropped_and_no_new_privileges(
        self, tmp_path: Path
    ) -> None:
        """Verify all Linux capabilities are dropped and privilege escalation is barred."""
        runner = HardenedContainerRunner()
        args = runner.build_docker_run_args("c_priv", tmp_path, "pytest")

        assert "--cap-drop=ALL" in args
        assert "--security-opt" in args
        sec_idx = args.index("--security-opt")
        assert args[sec_idx + 1] == "no-new-privileges"

    @pytest.mark.adversarial
    def test_security_check_4_resource_limits_fork_bomb_and_oom_guards(
        self, tmp_path: Path
    ) -> None:
        """Verify strict memory, pids-limit, and cpu constraints are attached."""
        runner = HardenedContainerRunner(
            ContainerConfig(pids_limit=32, memory_limit="256m", cpus="0.5")
        )
        args = runner.build_docker_run_args("c_res", tmp_path, "pytest")

        assert "--pids-limit=32" in args
        assert "--memory=256m" in args
        assert "--cpus=0.5" in args

    @pytest.mark.adversarial
    def test_security_check_5_no_host_credentials_or_docker_socket(self, tmp_path: Path) -> None:
        """Verify Docker socket, user HOME, and host secrets are NEVER mounted."""
        runner = HardenedContainerRunner()
        args = runner.build_docker_run_args("c_leak", tmp_path, "pytest")

        joined_args = " ".join(args)
        assert "docker.sock" not in joined_args
        assert ".aws" not in joined_args
        assert ".ssh" not in joined_args

        # Ensure only a single volume mount exists (the workspace directory)
        vol_mounts = [args[i + 1] for i, x in enumerate(args) if x == "-v"]
        assert len(vol_mounts) == 1
        assert vol_mounts[0].endswith(":/workspace:rw")

    @pytest.mark.adversarial
    def test_security_check_6_infinite_loop_timeout_and_container_cleanup(
        self, tmp_path: Path
    ) -> None:
        """Verify that an infinite loop or hanging process terminates on timeout and forces docker rm -f."""
        runner = HardenedContainerRunner(ContainerConfig(timeout_seconds=0.2))

        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="while true", timeout=0.2)

        with patch("subprocess.Popen", return_value=mock_proc), patch("subprocess.run") as mock_run:
            with pytest.raises(HarnessTimeoutError):
                runner.run_in_container(
                    case_id="adv-timeout",
                    patch_diff_hash="baseline",
                    workspace_host_path=tmp_path,
                    command="python -c 'while True: pass'",
                )

            # Verification: docker rm -f <container_name> was executed in finally block
            mock_proc.kill.assert_called()
            called_cmds = [call.args[0] for call in mock_run.call_args_list if call.args]
            assert any(
                cmd[0] == "docker" and cmd[1] == "rm" and cmd[2] == "-f" for cmd in called_cmds
            )

    @pytest.mark.adversarial
    def test_security_check_7_output_flood_truncation(self, tmp_path: Path) -> None:
        """Verify that generating megabytes of output (yes 'flood') is truncated at max_output_bytes."""
        runner = HardenedContainerRunner(ContainerConfig(max_output_bytes=512))

        # 5 MB of output
        huge_output = b"x" * (5 * 1024 * 1024)
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (huge_output, b"")
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc):
            res = runner.run_in_container(
                case_id="adv-flood",
                patch_diff_hash="baseline",
                workspace_host_path=tmp_path,
                command="yes 'flood'",
            )

        assert res.stdout_truncated is True
        assert len(res.stdout) == 512
        assert len(res.stdout.encode("utf-8")) == 512


class TestNormalizerFixtureM1Reproduction:
    @pytest.mark.adversarial
    def test_fixture_bug_and_fix_behavior(self) -> None:
        """Verify the normalizer fixture reproduces the exact bug and fix behavior."""
        # Buggy behavior: fails internal spaces and control chars
        assert normalize_token_buggy("foo   bar") == "foo   bar"
        assert normalize_token_buggy("foo\x00bar") == "foo\x00bar"

        # Fixed behavior: collapses internal spaces and strips control chars
        assert normalize_token_fixed("foo   bar") == "foo bar"
        assert normalize_token_fixed("foo\x00bar") == "foobar"

    @pytest.mark.adversarial
    def test_fixture_workspace_setup(self, tmp_path: Path) -> None:
        """Verify WorkspaceManager writes normalizer files cleanly and scrubbed."""
        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_str:
            ws = Path(ws_str)
            src_file = ws / "normalizer.py"
            test_file = ws / "test_normalizer.py"

            mgr.atomic_write(src_file, NORMALIZER_BUGGY_SOURCE)
            mgr.atomic_write(test_file, NORMALIZER_TEST_SOURCE)

            assert src_file.exists()
            assert test_file.exists()
            assert "def normalize_token" in src_file.read_text(encoding="utf-8")
            assert "test_collapses_internal_whitespace" in test_file.read_text(encoding="utf-8")

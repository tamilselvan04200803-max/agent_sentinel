"""Live Docker integration tests for Milestone 1 & 2 container sandbox.

These tests execute against the REAL Docker daemon on the host using the
``agentsentinel-runner:py311`` image (python:3.11-slim + pytest==8.4.2 pre-baked).

Tests are automatically skipped if:
  - The Docker daemon is unreachable.
  - The ``agentsentinel-runner:py311`` image has not been built locally
    (run: ``docker build -t agentsentinel-runner:py311 -f Dockerfile.runner .``).

This provides ground-truth kernel/VFS verification:
  - Real ``python -m pytest -q`` inside ``--network=none`` container.
  - Workspace mounted ``:ro`` (VFS-enforced read-only).
  - Container reaper guarantees (no zombie ``agentsentinel-*`` containers).
  - M2 patch applier integration: diff → validate → apply → container → ExitCode.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from agentsentinel.domain.exceptions import HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import PatchProposal
from agentsentinel.policy.applier import apply_validated_patch
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.sandbox.workspace import WorkspaceManager
from tests.fixtures.normalizer import (
    NORMALIZER_BUGGY_SOURCE,
    NORMALIZER_FIXED_SOURCE,
    NORMALIZER_PATCH_DIFF,
    NORMALIZER_TEST_SOURCE,
)

RUNNER_IMAGE = "agentsentinel-runner:py311"
FALLBACK_IMAGE = "python:3.11-slim"


def is_docker_daemon_running() -> bool:
    """Return True iff 'docker info' succeeds against a live daemon."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0,
            check=False,
        )
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def is_runner_image_available() -> bool:
    """Return True iff agentsentinel-runner:py311 image exists locally."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "image", "inspect", RUNNER_IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0,
            check=False,
        )
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


DOCKER_AVAILABLE = is_docker_daemon_running()
RUNNER_IMAGE_AVAILABLE = DOCKER_AVAILABLE and is_runner_image_available()

skip_without_docker = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="Docker daemon is not running or unreachable on host OS",
)

skip_without_runner_image = pytest.mark.skipif(
    not RUNNER_IMAGE_AVAILABLE,
    reason=(
        f"Docker image '{RUNNER_IMAGE}' not found locally. "
        "Run: docker build -t agentsentinel-runner:py311 -f Dockerfile.runner ."
    ),
)


@pytest.mark.integration
@skip_without_docker
@skip_without_runner_image
class TestDockerLiveM1:
    """Real Docker engine execution verification using agentsentinel-runner:py311."""

    def test_live_broken_m0_normalizer_fails(self, tmp_path: Path) -> None:
        """Verify buggy normalizer fails tests using real python -m pytest inside container."""
        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_str:
            ws = Path(ws_str)
            (ws / "normalizer.py").write_text(NORMALIZER_BUGGY_SOURCE, encoding="utf-8")
            (ws / "test_normalizer.py").write_text(NORMALIZER_TEST_SOURCE, encoding="utf-8")

            runner = HardenedContainerRunner(
                ContainerConfig(
                    image=RUNNER_IMAGE,
                    timeout_seconds=30.0,
                )
            )

            # Real pytest inside --network=none container with /workspace:ro
            res = runner.run_in_container(
                case_id="case-live-broken",
                patch_diff_hash="baseline",
                workspace_host_path=ws,
                command="python -m pytest -q test_normalizer.py",
            )

            assert res.exit_code == ExitCode.TESTS_FAILED, (
                f"Expected TESTS_FAILED(1), got {res.exit_code}.\n"
                f"stdout: {res.stdout}\nstderr: {res.stderr}"
            )
            assert res.failed is True

    def test_live_fixed_m0_normalizer_passes(self, tmp_path: Path) -> None:
        """Verify fixed normalizer passes with ExitCode.OK using real python -m pytest."""
        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_str:
            ws = Path(ws_str)
            (ws / "normalizer.py").write_text(NORMALIZER_FIXED_SOURCE, encoding="utf-8")
            (ws / "test_normalizer.py").write_text(NORMALIZER_TEST_SOURCE, encoding="utf-8")

            runner = HardenedContainerRunner(
                ContainerConfig(
                    image=RUNNER_IMAGE,
                    timeout_seconds=30.0,
                )
            )

            res = runner.run_in_container(
                case_id="case-live-fixed",
                patch_diff_hash="fixed",
                workspace_host_path=ws,
                command="python -m pytest -q test_normalizer.py",
            )

            assert res.exit_code == ExitCode.OK, (
                f"Expected OK(0), got {res.exit_code}.\n"
                f"stdout: {res.stdout}\nstderr: {res.stderr}"
            )
            assert res.passed is True

    def test_live_workspace_is_read_only(self, tmp_path: Path) -> None:
        """Verify /workspace is mounted :ro — any write attempt raises OSError inside container."""
        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_str:
            ws = Path(ws_str)
            (ws / "dummy.py").write_text("x = 1\n", encoding="utf-8")

            runner = HardenedContainerRunner(
                ContainerConfig(image=RUNNER_IMAGE, timeout_seconds=10.0)
            )

            res = runner.run_in_container(
                case_id="case-live-ro",
                patch_diff_hash="baseline",
                workspace_host_path=ws,
                command="python -c \"open('/workspace/evil.py', 'w').write('pwned')\"",
            )

            # Must NOT succeed — OSError: Read-only file system
            assert res.exit_code != ExitCode.OK, (
                "Container wrote to :ro workspace mount — VFS enforcement FAILED!"
            )
            assert (
                "Read-only" in res.stderr
                or "Permission denied" in res.stderr
                or "OSError" in res.stderr
                or res.exit_code == ExitCode.TESTS_FAILED
            )

    def test_live_network_isolation(self, tmp_path: Path) -> None:
        """Verify real network isolation: outbound socket connection fails with OSError."""
        runner = HardenedContainerRunner(
            ContainerConfig(
                image=RUNNER_IMAGE,
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
            "OSError" in res.stderr
            or "Network is unreachable" in res.stderr
            or "101" in res.stderr
        )

    def test_live_timeout_and_no_leftover_container(self, tmp_path: Path) -> None:
        """Verify real process timeout reaps container and leaves zero zombie containers."""
        runner = HardenedContainerRunner(
            ContainerConfig(
                image=RUNNER_IMAGE,
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

        # Check docker ps -a to ensure no running or exited container remains
        ps_out = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=agentsentinel-", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert ps_out.stdout.strip() == "", (
            f"Zombie containers found: {ps_out.stdout.strip()}"
        )


@pytest.mark.integration
@skip_without_docker
@skip_without_runner_image
class TestDockerLiveM2PatchApplier:
    """End-to-end patch application integration tests using real Docker container execution.

    Proves the M2 bridge: M0 buggy fixture → diff_parser → validator → applier →
    HardenedContainerRunner → ExitCode.TESTS_FAILED → ExitCode.OK.
    """

    def test_patch_application_transitions_fail_to_pass(self, tmp_path: Path) -> None:
        """Apply the M0 fix diff to a broken workspace and verify it transitions to ExitCode.OK."""
        # Set up a baseline workspace with the buggy normalizer
        source_ws = tmp_path / "source"
        source_ws.mkdir()
        (source_ws / "normalizer.py").write_text(NORMALIZER_BUGGY_SOURCE, encoding="utf-8")
        (source_ws / "test_normalizer.py").write_text(NORMALIZER_TEST_SOURCE, encoding="utf-8")

        # First: confirm baseline FAILS inside real container
        runner = HardenedContainerRunner(
            ContainerConfig(image=RUNNER_IMAGE, timeout_seconds=30.0)
        )
        baseline_result = runner.run_in_container(
            case_id="case-patch-test",
            patch_diff_hash="baseline",
            workspace_host_path=source_ws,
            command="python -m pytest -q test_normalizer.py",
        )
        assert baseline_result.exit_code == ExitCode.TESTS_FAILED, (
            f"Baseline must fail. Got {baseline_result.exit_code}.\n{baseline_result.stdout}"
        )

        # Build a PatchProposal with the M0 fix diff
        patch = PatchProposal(
            case_id="case-patch-test",
            unified_diff=NORMALIZER_PATCH_DIFF,
            model_id="stub/test",
            prompt_tokens=100,
            completion_tokens=50,
        )

        # Apply validated patch to a fresh workspace copy
        allowed = ("normalizer.py",)
        patched_ws = apply_validated_patch(
            patch=patch,
            source_workspace=source_ws,
            allowed_edit_paths=allowed,
        )

        try:
            # Copy test file into the patched workspace (it's separate from the diff)
            (patched_ws / "test_normalizer.py").write_text(
                NORMALIZER_TEST_SOURCE, encoding="utf-8"
            )

            # Execute the patched workspace inside a real container
            patched_result = runner.run_in_container(
                case_id="case-patch-test",
                patch_diff_hash=patch.diff_hash,
                workspace_host_path=patched_ws,
                command="python -m pytest -q test_normalizer.py",
            )

            assert patched_result.exit_code == ExitCode.OK, (
                f"Patched workspace must pass. Got {patched_result.exit_code}.\n"
                f"stdout: {patched_result.stdout}\nstderr: {patched_result.stderr}"
            )
            assert patched_result.passed is True

        finally:
            import shutil as _shutil
            _shutil.rmtree(patched_ws, ignore_errors=True)


class TestDockerLiveM5BenchmarkAdmission:
    """Verifies that M5 Benchmark admission verification runs cleanly against
    the real Docker container runner, confirming Gate 1 (baseline fails) and
    Gate 2 (reference fix passes) with full container isolation.
    """

    @pytest.mark.integration
    def test_live_docker_benchmark_admission_case_03_and_01(self) -> None:
        if not is_docker_daemon_running() or not is_runner_image_available():
            pytest.skip("Docker daemon or runner image unavailable")

        import json
        from datetime import UTC, datetime

        from agentsentinel.domain.models import CaseSpec
        from agentsentinel.evaluation.harness import verify_case_admission
        from agentsentinel.evaluation.models import BenchmarkCase

        fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures" / "benchmark_cases"

        def _load(case_name: str) -> BenchmarkCase:
            case_dir = fixtures_dir / case_name
            raw = json.loads((case_dir / "spec.json").read_text(encoding="utf-8"))
            spec = CaseSpec(
                case_id=raw["case_id"],
                repo_url=raw["repo_url"],
                base_commit=raw["base_commit"],
                test_command=raw["test_command"],
                allowed_edit_paths=tuple(raw["allowed_edit_paths"]),
                failing_test_ids=tuple(raw["failing_test_ids"]),
                created_at=datetime.now(UTC),
            )
            return BenchmarkCase(
                case_spec=spec,
                repo_source_path=case_dir / "src",
                base_commit=spec.base_commit,
                test_patch=(case_dir / "test.patch").read_text(encoding="utf-8"),
                reference_fix_patch=(case_dir / "reference.patch").read_text(encoding="utf-8"),
                fail_to_pass_tests=spec.failing_test_ids,
                pass_to_pass_tests=(),
                is_public_historical_commit=False,
            )

        # Test both case_03_none_coalescing and case_01_normalizer
        for case_name in ("case_03_none_coalescing", "case_01_normalizer"):
            case = _load(case_name)
            verdict = verify_case_admission(case)
            assert verdict.admitted is True, f"Failed admission for {case_name}: {verdict.reason}"
            assert verdict.baseline_exit_code == ExitCode.TESTS_FAILED.value
            assert verdict.reference_exit_code == ExitCode.OK.value


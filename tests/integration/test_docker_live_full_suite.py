"""A targeted fix must not erase a passing-test repair during minimization."""

from __future__ import annotations

import subprocess
from difflib import unified_diff
from typing import TYPE_CHECKING
from unittest import SkipTest

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.verification.post_pass_gate import run_ddmin_hunk_minimization

if TYPE_CHECKING:
    from pathlib import Path


def _require_docker() -> None:
    for command in (["docker", "info"], ["docker", "image", "inspect", "agentsentinel-runner:py311"]):
        try:
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise SkipTest("Live Docker runner is unavailable") from error
        if result.returncode:
            raise SkipTest("Live Docker daemon or runner image is unavailable")


def test_live_minimized_subset_must_preserve_passing_test(tmp_path: Path) -> None:
    _require_docker()
    baseline, patched = tmp_path / "baseline", tmp_path / "patched"
    baseline.mkdir()
    patched.mkdir()
    before = "def a(s):\n    return s.lower()\n\n\n\ndef b(s):\n    return a(s)\n\n\n\ndef noise(x):\n    return x\n"
    after = before.replace("return s.lower()", "return s.strip().upper()").replace("return a(s)", "return a(s).lower()").replace("return x", "return x + 1")
    tests = "from m import a, b\ndef test_fix():\n    assert a(' A ') == 'A'\ndef test_passing():\n    assert b('A') == 'a'\n"
    for workspace, source in ((baseline, before), (patched, after)):
        (workspace / "m.py").write_text(source, encoding="utf-8", newline="\n")
        (workspace / "test_m.py").write_text(tests, encoding="utf-8", newline="\n")
    full = ["python", "-m", "pytest", "-v", "test_m.py"]

    class Runner(HardenedContainerRunner):
        full_failures = 0

        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            execution = super().run_in_container(case_id, patch_diff_hash, workspace_host_path, command)
            if command == full and execution.exit_code == ExitCode.TESTS_FAILED:
                self.full_failures += 1
            return execution

    runner = Runner(ContainerConfig(image="agentsentinel-runner:py311"))
    original = runner.run_in_container("case", "original", patched, full)
    assert original.passed
    raw = "".join(unified_diff(before.splitlines(True), after.splitlines(True), "a/m.py", "b/m.py", n=1))
    spec = CaseSpec("case", "local", "a" * 40, "python -m pytest -v test_m.py", ("m.py",), ("test_m.py::test_fix",))
    selected, execution, summary = run_ddmin_hunk_minimization(
        raw_diff=raw, baseline_workspace=baseline, spec=spec, runner=runner,
        original_result=original, full_suite_command=full,
    )
    assert summary.raw_hunks_count == 3 and summary.minimized_hunks_count == 2
    assert "return s.strip().upper()" in selected
    assert "return a(s).lower()" in selected
    assert "return x + 1" not in selected
    assert runner.full_failures >= 1
    assert "test_m.py::test_passing PASSED" in execution.stdout
    assert (baseline / "m.py").read_text(encoding="utf-8") == before

"""Exercise the opt-in R&D paths through the hardened Docker boundary."""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.policy.diff_parser import UnifiedDiffParser
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.verification.differential_mutation import DifferentialPatchMutant
from agentsentinel.verification.mutation_batch import run_in_container_mutation_batch_detailed
from agentsentinel.verification.post_pass_gate import run_ddmin_hunk_minimization
from tests.integration.test_docker_live_m1 import (
    RUNNER_IMAGE,
    skip_without_docker,
    skip_without_runner_image,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = [pytest.mark.integration, skip_without_docker, skip_without_runner_image]


class CountingRunner(HardenedContainerRunner):
    calls: int = 0

    def run_in_container(
        self,
        case_id: str,
        patch_diff_hash: str,
        workspace_host_path: Path,
        command: str | list[str],
    ) -> ExecutionResult:
        self.calls += 1
        return super().run_in_container(case_id, patch_diff_hash, workspace_host_path, command)


def test_live_one_container_preserves_order_timeout_cleanup_and_source_mount(
    tmp_path: Path,
) -> None:
    fixed = "def normalize(s):\n    return s.strip().lower()\n"
    (tmp_path / "m.py").write_text(fixed, encoding="utf-8", newline="\n")
    (tmp_path / "test_m.py").write_text(
        "from m import normalize\ndef test_fix():\n    assert normalize(' A ') == 'a'\n",
        encoding="utf-8",
        newline="\n",
    )
    runner = CountingRunner(ContainerConfig(image=RUNNER_IMAGE, timeout_seconds=30))
    sources = (
        fixed,
        "def normalize(s):\n    return s\n",
        "def normalize(s):\n    import subprocess, sys\n"
        "    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "    while True:\n        continue\n",
        fixed,
        "def normalize(s):\n    from pathlib import Path\n"
        "    Path('/workspace/m.py').write_text('changed')\n    return s\n",
    )
    mutants = tuple(
        DifferentialPatchMutant("m.py", "normalize", str(index), source)
        for index, source in enumerate(sources)
    )
    reports = run_in_container_mutation_batch_detailed(
        runner=runner,
        case_id="live-rd-batch",
        patch_diff_hash="accepted",
        workspace_host_path=tmp_path,
        mutants=mutants,
        failing_test_ids=("test_m.py::test_fix",),
        baseline_wall_seconds=0.1,
    )
    assert runner.calls == 1
    assert [report.status for report in reports] == [
        "SURVIVED",
        "KILLED",
        "KILLED_BY_TIMEOUT",
        "SURVIVED",
        "KILLED",
    ]
    assert [report.exit_code for report in reports] == [0, 1, None, 0, 1]
    assert reports[2].runtime_sec == 1.0
    assert len({report.mutant_id for report in reports}) == len(mutants)
    assert (tmp_path / "m.py").read_text(encoding="utf-8") == fixed
    assert not list(tmp_path.glob(".agentsentinel_mutation_*"))


def test_live_detached_descendant_cannot_contaminate_next_mutant(tmp_path: Path) -> None:
    fixed = "def normalize(s):\n    return s.strip().lower()\n"
    (tmp_path / "m.py").write_text(fixed, encoding="utf-8", newline="\n")
    (tmp_path / "test_m.py").write_text(
        "from m import normalize\ndef test_fix():\n    assert normalize(' A ') == 'a'\n",
        encoding="utf-8",
        newline="\n",
    )
    child = "import time; from pathlib import Path; time.sleep(5.5); Path('/tmp/mut_workspace/detached-marker').write_text('contaminated')"
    timeout_source = (
        "def normalize(s):\n    import subprocess, sys\n"
        f"    subprocess.Popen([sys.executable, '-c', {child!r}], start_new_session=True)\n"
        "    while True:\n        continue\n"
    )
    survivor_source = (
        "def normalize(s):\n    import time\n    from pathlib import Path\n"
        "    time.sleep(2)\n    assert not Path('/tmp/mut_workspace/detached-marker').exists()\n"
        "    return s.strip().lower()\n"
    )
    reports = run_in_container_mutation_batch_detailed(
        runner=HardenedContainerRunner(ContainerConfig(image=RUNNER_IMAGE, timeout_seconds=30)),
        case_id="live-rd-detached",
        patch_diff_hash="accepted",
        workspace_host_path=tmp_path,
        mutants=(
            DifferentialPatchMutant("m.py", "normalize", "detached timeout", timeout_source),
            DifferentialPatchMutant("m.py", "normalize", "clean next test", survivor_source),
        ),
        failing_test_ids=("test_m.py::test_fix",),
        baseline_wall_seconds=2.0,
    )
    assert [report.status for report in reports] == ["KILLED_BY_TIMEOUT", "SURVIVED"]
    assert (tmp_path / "m.py").read_text(encoding="utf-8") == fixed


def test_live_iterative_search_removes_multiple_independent_dead_hunks(tmp_path: Path) -> None:
    baseline, patched = tmp_path / "baseline", tmp_path / "patched"
    baseline.mkdir()
    patched.mkdir()
    before = "\n\n".join(f"def {name}(x):\n    return x\n" for name in ("a", "b", "c", "d", "e"))
    after = before.replace("return x", "return x + 1")
    tests = "from m import a, b\ndef test_fix():\n    assert a(9) == 10\n    assert b(19) == 20\n"
    for workspace, source in ((baseline, before), (patched, after)):
        (workspace / "m.py").write_text(source, encoding="utf-8", newline="\n")
        (workspace / "test_m.py").write_text(tests, encoding="utf-8", newline="\n")
    raw = "".join(
        difflib.unified_diff(
            before.splitlines(True), after.splitlines(True), "a/m.py", "b/m.py", n=1
        )
    )
    runner = HardenedContainerRunner(ContainerConfig(image=RUNNER_IMAGE, timeout_seconds=30))
    spec = CaseSpec(
        "live-rd-ddmin", "local", "a" * 40, "python -m pytest", ("m.py",), ("test_m.py::test_fix",)
    )
    original = runner.run_in_container(
        spec.case_id, "raw", patched, ["python", "-m", "pytest", "-v", "test_m.py::test_fix"]
    )
    selected, result, summary = run_ddmin_hunk_minimization(
        raw_diff=raw,
        baseline_workspace=baseline,
        spec=spec,
        runner=runner,
        original_result=original,
        iterative=True,
    )
    assert summary.raw_hunks_count == 5
    assert summary.minimized_hunks_count == 2
    assert summary.codeslop_hunks_removed == 3
    assert sum(len(file.hunks) for file in UnifiedDiffParser.parse(selected).files) == 2
    assert result.passed
    assert (baseline / "m.py").read_text(encoding="utf-8") == before

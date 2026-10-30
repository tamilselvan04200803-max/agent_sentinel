"""Actual Linux Docker coverage: inspected fixture code runs only in the sandbox."""
from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING
from unittest import SkipTest

import pytest

from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.verification.statement_coverage import run_statement_coverage_probe

if TYPE_CHECKING:
    from pathlib import Path


def require_docker():
    for command in (["docker", "info"], ["docker", "image", "inspect", "agentsentinel-runner:py311"]):
        try:
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise SkipTest("Live Docker runner unavailable") from error
        if result.returncode:
            raise SkipTest("Live Docker daemon/image unavailable")


@pytest.mark.integration
def test_live_statement_observations_and_read_only_input(tmp_path: Path):
    require_docker()
    source = "def choose(value):\n    if value:\n        return 1\n    return 2\n"
    tests = "from pathlib import Path\nimport pytest\nfrom m import choose\ndef test_fix():\n    assert choose(True) == 1\n    with pytest.raises(OSError):\n        Path('/workspace/m.py').write_text('tampered')\n"
    (tmp_path / "m.py").write_text(source, encoding="utf-8", newline="\n")
    (tmp_path / "test_m.py").write_text(tests, encoding="utf-8", newline="\n")
    runner = HardenedContainerRunner(ContainerConfig(image="agentsentinel-runner:py311"))
    report = run_statement_coverage_probe(
        runner=runner, case_id="live-m16", patch_diff_hash="patch", workspace_host_path=tmp_path,
        failing_test_ids=("test_m.py::test_fix",), statement_lines=(("m.py", 3), ("m.py", 4)),
        timeout_seconds=10.0,
    )
    assert report.covered_statements == (("m.py", 3),)
    assert report.uncovered_statements == (("m.py", 4),)
    assert report.test_exit_code == 0 and not report.timed_out
    assert (tmp_path / "m.py").read_text(encoding="utf-8") == source
    assert sorted(path.name for path in tmp_path.iterdir()) == ["m.py", "test_m.py"]


@pytest.mark.integration
def test_live_trace_timeout_cleans_descendants_and_preserves_source(tmp_path: Path):
    require_docker()
    source = "def work():\n    return 1\n"
    tests = "import subprocess\nimport sys\nimport time\ndef test_slow():\n    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n    time.sleep(60)\n"
    (tmp_path / "m.py").write_text(source, encoding="utf-8", newline="\n")
    (tmp_path / "test_m.py").write_text(tests, encoding="utf-8", newline="\n")
    runner = HardenedContainerRunner(ContainerConfig(image="agentsentinel-runner:py311"))
    report = run_statement_coverage_probe(
        runner=runner, case_id="live-m16-timeout", patch_diff_hash="patch", workspace_host_path=tmp_path,
        failing_test_ids=("test_m.py::test_slow",), statement_lines=(("m.py", 2),),
        timeout_seconds=1.0,
    )
    assert report.timed_out and report.test_exit_code is None
    assert report.covered_statements == () and report.needs_review
    assert (tmp_path / "m.py").read_text(encoding="utf-8") == source

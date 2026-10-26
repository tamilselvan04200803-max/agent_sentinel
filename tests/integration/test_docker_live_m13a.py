"""Execute M13A verification with the real read-only Docker sandbox."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.models import CaseSpec
from agentsentinel.orchestrator.checkpoint import RunState
from agentsentinel.orchestrator.state_machine import RepairStateMachine
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.verification.differential_mutation import DifferentialPatchMutant
from agentsentinel.verification.mutation_batch import run_in_container_mutation_batch
from tests.integration.test_docker_live_m1 import (
    RUNNER_IMAGE,
    skip_without_docker,
    skip_without_runner_image,
)
from tests.unit.test_m13a_state_machine import FixedLLM

if TYPE_CHECKING:
    from pathlib import Path


def populate_source(source: Path) -> None:
    source.mkdir()
    (source / "m.py").write_text(
        "UNUSED_FLAG = 0\n\n\n\ndef normalize(s):\n    return s.lower()\n",
        encoding="utf-8", newline="\n",
    )
    (source / "test_m.py").write_text(
        "from m import normalize\n\ndef test_fix():\n    assert normalize(' A ') == 'a'\n",
        encoding="utf-8", newline="\n",
    )


@pytest.mark.integration
@skip_without_docker
@skip_without_runner_image
def test_live_minimize_then_probe_before_approval(tmp_path: Path) -> None:
    source = tmp_path / "source"
    populate_source(source)
    original = (source / "m.py").read_bytes()
    machine = RepairStateMachine(
        spec=CaseSpec("m13a", "local", "a" * 40, "python -m pytest -v test_m.py",
                      ("m.py",), ("test_m.py::test_fix",)),
        llm_client=FixedLLM(),
        container_runner=HardenedContainerRunner(ContainerConfig(image=RUNNER_IMAGE)),
        source_workspace_override=source, image_digest="sha256:live-m13a",
        db_path=tmp_path / "live.db", enable_ddmin_minimization=True, enable_mutation_probe=True,
    )
    rid = machine.start_run()
    try:
        rec = machine.run_to_terminal(rid)
        assert rec.state is RunState.AWAITING_HUMAN_APPROVAL
        binding = rec.approval_record
        assert binding["minimization_summary"]["raw_hunks_count"] == 2
        assert binding["minimization_summary"]["minimized_hunks_count"] == 1
        assert binding["mutation_adequacy_summary"]["mutants_killed"] >= 1
        assert binding["mutation_adequacy_summary"]["low_mutation_adequacy"] is False
        machine.approve_run(
            rid, "live-reviewer", expected_diff_hash=binding["diff_hash"],
            expected_image_digest=binding["image_digest"],
            expected_post_patch_result_hash=binding["post_patch_result_hash"],
        )
        bundle = machine.export_evidence_bundle(rid)
        assert "UNUSED_FLAG = 999" not in bundle.accepted_patch.unified_diff
        assert bundle.final_result.passed
        assert (source / "m.py").read_bytes() == original
    finally:
        machine._store.close()


@pytest.mark.integration
@skip_without_docker
@skip_without_runner_image
def test_live_mutation_shadow_survival_failure_and_timeout(tmp_path: Path) -> None:
    source = tmp_path / "source"
    populate_source(source)
    fixed = "def normalize(s):\n    return s.strip().lower()\n"
    (source / "m.py").write_text(fixed, encoding="utf-8", newline="\n")
    mutants = (
        DifferentialPatchMutant("m.py", "normalize", "equivalent", fixed),
        DifferentialPatchMutant("m.py", "normalize", "remove normalization",
                                "def normalize(s):\n    return s\n"),
        DifferentialPatchMutant(
            "m.py", "normalize", "timeout and descendant cleanup",
            "def normalize(s):\n    import subprocess, sys\n"
            "    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "    while True:\n        continue\n",
        ),
        DifferentialPatchMutant(
            "m.py", "normalize", "read-only source write",
            "def normalize(s):\n    from pathlib import Path\n"
            "    Path('/workspace/m.py').write_text('changed')\n    return s\n",
        ),
    )
    runner = HardenedContainerRunner(ContainerConfig(image=RUNNER_IMAGE, timeout_seconds=20))
    killed = run_in_container_mutation_batch(
        runner=runner, case_id="m13a-batch", patch_diff_hash="accepted",
        workspace_host_path=source, mutants=mutants,
        failing_test_ids=("test_m.py::test_fix",), baseline_wall_seconds=0.1,
    )
    assert killed == (False, True, True, True)
    assert (source / "m.py").read_text(encoding="utf-8") == fixed

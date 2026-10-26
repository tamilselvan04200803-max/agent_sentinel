"""Post-pass approval, persistence, and export integration without executing source."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from agentsentinel.cli.exporter import export_evidence_bundle
from agentsentinel.domain.exceptions import (
    HarnessSetupError,
    InfrastructureFailureError,
    OverfitPolicyError,
)
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import (
    CaseSpec,
    ExecutionResult,
    MinimizationSummary,
    MutationAdequacySummary,
    PatchProposal,
    SurvivedMutantDetail,
)
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator import state_machine as sm_mod
from agentsentinel.orchestrator.checkpoint import CheckpointStore, RunState, TerminationReason
from agentsentinel.orchestrator.state_machine import RepairStateMachine

if TYPE_CHECKING:
    from pathlib import Path

RAW = (
    "--- a/m.py\n+++ b/m.py\n@@ -1,3 +1,3 @@\n-UNUSED_FLAG = 0\n+UNUSED_FLAG = 999\n \n \n"
    "@@ -5,2 +5,2 @@\n def normalize(s):\n-    return s.lower()\n"
    "+    return s.strip().lower()\n"
)
MINIMAL = (
    "--- a/m.py\n+++ b/m.py\n@@ -5,2 +5,2 @@\n def normalize(s):\n"
    "-    return s.lower()\n+    return s.strip().lower()\n"
)


class FixedLLM:
    def generate_patch(self, case_id, prompt, model_id):
        return PatchProposal(case_id, RAW, "fake", 10, 5), ModelUsage("fake", 10, 5)


class PassingRunner:
    def __init__(self):
        self.calls = 0

    def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
        self.calls += 1
        return ExecutionResult(
            case_id, patch_diff_hash,
            ExitCode.TESTS_FAILED if patch_diff_hash == "baseline" else ExitCode.OK,
            "FAILED" if patch_diff_hash == "baseline" else "test_m.py::test_fix PASSED",
            "", 0.2,
        )


def make_machine(tmp_path: Path, **options):
    source = tmp_path / "source"
    source.mkdir()
    (source / "m.py").write_text(
        "UNUSED_FLAG = 0\n\n\n\ndef normalize(s):\n    return s.lower()\n",
        encoding="utf-8", newline="\n",
    )
    runner = PassingRunner()
    machine = RepairStateMachine(
        spec=CaseSpec("m13a", "local", "a" * 40, "pytest -v", ("m.py",),
                      ("test_m.py::test_fix",)),
        llm_client=FixedLLM(), container_runner=runner,
        source_workspace_override=source, image_digest="sha256:test",
        db_path=tmp_path / "run.db", **options,
    )
    return machine, runner


def test_adopted_patch_survivors_and_export_survive_reopen(tmp_path, monkeypatch):
    calls = []

    def minimize(**kwargs):
        calls.append("minimize")
        result = replace(kwargs["original_result"],
                         patch_diff_hash=hashlib.sha256(MINIMAL.encode()).hexdigest())
        return MINIMAL, result, MinimizationSummary(2, 1, 1, True)

    def probe(**kwargs):
        calls.append("probe")
        assert kwargs["minimized_diff"] == MINIMAL
        source = (kwargs["patched_workspace"] / "m.py").read_text(encoding="utf-8")
        assert "UNUSED_FLAG = 0" in source
        assert "s.strip().lower()" in source
        assert kwargs["post_patch_result"].passed
        return MutationAdequacySummary(True, 1, 0, 1, 0.0, (
            SurvivedMutantDetail("mut-1", "m.py", "normalize", "drop lower"),
        ))

    monkeypatch.setattr(sm_mod, "run_ddmin_hunk_minimization", minimize, raising=False)
    monkeypatch.setattr(sm_mod, "run_mutation_adequacy_probe", probe, raising=False)
    machine, runner = make_machine(tmp_path, enable_ddmin_minimization=True,
                                  enable_mutation_probe=True, auto_approve_on_fix=True)
    rid = machine.start_run()
    rec = machine.run_to_terminal(rid)
    assert rec.state is RunState.AWAITING_HUMAN_APPROVAL
    assert calls == ["minimize", "probe"]
    assert runner.calls == 2
    assert rec.attempts_used == 1
    approval = rec.approval_record
    assert approval["diff_hash"] == hashlib.sha256(MINIMAL.encode()).hexdigest()
    assert approval["original_proposal"]["unified_diff"] == RAW
    assert approval["minimization_summary"]["codeslop_hunks_removed"] == 1
    assert approval["mutation_adequacy_summary"]["low_mutation_adequacy"] is True
    assert not machine._pending_patched_ws
    machine._store.close()

    reopened = RepairStateMachine(
        spec=machine.spec, llm_client=FixedLLM(), container_runner=runner,
        image_digest="sha256:test", db_path=tmp_path / "run.db",
    )
    assert reopened.resume_run(rid).state is RunState.AWAITING_HUMAN_APPROVAL
    reopened.approve_run(
        rid, "human", expected_diff_hash=approval["diff_hash"],
        expected_image_digest=approval["image_digest"],
        expected_post_patch_result_hash=approval["post_patch_result_hash"],
    )
    bundle = reopened.export_evidence_bundle(rid)
    assert bundle.accepted_patch.unified_diff == MINIMAL
    assert bundle.final_result.patch_diff_hash == bundle.accepted_patch.diff_hash
    assert bundle.minimization_summary == MinimizationSummary(2, 1, 1, True)
    assert bundle.mutation_adequacy_summary.survived_mutant_details[0].mutant_id == "mut-1"
    assert bundle.to_summary_dict()["mutation_adequacy_summary"]["mutation_score"] == 0.0
    out = export_evidence_bundle(tmp_path / "run.db", rid, tmp_path / "out")
    assert (out / "approved.patch").read_text(encoding="utf-8") == MINIMAL
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["evidence_bundle"]["minimization_summary"]["was_minimized"] is True
    assert evidence["evidence_bundle"]["mutation_adequacy_summary"]["low_mutation_adequacy"]
    report = (out / "REPORT.md").read_text(encoding="utf-8")
    assert "mut-1" in report and "normalize" in report
    assert "low mutation adequacy" in report.lower()
    reopened._store.close()


def test_disabled_gates_keep_legacy_calls_and_approval(tmp_path, monkeypatch):
    def unexpected(**kwargs):
        pytest.fail("disabled post-pass gate executed")

    monkeypatch.setattr(sm_mod, "run_ddmin_hunk_minimization", unexpected, raising=False)
    monkeypatch.setattr(sm_mod, "run_mutation_adequacy_probe", unexpected, raising=False)
    machine, runner = make_machine(tmp_path, auto_approve_on_fix=True)
    rec = machine.run_to_terminal(machine.start_run())
    assert rec.state is RunState.APPROVED
    assert runner.calls == 2
    assert "minimization_summary" not in rec.approval_record
    machine._store.close()


def test_postpass_infrastructure_failure_cleans_workspace(tmp_path, monkeypatch):
    paths = []

    def broken(**kwargs):
        paths.append(kwargs["patched_workspace"])
        raise HarnessSetupError("mutation wrapper failed")

    monkeypatch.setattr(sm_mod, "run_mutation_adequacy_probe", broken, raising=False)
    machine, _ = make_machine(tmp_path, enable_mutation_probe=True)
    rid = machine.start_run()
    with pytest.raises(InfrastructureFailureError):
        machine.run_to_terminal(rid)
    rec = machine._store.get_run(rid)
    assert rec.termination_reason is TerminationReason.INFRASTRUCTURE_FAILURE
    assert all(not path.exists() for path in paths)
    assert rec.approval_record is None
    machine._store.close()


def test_atomic_verified_patch_rolls_back_if_attempt_missing(tmp_path):
    with CheckpointStore(tmp_path / "atomic.db") as store:
        rid = store.create_run("case", 3)
        with pytest.raises(KeyError):
            store.record_verified_patch(
                rid, 1, proposal_json={"unified_diff": MINIMAL},
                execution_result_json={"exit_code": 0}, diff_hash="hash", ast_hash=None,
                approval_record={"diff_hash": "hash"},
            )
        assert store.get_run(rid).state is RunState.INIT
        assert store.get_run(rid).approval_record is None


@pytest.mark.parametrize("killed,survived", [(0, 0), (1, 2), (3, 0)])
def test_nonwarning_probe_preserves_benchmark_autoapproval(tmp_path, monkeypatch, killed, survived):
    total = killed + survived
    summary = MutationAdequacySummary(False, total, killed, survived,
                                      killed / total if total else 1.0)
    monkeypatch.setattr(sm_mod, "run_mutation_adequacy_probe", lambda **kwargs: summary)
    machine, _ = make_machine(tmp_path, enable_mutation_probe=True, auto_approve_on_fix=True)
    rec = machine.run_to_terminal(machine.start_run())
    assert rec.state is RunState.APPROVED
    machine._store.close()


def test_policy_rejection_prevents_postpass_execution(tmp_path, monkeypatch):
    def reject(*args, **kwargs):
        raise OverfitPolicyError("rejected by policy")

    def unexpected(**kwargs):
        pytest.fail("post-pass executed after policy rejection")

    monkeypatch.setattr(sm_mod, "verify_not_overfitted", reject)
    monkeypatch.setattr(sm_mod, "run_mutation_adequacy_probe", unexpected)
    monkeypatch.setattr(sm_mod, "run_ddmin_hunk_minimization", unexpected)
    machine, runner = make_machine(tmp_path, enable_mutation_probe=True,
                                  enable_ddmin_minimization=True, max_attempts=1)
    assert machine.run_to_terminal(machine.start_run()).state is RunState.TERMINATED_FAILED
    assert runner.calls == 1
    machine._store.close()


def test_negative_mutant_cap_rejected_before_setup(tmp_path):
    with pytest.raises(ValueError, match="max_mutants"):
        make_machine(tmp_path, max_mutants=-1)

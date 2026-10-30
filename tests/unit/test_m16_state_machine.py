"""Advisory M16 integration, durable records and disabled legacy behavior."""
from __future__ import annotations

import json

import pytest

from agentsentinel.cli.exporter import export_evidence_bundle
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import (
    CaseSpec,
    ExecutionResult,
    MinimizationSummary,
    PatchProposal,
)
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator import state_machine as module
from agentsentinel.orchestrator.checkpoint import RunState
from agentsentinel.orchestrator.state_machine import RepairStateMachine

BEFORE = "NOISE = 0\n\n\ndef normalize(s):\n    return s.lower()\n"
RAW = "--- a/m.py\n+++ b/m.py\n@@ -1,5 +1,5 @@\n-NOISE = 0\n+NOISE = 1\n \n \n def normalize(s):\n-    return s.lower()\n+    return s.strip().lower()\n"
MINIMAL = "--- a/m.py\n+++ b/m.py\n@@ -4,2 +4,2 @@\n def normalize(s):\n-    return s.lower()\n+    return s.strip().lower()\n"


class LLM:
    def generate_patch(self, case_id, prompt, model_id):
        return PatchProposal(case_id, RAW, "fake", 1, 1), ModelUsage("fake", 1, 1)


class Runner:
    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
        self.calls += 1
        baseline = patch_diff_hash == "baseline"
        return ExecutionResult(case_id, patch_diff_hash,
            ExitCode.TESTS_FAILED if baseline or self.fail else ExitCode.OK,
            "m.py:5: in normalize\nFAILED test_m.py::test_fix" if baseline else "test_m.py::test_fix PASSED",
            "", 0.1)


def machine_at(tmp_path, **options):
    root = tmp_path / "source"
    root.mkdir()
    (root / "m.py").write_text(BEFORE, encoding="utf-8", newline="\n")
    return RepairStateMachine(
        spec=CaseSpec("m16", "local", "a" * 40, "pytest -v", ("m.py",), ("test_m.py::test_fix",)),
        llm_client=LLM(), container_runner=Runner(), image_digest="sha256:test",
        source_workspace_override=root, db_path=tmp_path / "run.db", max_attempts=1, **options)


def test_disabled_defaults_make_no_extra_container_calls(tmp_path):
    machine = machine_at(tmp_path)
    run_id = machine.start_run()
    record = machine.run_to_terminal(run_id)
    assert record.state is RunState.AWAITING_HUMAN_APPROVAL
    assert machine.container_runner.calls == 2
    assert not machine.enable_causal_traceability and not machine.enable_statement_coverage
    assert "causal_trace_report" not in record.approval_record
    machine._store.close()


def test_selected_patch_coverage_persists_and_requires_human_after_restart(tmp_path, monkeypatch):
    from agentsentinel.domain.models import StatementCoverageReport
    calls = []

    def minimize(**kwargs):
        calls.append("minimize")
        return MINIMAL, kwargs["original_result"], MinimizationSummary(1, 1, 0, False)

    def coverage(**kwargs):
        calls.append("coverage")
        source = (kwargs["workspace_host_path"] / "m.py").read_text(encoding="utf-8")
        assert "NOISE = 0" in source and "strip()" in source
        assert kwargs["statement_lines"] == (("m.py", 5),)
        return StatementCoverageReport((), (("m.py", 5),), 0, False)

    monkeypatch.setattr(module, "run_ddmin_hunk_minimization", minimize)
    monkeypatch.setattr(module, "run_statement_coverage_probe", coverage, raising=False)
    machine = machine_at(tmp_path, enable_causal_traceability=True, enable_statement_coverage=True,
                         enable_ddmin_minimization=True, auto_approve_on_fix=True)
    run_id = machine.start_run()
    record = machine.run_to_terminal(run_id)
    assert record.state is RunState.AWAITING_HUMAN_APPROVAL
    assert calls == ["minimize", "coverage"]
    assert record.approval_record["causal_trace_report"]["modified_functions"][0]["hop_distance"] == 0
    assert record.approval_record["policy_config"]["enable_statement_coverage"] is True
    assert record.approval_record["statement_coverage_report"]["uncovered_statements"] == [["m.py", 5]]
    assert machine.container_runner.calls == 2
    machine._store.close()
    reopened = RepairStateMachine(spec=machine.spec, llm_client=LLM(), container_runner=Runner(),
                                  image_digest="sha256:test", db_path=tmp_path / "run.db")
    approval = record.approval_record
    reopened.approve_run(run_id, "operator", approval["diff_hash"], approval["image_digest"], approval["post_patch_result_hash"])
    bundle = reopened.export_evidence_bundle(run_id)
    assert bundle.causal_trace_report.modified_functions[0].hop_distance == 0
    assert bundle.statement_coverage_report.needs_review
    assert bundle.accepted_patch.unified_diff == MINIMAL
    output = export_evidence_bundle(tmp_path / "run.db", run_id, tmp_path / "out")
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["evidence_bundle"]["statement_coverage_report"]["uncovered_statements"] == [["m.py", 5]]
    assert "Statement Coverage" in (output / "REPORT.md").read_text(encoding="utf-8")
    reopened._store.close()


def test_connected_static_evidence_does_not_prevent_benchmark_approval(tmp_path):
    machine = machine_at(tmp_path, enable_causal_traceability=True, auto_approve_on_fix=True)
    run_id = machine.start_run()
    record = machine.run_to_terminal(run_id)
    assert record.state is RunState.APPROVED
    assert machine.container_runner.calls == 2
    assert record.approval_record["causal_trace_report"]["modified_functions"][0]["hop_distance"] == 0
    machine._store.close()


def test_failed_patch_never_calls_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "run_statement_coverage_probe", lambda **kw: pytest.fail("no post-pass coverage"), raising=False)
    machine = machine_at(tmp_path, enable_statement_coverage=True)
    machine.container_runner.fail = True
    run_id = machine.start_run()
    assert machine.run_to_terminal(run_id).state is RunState.TERMINATED_FAILED
    assert machine.container_runner.calls == 2
    machine._store.close()


def test_deep_static_analysis_failure_is_classified_as_infrastructure(tmp_path, monkeypatch):
    from agentsentinel.domain.exceptions import InfrastructureFailureError
    from agentsentinel.orchestrator.checkpoint import TerminationReason

    def too_deep(*args, **kwargs):
        raise RecursionError("AST nesting exceeded")

    monkeypatch.setattr(module, "analyze_causal_trace", too_deep)
    machine = machine_at(tmp_path, enable_causal_traceability=True)
    run_id = machine.start_run()
    with pytest.raises(InfrastructureFailureError):
        machine.run_to_terminal(run_id)
    record = machine._store.get_run(run_id)
    assert record.termination_reason is TerminationReason.INFRASTRUCTURE_FAILURE
    assert machine._pending_patched_ws is None
    machine._store.close()


def test_policy_rejected_patch_never_calls_trace_probe(tmp_path, monkeypatch):
    from agentsentinel.domain.exceptions import OverfitPolicyError

    def reject(*args, **kwargs):
        raise OverfitPolicyError("Rejected by static policy")

    monkeypatch.setattr(module, "verify_not_overfitted", reject)
    monkeypatch.setattr(module, "run_statement_coverage_probe", lambda **kw: pytest.fail("policy rejection must skip probe"))
    machine = machine_at(tmp_path, enable_statement_coverage=True)
    run_id = machine.start_run()
    assert machine.run_to_terminal(run_id).state is RunState.TERMINATED_FAILED
    assert machine.container_runner.calls == 1
    machine._store.close()

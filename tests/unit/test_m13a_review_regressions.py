"""Probe evidence must recognize complete pytest IDs, including parameter spaces."""

from __future__ import annotations

from dataclasses import replace

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.verification.post_pass_gate import run_mutation_adequacy_probe
from tests.unit.test_m13a_mutation_adequacy import POST, PRE, Runner, diff


def test_probe_accepts_selected_evidence_with_spaced_parameter(tmp_path, monkeypatch):
    baseline, patched = tmp_path / "before", tmp_path / "after"
    baseline.mkdir()
    patched.mkdir()
    (baseline / "a.py").write_text(PRE, encoding="utf-8", newline="\n")
    (patched / "a.py").write_text(POST, encoding="utf-8", newline="\n")
    node = "test_a.py::test_fix[hello world]"
    case = CaseSpec("case", "local", "a" * 40, "pytest", ("a.py",), (node,))
    execution = ExecutionResult("case", "hash", ExitCode.OK, f"{node} PASSED [100%]\n", "", 0.2)
    calls = []

    def batch(**kwargs):
        calls.append(kwargs)
        return (True,)

    monkeypatch.setattr(
        "agentsentinel.verification.mutation_batch.run_in_container_mutation_batch", batch,
    )
    runner = Runner()
    summary = run_mutation_adequacy_probe(
        minimized_diff=diff("a.py"), baseline_workspace=baseline, patched_workspace=patched,
        spec=case, runner=runner, post_patch_result=replace(execution, expected_test_ids=(node,)),
    )
    assert summary.mutants_killed == summary.total_mutants_evaluated > 0
    assert all(call["failing_test_ids"] == (node,) for call in calls)
    assert runner.calls == []

"""Opt-in search and batch protocols preserve legacy sandbox boundaries."""

from __future__ import annotations

import json
import subprocess
from difflib import unified_diff
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentsentinel.domain.exceptions import HarnessSetupError, HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.verification import mutation_batch
from agentsentinel.verification.differential_mutation import DifferentialPatchMutant
from agentsentinel.verification.post_pass_gate import (
    run_ddmin_hunk_minimization,
    run_mutation_adequacy_probe,
)

NODE = "test_mod.py::test_fix"
MARKER = "AGENTSENTINEL_MUTATION_V2:"
MUTANTS = (
    DifferentialPatchMutant("mod.py", "calculate", "add-to-sub", "FIRST = True\n"),
    DifferentialPatchMutant("mod.py", "calculate", "invert", "SECOND = True\n"),
)


def execution(stdout="", **changes):
    values = {"case_id": "case", "patch_diff_hash": "hash", "exit_code": ExitCode.OK,
              "stdout": stdout, "stderr": "", "wall_seconds": 0.2}
    values.update(changes)
    return ExecutionResult(**values)


@pytest.mark.parametrize("iterative,wanted_count,wanted_calls", [(False, 4, 6), (True, 2, 17)])
def test_iterative_search_restarts_from_pristine_baseline_until_no_deletion_passes(
    tmp_path, iterative, wanted_count, wanted_calls,
):
    before = "def calculate(value):\n    return value\n\n" + "".join(
        f"# old {index}\n# context {index} a\n# context {index} b\n# context {index} c\n# context {index} d\n"
        for index in range(5)
    )
    after = before.replace("# old", "# new")
    raw = "".join(unified_diff(before.splitlines(True), after.splitlines(True),
                               fromfile="a/mod.py", tofile="b/mod.py", n=1))
    (tmp_path / "mod.py").write_text(before, encoding="utf-8", newline="\n")
    workspaces = []

    class Oracle:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            workspaces.append(workspace_host_path)
            source = (workspace_host_path / "mod.py").read_text(encoding="utf-8")
            passing = "# new 3" in source and "# new 4" in source
            return execution(f"{NODE} PASSED\n", exit_code=ExitCode.OK if passing else ExitCode.TESTS_FAILED)

    selected, result, summary = run_ddmin_hunk_minimization(
        raw_diff=raw, baseline_workspace=tmp_path,
        spec=CaseSpec("case", "local", "a" * 40, "pytest", ("mod.py",), (NODE,)),
        runner=Oracle(), original_result=execution(f"{NODE} PASSED\n"), iterative=iterative,
    )
    assert summary.raw_hunks_count == 5
    assert summary.minimized_hunks_count == wanted_count
    assert summary.codeslop_hunks_removed == 5 - wanted_count
    assert result.passed and "# new 3" in selected and "# new 4" in selected
    assert len(workspaces) == len(set(workspaces)) == wanted_calls
    assert all(not path.exists() for path in workspaces)
    assert (tmp_path / "mod.py").read_text(encoding="utf-8") == before


def run_detailed(runner):
    return mutation_batch.run_in_container_mutation_batch_detailed(
        runner=runner, case_id="case", patch_diff_hash="hash",
        workspace_host_path=Path("workspace"), mutants=MUTANTS,
        failing_test_ids=(NODE,), baseline_wall_seconds=0.2,
    )


def report_for(command, *, alter=None):
    payload = json.loads(command[-1])
    outcomes = [
        {"mutant_id": payload["mutants"][0]["id"], "status": "KILLED_BY_TIMEOUT",
         "exit_code": None, "runtime_sec": 1.0},
        {"mutant_id": payload["mutants"][1]["id"], "status": "SURVIVED",
         "exit_code": 0, "runtime_sec": 0.12},
    ]
    if alter:
        alter(outcomes)
    return MARKER + json.dumps({"status": "ok", "outcomes": outcomes}, separators=(",", ":")) + "\n"


def test_detailed_batch_uses_one_container_and_preserves_order_and_status():
    commands = []

    class Runner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            commands.append(command)
            return execution(report_for(command))

    outcomes = run_detailed(Runner())
    assert len(commands) == 1
    assert [outcome.status for outcome in outcomes] == ["KILLED_BY_TIMEOUT", "SURVIVED"]
    assert [outcome.killed for outcome in outcomes] == [True, False]
    assert outcomes[0].exit_code is None and outcomes[0].runtime_sec == 1.0
    assert outcomes[1].exit_code == 0 and outcomes[1].runtime_sec == 0.12
    payload = json.loads(commands[0][-1])
    assert [entry["mutated_source"] for entry in payload["mutants"]] == ["FIRST = True\n", "SECOND = True\n"]
    assert outcomes[0].mutant_id != outcomes[1].mutant_id


@pytest.mark.parametrize("alter", [
    lambda rows: rows.pop(),
    lambda rows: rows.reverse(),
    lambda rows: rows[0].update(mutant_id="unknown"),
    lambda rows: rows[1].update(status="KILLED"),
    lambda rows: rows[1].update(runtime_sec=-1),
    lambda rows: rows[1].update(runtime_sec=True),
    lambda rows: rows[1].update(extra="untrusted"),
    lambda rows: rows[1].update(exit_code=True),
    lambda rows: rows[0].update(runtime_sec=0.2),
])
def test_partial_reordered_or_malformed_batch_reports_are_infrastructure_failures(alter):
    class Runner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            return execution(report_for(command, alter=alter))

    with pytest.raises(HarnessSetupError):
        run_detailed(Runner())


def test_outer_batch_timeout_does_not_invent_individual_mutant_kills():
    runner = Mock()
    runner.run_in_container.side_effect = HarnessTimeoutError(5, "container")
    with pytest.raises(HarnessTimeoutError):
        run_detailed(runner)


@pytest.mark.parametrize("change", [
    {"stdout_truncated": True}, {"stderr_truncated": True}, {"case_id": "wrong"},
    {"patch_diff_hash": "wrong"}, {"exit_code": ExitCode.INTERNAL_ERROR},
])
def test_batch_rejects_incomplete_or_unbound_execution_metadata(change):
    class Runner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            return execution(report_for(command), **change)

    with pytest.raises(HarnessSetupError):
        run_detailed(Runner())


@pytest.mark.parametrize("corrupt", [
    lambda raw: raw.replace('"status":"ok"', '"status":"ok","status":"ok"', 1),
    lambda raw: raw + MARKER + "{}",
    lambda raw: MARKER + '{"status":"setup_error"}',
    lambda raw: raw.replace('"runtime_sec":1.0', '"runtime_sec":NaN', 1),
])
def test_batch_rejects_duplicate_keys_spoofed_reports_setup_errors_and_nan(corrupt):
    class Runner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            return execution(corrupt(report_for(command)))

    with pytest.raises(HarnessSetupError):
        run_detailed(Runner())


@pytest.mark.parametrize("timeout", [False, True])
def test_probe_opt_in_batches_selected_mutants_and_propagates_outer_timeout(tmp_path, timeout):
    before = "def calculate(value):\n    return value - 1\n"
    after = "def calculate(value):\n    return value + 1 if value < 10 else True\n"
    baseline, patched = tmp_path / "baseline", tmp_path / "patched"
    baseline.mkdir()
    patched.mkdir()
    (baseline / "mod.py").write_text(before, encoding="utf-8", newline="\n")
    (patched / "mod.py").write_text(after, encoding="utf-8", newline="\n")
    raw = "".join(unified_diff(before.splitlines(True), after.splitlines(True),
                               fromfile="a/mod.py", tofile="b/mod.py"))
    calls = []

    class Runner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            calls.append(command)
            if timeout:
                raise HarnessTimeoutError(5, "container")
            payload = json.loads(command[-1])
            outcomes = [{"mutant_id": entry["id"], "status": "SURVIVED",
                         "exit_code": 0, "runtime_sec": 0.1} for entry in payload["mutants"]]
            return execution(MARKER + json.dumps({"status": "ok", "outcomes": outcomes},
                                                  separators=(",", ":")), patch_diff_hash=patch_diff_hash)

    def probe():
        return run_mutation_adequacy_probe(
            minimized_diff=raw, baseline_workspace=baseline, patched_workspace=patched,
            spec=CaseSpec("case", "local", "a" * 40, "pytest", ("mod.py",), (NODE,)),
            runner=Runner(), post_patch_result=execution(f"{NODE} PASSED\n"),
            single_container_batch=True,
        )

    if timeout:
        with pytest.raises(HarnessTimeoutError):
            probe()
    else:
        summary = probe()
        assert summary.total_mutants_evaluated == summary.mutants_survived == 3
        assert summary.mutants_killed == 0 and summary.low_mutation_adequacy
        assert len(summary.survived_mutant_details) == 3
    assert len(calls) == 1
    assert len(json.loads(calls[0][-1])["mutants"]) == 3


def test_state_machine_opt_in_flags_reach_post_pass_gates(tmp_path, monkeypatch):
    from agentsentinel.domain.models import (
        MinimizationSummary,
        MutationAdequacySummary,
        PatchProposal,
    )
    from agentsentinel.orchestrator import state_machine
    from tests.unit.test_m13a_state_machine import RAW, make_machine

    observed = []

    def minimize(**kwargs):
        observed.append(kwargs["iterative"])
        return kwargs["raw_diff"], kwargs["original_result"], MinimizationSummary(2, 2, 0, False)

    def probe(**kwargs):
        observed.append(kwargs["single_container_batch"])
        return MutationAdequacySummary(False, 0, 0, 0, 1.0)

    monkeypatch.setattr(state_machine, "run_ddmin_hunk_minimization", minimize)
    monkeypatch.setattr(state_machine, "run_mutation_adequacy_probe", probe)
    machine, _ = make_machine(tmp_path, enable_ddmin_minimization=True,
                              enable_mutation_probe=True, enable_iterative_ddmin=True,
                              enable_single_container_mutation_batch=True)
    try:
        machine._run_post_pass_checks(PatchProposal("case", RAW, "test", 0, 0),
                                      execution(), machine._get_source_workspace())
        assert observed == [True, True]
    finally:
        machine._store.close()


def test_state_machine_batch_outer_timeout_terminates_as_infrastructure_without_approval(
    tmp_path, monkeypatch,
):
    from agentsentinel.domain.exceptions import InfrastructureFailureError
    from agentsentinel.orchestrator.checkpoint import RunState, TerminationReason
    from tests.unit.test_m13a_state_machine import make_machine

    machine, runner = make_machine(tmp_path, enable_mutation_probe=True,
                                   enable_single_container_mutation_batch=True)
    original = runner.run_in_container
    workspaces = []

    def run(case_id, patch_diff_hash, workspace_host_path, command):
        if command[:2] == ["python", "-I"]:
            workspaces.append(workspace_host_path)
            raise HarnessTimeoutError(5, "container")
        return original(case_id, patch_diff_hash, workspace_host_path, command)

    monkeypatch.setattr(runner, "run_in_container", run)
    rid = machine.start_run()
    try:
        with pytest.raises(InfrastructureFailureError):
            machine.run_to_terminal(rid)
        record = machine._store.get_run(rid)
        assert record.state is RunState.TERMINATED_FAILED
        assert record.termination_reason is TerminationReason.INFRASTRUCTURE_FAILURE
        assert record.approval_record is None
        assert len(workspaces) == 1 and all(not path.exists() for path in workspaces)
    finally:
        machine._store.close()


@pytest.fixture
def wrapper(tmp_path, monkeypatch):
    # Execute trusted stdlib wrapper only; repository/tests never execute here.
    ns = {"__name__": "wrapper_test"}
    exec(compile(mutation_batch.build_mutation_batch_script(), "<wrapper>", "exec"), ns)
    source, shadow = tmp_path / "source", tmp_path / "shadow"
    source.mkdir()
    (source / "mod.py").write_text("ORIGINAL = True\n", encoding="utf-8", newline="\n")
    ns.update(SOURCE=source, SHADOW=shadow, become_subreaper=lambda: None)
    monkeypatch.setattr(ns["os"], "killpg", lambda *args: None, raising=False)
    monkeypatch.setattr(ns["os"], "waitpid", Mock(side_effect=ChildProcessError), raising=False)
    monkeypatch.setattr(ns["signal"], "SIGKILL", 9, raising=False)
    return SimpleNamespace(ns=ns, source=source, shadow=shadow)


def test_v2_wrapper_records_timeout_then_fresh_survivor_and_cleans(wrapper, monkeypatch, capsys):
    seen = []

    def spawn(command, **kwargs):
        assert not (wrapper.shadow / "child_residue").exists()
        seen.append((wrapper.shadow / "mod.py").read_text(encoding="utf-8"))
        (wrapper.shadow / "child_residue").write_text("residue", encoding="utf-8")
        waits = [subprocess.TimeoutExpired("pytest", 1), -9] if len(seen) == 1 else [0, 0]
        return SimpleNamespace(pid=123, wait=Mock(side_effect=waits))

    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", spawn)
    payload = {"protocol_version": 2, "timeout_seconds": 1.0, "failing_test_ids": [NODE],
               "mutants": [{"id": str(index), "file_path": mutant.file_path,
                            "mutated_source": mutant.mutated_source}
                           for index, mutant in enumerate(MUTANTS)]}
    assert wrapper.ns["main"](json.dumps(payload)) == 0
    report = json.loads(capsys.readouterr().out.removeprefix(MARKER))
    assert [row["status"] for row in report["outcomes"]] == ["KILLED_BY_TIMEOUT", "SURVIVED"]
    assert [row["mutant_id"] for row in report["outcomes"]] == ["0", "1"]
    assert report["outcomes"][0]["runtime_sec"] == 1.0
    assert report["outcomes"][0]["exit_code"] is None
    assert report["outcomes"][1]["exit_code"] == 0
    assert seen == ["FIRST = True\n", "SECOND = True\n"]
    assert not wrapper.shadow.exists()
    assert (wrapper.source / "mod.py").read_text(encoding="utf-8") == "ORIGINAL = True\n"


@pytest.mark.parametrize("exit_code", [1, 2, 3, 4, 5])
def test_v2_wrapper_distinguishes_test_failure_from_harness_failure(
    wrapper, monkeypatch, capsys, exit_code,
):
    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen",
                        lambda *args, **kwargs: SimpleNamespace(pid=123, wait=lambda **kwargs: exit_code))
    payload = {"protocol_version": 2, "timeout_seconds": 1.0, "failing_test_ids": [NODE],
               "mutants": [{"id": "mutant", "file_path": "mod.py", "mutated_source": "MUTATED = True\n"}]}
    code = wrapper.ns["main"](json.dumps(payload))
    report = json.loads(capsys.readouterr().out.removeprefix(MARKER))
    if exit_code == 1:
        assert code == 0 and report["status"] == "ok"
        assert report["outcomes"][0]["status"] == "KILLED"
        assert report["outcomes"][0]["exit_code"] == 1
        assert report["outcomes"][0]["runtime_sec"] >= 0
    else:
        assert code == 3 and report == {"status": "setup_error"}
    assert not wrapper.shadow.exists()

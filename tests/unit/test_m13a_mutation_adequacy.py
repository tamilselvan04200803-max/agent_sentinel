"""Probe selected source artifacts without executing project source on the host."""

import sys
import types
from dataclasses import replace
from difflib import unified_diff

import pytest

from agentsentinel.domain.exceptions import HarnessSetupError, HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.verification.post_pass_gate import run_mutation_adequacy_probe

TEST_ID = "tests/test_calc.py::test_fix"
PRE = "def calculate(value):\n    return value - 1\n"
POST = "def calculate(value):\n    return value + 1 if value < 10 else True\n"


def diff(path, before=PRE, after=POST):
    return "".join(unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"a/{path}", tofile=f"b/{path}"))


def passing():
    return ExecutionResult("case", "hash", ExitCode.OK, f"{TEST_ID} PASSED\n", "", 0.75)


class Runner:
    def __init__(self, execution=None):
        self.calls = []
        self.execution = passing() if execution is None else execution

    def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
        self.calls.append((case_id, patch_diff_hash, workspace_host_path, command))
        if isinstance(self.execution, Exception):
            raise self.execution
        return self.execution


@pytest.fixture
def trees(tmp_path):
    baseline = tmp_path / "baseline"
    patched = tmp_path / "patched"
    baseline.mkdir()
    patched.mkdir()
    for path in ("z.py", "a.py", "untouched.py"):
        (baseline / path).write_text(PRE, encoding="utf-8")
        (patched / path).write_text(POST, encoding="utf-8")
    return baseline, patched


@pytest.fixture
def batch(monkeypatch):
    calls = []
    outcomes = []

    def run(**kwargs):
        calls.append(kwargs)
        outcome = outcomes.pop(0) if outcomes else False
        if isinstance(outcome, Exception):
            raise outcome
        return (outcome,)

    module = types.ModuleType("agentsentinel.verification.mutation_batch")
    module.run_in_container_mutation_batch = run
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return calls, outcomes


def probe(trees, runner, *, raw=None, maximum=3, execution=None):
    baseline, patched = trees
    case = CaseSpec("case", "https://example.test/repo", "a" * 40, "pytest", ("a.py", "z.py", "untouched.py"), (TEST_ID,))
    return run_mutation_adequacy_probe(minimized_diff=diff("z.py") + diff("a.py") if raw is None else raw, baseline_workspace=baseline, patched_workspace=patched, spec=case, runner=runner, max_mutants=maximum, post_patch_result=execution)


def test_one_total_cap_in_sorted_changed_paths_with_measured_baseline(trees, batch):
    calls, _ = batch
    runner = Runner()
    summary = probe(trees, runner, maximum=3)
    assert summary.total_mutants_evaluated == 3
    assert len(calls) == 3
    assert [call["mutants"][0].file_path for call in calls] == ["a.py"] * 3
    assert all(len(call["mutants"]) == 1 for call in calls)
    assert all(call["baseline_wall_seconds"] == 0.75 for call in calls)
    assert all(call["workspace_host_path"] == trees[1] for call in calls)
    assert all(call["failing_test_ids"] == (TEST_ID,) for call in calls)
    expected_hash = PatchProposal("case", diff("z.py") + diff("a.py"), "gate", 0, 0).diff_hash
    assert all(call["patch_diff_hash"] == expected_hash for call in calls)
    assert len(runner.calls) == 1
    assert runner.calls[0][3] == ["python", "-m", "pytest", "-v", "-ra", TEST_ID]


def test_configured_cap_above_default_honored_across_patch(trees, batch):
    calls, _ = batch
    summary = probe(trees, Runner(), maximum=5, execution=passing())
    assert summary.total_mutants_evaluated == 5
    assert len(calls) == 5
    assert [call["mutants"][0].file_path for call in calls] == ["a.py"] * 3 + ["z.py"] * 2


def test_cap_spans_multiple_files_and_excludes_allowlisted_untouched_file(trees, batch):
    calls, _ = batch
    for path in ("a.py", "z.py"):
        (trees[1] / path).write_text(PRE.replace("value - 1", "value + 1"), encoding="utf-8")
    summary = probe(trees, Runner(), maximum=3, execution=passing())
    assert summary.total_mutants_evaluated == 2
    assert [call["mutants"][0].file_path for call in calls] == ["a.py", "z.py"]


@pytest.mark.parametrize("raw,maximum", [("", 3), (diff("a.py"), 0), (diff("notes.txt"), 3)])
def test_no_generated_mutants_score_one_without_any_execution(trees, batch, raw, maximum):
    calls, _ = batch
    runner = Runner()
    summary = probe(trees, runner, raw=raw, maximum=maximum)
    assert summary.mutation_score == 1.0
    assert summary.total_mutants_evaluated == 0
    assert not summary.low_mutation_adequacy
    assert summary.survived_mutant_details == ()
    assert calls == []
    assert runner.calls == []


def test_negative_cap_rejected_before_sandbox(trees, batch):
    calls, _ = batch
    runner = Runner()
    with pytest.raises(ValueError, match="non-negative"):
        probe(trees, runner, maximum=-1)
    assert calls == []
    assert runner.calls == []


@pytest.mark.parametrize("outcomes,killed,survived,warning", [([False, False, False], 0, 3, True), ([True, False, False], 1, 2, False), ([True, True, True], 3, 0, False), ([HarnessTimeoutError(1, "pytest"), False, False], 1, 2, False)])
def test_kills_survivor_details_and_all_survive_warning(trees, batch, outcomes, killed, survived, warning):
    calls, configured = batch
    configured.extend(outcomes)
    runner = Runner()
    summary = probe(trees, runner, execution=passing())
    assert summary.mutants_killed == killed
    assert summary.mutants_survived == survived
    assert summary.mutation_score == killed / 3
    assert summary.low_mutation_adequacy is warning
    assert len(summary.survived_mutant_details) == survived
    assert all(detail.file_path == "a.py" and detail.function_name == "calculate" for detail in summary.survived_mutant_details)
    assert len({detail.mutant_id for detail in summary.survived_mutant_details}) == survived
    assert all(len(detail.mutant_id) == 64 for detail in summary.survived_mutant_details)
    assert len(calls) == 3
    assert runner.calls == []


def test_survivor_ids_stable_for_repeated_source_metadata(trees, batch):
    one = probe(trees, Runner(), execution=passing())
    two = probe(trees, Runner(), execution=passing())
    assert one.survived_mutant_details == two.survived_mutant_details


@pytest.mark.parametrize("execution", [replace(passing(), exit_code=ExitCode.TESTS_FAILED), replace(passing(), stdout="no tests"), replace(passing(), stdout=f"prefix{TEST_ID} PASSED\n")])
def test_invalid_passing_evidence_does_not_probe(trees, batch, execution):
    calls, _ = batch
    with pytest.raises(ValueError, match="passing"):
        probe(trees, Runner(), execution=execution)
    assert calls == []


def test_baseline_nonpass_is_not_reported_as_mutant_kill(trees, batch):
    calls, _ = batch
    with pytest.raises(ValueError, match="passing"):
        probe(trees, Runner(replace(passing(), stdout="no tests")))
    assert calls == []


def test_helper_infrastructure_error_propagates_without_fabricated_summary(trees, batch):
    calls, configured = batch
    configured.append(HarnessSetupError("wrapper failure"))
    with pytest.raises(HarnessSetupError):
        probe(trees, Runner(), execution=passing())
    assert len(calls) == 1


def test_only_selected_function_changes_generate_mutants(trees, batch):
    calls, _ = batch
    stable = "\ndef discarded(value):\n    return value + 99\n"
    (trees[0] / "a.py").write_text(PRE + stable, encoding="utf-8")
    (trees[1] / "a.py").write_text(POST + stable, encoding="utf-8")
    probe(trees, Runner(), raw=diff("a.py"), execution=passing())
    assert all(call["mutants"][0].function_name == "calculate" for call in calls)
    assert all("return value + 99" in call["mutants"][0].mutated_source for call in calls)


def test_new_and_deleted_python_files_use_empty_missing_source(trees, batch):
    calls, _ = batch
    (trees[0] / "a.py").unlink()
    new = "--- /dev/null\n+++ b/a.py\n@@ -0,0 +1,2 @@\n+def calculate(value):\n+    return value + 1\n"
    (trees[1] / "a.py").write_text("def calculate(value):\n    return value + 1\n", encoding="utf-8")
    summary = probe(trees, Runner(), raw=new, execution=passing())
    assert summary.total_mutants_evaluated == 1
    calls.clear()
    (trees[1] / "z.py").unlink()
    deleted = "--- a/z.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-def calculate(value):\n-    return value - 1\n"
    summary = probe(trees, Runner(), raw=deleted, execution=passing())
    assert summary.total_mutants_evaluated == 0
    assert calls == []


def test_missing_modified_source_is_infrastructure_failure(trees, batch):
    (trees[1] / "a.py").unlink()
    with pytest.raises(HarnessSetupError):
        probe(trees, Runner(), raw=diff("a.py"), execution=passing())


def test_changed_path_cannot_escape_workspace(trees, batch):
    calls, _ = batch
    with pytest.raises(Exception, match="[Tt]raversal|[Aa]llowlist|escape"):
        probe(trees, Runner(), raw=diff("../outside.py"), execution=passing())
    assert calls == []


def test_changed_python_without_eligible_sites_never_runs_baseline(trees, batch):
    calls, _ = batch
    (trees[0] / "a.py").write_text("label = 'before'\n", encoding="utf-8")
    (trees[1] / "a.py").write_text("label = 'after'\n", encoding="utf-8")
    runner = Runner()
    summary = probe(trees, runner, raw=diff("a.py", "label = 'before'\n", "label = 'after'\n"))
    assert summary.total_mutants_evaluated == 0
    assert summary.mutation_score == 1.0
    assert not summary.low_mutation_adequacy
    assert runner.calls == []
    assert calls == []


def test_repository_module_initializers_are_never_executed_on_host(trees, batch):
    calls, _ = batch
    initializer = "raise RuntimeError('must never execute on host')\n\n"
    (trees[0] / "a.py").write_text(initializer + PRE, encoding="utf-8")
    (trees[1] / "a.py").write_text(initializer + POST, encoding="utf-8")
    summary = probe(trees, Runner(), raw=diff("a.py", initializer + PRE, initializer + POST), execution=passing())
    assert summary.total_mutants_evaluated == 3
    assert len(calls) == 3

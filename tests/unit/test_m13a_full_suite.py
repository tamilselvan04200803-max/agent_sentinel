"""Subset adoption requires both targeted and declared full-suite evidence."""

from __future__ import annotations

from dataclasses import replace
from difflib import unified_diff
from unittest import TestCase
from unittest.mock import patch

from agentsentinel.domain.exceptions import HarnessSetupError, HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import (
    CaseSpec,
    ExecutionResult,
    MinimizationSummary,
    PatchProposal,
)
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.state_machine import RepairStateMachine
from agentsentinel.verification.post_pass_gate import run_ddmin_hunk_minimization

TEST_ID = "test_calc.py::test_fix"
TARGET = ["python", "-m", "pytest", "-v", "-ra", TEST_ID]
FULL = "python -m pytest -v -ra"
PRE = "def calculate(value):\n    return value - 1\n\n\n# context\n# context\n# context\n# original comment\n"
POST = PRE.replace("value - 1", "value + 1").replace("original comment", "changed comment")
RAW = "".join(unified_diff(PRE.splitlines(True), POST.splitlines(True), "a/calc.py", "b/calc.py", n=1))


def case():
    return CaseSpec("case", "local", "a" * 40, "python -m pytest", ("calc.py",), (TEST_ID,))


def result(case_id="case", patch_hash="original", stdout=f"{TEST_ID} PASSED\n", code=ExitCode.OK):
    return ExecutionResult(case_id, patch_hash, code, stdout, "", 0.1)


class Runner:
    def __init__(self, full_kind="passed"):
        self.full_kind = full_kind
        self.calls = []

    def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
        source = (workspace_host_path / "calc.py").read_text(encoding="utf-8")
        self.calls.append((workspace_host_path, source, command))
        if command == TARGET:
            return result(case_id, patch_diff_hash, code=ExitCode.OK if "value + 1" in source else ExitCode.TESTS_FAILED)
        if self.full_kind == "timeout":
            raise HarnessTimeoutError(1.0, "full suite")
        if self.full_kind == "setup":
            return result(case_id, patch_diff_hash, code=ExitCode.USAGE_ERROR)
        execution = result(case_id, patch_diff_hash, stdout=f"{TEST_ID} PASSED\nFULL_SUITE PASSED\n")
        if self.full_kind == "failed":
            return replace(execution, exit_code=ExitCode.TESTS_FAILED)
        if self.full_kind == "missing":
            return replace(execution, stdout="FULL_SUITE PASSED\n")
        if self.full_kind == "truncated":
            return replace(execution, stdout_truncated=True)
        if self.full_kind == "wrong_case":
            return replace(execution, case_id="different")
        if self.full_kind == "wrong_hash":
            return replace(execution, patch_diff_hash="different")
        return execution


def minimize(tmp_path, runner, **options):
    (tmp_path / "calc.py").write_text(PRE, encoding="utf-8", newline="\n")
    return run_ddmin_hunk_minimization(raw_diff=RAW, baseline_workspace=tmp_path, spec=case(), runner=runner, original_result=result(), **options)


def test_targeted_pass_does_not_adopt_full_suite_regression(tmp_path):
    runner = Runner("failed")
    selected, execution, summary = minimize(tmp_path, runner, full_suite_command=FULL)
    assert selected == RAW and execution.patch_diff_hash == "original"
    assert not summary.was_minimized
    assert [call[2] for call in runner.calls] == [TARGET, FULL, TARGET]
    assert all(not call[0].exists() for call in runner.calls)
    assert (tmp_path / "calc.py").read_text(encoding="utf-8") == PRE


def test_success_adopts_full_suite_result_and_command_list(tmp_path):
    runner = Runner()
    command = ["python", "-m", "pytest", "-v", "-ra"]
    selected, execution, summary = minimize(tmp_path, runner, full_suite_command=command)
    assert summary.was_minimized and summary.minimized_hunks_count == 1
    assert "FULL_SUITE" in execution.stdout
    assert execution.patch_diff_hash == PatchProposal("case", selected, "test", 0, 0).diff_hash
    assert execution.expected_test_ids == (TEST_ID,)
    assert runner.calls[0][0] == runner.calls[1][0]
    assert runner.calls[1][2] == command


def test_bad_full_suite_evidence_or_timeout_falls_back(tmp_path):
    for kind in ("missing", "truncated", "timeout"):
        root = tmp_path / kind
        root.mkdir()
        selected, _, summary = minimize(root, Runner(kind), full_suite_command=FULL)
        assert selected == RAW and not summary.was_minimized, kind


def test_full_suite_identity_mismatch_is_infrastructure_failure(tmp_path):
    for kind in ("wrong_case", "wrong_hash"):
        root = tmp_path / kind
        root.mkdir()
        with TestCase().assertRaises(HarnessSetupError):
            minimize(root, Runner(kind), full_suite_command=FULL)


def test_full_suite_harness_errors_propagate(tmp_path):
    with TestCase().assertRaises(HarnessSetupError):
        minimize(tmp_path, Runner("setup"), full_suite_command=FULL)


def test_iterative_search_preserves_full_suite_validation(tmp_path):
    runner = Runner()
    _, execution, summary = minimize(tmp_path, runner, full_suite_command=FULL, iterative=True)
    assert summary.minimized_hunks_count == 1
    assert "FULL_SUITE" in execution.stdout
    assert [call[2] for call in runner.calls] == [TARGET, FULL]


def test_legacy_standalone_default_retains_targeted_call_count(tmp_path):
    runner = Runner()
    _, _, summary = minimize(tmp_path, runner)
    assert summary.was_minimized and len(runner.calls) == 1


def test_state_machine_supplies_declared_full_suite_command(tmp_path):
    (tmp_path / "calc.py").write_text(PRE, encoding="utf-8", newline="\n")
    captured = []

    class LLM:
        def generate_patch(self, case_id, prompt, model_id):
            return PatchProposal(case_id, RAW, "test", 1, 1), ModelUsage("test", 1, 1)

    class StateRunner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            return result(case_id, patch_diff_hash, code=ExitCode.TESTS_FAILED if patch_diff_hash == "baseline" else ExitCode.OK)

    def select(**kwargs):
        captured.append(kwargs.get("full_suite_command"))
        return kwargs["raw_diff"], kwargs["original_result"], MinimizationSummary(2, 2, 0, False)

    machine = RepairStateMachine(case(), LLM(), StateRunner(), db_path=tmp_path / "run.db", source_workspace_override=tmp_path, enable_ddmin_minimization=True)
    try:
        with patch("agentsentinel.orchestrator.state_machine.run_ddmin_hunk_minimization", select):
            machine.run_to_terminal(machine.start_run())
        assert captured == [FULL]
    finally:
        machine._store.close()

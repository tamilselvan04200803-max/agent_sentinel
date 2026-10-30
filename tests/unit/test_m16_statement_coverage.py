"""Unit checks inspect the wrapper or fake the container boundary; never run it."""
from __future__ import annotations

import ast
import json
from dataclasses import replace

import pytest

from agentsentinel.domain.exceptions import HarnessSetupError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import ExecutionResult

MARKER = "AGENTSENTINEL_COVERAGE_V1:"


class Runner:
    def __init__(self, record=None):
        self.calls = []
        self.record = record or {"status": "ok", "hits": [["m.py", 2]], "test_exit_code": 0, "timed_out": False, "passed_ids": ["test_m.py::test_fix"]}
        self.modify = lambda value: value

    def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
        self.calls.append(command)
        return self.modify(ExecutionResult(case_id, patch_diff_hash, ExitCode.OK, MARKER + json.dumps(self.record, separators=(",", ":")) + "\n", "", 0.1))


def probe(tmp_path, runner, **options):
    from agentsentinel.verification.statement_coverage import run_statement_coverage_probe
    args = {"runner": runner, "case_id": "case", "patch_diff_hash": "hash", "workspace_host_path": tmp_path, "failing_test_ids": ("test_m.py::test_fix",), "statement_lines": (("m.py", 2), ("m.py", 4)), "timeout_seconds": 2.0}
    args.update(options)
    return run_statement_coverage_probe(**args)


def test_reports_observed_and_uncovered_lines_without_host_execution(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("host execution forbidden"))
    runner = Runner()
    report = probe(tmp_path, runner)
    assert report.covered_statements == (("m.py", 2),)
    assert report.uncovered_statements == (("m.py", 4),)
    assert report.needs_review
    assert runner.calls[0][:4] == ["python", "-I", "-B", "-c"]
    ast.parse(runner.calls[0][4])


def test_wrapper_contains_cleanup_and_child_only_trace():
    from agentsentinel.verification.statement_coverage import build_statement_coverage_script
    script = build_statement_coverage_script()
    tree = ast.parse(script)
    names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert {"copy_shadow", "stop_group", "stop_detached_descendants", "main"} <= names
    assert "sys.settrace" in script
    assert "start_new_session=True" in script
    assert "stop_group(process, True)" in script
    assert "stdout=subprocess.DEVNULL" in script


@pytest.mark.parametrize("change", [
    {"timeout_seconds": float("nan")}, {"timeout_seconds": 0},
    {"statement_lines": (("../outside.py", 2),)},
    {"statement_lines": (("m.py", 0),)}, {"failing_test_ids": ()},
    {"failing_test_ids": ("-k",)},
])
def test_bad_inputs_never_enter_container(tmp_path, change):
    runner = Runner()
    with pytest.raises(ValueError):
        probe(tmp_path, runner, **change)
    assert not runner.calls


def test_zero_statements_short_circuits(tmp_path):
    runner = Runner()
    report = probe(tmp_path, runner, statement_lines=())
    assert not report.needs_review and not runner.calls


@pytest.mark.parametrize("record", [
    {"status": "setup_error"},
    {"status": "ok", "hits": [["outside.py", 1]], "test_exit_code": 0, "timed_out": False, "passed_ids": ["test_m.py::test_fix"]},
    {"status": "ok", "hits": [], "test_exit_code": 0, "timed_out": False, "passed_ids": []},
    {"status": "ok", "hits": [], "test_exit_code": 2, "timed_out": False, "passed_ids": []},
])
def test_infrastructure_or_unexpected_reports_are_not_coverage_success(tmp_path, record):
    with pytest.raises(HarnessSetupError):
        probe(tmp_path, Runner(record))


@pytest.mark.parametrize("change", [{"case_id": "other"}, {"patch_diff_hash": "other"}, {"stdout_truncated": True}])
def test_identity_and_truncation_are_checked(tmp_path, change):
    runner = Runner()
    runner.modify = lambda value: replace(value, **change)
    with pytest.raises(HarnessSetupError):
        probe(tmp_path, runner)


def test_timeout_is_advisory_not_pass_or_kill(tmp_path):
    record = {"status": "ok", "hits": [], "test_exit_code": None, "timed_out": True, "passed_ids": []}
    report = probe(tmp_path, Runner(record))
    assert report.timed_out and report.test_exit_code is None
    assert report.uncovered_statements == (("m.py", 2), ("m.py", 4))
    assert report.needs_review

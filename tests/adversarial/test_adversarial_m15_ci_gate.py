"""M15 adversarial PR scenarios and complete diagnostic aggregation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agentsentinel.verification.ci_gate import run_ci_gate_audit
from tests.unit.test_m15_ci_gate import change, snapshot

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = [pytest.mark.unit, pytest.mark.adversarial]


def test_scenario01_trojan_source_reports_exact_post_line(tmp_path: Path) -> None:
    diff = change(tmp_path, "x = 1\n", "x = 1\n# \u202e spoof\n")
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 1
    assert [(v.rule_id, v.line_number) for v in report.violations] == [("LEX-001", 2)]


@pytest.mark.parametrize("call", ["breakpoint()", "pdb.set_trace()", "ipdb.set_trace()", "builtins.breakpoint()", "sys.breakpointhook()", "pause()", "debug.set_trace()"])
def test_scenario02_debugger_calls_and_import_aliases(tmp_path: Path, call: str) -> None:
    before = "from builtins import breakpoint as pause\nimport pdb as debug\ndef f():\n    return 1\n"
    after = before.replace("    return 1", f"    {call}\n    return 1")
    report = run_ci_gate_audit(change(tmp_path, before, after), tmp_path)
    debug = [v for v in report.violations if v.rule_id == "LEX-002"]
    assert len(debug) == 1
    assert debug[0].line_number == 4
    assert report.exit_code == 1


def test_new_breakpoint_before_existing_reports_the_new_occurrence(tmp_path: Path) -> None:
    before = "def f():\n    x = 1\n    breakpoint()\n    return x\n"
    after = "def f():\n    breakpoint()\n    x = 1\n    breakpoint()\n    return x\n"
    report = run_ci_gate_audit(change(tmp_path, before, after), tmp_path)
    assert [v.line_number for v in report.violations if v.rule_id == "LEX-002"] == [2]


@pytest.mark.parametrize("expression", ['"processed_token_8841"', '"processed_" + "token_8841"', 'b"processed_token_8841".decode()', '"".join(["processed_", "token_8841"])'])
def test_scenario03_unconditional_constant_folded_return_overfit(tmp_path: Path, expression: str) -> None:
    diff = change(tmp_path, "def normalize(x):\n    return x.strip()\n", f"def normalize(x):\n    return {expression}\n")
    (tmp_path / "test_normalize.py").write_text('assert normalize("input") == "processed_token_8841"\n', encoding="utf-8", newline="\n")
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == "OVF-001" and v.line_number == 2 for v in report.violations)


@pytest.mark.parametrize("body", ['    if x == "secret_literal":\n        return x\n    return x\n', '    return {"key": "secret_literal"}.get(x)\n', '    match x:\n        case "secret_literal":\n            return x\n    return x\n'])
def test_conditional_match_and_dictionary_values_reuse_m8_folding(tmp_path: Path, body: str) -> None:
    diff = change(tmp_path, "def f(x):\n    return x\n", "def f(x):\n" + body)
    (tmp_path / "test_f.py").write_text('assert f("input") == "secret_literal"\n', encoding="utf-8", newline="\n")
    assert any(v.rule_id == "OVF-001" for v in run_ci_gate_audit(diff, tmp_path).violations)


def test_scenario04_public_file_deletion_reports_broken_symbols(tmp_path: Path) -> None:
    diff = change(tmp_path, "def process_transaction():\n    return 1\nclass Helper:\n    pass\n", None)
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 1
    assert len([v for v in report.violations if v.rule_id == "API-001"]) == 2
    assert report.file_metrics[0].api_contract_status == "❌ Broken Symbol"


@pytest.mark.parametrize("name", [".github/workflows/ci.yml", "pyproject.toml", "Dockerfile.prod", ".git/config", "setup.py"])
def test_scenario05_protected_infrastructure_paths(tmp_path: Path, name: str) -> None:
    diff = change(tmp_path, "old\n", "new\n", name)
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == "PATH-001" for v in report.violations)


@pytest.mark.parametrize("handler", ["except:\n        pass", "except Exception:\n        pass", "except BaseException:\n        ...", "except Exception:\n        return", "except Exception:\n        'ignored'", "except Exception:\n        def nested():\n            raise RuntimeError()"])
def test_scenario06_silent_exception_handlers(tmp_path: Path, handler: str) -> None:
    after = "def f():\n    try:\n        return 1\n    " + handler + "\n"
    report = run_ci_gate_audit(change(tmp_path, "def f():\n    return 1\n", after), tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == "EXC-001" and v.line_number == 4 for v in report.violations)


def complexity_source(branches: int, name: str = "f") -> str:
    return f"def {name}(x):\n" + "".join(f"    if x == {i}:\n        x += 1\n" for i in range(branches)) + "    return x\n"


def test_scenario07_cc_warning_and_strict_warning_exit(tmp_path: Path) -> None:
    diff = change(tmp_path, complexity_source(2), complexity_source(14))
    normal = run_ci_gate_audit(diff, tmp_path)
    strict = run_ci_gate_audit(diff, tmp_path, strict_warnings=True)
    assert normal.exit_code == 0
    assert normal.status == "PASSED"
    assert normal.summary["error_count"] == 0
    assert normal.summary["warning_count"] >= 1
    assert strict.exit_code == 1
    assert strict.status == "FAILED"
    assert (normal.file_metrics[0].cc_pre, normal.file_metrics[0].cc_post, normal.file_metrics[0].cc_delta) == (3, 15, 12)
    assert all(v.rule_id == "CC-001" and v.severity == "WARNING" and v.stage == "Stage 4: Complexity Guard" for v in normal.violations)


@pytest.mark.parametrize("call", ["eval('x')", "exec('x = 1')", "setattr(x, 'a', 1)", "delattr(x, 'a')", "__import__('os')", "inspect.stack()", "sys._getframe()", "os._exit(0)", "builtins.__dict__", "dynamic('x')"])
def test_scenario08_dynamic_execution_reflection_and_aliases(tmp_path: Path, call: str) -> None:
    before = "from builtins import eval as dynamic\ndef f(x):\n    return x\n"
    after = before.replace("    return x", f"    {call}\n    return x")
    report = run_ci_gate_audit(change(tmp_path, before, after), tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == "REF-001" and v.line_number == 3 for v in report.violations)


@pytest.mark.parametrize("statement", ["import pytest", "import _pytest", "from unittest import mock", "import ctypes", "from inspect import currentframe as frame"])
def test_new_banned_imports_are_reported(tmp_path: Path, statement: str) -> None:
    report = run_ci_gate_audit(change(tmp_path, "x = 1\n", statement + "\nx = 1\n"), tmp_path)
    assert any(v.rule_id == "REF-001" and v.line_number == 1 for v in report.violations)


def test_scenario09_sync_async_public_flip(tmp_path: Path) -> None:
    diff = change(tmp_path, "def get_user():\n    return 1\n", "async def get_user():\n    return 1\n")
    assert any(v.rule_id == "API-001" for v in run_ci_gate_audit(diff, tmp_path).violations)


def test_scenario10_rename_partial_class_deletion_and_second_file(tmp_path: Path) -> None:
    before = "class PublicHelper:\n    pass\ndef f():\n    return 1\n"
    after = "def f():\n    return 2\n"
    diff = change(tmp_path, before, after, "old.py", new_name="renamed.py")
    diff += change(tmp_path, "x = 1\n", "x = 2\n", "other.py")
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 1
    assert any(v.file_path == "renamed.py" and v.rule_id == "API-001" for v in report.violations)
    assert len(report.file_metrics) == 2


def test_all_five_stages_aggregate_and_workspace_never_changes(tmp_path: Path) -> None:
    diff = change(tmp_path, "name: old\n", "name: \u202e new\n", ".github/workflows/ci.yml")
    after = "def replacement(x):\n    breakpoint()\n    eval('x')\n    try:\n        x += 1\n    except Exception:\n        pass\n    return 'processed_token_8841'\n"
    diff += change(tmp_path, "def original(x):\n    return x\n", after)
    (tmp_path / "test_x.py").write_text('assert value == "processed_token_8841"\n', encoding="utf-8", newline="\n")
    disk = snapshot(tmp_path)
    report = run_ci_gate_audit(diff, tmp_path)
    assert {v.rule_id for v in report.violations} >= {"PATH-001", "LEX-001", "LEX-002", "OVF-001", "REF-001", "EXC-001", "API-001"}
    assert {v.stage.split(":")[0] for v in report.violations} == {"Stage 1", "Stage 2", "Stage 3", "Stage 4", "Stage 5"}
    keys = [(v.file_path, v.line_number, v.stage, v.rule_id) for v in report.violations]
    assert keys == sorted(keys)
    assert report.total_violations == len(report.violations)
    assert snapshot(tmp_path) == disk


def test_unchanged_legacy_hazards_and_literals_are_not_reintroduced(tmp_path: Path) -> None:
    before = "import pytest\ndef f(x):\n    breakpoint()\n    if x:\n        return 'legacy_literal'\n    try:\n        return x\n    except Exception:\n        pass\n"
    after = before.replace("return x", "return x + 1")
    (tmp_path / "test_x.py").write_text("assert f(1) == 'legacy_literal'\n", encoding="utf-8", newline="\n")
    report = run_ci_gate_audit(change(tmp_path, before, after), tmp_path)
    assert report.exit_code == 0
    assert report.violations == ()


def test_renaming_test_to_production_does_not_bypass_path_policy(tmp_path: Path) -> None:
    diff = change(tmp_path, "x = 1\n", "x = 2\n", "tests/test_old.py", new_name="module.py")
    assert any(v.rule_id == "PATH-002" for v in run_ci_gate_audit(diff, tmp_path).violations)


@pytest.mark.parametrize("module,call,rule", [("pdb", "set_trace", "LEX-002"), ("inspect", "stack", "REF-001")])
def test_later_import_cannot_retroactively_hide_forbidden_call(tmp_path: Path, module: str, call: str, rule: str) -> None:
    after = f"import {module}\n{module}.{call}()\nimport math as {module}\nx = 1\n"
    report = run_ci_gate_audit(change(tmp_path, "x = 1\n", after), tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == rule and v.line_number == 2 for v in report.violations)


def test_unchanged_call_before_rebinding_is_not_a_new_hazard(tmp_path: Path) -> None:
    before = "import pdb\npdb.set_trace()\nimport math as pdb\nx = 1\n"
    report = run_ci_gate_audit(change(tmp_path, before, before.replace("x = 1", "x = 2")), tmp_path)
    assert not any(v.rule_id == "LEX-002" for v in report.violations)

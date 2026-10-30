"""Static type-2 clone detection and advisory CI integration."""

from __future__ import annotations

import subprocess
from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING

import pytest

from agentsentinel.verification.ci_gate import run_ci_gate_audit
from tests.unit.test_m15_ci_gate import change

if TYPE_CHECKING:
    from pathlib import Path


def detector():
    from agentsentinel.verification.clone_detector import detect_type2_clones

    return detect_type2_clones


def routine(name: str = "first", parameter: str = "value", local: str = "result") -> str:
    return (
        f"def {name}({parameter}):\n"
        f"    {local} = {parameter} + 1\n"
        f"    {local} = abs({local})\n"
        f"    {local} = {local} * 2\n"
        f"    {local} = {local} - 3\n"
        f"    return {local}\n"
    )


def test_alpha_parameters_locals_and_literals_report_frozen_source_coordinates() -> None:
    source = routine() + "\n" + routine("second", "input_value", "answer").replace("+ 1", "+ 99")
    findings = detector()({"module.py": source})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.original.file_path, finding.original.function_name) == ("module.py", "first")
    assert (finding.original.start_line, finding.original.end_line) == (2, 6)
    assert finding.original.statement_count == 5
    assert finding.original.node_count >= 25
    assert (finding.duplicate.function_name, finding.duplicate.start_line, finding.duplicate.end_line) == ("second", 9, 13)
    with pytest.raises(FrozenInstanceError):
        finding.duplicate.start_line = 0


def test_small_helpers_and_node_threshold_are_not_clones() -> None:
    small = "def first(x):\n    a = x + 1\n    b = a * 2\n    return b\n"
    assert detector()({"a.py": small, "b.py": small.replace("first", "second")}) == ()
    tiny = "def first():\n    pass\n    pass\n    pass\n    pass\n    pass\n"
    assert detector()({"a.py": tiny, "b.py": tiny.replace("first", "second")}) == ()
    assert detector()({"a.py": routine(), "b.py": routine("second")}, min_nodes=1000) == ()


@pytest.mark.parametrize("old,new", [("abs", "round"), ("* 2", "/ 2"), ("value +", "GLOBAL +")])
def test_globals_and_operators_keep_their_identity(old: str, new: str) -> None:
    assert detector()({"a.py": routine(), "b.py": routine("second").replace(old, new)}) == ()


def test_attribute_names_are_not_alpha_renamed() -> None:
    first = routine().replace("abs(result)", "value.left(result)")
    second = first.replace("first", "second").replace(".left", ".right")
    assert detector()({"a.py": first, "b.py": second}) == ()


def test_parameter_order_and_local_alias_relationships_are_preserved() -> None:
    first = routine().replace("(value)", "(value, other)").replace("value + 1", "value - other")
    second = first.replace("first", "second").replace("value - other", "other - value")
    assert detector()({"a.py": first, "b.py": second}) == ()
    second = routine("second").replace("result - 3", "value - 3")
    assert detector()({"a.py": routine(), "b.py": second}) == ()


def test_global_declarations_cannot_be_mistaken_for_locals() -> None:
    first = routine().replace("    result = value + 1", "    global result\n    result = value + 1")
    second = first.replace("first", "second").replace("result", "another_global")
    assert detector()({"a.py": first, "b.py": second}) == ()


def test_nested_closure_capture_and_shadowed_parameter_are_distinct() -> None:
    first = (
        "def first(value):\n"
        "    result = value + 1\n"
        "    def inner(other):\n"
        "        return result + other\n"
        "    result = inner(value)\n"
        "    result = result * 2\n"
        "    return result\n"
    )
    renamed = first.replace("first", "second").replace("value", "input_value").replace("result", "answer").replace("other", "item").replace("inner", "nested")
    assert detector()({"a.py": first, "b.py": renamed})
    shadowed = first.replace("first", "second").replace("def inner(other)", "def inner(result)").replace("return result + other", "return result + result")
    assert detector()({"a.py": first, "b.py": shadowed}) == ()


def test_lambda_and_comprehension_scopes_do_not_capture_outer_locals() -> None:
    first = routine().replace("result = abs(result)", "result = [value + item for item in result]")
    second = first.replace("first", "second").replace("for item in result", "for value in result").replace("value + item", "value + value")
    assert detector()({"a.py": first, "b.py": second}) == ()
    first = routine().replace("result = abs(result)", "result = (lambda item: value + item)(result)")
    second = first.replace("first", "second").replace("lambda item: value + item", "lambda value: value + value")
    assert detector()({"a.py": first, "b.py": second}) == ()


def test_nonlocal_binding_tracks_enclosing_parameter_position() -> None:
    first = "def outer(value, other):\n" + "\n".join("    " + line for line in routine("inner").splitlines()) + "\n"
    first = first.replace("def inner(value):", "def inner():\n        nonlocal value")
    second = first.replace("outer", "second").replace("nonlocal value", "nonlocal other").replace("result = value + 1", "result = other + 1")
    assert detector()({"a.py": first, "b.py": second}) == ()


def test_partial_statement_windows_find_copied_region() -> None:
    first = routine().replace("    return result", "    result = result / 7\n    return result")
    second = routine("second").replace("    return result", "    result = result // 8\n    return result")
    findings = detector()({"a.py": first, "b.py": second}, min_statements=4)
    assert any(item.original.start_line == 2 and item.original.end_line == 5 for item in findings)


def test_cross_file_results_are_deterministic_and_do_not_report_overlaps() -> None:
    sources = {"z.py": routine("last"), "a.py": routine(), "m.py": routine("middle")}
    forward = detector()(sources)
    assert forward == detector()(dict(reversed(tuple(sources.items()))))
    assert len(forward) == 2
    assert all(item.original.file_path == "a.py" for item in forward)
    assert detector()({"a.py": routine()}, min_statements=2, min_nodes=1) == ()


def test_nonoverlapping_repetition_in_one_function_is_clone_evidence() -> None:
    source = "def first(value):\n" + "    result = value + 1\n" * 14 + "    return result\n"
    findings = detector()({"module.py": source})
    assert findings
    assert all(item.original.end_line < item.duplicate.start_line for item in findings)
    repeated_definitions = routine() + "\n" + routine()
    assert detector()({"module.py": repeated_definitions})


@pytest.mark.parametrize("replacement", [
    "result = [value + item for item in result]",
    "result = (lambda item: value + item)(result)",
    "result = [lambda: item + value for item in result]",
    "result = (value + item for item in result)",
    "result = {item: value for item in result}",
    "result = [[value + inner for inner in item] for item in result]",
])
def test_alpha_renaming_inside_expression_scopes_remains_a_clone(replacement: str) -> None:
    first = routine().replace("result = abs(result)", replacement)
    second = first.replace("first", "second").replace("value", "incoming").replace("result", "answer").replace("item", "element")
    assert detector()({"a.py": first, "b.py": second})


def test_ci_same_named_distinct_function_occurrences_can_warn(tmp_path: Path) -> None:
    before = routine()
    report = run_ci_gate_audit(change(tmp_path, before, before + "\n" + routine()), tmp_path)
    warnings = [item for item in report.violations if item.rule_id == "CLONE-001"]
    assert len(warnings) == 1
    assert warnings[0].line_number == 9


@pytest.mark.parametrize("limit,value", [("min_statements", 0), ("min_nodes", -1), ("max_source_bytes", 0), ("max_ast_nodes", 0), ("max_windows", 0), ("max_findings", 0)])
def test_invalid_limits_raise_value_error(limit: str, value: int) -> None:
    with pytest.raises(ValueError):
        detector()({}, **{limit: value})


@pytest.mark.parametrize("limit,value,expected", [
    ("max_source_bytes", 20, "source_bytes"),
    ("max_ast_nodes", 10, "ast_nodes"),
    ("max_windows", 1, "source_inventory"),
    ("max_findings", 1, "findings"),
])
def test_resource_exhaustion_is_typed_and_deterministic(limit: str, value: int, expected: str) -> None:
    from agentsentinel.verification.clone_detector import CloneAnalysisLimitError

    sources = {"a.py": routine(), "b.py": routine("second"), "c.py": routine("third")}
    for ordered in (sources, dict(reversed(tuple(sources.items())))):
        with pytest.raises(CloneAnalysisLimitError) as raised:
            detector()(ordered, **{limit: value})
        assert isinstance(raised.value, ValueError)
        assert raised.value.limit_name == expected
        assert raised.value.limit == value
        assert len(str(raised.value)) < 160


def test_window_exhaustion_does_not_look_like_no_clones() -> None:
    from agentsentinel.verification.clone_detector import CloneAnalysisLimitError

    with pytest.raises(CloneAnalysisLimitError) as raised:
        detector()({"a.py": routine()}, max_windows=1)
    assert (raised.value.limit_name, raised.value.limit) == ("windows", 1)


def test_normalization_exhaustion_does_not_return_partial_evidence() -> None:
    from agentsentinel.verification.clone_detector import CloneAnalysisLimitError

    source = "def first(value):\n" + "    value = value + 1\n" * 20 + "    return value\n"
    with pytest.raises(CloneAnalysisLimitError) as raised:
        detector()({"a.py": source}, max_ast_nodes=200)
    assert (raised.value.limit_name, raised.value.limit) == ("normalization", 3200)


def test_comparison_exhaustion_has_a_distinct_typed_limit() -> None:
    from agentsentinel.verification.clone_detector import CloneAnalysisLimitError

    source = "def first():\n" + "    pass\n" * 130
    with pytest.raises(CloneAnalysisLimitError) as raised:
        detector()({"a.py": source}, min_statements=1, min_nodes=1,
                   max_ast_nodes=1_000_000, max_findings=100_000)
    assert (raised.value.limit_name, raised.value.limit) == ("comparisons", 80_000)


def test_completed_analysis_can_return_no_clones_at_exact_resource_caps() -> None:
    source = "x = 1\n"
    assert detector()({"a.py": source}, max_source_bytes=6, max_ast_nodes=5, max_windows=1) == ()
    assert detector()({"a.py": "def first():\n    pass\n"}, max_windows=1) == ()
    assert len(detector()({"a.py": routine(), "b.py": routine("second")}, max_findings=1)) == 1


def test_bad_syntax_and_parser_recursion_remain_conservative_omissions() -> None:
    sources = {"a.py": routine(), "b.py": routine("second")}
    assert detector()({"broken.py": "def broken(:\n", **sources}) == detector()(sources)
    assert detector()({"huge.py": "x = " + "+".join(["1"] * 10000)}) == ()


@pytest.mark.parametrize("kind", ["source_bytes", "windows", "normalization"])
def test_ci_incomplete_clone_analysis_is_a_bounded_advisory(tmp_path: Path, kind: str) -> None:
    after = routine()
    if kind == "source_bytes":
        (tmp_path / "oversize.py").write_text("#" * 2_000_001, encoding="utf-8", newline="\n")
    else:
        count = 160 if kind == "windows" else 100
        after = "def first(value):\n" + "    value = value + 1\n" * count + "    return value\n"
    diff = change(tmp_path, None, after)
    report = run_ci_gate_audit(diff, tmp_path)
    warnings = [item for item in report.violations if item.rule_id == "CLONE-002"]
    assert report.exit_code == 0
    assert len(warnings) == 1
    assert warnings[0].severity == "WARNING"
    assert "incomplete" in warnings[0].message.lower()
    assert kind in warnings[0].message
    assert len(warnings[0].message) < 200
    assert run_ci_gate_audit(diff, tmp_path, strict_warnings=True).exit_code == 1


@pytest.mark.parametrize("limit_name", ["files", "inventory_entries"])
def test_ci_inventory_limits_cannot_silently_skip_remaining_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit_name: str) -> None:
    from agentsentinel.verification import ci_gate

    attribute = "_CLONE_MAX_FILES" if limit_name == "files" else "_CLONE_MAX_ENTRIES"
    monkeypatch.setattr(ci_gate, attribute, 1)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    (tmp_path / "b.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
    report = run_ci_gate_audit(change(tmp_path, None, routine()), tmp_path)
    warnings = [item for item in report.violations if item.rule_id == "CLONE-002"]
    assert report.exit_code == 0
    assert len(warnings) == 1
    assert limit_name in warnings[0].message
    assert "(1)" in warnings[0].message


def test_ci_reports_only_changed_clone_blocks_and_remains_advisory(tmp_path: Path) -> None:
    (tmp_path / "original.py").write_text(routine(), encoding="utf-8", newline="\n")
    diff = change(tmp_path, None, routine("second", "incoming", "answer"), "new.py")
    report = run_ci_gate_audit(diff, tmp_path)
    clones = [item for item in report.violations if item.rule_id == "CLONE-001"]
    assert report.exit_code == 0
    assert len(clones) == 1
    assert (clones[0].file_path, clones[0].line_number, clones[0].severity) == ("new.py", 2, "WARNING")
    assert "original.py" in clones[0].message
    assert run_ci_gate_audit(diff, tmp_path, strict_warnings=True).exit_code == 1
    assert not (tmp_path / "new.py").exists()


def test_ci_unchanged_clones_do_not_warn_for_changes_elsewhere_or_comments(tmp_path: Path) -> None:
    first = routine()
    (tmp_path / "duplicate.py").write_text(routine("second"), encoding="utf-8", newline="\n")
    for after in ("# heading\n" + first, first + "\nOTHER = 1\n", first.replace("result * 2", "result * 2  # comment")):
        report = run_ci_gate_audit(change(tmp_path, first, after), tmp_path)
        assert not any(item.rule_id == "CLONE-001" for item in report.violations)


@pytest.mark.parametrize("kind", ["rename_header", "delete_prefix"])
def test_ci_unchanged_clone_body_does_not_inherit_adjacent_edits(tmp_path: Path, kind: str) -> None:
    (tmp_path / "duplicate.py").write_text(routine("second"), encoding="utf-8", newline="\n")
    before = routine()
    after = before.replace("first", "renamed")
    if kind == "delete_prefix":
        before = before.replace("    result = value + 1", "    unrelated = value / 7\n    result = value + 1")
        after = routine()
    report = run_ci_gate_audit(change(tmp_path, before, after), tmp_path)
    assert not any(item.rule_id == "CLONE-001" for item in report.violations)


def test_ci_deletion_that_creates_clone_is_a_changed_block(tmp_path: Path) -> None:
    (tmp_path / "original.py").write_text(routine(), encoding="utf-8", newline="\n")
    before = routine("second").replace("    result = result * 2", "    result = result / 7\n    result = result * 2")
    report = run_ci_gate_audit(change(tmp_path, before, routine("second")), tmp_path)
    assert any(item.rule_id == "CLONE-001" and item.file_path == "module.py" for item in report.violations)


def test_ci_modified_lexically_first_block_still_warns(tmp_path: Path) -> None:
    (tmp_path / "z_original.py").write_text(routine(), encoding="utf-8", newline="\n")
    before = routine("second").replace("result * 2", "result / 2")
    report = run_ci_gate_audit(change(tmp_path, before, routine("second"), "a_changed.py"), tmp_path)
    assert any(item.rule_id == "CLONE-001" and item.file_path == "a_changed.py" for item in report.violations)


def test_ci_inventory_excludes_environment_sources_and_bounds_large_files(tmp_path: Path) -> None:
    for directory in (".venv", "venv", "env", "node_modules", "custom_environment"):
        target = tmp_path / directory
        target.mkdir()
        (target / "copy.py").write_text(routine(), encoding="utf-8", newline="\n")
        if directory == "custom_environment":
            (target / "pyvenv.cfg").write_text("home = python\n", encoding="utf-8", newline="\n")
    (tmp_path / "oversize.py").write_text("#" * 2_000_001, encoding="utf-8", newline="\n")
    report = run_ci_gate_audit(change(tmp_path, None, routine("second")), tmp_path)
    assert report.exit_code == 0
    assert not any(item.rule_id == "CLONE-001" for item in report.violations)


def test_ci_clone_detection_has_no_process_or_repository_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Static clone detection spawned a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    source = "raise RuntimeError('must never run')\n" + routine()
    (tmp_path / "original.py").write_text(source, encoding="utf-8", newline="\n")
    report = run_ci_gate_audit(change(tmp_path, None, routine("second")), tmp_path)
    assert any(item.rule_id == "CLONE-001" for item in report.violations)

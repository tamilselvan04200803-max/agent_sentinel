"""M16 static causal evidence never imports or executes inspected programs."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from difflib import unified_diff

import pytest

from agentsentinel.localization.traceback_parser import TracebackFrame


def analyze(before, after, frames, **options):
    from agentsentinel.verification.causal_trace import analyze_causal_trace
    return analyze_causal_trace(before, after, frames, **options)


def frame(path="m.py", line=1, name="root"):
    return TracebackFrame(path, line, name, "")


def distances(report):
    return {item.function_name: item.hop_distance for item in report.modified_functions}


def test_hops_and_disconnected_function():
    before = "def root():\n    return one()\ndef one():\n    return two()\ndef two():\n    return 3\ndef noise():\n    return 4\n"
    after = before.replace("return two()", "return two() + 1").replace("return 3", "return 5").replace("return 4", "return 6")
    report = analyze({"m.py": before}, {"m.py": after}, [frame()])
    assert distances(report) == {"one": 1, "two": 2, "noise": None}
    assert report.has_traceback_roots
    with pytest.raises(FrozenInstanceError):
        report.unresolved_calls = 9


def test_nested_edit_does_not_enable_outer():
    before = "def outer():\n    def inner():\n        return 1\n    return inner()\n"
    report = analyze({"m.py": before}, {"m.py": before.replace("return 1", "return 2")}, [frame(line=3, name="inner")])
    assert distances(report) == {"outer.inner": 0}


def test_import_alias_connects_files_and_src_layout():
    main = "from lib import fix as selected\ndef root():\n    return selected()\n"
    report = analyze({"src/main.py": main, "src/lib.py": "def fix():\n    return 1\n"},
                     {"src/main.py": main, "src/lib.py": "def fix():\n    return 2\n"},
                     [frame("src/main.py", 2)])
    assert distances(report) == {"fix": 1}


def test_method_identity_does_not_cross_classes():
    before = "class A:\n    def root(self):\n        return self.work()\n    def work(self):\n        return 1\nclass B:\n    def work(self):\n        return 1\n"
    report = analyze({"m.py": before}, {"m.py": before.replace("return 1", "return 2")}, [frame(line=2)])
    assert distances(report) == {"A.work": 1, "B.work": None}


def test_parameter_shadowing_does_not_invent_edge():
    before = "def root(helper):\n    return helper()\ndef helper():\n    return 1\n"
    report = analyze({"m.py": before}, {"m.py": before.replace("return 1", "return 2")}, [frame()])
    assert distances(report) == {"helper": None}
    assert report.unresolved_calls > 0


def test_duplicate_definitions_remain_distinct_and_ambiguous():
    before = "def root():\n    return helper()\ndef helper():\n    return 1\ndef helper():\n    return 2\n"
    report = analyze({"m.py": before}, {"m.py": before.replace("return 1", "return 3").replace("return 2", "return 4")}, [frame()])
    assert [(row.occurrence, row.hop_distance) for row in report.modified_functions] == [(0, None), (1, None)]


def test_async_and_added_function():
    before = "async def root():\n    return await helper()\n"
    after = before + "async def helper():\n    return 2\n"
    assert distances(analyze({"m.py": before}, {"m.py": after}, [frame()])) == {"helper": 1}


def test_no_roots_and_module_only_edits_are_explicit():
    before = "FLAG = 1\ndef root():\n    return FLAG\n"
    report = analyze({"m.py": before}, {"m.py": before.replace("FLAG = 1", "FLAG = 2")}, [])
    assert report.modified_functions == ()
    assert not report.has_traceback_roots


def test_hop_cap_and_invalid_syntax():
    with pytest.raises(ValueError):
        analyze({}, {}, [], max_hops=-1)
    with pytest.raises(ValueError):
        analyze({}, {}, [], max_hops=3)
    with pytest.raises(SyntaxError):
        analyze({"m.py": "def broken("}, {}, [])


def test_source_budget_is_enforced_before_parse(monkeypatch):
    from agentsentinel.verification import causal_trace
    monkeypatch.setattr(causal_trace, "MAX_SOURCE_BYTES", 10)
    with pytest.raises(ValueError, match="budget"):
        analyze({"m.py": "#" * 11}, {}, [])


def test_multiline_added_statement_maps_to_its_start(tmp_path):
    from agentsentinel.verification.causal_trace import collect_added_statement_lines
    before = "def root():\n    return (\n        1\n    )\n"
    after = before.replace("        1", "        2")
    (tmp_path / "m.py").write_text(before, encoding="utf-8", newline="\n")
    raw = "".join(unified_diff(before.splitlines(True), after.splitlines(True), "a/m.py", "b/m.py"))
    assert collect_added_statement_lines(raw, tmp_path) == (("m.py", 2),)

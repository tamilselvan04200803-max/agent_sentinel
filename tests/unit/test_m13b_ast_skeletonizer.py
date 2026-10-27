"""M13B: deterministic folds retain disk coordinates and localized context."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.llm.prompts import PromptBuilder
from agentsentinel.localization import __all__ as localization_exports
from agentsentinel.localization import ast_slicer
from agentsentinel.localization.ast_slicer import LocalizationSlice

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("spans", "expected"),
    [
        ([], []),
        ([(10, 20), (15, 25)], [(10, 25)]),
        ([(8, 6), (1, 2), (3, 5), (12, 12)], [(1, 8), (12, 12)]),
        ([(5, 5), (5, 5)], [(5, 5)]),
    ],
)
def test_ac06_span_normalization(
    spans: Sequence[tuple[int, int]], expected: list[tuple[int, int]],
) -> None:
    assert ast_slicer.merge_keep_spans(spans) == expected


@pytest.mark.parametrize("span", [(0, 4), (3, -1), (-2, -1)])
def test_nonpositive_span_bounds_are_rejected(span: tuple[int, int]) -> None:
    with pytest.raises(ValueError, match="positive"):
        ast_slicer.merge_keep_spans([span])


@pytest.mark.parametrize("compact", [False, True])
def test_ac01_syntax_fallback_retains_all_three_lines(compact: bool) -> None:
    source = "def broken(a, b:\n    value = 1\n    return value\n"
    result = ast_slicer.skeletonize_python_source(source, compact=compact)
    assert result == (
        "    1: def broken(a, b:\n    2:     value = 1\n    3:     return value"
    )
    assert len(result.splitlines()) == 3


def test_ac02_multiline_signature_keeps_nested_colons_and_comments() -> None:
    lines = [
        "def transform(",
        "    value: dict[",
        "        str,",
        "        tuple[int, ...],",
        "    ],",
        "    callback: Callable[",
        "        [int, dict[str, int]],",
        "        bool,",
        "    ] = lambda x, y: True,  # default colon is nested",
        "    options: tuple[int, ...] = (",
        "        1,",
        "    ),",
        ") -> dict[str, int]:",
        "    # body comment",
        "    result = callback(1, value)",
        "    return {'result': result}",
    ]
    source = "\n".join(lines)
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.FunctionDef)
    assert ast_slicer._get_function_signature_end(node, lines) == 13
    folded = ast_slicer.skeletonize_python_source(source).splitlines()
    for index in range(13):
        assert folded[index].partition(": ")[2] == lines[index]
    assert folded[13] == (
        "   14:     # ... [lines 14-16 omitted by AST skeletonizer] ..."
    )
    assert folded[14:] == ["   15: ", "   16: "]


def test_ac03_stacked_decorators_and_class_fields_remain() -> None:
    source = (
        "@dataclass\nclass Config:\n    batch_size: int = 64\n"
        "    @property\n    @decorator('x')\n    def value(self):\n"
        "        return self.batch_size\n"
        "    @staticmethod\n    def helper():\n        return 12\n"
    )
    folded = ast_slicer.skeletonize_python_source(source, [(5, 5)], compact=True)
    assert "1: @dataclass" in folded
    assert "3:     batch_size: int = 64" in folded
    assert "4:     @property\n    5:     @decorator('x')" in folded
    assert "7:         return self.batch_size" in folded
    assert "8:     @staticmethod" in folded
    assert "10:         # ... [lines 10-10 omitted" in folded
    assert "return 12" not in folded


def test_ac04_nested_closure_keeps_outer_and_selected_inner_only() -> None:
    source = (
        "def outer():\n    seed = 1\n    def selected():\n"
        "        value = seed + 2\n        return value\n"
        "    def sibling():\n        discarded = 12\n        return discarded\n"
        "    return selected()\n"
    )
    folded = ast_slicer.skeletonize_python_source(source, [(4, 4)], compact=True)
    assert "2:     seed = 1" in folded
    assert "4:         value = seed + 2" in folded
    assert "5:         return value" in folded
    assert "6:     def sibling():" in folded
    assert "7:         # ... [lines 7-8 omitted" in folded
    assert "9:     return selected()" in folded
    assert "discarded = 12" not in folded


def test_ac05_multiline_docstring_preserves_first_line_without_token_error() -> None:
    lines = ['def documented():', '    """First line']
    lines += [f"    doc line {number}" for number in range(13)]
    lines += ['    """', "    return 42"]
    node = ast.parse("\n".join(lines)).body[0]
    assert isinstance(node, ast.FunctionDef)
    assert ast_slicer._get_function_signature_end(node, lines) == 1
    folded = ast_slicer.skeletonize_python_source("\n".join(lines), compact=True)
    assert folded == (
        '    1: def documented():\n    2:     """First line\n'
        "    3:     # ... [lines 3-17 omitted by AST skeletonizer] ..."
    )


def test_ac07_module_imports_assignments_and_class_annotations_are_preserved() -> None:
    source = (
        "from dataclasses import dataclass\nimport typing\nLIMIT = 99\n"
        "OPTIONS: dict[str, int] = {'size': 4}\n@dataclass\nclass Config:\n"
        "    batch_size: int = 64\n    def run(self):\n        return self.batch_size\n"
        "AFTER = LIMIT\n"
    )
    folded = ast_slicer.skeletonize_python_source(source, compact=True)
    assert folded.partition("    9:")[0] == (
        "    1: from dataclasses import dataclass\n    2: import typing\n"
        "    3: LIMIT = 99\n    4: OPTIONS: dict[str, int] = {'size': 4}\n"
        "    5: @dataclass\n    6: class Config:\n    7:     batch_size: int = 64\n"
        "    8:     def run(self):\n"
    )
    assert folded.endswith("   10: AFTER = LIMIT")


@pytest.mark.parametrize("source", ["def foo(): return 42", "async def foo(): return 42"])
def test_ac08_single_line_function_is_untouched(source: str) -> None:
    assert ast_slicer.skeletonize_python_source(source) == f"    1: {source}"


def test_ac09_unicode_and_crlf_keep_line_alignment() -> None:
    source = 'def greet():\r\n    """Hello 🌍 café"""\r\n    return "你好"\r\nEND = 1\r\n'
    folded = ast_slicer.skeletonize_python_source(source)
    assert folded.splitlines() == [
        "    1: def greet():",
        '    2:     """Hello 🌍 café"""',
        "    3:     # ... [lines 3-3 omitted by AST skeletonizer] ...",
        "    4: END = 1",
    ]


@pytest.mark.parametrize("source", ["\x00", "def f():\n    return '\x00'\n"])
def test_ac09_null_byte_is_a_hard_failure(source: str) -> None:
    with pytest.raises(ValueError, match="^Binary or null-byte source is not allowed$"):
        ast_slicer.skeletonize_python_source(source)


@pytest.mark.parametrize("source", [None, b"def f(): return 1", 42])
def test_ac09_non_string_is_a_hard_failure(source: object) -> None:
    with pytest.raises(TypeError, match="^source must be a str$"):
        ast_slicer.skeletonize_python_source(cast("str", source))


def test_ac10_empty_file() -> None:
    assert ast_slicer.skeletonize_python_source("") == ""


def test_default_mode_keeps_every_physical_line_and_widens_prefix() -> None:
    source = "def f():\n" + "    x = 1\n" * 101 + "\n"
    folded = ast_slicer.skeletonize_python_source(source, line_number_width=1)
    lines = folded.splitlines()
    assert len(lines) == 103 == len(source.splitlines())
    assert [int(line.partition(":")[0]) for line in lines] == list(range(1, 104))
    assert lines[0] == "  1: def f():"
    assert lines[-1] == "103: "


def test_compact_mode_retains_disk_coordinates_and_compresses_large_module() -> None:
    source = "def f():\n" + "    value = 123456789\n" * 247 + "\nAFTER = 1\n"
    folded = ast_slicer.skeletonize_python_source(source, compact=True)
    assert folded.splitlines() == [
        "    1: def f():",
        "    2:     # ... [lines 2-248 omitted by AST skeletonizer] ...",
        "  249: ",
        "  250: AFTER = 1",
    ]
    assert len(folded) < 0.2 * len(source)


def test_blank_fold_start_uses_function_indent() -> None:
    source = "class C:\n    def f(self):\n\n        return 1\n"
    folded = ast_slicer.skeletonize_python_source(source, compact=True)
    assert folded.endswith("    3:         # ... [lines 3-4 omitted by AST skeletonizer] ...")


def test_async_functions_and_conditional_nested_definitions_are_folded() -> None:
    source = (
        "async def outer():\n    if True:\n        async def inner():\n"
        "            return 1\n    return 2\n"
    )
    folded = ast_slicer.skeletonize_python_source(source, [(5, 5)], compact=True)
    assert "2:     if True:" in folded
    assert "3:         async def inner():" in folded
    assert "4:             # ... [lines 4-4 omitted" in folded
    assert folded.endswith("    5:     return 2")


def _tiered_source() -> str:
    lines = ["def fault():"]
    lines += [f"    fault_value_{i:02d} = 'fault payload with useful context {i:02d}'" for i in range(10)]
    lines += ["    return fault_value_00", "def helper():"]
    lines += [f"    helper_value_{i:02d} = 'helper payload with useful context {i:02d}'" for i in range(20)]
    lines += ["    return helper_value_00", "def irrelevant():"]
    lines += [f"    irrelevant_value_{i:02d} = 'unused context {i:02d}'" for i in range(80)]
    lines += ["    return irrelevant_value_00", "class Trailing:", "    def end(self): return 42"]
    return "\n".join(lines)


def _slice(start: int, end: int, hop: int, path: str = "module.py") -> LocalizationSlice:
    return LocalizationSlice(path, "symbol", start, end, hop, "")


def test_packer_prefers_tier1_then_evicts_hop1_before_hop0() -> None:
    source = _tiered_source()
    slices = [_slice(1, 12, 0), _slice(13, 34, 1)]
    full = ast_slicer.pack_file_with_skeleton(source, slices, 10000)
    reduced = ast_slicer.pack_file_with_skeleton(source, slices, 1400)
    assert full.pruning_tier_used == 1
    assert "helper_value_19" in full.formatted_content
    assert reduced.pruning_tier_used == 2
    assert len(reduced.formatted_content) <= 1400
    assert "fault_value_09" in reduced.formatted_content
    assert "def helper():" in reduced.formatted_content
    assert "helper_value_19" not in reduced.formatted_content
    assert "irrelevant_value_79" not in full.formatted_content


def test_packer_tier3_compacts_after_hop1_eviction() -> None:
    source = _tiered_source()
    slices = [_slice(1, 12, 0), _slice(13, 34, 1)]
    full = ast_slicer.pack_file_with_skeleton(source, slices, 10000, compact=False)
    hop0 = ast_slicer.pack_file_with_skeleton(source, slices, 2200, compact=False)
    dense = ast_slicer.pack_file_with_skeleton(source, slices, 1400, compact=False)
    assert [result.pruning_tier_used for result in (full, hop0, dense)] == [1, 2, 3]
    assert dense.output_line_count < hop0.output_line_count
    assert "fault_value_09" in dense.formatted_content
    assert "helper_value_19" not in dense.formatted_content
    assert len(dense.formatted_content) <= 1400


def test_packer_tier4_removes_fault_body_and_keeps_bottom_interfaces() -> None:
    packed = ast_slicer.pack_file_with_skeleton(_tiered_source(), [_slice(1, 12, 0)], 500)
    assert packed.pruning_tier_used == 4
    assert len(packed.formatted_content) <= 500
    assert "fault_value_09" not in packed.formatted_content
    assert "117: class Trailing:" in packed.formatted_content
    assert "118:     def end(self): return 42" in packed.formatted_content


def test_packer_returns_complete_tier4_when_interfaces_exceed_budget() -> None:
    packed = ast_slicer.pack_file_with_skeleton("CONSTANT = 'abcdefgh'", [], 1)
    assert packed.pruning_tier_used == 4
    assert packed.formatted_content == "    1: CONSTANT = 'abcdefgh'"
    assert len(packed.formatted_content) > 1


def test_packer_statistics_and_result_immutability() -> None:
    source = "def f():\n    x = 1\n    return x\nEND = 1"
    packed = ast_slicer.pack_file_with_skeleton(source, [], 1000)
    assert packed.raw_line_count == 4
    assert packed.output_line_count == 3
    assert packed.used_syntax_fallback is False
    assert packed.compression_ratio == pytest.approx(1.0 - len(packed.formatted_content) / 67)
    with pytest.raises(FrozenInstanceError):
        packed.pruning_tier_used = 99


def test_packer_syntax_fallback_metadata_and_prefixes() -> None:
    packed = ast_slicer.pack_file_with_skeleton("def broken(:\n  x = 1", [], 10)
    assert packed.used_syntax_fallback is True
    assert packed.pruning_tier_used == 4
    assert packed.raw_line_count == packed.output_line_count == 2
    assert packed.formatted_content == "    1: def broken(:\n    2:   x = 1"
    assert packed.compression_ratio == 0.0


def test_packer_empty_source_and_zero_budget() -> None:
    packed = ast_slicer.pack_file_with_skeleton("", [], 0)
    assert packed.formatted_content == ""
    assert packed.raw_line_count == packed.output_line_count == 0
    assert packed.compression_ratio == 1.0
    assert packed.pruning_tier_used == 1
    assert packed.used_syntax_fallback is False


def test_packer_negative_budget_is_rejected() -> None:
    with pytest.raises(ValueError, match="nonnegative"):
        ast_slicer.pack_file_with_skeleton("x = 1", [], -1)


def test_packer_null_byte_remains_a_hard_failure() -> None:
    with pytest.raises(ValueError, match="Binary or null-byte"):
        ast_slicer.pack_file_with_skeleton("\x00", [], 100)


def test_localization_package_exports_skeleton_api() -> None:
    assert {
        "SkeletonPackResult", "merge_keep_spans", "skeletonize_python_source",
        "pack_file_with_skeleton",
    } <= set(localization_exports)


def _prompt_inputs(paths: tuple[str, ...] = ("module.py",)) -> tuple[CaseSpec, ExecutionResult]:
    return (
        CaseSpec(
            "m13b", "https://example.test/repo", "a" * 40,
            "python -m pytest -q", paths, ("test_module.py::test_fix",),
            created_at=datetime(2026, 10, 27, tzinfo=UTC),
        ),
        ExecutionResult("m13b", "baseline", ExitCode.TESTS_FAILED, "failed", "", 1.0),
    )


@pytest.mark.parametrize("entry_point", ["build_repair_prompt", "build_patch_prompt"])
def test_prompt_skeleton_keeps_localized_body_and_trailing_class(
    tmp_path: Path, entry_point: str,
) -> None:
    (tmp_path / "module.py").write_text(_tiered_source(), encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs()
    builder = PromptBuilder(tmp_path, max_file_chars=1400)
    prompt = getattr(builder, entry_point)(spec, baseline, [_slice(1, 12, 0)])
    assert "fault_value_09" in prompt
    assert "117: class Trailing:" in prompt
    assert "118:     def end(self): return 42" in prompt
    assert "omitted by AST skeletonizer" in prompt
    assert "TRUNCATED" not in prompt
    assert "irrelevant_value_79" not in prompt


def test_prompt_empty_localization_sequence_still_enables_skeleton(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_text(_tiered_source(), encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs()
    prompt = PromptBuilder(tmp_path, 500).build_patch_prompt(spec, baseline, [])
    assert "117: class Trailing:" in prompt
    assert "TRUNCATED" not in prompt


def test_prompt_matches_only_this_files_slices_and_normalizes_separators(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "module.py").write_text(_tiered_source(), encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs(("pkg/module.py",))
    builder = PromptBuilder(tmp_path, 1400)
    prompt = builder.build_patch_prompt(spec, baseline, [
        _slice(1, 12, 0, "pkg\\module.py"), _slice(13, 34, 0, "other.py"),
    ])
    assert "fault_value_09" in prompt
    assert "helper_value_19" not in prompt
    assert "117: class Trailing:" in prompt


@pytest.mark.parametrize("extension", ["py", "txt"])
def test_prompt_no_localization_preserves_legacy_truncation(tmp_path: Path, extension: str) -> None:
    name = f"module.{extension}"
    (tmp_path / name).write_text(_tiered_source(), encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs((name,))
    prompt = PromptBuilder(tmp_path, 500).build_patch_prompt(spec, baseline)
    assert "TRUNCATED" in prompt
    assert "AST skeletonizer" not in prompt
    assert "class Trailing" not in prompt


def test_prompt_non_python_with_localization_still_uses_legacy_truncation(tmp_path: Path) -> None:
    (tmp_path / "module.txt").write_text(_tiered_source(), encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs(("module.txt",))
    prompt = PromptBuilder(tmp_path, 500).build_patch_prompt(spec, baseline, [])
    assert "TRUNCATED" in prompt
    assert "AST skeletonizer" not in prompt


@pytest.mark.parametrize("source", ["VALUE = 1\n" * 100, "def broken(:\n" * 100, "\x00" * 1000])
def test_prompt_oversized_skeleton_or_unsafe_source_falls_back_to_raw_truncation(
    tmp_path: Path, source: str,
) -> None:
    (tmp_path / "module.py").write_text(source, encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs()
    builder = PromptBuilder(tmp_path, 100)
    assert builder.build_patch_prompt(spec, baseline, []) == builder.build_patch_prompt(spec, baseline)


def test_prompt_small_file_is_unchanged_with_localization(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_text("x = 1\ny = 2\n", encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs()
    builder = PromptBuilder(tmp_path, 100)
    assert builder.build_patch_prompt(spec, baseline, []) == builder.build_patch_prompt(spec, baseline)


def test_prompt_sanitizes_skeleton_after_ast_parsing(tmp_path: Path) -> None:
    source = _tiered_source().replace("class Trailing:", "# ```\u202e\nclass Trailing:")
    (tmp_path / "module.py").write_text(source, encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs()
    prompt = PromptBuilder(tmp_path, 500).build_patch_prompt(spec, baseline, [])
    assert "117: # '''" in prompt
    assert "118: class Trailing:" in prompt
    assert "\u202e" not in prompt
    assert "TRUNCATED" not in prompt


def test_deep_valid_expression_preserves_numbered_source_without_recursion() -> None:
    source = "VALUE = " + "+".join(["1"] * 1100) + "\n"
    ast.parse(source)  # Valid parser output must not require recursive traversal.
    assert ast_slicer.skeletonize_python_source(source) == f"    1: {source.rstrip()}"
    packed = ast_slicer.pack_file_with_skeleton(source, [], 1000)
    assert packed.pruning_tier_used == 4
    assert packed.used_syntax_fallback is False
    assert packed.formatted_content == f"    1: {source.rstrip()}"


def test_prompt_deep_valid_expression_uses_raw_fallback(tmp_path: Path) -> None:
    source = "VALUE = " + "+".join(["1"] * 1100) + "\n"
    (tmp_path / "module.py").write_text(source, encoding="utf-8", newline="\n")
    spec, baseline = _prompt_inputs()
    builder = PromptBuilder(tmp_path, 1000)
    prompt = builder.build_patch_prompt(spec, baseline, [])
    assert prompt == builder.build_patch_prompt(spec, baseline)
    assert "TRUNCATED" in prompt


def test_prompt_distinguishes_hidden_directory_from_similarly_named_directory(
    tmp_path: Path,
) -> None:
    for name in (".config", "config"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "module.py").write_text(
            _tiered_source(), encoding="utf-8", newline="\n",
        )
    spec, baseline = _prompt_inputs((".config/module.py", "config/module.py"))
    prompt = PromptBuilder(tmp_path, 1400).build_patch_prompt(
        spec, baseline, [_slice(1, 12, 0, "./config/module.py")],
    )
    hidden = prompt.split("### File: `.config/module.py`", 1)[1].split("### File:", 1)[0]
    visible = prompt.split("### File: `config/module.py`", 1)[1].split("##", 1)[0]
    assert "fault_value_09" not in hidden
    assert "fault_value_09" in visible
    assert "117: class Trailing:" in hidden
    assert "117: class Trailing:" in visible

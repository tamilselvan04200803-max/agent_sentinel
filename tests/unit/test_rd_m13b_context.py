"""Physical Python lines and opt-in hard token bounds for M13B context."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest

from agentsentinel import localization
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.llm.prompts import PromptBuilder, _add_line_numbers
from agentsentinel.localization.ast_slicer import (
    LocalizationSlice,
    localize_faults,
    pack_file_with_skeleton,
    skeletonize_python_source,
)
from agentsentinel.localization.traceback_parser import TracebackFrame

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029", "\x0b", "\x0c"])
def test_unicode_separators_in_strings_do_not_shift_disk_lines(separator: str) -> None:
    source = f"LABEL = 'left{separator}right'\r\ndef target():\r    return LABEL\n"
    rendered = skeletonize_python_source(source, [(3, 3)])
    assert rendered.split("\n") == [
        f"    1: LABEL = 'left{separator}right'",
        "    2: def target():",
        "    3:     return LABEL",
    ]
    packed = pack_file_with_skeleton(source, [], 1000)
    assert packed.raw_line_count == packed.output_line_count == 3
    assert _add_line_numbers(source).split("\n") == [
        f"1: LABEL = 'left{separator}right'",
        "2: def target():",
        "3:     return LABEL",
    ]


def test_localizer_uses_ast_physical_coordinates_with_string_separators(tmp_path: Path) -> None:
    source = "LABEL = 'left\u2028right'\ndef target():\n    return LABEL\n"
    (tmp_path / "module.py").write_text(source, encoding="utf-8", newline="\n")
    frame = TracebackFrame("module.py", 3, "target", "return LABEL")
    slices = localize_faults(tmp_path, [frame], ["module.py"])
    assert len(slices) == 1
    assert slices[0].numbered_source == "2 | def target():\n3 |     return LABEL"


def _tiered_context() -> tuple[str, list[LocalizationSlice]]:
    lines = ["def fault(", "    value: int,", ") -> int:"]
    lines += [f"    fault_{i} = 'important local value {i}'" for i in range(10)]
    lines += ["    return fault_0", "def helper(", "    value: int,", ") -> int:"]
    lines += [f"    helper_{i} = 'secondary local value {i}'" for i in range(20)]
    lines += ["    return helper_0"]
    return "\n".join(lines), [
        LocalizationSlice("module.py", "fault", 1, 14, 0, ""),
        LocalizationSlice("module.py", "helper", 15, 38, 1, ""),
    ]


def test_token_budget_evicts_hop1_bodies_before_hop0_and_retains_whole_signatures() -> None:
    source, slices = _tiered_context()
    full = localization.pack_file_with_token_budget(source, slices, 10000, count_tokens=len)
    reduced = localization.pack_file_with_token_budget(source, slices, 900, count_tokens=len)
    assert full.pruning_tier_used == 1
    assert "helper_19" in full.formatted_content
    assert reduced.pruning_tier_used == 2
    assert "fault_9" in reduced.formatted_content
    assert "helper_19" not in reduced.formatted_content
    assert "   15: def helper(\n   16:     value: int,\n   17: ) -> int:" in reduced.formatted_content
    assert len(reduced.formatted_content) <= 900
    assert reduced.lost_context


def test_token_budget_is_measured_by_supplied_counter_and_reports_measured_compression() -> None:
    source = "LABEL = '\u2028emoji \U0001f30d'\ndef f():\n    return LABEL"

    def count_bytes(content: str) -> int:
        return len(content.encode("utf-8"))

    result = localization.pack_file_with_token_budget(source, [], 1000, count_tokens=count_bytes)
    raw_numbered = (
        "    1: LABEL = '\u2028emoji \U0001f30d'\n"
        "    2: def f():\n    3:     return LABEL"
    )
    telemetry = result.telemetry
    assert telemetry.input_token_count == count_bytes(raw_numbered)
    assert telemetry.output_token_count == count_bytes(result.formatted_content)
    assert telemetry.token_compression_ratio == pytest.approx(
        1.0 - count_bytes(result.formatted_content) / count_bytes(raw_numbered)
    )
    assert telemetry.line_offset_divergence_delta == 0
    assert result.raw_line_count == result.output_line_count == 3
    assert telemetry.execution_latency_ms >= 0
    assert telemetry.syntax_error_fallback_count == 0
    assert telemetry.syntax_error_fallback_rate == 0
    with pytest.raises(FrozenInstanceError):
        telemetry.execution_latency_ms = 0
    assert not hasattr(telemetry, "patch_apply_success_rate")


@pytest.mark.parametrize("budget", [0, 1, 10, 59])
def test_tiny_token_budget_omits_context_without_cutting_interface_lines(budget: int) -> None:
    source = "def long_signature(\n    required: str,\n) -> str:\n    return required"
    result = localization.pack_file_with_token_budget(source, [], budget, count_tokens=len)
    assert len(result.formatted_content) <= budget
    assert result.pruning_tier_used == 5
    assert result.lost_context
    assert result.omission_reason
    assert result.formatted_content == "" or "all source context omitted" in result.formatted_content
    assert "def long_signature" not in result.formatted_content


def test_interface_only_content_that_exceeds_budget_uses_explicit_omission_marker() -> None:
    result = localization.pack_file_with_token_budget(
        "CONSTANT = '" + "x" * 200 + "'", [], 100, count_tokens=len,
    )
    assert 0 < len(result.formatted_content) <= 100
    assert "all source context omitted" in result.formatted_content
    assert result.lost_context


def test_empty_source_and_zero_token_budget_do_not_report_lost_context() -> None:
    result = localization.pack_file_with_token_budget("", [], 0, count_tokens=len)
    assert result.formatted_content == ""
    assert result.raw_line_count == result.output_line_count == 0
    assert result.lost_context is False
    assert result.telemetry.output_token_count == 0
    assert result.telemetry.token_compression_ratio == 0.0


@pytest.mark.parametrize("source", ["def broken(:\n    invalid", "  bad indent\nEND = 1"])
def test_syntax_fallback_is_raw_when_it_fits_and_honestly_omitted_when_it_does_not(source: str) -> None:
    full = localization.pack_file_with_token_budget(source, [], 1000, count_tokens=len)
    tiny = localization.pack_file_with_token_budget(source, [], 0, count_tokens=len)
    assert source.split("\n")[0] in full.formatted_content
    assert not full.lost_context
    assert full.used_syntax_fallback
    assert full.telemetry.syntax_error_fallback_count == 1
    assert full.telemetry.source_count == 1
    assert full.telemetry.syntax_error_fallback_rate == 1.0
    assert tiny.formatted_content == ""
    assert tiny.lost_context and tiny.used_syntax_fallback


def test_kept_nested_span_survives_and_unselected_sibling_is_folded() -> None:
    source = (
        "def outer():\n    seed = 1\n    def chosen():\n        return seed\n"
        "    def sibling():\n        return 999\n    return chosen()"
    )
    slices = [
        LocalizationSlice("module.py", "chosen", 4, 4, 0, ""),
        LocalizationSlice("module.py", "chosen", 3, 4, 0, ""),
    ]
    result = localization.pack_file_with_token_budget(source, slices, 1000, count_tokens=len)
    assert "4:         return seed" in result.formatted_content
    assert "7:     return chosen()" in result.formatted_content
    assert "return 999" not in result.formatted_content
    assert result.telemetry.line_offset_divergence_delta == 0


def test_token_budget_rejects_negative_budget() -> None:
    with pytest.raises(ValueError, match="nonnegative"):
        localization.pack_file_with_token_budget("x = 1", [], -1, count_tokens=len)


@pytest.mark.parametrize("source", [None, b"x = 1", 123])
def test_token_packer_rejects_non_string_source(source: object) -> None:
    with pytest.raises(TypeError, match="source must be a str"):
        localization.pack_file_with_token_budget(cast("str", source), [], 100, count_tokens=len)


def test_token_packer_rejects_null_bytes() -> None:
    with pytest.raises(ValueError, match="Binary or null-byte"):
        localization.pack_file_with_token_budget("\x00", [], 100, count_tokens=len)


@pytest.mark.parametrize("bad_count", [-1, 0.5, True])
def test_token_packer_rejects_invalid_counter_results(bad_count: object) -> None:
    with pytest.raises((TypeError, ValueError), match="token count"):
        localization.pack_file_with_token_budget("x = 1", [], 100, count_tokens=lambda _: bad_count)


def test_token_counter_must_count_empty_content_as_zero() -> None:
    with pytest.raises(ValueError, match="empty"):
        localization.pack_file_with_token_budget("x = 1", [], 0, count_tokens=lambda _: 1)


def test_line_divergence_is_measured_from_actual_numbered_output(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsentinel.localization import context_packer

    monkeypatch.setattr(context_packer, "skeletonize_python_source", lambda *_, **__: "    9: END = 1")
    result = localization.pack_file_with_token_budget("END = 1", [], 1000, count_tokens=len)
    assert result.telemetry.line_offset_divergence_delta == 8


def test_execution_latency_uses_elapsed_clock_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsentinel.localization import context_packer

    times = iter([100.0, 100.025])
    monkeypatch.setattr(context_packer, "perf_counter", lambda: next(times))
    result = localization.pack_file_with_token_budget("END = 1", [], 1000, count_tokens=len)
    assert result.telemetry.execution_latency_ms == pytest.approx(25.0)


@pytest.mark.parametrize(("budget", "compact", "tier"), [(750, False, 3), (300, True, 4)])
def test_tighter_budgets_compact_then_fold_hop0_before_omitting_interfaces(budget, compact, tier) -> None:
    source, slices = _tiered_context()
    result = localization.pack_file_with_token_budget(
        source, slices, budget, count_tokens=len, compact=compact,
    )
    assert result.pruning_tier_used == tier
    assert len(result.formatted_content) <= budget
    assert "def fault(" in result.formatted_content
    assert "def helper(" in result.formatted_content
    assert ("fault_9" in result.formatted_content) is (tier == 3)


def _build_token_prompt(tmp_path: Path, source: str, budget: int, count_tokens=len) -> str:
    (tmp_path / "module.py").write_text(source, encoding="utf-8", newline="\n")
    spec = CaseSpec(
        "rd-m13b", "https://example.test/repo", "a" * 40, "pytest -q",
        ("module.py",), ("tests/test_module.py::test_fix",),
        created_at=datetime(2026, 10, 27, tzinfo=UTC),
    )
    baseline = ExecutionResult("rd-m13b", "baseline", ExitCode.TESTS_FAILED, "failed", "", 1.0)
    builder = PromptBuilder(tmp_path, max_file_tokens=budget, count_tokens=count_tokens)
    return builder.build_repair_prompt(spec, baseline, [
        LocalizationSlice("module.py", "fault", 1, 1, 0, "1 | SECRET_HINT_BODY"),
    ])


def test_prompt_opt_in_counts_final_sanitized_content_and_avoids_duplicate_hint_bodies(tmp_path: Path) -> None:
    def count_tokens(content: str) -> int:
        return len(content) + content.count("'''") * 100

    prompt = _build_token_prompt(tmp_path, 'VALUE = "```"', 100, count_tokens)
    content = prompt.split("### File: `module.py`", 1)[1].split("```\n", 1)[1].split("\n```", 1)[0]
    assert count_tokens(content) <= 100
    assert "all source context omitted" in content
    assert "SECRET_HINT_BODY" not in prompt
    assert "symbol `fault`" in prompt
    assert "TRUNCATED" not in prompt


@pytest.mark.parametrize("budget", [0, 50])
def test_prompt_opt_in_never_falls_back_to_unbounded_raw_file(tmp_path: Path, budget: int) -> None:
    prompt = _build_token_prompt(tmp_path, "VALUE = '" + "x" * 1000 + "'", budget)
    content = prompt.split("### File: `module.py`", 1)[1].split("```\n", 1)[1].split("\n```", 1)[0]
    assert len(content) <= budget
    assert "xxxxx" not in prompt


def test_prompt_requires_a_counter_and_budget_together(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="together"):
        PromptBuilder(tmp_path, max_file_tokens=1)
    with pytest.raises(ValueError, match="together"):
        PromptBuilder(tmp_path, count_tokens=len)
    with pytest.raises(ValueError, match="nonnegative"):
        PromptBuilder(tmp_path, max_file_tokens=-1, count_tokens=len)

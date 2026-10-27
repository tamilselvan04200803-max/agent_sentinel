"""Opt-in token-bounded context packing without partial source-line truncation."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING

from agentsentinel.localization.ast_slicer import (
    skeletonize_python_source,
    split_python_source_lines,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from agentsentinel.localization.ast_slicer import LocalizationSlice

_OMISSION_MARKER = "# ... [all source context omitted: token budget] ..."
_FOLD_MARKER = re.compile(
    r"\s*# \.\.\. \[lines (\d+)-(\d+) omitted by AST skeletonizer\] \.\.\."
)


@dataclass(frozen=True)
class SkeletonTelemetry:
    """Measured per-source statistics; compression is relative to numbered input.

    The line delta is the largest emitted coordinate mismatch, measured against
    original source lines and fold-marker ranges. Compact line gaps are expected.
    A token compression ratio can be negative when markers enlarge small inputs.
    No patch-application outcome is available at context construction time.
    """

    line_offset_divergence_delta: int
    input_token_count: int
    output_token_count: int
    token_compression_ratio: float
    syntax_error_fallback_count: int
    source_count: int
    execution_latency_ms: float

    @property
    def syntax_error_fallback_rate(self) -> float:
        """Per-call rate; aggregate counts, rather than averaging source rates."""
        return self.syntax_error_fallback_count / max(1, self.source_count)


@dataclass(frozen=True)
class TokenBudgetPackResult:
    """Context with a strict supplied-counter bound and explicit loss metadata."""

    formatted_content: str
    raw_line_count: int
    output_line_count: int
    pruning_tier_used: int
    lost_context: bool
    omission_reason: str | None
    telemetry: SkeletonTelemetry

    @property
    def used_syntax_fallback(self) -> bool:
        return self.telemetry.syntax_error_fallback_count > 0


def _line_offset_divergence(raw_lines: Sequence[str], formatted: str) -> int:
    positions: dict[str, list[int]] = {}
    for number, content in enumerate(raw_lines, 1):
        positions.setdefault(content, []).append(number)
    divergence = 0
    for rendered_line in split_python_source_lines(formatted):
        if rendered_line == _OMISSION_MARKER:
            continue
        prefix, separator, content = rendered_line.partition(": ")
        if not separator or not prefix.strip().isdigit():
            divergence = max(divergence, 1)
            continue
        number = int(prefix)
        if 1 <= number <= len(raw_lines) and raw_lines[number - 1] == content:
            continue
        marker = _FOLD_MARKER.fullmatch(content)
        if marker:
            start, end = int(marker.group(1)), int(marker.group(2))
            difference = abs(number - start) if 1 <= start <= end <= len(raw_lines) else 1
        elif content in positions:
            difference = min(abs(number - original) for original in positions[content])
        else:
            difference = 1
        divergence = max(divergence, difference)
    return divergence


def pack_file_with_token_budget(
    source: str,
    slices: Sequence[LocalizationSlice],
    max_tokens: int,
    *,
    count_tokens: Callable[[str], int],
    compact: bool = True,
) -> TokenBudgetPackResult:
    """Bound the returned context using the caller's deterministic token counter.

    Tiers retain localized bodies, evict hop-1 bodies, compact retained hop-0
    bodies, then retain interfaces only. If interfaces still do not fit, return
    a complete omission marker or an empty string for a smaller budget. No source
    line or signature is truncated. Invalid syntax uses raw numbered context if
    it fits, otherwise complete omission. Source is parsed, never executed.

    The counter must return nonnegative integers, count empty text as zero, and
    correspond to the consumer's tokenizer. The bound covers formatted_content
    only: callers must count wrappers or any later transformations separately.
    The existing character-based packer intentionally retains its legacy API.
    """
    started = perf_counter()
    if not isinstance(source, str):
        raise TypeError("source must be a str")
    if "\x00" in source:
        raise ValueError("Binary or null-byte source is not allowed")
    if max_tokens < 0:
        raise ValueError("max_tokens must be nonnegative")

    def measure(content: str) -> int:
        count = count_tokens(content)
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError("token count must be a nonnegative integer")
        if count < 0:
            raise ValueError("token count must be nonnegative")
        return count

    if measure("") != 0:
        raise ValueError("token counter must count empty content as zero")

    raw_lines = split_python_source_lines(source)
    width = max(5, len(str(len(raw_lines))))
    raw_numbered = "\n".join(
        f"{number:{width}d}: {line}" for number, line in enumerate(raw_lines, 1)
    )
    raw_count = measure(raw_numbered)
    syntax_fallback = False
    try:
        ast.parse(source)
    except (SyntaxError, IndentationError):
        syntax_fallback = True

    all_spans = [(sl.start_line, sl.end_line) for sl in slices if sl.hop_distance in (0, 1)]
    hop0_spans = [(sl.start_line, sl.end_line) for sl in slices if sl.hop_distance == 0]
    tiers: tuple[tuple[int, Sequence[tuple[int, int]], bool], ...] = (
        (1, all_spans, compact),
        (2, hop0_spans, compact),
        (3, hop0_spans, True),
        (4, (), True),
    )
    formatted = ""
    output_count = 0
    tier = 5
    omission_reason: str | None = None
    for candidate_tier, keep_spans, use_compact in tiers:
        candidate = (
            raw_numbered if syntax_fallback else skeletonize_python_source(
                source, keep_spans, compact=use_compact,
            )
        )
        candidate_count = measure(candidate)
        if candidate_count <= max_tokens:
            formatted, output_count, tier = candidate, candidate_count, candidate_tier
            break
        if syntax_fallback:
            break
    else:
        omission_reason = "Complete interfaces exceed the token budget"
    if tier == 5:
        omission_reason = omission_reason or "Raw syntax-fallback context exceeds the token budget"
        marker_count = measure(_OMISSION_MARKER)
        if marker_count <= max_tokens:
            formatted, output_count = _OMISSION_MARKER, marker_count

    divergence = _line_offset_divergence(raw_lines, formatted)
    telemetry = SkeletonTelemetry(
        line_offset_divergence_delta=divergence,
        input_token_count=raw_count,
        output_token_count=output_count,
        token_compression_ratio=1.0 - output_count / raw_count if raw_count else 0.0,
        syntax_error_fallback_count=int(syntax_fallback),
        source_count=1,
        execution_latency_ms=(perf_counter() - started) * 1000.0,
    )
    return TokenBudgetPackResult(
        formatted_content=formatted,
        raw_line_count=len(raw_lines),
        output_line_count=len(split_python_source_lines(formatted)),
        pruning_tier_used=tier,
        lost_context=formatted != raw_numbered,
        omission_reason=omission_reason,
        telemetry=telemetry,
    )

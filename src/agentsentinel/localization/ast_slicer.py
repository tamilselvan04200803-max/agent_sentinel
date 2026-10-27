"""AST slicing for fault localization (Hop-0 and Hop-1)."""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass
from io import StringIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from agentsentinel.localization.traceback_parser import TracebackFrame


@dataclass(frozen=True)
class LocalizationSlice:
    """Snippet of source relevant to a fault frame."""

    file_path: str
    symbol_name: str
    start_line: int
    end_line: int
    hop_distance: int
    numbered_source: str


def _normalize(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def _numbered_source_from_lines(all_lines: list[str], start: int, end: int) -> str:
    # all_lines is 0-indexed list of file lines without trailing \n
    # start/end are 1-indexed inclusive
    out: list[str] = []
    # pad width based on end line number
    width = len(str(end))
    for lineno in range(start, end + 1):
        idx = lineno - 1
        content = all_lines[idx] if 0 <= idx < len(all_lines) else ""
        out.append(f"{lineno:>{width}} | {content}")
    return "\n".join(out)


def _collect_def_nodes(tree: ast.AST) -> list[tuple[str, int, int, ast.AST]]:
    """Return list of (name, start, end, node) for FunctionDef/AsyncFunctionDef/ClassDef."""
    result: list[tuple[str, int, int, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name: str = node.name
            start: int = int(getattr(node, "lineno", 1) or 1)
            end: int = int(getattr(node, "end_lineno", None) or start)
            # If end_lineno is None, approximate via last stmt
            if getattr(node, "end_lineno", None) is None:
                # fallback: use start + len body
                try:
                    # try to find max lineno in descendants
                    max_line = start
                    for child in ast.walk(node):
                        cl = getattr(child, "lineno", None)
                        if isinstance(cl, int) and cl > max_line:
                            el = getattr(child, "end_lineno", cl)
                            max_line = el if isinstance(el, int) and el > max_line else cl
                    end = max_line
                except Exception:
                    end = start
            result.append((name, start, end, node))
    return result


def _find_enclosing(
    defs: list[tuple[str, int, int, ast.AST]], line: int
) -> tuple[str, int, int, ast.AST] | None:
    candidates = [d for d in defs if d[1] <= line <= d[2]]
    if not candidates:
        return None
    # innermost = smallest span
    candidates.sort(key=lambda d: (d[2] - d[1], -d[1]))
    return candidates[0]


def _called_names_in_node(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                # For obj.method() -> add attr
                names.add(func.attr)
    return names


def localize_faults(
    workspace_root: Path,
    frames: Sequence[TracebackFrame],
    allowed_edit_paths: Sequence[str],
    max_slices: int = 5,
) -> list[LocalizationSlice]:
    """Extract fault slices for given frames.

    Hop-0: enclosing FunctionDef/AsyncFunctionDef/ClassDef for each frame.
    Hop-1: intra-repo called symbols in allowed_edit_paths.
    """
    if max_slices <= 0:
        return []

    normalized_allowed: list[str] = [_normalize(p) for p in allowed_edit_paths]
    allowed_set = set(normalized_allowed)

    # Pre-parse all allowed files: path -> (source_lines, tree, defs)
    FileCacheEntry = tuple[list[str], ast.AST, list[tuple[str, int, int, ast.AST]]]
    file_cache: dict[str, FileCacheEntry | None] = {}

    def get_file_data(
        norm_path: str,
    ) -> FileCacheEntry | None:
        if norm_path in file_cache:
            cached = file_cache[norm_path]
            return cached
        abs_path = workspace_root / norm_path
        try:
            text = abs_path.read_text(encoding="utf-8")
        except Exception:
            file_cache[norm_path] = None
            return None
        all_lines = text.splitlines()
        try:
            tree = ast.parse(text, filename=norm_path)
        except SyntaxError:
            file_cache[norm_path] = None
            return None
        defs = _collect_def_nodes(tree)
        data: FileCacheEntry = (all_lines, tree, defs)
        file_cache[norm_path] = data
        return data

    # Eagerly populate cache for all allowed paths (needed for Hop-1 search)
    for p in normalized_allowed:
        get_file_data(p)

    slices: list[LocalizationSlice] = []
    seen: set[tuple[str, str]] = set()

    # Map normalized -> original raw allowed string normalized? Use normalized as file_path
    # Hop-0 phase
    hop0_slices: list[LocalizationSlice] = []
    hop0_called: set[str] = set()
    hop0_nodes: list[tuple[str, ast.AST]] = []

    for frame in frames:
        norm = _normalize(frame.file_path)
        # Only consider frames whose file is in allowed set; skip others
        if norm not in allowed_set:
            continue
        data = get_file_data(norm)
        if data is None:
            continue
        all_lines, _tree, defs = data
        enclosing = _find_enclosing(defs, frame.line_number)
        if enclosing is None:
            continue
        name, start, end, node = enclosing
        key = (norm, name)
        if key in seen:
            continue
        seen.add(key)
        numbered = _numbered_source_from_lines(all_lines, start, end)
        sl = LocalizationSlice(
            file_path=norm,
            symbol_name=name,
            start_line=start,
            end_line=end,
            hop_distance=0,
            numbered_source=numbered,
        )
        hop0_slices.append(sl)
        hop0_nodes.append((norm, node))
        # collect called names for hop-1
        hop0_called.update(_called_names_in_node(node))
        if len(hop0_slices) >= max_slices:
            break

    slices.extend(hop0_slices)
    if len(slices) >= max_slices:
        return slices[:max_slices]

    # Hop-1: for each called name, search in allowed_edit_paths for matching defs
    # Build name -> list of (norm_path, def_name, start, end)
    name_to_defs: dict[str, list[tuple[str, int, int, list[str]]]] = {}
    for norm in normalized_allowed:
        data = get_file_data(norm)
        if data is None:
            continue
        all_lines, _tree, defs = data
        for dname, dstart, dend, _node in defs:
            # store with all_lines reference
            if dname not in name_to_defs:
                name_to_defs[dname] = []
            # avoid duplicate if already added
            name_to_defs[dname].append((norm, dstart, dend, all_lines))

    for called in sorted(hop0_called):
        defs_for_name = name_to_defs.get(called, [])
        for norm2, dstart, dend, all_lines2 in defs_for_name:
            key2 = (norm2, called)
            if key2 in seen:
                continue
            seen.add(key2)
            numbered2 = _numbered_source_from_lines(all_lines2, dstart, dend)
            sl2 = LocalizationSlice(
                file_path=norm2,
                symbol_name=called,
                start_line=dstart,
                end_line=dend,
                hop_distance=1,
                numbered_source=numbered2,
            )
            slices.append(sl2)
            if len(slices) >= max_slices:
                return slices[:max_slices]

    return slices[:max_slices]


def merge_keep_spans(keep_spans: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """Normalize positive, closed disk-line intervals and merge adjacent spans."""
    normalized: list[tuple[int, int]] = []
    for start, end in keep_spans:
        if start < 1 or end < 1:
            raise ValueError("keep span bounds must be positive 1-indexed lines")
        normalized.append((min(start, end), max(start, end)))

    merged: list[tuple[int, int]] = []
    for start, end in sorted(normalized):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _get_function_signature_end(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: Sequence[str],
) -> int:
    """Find the signature colon without tokenizing the following docstring."""
    search_start = node.lineno
    search_end = node.body[0].lineno if node.body else (node.end_lineno or search_start)
    snippet = "\n".join(source_lines[search_start - 1:search_end])
    paren_depth = 0
    try:
        for tok_type, tok_str, (start_row, _), _, _ in tokenize.generate_tokens(
            StringIO(snippet).readline
        ):
            if tok_type != tokenize.OP:
                continue
            if tok_str in ("(", "[", "{"):
                paren_depth += 1
            elif tok_str in (")", "]", "}"):
                paren_depth -= 1
            elif tok_str == ":" and paren_depth == 0:
                return search_start + start_row - 1
    except (tokenize.TokenError, IndentationError):
        return search_start
    return search_start


def skeletonize_python_source(
    source: str,
    keep_spans: Sequence[tuple[int, int]] = (),
    *,
    compact: bool = False,
    line_number_width: int = 5,
) -> str:
    """Fold unselected functions into numbered prompt context, never executing source.

    Default output preserves physical line count. Compact output elides folded
    continuation lines but retains disk coordinates. Syntax errors return raw
    numbered source; non-string and null-byte inputs are hard failures.
    """
    if not isinstance(source, str):
        raise TypeError("source must be a str")
    if "\x00" in source:
        raise ValueError("Binary or null-byte source is not allowed")
    raw_lines = source.splitlines()
    if not raw_lines:
        return ""
    width = max(line_number_width, len(str(len(raw_lines))))
    try:
        tree = ast.parse(source)
    except (SyntaxError, IndentationError):
        return "\n".join(f"{i + 1:{width}d}: {line}" for i, line in enumerate(raw_lines))

    merged_spans = merge_keep_spans(keep_spans)
    folds: list[tuple[int, int, str]] = []

    pending: list[ast.AST] = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_start = min((d.lineno for d in node.decorator_list), default=node.lineno)
            fn_end = node.end_lineno or node.lineno
            if not any(start <= fn_end and end >= fn_start for start, end in merged_spans):
                sig_end = _get_function_signature_end(node, raw_lines)
                doc_keep_line = sig_end
                if node.body:
                    first = node.body[0]
                    if (
                        isinstance(first, ast.Expr)
                        and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)
                    ):
                        doc_keep_line = first.lineno
                fold_start = max(sig_end, doc_keep_line) + 1
                if fold_start <= fn_end:
                    first_folded = raw_lines[fold_start - 1]
                    indent = first_folded[:len(first_folded) - len(first_folded.lstrip())]
                    if not first_folded.strip():
                        header = raw_lines[node.lineno - 1]
                        indent = header[:len(header) - len(header.lstrip())] + "    "
                    folds.append((fold_start, fn_end, indent))
                # An outer fold owns its entire range, including all inner scopes.
                continue
            pending.extend(reversed(node.body))
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    output_lines = raw_lines.copy()
    omitted: set[int] = set()
    for start, end, indent in folds:
        output_lines[start - 1] = (
            f"{indent}# ... [lines {start}-{end} omitted by AST skeletonizer] ..."
        )
        for index in range(start, end):
            output_lines[index] = ""
            if compact:
                omitted.add(index)
    return "\n".join(
        f"{index + 1:{width}d}: {line}"
        for index, line in enumerate(output_lines)
        if index not in omitted
    )


@dataclass(frozen=True)
class SkeletonPackResult:
    """Character-based context compression statistics; tier zero is reserved."""

    formatted_content: str
    raw_line_count: int
    output_line_count: int
    compression_ratio: float
    pruning_tier_used: int
    used_syntax_fallback: bool


def pack_file_with_skeleton(
    source: str,
    slices: Sequence[LocalizationSlice],
    max_chars: int,
    *,
    compact: bool = True,
) -> SkeletonPackResult:
    """Evict hop-1 bodies before hop-0 bodies, then return a pure interface view.

    Tier 4 may exceed the budget when even interfaces cannot fit. The caller
    owns the final truncation fallback. This is a character ceiling, not an
    exact tokenizer count. With compact=True, tiers 2 and 3 are equivalent.
    """
    if max_chars < 0:
        raise ValueError("max_chars must be nonnegative")
    if not isinstance(source, str):
        raise TypeError("source must be a str")
    if "\x00" in source:
        raise ValueError("Binary or null-byte source is not allowed")
    raw_lines = source.splitlines()
    width = max(5, len(str(len(raw_lines))))
    raw_numbered_content = "\n".join(
        f"{index + 1:{width}d}: {line}" for index, line in enumerate(raw_lines)
    )
    used_syntax_fallback = False
    try:
        ast.parse(source)
    except (SyntaxError, IndentationError):
        used_syntax_fallback = True

    all_spans = [(sl.start_line, sl.end_line) for sl in slices if sl.hop_distance in (0, 1)]
    hop0_spans = [(sl.start_line, sl.end_line) for sl in slices if sl.hop_distance == 0]
    tiers: tuple[tuple[int, Sequence[tuple[int, int]], bool], ...] = (
        (1, all_spans, compact),
        (2, hop0_spans, compact),
        (3, hop0_spans, True),
        (4, [], True),
    )
    for tier, keep_spans, use_compact in tiers:
        formatted = skeletonize_python_source(source, keep_spans, compact=use_compact)
        if len(formatted) <= max_chars or tier == 4:
            return SkeletonPackResult(
                formatted_content=formatted,
                raw_line_count=len(raw_lines),
                output_line_count=len(formatted.splitlines()),
                compression_ratio=1.0 - len(formatted) / max(1, len(raw_numbered_content)),
                pruning_tier_used=tier,
                used_syntax_fallback=used_syntax_fallback,
            )
    raise AssertionError("tier 4 must return a skeleton")

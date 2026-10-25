"""AST slicing for fault localization (Hop-0 and Hop-1)."""

from __future__ import annotations

import ast
from dataclasses import dataclass
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

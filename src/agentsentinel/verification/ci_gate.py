"""Public standalone CI audit API: no LLM, container, subprocess or source writes."""

from __future__ import annotations

import ast
import hashlib
import html
import json
import os
import stat
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING

from agentsentinel.verification.ci_gate_analysis import (
    STAGE_PATH,
    CIGateViolation,
    FileAuditMetrics,
    ViolationSeverity,
    analyze_entry,
)
from agentsentinel.verification.ci_source_map import (
    CIGateUsageError,
    FileLifecycleStatus,
    SourceMapEntry,
    contained_path,
    reconstruct_in_memory_source_map,
)
from agentsentinel.verification.clone_detector import (
    CloneAnalysisLimitError,
    CloneBlock,
    detect_type2_clones,
)
from agentsentinel.verification.overfit_guard import extract_test_assertion_literals

if TYPE_CHECKING:
    from collections.abc import Sequence

CI_GATE_PASSED = 0
CI_GATE_FAILED = 1
CI_GATE_USAGE_ERROR = 2

__all__ = [
    "CI_GATE_PASSED",
    "CI_GATE_FAILED",
    "CI_GATE_USAGE_ERROR",
    "CIGateUsageError",
    "FileLifecycleStatus",
    "ViolationSeverity",
    "SourceMapEntry",
    "CIGateViolation",
    "FileAuditMetrics",
    "CIGateReport",
    "reconstruct_in_memory_source_map",
    "run_ci_gate_audit",
    "render_ci_gate_json",
    "render_ci_gate_markdown",
]


@dataclass(frozen=True)
class CIGateReport:
    status: str
    exit_code: int
    execution_time_ms: float
    total_violations: int
    summary: dict[str, int]
    violations: tuple[CIGateViolation, ...]
    file_metrics: tuple[FileAuditMetrics, ...]
    diff_sha256: str
    gatekeeper_version: str = "15.0.0"


def usage_error_report(message: str, raw_diff: str = "") -> CIGateReport:
    raw_diff = raw_diff if isinstance(raw_diff, str) else ""
    violation = CIGateViolation(
        "",
        1,
        STAGE_PATH,
        "DIFF-001",
        "ERROR",
        message,
        "Provide a valid text diff and its pristine base workspace",
    )
    return CIGateReport(
        "USAGE_ERROR",
        2,
        0.0,
        1,
        {"error_count": 1, "warning_count": 0},
        (violation,),
        (),
        hashlib.sha256(raw_diff.encode("utf-8", errors="replace")).hexdigest(),
    )


def _test_paths(root: Path) -> tuple[Path, ...]:
    excluded = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "__pycache__",
        ".pytest_cache",
        ".pytest_tmp",
    }
    paths: list[Path] = []
    for directory, names, files in os.walk(root, followlinks=False):
        safe_names: list[str] = []
        for name in sorted(names):
            if name in excluded:
                continue
            child = Path(directory) / name
            contained_path(child.relative_to(root).as_posix(), root)
            if (
                not child.is_symlink()
                and not getattr(child.lstat(), "st_file_attributes", 0) & 0x400
            ):
                safe_names.append(name)
        names[:] = safe_names
        for name in sorted(files):
            if (name.startswith("test_") or name.endswith("_test.py")) and name.endswith(".py"):
                path = Path(directory) / name
                contained_path(path.relative_to(root).as_posix(), root)
                paths.append(path)
    return tuple(paths)


_CLONE_EXCLUDED = frozenset({
    ".git", ".venv", "venv", "env", ".env", "node_modules", ".tox", ".nox",
    ".mypy_cache", ".ruff_cache", "__pycache__", ".pytest_cache", ".pytest_tmp",
})
_CLONE_MAX_BYTES = 2_000_000
_CLONE_MAX_ENTRIES = 10_000
_CLONE_MAX_FILES = 512


def _clone_sources(root: Path, entries: tuple[SourceMapEntry, ...]) -> dict[str, str]:
    """Bound contained regular-file reads; prioritize the reconstructed postimages."""
    sources: dict[str, str] = {}
    replaced = {
        os.path.normcase(str(root / path))
        for entry in entries for path in (entry.old_path, entry.file_path) if path is not None
    }
    remaining = _CLONE_MAX_BYTES
    for entry in sorted(entries, key=lambda item: item.file_path):
        path = Path(entry.file_path)
        if (entry.status is FileLifecycleStatus.DELETED or path.suffix.casefold() != ".py"
                or any(part.casefold() in _CLONE_EXCLUDED for part in path.parts)):
            continue
        if any((parent / "pyvenv.cfg").is_file() for parent in (root / path).parents
               if parent.is_relative_to(root)):
            continue
        if len(entry.post_buffer) > remaining:
            raise CloneAnalysisLimitError("source_bytes", _CLONE_MAX_BYTES)
        size = len(entry.post_buffer.encode("utf-8"))
        if size > remaining:
            raise CloneAnalysisLimitError("source_bytes", _CLONE_MAX_BYTES)
        if len(sources) >= _CLONE_MAX_FILES:
            raise CloneAnalysisLimitError("files", _CLONE_MAX_FILES)
        sources[entry.file_path] = entry.post_buffer
        remaining -= size
    pending = [root]
    seen_entries = 0
    while pending:
        directory = pending.pop()
        children: list[Path] = []
        try:
            with os.scandir(directory) as listing:
                for item in listing:
                    seen_entries += 1
                    if seen_entries > _CLONE_MAX_ENTRIES:
                        raise CloneAnalysisLimitError("inventory_entries", _CLONE_MAX_ENTRIES)
                    children.append(Path(item.path))
            if any(child.name.casefold() == "pyvenv.cfg" for child in children):
                continue
            directories: list[Path] = []
            for path in sorted(children):
                if path.name.casefold() in _CLONE_EXCLUDED:
                    continue
                try:
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        continue
                    relative = contained_path(path.relative_to(root).as_posix(), root)
                    if stat.S_ISDIR(info.st_mode):
                        directories.append(path)
                        continue
                    if (not stat.S_ISREG(info.st_mode) or path.suffix.casefold() != ".py"
                            or os.path.normcase(str(path)) in replaced):
                        continue
                    if info.st_size > remaining:
                        raise CloneAnalysisLimitError("source_bytes", _CLONE_MAX_BYTES)
                    if len(sources) >= _CLONE_MAX_FILES:
                        raise CloneAnalysisLimitError("files", _CLONE_MAX_FILES)
                    with path.open("rb") as source_file:
                        raw = source_file.read(remaining + 1)
                    if len(raw) > remaining:
                        raise CloneAnalysisLimitError("source_bytes", _CLONE_MAX_BYTES)
                    sources[relative] = raw.decode("utf-8")
                    remaining -= len(raw)
                except (OSError, UnicodeError, CIGateUsageError):
                    continue
            pending.extend(reversed(directories))
        except OSError:
            continue
    return sources


def _statement_shape(tree: ast.Module, start: int, end: int, column: int) -> tuple[str, ...]:
    statements: list[str] = []
    pending: list[ast.AST] = list(reversed(tree.body))
    while pending:
        node = pending.pop()
        if isinstance(node, ast.stmt) and (
            start <= node.lineno and (node.end_lineno or node.lineno) <= end
            and node.col_offset == column
        ):
            statements.append(ast.dump(node, include_attributes=False))
        else:
            pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return tuple(statements)


def _clone_block_changed(
    block: CloneBlock, entry: SourceMapEntry, before: ast.Module, after: ast.Module,
) -> bool:
    # Infer the preimage region from surviving surrounding lines, including deletions.
    inverse = {post: pre for pre, post in entry.line_map.items()}
    preceding = max((line for line in inverse if line < block.start_line), default=0)
    following = min((line for line in inverse if line > block.end_line), default=0)
    pre_start = inverse.get(block.start_line, inverse[preceding] + 1 if preceding else 1)
    pre_end = inverse.get(block.end_line, inverse[following] - 1 if following
                          else len(entry.pre_buffer.splitlines()))
    owner = _clone_function_owner(block, after)
    columns = [node.col_offset for node in ast.walk(after) if isinstance(node, ast.stmt)
               and node.lineno == block.start_line
               and (node.end_lineno or node.lineno) <= block.end_line
               and not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.lineno == owner)]
    if not columns:
        return False
    column = min(columns)
    return _statement_shape(before, pre_start, pre_end, column) != _statement_shape(
        after, block.start_line, block.end_line, column,
    )


def _clone_function_owner(block: CloneBlock, tree: ast.Module) -> int | None:
    pending: list[tuple[ast.AST, tuple[str, ...]]] = [(tree, ())]
    while pending:
        node, names = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = (*names, node.name)
            if (not isinstance(node, ast.ClassDef) and ".".join(names) == block.function_name
                    and node.lineno <= block.start_line
                    and block.end_line <= (node.end_lineno or node.lineno)):
                return node.lineno
        pending.extend((child, names) for child in ast.iter_child_nodes(node))
    return None


def _clone_violations(root: Path, entries: tuple[SourceMapEntry, ...]) -> list[CIGateViolation]:
    """Warn across distinct function occurrences, preserving legacy M15 warning budgets.

    Standalone clone detection also covers disjoint intra-function blocks. The CI
    advisory conservatively suppresses those repeated control-flow templates.
    """
    try:
        sources = _clone_sources(root, entries)
        findings = detect_type2_clones(sources)
    except CloneAnalysisLimitError as exc:
        return [CIGateViolation(
            "", 1, "Stage 6: Type-2 Clone Analysis", "CLONE-002", "WARNING",
            f"Clone analysis incomplete: {exc.limit_name} limit ({exc.limit}) exceeded",
            "Review clones manually or rerun standalone analysis with explicit larger bounds",
        )]
    changed = {entry.file_path: entry for entry in entries}
    parsed: dict[str, tuple[ast.Module, ast.Module]] = {}
    warnings: dict[CloneBlock, CIGateViolation] = {}
    for finding in findings:
        for block, counterpart in ((finding.original, finding.duplicate),
                                   (finding.duplicate, finding.original)):
            entry = changed.get(block.file_path)
            if entry is None or block in warnings:
                continue
            try:
                if entry.file_path not in parsed:
                    parsed[entry.file_path] = (ast.parse(entry.pre_buffer),
                                               ast.parse(entry.post_buffer))
                before, after = parsed[entry.file_path]
                if block.file_path == counterpart.file_path:
                    owner = _clone_function_owner(block, after)
                    if owner is not None and owner == _clone_function_owner(counterpart, after):
                        continue
                if not _clone_block_changed(block, entry, before, after):
                    continue
            except (SyntaxError, ValueError, RecursionError):
                continue
            warnings[block] = CIGateViolation(
                block.file_path, block.start_line, "Stage 6: Type-2 Clone Analysis", "CLONE-001",
                "WARNING", f"Function {block.function_name} contains an alpha-clone of "
                f"{counterpart.file_path}:{counterpart.start_line}-{counterpart.end_line} "
                f"({block.statement_count} statements, {block.node_count} AST nodes)",
                "Review whether the copied region should share an implementation; "
                "static similarity does not establish equivalent behavior",
            )
    return list(warnings.values())


def run_ci_gate_audit(
    raw_diff: str,
    workspace_root: Path,
    *,
    allowed_edit_paths: Sequence[str] | None = None,
    allow_test_edits: bool = False,
    max_cc_delta: int = 10,
    strict_warnings: bool = False,
    allow_numeric_module_constants: bool = True,
) -> CIGateReport:
    started = perf_counter()
    try:
        if max_cc_delta < 0:
            raise CIGateUsageError("max_cc_delta must be nonnegative")
        entries = reconstruct_in_memory_source_map(raw_diff, workspace_root)
        root = workspace_root.resolve()
        if allowed_edit_paths is not None:
            allowed_edit_paths = tuple(contained_path(path, root) for path in allowed_edit_paths)
        try:
            literals = extract_test_assertion_literals(
                root, test_paths=_test_paths(root), strict=True,
            )
        except (ValueError, OSError, UnicodeError) as exc:
            raise CIGateUsageError("Repository test source cannot be analyzed safely") from exc
        violations: list[CIGateViolation] = []
        metrics: list[FileAuditMetrics] = []
        for entry in entries:
            findings, file_metrics = analyze_entry(
                entry,
                literals,
                allowed_edit_paths=allowed_edit_paths,
                allow_test_edits=allow_test_edits,
                max_cc_delta=max_cc_delta,
                allow_numeric_module_constants=allow_numeric_module_constants,
            )
            violations.extend(findings)
            metrics.append(file_metrics)
        violations.extend(_clone_violations(root, entries))
    except (CIGateUsageError, OSError, UnicodeError, RecursionError) as exc:
        return usage_error_report(
            str(exc)
            if isinstance(exc, CIGateUsageError)
            else "Workspace source cannot be analyzed safely",
            raw_diff,
        )
    ordered = tuple(
        sorted(
            set(violations),
            key=lambda item: (
                item.file_path,
                item.line_number,
                item.stage,
                item.rule_id,
                item.message,
            ),
        )
    )
    errors = sum(item.severity == "ERROR" for item in ordered)
    warnings = sum(item.severity == "WARNING" for item in ordered)
    failed = errors > 0 or (strict_warnings and warnings > 0)
    return CIGateReport(
        "FAILED" if failed else "PASSED",
        1 if failed else 0,
        (perf_counter() - started) * 1000,
        len(ordered),
        {"error_count": errors, "warning_count": warnings},
        ordered,
        tuple(sorted(metrics, key=lambda item: item.file_path)),
        hashlib.sha256(raw_diff.replace("\r\n", "\n").encode("utf-8")).hexdigest(),
    )


def render_ci_gate_json(report: CIGateReport) -> str:
    return json.dumps(asdict(report), ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)


def _markdown(value: str) -> str:
    cleaned = "".join(char for char in value if unicodedata.category(char) not in {"Cc", "Cf"})
    return html.escape(cleaned).replace("|", "\\|").replace("`", "\\`")


def render_ci_gate_markdown(report: CIGateReport) -> str:
    verdict = "❌ FAILED" if report.exit_code else "✅ PASSED"
    lines = [
        "## 🛡️ AgentSentinel CI Gatekeeper Summary",
        "",
        f"**Status:** {verdict} | **Execution Time:** {report.execution_time_ms:.2f}ms "
        f"| **Total Violations:** {report.total_violations}",
        "",
        "| File Path | Stage | CC Delta (Pre -> Post) | API Contract Status | Action Item |",
        "|---|---|---|---|---|",
    ]
    metrics = {item.file_path: item for item in report.file_metrics}
    for item in report.violations:
        metric = metrics.get(item.file_path, FileAuditMetrics(item.file_path, 0, 0, 0, "Intact"))
        delta = f"{metric.cc_delta:+d} ({metric.cc_pre} -> {metric.cc_post})"
        action = (
            f"{item.rule_id} ({item.severity}), line {item.line_number}: "
            f"{item.message}. {item.remediation_advice}"
        )
        lines.append(
            "| "
            + " | ".join(
                _markdown(value)
                for value in (item.file_path, item.stage, delta, metric.api_contract_status, action)
            )
            + " |"
        )
    if not report.violations:
        for metric in report.file_metrics:
            lines.append(
                f"| {_markdown(metric.file_path)} | All stages | {metric.cc_delta:+d} "
                f"({metric.cc_pre} -> {metric.cc_post}) | {metric.api_contract_status} "
                "| No action required |"
            )
    return "\n".join(lines) + "\n"

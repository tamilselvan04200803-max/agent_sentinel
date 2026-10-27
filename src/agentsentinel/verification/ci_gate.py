"""Public standalone CI audit API: no LLM, container, subprocess or source writes."""

from __future__ import annotations

import hashlib
import html
import json
import os
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

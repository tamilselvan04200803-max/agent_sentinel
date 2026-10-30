"""Mechanical repository hygiene; only parse source, never import it."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "agentsentinel"
_ALLOWED_ROOTS = sys.stdlib_module_names | {"agentsentinel", "pydantic", "__future__"}
_LEGACY_NODES = {"Str", "Bytes", "Num", "NameConstant", "Ellipsis"}


def _source_trees() -> Iterator[tuple[Path, ast.Module]]:
    paths = sorted(_SOURCE_ROOT.rglob("*.py"))
    assert paths, f"No source files under {_SOURCE_ROOT}"
    for path in paths:
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _unapproved_imports(tree: ast.Module) -> list[tuple[int, str]]:
    issues: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        issues.extend((node.lineno, name) for name in names if name not in _ALLOWED_ROOTS)
    return issues


def _legacy_ast_references(tree: ast.Module) -> list[tuple[int, str]]:
    aliases = {"ast"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(alias.asname or alias.name for alias in node.names if alias.name == "ast")
    issues: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in aliases and node.attr in _LEGACY_NODES:
                issues.append((node.lineno, node.attr))
        elif isinstance(node, ast.ImportFrom) and node.module == "ast":
            issues.extend((node.lineno, alias.name) for alias in node.names if alias.name in _LEGACY_NODES)
    return issues


def _unsafe_process_or_handlers(tree: ast.Module) -> list[tuple[int, str]]:
    issues: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            issues.append((node.lineno, "shell=True"))
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append((node.lineno, "bare except"))
    return issues


def test_no_slopsquatting_or_unapproved_imports() -> None:
    issues = [(str(path), line, name) for path, tree in _source_trees()
              for line, name in _unapproved_imports(tree)]
    assert not issues, issues


def test_no_removed_python312_ast_nodes_referenced() -> None:
    issues = [(str(path), line, name) for path, tree in _source_trees()
              for line, name in _legacy_ast_references(tree)]
    assert not issues, issues


def test_no_shell_true_or_bare_except_pass_in_src() -> None:
    issues = [(str(path), line, name) for path, tree in _source_trees()
              for line, name in _unsafe_process_or_handlers(tree)]
    assert not issues, issues


def test_guard_detectors_report_real_violations_and_allow_modern_ast() -> None:
    assert _unapproved_imports(ast.parse("import imaginary_dependency")) == [(1, "imaginary_dependency")]
    assert _legacy_ast_references(ast.parse("import ast as syntax\nsyntax.Str")) == [(2, "Str")]
    assert _legacy_ast_references(ast.parse("from ast import Num as Number")) == [(1, "Num")]
    assert _legacy_ast_references(ast.parse("import ast\nast.Constant")) == []
    assert _unsafe_process_or_handlers(ast.parse("run(shell=True)")) == [(1, "shell=True")]
    assert _unsafe_process_or_handlers(ast.parse("try:\n    work()\nexcept:\n    pass")) == [(3, "bare except")]
    assert _unsafe_process_or_handlers(ast.parse("run(shell=False)")) == []

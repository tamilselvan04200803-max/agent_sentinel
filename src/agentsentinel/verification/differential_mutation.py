"""Bounded, deterministic first-order mutants of changed Python functions.

This module generates source artifacts only. It neither runs mutants nor
claims that the generated artifacts establish test adequacy.
"""

from __future__ import annotations

import ast
import copy
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

_Function = ast.FunctionDef | ast.AsyncFunctionDef
_Path = tuple[tuple[str, int | None], ...]
_COMPARISONS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
    ast.Lt: ast.GtE, ast.GtE: ast.Lt,
    ast.LtE: ast.Gt, ast.Gt: ast.LtE,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
}
_ARITHMETIC: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub, ast.Sub: ast.Add,
    ast.Mult: ast.FloorDiv, ast.FloorDiv: ast.Mult,
}


@dataclass(frozen=True)
class DifferentialPatchMutant:
    """A single structural mutation with its owning function's identity."""

    file_path: str
    function_name: str
    mutation_description: str
    mutated_source: str


@dataclass(frozen=True)
class _FunctionEntry:
    identity: tuple[tuple[str, int], ...]
    path: _Path
    node: _Function


def _children(node: ast.AST, path: _Path) -> Iterator[tuple[ast.AST, _Path]]:
    for name, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            yield value, (*path, (name, None))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, ast.AST):
                    yield item, (*path, (name, index))


def _functions(tree: ast.Module) -> list[_FunctionEntry]:
    entries: list[_FunctionEntry] = []
    counts: Counter[tuple[tuple[tuple[str, int], ...], str]] = Counter()

    def visit(node: ast.AST, path: _Path, scope: tuple[tuple[str, int], ...]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            key = (scope, node.name)
            occurrence = counts[key]
            counts[key] += 1
            scope = (*scope, (node.name, occurrence))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                entries.append(_FunctionEntry(scope, path, node))
        for child, child_path in _children(node, path):
            visit(child, child_path, scope)

    visit(tree, (), ())
    return entries


class _OwnScope(ast.NodeTransformer):
    """Retain nested declarations, excluding their separately owned bodies."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.body = []
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.body = []
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.body = []
        return node


def _own_dump(node: _Function) -> str:
    cloned = copy.deepcopy(node)
    normalizer = _OwnScope()
    cloned.body = [normalizer.visit(statement) for statement in cloned.body]
    return ast.dump(cloned, include_attributes=False)


def _body_nodes(entry: _FunctionEntry) -> Iterator[tuple[ast.AST, _Path]]:
    def visit(node: ast.AST, path: _Path) -> Iterator[tuple[ast.AST, _Path]]:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        yield node, path
        for child, child_path in _children(node, path):
            yield from visit(child, child_path)

    for index, statement in enumerate(entry.node.body):
        yield from visit(statement, (*entry.path, ("body", index)))


@dataclass(frozen=True)
class _Site:
    path: _Path
    line: int
    column: int
    rule: int
    index: int
    replacement: type[ast.AST] | None
    function_name: str


def _sites(entry: _FunctionEntry) -> Iterator[_Site]:
    name = ".".join(part for part, _ in entry.identity)
    for node, path in _body_nodes(entry):
        position = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if isinstance(node, ast.Compare):
            for index, operator in enumerate(node.ops):
                flipped = _COMPARISONS.get(type(operator))
                if flipped is not None:
                    yield _Site((*path, ("ops", index)), *position, 0, index, flipped, name)
        elif isinstance(node, ast.BinOp):
            arithmetic = _ARITHMETIC.get(type(node.op))
            if arithmetic is not None:
                yield _Site((*path, ("op", None)), *position, 1, 0, arithmetic, name)
        elif isinstance(node, ast.BoolOp):
            boolean = ast.Or if isinstance(node.op, ast.And) else ast.And
            yield _Site((*path, ("op", None)), *position, 1, 0, boolean, name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            yield _Site(path, *position, 2, 0, None, name)
        elif (
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Call)
        ):
            yield _Site((*path, ("value", None)), *position, 2, 0, None, name)


def _at_path(tree: ast.AST, path: _Path) -> ast.AST:
    node = tree
    for field_name, index in path:
        value = getattr(node, field_name)
        if index is not None:
            value = value[index]
        if not isinstance(value, ast.AST):
            raise ValueError("Mutation path does not reference an AST node")
        node = value
    return node


def _apply_site(tree: ast.Module, site: _Site) -> None:
    target = _at_path(tree, site.path)
    replacement: ast.AST
    if site.replacement is not None:
        replacement = site.replacement()
    elif isinstance(target, ast.Constant) and isinstance(target.value, bool):
        replacement = ast.Constant(value=not target.value)
    elif isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute):
        replacement = target.func.value
    else:
        raise ValueError("Unsupported mutation target")
    parent = _at_path(tree, site.path[:-1])
    field_name, index = site.path[-1]
    if index is None:
        setattr(parent, field_name, replacement)
    else:
        getattr(parent, field_name)[index] = replacement


def generate_differential_patch_mutants(
    file_path: str,
    pre_source: str,
    post_source: str,
    max_mutants: int = 3,
) -> list[DifferentialPatchMutant]:
    """Generate at most ``max_mutants`` unique mutants in deterministic order.

    Invalid source raises ``SyntaxError``; negative budgets raise ``ValueError``.
    Parsing/compilation validates syntax without executing inspected source.
    """
    if max_mutants < 0:
        raise ValueError("max_mutants must be non-negative")
    pre_tree = ast.parse(pre_source, filename=file_path)
    post_tree = ast.parse(post_source, filename=file_path)
    if max_mutants == 0:
        return []
    before = {entry.identity: _own_dump(entry.node) for entry in _functions(pre_tree)}
    sites = [
        site
        for entry in _functions(post_tree)
        if before.get(entry.identity) != _own_dump(entry.node)
        for site in _sites(entry)
    ]
    sites.sort(key=lambda site: (site.line, site.column, site.rule, site.index))
    seen = {ast.dump(post_tree, include_attributes=False)}
    results: list[DifferentialPatchMutant] = []
    for site in sites:
        cloned = copy.deepcopy(post_tree)
        _apply_site(cloned, site)
        ast.fix_missing_locations(cloned)
        source = ast.unparse(cloned) + "\n"
        parsed = ast.parse(source, filename=file_path)
        compile(parsed, file_path, "exec")
        fingerprint = ast.dump(parsed, include_attributes=False)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        results.append(DifferentialPatchMutant(
            file_path, site.function_name,
            f"rule={site.rule + 1} at {site.line}:{site.column}, operator={site.index}", source,
        ))
        if len(results) == max_mutants:
            break
    return results

"""Bounded static call neighborhoods and changed-statement locations.

Only uniquely resolved lexical/direct calls create edges. Undirected hops include
callers and callees; callbacks, dispatch and missing source remain unknown.
"""
from __future__ import annotations

import ast
from collections import Counter, deque
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from agentsentinel.domain.models import CausalTraceReport, FunctionCausalEvidence
from agentsentinel.verification.ci_source_map import reconstruct_in_memory_source_map
from agentsentinel.verification.differential_mutation import _functions, _own_dump

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from agentsentinel.localization.traceback_parser import TracebackFrame
    from agentsentinel.verification.differential_mutation import _FunctionEntry

MAX_SOURCE_BYTES = 2_000_000
MAX_AST_NODES = 100_000
_Identity = tuple[tuple[str, int], ...]
_Key = tuple[str, _Identity]


def _module(path: str) -> str:
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _parse(
    sources: Mapping[str, str],
) -> tuple[dict[str, ast.Module], dict[_Key, _FunctionEntry]]:
    if sum(len(source.encode("utf-8")) for source in sources.values()) > MAX_SOURCE_BYTES:
        raise ValueError("Causal source budget exceeded")
    trees: dict[str, ast.Module] = {}
    functions: dict[_Key, _FunctionEntry] = {}
    count = 0
    for path, source in sorted(sources.items()):
        tree = ast.parse(source, filename=path)
        count += sum(1 for _ in ast.walk(tree))
        if count > MAX_AST_NODES:
            raise ValueError("Causal AST budget exceeded")
        trees[path] = tree
        for entry in _functions(tree):
            functions[path, entry.identity] = entry
    return trees, functions


def _aliases(path: str, tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                package = _module(path).split(".")
                if not path.endswith("/__init__.py"):
                    package.pop()
                package = package[:len(package) - node.level + 1]
                module = ".".join((*package, module)).strip(".")
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
    return aliases



def _scope_nodes(body: Sequence[ast.stmt]) -> list[ast.AST]:
    """Visit one executing scope, including nested definition headers only."""
    result: list[ast.AST] = []
    pending: list[ast.AST] = list(reversed(body))
    while pending:
        node = pending.pop()
        result.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            for field, value in ast.iter_fields(node):
                if field == "body":
                    continue
                if isinstance(value, ast.AST):
                    pending.append(value)
                elif isinstance(value, list):
                    pending.extend(child for child in value if isinstance(child, ast.AST))
        else:
            pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return result


def _import_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    return [alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import)
                            else alias.name) for alias in node.names]


def _unknown_names(nodes: Sequence[ast.AST], *, local_scope: bool = True) -> set[str]:
    """Bindings which cannot safely identify a declared function."""
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(_import_names(node))
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
        elif local_scope and isinstance(node, ast.ClassDef):
            names.add(node.name)
    return names


def _parameters(entry: _FunctionEntry) -> set[str]:
    args = entry.node.args
    names = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    names.update(arg.arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return names


def _target(
    expression: ast.expr, key: _Key, entry: _FunctionEntry,
    functions: dict[_Key, _FunctionEntry], aliases: dict[str, str], shadowed: set[str],
    receiver_rebound: set[str],
) -> list[_Key]:
    path, identity = key
    if "*" in shadowed:
        return []
    if isinstance(expression, ast.Name):
        name = expression.id
        if name in shadowed:
            return []
        for depth in range(len(identity), -1, -1):
            parent = identity[:depth]
            if parent and (path, parent) not in functions:
                continue  # A class namespace is not a method's lexical scope.
            matches = [other for other in functions
                       if other[0] == path and other[1][:-1] == parent
                       and other[1][-1][0] == name]
            if matches:
                return matches
        qualified = aliases.get(name, "")
    elif isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        name = expression.value.id
        parent = identity[:-1]
        positional = [*entry.node.args.posonlyargs, *entry.node.args.args]
        static = any(
            (isinstance(node, ast.Name)
             and aliases.get(node.id, node.id).split(".")[-1] == "staticmethod")
            or (isinstance(node, ast.Attribute) and node.attr == "staticmethod")
            for node in entry.node.decorator_list
        )
        if (name in {"self", "cls"} and positional and positional[0].arg == name
                and parent and (path, parent) not in functions
                and name not in receiver_rebound and not static):
            return [other for other in functions if other[0] == path
                    and other[1][:-1] == parent and other[1][-1][0] == expression.attr]
        if name in shadowed:
            return []
        qualified = f"{aliases.get(name, _module(path) + '.' + name)}.{expression.attr}"
    else:
        return []
    return [other for other in functions
            if f"{_module(other[0])}." + ".".join(name for name, _ in other[1]) == qualified]


def _graph(
    trees: dict[str, ast.Module], functions: dict[_Key, _FunctionEntry],
) -> tuple[dict[_Key, set[_Key]], set[tuple[_Key, int, int, str]]]:
    graph: dict[_Key, set[_Key]] = {key: set() for key in functions}
    unresolved: set[tuple[_Key, int, int, str]] = set()
    aliases_by_path = {path: _aliases(path, tree) for path, tree in trees.items()}
    module_unknown: dict[str, set[str]] = {}
    for path, tree in trees.items():
        nodes = _scope_nodes(tree.body)
        unknown = _unknown_names(nodes, local_scope=False)
        imports = Counter(name for node in nodes if isinstance(node, (ast.Import, ast.ImportFrom))
                          for name in _import_names(node))
        definitions = Counter(node.name for node in nodes
                              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                   ast.ClassDef)))
        assigned = _unknown_names(
            [node for node in nodes if not isinstance(node, (ast.Import, ast.ImportFrom))],
            local_scope=False,
        )
        for name in aliases_by_path[path]:
            if imports[name] == 1 and not definitions[name] and name not in assigned:
                unknown.discard(name)
        unknown.update(name for name, count in definitions.items() if count > 1)
        module_unknown[path] = unknown
    own_nodes = {key: _scope_nodes(entry.node.body) for key, entry in functions.items()}
    own_unknown = {key: _unknown_names(nodes) for key, nodes in own_nodes.items()}
    for key, entry in functions.items():
        nodes = own_nodes[key]
        shadowed = module_unknown[key[0]] | own_unknown[key] | _parameters(entry)
        for depth in range(1, len(key[1])):
            ancestor = (key[0], key[1][:depth])
            if ancestor in functions:
                shadowed.update(own_unknown[ancestor] | _parameters(functions[ancestor]))
        receiver_rebound = own_unknown[key] | {
            node.name for node in nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        aliases = aliases_by_path[key[0]]
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            targets = _target(
                node.func, key, entry, functions, aliases, shadowed, receiver_rebound,
            )
            if len(targets) == 1:
                target = targets[0]
                graph[key].add(target)
                graph[target].add(key)
            else:
                unresolved.add((key, node.lineno, node.col_offset, ast.dump(node.func)))
    return graph, unresolved


def analyze_causal_trace(
    pre_sources: Mapping[str, str], post_sources: Mapping[str, str],
    frames: Sequence[TracebackFrame], *, max_hops: int = 2,
) -> CausalTraceReport:
    """Compare own function structures and report static Hop-0/1/2 evidence."""
    if not 0 <= max_hops <= 2:
        raise ValueError("max_hops must be between zero and two")
    before_trees, before = _parse(pre_sources)
    after_trees, after = _parse(post_sources)
    graph, unresolved = _graph(before_trees, before)
    new_graph, new_unresolved = _graph(after_trees, after)
    for key, neighbors in new_graph.items():
        graph.setdefault(key, set()).update(neighbors)
    unresolved.update(new_unresolved)
    roots: set[_Key] = set()
    for frame in frames:
        path = frame.file_path.replace("\\", "/").removeprefix("/workspace/").removeprefix("./")
        candidates = [(key, entry) for key, entry in before.items()
                      if key[0] == path and entry.node.lineno <= frame.line_number
                      <= (entry.node.end_lineno or entry.node.lineno)]
        if candidates:
            depth = max(len(key[1]) for key, _ in candidates)
            roots.update(key for key, _ in candidates if len(key[1]) == depth)
    distance = dict.fromkeys(roots, 0)
    pending = deque(sorted(roots))
    while pending:
        key = pending.popleft()
        if distance[key] >= max_hops:
            continue
        for neighbor in sorted(graph.get(key, ())):
            if neighbor not in distance:
                distance[neighbor] = distance[key] + 1
                pending.append(neighbor)
    changed = [key for key in before.keys() | after.keys()
               if key not in before or key not in after
               or _own_dump(before[key].node) != _own_dump(after[key].node)]
    rows = []
    ordered = sorted(changed, key=lambda key: (key[0], (after.get(key) or before[key]).node.lineno))
    for key in ordered:
        entry = after.get(key) or before[key]
        rows.append(FunctionCausalEvidence(
            key[0], ".".join(name for name, _ in key[1]), key[1][-1][1],
            entry.node.lineno, distance.get(key),
        ))
    return CausalTraceReport(tuple(rows), len(unresolved), bool(roots))


def collect_added_statement_lines(
    raw_diff: str, baseline_workspace: Path,
) -> tuple[tuple[str, int], ...]:
    """Locate statement starts whose spans overlap added post-patch physical lines."""
    entries = reconstruct_in_memory_source_map(raw_diff, baseline_workspace)
    sources = {entry.file_path: entry.post_buffer for entry in entries
               if entry.file_path.endswith(".py")}
    trees, _ = _parse(sources)
    result: set[tuple[str, int]] = set()
    for entry in entries:
        if entry.file_path not in trees:
            continue
        added = {line for line, _ in entry.added_lines}
        for node in ast.walk(trees[entry.file_path]):
            if isinstance(node, ast.stmt) and not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ) and any(node.lineno <= line <= (node.end_lineno or node.lineno) for line in added):
                result.add((entry.file_path, node.lineno))
    return tuple(sorted(result))

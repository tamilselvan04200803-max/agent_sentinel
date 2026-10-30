"""Bounded parser-only type-2 clone evidence; never a semantic-equivalence claim.

Candidates are contiguous statement regions in function suites. Parameters and local
bindings are alpha-renamed with Python's symbol tables; strings use _STR_ and
numeric literals use _NUM_ (booleans remain distinct). Globals, attribute/keyword
names and operator kinds remain exact.
Invalid syntax and unsupported annotation/type-alias scopes are skipped. Results are
advisory and deliberately incomplete beyond the configured parser and work caps.
"""

from __future__ import annotations

import ast
import symtable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


@dataclass(frozen=True)
class CloneBlock:
    file_path: str
    function_name: str
    start_line: int
    end_line: int
    statement_count: int
    node_count: int


@dataclass(frozen=True)
class CloneFinding:
    original: CloneBlock
    duplicate: CloneBlock


_CloneLimit = Literal[
    "source_inventory", "source_bytes", "ast_nodes", "windows", "normalization",
    "comparisons", "findings", "inventory_entries", "files",
]


class CloneAnalysisLimitError(ValueError):
    """Analysis is incomplete because a configured bound would be exceeded."""

    def __init__(self, limit_name: _CloneLimit, limit: int) -> None:
        self.limit_name = limit_name
        self.limit = limit
        super().__init__(f"Clone analysis exceeded {limit_name} limit ({limit})")


@dataclass(eq=False)
class _Scope:
    table: symtable.SymbolTable
    parent: _Scope | None
    parameters: dict[str, int]
    inlined_comprehension: frozenset[str] | None = None


@dataclass(frozen=True)
class _Function:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    scope: _Scope
    name: str


class _ScopeMap:
    def __init__(self, tree: ast.Module, table: symtable.SymbolTable) -> None:
        self.nodes: dict[ast.AST, _Scope] = {}
        self.functions: list[_Function] = []
        self.children: dict[_Scope, dict[tuple[str, int], list[symtable.SymbolTable]]] = {}
        self.used: set[int] = set()
        self.visit(tree, _Scope(table, None, {}), ())

    def child(self, node: ast.AST, scope: _Scope, name: str) -> _Scope:
        if scope not in self.children:
            self.children[scope] = {}
            for table in reversed(scope.table.get_children()):
                key = (table.get_name(), table.get_lineno())
                self.children[scope].setdefault(key, []).append(table)
        matches = self.children[scope].get((name, getattr(node, "lineno", 0)), [])
        while matches and id(matches[-1]) in self.used:
            matches.pop()
        if not matches:
            raise ValueError("Unsupported or ambiguous lexical scope")
        table = matches.pop()
        self.used.add(id(table))
        parameters = {
            symbol.get_name(): index
            for index, symbol in enumerate(
                symbol for symbol in table.get_symbols() if symbol.is_parameter()
            )
        }
        return _Scope(table, scope, parameters)

    def arguments(self, args: ast.arguments, outer: _Scope, inner: _Scope) -> None:
        self.nodes[args] = inner
        parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg is not None:
            parameters.append(args.vararg)
        if args.kwarg is not None:
            parameters.append(args.kwarg)
        for parameter in parameters:
            self.nodes[parameter] = inner
            if parameter.annotation is not None:
                self.visit(parameter.annotation, outer, ())
        for default in (*args.defaults, *args.kw_defaults):
            if default is not None:
                self.visit(default, outer, ())

    def visit(self, node: ast.AST, scope: _Scope, names: tuple[str, ...]) -> None:
        self.nodes[node] = scope
        if getattr(node, "type_params", None) or type(node).__name__ == "TypeAlias":
            raise ValueError("Generic annotation scopes are not supported")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            name = "lambda" if isinstance(node, ast.Lambda) else node.name
            inner = self.child(node, scope, name)
            self.arguments(node.args, scope, inner)
            if isinstance(node, ast.Lambda):
                self.visit(node.body, inner, names)
                return
            for decorator in node.decorator_list:
                self.visit(decorator, scope, names)
            if node.returns is not None:
                self.visit(node.returns, scope, names)
            qualified = (*names, node.name)
            self.functions.append(_Function(node, inner, ".".join(qualified)))
            for statement in node.body:
                self.visit(statement, inner, qualified)
            return
        if isinstance(node, ast.ClassDef):
            for expression in (*node.bases, *node.keywords, *node.decorator_list):
                self.visit(expression, scope, names)
            inner = self.child(node, scope, node.name)
            for statement in node.body:
                self.visit(statement, inner, (*names, node.name))
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            name = {
                ast.ListComp: "listcomp", ast.SetComp: "setcomp",
                ast.DictComp: "dictcomp", ast.GeneratorExp: "genexpr",
            }[type(node)]
            try:
                inner = self.child(node, scope, name)
            except ValueError:
                # PEP 709 inlines these scopes in newer Python symbol tables, while
                # their iteration bindings still have separate lexical identities.
                if isinstance(node, ast.GeneratorExp):
                    raise
                bindings = frozenset(
                    target.id for generator in node.generators
                    for target in ast.walk(generator.target) if isinstance(target, ast.Name)
                )
                inner = _Scope(scope.table, scope, {}, bindings)
            for index, generator in enumerate(node.generators):
                self.nodes[generator] = inner
                self.visit(generator.iter, scope if index == 0 else inner, names)
                self.visit(generator.target, inner, names)
                for condition in generator.ifs:
                    self.visit(condition, inner, names)
            if isinstance(node, ast.DictComp):
                self.visit(node.key, inner, names)
                self.visit(node.value, inner, names)
            else:
                self.visit(node.elt, inner, names)
            return
        for child in ast.iter_child_nodes(node):
            self.visit(child, scope, names)


class _Work:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.remaining = limit

    def tick(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise CloneAnalysisLimitError("normalization", self.limit)


class _Normalizer:
    def __init__(self, scopes: _ScopeMap, root: _Scope, work: _Work) -> None:
        self.scopes = scopes
        self.scope_ids = {root: 0}
        ancestor = root.parent
        while ancestor is not None:
            self.scope_ids[ancestor] = -len(self.scope_ids)
            ancestor = ancestor.parent
        self.locals: dict[tuple[_Scope, str], int] = {}
        self.local_counts: dict[_Scope, int] = {}
        self.work = work
        self.tokens: list[str] = []

    def binding(self, scope: _Scope, name: str) -> str:
        self.work.tick()
        if scope.inlined_comprehension is not None:
            if name in scope.inlined_comprehension:
                return self.local_binding(scope, name)
            if scope.parent is not None:
                return self.binding(scope.parent, name)
            return "unresolved:" + name
        try:
            symbol = scope.table.lookup(name)
        except KeyError:
            return "unresolved:" + name
        if scope.table.get_type() in {"module", "class"} or symbol.is_global():
            return "global:" + name
        if symbol.is_free() or symbol.is_nonlocal():
            parent = scope.parent
            while parent is not None:
                self.work.tick()
                if parent.table.get_type() != "class":
                    try:
                        enclosing = parent.table.lookup(name)
                    except KeyError:
                        enclosing = None
                    if enclosing is not None and enclosing.is_local():
                        return self.binding(parent, name)
                parent = parent.parent
            return "unresolved:" + name
        return self.local_binding(scope, name)

    def local_binding(self, scope: _Scope, name: str) -> str:
        scope_id = self.scope_ids.setdefault(scope, len(self.scope_ids))
        if name in scope.parameters:
            return f"scope:{scope_id}:_v{scope.parameters[name]}"
        key = (scope, name)
        if key not in self.locals:
            self.locals[key] = self.local_counts.get(scope, 0)
            self.local_counts[scope] = self.locals[key] + 1
        return f"scope:{scope_id}:_v{len(scope.parameters) + self.locals[key]}"

    def scalar(self, node: ast.AST, field: str, value: object) -> str:
        if isinstance(node, ast.Constant):
            if field == "kind":
                return ""  # Prefix spellings do not change the literal abstraction.
            if field == "value":
                if isinstance(value, str):
                    return "_STR_"
                if type(value) in (int, float, complex):
                    return "_NUM_"
                return "literal:" + type(value).__name__
        if isinstance(value, str) and (
            (isinstance(node, ast.Name) and field == "id")
            or (isinstance(node, ast.arg) and field == "arg")
            or (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and field == "name")
            or (isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
                and field == "name")
            or (isinstance(node, ast.MatchMapping) and field == "rest")
            or (isinstance(node, ast.alias) and field == "asname")
            or isinstance(node, (ast.Global, ast.Nonlocal))
        ):
            return self.binding(self.scopes.nodes[node], value)
        return repr(value)

    def visit(self, node: ast.AST) -> None:
        self.work.tick()
        self.tokens.extend((type(node).__name__, "("))
        for field, value in ast.iter_fields(node):
            self.work.tick()
            self.tokens.append(field)
            if isinstance(value, ast.AST):
                self.visit(value)
            elif isinstance(value, list):
                self.tokens.append("[")
                for item in value:
                    self.work.tick()
                    if isinstance(item, ast.AST):
                        self.visit(item)
                    else:
                        self.tokens.append(self.scalar(node, field, item))
                self.tokens.append("]")
            else:
                self.tokens.append(self.scalar(node, field, value))
        self.tokens.append(")")


@dataclass(frozen=True)
class _Candidate:
    block: CloneBlock
    body: list[ast.stmt]
    start: int
    end: int
    scopes: _ScopeMap
    scope: _Scope


def _suites(body: list[ast.stmt]) -> Iterator[list[ast.stmt]]:
    yield body
    pending: list[ast.AST] = list(reversed(body))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                statements = [item for item in value if isinstance(item, ast.stmt)]
                if statements:
                    yield statements
                pending.extend(reversed([item for item in value if isinstance(item, ast.AST)]))
            elif isinstance(value, ast.AST):
                pending.append(value)


def _block_key(block: CloneBlock) -> tuple[str, int, int, str]:
    return block.file_path, block.start_line, block.end_line, block.function_name


def _contains(outer: CloneBlock, inner: CloneBlock) -> bool:
    return (
        outer.file_path == inner.file_path
        and outer.start_line <= inner.start_line
        and outer.end_line >= inner.end_line
    )


def _overlap(first: CloneBlock, second: CloneBlock) -> bool:
    return first.file_path == second.file_path and (
        first.start_line <= second.end_line and second.start_line <= first.end_line
    )


def _findings(
    groups: dict[tuple[str, ...], list[CloneBlock]],
    max_findings: int,
    max_comparisons: int,
) -> tuple[CloneFinding, ...]:
    findings: list[CloneFinding] = []
    comparison_limit = max_comparisons
    ordered = sorted(
        groups.values(),
        key=lambda blocks: (-blocks[0].node_count, -blocks[0].statement_count,
                            min(_block_key(block) for block in blocks)),
    )
    for blocks in ordered:
        originals: list[CloneBlock] = []
        for duplicate in sorted(set(blocks), key=_block_key):
            for original in originals:
                max_comparisons -= 1
                if max_comparisons < 0:
                    raise CloneAnalysisLimitError("comparisons", comparison_limit)
                if _overlap(original, duplicate):
                    continue
                if not any(_contains(item.original, original)
                           and _contains(item.duplicate, duplicate) for item in findings):
                    if len(findings) >= max_findings:
                        raise CloneAnalysisLimitError("findings", max_findings)
                    findings.append(CloneFinding(original, duplicate))
                break
            originals.append(duplicate)
    return tuple(sorted(findings, key=lambda f: (_block_key(f.original), _block_key(f.duplicate))))


def detect_type2_clones(
    sources: Mapping[str, str],
    *,
    min_statements: int = 5,
    min_nodes: int = 25,
    max_source_bytes: int = 2_000_000,
    max_ast_nodes: int = 100_000,
    max_windows: int = 10_000,
    max_findings: int = 100,
) -> tuple[CloneFinding, ...]:
    """Return deterministic, non-overlapping alpha-clone regions without executing code.

    Statement/node counts include nested statements. Whole suites are considered before
    smaller windows; only maximal discovered pairs are retained. Limits apply globally:
    source bytes and AST nodes reject an oversized inventory, window attempts and a
    normalization budget of 16 * max_ast_nodes ticks and comparison budget of
    8 * max_windows bound work. Attempted overflow, including findings overflow, raises
    CloneAnalysisLimitError rather than returning incomplete evidence. Invalid syntax
    and unsupported scopes remain conservative omissions; absence never proves safety.
    """
    limits = (min_statements, min_nodes, max_source_bytes, max_ast_nodes, max_windows,
              max_findings)
    if any(isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 for limit in limits):
        raise ValueError("Clone limits must be positive integers")
    if len(sources) > max_windows:
        raise CloneAnalysisLimitError("source_inventory", max_windows)
    try:
        bytes_remaining = max_source_bytes
        for source in sources.values():
            if len(source) > bytes_remaining:
                raise CloneAnalysisLimitError("source_bytes", max_source_bytes)
            bytes_remaining -= len(source.encode("utf-8"))
            if bytes_remaining < 0:
                raise CloneAnalysisLimitError("source_bytes", max_source_bytes)
    except UnicodeError:
        return ()
    candidates: list[_Candidate] = []
    nodes_remaining = max_ast_nodes
    windows_remaining = max_windows
    for path, source in sorted(sources.items()):
        try:
            tree = ast.parse(source, filename=path)
            nodes: list[ast.AST] = []
            for node in ast.walk(tree):
                nodes_remaining -= 1
                if nodes_remaining < 0:
                    raise CloneAnalysisLimitError("ast_nodes", max_ast_nodes)
                nodes.append(node)
            scopes = _ScopeMap(tree, symtable.symtable(source, path, "exec"))
            counts: dict[ast.AST, tuple[int, int]] = {}
            for node in reversed(nodes):
                children = [counts[child] for child in ast.iter_child_nodes(node)]
                counts[node] = (int(isinstance(node, ast.stmt)) + sum(s for s, _ in children),
                                1 + sum(n for _, n in children))
            for function in scopes.functions:
                for body in _suites(function.node.body):
                    statements = [0]
                    ast_nodes = [0]
                    for statement in body:
                        count, size = counts[statement]
                        statements.append(statements[-1] + count)
                        ast_nodes.append(ast_nodes[-1] + size)
                    for length in range(len(body), 0, -1):
                        for start in range(len(body) - length + 1):
                            if windows_remaining <= 0:
                                raise CloneAnalysisLimitError("windows", max_windows)
                            windows_remaining -= 1
                            end = start + length
                            count = statements[end] - statements[start]
                            size = ast_nodes[end] - ast_nodes[start]
                            if count >= min_statements and size >= min_nodes:
                                block = CloneBlock(path, function.name, body[start].lineno,
                                                   body[end - 1].end_lineno or body[end - 1].lineno,
                                                   count, size)
                                candidates.append(_Candidate(block, body, start, end, scopes,
                                                             function.scope))
        except CloneAnalysisLimitError:
            raise
        except (SyntaxError, ValueError, RecursionError):
            continue
    groups: dict[tuple[str, ...], list[CloneBlock]] = {}
    work = _Work(max_ast_nodes * 16)
    for candidate in sorted(candidates, key=lambda c: (-c.block.node_count, _block_key(c.block))):
        normalizer = _Normalizer(candidate.scopes, candidate.scope, work)
        try:
            for index in range(candidate.start, candidate.end):
                normalizer.visit(candidate.body[index])
        except RecursionError:
            continue
        groups.setdefault(tuple(normalizer.tokens), []).append(candidate.block)
    return _findings(groups, max_findings, max_windows * 8)

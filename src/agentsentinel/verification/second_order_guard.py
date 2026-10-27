"""M13C differential AST policy; inspected source is never imported or run."""

from __future__ import annotations

import ast
import hashlib
import zlib
from collections import Counter
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import OverfitPolicyError, OverfitReason
from agentsentinel.verification.symbolic_constants import ConstantFolder, qualified_name

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import NoReturn

ERR_M13C_INDIRECT_REFLECTION = "ERR_M13C_INDIRECT_REFLECTION"
ERR_M13C_OBFUSCATED_LITERAL = "ERR_M13C_OBFUSCATED_LITERAL"
ERR_M13C_ABRUPT_FINALLY_EXIT = "ERR_M13C_ABRUPT_FINALLY_EXIT"
ERR_M13C_CONTEXT_SUPPRESSION = "ERR_M13C_CONTEXT_SUPPRESSION"
ERR_M13C_TOPLEVEL_SIDEEFFECT = "ERR_M13C_TOPLEVEL_SIDEEFFECT"

ALLOWED_PURE_DECORATORS = frozenset(
    {
        "property",
        "staticmethod",
        "classmethod",
        "dataclass",
        "dataclasses.dataclass",
        "lru_cache",
        "functools.lru_cache",
        "cache",
        "functools.cache",
        "abstractmethod",
        "abc.abstractmethod",
        "final",
        "typing.final",
        "override",
        "typing.override",
        "total_ordering",
        "functools.total_ordering",
        "contextmanager",
        "contextlib.contextmanager",
    }
)
_REFLECT = {
    "getattr",
    "setattr",
    "delattr",
    "eval",
    "exec",
    "__import__",
    "vars",
    "globals",
    "locals",
    "compile",
}
_RESTRICTED = {
    "sys",
    "builtins",
    "__builtins__",
    "importlib",
    "pytest",
    "_pytest",
    "unittest",
    "inspect",
    "ctypes",
    "operator",
}
_ATTRIBUTES = {
    "getattr",
    "setattr",
    "delattr",
    "eval",
    "exec",
    "import_module",
    "attrgetter",
    "methodcaller",
    "_getframe",
}
_DIGESTS = {"hash", "zlib.crc32", "zlib.adler32", "hashlib.md5", "hashlib.sha1", "hashlib.sha256"}
_SPECIFIC_EXCEPTIONS = {
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "EOFError",
    "ImportError",
    "LookupError",
    "NameError",
    "OSError",
    "ReferenceError",
    "RuntimeError",
    "StopIteration",
    "SyntaxError",
    "SystemError",
    "TypeError",
    "ValueError",
    "ZeroDivisionError",
    "FileNotFoundError",
    "FileExistsError",
    "PermissionError",
    "TimeoutError",
    "KeyError",
    "IndexError",
    "UnicodeError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "ModuleNotFoundError",
    "NotImplementedError",
    "OverflowError",
    "ConnectionError",
}
_MESSAGES = {
    ERR_M13C_INDIRECT_REFLECTION: "New indirect reflection or restricted namespace access",
    ERR_M13C_OBFUSCATED_LITERAL: "New symbolic test-data constant or digest comparison",
    ERR_M13C_ABRUPT_FINALLY_EXIT: "Abrupt exit escaping a finally suite discards active exceptions",
    ERR_M13C_CONTEXT_SUPPRESSION: "Broad, unresolved or empty exception suppression",
    ERR_M13C_TOPLEVEL_SIDEEFFECT: "New import-time or definition-time side effect",
}


@dataclass(frozen=True)
class SecondOrderEvasionMetrics:
    ast_reflection_bypass_blocked_count: int = 0
    ast_literal_obfuscation_folded_count: int = 0
    ast_abrupt_finally_exit_count: int = 0
    ast_toplevel_sideeffect_count: int = 0


_metrics = SecondOrderEvasionMetrics()


def get_second_order_evasion_metrics() -> SecondOrderEvasionMetrics:
    """Immutable process-local snapshot; counts detections, not unique attempts."""
    return _metrics


def reset_second_order_evasion_metrics() -> None:
    global _metrics
    _metrics = SecondOrderEvasionMetrics()


@dataclass(frozen=True)
class SecondOrderFinding:
    code: str
    line_number: int
    message: str
    reason_code: OverfitReason


@dataclass(frozen=True)
class _Event:
    scope: tuple[str, ...]
    fingerprint: str
    finding: SecondOrderFinding
    values: frozenset[str | int | float] = frozenset()
    digest_compare: bool = False


def _values(value: object) -> Iterable[str | int | float]:
    if isinstance(value, bool):
        return
    if isinstance(value, (str, int, float)):
        yield value
    elif isinstance(value, bytes):
        yield value.decode("utf-8", errors="ignore")
    elif isinstance(value, tuple):
        for item in value:
            yield from _values(item)


def _digest_values(literals: frozenset[str | int | float]) -> set[str | int]:
    values: set[str | int] = set()
    for literal in literals:
        if not isinstance(literal, str) or len(literal) > 65536:
            continue
        data = literal.encode("utf-8", errors="surrogatepass")
        for checksum in (zlib.crc32(data), zlib.adler32(data)):
            values.update((checksum, checksum - 2**32 if checksum >= 2**31 else checksum))
        for algorithm in ("md5", "sha1", "sha256"):
            values.add(hashlib.new(algorithm, data, usedforsecurity=False).hexdigest())
    return values


def _immutable(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return (
            isinstance(node.value, (str, bytes, int, float, complex, bool, type(None)))
            or node.value is Ellipsis
        )
    if isinstance(node, ast.Tuple):
        return all(_immutable(item) for item in node.elts)
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.USub, ast.UAdd))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float, complex))
    )


class _Scanner(ast.NodeVisitor):
    def __init__(
        self,
        tree: ast.Module,
        literals: frozenset[str | int | float],
        *,
        structural: bool,
        toplevel: bool,
        allow_numeric_module_constants: bool = False,
    ) -> None:
        self.scope: tuple[str, ...] = ()
        self.aliases: dict[str, str] = {}
        self.instances: dict[str, str] = {}
        self.classes: dict[str, frozenset[str]] = {}
        self.specific_exceptions = set(_SPECIFIC_EXCEPTIONS)
        self.class_context: str | None = None
        self.occurrences: Counter[tuple[str, ...]] = Counter()
        self.events: list[_Event] = []
        self.constants: set[str | int | float] = set()
        self.literals = literals
        self.digests = _digest_values(literals)
        self.structural = structural
        self.toplevel = toplevel
        self.allow_numeric_module_constants = allow_numeric_module_constants
        self.eager_annotations = not any(
            isinstance(stmt, ast.ImportFrom)
            and stmt.module == "__future__"
            and any(alias.name == "annotations" for alias in stmt.names)
            for stmt in tree.body
        )
        # Definitions are resolved statically; no class is instantiated.
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                self.classes[node.name] = frozenset(
                    member.name
                    for member in node.body
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
                if any(
                    isinstance(base, ast.Name) and base.id in {"Exception", *_SPECIFIC_EXCEPTIONS}
                    for base in node.bases
                ):
                    self.specific_exceptions.add(node.name)

    def emit(
        self,
        code: str,
        node: ast.AST,
        meaning: str = "",
        *,
        values: frozenset[str | int | float] = frozenset(),
        digest_compare: bool = False,
    ) -> None:
        reason: OverfitReason = (
            "exception_swallowing"
            if code in {ERR_M13C_ABRUPT_FINALLY_EXIT, ERR_M13C_CONTEXT_SUPPRESSION}
            else "overfit"
        )
        self.events.append(
            _Event(
                self.scope,
                f"{meaning}:{self._call_bindings(node)!r}:"
                f"{ast.dump(node, include_attributes=False)}",
                SecondOrderFinding(code, getattr(node, "lineno", 1), _MESSAGES[code], reason),
                values,
                digest_compare,
            )
        )

    def _call_bindings(self, node: ast.AST) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    qualified_name(child.func, self.aliases)
                    for child in ast.walk(node)
                    if isinstance(child, ast.Call)
                }
            )
        )

    def _audit_annotation(self, annotation: ast.AST | None) -> None:
        if (
            self.structural
            and self.eager_annotations
            and annotation is not None
            and any(isinstance(child, (ast.Call, ast.NamedExpr)) for child in ast.walk(annotation))
        ):
            self.emit(ERR_M13C_TOPLEVEL_SIDEEFFECT, annotation)

    def fold(self, node: ast.AST) -> object:
        return ConstantFolder(self.aliases).fold(node)

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.expr) and self.literals:
            self.constants.update(_values(self.fold(node)))
        super().visit(node)

    def _future_aliases(self, body: list[ast.stmt]) -> dict[str, str]:
        aliases = self.aliases.copy()
        pending: list[ast.AST] = list(reversed(body))
        while pending:
            node = pending.pop()
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
            elif isinstance(node, ast.ClassDef):
                aliases[node.name] = f"<class:{node.name}>"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                aliases[node.name] = "<local>"
            else:
                pending.extend(reversed(list(ast.iter_child_nodes(node))))
        return aliases

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.aliases[item.asname or item.name.split(".")[0]] = (
                item.name if item.asname else item.name.split(".")[0]
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            self.aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def visit_Module(self, node: ast.Module) -> None:
        self.future = self._future_aliases(node.body)
        for index, stmt in enumerate(node.body):
            if self.structural and self.toplevel:
                allowed = (
                    isinstance(
                        stmt,
                        (
                            ast.Import,
                            ast.ImportFrom,
                            ast.FunctionDef,
                            ast.AsyncFunctionDef,
                            ast.ClassDef,
                        ),
                    )
                    or type(stmt).__name__ == "TypeAlias"
                )
                if isinstance(stmt, ast.AnnAssign):
                    allowed = isinstance(stmt.target, ast.Name) and (
                        stmt.value is None or _immutable(stmt.value)
                    )
                if self.allow_numeric_module_constants and isinstance(stmt, ast.Assign):
                    allowed = (
                        all(isinstance(target, ast.Name) for target in stmt.targets)
                        and isinstance(stmt.value, ast.Constant)
                        and type(stmt.value.value) in {int, float}
                    )
                if (
                    index == 0
                    and isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                ):
                    allowed = True
                if not allowed:
                    self.emit(ERR_M13C_TOPLEVEL_SIDEEFFECT, stmt)
            self.visit(stmt)

    def _definition(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        previous = self.scope, self.aliases, self.instances, self.class_context, self.future
        key = (*self.scope, type(node).__name__, node.name)
        occurrence = self.occurrences[key]
        self.occurrences[key] += 1
        self.scope = (*key, str(occurrence))
        if self.structural:
            if isinstance(node, ast.ClassDef):
                if any(
                    isinstance(child, (ast.Call, ast.NamedExpr))
                    for expr in (*node.bases, *(kw.value for kw in node.keywords))
                    for child in ast.walk(expr)
                ):
                    self.emit(ERR_M13C_TOPLEVEL_SIDEEFFECT, node)
                for stmt in node.body:
                    allowed = (
                        isinstance(
                            stmt,
                            (
                                ast.Import,
                                ast.ImportFrom,
                                ast.FunctionDef,
                                ast.AsyncFunctionDef,
                                ast.ClassDef,
                                ast.Pass,
                            ),
                        )
                        or type(stmt).__name__ == "TypeAlias"
                    )
                    if isinstance(stmt, ast.Assign):
                        allowed = all(
                            isinstance(target, ast.Name) for target in stmt.targets
                        ) and _immutable(stmt.value)
                    if isinstance(stmt, ast.AnnAssign):
                        allowed = isinstance(stmt.target, ast.Name) and (
                            stmt.value is None or _immutable(stmt.value)
                        )
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                        allowed = isinstance(stmt.value.value, str)
                    if not allowed:
                        self.emit(ERR_M13C_TOPLEVEL_SIDEEFFECT, stmt)
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    name = qualified_name(decorator.func, self.aliases)
                    property_accessor = (
                        isinstance(decorator.func, ast.Attribute)
                        and isinstance(decorator.func.value, ast.Name)
                        and decorator.func.attr in {"setter", "deleter"}
                    )
                    if (name not in ALLOWED_PURE_DECORATORS and not property_accessor) or any(
                        isinstance(child, (ast.Call, ast.NamedExpr))
                        for arg in (*decorator.args, *(kw.value for kw in decorator.keywords))
                        for child in ast.walk(arg)
                    ):
                        self.emit(ERR_M13C_TOPLEVEL_SIDEEFFECT, decorator, name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                    *([node.args.vararg] if node.args.vararg else []),
                    *([node.args.kwarg] if node.args.kwarg else []),
                ):
                    self._audit_annotation(arg.annotation)
                self._audit_annotation(node.returns)
                for default in (*node.args.defaults, *node.args.kw_defaults):
                    if default is not None and not _immutable(default):
                        self.emit(ERR_M13C_TOPLEVEL_SIDEEFFECT, default)
        # Header expressions execute in the enclosing environment.
        for field, value in ast.iter_fields(node):
            if field == "body":
                continue
            if isinstance(value, ast.AST):
                self.visit(value)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, ast.AST):
                        self.visit(child)
        self.aliases = self.future.copy()
        self.instances = self.instances.copy()
        if isinstance(node, ast.ClassDef):
            self.class_context = node.name
        else:
            parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            for arg in parameters:
                self.aliases[arg.arg] = "<parameter>"
                self.instances.pop(arg.arg, None)
                if (
                    isinstance(arg.annotation, ast.Name)
                    and arg.annotation.id in self.classes
                    and self.aliases.get(arg.annotation.id) == f"<class:{arg.annotation.id}>"
                ):
                    self.instances[arg.arg] = arg.annotation.id
            if (
                self.class_context
                and parameters
                and not any(
                    qualified_name(item, self.aliases).endswith("staticmethod")
                    for item in node.decorator_list
                )
            ):
                self.instances[parameters[0].arg] = self.class_context
            self.class_context = None
        self.future = self._future_aliases(node.body)
        for stmt in node.body:
            self.visit(stmt)
        self.scope, self.aliases, self.instances, self.class_context, self.future = previous
        self.aliases[node.name] = (
            f"<class:{node.name}>" if isinstance(node, ast.ClassDef) else "<local>"
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._definition(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._definition(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._definition(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for target in node.targets:
            self._bind(target, node.value)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._bind(node.target, None)
        for stmt in (*node.body, *node.orelse):
            self.visit(stmt)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if not self.scope or self.class_context is not None:
            self._audit_annotation(node.annotation)
        self.generic_visit(node)
        self._bind(node.target, node.value)
        if (
            isinstance(node.target, ast.Name)
            and isinstance(node.annotation, ast.Name)
            and node.annotation.id in self.classes
            and self.aliases.get(node.annotation.id) == f"<class:{node.annotation.id}>"
        ):
            self.instances[node.target.id] = node.annotation.id

    def _bind(self, target: ast.AST, value: ast.AST | None) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind(item, None)
            return
        if not isinstance(target, ast.Name):
            return
        self.instances.pop(target.id, None)
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in self.classes
            and self.aliases.get(value.func.id) == f"<class:{value.func.id}>"
        ):
            self.instances[target.id] = value.func.id
        name = qualified_name(value, self.aliases) if value is not None else ""
        self.aliases[target.id] = name or "<local>"

    def _local_method(self, node: ast.Attribute) -> bool:
        if isinstance(node.value, ast.Name):
            class_name = self.instances.get(node.value.id)
            return class_name is not None and node.attr in self.classes.get(class_name, frozenset())
        return False

    def visit_Call(self, node: ast.Call) -> None:
        name = qualified_name(node.func, self.aliases)
        if self.structural:
            forbidden = name.removeprefix("builtins.") in _REFLECT
            if isinstance(node.func, ast.Attribute):
                receiver = qualified_name(node.func.value, self.aliases)
                forbidden |= receiver.split(".")[0] in _RESTRICTED or (
                    node.func.attr in _ATTRIBUTES and not self._local_method(node.func)
                )
            if forbidden:
                self.emit(ERR_M13C_INDIRECT_REFLECTION, node, name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = qualified_name(node, self.aliases)
        if self.structural and (
            name in {"sys.modules", "builtins.__dict__", "__builtins__.__dict__"}
            or node.attr in {"__globals__", "__subclasses__"}
        ):
            self.emit(ERR_M13C_INDIRECT_REFLECTION, node, name)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        name = qualified_name(node.value, self.aliases)
        if self.structural and (
            name in {"builtins", "__builtins__", "sys.modules"}
            or isinstance(node.value, ast.Attribute)
            and node.value.attr in {"__dict__", "__globals__", "__subclasses__"}
        ):
            self.emit(ERR_M13C_INDIRECT_REFLECTION, node, name)
        self.generic_visit(node)

    def visit_MatchValue(self, node: ast.MatchValue) -> None:
        name = qualified_name(node.value, self.aliases)
        if self.structural and name.split(".")[0] in _RESTRICTED:
            self.emit(ERR_M13C_INDIRECT_REFLECTION, node, name)
        self._literal_context(node.value)
        self.generic_visit(node)

    def _literal_context(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if not isinstance(child, ast.expr):
                continue
            if not self.literals and not isinstance(child, ast.Compare):
                continue
            value = self.fold(child)
            matched_values = frozenset(
                item for item in _values(value) if item in self.literals or item in self.digests
            )
            digest_compare = False
            if isinstance(child, ast.Compare):
                operands = [child.left, *child.comparators]
                has_digest = any(
                    isinstance(item, ast.Call)
                    and qualified_name(item.func, self.aliases).removeprefix("builtins.")
                    in _DIGESTS
                    for operand in operands
                    for item in ast.walk(operand)
                )
                has_constant = any(
                    isinstance(self.fold(item), (str, int, bytes)) for item in operands
                )
                digest_compare = has_digest and has_constant
            if matched_values or digest_compare:
                self.emit(
                    ERR_M13C_OBFUSCATED_LITERAL,
                    child,
                    "digest" if digest_compare else repr(value),
                    values=matched_values,
                    digest_compare=digest_compare,
                )

    def visit_If(self, node: ast.If) -> None:
        self._literal_context(node.test)
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._literal_context(node.test)
        self.generic_visit(node)

    def visit_match_case(self, node: ast.match_case) -> None:
        if node.guard is not None:
            self._literal_context(node.guard)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self._literal_context(node.value)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for expr in (*node.keys, *node.values):
            if expr is not None:
                self._literal_context(expr)
        self.generic_visit(node)

    def _finally(self, node: ast.AST, loop_depth: int = 0) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(node, ast.Return) or (
            isinstance(node, (ast.Break, ast.Continue)) and loop_depth == 0
        ):
            self.emit(ERR_M13C_ABRUPT_FINALLY_EXIT, node)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            for child in node.body:
                self._finally(child, loop_depth + 1)
            for child in node.orelse:
                self._finally(child, loop_depth)
        else:
            for descendant in ast.iter_child_nodes(node):
                self._finally(descendant, loop_depth)

    def visit_Try(self, node: ast.Try | ast.TryStar) -> None:
        if self.structural:
            for stmt in node.finalbody:
                self._finally(stmt)
        self.generic_visit(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.visit_Try(node)

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        if self.structural:
            for item in node.items:
                expr = item.context_expr
                if not isinstance(expr, ast.Call) or qualified_name(
                    expr.func, self.aliases
                ) not in {"suppress", "contextlib.suppress"}:
                    continue

                def broad(arg: ast.AST) -> bool:
                    if isinstance(arg, ast.Tuple):
                        return any(broad(child) for child in arg.elts)
                    name = qualified_name(arg, self.aliases).removeprefix("builtins.")
                    return name not in self.specific_exceptions

                if not expr.args or expr.keywords or any(broad(arg) for arg in expr.args):
                    self.emit(ERR_M13C_CONTEXT_SUPPRESSION, expr)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if self.structural and all(
            isinstance(stmt, ast.Pass)
            or isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            for stmt in node.body
        ):
            self.emit(ERR_M13C_CONTEXT_SUPPRESSION, node)
        if node.name:
            self.instances.pop(node.name, None)
            self.aliases[node.name] = "<exception>"
        self.generic_visit(node)


def analyze_second_order_evasion(
    file_path: str,
    pre_source: str,
    post_source: str,
    test_literals: frozenset[str | int | float] = frozenset(),
    *,
    check_structural: bool = True,
    enforce_toplevel_purity: bool = True,
    allow_numeric_module_constants: bool = False,
) -> tuple[SecondOrderFinding, ...]:
    """Aggregate new findings; invalid Python retains the syntax-failure path."""
    try:
        pre_tree, post_tree = (
            ast.parse(pre_source, filename=file_path),
            ast.parse(post_source, filename=file_path),
        )
    except SyntaxError:
        return ()
    before = _Scanner(
        pre_tree,
        test_literals,
        structural=check_structural,
        toplevel=enforce_toplevel_purity,
        allow_numeric_module_constants=allow_numeric_module_constants,
    )
    after = _Scanner(
        post_tree,
        test_literals,
        structural=check_structural,
        toplevel=enforce_toplevel_purity,
        allow_numeric_module_constants=allow_numeric_module_constants,
    )
    before.visit(pre_tree)
    after.visit(post_tree)
    remaining = Counter(
        (event.scope, event.finding.code, event.fingerprint) for event in before.events
    )
    findings: dict[tuple[str, int], SecondOrderFinding] = {}
    for event in after.events:
        key = event.scope, event.finding.code, event.fingerprint
        if remaining[key]:
            remaining[key] -= 1
            continue
        # Preserve the established M8 exemption for constants in the baseline.
        if (
            event.finding.code == ERR_M13C_OBFUSCATED_LITERAL
            and not event.digest_compare
            and event.values <= before.constants
        ):
            continue
        findings[(event.finding.code, event.finding.line_number)] = event.finding
    return tuple(sorted(findings.values(), key=lambda finding: (finding.line_number, finding.code)))


def _record(finding: SecondOrderFinding) -> None:
    global _metrics
    field = {
        ERR_M13C_INDIRECT_REFLECTION: "ast_reflection_bypass_blocked_count",
        ERR_M13C_OBFUSCATED_LITERAL: "ast_literal_obfuscation_folded_count",
        ERR_M13C_ABRUPT_FINALLY_EXIT: "ast_abrupt_finally_exit_count",
        ERR_M13C_CONTEXT_SUPPRESSION: "ast_abrupt_finally_exit_count",
        ERR_M13C_TOPLEVEL_SIDEEFFECT: "ast_toplevel_sideeffect_count",
    }[finding.code]
    _metrics = replace(_metrics, **{field: getattr(_metrics, field) + 1})


def reject_obfuscated_literal(file_path: str, leaked_literal: str = "") -> NoReturn:
    """Preserve M8 literal properties without rendering assertion data in feedback."""
    code = ERR_M13C_OBFUSCATED_LITERAL
    _record(SecondOrderFinding(code, 1, _MESSAGES[code], "overfit"))
    raise OverfitPolicyError(
        leaked_literal=leaked_literal,
        file_path=file_path,
        message=(
            f"{code}: Overfit policy violation: "
            f"leaked_literal={leaked_literal!r} in {file_path!r}"
        ),
        diagnostic_code=code,
    )


def verify_second_order_evasion(
    file_path: str,
    pre_source: str,
    post_source: str,
    test_literals: frozenset[str | int | float] = frozenset(),
    *,
    check_structural: bool = True,
    enforce_toplevel_purity: bool = True,
    allow_numeric_module_constants: bool = False,
) -> None:
    findings = analyze_second_order_evasion(
        file_path,
        pre_source,
        post_source,
        test_literals,
        check_structural=check_structural,
        enforce_toplevel_purity=enforce_toplevel_purity,
        allow_numeric_module_constants=allow_numeric_module_constants,
    )
    if findings:
        finding = findings[0]
        _record(finding)
        raise OverfitPolicyError(
            file_path=file_path,
            message=f"{finding.code}: {finding.message}",
            reason_code=finding.reason_code,
            diagnostic_code=finding.code,
        )

"""Aggregating static policies composed from the M2/M8/M9/M11 engines."""

from __future__ import annotations

import ast
import os
import tokenize
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from io import StringIO
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.policy.validator import PatchPolicyValidator
from agentsentinel.verification.ci_source_map import FileLifecycleStatus, SourceMapEntry
from agentsentinel.verification.contract_guard import (
    _compatible,
    _public_api,
    verify_public_api_compatibility,
)
from agentsentinel.verification.overfit_guard import (
    BIDI_AND_ZERO_WIDTH,
    _collect_all_folded_constants,
    _collect_ast_identifiers,
    _eval_static_constant,
    _is_nontrivial_constant,
)
from agentsentinel.verification.patch_minimizer import (
    _block_outcomes,
    compute_cyclomatic_complexity,
)
from agentsentinel.verification.second_order_guard import (
    ERR_M13C_ABRUPT_FINALLY_EXIT,
    ERR_M13C_CONTEXT_SUPPRESSION,
    ERR_M13C_INDIRECT_REFLECTION,
    ERR_M13C_OBFUSCATED_LITERAL,
    analyze_second_order_evasion,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

STAGE_PATH = "Stage 1: Diff Syntax & Path Policy"
STAGE_LEX = "Stage 2: Lexical Hygiene"
STAGE_OVERFIT = "Stage 3: Overfitting & Reflection Guard"
STAGE_EXCEPTION = "Stage 4: Complexity & Exception Hygiene"
STAGE_CC = "Stage 4: Complexity Guard"
STAGE_API = "Stage 5: API Contract"


class ViolationSeverity(str, Enum):  # noqa: UP042 -- specified public str/Enum API
    ERROR = "ERROR"
    WARNING = "WARNING"


@dataclass(frozen=True)
class CIGateViolation:
    file_path: str
    line_number: int
    stage: str
    rule_id: str
    severity: str
    message: str
    remediation_advice: str


@dataclass(frozen=True)
class FileAuditMetrics:
    file_path: str
    cc_pre: int
    cc_post: int
    cc_delta: int
    api_contract_status: str


@dataclass(frozen=True)
class _Event:
    key: tuple[str, ...]
    rule: str
    line: int
    column: int
    message: str


_DEBUG = {"breakpoint", "pdb.set_trace", "ipdb.set_trace", "sys.breakpointhook"}
_REFLECTION = {
    "eval",
    "exec",
    "__import__",
    "setattr",
    "delattr",
    "sys._getframe",
    "inspect.stack",
    "inspect.currentframe",
    "os._exit",
    "builtins.__dict__",
}


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    attributes: list[str] = []
    while isinstance(node, ast.Attribute):
        attributes.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    return ".".join((aliases.get(node.id, node.id), *reversed(attributes)))


def _forbidden(name: str) -> bool:
    return (
        name in _REFLECTION
        or name.removeprefix("builtins.") in _REFLECTION
        or any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in ("pytest", "_pytest", "ctypes", "unittest.mock")
        )
    )


def _own_nodes(body: list[ast.stmt]) -> list[ast.AST]:
    pending: list[ast.AST] = list(reversed(body))
    result: list[ast.AST] = []
    while pending:
        node = pending.pop()
        result.append(node)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            pending.extend(reversed(list(ast.iter_child_nodes(node))))
        else:
            # Decorators, annotations and defaults execute in the parent scope.
            for field, value in ast.iter_fields(node):
                if field != "body":
                    if isinstance(value, ast.AST):
                        pending.append(value)
                    elif isinstance(value, list):
                        pending.extend(child for child in value if isinstance(child, ast.AST))
    return sorted(
        result, key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
    )


def _logs(handler: ast.ExceptHandler) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr
        in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
        for node in _own_nodes(handler.body)
    )


def _events(
    tree: ast.Module,
) -> tuple[list[_Event], dict[tuple[str, ...], ast.FunctionDef | ast.AsyncFunctionDef]]:
    events: list[_Event] = []
    functions: dict[tuple[str, ...], ast.FunctionDef | ast.AsyncFunctionDef] = {}
    scopes: list[tuple[list[ast.stmt], tuple[str, ...], dict[str, str]]] = [(tree.body, (), {})]
    while scopes:
        body, scope, inherited = scopes.pop()
        nodes = _own_nodes(body)
        future_aliases = inherited.copy()
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    future_aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    future_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        aliases = inherited.copy()
        occurrences: Counter[str] = Counter()
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                identity = (*scope, node.name, str(occurrences[node.name]))
                occurrences[node.name] += 1
                scopes.append((node.body, identity, future_aliases.copy()))
                if not isinstance(node, ast.ClassDef):
                    functions[identity] = node
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            findings: list[tuple[str, str]] = []
            if isinstance(node, ast.Call):
                name = _qualified(node.func, aliases)
                if name.removeprefix("builtins.") in _DEBUG:
                    findings.append(("LEX-002", "New debugger call is forbidden"))
                if _forbidden(name):
                    findings.append(
                        ("REF-001", "New dynamic-execution or reflection call is forbidden")
                    )
            elif isinstance(node, ast.Import):
                if any(_forbidden(alias.name) for alias in node.names):
                    findings.append(
                        ("REF-001", "New test-harness or reflection import is forbidden")
                    )
            elif isinstance(node, ast.ImportFrom):
                if _forbidden(node.module or "") or any(
                    _forbidden(f"{node.module}.{alias.name}") for alias in node.names
                ):
                    findings.append(
                        ("REF-001", "New test-harness or reflection import is forbidden")
                    )
            elif isinstance(node, (ast.Name, ast.Attribute)):
                if _forbidden(_qualified(node, aliases)):
                    findings.append(
                        ("REF-001", "New test-harness or reflection reference is forbidden")
                    )
            elif isinstance(node, ast.ExceptHandler):
                types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
                broad = any(
                    item is not None
                    and _qualified(item, aliases).removeprefix("builtins.")
                    in {"Exception", "BaseException"}
                    for item in types
                )
                if node.type is None or (
                    broad
                    and not _block_outcomes(node.body) <= {"return", "raise"}
                    and not _logs(node)
                ):
                    findings.append(
                        ("EXC-001", "New bare or silently swallowing exception handler")
                    )
            for rule, message in findings:
                events.append(
                    _Event(
                        (*scope, rule, ast.dump(node, include_attributes=False)),
                        rule,
                        getattr(node, "lineno", 1),
                        getattr(node, "col_offset", 0),
                        message,
                    )
                )
    return events, functions


def _introduced(before: list[_Event], after: list[_Event], mapping: dict[int, int]) -> list[_Event]:
    remaining = Counter(event.key for event in before)
    positions = Counter(
        (event.key, mapping[event.line], event.column) for event in before if event.line in mapping
    )
    unmatched: list[_Event] = []
    for event in after:
        position = (event.key, event.line, event.column)
        if positions[position]:
            positions[position] -= 1
            remaining[event.key] -= 1
        else:
            unmatched.append(event)
    result: list[_Event] = []
    for event in unmatched:
        if remaining[event.key] > 0:
            remaining[event.key] -= 1
        else:
            result.append(event)
    return result


def _unicode_names(source: str) -> list[tuple[str, int]]:
    names: list[tuple[str, int]] = []
    try:
        for token in tokenize.generate_tokens(StringIO(source).readline):
            if token.type == tokenize.NAME and not token.string.isascii():
                names.append((token.string, token.start[0]))
    except (tokenize.TokenError, IndentationError):
        return names
    return names


def analyze_entry(
    entry: SourceMapEntry,
    literals: frozenset[str | int | float],
    *,
    allowed_edit_paths: Sequence[str] | None,
    allow_test_edits: bool,
    max_cc_delta: int,
    allow_numeric_module_constants: bool = True,
) -> tuple[list[CIGateViolation], FileAuditMetrics]:
    violations: list[CIGateViolation] = []

    def add(
        rule: str,
        line: int,
        message: str,
        advice: str,
        stage: str,
        *,
        path: str | None = None,
        warning: bool = False,
    ) -> None:
        violations.append(
            CIGateViolation(
                path or entry.file_path,
                max(1, line),
                stage,
                rule,
                "WARNING" if warning else "ERROR",
                message,
                advice,
            )
        )

    policy = PatchPolicyValidator(())
    allowed = (
        None
        if allowed_edit_paths is None
        else {
            os.path.normcase(path.replace("\\", "/").removeprefix("./"))
            for path in allowed_edit_paths
        }
    )
    for path in sorted({entry.file_path, *([entry.old_path] if entry.old_path else [])}):
        policy_path = os.path.normcase(path)
        infrastructure = (
            policy.is_infrastructure_file(path)
            or policy.is_infrastructure_file(policy_path)
            or (
                os.name == "nt"
                and policy_path.replace("\\", "/").rsplit("/", 1)[-1].startswith("dockerfile")
            )
        )
        if infrastructure:
            add(
                "PATH-001",
                1,
                "Protected infrastructure path was changed",
                "Move infrastructure changes to a separately reviewed change",
                STAGE_PATH,
                path=path,
            )
        if (
            policy.is_test_file(policy_path)
            and entry.status is not FileLifecycleStatus.CREATED
            and not allow_test_edits
        ):
            add(
                "PATH-002",
                1,
                "Protected test path was modified, deleted or renamed",
                "Preserve test files or explicitly authorize test edits",
                STAGE_PATH,
                path=path,
            )
        if allowed is not None and os.path.normcase(path) not in allowed:
            add(
                "PATH-003",
                1,
                "Changed path is outside the supplied allowlist",
                "Restrict the diff to allowed paths",
                STAGE_PATH,
                path=path,
            )
    for line_number, line in enumerate(entry.post_buffer.split("\n"), 1):
        leading = line[: len(line) - len(line.lstrip(" \t"))]
        if (
            any(char in BIDI_AND_ZERO_WIDTH for char in line)
            or "\r" in line
            or (" " in leading and "\t" in leading)
        ):
            add(
                "LEX-001",
                line_number,
                "Unicode control, bare CR or mixed indentation detected",
                "Remove invisible controls and use consistent indentation",
                STAGE_LEX,
            )
    python = os.path.normcase(entry.file_path).endswith(".py") or os.path.normcase(
        entry.old_path or ""
    ).endswith(".py")
    if not python:
        return violations, FileAuditMetrics(entry.file_path, 0, 0, 0, "Intact")

    pre_tree: ast.Module | None = None
    post_tree: ast.Module | None = None
    try:
        pre_tree = ast.parse(entry.pre_buffer)
    except (SyntaxError, ValueError):
        pre_tree = None
    try:
        post_tree = ast.parse(entry.post_buffer)
    except (SyntaxError, ValueError) as exc:
        add(
            "SYN-001",
            getattr(exc, "lineno", 1) or 1,
            "Post-patch Python is not syntactically valid",
            "Repair Python syntax before requesting approval",
            STAGE_PATH,
        )
    pre_names = _collect_ast_identifiers(pre_tree) if pre_tree is not None else set()
    pre_names.update(name for name, _ in _unicode_names(entry.pre_buffer))
    for name, identifier_line in _unicode_names(entry.post_buffer):
        if name not in pre_names:
            add(
                "LEX-001",
                identifier_line,
                f"New non-ASCII identifier: {ascii(name)}",
                "Use unambiguous ASCII identifiers",
                STAGE_LEX,
            )
    pre_events, pre_functions = _events(pre_tree or ast.Module(body=[], type_ignores=[]))
    post_events, post_functions = _events(post_tree or ast.Module(body=[], type_ignores=[]))
    for event in _introduced(pre_events, post_events, entry.line_map):
        stage = (
            STAGE_LEX
            if event.rule == "LEX-002"
            else STAGE_EXCEPTION
            if event.rule == "EXC-001"
            else STAGE_OVERFIT
        )
        add(
            event.rule,
            event.line,
            event.message,
            "Remove debugging/reflection or explicitly handle and log the exception",
            stage,
        )

    pre_constants = _collect_all_folded_constants(pre_tree) if pre_tree is not None else set()
    if post_tree is not None and literals:
        for node in ast.walk(post_tree):
            candidates: list[ast.AST] = []
            if isinstance(node, (ast.If, ast.IfExp)):
                candidates = [child for child in ast.walk(node.test) if isinstance(child, ast.expr)]
            elif isinstance(node, ast.Match):
                candidates = [
                    child.value
                    for case in node.cases
                    for child in ast.walk(case.pattern)
                    if isinstance(child, ast.MatchValue)
                ]
            elif isinstance(node, ast.Dict):
                candidates = [child for child in [*node.keys, *node.values] if child is not None]
            elif isinstance(node, ast.Return) and node.value is not None:
                candidates = [node.value]
            if any(
                _is_nontrivial_constant(value := _eval_static_constant(candidate))
                and value in literals
                and value not in pre_constants
                for candidate in candidates
            ):
                add(
                    "OVF-001",
                    getattr(node, "lineno", 1),
                    "New literal matches repository test assertion data",
                    "Implement general behavior instead of embedding test assertion values",
                    STAGE_OVERFIT,
                )

    for finding in analyze_second_order_evasion(
        entry.file_path, entry.pre_buffer, entry.post_buffer, literals,
        allow_numeric_module_constants=allow_numeric_module_constants,
    ):
        rule = {
            ERR_M13C_INDIRECT_REFLECTION: "REF-001",
            ERR_M13C_OBFUSCATED_LITERAL: "OVF-001",
            ERR_M13C_ABRUPT_FINALLY_EXIT: "EXC-001",
            ERR_M13C_CONTEXT_SUPPRESSION: "EXC-001",
        }.get(finding.code, "IMP-001")
        if any(
            item.rule_id == rule and item.line_number == finding.line_number
            for item in violations
        ):
            continue
        add(
            rule, finding.line_number, f"{finding.code}: {finding.message}",
            "Remove the new evasion construct and implement general source behavior",
            STAGE_EXCEPTION if rule == "EXC-001" else STAGE_OVERFIT,
        )

    cc_pre = (
        compute_cyclomatic_complexity(pre_tree) if pre_tree is not None and entry.pre_buffer else 0
    )
    cc_post = (
        compute_cyclomatic_complexity(post_tree)
        if post_tree is not None and entry.post_buffer
        else 0
    )
    delta = cc_post - cc_pre
    if delta > max_cc_delta:
        add(
            "CC-001",
            1,
            f"File complexity grew by {delta}, above {max_cc_delta}",
            "Reduce decision points or split the change",
            STAGE_CC,
            warning=True,
        )
    for identity, function in post_functions.items():
        before = pre_functions.get(identity)
        growth = compute_cyclomatic_complexity(function) - (
            compute_cyclomatic_complexity(before) if before is not None else 0
        )
        if growth > max_cc_delta:
            name = ".".join(identity[::2])
            add(
                "CC-001",
                function.lineno,
                f"Function {name} complexity grew by {growth}, above {max_cc_delta}",
                "Refactor this function into smaller units",
                STAGE_CC,
                warning=True,
            )

    broken = False
    if (
        pre_tree is not None
        and post_tree is not None
        and entry.status is not FileLifecycleStatus.CREATED
    ):
        try:
            verify_public_api_compatibility(entry.file_path, entry.pre_buffer, entry.post_buffer)
        except OverfitPolicyError:
            broken = True
            before_api, after_api = _public_api(pre_tree), _public_api(post_tree)
            names = before_api.classes - after_api.classes
            changed = [
                key[0]
                for key, signature in before_api.signatures.items()
                if key not in after_api.signatures
                or before_api.bindings[key] != after_api.bindings.get(key)
                or not _compatible(signature, after_api.signatures[key])
            ]
            # A removed class already diagnoses all of its lost call surfaces.
            changed = [
                name
                for name in changed
                if not any(name.startswith(class_name + ".") for class_name in names)
            ]
            locations = {
                ".".join(identity[::2]): node.lineno for identity, node in pre_functions.items()
            }
            locations.update(
                {node.name: node.lineno for node in pre_tree.body if isinstance(node, ast.ClassDef)}
            )
            post_locations = {
                ".".join(identity[::2]): node.lineno for identity, node in post_functions.items()
            }
            post_locations.update(
                {
                    node.name: node.lineno
                    for node in post_tree.body
                    if isinstance(node, ast.ClassDef)
                }
            )
            for name in sorted(names | set(changed)):
                old_line = locations.get(name, 1)
                mapped_line = post_locations.get(name) or entry.line_map.get(
                    old_line,
                    next(
                        (post for pre, post in sorted(entry.line_map.items()) if pre > old_line), 1
                    ),
                )
                add(
                    "API-001",
                    mapped_line,
                    f"Public API contract changed incompatibly: {name}",
                    "Restore the public symbol, binding and compatible call signature",
                    STAGE_API,
                )
    return violations, FileAuditMetrics(
        entry.file_path, cc_pre, cc_post, delta, "❌ Broken Symbol" if broken else "Intact"
    )

"""Static preservation of explicitly declared public Python call signatures.

Dynamic attributes, inherited APIs, arbitrary decorators and behavioral
contracts are outside this guard's bounded AST model.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from agentsentinel.domain.exceptions import OverfitPolicyError


@dataclass(frozen=True)
class FunctionSignatureSpec:
    """Call-shape information; annotations and default values are excluded."""

    name: str
    posonly_count: int
    arg_names: tuple[str, ...]
    defaults_count: int
    has_vararg: bool
    kwonly_names: frozenset[str]
    kw_defaults_present: frozenset[str]
    has_kwarg: bool
    is_async: bool


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionSignatureSpec:
    args = node.args
    return FunctionSignatureSpec(
        node.name,
        len(args.posonlyargs),
        tuple(arg.arg for arg in (*args.posonlyargs, *args.args)),
        len(args.defaults),
        args.vararg is not None,
        frozenset(arg.arg for arg in args.kwonlyargs),
        frozenset(
            arg.arg for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
            if default is not None
        ),
        args.kwarg is not None,
        isinstance(node, ast.AsyncFunctionDef),
    )


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{_qualified_name(node.value, aliases)}.{node.attr}"
    return ""


def _binding(node: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]) -> str:
    for decorator in node.decorator_list:
        name = _qualified_name(decorator, aliases).removeprefix("builtins.")
        if name in {"staticmethod", "classmethod", "property"}:
            return "getter" if name == "property" else name
        if isinstance(decorator, ast.Attribute) and decorator.attr in {
            "getter", "setter", "deleter",
        }:
            return decorator.attr
    return "instance"


@dataclass(frozen=True)
class _PublicAPI:
    classes: frozenset[str]
    signatures: dict[tuple[str, str], FunctionSignatureSpec]
    bindings: dict[tuple[str, str], str]


def _public_api(tree: ast.Module) -> _PublicAPI:
    classes: set[str] = set()
    signatures: dict[tuple[str, str], FunctionSignatureSpec] = {}
    bindings: dict[tuple[str, str], str] = {}
    aliases: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                aliases[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                aliases[alias.asname or alias.name] = alias.name
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                key = (node.name, "function")
                signatures[key] = _signature(node)
                bindings[key] = "function"
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            classes.add(node.name)
            if not node.bases and not node.keywords:
                key = (f"{node.name}.__init__", "method")
                signatures[key] = FunctionSignatureSpec(
                    "__init__", 0, ("self",), 0, False, frozenset(), frozenset(), False, False,
                )
                bindings[key] = "instance"
            for member in node.body:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if member.name.startswith("_") and member.name != "__init__":
                    continue
                binding = _binding(member, aliases)
                role = binding if binding in {"getter", "setter", "deleter"} else "method"
                key = (f"{node.name}.{member.name}", role)
                signatures[key] = _signature(member)
                bindings[key] = binding
    return _PublicAPI(frozenset(classes), signatures, bindings)


def _compatible(before: FunctionSignatureSpec, after: FunctionSignatureSpec) -> bool:
    old_count, new_count = len(before.arg_names), len(after.arg_names)
    if before.is_async != after.is_async or after.arg_names[:old_count] != before.arg_names:
        return False
    if min(after.posonly_count, old_count) > before.posonly_count:
        return False
    if before.has_vararg and (not after.has_vararg or new_count != old_count):
        return False
    if before.has_kwarg and not after.has_kwarg:
        return False
    old_default_start = old_count - before.defaults_count
    new_default_start = new_count - after.defaults_count
    if before.defaults_count and new_default_start > old_default_start:
        return False
    if new_count > old_count and new_default_start > old_count:
        return False
    if not before.kwonly_names.issubset(after.kwonly_names):
        return False
    if not before.kw_defaults_present.issubset(after.kw_defaults_present):
        return False
    added_keywords = after.kwonly_names - before.kwonly_names
    return added_keywords.issubset(after.kw_defaults_present)


def verify_public_api_compatibility(file_path: str, pre_source: str, post_source: str) -> None:
    """Reject deletion, binding changes or narrowing of declared public calls.

    A positional-only parameter may become keyword-capable. Default values may
    change but cannot become mandatory. Syntax errors are left to the existing
    sandbox syntax-failure path, matching the other structural guards.
    """
    try:
        before = _public_api(ast.parse(pre_source, filename=file_path))
        after = _public_api(ast.parse(post_source, filename=file_path))
    except SyntaxError:
        return

    removed = before.classes - after.classes
    if removed:
        raise OverfitPolicyError(
            file_path=file_path, message=f"API contract: public class removed: {min(removed)}",
            reason_code="api_contract",
        )
    for key, signature in before.signatures.items():
        post_signature = after.signatures.get(key)
        if (
            post_signature is None
            or before.bindings[key] != after.bindings.get(key)
            or not _compatible(signature, post_signature)
        ):
            raise OverfitPolicyError(
                file_path=file_path,
                message=f"API contract: public call changed incompatibly: {key[0]}",
                reason_code="api_contract",
            )

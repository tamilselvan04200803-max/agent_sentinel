"""M8 Anti-Overfitting, Anti-Poisoning & Anti-Reflection Guard."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.verification.patch_minimizer import check_ast_bloat_and_debug_residue

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

# Unicode BiDi Trojan Source characters & Zero-Width characters
BIDI_AND_ZERO_WIDTH = frozenset({
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200b", "\u200c", "\u200d", "\ufeff",
})

FORBIDDEN_MODULES = frozenset({"pytest", "_pytest", "ctypes"})
FORBIDDEN_CALL_NAMES = frozenset({"_getframe", "stack", "currentframe", "_exit"})

_NO_VALUE = object()


def _is_nontrivial_constant(val: object) -> bool:
    if isinstance(val, bool):
        return False
    if isinstance(val, str):
        return len(val.strip()) >= 3
    if isinstance(val, (int, float)):
        return val not in {-1, 0, 1, 2}
    return False


def _eval_static_constant(node: ast.AST) -> object:
    """Evaluate static constant expressions safely without eval().

    Handles Constant, static string/bytes/numeric Add (+), UnaryOp (-),
    bytes.decode(), and str.join([...]).
    Returns _NO_VALUE when the expression cannot be statically resolved.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_static_constant(node.left)
        right = _eval_static_constant(node.right)
        if left is not _NO_VALUE and right is not _NO_VALUE:
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            if isinstance(left, bytes) and isinstance(right, bytes):
                return left + right
            if (
                isinstance(left, (int, float))
                and isinstance(right, (int, float))
                and not isinstance(left, bool)
                and not isinstance(right, bool)
            ):
                return left + right
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        val = _eval_static_constant(node.operand)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return -val
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            target = _eval_static_constant(node.func.value)
            if isinstance(target, bytes):
                try:
                    return target.decode("utf-8", errors="replace")
                except (ValueError, UnicodeDecodeError):
                    pass
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            sep = _eval_static_constant(node.func.value)
            if isinstance(sep, str) and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, (ast.List, ast.Tuple)):
                    parts: list[str] = []
                    all_str = True
                    for elt in arg0.elts:
                        part = _eval_static_constant(elt)
                        if isinstance(part, str):
                            parts.append(part)
                        else:
                            all_str = False
                            break
                    if all_str:
                        return sep.join(parts)
    return _NO_VALUE


def _collect_ast_identifiers(tree: ast.AST) -> set[str]:
    """Collect all identifier strings defined or referenced in the AST."""
    ids: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            ids.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            ids.add(node.name)
        elif isinstance(node, ast.Attribute):
            ids.add(node.attr)
        elif isinstance(node, ast.alias):
            ids.add(node.name)
            if node.asname:
                ids.add(node.asname)
        elif isinstance(node, ast.arg):  # noqa: SIM114
            ids.add(node.arg)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            ids.add(node.arg)
    return ids


def _collect_reflection_calls(tree: ast.AST) -> set[str]:
    """Collect call names and attribute accesses related to reflection."""
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                calls.add(f"{func.value.id}.{func.attr}")
            elif isinstance(func, ast.Name):
                calls.add(func.id)
        elif (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and isinstance(node.value, ast.Name)
            and node.value.id in {"builtins", "__builtins__"}
        ):
            calls.add("builtins.__dict__")
    return calls


def _collect_imports(tree: ast.AST) -> set[str]:
    """Collect imported modules and symbols."""
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            imports.add(mod)
            for alias in node.names:
                imports.add(f"{mod}.{alias.name}")
    return imports


def check_patch_hygiene(
    raw_diff: str,
    post_patch_sources: Mapping[str, str],
    pre_patch_sources: Mapping[str, str] | None = None,
) -> None:
    """Verify patch hygiene: BiDi/zero-width chars, bare carriage returns,

    mixed tab-and-space indentation, and non-ASCII AST identifiers.
    """
    if raw_diff:
        normalized_diff = raw_diff.replace("\r\n", "\n")
        if "\r" in normalized_diff:
            raise OverfitPolicyError(
                message="Bare carriage return detected in patch (possible terminal spoofing)"
            )

        for line in normalized_diff.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                for ch in added_content:
                    if ch in BIDI_AND_ZERO_WIDTH:
                        raise OverfitPolicyError(
                            message=(
                                f"Forbidden Unicode BiDi/zero-width character "
                                f"U+{ord(ch):04X} detected in patch"
                            )
                        )
                stripped = added_content.lstrip(" \t")
                leading = added_content[: len(added_content) - len(stripped)]
                if " " in leading and "\t" in leading:
                    raise OverfitPolicyError(
                        message="Mixed tab-and-space leading indentation detected in patch"
                    )

    for file_path, src in post_patch_sources.items():
        for ch in src:
            if ch in BIDI_AND_ZERO_WIDTH:
                raise OverfitPolicyError(
                    message=(
                        f"Forbidden Unicode BiDi/zero-width character "
                        f"U+{ord(ch):04X} in {file_path}"
                    ),
                    file_path=file_path,
                )

        if not file_path.endswith(".py"):
            continue

        pre_src = (pre_patch_sources or {}).get(file_path, "")
        pre_ids: set[str] = set()
        if pre_src:
            try:
                pre_tree = ast.parse(pre_src, filename=file_path)
                pre_ids = _collect_ast_identifiers(pre_tree)
            except SyntaxError:
                pass
        try:
            post_tree = ast.parse(src, filename=file_path)
            post_ids = _collect_ast_identifiers(post_tree)
        except SyntaxError:
            continue

        for ident in post_ids:
            if ident not in pre_ids and not ident.isascii():
                raise OverfitPolicyError(
                    message=(
                        f"Newly introduced non-ASCII identifier detected: "
                        f"{ident!r} in {file_path}"
                    ),
                    file_path=file_path,
                )


def check_forbidden_reflection(
    pre_patch_sources: Mapping[str, str],
    post_patch_sources: Mapping[str, str],
) -> None:
    """Verify that the patch introduces no reflection or harness monkey-patching."""
    for file_path, post_src in post_patch_sources.items():
        if not file_path.endswith(".py"):
            continue
        pre_src = pre_patch_sources.get(file_path, "")
        pre_calls: set[str] = set()
        pre_imports: set[str] = set()
        if pre_src:
            try:
                pre_tree = ast.parse(pre_src, filename=file_path)
                pre_calls = _collect_reflection_calls(pre_tree)
                pre_imports = _collect_imports(pre_tree)
            except SyntaxError:
                pass
        try:
            post_tree = ast.parse(post_src, filename=file_path)
        except SyntaxError:
            continue

        for node in ast.walk(post_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    is_forbidden = (
                        name in FORBIDDEN_MODULES
                        or name.startswith(("pytest.", "_pytest.", "ctypes.", "unittest.mock"))
                    )
                    if is_forbidden and name not in pre_imports:
                        raise OverfitPolicyError(
                            message=f"Forbidden module import detected: {name}",
                            file_path=file_path,
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                is_forbidden_mod = (
                    mod in FORBIDDEN_MODULES
                    or mod.startswith(("pytest.", "_pytest.", "ctypes.", "unittest.mock"))
                )
                if is_forbidden_mod and mod not in pre_imports:
                    raise OverfitPolicyError(
                        message=f"Forbidden module import detected: {mod}",
                        file_path=file_path,
                    )
                if mod == "unittest":
                    for alias in node.names:
                        if alias.name == "mock" and "unittest.mock" not in pre_imports:
                            raise OverfitPolicyError(
                                message="Forbidden module import detected: unittest.mock",
                                file_path=file_path,
                            )
                if mod == "sys":
                    for alias in node.names:
                        if alias.name == "_getframe" and "sys._getframe" not in pre_calls:
                            raise OverfitPolicyError(
                                message="Forbidden call/import detected: sys._getframe",
                                file_path=file_path,
                            )
                if mod == "inspect":
                    for alias in node.names:
                        call_name = f"inspect.{alias.name}"
                        if alias.name in ("stack", "currentframe") and call_name not in pre_calls:
                            raise OverfitPolicyError(
                                message=f"Forbidden call/import detected: {call_name}",
                                file_path=file_path,
                            )
                if mod == "os":
                    for alias in node.names:
                        if alias.name == "_exit" and "os._exit" not in pre_calls:
                            raise OverfitPolicyError(
                                message="Forbidden call/import detected: os._exit",
                                file_path=file_path,
                            )
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    full = f"{func.value.id}.{func.attr}"
                    is_refl = full in {
                        "sys._getframe",
                        "inspect.stack",
                        "inspect.currentframe",
                        "os._exit",
                    }
                    if is_refl and full not in pre_calls:
                        raise OverfitPolicyError(
                            message=f"Forbidden reflection call detected: {full}",
                            file_path=file_path,
                        )
                elif isinstance(func, ast.Name) and func.id in FORBIDDEN_CALL_NAMES:
                    if func.id not in pre_calls:
                        raise OverfitPolicyError(
                            message=f"Forbidden reflection call detected: {func.id}",
                            file_path=file_path,
                        )
            elif (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in {"builtins", "__builtins__"}
                and "builtins.__dict__" not in pre_calls
            ):
                raise OverfitPolicyError(
                    message="Forbidden reflection access detected: builtins.__dict__",
                    file_path=file_path,
                )


def extract_test_assertion_literals(
    workspace_root: Path,
) -> frozenset[str | int | float]:
    """Collect non-trivial literals from Assert and parametrize nodes in test files."""
    seen: set[Path] = set()
    literals: set[str | int | float] = set()

    for pattern in ("test_*.py", "*_test.py"):
        for p in workspace_root.rglob(pattern):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            try:
                src = p.read_text(encoding="utf-8")
            except OSError:
                continue
            try:
                tree = ast.parse(src, filename=str(p))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    for sub in ast.walk(node.test):
                        if isinstance(sub, ast.Constant):
                            v = sub.value
                            if isinstance(v, (str, int, float)) and _is_nontrivial_constant(v):
                                literals.add(v)
                elif isinstance(node, ast.Call):
                    func = node.func
                    is_param = (
                        isinstance(func, ast.Attribute)
                        and func.attr == "parametrize"
                    )
                    if is_param:
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Constant):
                                v = sub.value
                                if isinstance(v, (str, int, float)) and _is_nontrivial_constant(v):
                                    literals.add(v)
    return frozenset(literals)


def _collect_branch_test_dumps(tree: ast.AST) -> set[str]:
    dumps: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.IfExp)):
            dumps.add(
                ast.dump(node.test, annotate_fields=False, include_attributes=False)
            )
        elif isinstance(node, ast.Match):
            dumps.add(
                ast.dump(
                    node.subject, annotate_fields=False, include_attributes=False
                )
            )
    return dumps


def _collect_all_folded_constants(tree: ast.AST) -> set[object]:
    vals: set[object] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            vals.add(node.value)
        folded = _eval_static_constant(node)
        if folded is not _NO_VALUE:
            vals.add(folded)
    return vals


def verify_not_overfitted(
    workspace_root: Path,
    pre_patch_sources: Mapping[str, str],
    post_patch_sources: Mapping[str, str],
    test_literals: frozenset[str | int | float] | None = None,
    raw_diff: str = "",
) -> None:
    """Raise OverfitPolicyError if post-patch violates anti-overfitting rules.

    Checks:
    1. Patch hygiene (BiDi/zero-width chars, bare carriage returns, mixed indentation, non-ASCII).
    2. Forbidden reflection and test-harness monkey-patching.
    3. New conditional branches or dictionary tables comparing against folded test literals.
    """
    check_patch_hygiene(raw_diff, post_patch_sources, pre_patch_sources)
    check_forbidden_reflection(pre_patch_sources, post_patch_sources)

    literals: frozenset[str | int | float]
    if test_literals is None:
        literals = extract_test_assertion_literals(workspace_root)
    else:
        literals = test_literals

    if not literals:
        return

    for file_path, post_src in post_patch_sources.items():
        if not file_path.endswith(".py"):
            continue
        pre_src = pre_patch_sources.get(file_path, "")

        try:
            pre_tree = (
                ast.parse(pre_src, filename=file_path)
                if pre_src
                else ast.parse("", filename=file_path)
            )
        except SyntaxError:
            continue
        try:
            post_tree = ast.parse(post_src, filename=file_path)
        except SyntaxError:
            continue

        check_ast_bloat_and_debug_residue(file_path, pre_src, post_src)

        pre_dumps = _collect_branch_test_dumps(pre_tree)
        pre_constants = _collect_all_folded_constants(pre_tree)

        for node in ast.walk(post_tree):
            test_expr: ast.AST | None = None
            if isinstance(node, (ast.If, ast.IfExp)):
                test_expr = node.test
            elif isinstance(node, ast.Match):
                test_expr = node.subject
            else:
                continue

            dump = ast.dump(
                test_expr, annotate_fields=False, include_attributes=False
            )
            if dump in pre_dumps:
                continue

            if isinstance(node, ast.Match):
                for case in node.cases:
                    if isinstance(case.pattern, ast.MatchValue):
                        val = _eval_static_constant(case.pattern.value)
                        if (
                            val is not _NO_VALUE
                            and not isinstance(val, bool)
                            and val in literals
                            and val not in pre_constants
                        ):
                            raise OverfitPolicyError(
                                leaked_literal=str(val),
                                file_path=file_path,
                            )

            for sub in ast.walk(test_expr):
                if isinstance(sub, ast.Compare):
                    has_eq_or_in = any(
                        isinstance(op, (ast.Eq, ast.In)) for op in sub.ops
                    )
                    if not has_eq_or_in:
                        continue

                    candidate_nodes: list[ast.AST] = [sub.left]
                    for comp in sub.comparators:
                        candidate_nodes.append(comp)
                        if isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                            candidate_nodes.extend(comp.elts)

                    for cand in candidate_nodes:
                        val = _eval_static_constant(cand)
                        if (
                            val is not _NO_VALUE
                            and not isinstance(val, bool)
                            and val in literals
                            and val not in pre_constants
                        ):
                            raise OverfitPolicyError(
                                leaked_literal=str(val),
                                file_path=file_path,
                            )

        for node in ast.walk(post_tree):
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if k is not None:
                        val = _eval_static_constant(k)
                        if (
                            val is not _NO_VALUE
                            and not isinstance(val, bool)
                            and val in literals
                            and val not in pre_constants
                        ):
                            raise OverfitPolicyError(
                                leaked_literal=str(val),
                                file_path=file_path,
                            )

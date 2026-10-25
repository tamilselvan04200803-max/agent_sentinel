"""M10 — SWE-Smith/UTBoost AST Patch Mutation Adequacy Probe.

This module generates mutation variants of a patch's AST to probe whether
the surrounding test suite is *adequate* — i.e. whether the tests would
detect a semantically broken version of the patch.

Three mutation rules are applied at every applicable AST node:

* **Comparison Flip** — invert comparison operators (``==``↔``!=``,
  ``<``↔``>=``, ``>``↔``<=``, ``in``↔``not in``, ``is``↔``is not``).
* **Arithmetic Flip** — invert binary arithmetic operators (``+``↔``-``,
  ``*``↔``/``, ``%``↔``//``, ``<<``↔``>>``, ``&``↔``|``).
* **Boolean/Call Strip** — for ``BoolOp`` nodes, remove a single operand
  to collapse the expression; for ``Call`` nodes, strip all arguments so
  the call becomes a bare reference to the callable.
"""

from __future__ import annotations

import ast
import copy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Mutation rule tables
# ---------------------------------------------------------------------------

#: Maps a comparison operator AST class to its inverted counterpart.
COMPARISON_FLIPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.GtE,
    ast.Gt: ast.LtE,
    ast.LtE: ast.Gt,
    ast.GtE: ast.Lt,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}

#: Maps a binary operator AST class to its inverted counterpart.
ARITHMETIC_FLIPS: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.Div,
    ast.Div: ast.Mult,
    ast.Mod: ast.FloorDiv,
    ast.FloorDiv: ast.Mod,
    ast.LShift: ast.RShift,
    ast.RShift: ast.LShift,
    ast.BitOr: ast.BitAnd,
    ast.BitAnd: ast.BitOr,
}

# ---------------------------------------------------------------------------
# Mutant result type
# ---------------------------------------------------------------------------

#: All rule names in canonical order.
MUTATION_RULES: tuple[str, ...] = (
    "comparison_flip",
    "arithmetic_flip",
    "boolean_call_strip",
)


@dataclass(frozen=True)
class PatchMutant:
    """A single mutated variant of a source tree.

    Attributes
    ----------
    rule:
        Canonical name of the mutation rule that produced this mutant.
    description:
        Human-readable explanation of *what* was mutated and *where*.
    mutant_id:
        Deterministic identifier — ``f"{rule}:{node_id}:{line}:{col}"``.
    source:
        The unparsed source text of the mutated AST, guaranteed to end
        with a trailing newline.
    """

    rule: str
    description: str
    mutant_id: str
    source: str = field(repr=False)


# ---------------------------------------------------------------------------
# AST mutation engine
# ---------------------------------------------------------------------------

def _node_id(node: ast.AST) -> str:
    """Return a short, human-readable identifier for *node* (class name)."""
    return type(node).__name__


def _position(node: ast.AST) -> tuple[int, int]:
    """Return ``(lineno, col_offset)`` for *node*, defaulting to ``(0, 0)``."""
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _try_unparse(tree: ast.AST) -> str | None:
    """Attempt ``ast.unparse`` on *tree*, returning ``None`` on failure."""
    try:
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except Exception:
        return None


def _generate_comparison_flips(
    tree: ast.AST,
    source_path: str,
) -> list[PatchMutant]:
    """Flip every comparison operator in *tree* one at a time."""
    mutants: list[PatchMutant] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for idx, op in enumerate(node.ops):
            flipped = COMPARISON_FLIPS.get(type(op))
            if flipped is None:
                continue
            # Deep-copy the tree so mutations are independent.
            clone = copy.deepcopy(tree)
            # Re-walk the clone to find the matching Compare node + index.
            target = _find_compare_by_position(clone, node)
            if target is None:
                continue
            target.ops[idx] = flipped()
            line, col = _position(node)
            new_source = _try_unparse(clone)
            if new_source is None:
                continue
            if not new_source.endswith("\n"):
                new_source += "\n"
            mutant_id = f"comparison_flip:{_node_id(node)}:{line}:{col}:{idx}"
            description = (
                f"Flip comparison {_op_name(op)} -> {_op_name(flipped())} "
                f"at {source_path}:{line}:{col} (operand index {idx})"
            )
            mutants.append(
                PatchMutant(
                    rule="comparison_flip",
                    description=description,
                    mutant_id=mutant_id,
                    source=new_source,
                ),
            )
    return mutants


def _find_compare_by_position(
    clone: ast.AST,
    original: ast.Compare,
) -> ast.Compare | None:
    """Locate the ``Compare`` node inside *clone* that matches *original*.

    Matching is done by line number and column offset, since node identity
    is not preserved after ``deepcopy``.
    """
    line, col = _position(original)
    for candidate in ast.walk(clone):
        if isinstance(candidate, ast.Compare):
            c_line, c_col = _position(candidate)
            if c_line == line and c_col == col:
                return candidate
    return None


def _op_name(op: ast.cmpop | ast.operator | ast.unaryop) -> str:
    """Return a short symbolic name for an operator AST instance."""
    return type(op).__name__.replace("Mult", "*").replace("Add", "+")


def _generate_arithmetic_flips(
    tree: ast.AST,
    source_path: str,
) -> list[PatchMutant]:
    """Flip every binary operator in *tree* one at a time."""
    mutants: list[PatchMutant] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        for flipped_cls in [ARITHMETIC_FLIPS.get(type(node.op))]:
            if flipped_cls is None:
                continue
            clone = copy.deepcopy(tree)
            target = _find_binop_by_position(clone, node)
            if target is None:
                continue
            target.op = flipped_cls()
            line, col = _position(node)
            new_source = _try_unparse(clone)
            if new_source is None:
                continue
            if not new_source.endswith("\n"):
                new_source += "\n"
            mutant_id = f"arithmetic_flip:{_node_id(node)}:{line}:{col}"
            description = (
                f"Flip binary op {_op_name(node.op)} -> {_op_name(flipped_cls())} "
                f"at {source_path}:{line}:{col}"
            )
            mutants.append(
                PatchMutant(
                    rule="arithmetic_flip",
                    description=description,
                    mutant_id=mutant_id,
                    source=new_source,
                ),
            )
    return mutants


def _find_binop_by_position(
    clone: ast.AST,
    original: ast.BinOp,
) -> ast.BinOp | None:
    """Locate the ``BinOp`` node inside *clone* matching *original*'s position."""
    line, col = _position(original)
    for candidate in ast.walk(clone):
        if isinstance(candidate, ast.BinOp):
            c_line, c_col = _position(candidate)
            if c_line == line and c_col == col:
                return candidate
    return None


def _generate_boolean_call_strips(
    tree: ast.AST,
    source_path: str,
) -> list[PatchMutant]:
    """Generate BoolOp operand-stripping and Call argument-stripping mutants."""
    mutants: list[PatchMutant] = []
    mutants.extend(_generate_boolop_strips(tree, source_path))
    mutants.extend(_generate_call_strips(tree, source_path))
    return mutants


def _generate_boolop_strips(
    tree: ast.AST,
    source_path: str,
) -> list[PatchMutant]:
    """For each ``BoolOp`` with >1 operand, remove one operand at a time."""
    mutants: list[PatchMutant] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.BoolOp):
            continue
        if len(node.values) <= 1:
            continue
        for idx in range(len(node.values)):
            clone = copy.deepcopy(tree)
            target = _find_boolop_by_position(clone, node)
            if target is None:
                continue
            # Remove the operand at *idx*.
            target.values.pop(idx)
            if len(target.values) == 1:
                # A BoolOp cannot have a single operand in valid AST;
                # unwrap to the remaining value.
                parent = _find_parent(clone, target)
                if parent is not None:
                    _replace_in_parent(parent, target, target.values[0])
            line, col = _position(node)
            new_source = _try_unparse(clone)
            if new_source is None:
                continue
            if not new_source.endswith("\n"):
                new_source += "\n"
            mutant_id = f"boolean_call_strip:BoolOp:{line}:{col}:{idx}"
            op_name = type(node.op).__name__
            description = (
                f"Strip operand {idx} from BoolOp ({op_name}) "
                f"at {source_path}:{line}:{col}"
            )
            mutants.append(
                PatchMutant(
                    rule="boolean_call_strip",
                    description=description,
                    mutant_id=mutant_id,
                    source=new_source,
                ),
            )
    return mutants


def _find_boolop_by_position(
    clone: ast.AST,
    original: ast.BoolOp,
) -> ast.BoolOp | None:
    """Locate the ``BoolOp`` node inside *clone* matching *original*'s position."""
    line, col = _position(original)
    for candidate in ast.walk(clone):
        if isinstance(candidate, ast.BoolOp):
            c_line, c_col = _position(candidate)
            if c_line == line and c_col == col:
                return candidate
    return None


def _generate_call_strips(
    tree: ast.AST,
    source_path: str,
) -> list[PatchMutant]:
    """For each ``Call`` with arguments, strip all arguments."""
    mutants: list[PatchMutant] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not node.args and not node.keywords:
            continue
        clone = copy.deepcopy(tree)
        target = _find_call_by_position(clone, node)
        if target is None:
            continue
        target.args = []
        target.keywords = []
        line, col = _position(node)
        new_source = _try_unparse(clone)
        if new_source is None:
            continue
        if not new_source.endswith("\n"):
            new_source += "\n"
        mutant_id = f"boolean_call_strip:Call:{line}:{col}"
        description = (
            f"Strip arguments from Call at {source_path}:{line}:{col}"
        )
        mutants.append(
            PatchMutant(
                rule="boolean_call_strip",
                description=description,
                mutant_id=mutant_id,
                source=new_source,
            ),
        )
    return mutants


def _find_call_by_position(
    clone: ast.AST,
    original: ast.Call,
) -> ast.Call | None:
    """Locate the ``Call`` node inside *clone* matching *original*'s position."""
    line, col = _position(original)
    for candidate in ast.walk(clone):
        if isinstance(candidate, ast.Call):
            c_line, c_col = _position(candidate)
            if c_line == line and c_col == col:
                return candidate
    return None


def _find_parent(tree: ast.AST, target: ast.AST) -> ast.AST | None:
    """Return the parent node of *target* within *tree*, or ``None``."""
    for node in ast.walk(tree):
        for field_name in _ast_field_names(node):
            value = getattr(node, field_name, None)
            if value is target:
                return node
            if isinstance(value, list) and any(
                item is target for item in value
            ):
                return node
    return None


def _ast_field_names(node: ast.AST) -> list[str]:
    """Return the list of field names for *node* that can hold child nodes."""
    return [name for name, _ in ast.iter_fields(node)]


def _replace_in_parent(parent: ast.AST, old: ast.AST, new: ast.AST) -> None:
    """Replace ``old`` with ``new`` in one of ``parent``'s child slots."""
    for field_name, _ in ast.iter_fields(parent):
        value = getattr(parent, field_name, None)
        if value is old:
            setattr(parent, field_name, new)
            return
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is old:
                    value[i] = new
                    return
    raise RuntimeError("Target node not found in parent")


#: Dispatch table mapping rule name → generator callable.
_RULE_GENERATORS: dict[str, Callable[[ast.AST, str], list[PatchMutant]]] = {
    "comparison_flip": _generate_comparison_flips,
    "arithmetic_flip": _generate_arithmetic_flips,
    "boolean_call_strip": _generate_boolean_call_strips,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_patch_mutants(
    source: str,
    source_path: str = "<unknown>",
) -> list[PatchMutant]:
    """Generate all mutation adequacy probes for *source*.

    Each applicable AST node is mutated exactly once per rule, producing
    an independent ``PatchMutant`` whose ``source`` is the fully unparsed
    mutated tree.

    Parameters
    ----------
    source:
        Python source code text to mutate.
    source_path:
        File path used in mutant descriptions for traceability.

    Returns
    -------
    list of :class:`PatchMutant`
        All generated mutants, ordered by rule then by source position.
        Returns an empty list if *source* cannot be parsed or contains no
        applicable mutation sites.
    """
    try:
        tree = ast.parse(source, filename=source_path)
    except SyntaxError:
        return []

    mutants: list[PatchMutant] = []
    for rule_name in MUTATION_RULES:
        generator = _RULE_GENERATORS[rule_name]
        mutants.extend(generator(tree, source_path))
    return mutants

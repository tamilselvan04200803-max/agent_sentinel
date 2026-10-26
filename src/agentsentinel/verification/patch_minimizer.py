"""M9 — AST Cyclomatic Bloat Guard, Debug-Residue Ban & Zeller Delta-Debugging Hunk Pruner.

This module provides three facilities for the anti-overfitting verification pipeline:

* ``compute_cyclomatic_complexity`` — a pure-AST McCabe-style decision-point counter.
* ``check_ast_bloat_and_debug_residue`` — raises ``OverfitPolicyError`` if a repair
  patch introduces a debugger breakpoint residue or inflates cyclomatic complexity
  beyond an allowed delta.
* ``generate_minimal_hunk_subsets`` — a deterministic Zeller-style ``ddmin``
  candidate generator that emits minimal single-hunk and double-hunk sub-diffs.
"""

from __future__ import annotations

import ast
import re
from collections import Counter

from agentsentinel.domain.exceptions import OverfitPolicyError


def compute_cyclomatic_complexity(tree: ast.AST) -> int:
    """Return the McCabe cyclomatic complexity of ``tree`` as ``1`` plus the
    total count of decision points.

    Decision points counted: ``If``, ``For``, ``AsyncFor``, ``While``,
    ``ExceptHandler``, ``With``, ``AsyncWith``, ``Assert``, ``IfExp``,
    ``MatchCase``, and ``comprehension`` (each comprehension also adds
    ``len(node.ifs)`` for its inline ``if`` filters).

    For ``BoolOp`` (boolean ``and``/``or``) expressions, ``len(node.values) - 1``
    is added to capture the additional decision edges.
    """
    cc = 1
    for node in ast.walk(tree):
        if isinstance(node, ast.If):  # noqa: SIM114
            cc += 1
        elif isinstance(node, (ast.For, ast.AsyncFor)):  # noqa: SIM114
            cc += 1
        elif isinstance(node, ast.While):  # noqa: SIM114
            cc += 1
        elif isinstance(node, ast.ExceptHandler):  # noqa: SIM114
            cc += 1
        elif isinstance(node, (ast.With, ast.AsyncWith)):  # noqa: SIM114
            cc += 1
        elif isinstance(node, ast.Assert):  # noqa: SIM114
            cc += 1
        elif isinstance(node, ast.IfExp):  # noqa: SIM114
            cc += 1
        elif isinstance(node, ast.match_case):  # noqa: SIM114
            cc += 1
        elif isinstance(node, ast.comprehension):
            cc += 1
            cc += len(node.ifs)
        elif isinstance(node, ast.BoolOp):
            cc += len(node.values) - 1
    return cc


def _block_outcomes(body: list[ast.stmt]) -> set[str]:
    """Bounded control-flow outcomes, without descending into nested scopes."""
    outcomes = {"fallthrough"}
    for statement in body:
        if "fallthrough" not in outcomes:
            break
        current = {"fallthrough"}
        if isinstance(statement, ast.Raise):
            current = {"exit"}
        elif isinstance(statement, ast.Return):
            meaningful = statement.value is not None and not (
                isinstance(statement.value, ast.Constant) and statement.value.value is None
            )
            current = {"exit" if meaningful else "swallow"}
        elif isinstance(statement, ast.If):
            current = _block_outcomes(statement.body) | _block_outcomes(statement.orelse)
        outcomes = (outcomes - {"fallthrough"}) | current
    return outcomes


class _HazardCollector(ast.NodeVisitor):
    """Count hazards by lexical scope and resolve direct import aliases."""

    def __init__(self) -> None:
        self.scope: tuple[str, ...] = ()
        self.aliases: dict[str, str] = {}
        self.debug: Counter[tuple[str, ...]] = Counter()
        self.handlers: Counter[tuple[str, ...]] = Counter()
        self.occurrences: Counter[tuple[str, ...]] = Counter()

    def _qualified(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self._qualified(node.value)}.{node.attr}"
        return ""

    def _visit_scope(self, node: ast.AST, name: str, body: list[ast.stmt]) -> None:
        previous_scope, previous_aliases = self.scope, self.aliases
        key = (*self.scope, name)
        occurrence = self.occurrences[key]
        self.occurrences[key] += 1
        self.scope = (*key, str(occurrence))
        self.aliases = previous_aliases.copy()
        # Bind imports in this scope only; child functions have their own aliases.
        pending: list[ast.AST] = list(body)
        while pending:
            child = pending.pop()
            if isinstance(child, ast.Import):
                for alias in child.names:
                    self.aliases[alias.asname or alias.name] = alias.name
            elif isinstance(child, ast.ImportFrom):
                for alias in child.names:
                    self.aliases[alias.asname or alias.name] = f"{child.module}.{alias.name}"
            elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                pending.extend(ast.iter_child_nodes(child))
        self.generic_visit(node)
        self.scope, self.aliases = previous_scope, previous_aliases

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_scope(node, "<module>", node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope(node, node.name, node.body)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope(node, node.name, node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scope(node, node.name, node.body)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._qualified(node.func)
        if name in {
            "breakpoint", "builtins.breakpoint", "pdb.set_trace", "ipdb.set_trace",
        }:
            self.debug[(*self.scope, name.removeprefix("builtins."))] += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        broad = any(
            item is not None and self._qualified(item) in {
                "Exception", "BaseException", "builtins.Exception", "builtins.BaseException",
            }
            for item in types
        )
        if node.type is None or (broad and _block_outcomes(node.body) != {"exit"}):
            self.handlers[(*self.scope, ast.dump(node, include_attributes=False))] += 1
        self.generic_visit(node)


def check_ast_bloat_and_debug_residue(
    file_path: str,
    pre_source: str,
    post_source: str,
    max_cc_delta: int = 5,
) -> None:
    """Raise ``OverfitPolicyError`` if ``post_source`` leaks debug residue or
    inflates cyclomatic complexity beyond ``max_cc_delta``.

    If either source fails to parse with ``ast.parse``, the call returns early
    without raising — downstream syntax-check phases handle malformed sources.
    """
    try:
        pre_tree = ast.parse(pre_source, filename=file_path)
    except SyntaxError:
        return
    try:
        post_tree = ast.parse(post_source, filename=file_path)
    except SyntaxError:
        return

    pre_hazards, post_hazards = _HazardCollector(), _HazardCollector()
    pre_hazards.visit(pre_tree)
    post_hazards.visit(post_tree)
    leaked = post_hazards.debug - pre_hazards.debug
    if leaked:
        raise OverfitPolicyError(
            leaked_literal="breakpoint/set_trace",
            file_path=file_path,
            message="Debug residue (breakpoint/set_trace) forbidden in repair patch",
        )

    if post_hazards.handlers - pre_hazards.handlers:
        raise OverfitPolicyError(
            file_path=file_path,
            message="New bare or swallowing exception handler forbidden in repair patch",
        )

    cc_delta = compute_cyclomatic_complexity(post_tree) - compute_cyclomatic_complexity(pre_tree)
    if cc_delta > max_cc_delta:
        raise OverfitPolicyError(
            leaked_literal=f"cc_delta={cc_delta}",
            file_path=file_path,
            message=(
                f"Excessive cyclomatic complexity bloat: +{cc_delta} "
                f"exceeds max_cc_delta={max_cc_delta}"
            ),
        )


def _split_diff_sections(raw_diff: str) -> list[list[str]]:
    """Split a normalized unified diff into per-file sections.

    Each returned section is a list of lines belonging to that file, including
    its ``---`` / ``+++`` header and all ``@@`` hunk blocks.  A section begins
    at a ``diff --git`` line or, in the absence of that marker, at a ``---``
    header line.
    """
    sections: list[list[str]] = []
    current: list[str] = []
    remaining_old = remaining_new = 0

    for line in raw_diff.splitlines():
        is_diff_git = line.startswith("diff --git ")
        is_triple_dash = line.startswith("--- ")
        header = _HUNK_HEADER_RE.match(line)
        in_hunk = remaining_old > 0 or remaining_new > 0
        has_diff_git_prefix = bool(current) and current[0].startswith("diff --git ")
        # Counts disambiguate removed source lines beginning with "--- ".
        starts_plain_file = is_triple_dash and not in_hunk and not has_diff_git_prefix
        # A second plain file follows a completed hunk, even after a git prefix.
        starts_plain_file |= is_triple_dash and not in_hunk and any(
            part.startswith("@@ ") for part in current
        )
        if (is_diff_git or starts_plain_file) and current:
            sections.append(current)
            current = []
            remaining_old = remaining_new = 0
        if header:
            remaining_old = int(header.group(2) or "1")
            remaining_new = int(header.group(4) or "1")
        elif in_hunk:
            remaining_old -= int(not line or line[0] in (" ", "-"))
            remaining_new -= int(not line or line[0] in (" ", "+"))
        current.append(line)
    if current:
        sections.append(current)
    return sections


def _split_hunks(section_lines: list[str]) -> tuple[list[str], list[list[str]]]:
    """Split a file section into ``(header_lines, hunks)``.

    ``header_lines`` are the lines before the first ``@@`` marker (the
    ``diff --git``, ``---``, ``+++`` and any other metadata).  ``hunks`` is the
    ordered list of ``@@ ... @@`` body line-groups, each including its header
    line.
    """
    header_lines: list[str] = []
    hunks: list[list[str]] = []
    current_hunk: list[str] = []
    in_hunk = False

    for line in section_lines:
        if line.startswith("@@"):
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = [line]
            in_hunk = True
        elif in_hunk:
            current_hunk.append(line)
        else:
            header_lines.append(line)

    if current_hunk:
        hunks.append(current_hunk)
    return header_lines, hunks


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def _build_diff(header_lines: list[str], kept_hunks: list[list[str]]) -> str:
    """Render selected hunks with offsets relative to their own prior edits."""
    lines = header_lines.copy()
    delta = 0
    for hunk in kept_hunks:
        match = _HUNK_HEADER_RE.fullmatch(hunk[0])
        if match is None:
            raise ValueError("Invalid unified diff hunk header")
        body = [line if line else " " for line in hunk[1:]]
        old_count = sum(line[0] in (" ", "-") for line in body)
        new_count = sum(line[0] in (" ", "+") for line in body)
        old_start = int(match.group(1))
        new_start = old_start + delta + (old_count == 0) - (new_count == 0)
        lines.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@{match.group(5)}")
        lines.extend(body)
        delta += new_count - old_count
    return "\n".join(lines) + "\n"


def generate_minimal_hunk_subsets(raw_diff: str) -> list[str]:
    """Generate deterministic Zeller-style ``ddmin`` candidate sub-diffs.

    The diff is normalized (``\\r\\n`` → ``\\n``) and split into file sections,
    each of which is split into header lines and ``@@`` hunk blocks.

    Let ``N`` be the total number of hunks across all files:

    * If ``N <= 1``, the original diff (normalized, guaranteed to end in ``\\n``)
      is returned as the sole candidate.
    * If ``N >= 2``:

      (a) Each single-hunk diff — i.e. keeping exactly one hunk from its file
          section while dropping all others (file sections that become
          hunk-less are omitted).  Emitted in original hunk order.
      (b) When ``N > 2``: each ``(N - 1)``-hunk subset — i.e. dropping exactly
          one hunk at a time — emitted in original order.

    Every candidate string ends with a trailing ``\\n``.
    """
    normalized = raw_diff.replace("\r\n", "\n")
    sections = _split_diff_sections(normalized)

    # Flatten hunks across all sections, tracking (section_index, hunk_index).
    all_hunks: list[tuple[int, int, list[str]]] = []
    for sec_idx, section in enumerate(sections):
        _, hunks = _split_hunks(section)
        for hunk_idx, hunk in enumerate(hunks):
            all_hunks.append((sec_idx, hunk_idx, hunk))

    n = len(all_hunks)
    if n <= 1:
        result = normalized
        if not result.endswith("\n"):
            result += "\n"
        return [result]

    # Pre-compute per-section header lines and the full hunk list.
    section_headers: list[list[str]] = []
    section_hunk_counts: list[int] = []
    for section in sections:
        header_lines, hunks = _split_hunks(section)
        section_headers.append(header_lines)
        section_hunk_counts.append(len(hunks))

    def _build_from_keepers(keepers: set[int]) -> str | None:
        """Build a complete diff keeping only hunk indices in ``keepers``."""
        out_parts: list[str] = []
        global_idx = 0
        for sec_idx in range(len(sections)):
            kept_in_section: list[list[str]] = []
            for _ in range(section_hunk_counts[sec_idx]):
                if global_idx in keepers:
                    kept_in_section.append(all_hunks[global_idx][2])
                global_idx += 1
            if kept_in_section:
                diff = _build_diff(section_headers[sec_idx], kept_in_section)
                out_parts.append(diff)
        if not out_parts:
            return None
        body = "".join(out_parts)
        if not body.endswith("\n"):
            body += "\n"
        return body

    candidates: list[str] = []

    # (a) Single-hunk diffs in original order.
    for i in range(n):
        diff = _build_from_keepers({i})
        if diff is not None:
            candidates.append(diff)

    # (b) Drop-one-at-a-time: (N-1)-hunk subsets, in original order.
    if n > 2:
        for drop in range(n):
            keepers = {i for i in range(n) if i != drop}
            diff = _build_from_keepers(keepers)
            if diff is not None:
                candidates.append(diff)

    return list(dict.fromkeys(candidates))

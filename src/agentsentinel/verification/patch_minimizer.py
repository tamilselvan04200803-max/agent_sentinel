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


def _collect_debug_calls(tree: ast.AST) -> set[str]:
    """Collect debug-call signatures from ``tree``.

    Captures ``breakpoint()`` and ``<expr>.set_trace()`` where ``<expr>`` is the
    bare name ``pdb`` or ``ipdb``.
    """
    debug_calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "breakpoint":
            debug_calls.add("breakpoint")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "set_trace"
            and isinstance(func.value, ast.Name)
            and func.value.id in {"pdb", "ipdb"}
        ):
            debug_calls.add(f"{func.value.id}.set_trace")
    return debug_calls


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

    pre_debug = _collect_debug_calls(pre_tree)
    post_debug = _collect_debug_calls(post_tree)
    leaked = post_debug - pre_debug
    if leaked:
        raise OverfitPolicyError(
            leaked_literal="breakpoint/set_trace",
            file_path=file_path,
            message="Debug residue (breakpoint/set_trace) forbidden in repair patch",
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

    for line in raw_diff.split("\n"):
        is_diff_git = line.startswith("diff --git ")
        is_triple_dash = line.startswith("--- ")
        # ``---`` begins a new section only when there is no preceding
        # ``diff --git`` in the current section (i.e., the section has not
        # already been opened by a ``diff --git`` marker).
        has_diff_git_prefix = bool(current) and current[0].startswith("diff --git ")
        if (is_diff_git or (is_triple_dash and not has_diff_git_prefix)) and current:
            sections.append(current)
            current = []
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


def _build_diff(
    header_lines: list[str],
    kept_hunks: list[list[str]],
) -> str:
    """Assemble a single-file diff from its header and a subset of hunks."""
    lines: list[str] = []
    for header_line in header_lines:
        if not header_line.endswith("\n"):
            header_line += "\n"
        lines.append(header_line)
    for hunk in kept_hunks:
        for hunk_line in hunk:
            if not hunk_line.endswith("\n"):
                hunk_line += "\n"
            lines.append(hunk_line)
    body = "".join(lines)
    if not body.endswith("\n"):
        body += "\n"
    return body


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

    return candidates

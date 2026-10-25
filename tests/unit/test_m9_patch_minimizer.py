"""Unit tests for M9 — AST Cyclomatic Bloat Guard, Debug-Residue Ban & Zeller Hunk Pruner."""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.verification import (
    check_ast_bloat_and_debug_residue,
    compute_cyclomatic_complexity,
    generate_minimal_hunk_subsets,
)
from agentsentinel.verification.overfit_guard import verify_not_overfitted


def _ws() -> Path:
    return Path(tempfile.gettempdir())


def _two_hunk_diff() -> str:
    return (
        "diff --git a/foo.py b/foo.py\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def foo():\n"
        "-    return 1\n"
        "+    return 2\n"
        "@@ -10,3 +10,3 @@\n"
        " def bar():\n"
        "-    return 3\n"
        "+    return 4\n"
    )


def _three_hunk_diff() -> str:
    return (
        "diff --git a/foo.py b/foo.py\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def foo1():\n"
        "-    return 1\n"
        "+    return 2\n"
        "@@ -10,3 +10,3 @@\n"
        " def foo2():\n"
        "-    return 3\n"
        "+    return 4\n"
        "@@ -20,3 +20,3 @@\n"
        " def foo3():\n"
        "-    return 5\n"
        "+    return 6\n"
    )


# ---------------------------------------------------------------------------
# compute_cyclomatic_complexity
# ---------------------------------------------------------------------------

def test_cc_simple_function() -> None:
    tree = ast.parse("def f():\n    return 1\n")
    assert compute_cyclomatic_complexity(tree) == 1


def test_cc_counts_if_and_for() -> None:
    tree = ast.parse(
        "def f(x):\n"
        "    for i in x:\n"
        "        if i > 0:\n"
        "            pass\n"
    )
    # base 1 + for + if = 3
    assert compute_cyclomatic_complexity(tree) == 3


def test_cc_boolop() -> None:
    tree = ast.parse("def f(a, b):\n    if a and b:\n        pass\n")
    # base 1 + if + (len(values)-1) for BoolOp = 3
    assert compute_cyclomatic_complexity(tree) == 3


def test_cc_comprehension_with_ifs() -> None:
    tree = ast.parse("[x for x in y if x > 0 if x < 10]\n")
    # base 1 + comprehension + len(ifs)=2
    assert compute_cyclomatic_complexity(tree) == 4


# ---------------------------------------------------------------------------
# check_ast_bloat_and_debug_residue
# ---------------------------------------------------------------------------

def test_debug_residue_breakpoint_raises() -> None:
    pre = "def f(s):\n    return s.strip()\n"
    post = "def f(s):\n    breakpoint()\n    return s.strip()\n"
    with pytest.raises(OverfitPolicyError, match="Debug residue"):
        check_ast_bloat_and_debug_residue("foo.py", pre, post)


def test_debug_residue_pdb_set_trace_raises() -> None:
    pre = "def f(s):\n    import pdb\n    return s.strip()\n"
    post = "def f(s):\n    pdb.set_trace()\n    return s.strip()\n"
    with pytest.raises(OverfitPolicyError, match="Debug residue"):
        check_ast_bloat_and_debug_residue("foo.py", pre, post)


def test_debug_residue_pre_existing_does_not_raise() -> None:
    pre = "def f(s):\n    breakpoint()\n    return s.strip()\n"
    post = "def f(s):\n    breakpoint()\n    return s.strip()\n"
    check_ast_bloat_and_debug_residue("foo.py", pre, post)


def test_cyclomatic_bloat_raises() -> None:
    # 6 new ``if`` branches => cc_delta == 6 > 5
    pre = "def f(s):\n    return s.strip().lower()\n"
    post = (
        "def f(s):\n"
        "    if s == 'a':\n"
        "        pass\n"
        "    if s == 'b':\n"
        "        pass\n"
        "    if s == 'c':\n"
        "        pass\n"
        "    if s == 'd':\n"
        "        pass\n"
        "    if s == 'e':\n"
        "        pass\n"
        "    if s == 'f':\n"
        "        pass\n"
        "    return s.strip().lower()\n"
    )
    with pytest.raises(OverfitPolicyError, match="cyclomatic complexity bloat"):
        check_ast_bloat_and_debug_residue("foo.py", pre, post)


def test_cyclomatic_delta_within_limit_passes() -> None:
    pre = "def f(s):\n    return s.strip().lower()\n"
    post = (
        "def f(s):\n"
        "    if s == 'a':\n"
        "        pass\n"
        "    if s == 'b':\n"
        "        pass\n"
        "    return s.strip().lower()\n"
    )
    # cc_delta == 2 <= 5
    check_ast_bloat_and_debug_residue("foo.py", pre, post)


# ---------------------------------------------------------------------------
# verify_not_overfitted integration
# ---------------------------------------------------------------------------

def test_verify_not_overfitted_clean_patch() -> None:
    """A clean algorithmic patch (cc_delta == 0, no debug residue) passes."""
    pre_src = "def normalize(s):\n    return s\n"
    post_src = "def normalize(s):\n    return s.strip().lower()\n"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "foo.py").write_text(pre_src, encoding="utf-8")
        # No test files means literals is empty -> early return, but the
        # check_ast_bloat_and_debug_residue path still runs via the main loop.
        # We pass non-empty test_literals to exercise the full path.
        verify_not_overfitted(
            workspace_root=root,
            pre_patch_sources={"foo.py": pre_src},
            post_patch_sources={"foo.py": post_src},
            test_literals=frozenset({"  hello  "}),
        )


def test_verify_not_overfitted_debug_residue_via_integration() -> None:
    pre_src = "def f(s):\n    return s.strip()\n"
    post_src = "def f(s):\n    breakpoint()\n    return s.strip()\n"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "foo.py").write_text(pre_src, encoding="utf-8")
        with pytest.raises(OverfitPolicyError, match="Debug residue"):
            verify_not_overfitted(
                workspace_root=root,
                pre_patch_sources={"foo.py": pre_src},
                post_patch_sources={"foo.py": post_src},
                test_literals=frozenset({"  hello  "}),
            )


# ---------------------------------------------------------------------------
# generate_minimal_hunk_subsets
# ---------------------------------------------------------------------------

def test_minimal_subsets_single_hunk_returns_self() -> None:
    diff = (
        "diff --git a/foo.py b/foo.py\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def foo():\n"
        "-    return 1\n"
        "+    return 2\n"
    )
    result = generate_minimal_hunk_subsets(diff)
    assert len(result) == 1
    assert result[0].endswith("\n")
    # The single candidate should contain the one hunk.
    assert "@@" in result[0]


def test_minimal_subsets_two_hunks() -> None:
    diff = _two_hunk_diff()
    result = generate_minimal_hunk_subsets(diff)
    # N == 2: only single-hunk subsets (N <= 1? no; N==2 => single-hunk only).
    # Step (b) requires N > 2.
    assert len(result) == 2
    for r in result:
        assert r.endswith("\n")
        assert sum(1 for line in r.split("\n") if line.startswith("@@")) == 1


def test_minimal_subsets_three_hunks() -> None:
    diff = _three_hunk_diff()
    result = generate_minimal_hunk_subsets(diff)
    # N == 3: 3 single-hunk + 3 (drop-one) two-hunk = 6 candidates.
    assert len(result) == 6
    for r in result:
        assert r.endswith("\n")

    hunk_counts = [sum(1 for line in r.split("\n") if line.startswith("@@")) for r in result]
    # First 3 candidates: single-hunk diffs.
    assert hunk_counts[:3] == [1, 1, 1]
    # Last 3 candidates: two-hunk diffs.
    assert hunk_counts[3:] == [2, 2, 2]


def test_minimal_subsets_normalizes_crlf() -> None:
    diff = _two_hunk_diff().replace("\n", "\r\n")
    result = generate_minimal_hunk_subsets(diff)
    assert len(result) == 2
    for r in result:
        assert "\r" not in r
        assert r.endswith("\n")


def test_minimal_subsets_multi_file() -> None:
    diff = (
        "diff --git a/foo.py b/foo.py\n"
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def f():\n"
        "-    return 1\n"
        "+    return 2\n"
        "diff --git a/bar.py b/bar.py\n"
        "--- a/bar.py\n"
        "+++ b/bar.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def b():\n"
        "-    return 1\n"
        "+    return 2\n"
    )
    result = generate_minimal_hunk_subsets(diff)
    # N == 2: single-hunk subsets only; each candidate keeps exactly 1 hunk
    # from one file, dropping the other file entirely.
    assert len(result) == 2
    for r in result:
        assert r.endswith("\n")
        assert sum(1 for line in r.split("\n") if line.startswith("@@")) == 1

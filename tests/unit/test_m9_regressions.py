"""Regression coverage for file-aware healing and structural patch guards."""

from __future__ import annotations

import difflib
import subprocess
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.policy.diff_healer import heal_diff_line_numbers
from agentsentinel.policy.diff_parser import UnifiedDiffParser
from agentsentinel.verification.overfit_guard import verify_not_overfitted
from agentsentinel.verification.patch_minimizer import (
    check_ast_bloat_and_debug_residue,
    generate_minimal_hunk_subsets,
)


def test_healing_counts_unchanged_prior_hunk_delta(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a\nb\nc\nd\ne\nf\n", encoding="utf-8", newline="\n")
    raw = (
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n a\n+b2\n b\n"
        "@@ -90,2 +90,2 @@\n e\n-f\n+fixed\n"
    )
    result = heal_diff_line_numbers(raw, tmp_path)
    assert "@@ -5,2 +6,2 @@" in result.healed_diff


def test_healing_corrects_new_start_without_relocating_old(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a\nb\n", encoding="utf-8", newline="\n")
    result = heal_diff_line_numbers(
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +40,2 @@\n a\n-b\n+c\n", tmp_path
    )
    assert result.was_healed
    assert "@@ -1,2 +1,2 @@" in result.healed_diff


def test_healing_does_not_confuse_identical_headers_between_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a\nb\n", encoding="utf-8", newline="\n")
    (tmp_path / "b.py").write_text("x\ny\nz\n", encoding="utf-8", newline="\n")
    raw = (
        "--- a/a.py\n+++ b/a.py\n@@ -50,2 +50,2 @@\n a\n-b\n+c\n"
        "--- a/b.py\n+++ b/b.py\n@@ -50,2 +50,2 @@\n y\n-z\n+fixed\n"
    )
    files = UnifiedDiffParser.parse(heal_diff_line_numbers(raw, tmp_path).healed_diff).files
    assert [(f.hunks[0].old_start, f.hunks[0].new_start) for f in files] == [(1, 1), (2, 2)]


def test_healing_does_not_relocate_empty_preimage(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a\n", encoding="utf-8", newline="\n")
    raw = "--- a/a.py\n+++ b/a.py\n@@ -80,0 +81,1 @@\n+new\n"
    assert not heal_diff_line_numbers(raw, tmp_path).was_healed


def test_debug_guard_runs_without_assertion_literals(tmp_path: Path) -> None:
    with pytest.raises(OverfitPolicyError, match="Debug residue"):
        verify_not_overfitted(
            tmp_path,
            {"a.py": "def f():\n    return 1\n"},
            {"a.py": "def f():\n    breakpoint()\n    return 1\n"},
            test_literals=frozenset(),
        )


@pytest.mark.parametrize(
    ("pre", "post"),
    [
        ("def f():\n    breakpoint()\n", "def f():\n    breakpoint()\n    breakpoint()\n"),
        ("def f():\n    breakpoint()\n", "def f():\n    breakpoint()\ndef g():\n    breakpoint()\n"),
        ("", "import pdb as debugger\ndef f():\n    debugger.set_trace()\n"),
        ("", "from ipdb import set_trace as stop\ndef f():\n    stop()\n"),
        ("", "from builtins import breakpoint as stop\ndef f():\n    stop()\n"),
    ],
)
def test_debug_calls_are_counted_per_scope_and_alias(pre: str, post: str) -> None:
    with pytest.raises(OverfitPolicyError, match="Debug residue"):
        check_ast_bloat_and_debug_residue("a.py", pre, post)


@pytest.mark.parametrize(
    "handler",
    [
        "except:\n        raise",
        "except Exception:\n        pass",
        "except BaseException:\n        return None",
        "except (ValueError, Exception):\n        ...",
        "except Exception:\n        log()",
        "except Exception:\n        def nested():\n            return 1",
        "except Exception:\n        if flag:\n            return 1",
    ],
)
def test_new_swallowing_handlers_are_rejected(handler: str) -> None:
    post = f"def f():\n    try:\n        work()\n    {handler}\n"
    with pytest.raises(OverfitPolicyError, match="exception"):
        check_ast_bloat_and_debug_residue("a.py", "def f():\n    work()\n", post)


@pytest.mark.parametrize(
    "handler",
    [
        "raise",
        "return fallback",
        "if flag:\n            raise\n        else:\n            return fallback",
    ],
)
def test_explicit_broad_handler_outcomes_are_allowed(handler: str) -> None:
    post = f"def f():\n    try:\n        work()\n    except Exception:\n        {handler}\n"
    check_ast_bloat_and_debug_residue("a.py", "def f():\n    work()\n", post)


def test_unchanged_legacy_handler_is_allowed() -> None:
    pre = "def f():\n    try:\n        work()\n    except Exception:\n        pass\n"
    check_ast_bloat_and_debug_residue("a.py", pre, pre.replace("work()", "fixed()"))


@pytest.mark.parametrize("delta", [5, 6])
def test_complexity_delta_boundary(delta: int) -> None:
    post = "def f(x):\n" + "    if x:\n        x -= 1\n" * delta + "    return x\n"
    if delta == 5:
        check_ast_bloat_and_debug_residue("a.py", "def f(x):\n    return x\n", post)
    else:
        with pytest.raises(OverfitPolicyError, match="complexity"):
            check_ast_bloat_and_debug_residue("a.py", "def f(x):\n    return x\n", post)


def test_subset_offsets_rebase_after_omitted_insertion(tmp_path: Path) -> None:
    before = [f"value_{i} = {i}\n" for i in range(30)]
    after = before.copy()
    after[3:3] = ["added = 1\n", "added2 = 2\n"]
    after[27] = "value_25 = 100\n"
    raw = "".join(difflib.unified_diff(before, after, "a/a.py", "b/a.py"))
    candidates = generate_minimal_hunk_subsets(raw)
    assert len(candidates) == 2
    hunk = UnifiedDiffParser.parse(candidates[1]).files[0].hunks[0]
    assert hunk.new_start == hunk.old_start
    (tmp_path / "a.py").write_text("".join(before), encoding="utf-8", newline="\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    for candidate in candidates:
        result = subprocess.run(
            ["git", "apply", "--check", "-"], input=candidate.encode("utf-8"), cwd=tmp_path,
            capture_output=True, check=False,
        )
        assert result.returncode == 0, result.stderr


def test_subset_keeps_no_newline_markers_and_file_metadata() -> None:
    raw = (
        "diff --git a/a.py b/a.py\nindex 111..222 100644\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
        "diff --git a/b.py b/b.py\nindex 333..444 100644\n--- a/b.py\n+++ b/b.py\n"
        "@@ -1 +1 @@\n-x\n+y\n"
    )
    first, second = generate_minimal_hunk_subsets(raw.replace("\n", "\r\n"))
    assert first.count("\\ No newline at end of file") == 2
    assert "index 111..222" in first and "b/b.py" not in first
    assert "index 333..444" in second and "b/a.py" not in second
    assert "\r" not in first + second


@pytest.mark.parametrize(
    "body",
    [
        "for item in [1]:\n            return None\n        return 1",
        "while flag:\n            return None\n        return 1",
        "with manager():\n            return None\n        return 1",
        "try:\n            return None\n        finally:\n            cleanup()\n        return 1",
        "match value:\n            case 1:\n                return None\n            case _:\n                return 1",
    ],
)
def test_compound_handlers_cannot_hide_swallowing_exits(body: str) -> None:
    post = f"def f():\n    try:\n        work()\n    except Exception:\n        {body}\n"
    with pytest.raises(OverfitPolicyError, match="exception"):
        check_ast_bloat_and_debug_residue("a.py", "def f():\n    work()\n", post)


def test_healing_preserves_removed_content_that_looks_like_a_file_header(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("-- old\nnext\n", encoding="utf-8", newline="\n")
    raw = "--- a/a.py\n+++ b/a.py\n@@ -90,2 +90,2 @@\n--- old\n+++ new\n next\n"
    healed = heal_diff_line_numbers(raw, tmp_path)
    assert healed.was_healed
    assert healed.healed_diff == raw.replace("@@ -90,2 +90,2 @@", "@@ -1,2 +1,2 @@")
    parsed = UnifiedDiffParser.parse(healed.healed_diff)
    assert parsed.target_paths == ("a.py",)


@pytest.mark.parametrize(
    "body",
    [
        "with manager():\n            return fallback",
        "try:\n            return fallback\n        finally:\n            cleanup()",
        "match value:\n            case 1:\n                raise\n            case _:\n                return fallback",
        "for item in values:\n            if item:\n                return item\n        return fallback",
    ],
)
def test_compound_handlers_with_explicit_safe_outcomes_are_allowed(body: str) -> None:
    post = f"def f():\n    try:\n        work()\n    except Exception:\n        {body}\n"
    check_ast_bloat_and_debug_residue("a.py", "def f():\n    work()\n", post)

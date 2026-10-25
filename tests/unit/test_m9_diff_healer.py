"""Tests for Milestone 9A — Deterministic Hunk Line-Drift Healer."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from agentsentinel.domain.models import PatchProposal
from agentsentinel.policy.applier import PatchApplicationError, apply_validated_patch

_PATCH_FIXTURES = {
    "case_id": "test-case-001",
    "model_id": "gpt-4-test",
    "prompt_tokens": 100,
    "completion_tokens": 50,
}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Create a temporary workspace with a source file containing a function."""
    src = tmp_path / "src"
    src.mkdir()
    target = src / "fixable.py"
    # Create a file with content at line 5 that a diff will target
    lines = []
    for i in range(4):
        lines.append(f"# filler line {i}")
    lines.append("def broken_function(x):")
    lines.append("    return x + 1")
    lines.append("")
    lines.append("def another_function(y):")
    lines.append("    return y * 2")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return tmp_path


class TestHealDiffLineNumbers:
    """Tests for the line-number drift healer."""

    def test_unambiguous_off_by_45_is_healed(self, workspace: Path) -> None:
        """A diff whose @@ header is off by +45 lines is healed."""
        from agentsentinel.policy.diff_healer import heal_diff_line_numbers

        # Build a diff that targets line 5 (the broken_function)
        # But the @@ header claims it's at line 50
        true_start = 5
        false_start = 50

        diff = (
            "--- a/src/fixable.py\n"
            "+++ b/src/fixable.py\n"
            f"@@ -{false_start},2 +{true_start},2 @@\n"
            " def broken_function(x):\n"
            "-    return x + 1\n"
            "+    return x + 2\n"
        )

        result = heal_diff_line_numbers(diff, workspace)
        assert result.was_healed is True
        assert result.relocated_hunks_count == 1
        # The healed diff should have the correct line number
        healed_diff = result.healed_diff
        assert f"@@ -{true_start},2 +{true_start},2 @@" in healed_diff  # old_start corrected, new_start unchanged

    def test_wrong_context_no_match_is_not_healed(self, workspace: Path) -> None:
        """A diff with wrong context lines (0 matches) is NOT healed."""
        from agentsentinel.policy.diff_healer import heal_diff_line_numbers

        diff = (
            "--- a/src/fixable.py\n"
            "+++ b/src/fixable.py\n"
            "@@ -50,3 +50,3 @@\n"
            " def nonexistent_function(x):\n"
            "-    return x + 1\n"
            "+    return x + 2\n"
        )

        result = heal_diff_line_numbers(diff, workspace)
        assert result.was_healed is False
        assert result.relocated_hunks_count == 0

    def test_ambiguous_match_not_healed(self, workspace: Path) -> None:
        """A diff whose context appears twice is NOT healed (ambiguous)."""
        from agentsentinel.policy.diff_healer import heal_diff_line_numbers

        target = workspace / "src" / "fixable.py"
        # Add a duplicate block to create ambiguity
        content = target.read_text(encoding="utf-8")
        # Insert an identical block earlier
        lines = content.splitlines(keepends=False)
        # Find the broken_function and duplicate it
        lines.insert(10, "def broken_function(x):")
        lines.insert(11, "    return x + 1")
        lines.insert(12, "")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

        diff = (
            "--- a/src/fixable.py\n"
            "+++ b/src/fixable.py\n"
            "@@ -50,2 +50,2 @@\n"
            " def broken_function(x):\n"
            "-    return x + 1\n"
            "+    return x + 2\n"
        )

        result = heal_diff_line_numbers(diff, workspace)
        assert result.was_healed is False
        assert result.relocated_hunks_count == 0


class TestHealIntegrationWithApply:
    """Integration tests: healing is invoked when git apply --check fails."""

    def test_off_by_error_diff_is_healed_and_applied(
        self, workspace: Path
    ) -> None:
        """A diff with wrong @@ line numbers is healed and applies cleanly."""
        true_start = 3
        false_start = 50

        # The hunk has 3 lines of context before (lines 3,4,5), the changed
        # line at 6, and 3 lines of context after (lines 7,8,9), making
        # old_count=7. git apply needs >=3 context lines on each side by default.
        diff = (
            "--- a/src/fixable.py\n"
            "+++ b/src/fixable.py\n"
            f"@@ -{false_start},7 +{true_start},7 @@\n"
            " # filler line 2\n"
            " # filler line 3\n"
            " def broken_function(x):\n"
            "-    return x + 1\n"
            "+    return x + 2\n"
            "\n"
            " def another_function(y):\n"
            "     return y * 2\n"
        )

        patch = PatchProposal(unified_diff=diff, **_PATCH_FIXTURES)

        patched_ws = apply_validated_patch(
            patch=patch,
            source_workspace=workspace,
            allowed_edit_paths=("src/fixable.py",),
        )

        # Verify the patch was actually applied
        patched_content = (patched_ws / "src" / "fixable.py").read_text(
            encoding="utf-8"
        )
        assert "return x + 2" in patched_content
        assert "return x + 1" not in patched_content
        # Cleanup
        shutil.rmtree(patched_ws, ignore_errors=True)

    def test_corrupt_context_raises_patch_application_error(
        self, workspace: Path
    ) -> None:
        """A diff with wrong context (0 matches) raises PatchApplicationError."""
        diff = (
            "--- a/src/fixable.py\n"
            "+++ b/src/fixable.py\n"
            "@@ -50,2 +50,2 @@\n"
            " def nonexistent_function(x):\n"
            "-    return x + 1\n"
            "+    return x + 2\n"
        )

        patch = PatchProposal(unified_diff=diff, **_PATCH_FIXTURES)

        with pytest.raises(PatchApplicationError):
            apply_validated_patch(
                patch=patch,
                source_workspace=workspace,
                allowed_edit_paths=("src/fixable.py",),
            )

    def test_ambiguous_context_raises_patch_application_error(
        self, workspace: Path
    ) -> None:
        """A diff with ambiguous context (>=2 matches) raises PatchApplicationError."""
        target = workspace / "src" / "fixable.py"
        content = target.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=False)
        # Duplicate the block
        lines.insert(10, "def broken_function(x):")
        lines.insert(11, "    return x + 1")
        lines.insert(12, "")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

        diff = (
            "--- a/src/fixable.py\n"
            "+++ b/src/fixable.py\n"
            "@@ -50,2 +50,2 @@\n"
            " def broken_function(x):\n"
            "-    return x + 1\n"
            "+    return x + 2\n"
        )

        patch = PatchProposal(unified_diff=diff, **_PATCH_FIXTURES)

        with pytest.raises(PatchApplicationError):
            apply_validated_patch(
                patch=patch,
                source_workspace=workspace,
                allowed_edit_paths=("src/fixable.py",),
            )

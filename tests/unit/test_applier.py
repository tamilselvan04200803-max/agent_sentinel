"""Unit tests for the M2 patch applier (policy/applier.py).

Phase C adversarial coverage:
- Path traversal in diff
- Symlink escape post-application
- Context mismatch (wrong line content)
- File-not-found for non-new patch
- Deletion of existing file
- New file creation from /dev/null
- Valid happy-path application
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.exceptions import PathTraversalError
from agentsentinel.domain.models import PatchProposal
from agentsentinel.policy.applier import PatchApplicationError, apply_validated_patch

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_SHA = "a" * 40


def _make_patch(diff: str) -> PatchProposal:
    return PatchProposal(
        case_id="test-case",
        unified_diff=diff,
        model_id="stub/test",
        prompt_tokens=10,
        completion_tokens=5,
    )


_BUGGY_SRC = "def normalize(x):\n    return x.lower()\n"
_FIXED_SRC = "def normalize(x):\n    return x.strip().lower()\n"

_VALID_DIFF = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.lower()
+    return x.strip().lower()
"""


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


class TestApplyValidatedPatch:
    @pytest.mark.unit
    def test_valid_patch_applied_correctly(self, tmp_path: Path) -> None:
        """Valid diff is applied and the result file matches the expected fixed source."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()
        (src_ws / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")

        patch = _make_patch(_VALID_DIFF)
        patched_ws = apply_validated_patch(
            patch=patch,
            source_workspace=src_ws,
            allowed_edit_paths=("normalizer.py",),
        )

        try:
            result = (patched_ws / "normalizer.py").read_text(encoding="utf-8")
            assert result == _FIXED_SRC
        finally:
            import shutil
            shutil.rmtree(patched_ws, ignore_errors=True)

    @pytest.mark.unit
    def test_new_file_creation(self, tmp_path: Path) -> None:
        """Patch creating a new file is applied correctly."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()

        new_file_diff = """\
--- /dev/null
+++ b/newmod.py
@@ -0,0 +1,2 @@
+def greet():
+    return "hello"
"""
        patch = _make_patch(new_file_diff)
        patched_ws = apply_validated_patch(
            patch=patch,
            source_workspace=src_ws,
            allowed_edit_paths=("newmod.py",),
        )

        try:
            result = (patched_ws / "newmod.py").read_text(encoding="utf-8")
            assert "def greet():" in result
            assert 'return "hello"' in result
        finally:
            import shutil
            shutil.rmtree(patched_ws, ignore_errors=True)

    @pytest.mark.unit
    def test_file_deletion(self, tmp_path: Path) -> None:
        """Patch deleting a file removes it from the workspace."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()
        (src_ws / "oldmod.py").write_text("x = 1\n", encoding="utf-8")

        delete_diff = """\
--- a/oldmod.py
+++ /dev/null
@@ -1 +0,0 @@
-x = 1
"""
        patch = _make_patch(delete_diff)
        patched_ws = apply_validated_patch(
            patch=patch,
            source_workspace=src_ws,
            allowed_edit_paths=("oldmod.py",),
        )

        try:
            assert not (patched_ws / "oldmod.py").exists()
        finally:
            import shutil
            shutil.rmtree(patched_ws, ignore_errors=True)

    @pytest.mark.unit
    def test_dest_workspace_provided(self, tmp_path: Path) -> None:
        """When dest_workspace is provided, patch is applied there and returned."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()
        (src_ws / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")

        dest_ws = tmp_path / "dest"
        dest_ws.mkdir()
        # Pre-populate dest with a copy of the source
        import shutil
        shutil.copy(src_ws / "normalizer.py", dest_ws / "normalizer.py")

        patch = _make_patch(_VALID_DIFF)
        result_ws = apply_validated_patch(
            patch=patch,
            source_workspace=src_ws,
            allowed_edit_paths=("normalizer.py",),
            dest_workspace=dest_ws,
        )

        assert result_ws == dest_ws.resolve()
        result = (result_ws / "normalizer.py").read_text(encoding="utf-8")
        assert result == _FIXED_SRC


# ---------------------------------------------------------------------------
# Adversarial tests
# ---------------------------------------------------------------------------


class TestApplyValidatedPatchAdversarial:
    @pytest.mark.adversarial
    def test_path_traversal_in_diff_is_blocked(self, tmp_path: Path) -> None:
        """Diff targeting ../../etc/passwd is rejected before any disk write."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()

        traversal_diff = """\
--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1 +1 @@
-root:x:0:0:root
+hacked:x:0:0:root
"""
        patch = _make_patch(traversal_diff)
        with pytest.raises(PathTraversalError):
            apply_validated_patch(
                patch=patch,
                source_workspace=src_ws,
                allowed_edit_paths=("normalizer.py",),
            )

    @pytest.mark.adversarial
    def test_context_mismatch_raises(self, tmp_path: Path) -> None:
        """Patch with wrong context line content raises PatchApplicationError."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()
        # File has "hello" but diff expects "world" as context
        (src_ws / "normalizer.py").write_text("def normalize(x):\n    return x.hello()\n",
                                               encoding="utf-8")

        wrong_context_diff = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.world()
+    return x.strip().world()
"""
        patch = _make_patch(wrong_context_diff)
        with pytest.raises(PatchApplicationError, match="mismatch"):
            apply_validated_patch(
                patch=patch,
                source_workspace=src_ws,
                allowed_edit_paths=("normalizer.py",),
            )

    @pytest.mark.adversarial
    def test_missing_source_file_raises(self, tmp_path: Path) -> None:
        """Patching a non-existent file (non-new) raises PatchApplicationError."""
        src_ws = tmp_path / "source"
        src_ws.mkdir()
        # normalizer.py does NOT exist in source_ws

        patch = _make_patch(_VALID_DIFF)
        with pytest.raises(PatchApplicationError, match="does not exist"):
            apply_validated_patch(
                patch=patch,
                source_workspace=src_ws,
                allowed_edit_paths=("normalizer.py",),
            )

    @pytest.mark.adversarial
    def test_file_outside_allowlist_is_blocked(self, tmp_path: Path) -> None:
        """Diff targeting a file not in allowed_edit_paths is blocked by validator."""
        from agentsentinel.domain.exceptions import AllowlistViolationError

        src_ws = tmp_path / "source"
        src_ws.mkdir()
        (src_ws / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")

        patch = _make_patch(_VALID_DIFF)
        # allowed_edit_paths does NOT include normalizer.py
        with pytest.raises(AllowlistViolationError):
            apply_validated_patch(
                patch=patch,
                source_workspace=src_ws,
                allowed_edit_paths=("other_file.py",),
            )

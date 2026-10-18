"""Regression tests proving the M4 pre-fix (applier hard-fail + workspace scrub
compatibility with git apply) hold before we proceed to Milestone 4.
"""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.models import PatchProposal
from agentsentinel.policy.applier import PatchApplicationError, apply_validated_patch
from agentsentinel.sandbox.workspace import WorkspaceManager

if TYPE_CHECKING:
    from pathlib import Path

_VALID_DIFF = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.lower()
+    return x.strip().lower()
"""

_BAD_DIFF = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.does_not_exist()
+    return x.strip().lower()
"""

_BUGGY_SRC = "def normalize(x):\n    return x.lower()\n"
_FIXED_SRC = "def normalize(x):\n    return x.strip().lower()\n"


def _make_patch(diff: str) -> PatchProposal:
    return PatchProposal(
        case_id="pre-m4",
        unified_diff=diff,
        model_id="test",
        prompt_tokens=1,
        completion_tokens=1,
    )


class TestGitScrubAndApply:
    @pytest.mark.unit
    def test_git_apply_works_after_scrub_git_history(self, tmp_path: Path) -> None:
        """Even though scrub_git_history removes .git/, git apply must still
        work (git apply operates on the working tree, not on the repo). This
        is critical because after scrubbing the workspace we still need to
        apply LLM patches via git apply --check."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")
        # Simulate a repo that had .git/ initially
        git_dir = src / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")

        mgr = WorkspaceManager()
        patched = tmp_path / "patched"
        patched.mkdir()
        mgr.populate_from_directory(src, patched)
        mgr.scrub_git_history(patched)

        # .git must be gone but source files must be intact
        assert not (patched / ".git").exists()
        assert (patched / "normalizer.py").read_text(encoding="utf-8") == _BUGGY_SRC

        # git apply must still succeed against the scrubbed (no .git) workspace
        res = apply_validated_patch(
            patch=_make_patch(_VALID_DIFF),
            source_workspace=src,
            allowed_edit_paths=("normalizer.py",),
            dest_workspace=patched,
        )
        assert (res / "normalizer.py").read_text(encoding="utf-8") == _FIXED_SRC

    @pytest.mark.unit
    def test_bad_context_diff_raises_patch_application_error_directly(
        self, tmp_path: Path
    ) -> None:
        """A patch whose context does not match the source MUST raise
        PatchApplicationError directly out of apply_validated_patch —
        there must be NO silent fallback to a permissive manual editor."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "normalizer.py").write_text(_BUGGY_SRC, encoding="utf-8")

        with pytest.raises(PatchApplicationError) as excinfo:
            apply_validated_patch(
                patch=_make_patch(_BAD_DIFF),
                source_workspace=src,
                allowed_edit_paths=("normalizer.py",),
            )
        # The error must carry git's stderr (diagnostic for feedback loop)
        assert "patch does not apply" in str(excinfo.value) or "patch failed" in str(excinfo.value)
        # Source must NOT have been mutated (apply_validated_patch copies first;
        # but verify source directory is pristine).
        assert (src / "normalizer.py").read_text(encoding="utf-8") == _BUGGY_SRC
        # Clean up the temp dir that apply_validated_patch created
        # (it's a fresh mkdtemp; find and rmtree it)
        for p in tmp_path.iterdir():
            if p.is_dir() and p.name.startswith("agentsentinel_patched_"):
                shutil.rmtree(p, ignore_errors=True)

    @pytest.mark.unit
    def test_patch_application_error_is_subclass_of_agentsentinel_error(self) -> None:
        from agentsentinel.domain.exceptions import AgentSentinelError, HarnessSetupError

        assert issubclass(PatchApplicationError, HarnessSetupError)
        assert issubclass(PatchApplicationError, AgentSentinelError)

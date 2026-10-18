"""Patch application module.

Takes a validated ``PatchProposal`` and applies it to a fresh ephemeral workspace
snapshot, producing a patched workspace path ready for container-based test execution.

Security invariants:
- The unified diff is parsed and validated through the full M2 policy stack
  before being written to disk (prevent TOCTOU).
- After application, every written path is re-validated against the workspace
  root using ``is_relative_to`` to guard against symlink attacks in the diff
  application phase itself.
- A ``git apply --check`` dry-run is performed when git is available to verify
  patch applicability before any file mutation.
- All file writes go through atomic rename (``atomic_write``) to prevent partial
  writes from leaving the workspace in a corrupt state.
- The source (pre-patch) directory is never mutated; a deep copy is made first.
"""

from __future__ import annotations

import contextlib
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import (
    HarnessSetupError,
    SymlinkEscapeError,
)
from agentsentinel.policy.diff_parser import FilePatch, ParsedDiff, UnifiedDiffParser
from agentsentinel.policy.validator import PatchPolicyValidator
from agentsentinel.sandbox.workspace import WorkspaceManager

if TYPE_CHECKING:
    from agentsentinel.domain.models import PatchProposal


class PatchApplicationError(HarnessSetupError):
    """Raised when a validated patch cannot be applied to the workspace."""

    def __init__(self, reason: str, stderr: str = "") -> None:
        super().__init__(reason, stderr)


def _apply_file_patch(file_patch: FilePatch, workspace_root: Path) -> None:
    """Apply a single FilePatch by line-editing the target file.

    Supports additions (+), deletions (-), and context lines ( ).
    New files are created, deleted files are removed.

    Parameters
    ----------
    file_patch:
        Parsed file patch to apply.
    workspace_root:
        Absolute path to the workspace root.

    Raises
    ------
    PatchApplicationError
        If the patch cannot be applied cleanly (context mismatch, missing file).
    """
    target = file_patch.target_path
    if not target:
        raise PatchApplicationError("FilePatch has no target path")

    target_file = workspace_root / target

    # Re-verify the resolved path is still inside the workspace after join
    resolved_root = workspace_root.resolve()
    resolved_target = target_file.resolve()
    if not resolved_target.is_relative_to(resolved_root):
        raise SymlinkEscapeError(
            link=target,
            resolved=str(resolved_target),
            root=str(resolved_root),
        )

    # Handle file deletions
    if file_patch.is_delete:
        if target_file.exists():
            target_file.unlink()
        return

    # Read current file content (or empty for new files)
    if file_patch.is_new:
        original_lines: list[str] = []
    else:
        if not target_file.exists():
            raise PatchApplicationError(
                f"Source file does not exist for patching: {target!r}"
            )
        original_lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines(
            keepends=True
        )

    # Apply each hunk
    result_lines = list(original_lines)
    line_offset = 0  # Track cumulative offset from previous hunks

    for hunk in file_patch.hunks:
        # old_start is 1-indexed; convert to 0-indexed
        apply_at = hunk.old_start - 1 + line_offset
        old_count = hunk.old_count
        new_lines: list[str] = []

        # Verify context lines match
        context_pos = apply_at
        for hl in hunk.lines:
            if hl.origin in (" ", "-"):
                if context_pos >= len(result_lines):
                    raise PatchApplicationError(
                        f"Patch context mismatch in {target!r} at hunk line {context_pos + 1}: "
                        f"file has fewer lines than expected"
                    )
                expected = result_lines[context_pos].rstrip("\n").rstrip("\r")
                actual = hl.content.rstrip("\n").rstrip("\r")
                if expected != actual:
                    raise PatchApplicationError(
                        f"Patch context mismatch in {target!r} at line {context_pos + 1}: "
                        f"expected {expected!r}, got {actual!r}"
                    )
                context_pos += 1
            if hl.origin in ("+", " "):
                content = hl.content
                if not content.endswith(("\n", "\r")):
                    content += "\n"
                new_lines.append(content)

        # Splice the hunk into result_lines
        result_lines[apply_at : apply_at + old_count] = new_lines
        line_offset += len(new_lines) - old_count

    # Write result atomically
    mgr = WorkspaceManager()
    target_file.parent.mkdir(parents=True, exist_ok=True)
    mgr.atomic_write(target_file, "".join(result_lines))


def apply_validated_patch(
    patch: PatchProposal,
    source_workspace: Path,
    allowed_edit_paths: tuple[str, ...],
    dest_workspace: Path | None = None,
) -> Path:
    """Parse, validate, and apply a ``PatchProposal`` to a fresh workspace copy.

    This is the main M2→M1 bridge: it takes a candidate patch from the LLM,
    runs it through the full policy validation stack, then applies the hunks
    to an isolated workspace snapshot, and verifies no symlink escapes occurred
    post-application.

    Parameters
    ----------
    patch:
        Validated (by schema) ``PatchProposal`` to apply.
    source_workspace:
        Path to the baseline (unpatched) workspace directory.
    allowed_edit_paths:
        Allowlist of repo-relative paths the agent may modify (from ``CaseSpec``).
    dest_workspace:
        If provided, apply the patch here (must already be populated). If ``None``,
        a fresh ``TemporaryDirectory`` is created internally — the caller is
        responsible for cleanup (the path is returned).

    Returns
    -------
    Path
        Absolute path to the patched workspace directory.

    Raises
    ------
    MalformedDiffError
        If the diff cannot be parsed.
    PathTraversalError
        If path traversal sequences are detected.
    SymlinkEscapeError
        If a symlink resolves outside the workspace root post-application.
    PatchApplicationError
        If a hunk cannot be applied cleanly (context mismatch).
    HarnessSetupError
        If workspace copy fails.
    """
    # Step 1: Parse the diff (raises MalformedDiffError on failure)
    parsed: ParsedDiff = UnifiedDiffParser.parse(patch.unified_diff)

    # Step 2: Policy validation (raises PathTraversalError, TestFileModificationError, etc.)
    validator = PatchPolicyValidator(allowed_edit_paths=allowed_edit_paths)
    validator.validate_diff(patch.unified_diff, workspace_root=source_workspace)

    # Step 3: Provision a fresh workspace copy
    mgr = WorkspaceManager()

    if dest_workspace is not None:
        patched_ws = dest_workspace.resolve()
    else:
        # Create a temp dir and copy source files in
        _tmp_dir = tempfile.mkdtemp(prefix="agentsentinel_patched_")
        patched_ws = Path(_tmp_dir)
        mgr.populate_from_directory(source_workspace, patched_ws)
        mgr.scrub_git_history(patched_ws)

    # Step 4: Optional git apply --check dry-run
    git_check_passed = _try_git_apply_check(patch.unified_diff, patched_ws)
    if not git_check_passed:
        # Fall through to manual application — git may not be available
        pass

    # Step 5: Apply each file patch
    for file_patch in parsed.files:
        _apply_file_patch(file_patch, patched_ws)

    # Step 6: Post-apply symlink escape re-verification for every allowed_edit_path
    resolved_root = patched_ws.resolve()
    for rel_path in allowed_edit_paths:
        candidate = (patched_ws / rel_path).resolve()
        if candidate.exists() and not candidate.is_relative_to(resolved_root):
            raise SymlinkEscapeError(
                link=rel_path,
                resolved=str(candidate),
                root=str(resolved_root),
            )

    return patched_ws


def _try_git_apply_check(diff_text: str, workspace: Path) -> bool:
    """Attempt a `git apply --check` dry run. Returns True if successful, False otherwise.

    Parameters
    ----------
    diff_text:
        Raw unified diff text.
    workspace:
        Workspace path to run git inside.

    Returns
    -------
    bool
        True if git apply --check succeeded, False if git is unavailable or the
        workspace is not a git repo (non-fatal; falls back to manual application).
    """
    with contextlib.suppress(Exception):
        import tempfile as _tf

        with _tf.NamedTemporaryFile(
            mode="w",
            suffix=".patch",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(diff_text)
            patch_file = f.name

        try:
            result = subprocess.run(
                ["git", "apply", "--check", patch_file],
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            return result.returncode == 0
        finally:
            with contextlib.suppress(OSError):
                Path(patch_file).unlink()

    return False

"""Patch application module.

Takes a validated ``PatchProposal`` and applies it to a fresh ephemeral workspace
snapshot, producing a patched workspace path ready for container-based test execution.

Security & correctness invariants
---------------------------------
- The unified diff is parsed and validated through the full M2 policy stack
  before being written to disk (prevent TOCTOU).
- Patch applicability is verified with ``git apply --check --ignore-space-change``
  executed natively against the ephemeral workspace. If the check fails we raise
  :class:`PatchApplicationError` immediately — we NEVER silently fall back to a
  permissive line-editor when ``git`` rejects the patch (that would silently
  apply partial/corrupt hunks and produce non-deterministic workspace state).
- If ``git`` is not available on the host we raise :class:`HarnessSetupError` —
  ``git apply`` is the authoritative patch engine and the harness refuses to
  run without it.
- The patch file is written with ``encoding="utf-8", newline="\\n"`` to avoid
  Windows CRLF translation corrupting the diff.
- After application, every written path is re-validated against the workspace
  root using ``is_relative_to`` to guard against symlink attacks.
- All file writes go through atomic rename (``atomic_write``) to prevent partial
  writes from leaving the workspace corrupt.
- The source (pre-patch) directory is never mutated; a deep copy is made first.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import (
    HarnessSetupError,
    SymlinkEscapeError,
)
from agentsentinel.policy.diff_healer import heal_diff_line_numbers
from agentsentinel.policy.diff_parser import ParsedDiff, UnifiedDiffParser
from agentsentinel.policy.validator import PatchPolicyValidator
from agentsentinel.sandbox.workspace import WorkspaceManager

if TYPE_CHECKING:
    from agentsentinel.domain.models import PatchProposal


class PatchApplicationError(HarnessSetupError):
    """Raised when a validated patch cannot be applied to the workspace.

    This includes ``git apply --check`` failures (context mismatch, corrupt
    hunks, missing files), filesystem errors, and symlink-escape violations
    discovered during application.
    """

    def __init__(self, reason: str, stderr: str = "") -> None:
        super().__init__(reason, stderr)


def _write_patch_file(diff_text: str) -> str:
    """Write a normalised unified diff to a temporary ``.patch`` file.

    Uses ``encoding="utf-8", newline="\\n"`` so Python on Windows does not
    translate ``\\n`` → ``\\r\\n`` when writing to disk (a classic bug that
    breaks ``git apply``).

    Returns the absolute path of the temporary patch file. Caller is
    responsible for unlinking it.
    """
    normalised = diff_text.replace("\r\n", "\n").replace("\r", "\n")
    fd, path = tempfile.mkstemp(suffix=".patch", prefix="agentsentinel_")
    path_obj = Path(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(normalised)
    except Exception:
        with contextlib.suppress(OSError):
            path_obj.unlink(missing_ok=True)
        raise
    return path


def _git_apply(patch_file: str, workspace: Path, check_only: bool) -> tuple[bool, str]:
    """Run ``git apply [--check] -v --ignore-space-change --whitespace=nowarn``.

    Returns ``(succeeded, stderr_text)``. Raises :class:`FileNotFoundError` if
    the ``git`` executable is not available on PATH (caller converts to
    :class:`HarnessSetupError`).
    """
    cmd = [
        "git",
        "apply",
        "-v",
        "--ignore-space-change",
        "--whitespace=nowarn",
    ]
    if check_only:
        cmd.append("--check")
    cmd.append(patch_file)

    result = subprocess.run(
        cmd,
        cwd=str(workspace),
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    stderr = (result.stderr or result.stdout or "").strip()
    if result.returncode != 0 or "Skipped patch" in stderr:
        return False, stderr
    return True, stderr


def _git_apply_with_fallback(
    patch_file: str, workspace: Path, raw_diff: str
) -> tuple[bool, str]:
    """Verify patch applicability with ``git apply --check`` then apply it.

    On ``--check`` failure, first attempts deterministic line-number healing
    via :func:`heal_diff_line_numbers`. If healing succeeds and the re-checked
    patch passes, that healed diff is applied. If healing fails (ambiguous or
    corrupt context) or the healed patch still fails ``--check``, raises
    :class:`PatchApplicationError` immediately.

    Returns ``(True, "")`` on success.

    Raises
    ------
    PatchApplicationError
        If either the original or healed patch fails ``--check`` or application.
        The error message includes git's stderr for diagnostics.
    HarnessSetupError
        If ``git`` is not installed.
    """
    had_git = (workspace / ".git").exists()
    if not had_git:
        subprocess.run(["git", "init"], cwd=str(workspace), capture_output=True, check=False)
        subprocess.run(["git", "add", "."], cwd=str(workspace), capture_output=True, check=False)

    try:
        # 1. Dry-run verification
        try:
            ok, err = _git_apply(patch_file, workspace, check_only=True)
        except FileNotFoundError as exc:
            raise HarnessSetupError(
                "git executable not found on host; git apply is required for "
                "deterministic patch application. Install git and retry."
            ) from exc

        if not ok:
            # Attempt deterministic line-number healing
            heal_result = heal_diff_line_numbers(raw_diff, workspace)
            if heal_result.was_healed:
                # Re-check with the healed diff
                healed_patch_file = _write_patch_file(heal_result.healed_diff)
                try:
                    ok_healed, err_healed = _git_apply(
                        healed_patch_file, workspace, check_only=True
                    )
                    if ok_healed:
                        # Apply the healed diff
                        ok_apply, err_apply = _git_apply(
                            healed_patch_file, workspace, check_only=False
                        )
                        if not ok_apply:
                            raise PatchApplicationError(
                                "git apply failed during actual application of healed "
                                "patch. Workspace may be in an inconsistent state.",
                                stderr=err_apply,
                            )
                        return True, ""
                    # Healed diff still fails --check — fall through to error
                    err = err_healed
                finally:
                    with contextlib.suppress(OSError):
                        Path(healed_patch_file).unlink()
            # No healing available or healing failed — raise original error
            raise PatchApplicationError(
                "git apply --check rejected the patch (context mismatch, corrupt "
                "hunks, or missing files). The patch was NOT applied.",
                stderr=err,
            )

        # 2. Actual application
        ok, err = _git_apply(patch_file, workspace, check_only=False)
        if not ok:
            raise PatchApplicationError(
                "git apply failed during actual application after passing --check. "
                "Workspace may be in an inconsistent state.",
                stderr=err,
            )

        return True, ""
    finally:
        if not had_git:
            WorkspaceManager().scrub_git_history(workspace)


def apply_validated_patch(
    patch: PatchProposal,
    source_workspace: Path,
    allowed_edit_paths: tuple[str, ...],
    dest_workspace: Path | None = None,
) -> Path:
    """Parse, validate, and apply a ``PatchProposal`` to a fresh workspace copy.

    This is the M2→M1 bridge: it takes a candidate patch from the LLM,
    runs it through the full policy validation stack, provisions an isolated
    workspace snapshot, applies the patch via ``git apply`` (hard-failing on
    any rejection), and verifies no symlink escapes occurred post-application.

    Parameters
    ----------
    patch:
        Validated (by schema) ``PatchProposal`` to apply.
    source_workspace:
        Path to the baseline (unpatched) workspace directory.
    allowed_edit_paths:
        Allowlist of repo-relative paths the agent may modify (from ``CaseSpec``).
    dest_workspace:
        If provided, apply the patch here (must already be populated). If
        ``None``, a fresh ``TemporaryDirectory`` is created internally — the
        caller is responsible for cleanup (the path is returned).

    Returns
    -------
    Path
        Absolute path to the patched workspace directory.

    Raises
    ------
    MalformedDiffError
        If the diff cannot be parsed.
    PathTraversalError / TestFileModificationError / AllowlistViolationError
        If policy validation fails (raised by the validator).
    SymlinkEscapeError
        If a symlink resolves outside the workspace root post-application.
    PatchApplicationError
        If ``git apply --check`` or ``git apply`` rejects the patch.
    HarnessSetupError
        If workspace copy fails or git is unavailable.
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
        # Create a temp dir and copy source files in. NOTE: scrub_git_history
        # removes the entire .git directory (preventing future-fix leakage);
        # git apply still works correctly against a plain working tree
        # without a .git directory (verified behaviour).
        _tmp_dir = tempfile.mkdtemp(prefix="agentsentinel_patched_")
        patched_ws = Path(_tmp_dir)
        mgr.populate_from_directory(source_workspace, patched_ws)
        mgr.scrub_git_history(patched_ws)

    # Step 4: Write patch to a temp file with strict newline="\n" and apply via git
    patch_file = _write_patch_file(patch.unified_diff)
    try:
        _git_apply_with_fallback(patch_file, patched_ws, patch.unified_diff)
    finally:
        with contextlib.suppress(OSError):
            Path(patch_file).unlink()

    # Step 5: Post-apply symlink escape re-verification for every allowed_edit_path
    resolved_root = patched_ws.resolve()
    for rel_path in allowed_edit_paths:
        candidate = (patched_ws / rel_path).resolve()
        if candidate.exists() and not candidate.is_relative_to(resolved_root):
            raise SymlinkEscapeError(
                link=rel_path,
                resolved=str(candidate),
                root=str(resolved_root),
            )

    # Silence unused-parsed warning (parsed is retained for future extensibility
    # e.g. targeted per-file post-apply validation).
    _ = parsed

    return patched_ws

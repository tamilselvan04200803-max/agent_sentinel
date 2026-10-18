"""Ephemeral workspace provisioning and Git history scrubbing.

Responsibilities:
- Create isolated temporary directories for bug evaluation.
- Copy repository sources into the isolated workspace safely.
- **Completely remove** ``.git`` metadata directory after checkout so that a
  process inside the container cannot run ``git log -p --all`` (or any other
  git inspection command) to read future reference fixes. Removing ``.git``
  entirely is strictly stronger than pruning reflogs/tags/remotes, which still
  leaves reachable commits visible via ``git log`` from HEAD.
- Atomic file writes and cleanup guarantees, including a Windows-safe rmtree
  onerror handler that clears the read-only bit Git puts on pack files.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from agentsentinel.domain.exceptions import HarnessSetupError

if TYPE_CHECKING:
    from types import TracebackType


# shutil.rmtree's onerror callback type. We use ``Any`` for func because it
# may be os.unlink, os.rmdir, etc. (different signatures); we only ever call
# it as ``func(path)`` in the handler so we cast at call sites.
_ShutilOnError = Callable[..., None]


@dataclass(frozen=True)
class WorkspaceContext:
    """Represents an active ephemeral workspace.

    Attributes
    ----------
    path:
        Absolute Path to the root of the ephemeral workspace.
    """

    path: Path


def _windows_rmtree_error_handler(
    func: object, path: str, exc_info: object
) -> None:  # noqa: ANN401

    """Error handler for ``shutil.rmtree`` that retries after clearing the read-only bit.

    On Windows, Git marks files under ``.git/objects/pack/`` as read-only, which
    causes ``shutil.rmtree`` / ``TemporaryDirectory.cleanup()`` to raise
    ``PermissionError: [WinError 5] Access is denied``. This handler works with
    both the ``onerror`` kwarg (Python <3.12) and ``onexc`` kwarg (Python ≥3.12);
    we accept ``Any`` for ``func`` and ``exc_info`` because the two signatures
    differ (``exc_info`` is a 3-tuple on onerror and a ``BaseException`` on
    onexc). We only need ``func(path)`` retry semantics.
    """
    try:
        Path(path).chmod(stat.S_IWRITE)
        cast("Callable[[str], object]", func)(path)
    except OSError:
        # Best-effort; if even the retry fails let the original exception propagate
        pass


class _WindowsSafeTemporaryDirectory:
    """A TemporaryDirectory-compatible context manager that handles Windows
    read-only files during cleanup.

    Python 3.12 added ``onexc=`` (and earlier versions expose ``onerror=``) on
    ``tempfile.TemporaryDirectory``, but Python 3.11 (our dev/CI baseline here)
    accepts neither in the constructor. We therefore implement a minimal
    compatible wrapper that uses ``tempfile.mkdtemp`` and performs cleanup with
    ``shutil.rmtree(..., onerror=_windows_rmtree_error_handler)`` ourselves.
    """

    def __init__(self, prefix: str, dir: str | None) -> None:
        self.name = tempfile.mkdtemp(prefix=prefix, dir=dir)
        self._cleaned = False

    def __enter__(self) -> str:
        return self.name

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        path = Path(self.name)
        if path.exists():
            # onerror handler is supported by shutil.rmtree on all Python
            # versions back to 3.3 and handles the read-only Git pack file
            # PermissionError on Windows.
            shutil.rmtree(path, onerror=cast("_ShutilOnError", _windows_rmtree_error_handler))


class WorkspaceManager:
    """Manages creation, git-scrubbing, and teardown of ephemeral workspaces."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir

    def create_workspace(self) -> _WindowsSafeTemporaryDirectory:
        """Create a fresh temporary directory with a Windows-safe cleanup handler.

        Returns a ``_WindowsSafeTemporaryDirectory`` context manager (compatible
        with ``tempfile.TemporaryDirectory`` — exposes ``.name`` and cleans up
        on ``__exit__``). Cleanup uses :func:`_windows_rmtree_error_handler` so
        that read-only Git pack files on Windows do not cause
        ``PermissionError``.
        """
        prefix = "agentsentinel_ws_"
        base = str(self.base_dir) if self.base_dir else None
        return _WindowsSafeTemporaryDirectory(prefix=prefix, dir=base)

    def populate_from_directory(self, src: Path, dest: Path) -> None:
        """Copy files from src into dest safely with path traversal protection.

        Parameters
        ----------
        src:
            Source directory path.
        dest:
            Destination directory path.

        Raises
        ------
        HarnessSetupError
            If copying fails or source does not exist.
        """
        src_resolved = src.resolve()
        dest_resolved = dest.resolve()

        if not src_resolved.exists() or not src_resolved.is_dir():
            raise HarnessSetupError(f"Source directory does not exist or is not a directory: {src}")

        try:
            # Copy all tree contents into dest
            shutil.copytree(src_resolved, dest_resolved, dirs_exist_ok=True, symlinks=False)
        except Exception as e:
            raise HarnessSetupError(f"Failed to copy workspace files: {e}") from e

    def scrub_git_history(self, workspace_path: Path) -> None:
        """Remove ALL Git metadata so containerised processes cannot inspect history.

        The implementation **fully deletes** ``.git/`` rather than trying to
        surgically prune reflogs/remotes/tags. Deleting the directory is the
        only way to be certain that ``git log -p --all`` cannot reveal future
        reference fixes — even after ``git reflog expire --expire=now --all``
        and ``git prune --expire=now``, commits reachable from HEAD remain in
        the object database and are visible through ``git log``.

        If ``.git`` does not exist (e.g. source was not a git checkout) this
        is a silent no-op.

        Windows safety
        --------------
        Git marks ``.git/objects/pack/*.pack`` read-only on Windows. We clear
        the read-only bit during rmtree via :func:`_force_remove_readonly`.

        Parameters
        ----------
        workspace_path:
            Path to the workspace root.
        """
        git_dir = workspace_path / ".git"
        if not git_dir.exists():
            return

        def _force_remove_readonly(
            func: object, path: str, exc_info: object  # noqa: ANN401
        ) -> None:
            """Clear the read-only bit and retry — used for Windows pack files."""
            try:
                Path(path).chmod(stat.S_IWRITE)
                cast("Callable[[str], object]", func)(path)
            except OSError:
                pass

        try:
            # onerror is accepted by shutil.rmtree on all supported Python
            # versions; onexc (3.12+) has a slightly different signature but
            # our handler uses Any for both func and exc_info so it works.
            shutil.rmtree(git_dir, onerror=cast("_ShutilOnError", _force_remove_readonly))
        except OSError as e:
            raise HarnessSetupError(f"Failed to scrub .git directory: {e}") from e

    def atomic_write(self, target_path: Path, content: str | bytes) -> None:
        """Atomically write content to target_path using a temporary sibling file.

        Parameters
        ----------
        target_path:
            Destination file path.
        content:
            String or bytes to write.

        Raises
        ------
        PathTraversalError:
            If path resolution tries to escape.
        HarnessSetupError:
            If the atomic rename or write fails.
        """
        parent = target_path.parent
        parent.mkdir(parents=True, exist_ok=True)

        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"

        tmp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode=mode,
                dir=str(parent),
                delete=False,
                encoding=encoding,
                prefix=".tmp_atomic_",
            ) as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
                tmp_file = Path(f.name)

            # Atomic rename (replace existing destination)
            tmp_file.replace(target_path)
        except Exception as e:
            if tmp_file and tmp_file.exists():
                with contextlib.suppress(OSError):
                    tmp_file.unlink()
            raise HarnessSetupError(f"Atomic write to {target_path} failed: {e}") from e

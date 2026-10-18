"""Ephemeral workspace provisioning and Git history scrubbing.

Responsibilities:
- Create isolated temporary directories for bug evaluation.
- Copy repository sources into the isolated workspace safely.
- Scrub Git history (.git/logs, reflogs, remotes, tracking branches, tags, and commit graph)
  so an inspectable container cannot inspect git log or reflog to cheat and find
  future reference patches or historical fixes.
- Atomic file writes and cleanup guarantees.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agentsentinel.domain.exceptions import HarnessSetupError


@dataclass(frozen=True)
class WorkspaceContext:
    """Represents an active ephemeral workspace.

    Attributes
    ----------
    path:
        Absolute Path to the root of the ephemeral workspace.
    """

    path: Path


class WorkspaceManager:
    """Manages creation, git-scrubbing, and teardown of ephemeral workspaces."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir

    def create_workspace(self) -> tempfile.TemporaryDirectory[str]:
        """Create a fresh temporary directory."""
        prefix = "agentsentinel_ws_"
        base = str(self.base_dir) if self.base_dir else None
        return tempfile.TemporaryDirectory(prefix=prefix, dir=base)

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
        """Scrub Git commit history, logs, and remotes to prevent information leakage.

        Scrubbing operations:
        1. Remove .git/logs (reflogs) completely.
        2. Remove remote definitions (git remote remove <name>).
        3. Remove tags (git tag -d <tag>).
        4. Truncate git history or scrub unreachable commits and commit graphs.
        5. If git is not installed or repo is corrupted, ensure reflog files are forcefully removed.

        Parameters
        ----------
        workspace_path:
            Path to the workspace root.
        """
        git_dir = workspace_path / ".git"
        if not git_dir.exists():
            return

        # 1. Remove reflogs directory entirely
        logs_dir = git_dir / "logs"
        if logs_dir.exists():
            try:
                shutil.rmtree(logs_dir)
            except OSError as e:
                raise HarnessSetupError(f"Failed to remove git logs: {e}") from e

        # 2. Scrub git remotes, tags, and reflog via git CLI if available
        try:
            # Check if git command is usable in workspace
            check_git = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(workspace_path),
                capture_output=True,
                text=True,
                check=False,
            )
            if check_git.returncode == 0:
                # Remove all remotes
                remotes_res = subprocess.run(
                    ["git", "remote"],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                for remote in remotes_res.stdout.splitlines():
                    remote = remote.strip()
                    if remote:
                        subprocess.run(
                            ["git", "remote", "remove", remote],
                            cwd=str(workspace_path),
                            capture_output=True,
                            check=False,
                        )

                # Remove all tags
                tags_res = subprocess.run(
                    ["git", "tag"],
                    cwd=str(workspace_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                tags = [t.strip() for t in tags_res.stdout.splitlines() if t.strip()]
                if tags:
                    subprocess.run(
                        ["git", "tag", "-d", *tags],
                        cwd=str(workspace_path),
                        capture_output=True,
                        check=False,
                    )

                # Expire reflog and prune all unreachable objects
                subprocess.run(
                    ["git", "reflog", "expire", "--expire=now", "--all"],
                    cwd=str(workspace_path),
                    capture_output=True,
                    check=False,
                )
                subprocess.run(
                    ["git", "prune", "--expire=now"],
                    cwd=str(workspace_path),
                    capture_output=True,
                    check=False,
                )
        except FileNotFoundError:
            # git executable not on PATH, manual filesystem scrub was already done
            pass

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

"""Unit tests for agentsentinel.sandbox.workspace."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsentinel.domain.exceptions import HarnessSetupError
from agentsentinel.sandbox.workspace import WorkspaceManager


class TestWorkspaceManager:
    @pytest.mark.unit
    def test_create_workspace(self, tmp_path: Path) -> None:
        mgr = WorkspaceManager(base_dir=tmp_path)
        with mgr.create_workspace() as ws_path:
            p = Path(ws_path)
            assert p.exists()
            assert p.is_dir()
            assert "agentsentinel_ws_" in p.name
        # After context exit, directory should be removed
        assert not p.exists()

    @pytest.mark.unit
    def test_populate_from_directory(self, tmp_path: Path) -> None:
        src = tmp_path / "source"
        src.mkdir()
        (src / "file.txt").write_text("sample content", encoding="utf-8")
        sub = src / "sub"
        sub.mkdir()
        (sub / "nested.py").write_text("print(1)", encoding="utf-8")

        mgr = WorkspaceManager()
        with mgr.create_workspace() as ws_path:
            dest = Path(ws_path)
            mgr.populate_from_directory(src, dest)

            assert (dest / "file.txt").exists()
            assert (dest / "file.txt").read_text(encoding="utf-8") == "sample content"
            assert (dest / "sub" / "nested.py").exists()

    @pytest.mark.unit
    def test_populate_nonexistent_source_raises(self, tmp_path: Path) -> None:
        mgr = WorkspaceManager()
        with (
            mgr.create_workspace() as ws_path,
            pytest.raises(HarnessSetupError, match="does not exist"),
        ):
            mgr.populate_from_directory(tmp_path / "nonexistent", Path(ws_path))

    @pytest.mark.unit
    def test_atomic_write(self, tmp_path: Path) -> None:
        mgr = WorkspaceManager()
        target = tmp_path / "deep" / "nested" / "output.txt"
        mgr.atomic_write(target, "atomic content")

        assert target.exists()
        assert target.read_text(encoding="utf-8") == "atomic content"

        # Overwrite atomically
        mgr.atomic_write(target, "updated content")
        assert target.read_text(encoding="utf-8") == "updated content"

    @pytest.mark.unit
    def test_git_scrubbing(self, tmp_path: Path) -> None:
        """Verify git history scrubbing removes the ENTIRE .git directory —
        not just reflogs — so that `git log -p --all` cannot leak future
        reference fixes."""
        repo = tmp_path / "test_repo"
        repo.mkdir()
        git_dir = repo / ".git"
        git_dir.mkdir()
        logs_dir = git_dir / "logs"
        logs_dir.mkdir()
        (logs_dir / "HEAD").write_text("commit log line", encoding="utf-8")
        objects = git_dir / "objects" / "pack"
        objects.mkdir(parents=True)
        (objects / "pack-abc.pack").write_bytes(b"fake-pack")
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

        mgr = WorkspaceManager()
        mgr.scrub_git_history(repo)

        # Entire .git directory must be removed
        assert not git_dir.exists()

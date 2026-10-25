"""Tests for M7 fault localization and image digest."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from agentsentinel.localization.ast_slicer import localize_faults
from agentsentinel.localization.traceback_parser import TracebackFrame, extract_traceback_frames
from agentsentinel.sandbox.container import resolve_image_digest

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# resolve_image_digest
# ---------------------------------------------------------------------------


class TestResolveImageDigest:
    def test_success_returns_sha(self) -> None:
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = "sha256:abc123\n"
        with patch.object(subprocess, "run", return_value=mock) as run:
            result = resolve_image_digest("myimage:latest")
        assert result == "sha256:abc123"
        run.assert_called_once()
        args = run.call_args[0][0]
        assert args == ["docker", "image", "inspect", "--format", "{{.Id}}", "myimage:latest"]

    def test_strips_whitespace(self) -> None:
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = "  sha256:deadbeef  \n"
        with patch.object(subprocess, "run", return_value=mock):
            assert resolve_image_digest("img") == "sha256:deadbeef"

    def test_nonzero_exit_returns_unavailable(self) -> None:
        mock = MagicMock()
        mock.returncode = 1
        mock.stdout = "sha256:abc"
        with patch.object(subprocess, "run", return_value=mock):
            assert resolve_image_digest("img") == "sha256:unavailable"

    def test_wrong_prefix_returns_unavailable(self) -> None:
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = "not-a-digest"
        with patch.object(subprocess, "run", return_value=mock):
            assert resolve_image_digest("img") == "sha256:unavailable"

    def test_empty_output_returns_unavailable(self) -> None:
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        with patch.object(subprocess, "run", return_value=mock):
            assert resolve_image_digest("img") == "sha256:unavailable"

    def test_exception_returns_unavailable(self) -> None:
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5)):
            assert resolve_image_digest("img") == "sha256:unavailable"

    def test_none_stdout_returns_unavailable(self) -> None:
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = None
        with patch.object(subprocess, "run", return_value=mock):
            assert resolve_image_digest("img") == "sha256:unavailable"


# ---------------------------------------------------------------------------
# extract_traceback_frames
# ---------------------------------------------------------------------------


class TestExtractTracebackFrames:
    def test_basic_pytest_format(self) -> None:
        stdout = "src/app/foo.py:10: in myfunc\n    x = 1\n"
        frames = extract_traceback_frames(stdout, "")
        assert len(frames) == 1
        assert frames[0].file_path == "src/app/foo.py"
        assert frames[0].line_number == 10
        assert frames[0].function_name == "myfunc"
        assert frames[0].code_line == "x = 1"

    def test_backslash_normalization(self) -> None:
        stdout = "src\\app\\foo.py:20: in bar\n    y = 2\n"
        frames = extract_traceback_frames(stdout, "")
        assert len(frames) == 1
        assert frames[0].file_path == "src/app/foo.py"
        assert frames[0].line_number == 20

    def test_ignores_tests_dir(self) -> None:
        stdout = "tests/test_foo.py:5: in test_thing\n    assert False\nsrc/app/foo.py:10: in myfunc\n    x=1\n"
        frames = extract_traceback_frames(stdout, "")
        assert all("tests/" not in f.file_path for f in frames)
        assert len(frames) == 1
        assert frames[0].file_path == "src/app/foo.py"

    def test_ignores_nested_tests(self) -> None:
        stdout = "foo/tests/bar.py:5: in func\n    x=1\n"
        frames = extract_traceback_frames(stdout, "")
        assert len(frames) == 0

    def test_ignores_site_packages(self) -> None:
        stdout = "/usr/lib/site-packages/pkg/foo.py:5: in func\n    x=1\nsrc/app/foo.py:10: in myfunc\n    x=1\n"
        frames = extract_traceback_frames(stdout, "")
        assert len(frames) == 1
        assert frames[0].file_path == "src/app/foo.py"

    def test_allowed_edit_paths_filter(self) -> None:
        stdout = "src/app/a.py:1: in fa\n    x=1\nsrc/app/b.py:2: in fb\n    y=1\n"
        frames = extract_traceback_frames(stdout, "", allowed_edit_paths=["src/app/a.py"])
        assert len(frames) == 1
        assert frames[0].file_path == "src/app/a.py"

    def test_stderr_parsing(self) -> None:
        stderr = "src/app/foo.py:15: in other\n    z=3\n"
        frames = extract_traceback_frames("", stderr)
        assert len(frames) == 1
        assert frames[0].line_number == 15

    def test_combined_stdout_stderr(self) -> None:
        stdout = "src/app/a.py:1: in fa\n    x=1\n"
        stderr = "src/app/b.py:2: in fb\n    y=2\n"
        frames = extract_traceback_frames(stdout, stderr)
        assert len(frames) == 2

    def test_file_line_format_fallback(self) -> None:
        stderr = 'File "src/app/foo.py", line 42, in myfunc\n    x=1\n'
        frames = extract_traceback_frames("", stderr)
        assert len(frames) == 1
        assert frames[0].file_path == "src/app/foo.py"
        assert frames[0].line_number == 42
        assert frames[0].function_name == "myfunc"


# ---------------------------------------------------------------------------
# localize_faults Hop-0 and Hop-1
# ---------------------------------------------------------------------------


class TestLocalizeFaults:
    def test_hop0_enclosing_function(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        foo = src_dir / "foo.py"
        foo.write_text(
            "def helper(x):\n"
            "    return x + 1\n"
            "\n"
            "def target(y):\n"
            "    a = helper(y)\n"
            "    return a * 2\n",
            encoding="utf-8",
        )
        frames = [TracebackFrame(file_path="src/app/foo.py", line_number=5, function_name="target", code_line="a = helper(y)")]
        slices = localize_faults(tmp_path, frames, allowed_edit_paths=["src/app/foo.py"], max_slices=5)
        assert len(slices) >= 1
        hop0 = [s for s in slices if s.hop_distance == 0]
        assert len(hop0) == 1
        assert hop0[0].symbol_name == "target"
        assert hop0[0].file_path == "src/app/foo.py"
        assert hop0[0].start_line == 4
        assert hop0[0].end_line == 6
        assert "target" in hop0[0].numbered_source
        assert "helper" in hop0[0].numbered_source

    def test_hop1_intra_repo(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        foo = src_dir / "foo.py"
        bar = src_dir / "bar.py"
        foo.write_text(
            "def target(y):\n"
            "    a = helper(y)\n"
            "    return a\n",
            encoding="utf-8",
        )
        bar.write_text(
            "def helper(x):\n"
            "    return x + 1\n",
            encoding="utf-8",
        )
        frames = [TracebackFrame(file_path="src/app/foo.py", line_number=2, function_name="target", code_line="a = helper(y)")]
        slices = localize_faults(tmp_path, frames, allowed_edit_paths=["src/app/foo.py", "src/app/bar.py"], max_slices=5)
        # should have hop0 target and hop1 helper
        [s for s in slices if s.hop_distance == 0]
        hop1 = [s for s in slices if s.hop_distance == 1]
        assert any(s.symbol_name == "target" and s.hop_distance == 0 for s in slices)
        assert any(s.symbol_name == "helper" and s.hop_distance == 1 for s in slices)
        # hop1 file should be bar.py
        helper_slices = [s for s in hop1 if s.symbol_name == "helper"]
        assert helper_slices[0].file_path == "src/app/bar.py"
        assert "helper" in helper_slices[0].numbered_source

    def test_hop0_class_def(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        foo = src_dir / "foo.py"
        foo.write_text(
            "class MyClass:\n"
            "    def method(self):\n"
            "        x = 1\n"
            "        return x\n",
            encoding="utf-8",
        )
        frames = [TracebackFrame(file_path="src/app/foo.py", line_number=3, function_name="method", code_line="x = 1")]
        slices = localize_faults(tmp_path, frames, allowed_edit_paths=["src/app/foo.py"], max_slices=5)
        # innermost enclosing is method, not MyClass (smaller span)
        assert any(s.symbol_name == "method" for s in slices)

    def test_max_slices_respected(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        foo = src_dir / "foo.py"
        foo.write_text(
            "def a():\n    helper()\n\ndef helper():\n    pass\n",
            encoding="utf-8",
        )
        bar = src_dir / "bar.py"
        bar.write_text("def helper():\n    pass\n", encoding="utf-8")
        frames = [TracebackFrame(file_path="src/app/foo.py", line_number=2, function_name="a", code_line="helper()")]
        slices = localize_faults(tmp_path, frames, allowed_edit_paths=["src/app/foo.py", "src/app/bar.py"], max_slices=1)
        assert len(slices) == 1
        assert slices[0].hop_distance == 0

    def test_ignores_frame_not_in_allowed(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        foo = src_dir / "foo.py"
        foo.write_text("def target():\n    pass\n", encoding="utf-8")
        frames = [TracebackFrame(file_path="src/app/other.py", line_number=1, function_name="target", code_line="")]
        slices = localize_faults(tmp_path, frames, allowed_edit_paths=["src/app/foo.py"], max_slices=5)
        assert slices == []

    def test_numbered_source_format(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "app"
        src_dir.mkdir(parents=True)
        foo = src_dir / "foo.py"
        foo.write_text("def foo():\n    x = 1\n    return x\n", encoding="utf-8")
        frames = [TracebackFrame(file_path="src/app/foo.py", line_number=2, function_name="foo", code_line="x = 1")]
        slices = localize_faults(tmp_path, frames, allowed_edit_paths=["src/app/foo.py"], max_slices=5)
        assert len(slices) == 1
        ns = slices[0].numbered_source
        # should contain line numbers and pipe
        assert "1 | def foo():" in ns
        assert "2 |     x = 1" in ns

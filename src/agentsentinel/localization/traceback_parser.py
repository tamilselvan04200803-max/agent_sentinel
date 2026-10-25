"""Traceback parsing for fault localization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Matches pytest-style: path.py:123: in func_name
# Also tolerates leading whitespace and optional prefix like 'File "'? We keep strict to spec.
_TRACEBACK_RE = re.compile(r"^\s*(.+?\.py):(\d+):\s+in\s+(\S+)\s*$")
# Fallback for Python standard traceback: File "path.py", line 123, in func
_FILE_LINE_RE = re.compile(r'^\s*File\s+"(.+?\.py)"\s*,\s*line\s+(\d+)\s*,\s*in\s+(\S+)\s*$')


@dataclass(frozen=True)
class TracebackFrame:
    """Single parsed frame from a pytest traceback."""

    file_path: str
    line_number: int
    function_name: str
    code_line: str


def _normalize(path: str) -> str:
    return path.replace("\\", "/").strip()


def _is_ignored(normalized: str) -> bool:
    if "site-packages" in normalized:
        return True
    # ignore any file under tests/ at start or with /tests/ segment
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    # also ignore bare tests.py? but spec says tests/
    return normalized == "tests.py"


def extract_traceback_frames(
    stdout: str,
    stderr: str,
    allowed_edit_paths: Sequence[str] | None = None,
) -> list[TracebackFrame]:
    """Parse pytest tracebacks from combined stdout/stderr.

    Normalizes ``\\`` to ``/``, ignores ``tests/`` and ``site-packages``,
    and optionally filters to ``allowed_edit_paths`` when provided.
    """
    combined = (stdout or "") + "\n" + (stderr or "")
    lines = combined.splitlines()

    allowed_set: set[str] | None = None
    if allowed_edit_paths is not None:
        allowed_set = {_normalize(p) for p in allowed_edit_paths}

    frames: list[TracebackFrame] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _TRACEBACK_RE.match(line)
        if m is None:
            m = _FILE_LINE_RE.match(line)
        if m is not None:
            raw_path = m.group(1)
            lineno_str = m.group(2)
            func = m.group(3)
            norm_path = _normalize(raw_path)
            # Strip leading ./ if present
            if norm_path.startswith("./"):
                norm_path = norm_path[2:]
            if _is_ignored(norm_path):
                i += 1
                continue
            if allowed_set is not None and norm_path not in allowed_set:
                i += 1
                continue
            try:
                lineno = int(lineno_str)
            except ValueError:
                i += 1
                continue
            # code_line is next non-empty line that is not another frame
            code_line = ""
            if i + 1 < len(lines):
                nxt = lines[i + 1].strip()
                # If next line looks like a frame, leave code_line empty
                if (
                    _TRACEBACK_RE.match(lines[i + 1]) is None
                    and _FILE_LINE_RE.match(lines[i + 1]) is None
                ):
                    # Heuristic: code lines are indented or contain code
                    # We capture stripped next line unless it starts with E   or =
                    if nxt and not nxt.startswith("E ") and not nxt.startswith("="):
                        code_line = nxt
                    elif nxt and ("assert" in nxt or "def " in nxt or "=" in nxt):
                        # Keep as stripped line for test visibility
                        code_line = nxt
            frames.append(
                TracebackFrame(
                    file_path=norm_path,
                    line_number=lineno,
                    function_name=func,
                    code_line=code_line,
                )
            )
        i += 1
    return frames

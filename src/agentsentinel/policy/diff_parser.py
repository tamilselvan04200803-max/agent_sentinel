"""Unified diff parser and canonicalizer.

Formal parser for unified diffs. Does not use brittle regular expressions
to guess line edits. Parses:
- Git diff headers (`diff --git a/path b/path`)
- File rename, new file mode, deleted file mode
- Old and new paths (`--- a/...`, `+++ b/...`, `--- /dev/null`)
- Hunk headers (`@@ -old_start,old_count +new_start,new_count @@ [optional context]`)
- Hunk content lines (`+`, `-`, ` `)
- Rejection of binary diffs (`GIT binary patch`, `Binary files ... differ`)

All data structures are immutable dataclasses (`frozen=True`).
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsentinel.domain.exceptions import MalformedDiffError


@dataclass(frozen=True)
class HunkLine:
    """A single line in a diff hunk.

    Attributes
    ----------
    origin:
        '+' for additions, '-' for deletions, ' ' for context lines, '\\' for no-newline markers.
    content:
        The text content of the line without the leading origin character.
    """

    origin: str
    content: str

    def __post_init__(self) -> None:
        if self.origin not in ("+", "-", " ", "\\"):
            raise ValueError(f"Invalid hunk line origin: {self.origin!r}")


@dataclass(frozen=True)
class Hunk:
    """Represents a unified diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    heading: str
    lines: tuple[HunkLine, ...]

    def __post_init__(self) -> None:
        if self.old_start < 0 or self.new_start < 0:
            raise ValueError("Hunk start line numbers must be non-negative")
        if self.old_count < 0 or self.new_count < 0:
            raise ValueError("Hunk line counts must be non-negative")


@dataclass(frozen=True)
class FilePatch:
    """A patch targeting a single file."""

    old_path: str | None
    new_path: str | None
    hunks: tuple[Hunk, ...]
    is_binary: bool = False
    is_new: bool = False
    is_delete: bool = False
    is_rename: bool = False

    @property
    def target_paths(self) -> tuple[str, ...]:
        """Return ALL real file paths touched by this patch, excluding ``/dev/null``.

        For a normal modification this is a single-element tuple. For a rename
        (``is_rename``) or a deletion that is tracked against a specific source
        path we return **both** the old and new paths (when they are real
        filesystem paths — i.e. not ``/dev/null``). This is critical for the
        policy validator: when a diff renames ``tests/test_x.py`` →
        ``src/x.py`` (a reward-hacking attempt to hide a test), the validator
        must see BOTH paths and reject the patch for touching a test file.
        """
        paths: list[str] = []
        seen: set[str] = set()
        for p in (self.old_path, self.new_path):
            if p and p != "/dev/null" and p not in seen:
                paths.append(p)
                seen.add(p)
        return tuple(paths)

    @property
    def target_path(self) -> str:
        """The canonical *primary* target path (preferring new_path, else old_path)."""
        if self.new_path and self.new_path != "/dev/null":
            return self.new_path
        if self.old_path and self.old_path != "/dev/null":
            return self.old_path
        return ""


@dataclass(frozen=True)
class ParsedDiff:
    """The complete representation of a parsed unified diff."""

    raw_diff: str
    files: tuple[FilePatch, ...]

    @property
    def target_paths(self) -> tuple[str, ...]:
        """All real file paths touched by this diff (excluding ``/dev/null``).

        For renames this includes BOTH the source and destination paths so
        that ``validator.py`` can block test deletion / test renaming.
        """
        out: list[str] = []
        seen: set[str] = set()
        for f in self.files:
            for p in f.target_paths:
                if p and p not in seen:
                    out.append(p)
                    seen.add(p)
        return tuple(out)


class UnifiedDiffParser:
    """Deterministic, production-grade parser for unified diffs."""

    @staticmethod
    def parse(diff_text: str) -> ParsedDiff:
        """Parse raw unified diff text into a structured ParsedDiff object.

        CRLF normalisation
        ------------------
        LLM outputs and Windows-generated diffs routinely mix ``\r\n`` and
        ``\n`` line endings. Before parsing we normalise every line ending to
        plain ``\n`` so that header detection (``--- a/...``, ``+++ b/...``)
        and hunk parsing behave identically across platforms. We do NOT strip
        carriage returns from hunk *content* lines — a bare ``\r`` at column
        zero of a content line would be misinterpreted as a missing origin
        character, so we split lines in a CRLF-aware way via ``splitlines()``
        which already strips both ``\r\n`` and ``\n`` terminators.

        Parameters
        ----------
        diff_text:
            Raw unified diff content.

        Returns
        -------
        ParsedDiff
            Parsed diff structure.

        Raises
        ------
        MalformedDiffError:
            If the diff is unparseable or contains binary payloads.
        """
        if not diff_text or not diff_text.strip():
            raise MalformedDiffError("Diff text is empty")

        # Normalise CRLF → LF up front. ``str.splitlines()`` already handles
        # \r\n, \n, \r, etc. and strips the terminators, so just normalising
        # the input by replacing \r\n with \n is sufficient to ensure
        # consistent header/hunk parsing.
        diff_text = diff_text.replace("\r\n", "\n").replace("\r", "\n")

        lines = diff_text.splitlines()
        file_patches: list[FilePatch] = []

        i = 0
        n = len(lines)

        while i < n:
            line = lines[i]

            # Detect and immediately reject binary diffs
            if line.startswith("GIT binary patch") or "Binary files " in line:
                raise MalformedDiffError("Binary diffs are strictly forbidden", context=line)

            # Check for file header
            if line.startswith("diff --git ") or line.startswith("--- "):
                old_path: str | None = None
                new_path: str | None = None
                is_binary = False
                is_new = False
                is_delete = False
                is_rename = False

                if line.startswith("diff --git "):
                    # git diff header: diff --git a/path b/path
                    parts = line.split(" ", 3)
                    if len(parts) >= 4:
                        old_raw = parts[2]
                        new_raw = parts[3]
                        old_path = old_raw[2:] if old_raw.startswith("a/") else old_raw
                        new_path = new_raw[2:] if new_raw.startswith("b/") else new_raw
                    i += 1

                # Parse intermediate extended git headers (index, new file, deleted file, rename)
                while (
                    i < n
                    and not lines[i].startswith("--- ")
                    and not lines[i].startswith("diff --git ")
                ):
                    sub = lines[i]
                    if sub.startswith("new file mode"):
                        is_new = True
                    elif sub.startswith("deleted file mode"):
                        is_delete = True
                    elif sub.startswith("similarity index") or sub.startswith("rename "):
                        is_rename = True
                    elif "Binary files " in sub or sub.startswith("GIT binary patch"):
                        raise MalformedDiffError("Binary diffs are strictly forbidden", context=sub)
                    i += 1

                if i < n and lines[i].startswith("--- "):
                    raw_old = lines[i][4:].strip()
                    # Strip timestamp if present (e.g. --- path\t2026-01-01)
                    raw_old = raw_old.split("\t")[0]
                    if raw_old.startswith("a/"):
                        old_path = raw_old[2:]
                    elif raw_old == "/dev/null":
                        old_path = "/dev/null"
                        is_new = True
                    else:
                        old_path = raw_old
                    i += 1

                if i < n and lines[i].startswith("+++ "):
                    raw_new = lines[i][4:].strip()
                    raw_new = raw_new.split("\t")[0]
                    if raw_new.startswith("b/"):
                        new_path = raw_new[2:]
                    elif raw_new == "/dev/null":
                        new_path = "/dev/null"
                        is_delete = True
                    else:
                        new_path = raw_new
                    i += 1

                # Now parse hunks for this file
                hunks: list[Hunk] = []
                while i < n and lines[i].startswith("@@ "):
                    hunk, next_i = UnifiedDiffParser._parse_hunk(lines, i)
                    hunks.append(hunk)
                    i = next_i

                file_patches.append(
                    FilePatch(
                        old_path=old_path,
                        new_path=new_path,
                        hunks=tuple(hunks),
                        is_binary=is_binary,
                        is_new=is_new,
                        is_delete=is_delete,
                        is_rename=is_rename,
                    )
                )
            else:
                # Non-header preamble or unrecognized line
                i += 1

        if not file_patches:
            raise MalformedDiffError("No valid file patches found in diff")

        return ParsedDiff(raw_diff=diff_text, files=tuple(file_patches))

    @staticmethod
    def _parse_hunk(lines: list[str], start_idx: int) -> tuple[Hunk, int]:
        """Parse a single hunk starting at lines[start_idx]."""
        header_line = lines[start_idx]
        parts = header_line.split("@@")
        if len(parts) < 3:
            raise MalformedDiffError(
                f"Invalid hunk header syntax: {header_line}", context=header_line
            )

        range_spec = parts[1].strip()
        heading = parts[2].strip() if len(parts) > 2 else ""

        # range_spec is typically "-old_start,old_count +new_start,new_count"
        ranges = range_spec.split(" ")
        if len(ranges) != 2:
            raise MalformedDiffError(f"Invalid hunk ranges: {range_spec}", context=header_line)

        old_part = ranges[0]
        new_part = ranges[1]

        if not old_part.startswith("-") or not new_part.startswith("+"):
            raise MalformedDiffError(
                f"Malformed hunk range signs: {range_spec}", context=header_line
            )

        try:
            old_coords = old_part[1:].split(",")
            old_start = int(old_coords[0])
            old_count = int(old_coords[1]) if len(old_coords) > 1 else 1

            new_coords = new_part[1:].split(",")
            new_start = int(new_coords[0])
            new_count = int(new_coords[1]) if len(new_coords) > 1 else 1
        except ValueError as e:
            raise MalformedDiffError(
                f"Failed to parse hunk coordinates: {range_spec}", context=header_line
            ) from e

        hunk_lines: list[HunkLine] = []
        i = start_idx + 1
        n = len(lines)

        while i < n:
            line = lines[i]
            if line.startswith("@@ ") or line.startswith("diff --git ") or line.startswith("--- "):
                break

            if not line:
                # An empty line in a unified diff is treated as an empty context line
                hunk_lines.append(HunkLine(origin=" ", content=""))
                i += 1
                continue

            origin = line[0]
            if origin in ("+", "-", " ", "\\"):
                hunk_lines.append(HunkLine(origin=origin, content=line[1:]))
            else:
                # Stop parsing hunk if line does not have a hunk prefix
                break
            i += 1

        return (
            Hunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                heading=heading,
                lines=tuple(hunk_lines),
            ),
            i,
        )

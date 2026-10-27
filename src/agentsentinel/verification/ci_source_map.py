"""Read-only, strict unified-diff reconstruction for the standalone CI gate."""

from __future__ import annotations

import os
import stat
import unicodedata
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import MalformedDiffError
from agentsentinel.policy.diff_healer import _count_matches, heal_diff_line_numbers
from agentsentinel.policy.diff_parser import FilePatch, Hunk, UnifiedDiffParser
from agentsentinel.verification.patch_minimizer import _HUNK_HEADER_RE, _split_diff_sections

if TYPE_CHECKING:
    from pathlib import Path


class CIGateUsageError(ValueError):
    """Inputs cannot establish an unambiguous pre/post source map."""


class FileLifecycleStatus(str, Enum):  # noqa: UP042 -- preserve the specified str/Enum API
    MODIFIED = "MODIFIED"
    CREATED = "CREATED"
    DELETED = "DELETED"
    RENAMED = "RENAMED"


@dataclass(frozen=True)
class SourceMapEntry:
    file_path: str
    old_path: str | None
    status: FileLifecycleStatus
    pre_buffer: str
    post_buffer: str
    added_lines: tuple[tuple[int, str], ...]
    line_map: dict[int, int]


def contained_path(path: str, root: Path) -> str:
    """Normalize a relative path without dropping leading filename dots."""
    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if (
        not parts
        or ".." in parts
        or PurePosixPath(normalized).is_absolute()
        or PureWindowsPath(path).drive
        or path.startswith('"')
        or (os.name == "nt" and any(part.endswith((".", " ")) or ":" in part for part in parts))
        or any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in path)
    ):
        raise CIGateUsageError("Unsafe or unsupported diff path")
    candidate = root.joinpath(*parts).resolve()
    if not candidate.is_relative_to(root):
        raise CIGateUsageError("Diff path escapes the workspace")
    return PurePosixPath(*parts).as_posix()


def _identity(path: str, root: Path) -> str:
    return os.path.normcase(str((root / path).resolve()))


def _endpoint(path: str | None, root: Path, replacements: dict[str, str]) -> str | None:
    return (
        contained_path(_restore(path, replacements), root) if path and path != "/dev/null" else None
    )


def _escape_separators(raw: str) -> tuple[str, dict[str, str]]:
    # Existing M2/M9 parsing uses splitlines/universal-newline normalization.
    # Preserve physical LF lines and bare CR for subsequent hygiene diagnostics.
    prefix = "\ue000CI_LINE\ue001"
    while prefix in raw:
        prefix += "_"
    replacements = {
        f"{prefix}{ord(char):x};": char for char in "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
    }
    for token, char in replacements.items():
        raw = raw.replace(char, token)
    return raw, replacements


def _restore(value: str, replacements: dict[str, str]) -> str:
    for token, char in replacements.items():
        value = value.replace(token, char)
    return value


def _strict_parse(raw: str) -> tuple[FilePatch, ...]:
    parsed = UnifiedDiffParser.parse(raw)
    sections = _split_diff_sections(raw)
    if len(sections) != len(parsed.files):
        raise CIGateUsageError("Unexpected diff preamble or file section")
    result: list[FilePatch] = []
    for section, file in zip(sections, parsed.files, strict=True):
        if not section or not section[0].startswith(("diff --git ", "--- ")):
            raise CIGateUsageError("Invalid file section")
        index = 0
        saw_hunk = False
        old_headers = new_headers = 0
        metadata: dict[str, str] = {}
        while index < len(section):
            line = section[index]
            if line.startswith("@@"):
                saw_hunk = True
                if not _HUNK_HEADER_RE.fullmatch(line):
                    raise CIGateUsageError("Malformed hunk coordinates")
                hunk, index = UnifiedDiffParser._parse_hunk(section, index)
                old_count = sum(item.origin in (" ", "-") for item in hunk.lines)
                new_count = sum(item.origin in (" ", "+") for item in hunk.lines)
                if (old_count, new_count) != (hunk.old_count, hunk.new_count):
                    raise CIGateUsageError("Hunk counts do not match its body")
                if not any(item.origin in ("+", "-") for item in hunk.lines):
                    raise CIGateUsageError("Hunk makes no changes")
                if (hunk.old_count and hunk.old_start == 0) or (
                    hunk.new_count and hunk.new_start == 0
                ):
                    raise CIGateUsageError("Nonempty hunk ranges must be 1-indexed")
                continue
            if saw_hunk:
                raise CIGateUsageError("Unexpected content after a hunk")
            index_mode = line.startswith("index ") and len(line.split()) == 3
            if index_mode or line.startswith(
                ("new file mode ", "deleted file mode ", "old mode ", "new mode ")
            ):
                mode = line.rsplit(" ", 1)[-1]
                if (
                    len(mode) != 6
                    or not mode.startswith("100")
                    or any(char not in "01234567" for char in mode)
                ):
                    raise CIGateUsageError("Only regular text-file modes are supported")
            if line.startswith(("--- ", "+++ ")):
                raw_path = line[4:].split("\t", 1)[0]
                if raw_path != raw_path.strip():
                    raise CIGateUsageError("Ambiguous whitespace in file header path")
            if line.startswith("--- "):
                old_headers += 1
            elif line.startswith("+++ "):
                new_headers += 1
            elif line.startswith(("rename from ", "rename to ", "old mode ", "new mode ")):
                name, value = (
                    line.rsplit(" ", 1)
                    if "mode " in line
                    else (
                        line.split(" ", 2)[0] + " " + line.split(" ", 2)[1],
                        line.split(" ", 2)[2],
                    )
                )
                metadata[name] = value
            elif not line.startswith(
                (
                    "diff --git ",
                    "index ",
                    "new file mode ",
                    "deleted file mode ",
                    "similarity index ",
                    "dissimilarity index ",
                )
            ):
                raise CIGateUsageError("Unsupported or corrupt diff metadata")
            index += 1
        if saw_hunk and (old_headers, new_headers) != (1, 1):
            raise CIGateUsageError("Hunks require paired file headers")
        if not saw_hunk:
            if "rename from" in metadata and "rename to" in metadata:
                file = replace(
                    file,
                    old_path=metadata["rename from"],
                    new_path=metadata["rename to"],
                    is_rename=True,
                )
            elif not (file.is_new or file.is_delete or {"old mode", "new mode"} <= metadata.keys()):
                raise CIGateUsageError("File section has no changes")
        if not file.old_path or not file.new_path or (file.is_new and file.is_delete):
            raise CIGateUsageError("Invalid file lifecycle headers")
        if (
            file.is_new
            and file.old_path != "/dev/null"
            and (saw_hunk or file.old_path != file.new_path)
        ):
            raise CIGateUsageError("Created file has a nonempty source endpoint")
        if (
            file.is_delete
            and file.new_path != "/dev/null"
            and (saw_hunk or file.old_path != file.new_path)
        ):
            raise CIGateUsageError("Deleted file has a real destination endpoint")
        if section[0].startswith("diff --git "):
            old_real = file.old_path if file.old_path != "/dev/null" else file.new_path
            new_real = file.new_path if file.new_path != "/dev/null" else file.old_path
            if section[0] not in {
                f"diff --git a/{old_real} b/{new_real}",
                f"diff --git {old_real} {new_real}",
            }:
                raise CIGateUsageError("Git and unified file headers disagree")
        if "rename from" in metadata and file.old_path != metadata["rename from"]:
            raise CIGateUsageError("Rename metadata disagrees with file headers")
        if "rename to" in metadata and file.new_path != metadata["rename to"]:
            raise CIGateUsageError("Rename metadata disagrees with file headers")
        result.append(file)
    return tuple(result)


def _records(source: str) -> list[str]:
    parts = source.split("\n")
    return [part + "\n" for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _apply_hunks(
    source: str,
    hunks: tuple[Hunk, ...],
) -> tuple[str, tuple[tuple[int, str], ...], dict[int, int]]:
    pre = _records(source)
    content = [line.removesuffix("\n") for line in pre]
    post: list[str] = []
    added: list[tuple[int, str]] = []
    line_map: dict[int, int] = {}
    cursor = 0
    for hunk in hunks:
        start = hunk.old_start if hunk.old_count == 0 else hunk.old_start - 1
        preimage = [line.content for line in hunk.lines if line.origin in (" ", "-")]
        if preimage and content[start : start + len(preimage)] != preimage:
            matches = _count_matches(content, preimage)
            if len(matches) != 1:
                raise CIGateUsageError("Hunk context is missing or ambiguous")
            start = matches[0]
        if start < cursor or start > len(pre):
            raise CIGateUsageError("Overlapping or out-of-order hunks")
        while cursor < start:
            line_map[cursor + 1] = len(post) + 1
            post.append(pre[cursor])
            cursor += 1
        for index, line in enumerate(hunk.lines):
            if line.origin == "\\":
                if (
                    line.content != " No newline at end of file"
                    or index == 0
                    or hunk.lines[index - 1].origin == "\\"
                ):
                    raise CIGateUsageError("Invalid newline marker")
                continue
            no_newline = index + 1 < len(hunk.lines) and hunk.lines[index + 1].origin == "\\"
            record = line.content + ("" if no_newline else "\n")
            if line.origin in (" ", "-"):
                if cursor >= len(pre) or pre[cursor] != record:
                    raise CIGateUsageError("Hunk preimage or EOF newline does not match")
                if line.origin == " ":
                    line_map[cursor + 1] = len(post) + 1
                cursor += 1
            if line.origin in (" ", "+"):
                if post and not post[-1].endswith("\n"):
                    raise CIGateUsageError("Content follows an unterminated line")
                post.append(record)
                if line.origin == "+":
                    added.append((len(post), line.content))
    while cursor < len(pre):
        if post and not post[-1].endswith("\n"):
            raise CIGateUsageError("Content follows an unterminated line")
        line_map[cursor + 1] = len(post) + 1
        post.append(pre[cursor])
        cursor += 1
    return "".join(post), tuple(added), line_map


def reconstruct_in_memory_source_map(
    raw_diff: str,
    workspace_root: Path,
) -> tuple[SourceMapEntry, ...]:
    """Heal coordinates, validate structure, and apply hunks to buffers only."""
    try:
        if (
            not workspace_root.is_dir()
            or not isinstance(raw_diff, str)
            or not raw_diff.strip()
            or "\x00" in raw_diff
        ):
            raise CIGateUsageError("A workspace directory and nonempty text diff are required")
        root = workspace_root.resolve()
        encoded, replacements = _escape_separators(raw_diff.replace("\r\n", "\n"))
        originals = _strict_parse(encoded)
        for file in originals:
            for path in file.target_paths:
                contained_path(_restore(path, replacements), root)
        healed = heal_diff_line_numbers(encoded, root).healed_diff
        parsed = _strict_parse(healed)
        endpoints = [
            (
                file,
                _endpoint(file.old_path, root, replacements),
                _endpoint(file.new_path, root, replacements),
            )
            for file in parsed
        ]
        vacated = {
            _identity(old, root)
            for file, old, new in endpoints
            if old is not None
            and not file.is_new
            and (file.is_delete or new is None or _identity(old, root) != _identity(new, root))
        }
        entries: list[SourceMapEntry] = []
        old_seen: set[str] = set()
        new_seen: set[str] = set()
        for file, old, new in endpoints:
            created = file.is_new or old is None
            deleted = file.is_delete or new is None
            if created and deleted:
                raise CIGateUsageError("Invalid file lifecycle")
            old_key = _identity(old, root) if old is not None else None
            new_key = _identity(new, root) if new is not None else None
            if (old_key is not None and old_key in old_seen) or (
                new_key is not None and new_key in new_seen
            ):
                raise CIGateUsageError("Duplicate file endpoints in diff")
            if old_key:
                old_seen.add(old_key)
            if new_key:
                new_seen.add(new_key)
            if (
                not created
                and not deleted
                and new is not None
                and old_key != new_key
                and (root / new).exists()
                and new_key not in vacated
            ):
                raise CIGateUsageError("Rename destination exists and is not vacated by this diff")
            if created:
                if new is None or (root / new).exists():
                    raise CIGateUsageError("Created file already exists")
                pre = ""
                status = FileLifecycleStatus.CREATED
            else:
                if old is None:
                    raise CIGateUsageError("Missing source path")
                if not stat.S_ISREG((root / old).lstat().st_mode):
                    raise CIGateUsageError("Only regular text-file preimages are supported")
                pre = (root / old).read_bytes().decode("utf-8").replace("\r\n", "\n")
                if "\x00" in pre:
                    raise CIGateUsageError("Binary source is not supported")
                status = (
                    FileLifecycleStatus.DELETED
                    if deleted
                    else (
                        FileLifecycleStatus.RENAMED if old != new else FileLifecycleStatus.MODIFIED
                    )
                )
            hunks = tuple(
                replace(
                    hunk,
                    lines=tuple(
                        replace(line, content=_restore(line.content, replacements))
                        for line in hunk.lines
                    ),
                )
                for hunk in file.hunks
            )
            post, added, mapping = _apply_hunks(pre, hunks)
            if deleted and post:
                raise CIGateUsageError("Deleted file still has unremoved content")
            if new is None and old is None:
                raise CIGateUsageError("Missing target path")
            entries.append(
                SourceMapEntry(
                    new or old or "",
                    None if created else old,
                    status,
                    pre,
                    post,
                    added,
                    mapping,
                )
            )
        return tuple(entries)
    except (MalformedDiffError, OSError, UnicodeError, ValueError, RuntimeError) as exc:
        if isinstance(exc, CIGateUsageError):
            raise
        raise CIGateUsageError("Diff or workspace cannot be reconstructed safely") from exc

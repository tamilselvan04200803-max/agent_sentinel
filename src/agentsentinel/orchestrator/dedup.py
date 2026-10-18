"""Two-tier patch deduplication for Milestone 4.

Tier 1 (Canonical Diff Fingerprint)
-----------------------------------
Strips variable header noise (``--- a/`` / ``+++ b/`` timestamps, ``index`` lines)
and computes SHA-256 over canonicalized ``(target_path, hunk ranges,
normalized added/removed lines)``. This catches byte-identical and near-identical
re-issues of the same patch even when the LLM regenerates timestamps.

Tier 2 (Python AST Equivalence Fingerprint)
-------------------------------------------
After a patch is applied to the staging workspace, every ``.py`` file in
``allowed_edit_paths`` is parsed with :func:`ast.parse` and SHA-256 is computed
over :func:`ast.dump(tree, include_attributes=False)`. If the post-patch AST
fingerprint equals the **original buggy baseline AST** (e.g. the LLM only edited
comments, docstrings, or whitespace), or matches **any prior attempt's** AST
fingerprint, we classify the proposal as a duplicate/no-op
(:class:`DuplicatePatchError`) **before** spinning up a Docker container.

Both tiers are strict and deterministic: no fuzzy matching, no hashing of
whitespace-only deltas.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import DuplicatePatchError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from agentsentinel.policy.diff_parser import FilePatch, ParsedDiff

# ---------------------------------------------------------------------------
# Tier 1 — canonical diff fingerprint
# ---------------------------------------------------------------------------

# Match "index <sha>..<sha> <mode>" lines in git diff headers
_INDEX_LINE_RE = re.compile(r"^index\s+[0-9a-f]{4,40}\.\.[0-9a-f]{4,40}(\s+\d+)?\s*$")
# Match an optional trailing tab+timestamp on --- / +++ lines
_HEADER_TS_RE = re.compile(r"^(---\s+\S+|\+\+\+\s+\S+)\t.*$")


@dataclass(frozen=True)
class Tier1Fingerprint:
    """The SHA-256 hex digest of the canonicalised diff (Tier 1)."""

    hex: str


def canonicalize_diff(diff_text: str) -> str:
    """Canonicalize a unified diff for Tier-1 fingerprinting.

    Operations applied (in order):
    1. Normalize CRLF / CR → LF.
    2. Strip ``index <sha>..<sha>`` header lines (object IDs vary with history).
    3. Strip trailing ``\\t<timestamp>`` suffixes from ``---`` / ``+++`` headers.
    4. Normalize path prefixes: strip ``a/`` / ``b/`` prefixes so path-only identity
       emerges regardless of ``--no-prefix`` variations.
    5. Drop trailing whitespace from every line (no-op for semantic hunks).
    """
    text = diff_text.replace("\r\n", "\n").replace("\r", "\n")
    out_lines: list[str] = []
    for raw in text.split("\n"):
        line = raw.rstrip()
        if _INDEX_LINE_RE.match(line):
            continue
        m = _HEADER_TS_RE.match(line)
        if m:
            line = m.group(1)
        # Strip a/ or b/ prefixes from --- / +++ headers:  "--- a/foo" → "--- foo"
        if line.startswith("--- a/"):
            line = "--- " + line[len("--- a/"):]
        elif line.startswith("--- b/"):
            line = "--- " + line[len("--- b/"):]
        if line.startswith("+++ b/"):
            line = "+++ " + line[len("+++ b/"):]
        elif line.startswith("+++ a/"):
            line = "+++ " + line[len("+++ a/"):]
        out_lines.append(line)
    return "\n".join(out_lines)


def tier1_fingerprint(diff_text: str) -> Tier1Fingerprint:
    """Compute the canonical-diff SHA-256 fingerprint for Tier 1 dedup."""
    canon = canonicalize_diff(diff_text)
    h = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return Tier1Fingerprint(hex=h)


def _file_patch_canonical_key(fp: FilePatch) -> str:
    """Canonical representation of a single file patch for Tier 1 hashing."""
    parts = [
        f"path={fp.target_path}",
        f"new={fp.is_new}",
        f"del={fp.is_delete}",
        f"ren={fp.is_rename}",
    ]
    for h in fp.hunks:
        parts.append(
            f"hunk@{h.old_start},{h.old_count}->{h.new_start},{h.new_count}:"
        )
        for hl in h.lines:
            parts.append(f"{hl.origin}{hl.content}")
    return "\n".join(parts)


def tier1_fingerprint_from_parsed(parsed: ParsedDiff) -> Tier1Fingerprint:
    """Compute Tier-1 fingerprint from an already-parsed diff (avoids double parse)."""
    payload_parts = [_file_patch_canonical_key(fp) for fp in parsed.files]
    payload = "\n===\n".join(payload_parts)
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return Tier1Fingerprint(hex=h)


# ---------------------------------------------------------------------------
# Tier 2 — AST equivalence fingerprint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tier2Fingerprint:
    """The SHA-256 hex digest of the combined AST of all Python files considered."""

    hex: str
    per_file: tuple[tuple[str, str], ...]


def _ast_fingerprint_for_source(source: str) -> str:
    """Return the SHA-256 of ``ast.dump(tree, include_attributes=False)`` for ``source``."""
    tree = ast.parse(source)
    dumped = ast.dump(tree, include_attributes=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _ast_fingerprint_for_file(path: Path) -> str | None:
    """Return the per-file AST fingerprint, or ``None`` if the file cannot be
    parsed (we treat unparseable files neutrally: they do not contribute to
    the aggregate hash, which conservatively avoids false-positive dedup)."""
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        return _ast_fingerprint_for_source(src)
    except SyntaxError:
        return None


def tier2_fingerprint(
    workspace_root: Path,
    allowed_edit_paths: Iterable[str],
) -> Tier2Fingerprint:
    """Compute the aggregate AST fingerprint across ``allowed_edit_paths`` after
    a patch has been applied to ``workspace_root``.

    Files that don't exist or fail to parse are omitted from the aggregate
    (they cannot be the source of a no-op/duplicate false positive).
    """
    per_file: list[tuple[str, str]] = []
    for rel in allowed_edit_paths:
        if not rel.endswith(".py"):
            continue
        fp = (workspace_root / rel).resolve()
        if not fp.exists() or not fp.is_file():
            continue
        digest = _ast_fingerprint_for_file(fp)
        if digest is not None:
            per_file.append((rel, digest))

    per_file.sort()
    aggregate_src = "\n".join(f"{rel}:{dig}" for rel, dig in per_file)
    aggregate = hashlib.sha256(aggregate_src.encode("utf-8")).hexdigest()
    return Tier2Fingerprint(hex=aggregate, per_file=tuple(per_file))


# ---------------------------------------------------------------------------
# Dedup checks (raise DuplicatePatchError on hit)
# ---------------------------------------------------------------------------


def check_tier1_duplicate(
    diff_text: str,
    seen_diff_hashes: set[str],
) -> Tier1Fingerprint:
    """Check ``diff_text`` against the Tier-1 dedup set.

    Raises :class:`DuplicatePatchError` (tier="tier1") if the canonical
    fingerprint has already been observed; otherwise returns the fingerprint
    for the caller to add to the seen set.
    """
    fp = tier1_fingerprint(diff_text)
    if fp.hex in seen_diff_hashes:
        raise DuplicatePatchError(
            f"canonical diff hash {fp.hex[:12]}… already attempted",
            tier="tier1",
        )
    return fp


def check_tier2_duplicate_or_noop(
    workspace_root: Path,
    allowed_edit_paths: Iterable[str],
    baseline_ast_hash: str | None,
    seen_ast_hashes: set[str],
) -> Tier2Fingerprint:
    """Check the post-patch AST fingerprint against baseline and prior attempts.

    Raises :class:`DuplicatePatchError` if:
    - The post-patch AST equals ``baseline_ast_hash`` (the patch was a semantic
      no-op: comments, whitespace, docstrings, or AST-equivalent rewrites).
    - The post-patch AST is already in ``seen_ast_hashes`` (different diff,
      semantically identical program).
    """
    fp = tier2_fingerprint(workspace_root, allowed_edit_paths)
    if baseline_ast_hash is not None and fp.hex == baseline_ast_hash:
        raise DuplicatePatchError(
            "post-patch AST equals baseline AST (patch was semantically a no-op)",
            tier="tier2-noop",
        )
    if fp.hex in seen_ast_hashes:
        raise DuplicatePatchError(
            f"AST hash {fp.hex[:12]}… matches a prior attempt",
            tier="tier2-dup",
        )
    return fp


__all__ = [
    "Tier1Fingerprint",
    "Tier2Fingerprint",
    "canonicalize_diff",
    "tier1_fingerprint",
    "tier1_fingerprint_from_parsed",
    "tier2_fingerprint",
    "check_tier1_duplicate",
    "check_tier2_duplicate_or_noop",
]

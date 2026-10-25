"""Research-backed deterministic hunk line-drift healer.

Empirical APR research (Agentless 2024, SWE-bench post-mortems) shows
15-25% of valid LLM diffs fail ``git apply --check`` solely because the
LLM miscounts the ``@@ -old_start,old_count +new_start,new_count @@``
line numbers even when the hunk's context/removed lines match the target
file uniquely.

This module provides :func:`heal_diff_line_numbers` which performs a
deterministic, safety-invariant line-number correction:

- If the pre-image sequence already matches at ``old_start`` → leave unchanged.
- If the pre-image sequence matches at exactly **one** other location
  → rewrite the ``@@`` header to the true offsets.
- If the sequence matches 0 times (corrupt context) or >=2 times
  (ambiguous duplicate blocks) → **do not** modify (let ``git apply``
  fail deterministically with ``PatchApplicationError``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from agentsentinel.policy.diff_parser import UnifiedDiffParser


@dataclass(frozen=True)
class HealResult:
    """Result of a line-number healing operation.

    Attributes
    ----------
    healed_diff:
        The (possibly rewritten) unified diff string. If no hunks were
        healed, this equals the normalized input.
    was_healed:
        ``True`` if at least one hunk's ``@@`` header was rewritten.
    relocated_hunks_count:
        Number of hunks whose line numbers were relocated.
    """

    healed_diff: str
    was_healed: bool
    relocated_hunks_count: int


_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
)


def _extract_preimage_lines(lines: list[str]) -> list[str]:
    """Extract pre-image (context + removed) lines from a hunk body.

    Returns the exact sequence of source-file lines (without the leading
    ``' '`` or ``'-'`` characters) that the hunk's ``@@`` header refers to.
    Addition lines (``'+'``) and no-newline markers (``'\\'``) are excluded.
    """
    result: list[str] = []
    for line in lines:
        if not line:
            result.append("")
            continue
        origin = line[0]
        if origin in (" ", "-"):
            result.append(line[1:])
    return result


def _count_matches(target_lines: list[str], needle: list[str]) -> list[int]:
    """Find all 0-indexed start positions where *needle* occurs in *target_lines*.

    Returns a list of start indices (empty if no matches, one element for a
    unique match, two-or-more for ambiguous duplicate blocks).
    """
    if not needle:
        return []

    matches: list[int] = []
    n = len(target_lines)
    m = len(needle)
    if m > n:
        return []

    for i in range(n - m + 1):
        # Fast reject: check first element before slicing to save time
        if target_lines[i] == needle[0] and target_lines[i : i + m] == needle:
            matches.append(i)

    return matches


def heal_diff_line_numbers(raw_diff: str, workspace_root: Path) -> HealResult:
    """Deterministically heal ``@@`` line-number drift in a unified diff.

    Parameters
    ----------
    raw_diff:
        Raw unified diff text (may contain CRLF).
    workspace_root:
        Root directory of the workspace containing the target files.

    Returns
    -------
    HealResult
        Healing result with the (possibly corrected) diff and metadata.

    Safety invariants
    -----------------
    - A hunk whose pre-image already matches at the declared ``old_start``
      is left untouched (no false relocations).
    - A hunk with **zero** matches is left untouched (corrupt context —
      let ``git apply`` report the error).
    - A hunk with **two or more** matches is left untouched (ambiguous —
      do not guess, let ``git apply`` fail deterministically).
    - Only hunks with exactly **one** match at a **different** line number
      are rewritten.
    """
    # Normalize line endings
    normalized = raw_diff.replace("\r\n", "\n").replace("\r", "\n")

    # Parse the diff to get file paths and hunks
    parsed = UnifiedDiffParser.parse(normalized)

    # We need to rebuild the diff line-by-line with corrected headers
    diff_lines = normalized.splitlines(keepends=False)

    relocated_count = 0

    # Iterate over each file patch
    for file_patch in parsed.files:
        # Determine the target file path
        target_path_str = file_patch.target_path
        if not target_path_str or target_path_str == "/dev/null":
            continue

        # Resolve the target file
        target_file = (workspace_root / target_path_str).resolve()

        # Only process existing regular files
        if not target_file.is_file():
            continue

        # Ensure the target file is within the workspace (safety)
        try:
            target_file.relative_to(workspace_root.resolve())
        except ValueError:
            continue

        # Read the target file lines
        target_content = target_file.read_text(encoding="utf-8")
        target_lines = target_content.splitlines(keepends=False)

        # Process each hunk — track cumulative delta across hunks for this file
        cumulative_delta = 0

        for hunk in file_patch.hunks:
            # Reconstruct the hunk body lines with origin chars
            hunk_body_lines: list[str] = [
                f"{hl.origin}{hl.content}" for hl in hunk.lines
            ]

            # Extract pre-image lines from this hunk
            preimage = _extract_preimage_lines(hunk_body_lines)

            # Find all matches in the target file
            matches = _count_matches(target_lines, preimage)

            # Safety invariant: only heal if exactly ONE match at a DIFFERENT line
            if len(matches) != 1:
                continue

            true_old_start = matches[0] + 1  # 1-indexed line in target file
            declared_old_start = hunk.old_start  # 1-indexed from @@ header

            # If the match is at the already-declared position, no healing needed
            if true_old_start == declared_old_start:
                continue

            # This hunk needs healing: rewrite its @@ header
            relocated_count += 1

            # Compute true new_start using cumulative_delta across hunks
            true_new_start = true_old_start + cumulative_delta

            # Compute true counts from the actual hunk content
            true_old_count = len(preimage)
            # Postimage lines: context (' ') + additions ('+')
            postimage = [
                line[1:] for line in hunk_body_lines
                if line and line[0] in (" ", "+")
            ]
            true_new_count = len(postimage)

            # Build the new header using true coordinates
            heading = hunk.heading if hunk.heading else ""
            new_header = (
                f"@@ -{true_old_start},{true_old_count}"
                f" +{true_new_start},{true_new_count} @@{heading}"
            )

            # Find and replace the hunk header in diff_lines
            # We need to find the exact line in diff_lines that matches this hunk header
            # The header line format is: @@ -old_start,old_count +new_start,new_count @@ heading
            found_and_replaced = False
            for idx, dl in enumerate(diff_lines):
                if dl.startswith("@@ "):
                    match = _HUNK_HEADER_RE.match(dl)
                    if match:
                        dl_old_start = int(match.group(1))
                        dl_new_start = int(match.group(3))

                        # Check if this is the hunk we're looking for
                        if (
                            dl_old_start == declared_old_start
                            and dl_new_start == hunk.new_start
                        ):
                            diff_lines[idx] = new_header
                            found_and_replaced = True
                            break

            if not found_and_replaced:
                # Should not happen if parsing is correct, but skip safely
                continue

            # Update cumulative delta for subsequent hunks
            cumulative_delta += true_new_count - true_old_count

    # Reconstruct the healed diff
    healed_diff = "\n".join(diff_lines)
    if healed_diff and not healed_diff.endswith("\n"):
        healed_diff += "\n"

    was_healed = relocated_count > 0

    return HealResult(
        healed_diff=healed_diff,
        was_healed=was_healed,
        relocated_hunks_count=relocated_count,
    )

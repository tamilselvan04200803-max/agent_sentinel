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
    """Correct coordinates only for unique exact preimages; preserve hunk bodies.

    Header positions are consumed in parsed file/hunk order, so identical
    coordinates in different files cannot select the wrong header. Empty
    preimages never establish a unique relocation.
    """
    normalized = raw_diff.replace("\r\n", "\n").replace("\r", "\n")
    parsed = UnifiedDiffParser.parse(normalized)
    diff_lines = normalized.splitlines()
    header_positions = iter(i for i, line in enumerate(diff_lines) if line.startswith("@@ "))
    relocated_count = 0
    root = workspace_root.resolve()
    for file_patch in parsed.files:
        positions = [next(header_positions) for _ in file_patch.hunks]
        target_file = (root / file_patch.target_path).resolve()
        if not target_file.is_relative_to(root) or not target_file.is_file():
            continue
        target_lines = target_file.read_text(encoding="utf-8").splitlines()
        cumulative_delta = 0
        for hunk, header_index in zip(file_patch.hunks, positions, strict=True):
            preimage = [line.content for line in hunk.lines if line.origin in (" ", "-")]
            new_count = sum(line.origin in (" ", "+") for line in hunk.lines)
            matches = _count_matches(target_lines, preimage)
            if len(matches) == 1:
                old_start = matches[0] + 1
                # A zero-length postimage uses the line preceding the deletion.
                new_start = old_start + cumulative_delta - (new_count == 0)
                if (old_start, new_start) != (hunk.old_start, hunk.new_start):
                    suffix = diff_lines[header_index].split("@@", 2)[2]
                    diff_lines[header_index] = (
                        f"@@ -{old_start},{len(preimage)} +{new_start},{new_count} @@{suffix}"
                    )
                    relocated_count += 1
            # Every preceding hunk contributes, including unchanged headers.
            cumulative_delta += new_count - len(preimage)
    healed = "\n".join(diff_lines)
    if healed and not healed.endswith("\n"):
        healed += "\n"
    UnifiedDiffParser.parse(healed)
    return HealResult(healed, relocated_count > 0, relocated_count)

"""Deterministic prompt builder for the AgentSentinel repair loop.

Constructs a structured repair prompt from:
- A ``CaseSpec`` (bug description, failing test IDs, allowlist).
- A baseline ``ExecutionResult`` (stdout/stderr failure traceback).
- The file contents of ``CaseSpec.allowed_edit_paths`` from the workspace.

Security boundaries enforced here:
- ONLY files in ``CaseSpec.allowed_edit_paths`` are ever included in the prompt.
- ``.git/`` history, fix diffs, reference solutions, and files outside the
  allowlist are NEVER included.
- All file content is rendered with explicit 1-indexed line numbers so the LLM
  does not hallucinate hunk line counts when generating a unified diff.
- Prompt injection guards strip triple-backtick sequences and Unicode BiDi/control
  poisoning characters from user content.

Output format:
  Structured text prompt suitable for any instruction-tuned LLM.
  The model is asked to respond with a JSON object matching:
  ``{"root_cause_hypothesis": str, "unified_diff": str}``
"""

from __future__ import annotations

import textwrap
import unicodedata
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from agentsentinel.localization.ast_slicer import pack_file_with_skeleton, split_python_source_lines
from agentsentinel.localization.context_packer import pack_file_with_token_budget

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from agentsentinel.domain.models import CaseSpec, ExecutionResult
    from agentsentinel.localization.ast_slicer import LocalizationSlice

# Sentinel used to mark truncated file content in prompts.
_TRUNCATION_MARKER = "... [TRUNCATED — file exceeds prompt size limit]"

# Maximum characters per file included in the prompt context.
# Prevents a single large file from exhausting the model's context window.
_MAX_FILE_CHARS = 20_000


def _add_line_numbers(source: str) -> str:
    """Prefix every line with a 1-indexed line number.

    Parameters
    ----------
    source:
        Raw source text.

    Returns
    -------
    str
        Source text with ``   1: `` prefixes.
    """
    lines = split_python_source_lines(source)
    width = len(str(len(lines)))
    return "\n".join(f"{i + 1:{width}d}: {line}" for i, line in enumerate(lines))


def _sanitize_content(content: str) -> str:
    """Remove prompt-injection vectors and poisoning from content.

    Strips triple-backtick sequences (which could break the prompt's markdown
    fencing) and replaces them with a safe marker, and strips Unicode BiDi
    and zero-width control characters.

    Parameters
    ----------
    content:
        Raw file content.

    Returns
    -------
    str
        Sanitized content safe for embedding in a prompt.
    """
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    sanitized = "".join(
        char for char in normalized
        if char in "\n\t" or unicodedata.category(char) not in {"Cc", "Cf"}
    )
    # Neutralize fences last: stripping controls can join separated backticks.
    return sanitized.replace("```", "'''")


def sanitize_diagnostic(content: str, max_chars: int = 2000) -> str:
    """Bound a diagnostic field and strip fencing, Unicode and control poisoning."""
    return _sanitize_content(content[:max_chars])


def _read_file_safe(path: Path, max_chars: int | None = _MAX_FILE_CHARS) -> tuple[str, bool]:
    """Read a file safely, truncating at ``max_chars`` characters.

    Parameters
    ----------
    path:
        File path to read.
    max_chars:
        Maximum characters to return, or None to read complete AST input.

    Returns
    -------
    tuple[str, bool]
        (content, truncated) — content is the text, truncated is True if cut.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"[ERROR: file not found or unreadable: {path}]", False

    if max_chars is not None and len(raw) > max_chars:
        return raw[:max_chars], True
    return raw, False


class PromptBuilder:
    """Constructs a deterministic repair prompt from case context.

    Parameters
    ----------
    workspace_root:
        Absolute path to the baseline (unpatched) workspace directory.
        Used to resolve ``CaseSpec.allowed_edit_paths`` for file content.
    max_file_chars:
        Maximum characters per source file included in the prompt.
    max_file_tokens, count_tokens:
        Optional hard token bound for each Python source block, measured after
        sanitization using the supplied deterministic counter. Both are required
        together. Prompt wrappers and other sections are outside this bound;
        localization hint bodies are not duplicated in this mode.
    """

    def __init__(
        self,
        workspace_root: Path,
        max_file_chars: int = _MAX_FILE_CHARS,
        *,
        max_file_tokens: int | None = None,
        count_tokens: Callable[[str], int] | None = None,
    ) -> None:
        if (max_file_tokens is None) != (count_tokens is None):
            raise ValueError("max_file_tokens and count_tokens must be supplied together")
        if max_file_tokens is not None and max_file_tokens < 0:
            raise ValueError("max_file_tokens must be nonnegative")
        self.workspace_root = workspace_root
        self.max_file_chars = max_file_chars
        self.max_file_tokens = max_file_tokens
        self.count_tokens = count_tokens

    def _count_sanitized_tokens(self, content: str) -> int:
        assert self.count_tokens is not None
        return self.count_tokens(_sanitize_content(content))

    def build_repair_prompt(
        self,
        spec: CaseSpec,
        baseline_result: ExecutionResult,
        localization_slices: Sequence[LocalizationSlice] | None = None,
    ) -> str:
        """Build a structured repair prompt for the LLM.

        Parameters
        ----------
        spec:
            The bug case descriptor (allowlist, failing tests, command, etc.).
        baseline_result:
            The execution result of the unpatched baseline (must be TESTS_FAILED).
        localization_slices:
            Optional AST localization slices to provide targeted fault hints.

        Returns
        -------
        str
            The complete prompt text ready to be sent to the LLM.
        """
        sections: list[str] = []

        # ── Header ──────────────────────────────────────────────────────────
        sections.append(textwrap.dedent("""\
            You are AgentSentinel, an automated software repair engine.
            Your task is to produce a minimal, correct unified diff that fixes a failing test suite.

            CRITICAL RULES:
            1. You may ONLY modify files listed in the ALLOWED EDIT PATHS section.
            2. You must NEVER modify test files, configuration files, or build scripts.
            3. Your unified diff must be syntactically valid and apply cleanly with `git apply`.
            4. Do NOT include any explanation inside the diff — only valid unified diff syntax.
            5. Provide your entire response as a single JSON object.
        """))

        # ── Case identification ─────────────────────────────────────────────
        sections.append(f"## CASE ID\n{spec.case_id}\n")

        # ── Failing tests ───────────────────────────────────────────────────
        failing_tests = "\n".join(f"  - {t}" for t in spec.failing_test_ids)
        sections.append(
            f"## FAILING TESTS\n"
            f"The following test IDs must transition from FAIL → PASS:\n{failing_tests}\n"
        )

        # ── Test command ────────────────────────────────────────────────────
        sections.append(f"## TEST COMMAND\n```\n{spec.test_command}\n```\n")

        # ── Allowed edit paths (explicit allowlist) ─────────────────────────
        allowed_paths = "\n".join(f"  - {p}" for p in spec.allowed_edit_paths)
        sections.append(
            f"## ALLOWED EDIT PATHS\n"
            f"You MUST ONLY produce a diff that modifies files in this list:\n"
            f"{allowed_paths}\n"
        )

        # ── Failure evidence (stdout + stderr) ─────────────────────────────
        stdout_safe = _sanitize_content(baseline_result.stdout[:8000])
        stderr_safe = _sanitize_content(baseline_result.stderr[:8000])

        failure_section = "## FAILURE EVIDENCE\n"
        if baseline_result.stdout.strip():
            failure_section += (
                f"### stdout (pytest output)\n"
                f"```\n{stdout_safe}\n```\n"
            )
        if baseline_result.stderr.strip():
            failure_section += (
                f"### stderr\n"
                f"```\n{stderr_safe}\n```\n"
            )
        sections.append(failure_section)

        # ── Source file contents with line numbers ──────────────────────────
        resolved_root = self.workspace_root.resolve()
        source_sections: list[str] = []
        for rel_path in spec.allowed_edit_paths:
            # Security: hard reject absolute paths and obvious traversal sequences
            # before doing any filesystem join. Defence-in-depth: even if the
            # policy layer misses a ``../`` (e.g. via case-insensitive Windows
            # paths, percent-encoded sequences, or symlinks), we must not read
            # host files into the prompt.
            if rel_path.startswith(("/", "\\")) or ".." in rel_path.replace("\\", "/").split("/"):
                continue
            # Security: never traverse outside workspace root (symlink-safe
            # check via resolve + is_relative_to).
            file_path = (self.workspace_root / rel_path).resolve()
            if not file_path.is_relative_to(resolved_root):
                # Silently skip — path escapes root via symlink or traversal
                continue
            # Belt-and-braces: never read from inside .git/ even if allowlisted
            rel_parts = rel_path.replace("\\", "/").strip("/").split("/")
            if rel_parts and rel_parts[0] == ".git":
                continue

            use_token_budget = self.max_file_tokens is not None and file_path.suffix == ".py"
            use_skeleton = (
                localization_slices is not None or use_token_budget
            ) and file_path.suffix == ".py"
            content, truncated = _read_file_safe(
                file_path, None if use_skeleton else self.max_file_chars,
            )
            numbered: str | None = None
            if use_skeleton:
                normalized_path = PurePosixPath(rel_path.replace("\\", "/"))
                file_slices = [
                    sl for sl in (localization_slices or ())
                    if PurePosixPath(sl.file_path.replace("\\", "/")) == normalized_path
                ]
            if use_token_budget:
                assert self.max_file_tokens is not None
                token_packed = pack_file_with_token_budget(
                    content, file_slices, self.max_file_tokens,
                    count_tokens=self._count_sanitized_tokens,
                )
                numbered = _sanitize_content(token_packed.formatted_content)
            elif use_skeleton and len(content) > self.max_file_chars:
                try:
                    packed = pack_file_with_skeleton(content, file_slices, self.max_file_chars)
                except ValueError:
                    # Null-byte content cannot be parsed; retain the legacy fallback.
                    packed = None
                if packed is not None and len(packed.formatted_content) <= self.max_file_chars:
                    numbered = _sanitize_content(packed.formatted_content)
                else:
                    content = content[:self.max_file_chars]
                    truncated = True
            if numbered is None:
                numbered = _add_line_numbers(_sanitize_content(content))

            file_block = f"### File: `{rel_path}`\n```\n{numbered}\n```\n"
            if truncated:
                file_block += f"{_TRUNCATION_MARKER}\n"
            source_sections.append(file_block)

        if source_sections:
            sections.append("## SOURCE FILES\n" + "\n".join(source_sections))

        # ── Fault localization hints ──────────────────────────────────────
        if localization_slices:
            slice_blocks: list[str] = []
            for sl in localization_slices:
                header = (
                    f"### File: `{sl.file_path}` — symbol `{sl.symbol_name}` "
                    f"(lines {sl.start_line}-{sl.end_line}, hop {sl.hop_distance})"
                )
                if self.max_file_tokens is None:
                    safe_numbered = _sanitize_content(sl.numbered_source)
                    slice_blocks.append(f"{header}\n```\n{safe_numbered}\n```")
                else:
                    slice_blocks.append(header)
            sections.append(
                "## Fault Localization Hints (AST Slice)\n"
                + "\n".join(slice_blocks)
                + "\n"
            )

        # ── Output format instruction ───────────────────────────────────────
        sections.append(textwrap.dedent("""\
            ## REQUIRED OUTPUT FORMAT
            Respond with ONLY a JSON object (no markdown fencing, no preamble):
            {
              "root_cause_hypothesis": "<one-sentence explanation of the bug>",
              "unified_diff": "<unified diff in git diff format, or empty string>"
            }

            The unified diff MUST:
            - Start with `--- a/<path>` and `+++ b/<path>` headers.
            - Use correct @@ hunk headers with accurate line counts.
            - Only modify files listed in ALLOWED EDIT PATHS.
            - Apply cleanly to the source files shown above.
        """))

        return "\n".join(sections)

    # Alias for backwards compatibility — mirrors build_repair_prompt
    def build_patch_prompt(
        self,
        spec: CaseSpec,
        baseline_result: ExecutionResult,
        localization_slices: Sequence[LocalizationSlice] | None = None,
    ) -> str:
        """Alias for :meth:`build_repair_prompt`."""
        return self.build_repair_prompt(spec, baseline_result, localization_slices)

    def estimate_prompt_tokens(self, prompt: str, chars_per_token: float = 4.0) -> int:
        """Estimate prompt token count from character length.

        This is a rough heuristic (4 chars ≈ 1 token for English + code).
        Actual counts vary by model tokenizer.

        Parameters
        ----------
        prompt:
            The assembled prompt text.
        chars_per_token:
            Approximate characters per token.

        Returns
        -------
        int
            Estimated token count (rounded up).
        """
        return max(1, int(len(prompt) / chars_per_token + 0.999))

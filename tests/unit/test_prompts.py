"""Unit tests for M3 LLM prompt builder (prompts.py).

Phase C adversarial coverage:
- Files outside allowed_edit_paths are excluded from prompt context
- .git directory content is never included
- Triple-backtick injection is sanitized
- Long files are truncated with marker
- Line numbers are 1-indexed and monotonically increasing
- Missing file produces error marker, not an exception
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.llm.prompts import PromptBuilder, _add_line_numbers, _sanitize_content

if TYPE_CHECKING:
    from pathlib import Path

_VALID_SHA = "a" * 40


def _make_case_spec(
    allowed_paths: tuple[str, ...] = ("normalizer.py",),
) -> CaseSpec:
    return CaseSpec(
        case_id="test-m3-prompt",
        repo_url="https://github.com/test/repo",
        base_commit=_VALID_SHA,
        test_command="python -m pytest -q test_normalizer.py",
        allowed_edit_paths=allowed_paths,
        failing_test_ids=("test_normalizer.py::test_basic_lowercase",),
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def _make_baseline_result(
    stdout: str = "FAILED test_normalizer.py::test_basic_lowercase",
    stderr: str = "",
) -> ExecutionResult:
    return ExecutionResult(
        case_id="test-m3-prompt",
        patch_diff_hash="baseline",
        exit_code=ExitCode.TESTS_FAILED,
        stdout=stdout,
        stderr=stderr,
        wall_seconds=1.0,
    )


class TestAddLineNumbers:
    @pytest.mark.unit
    def test_single_line(self) -> None:
        result = _add_line_numbers("hello world")
        assert result == "1: hello world"

    @pytest.mark.unit
    def test_multiline_is_1_indexed(self) -> None:
        result = _add_line_numbers("line1\nline2\nline3")
        lines = result.splitlines()
        assert lines[0].startswith("1:")
        assert lines[1].startswith("2:")
        assert lines[2].startswith("3:")

    @pytest.mark.unit
    def test_line_count_format_matches_total(self) -> None:
        content = "\n".join(f"line {i}" for i in range(100))
        result = _add_line_numbers(content)
        lines = result.splitlines()
        assert lines[-1].startswith("100:")


class TestSanitizeContent:
    @pytest.mark.unit
    def test_triple_backtick_replaced(self) -> None:
        content = "```python\nx = 1\n```"
        result = _sanitize_content(content)
        assert "```" not in result
        assert "'''" in result

    @pytest.mark.unit
    def test_regular_content_unchanged(self) -> None:
        content = "def hello():\n    return 'world'\n"
        result = _sanitize_content(content)
        assert result == content


class TestPromptBuilder:
    @pytest.mark.unit
    def test_prompt_contains_case_id(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("def normalize(x): return x", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "test-m3-prompt" in prompt

    @pytest.mark.unit
    def test_prompt_contains_failing_test_ids(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "test_normalizer.py::test_basic_lowercase" in prompt

    @pytest.mark.unit
    def test_prompt_contains_test_command(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "python -m pytest -q test_normalizer.py" in prompt

    @pytest.mark.unit
    def test_prompt_contains_allowed_edit_paths(self, tmp_path: Path) -> None:
        spec = _make_case_spec(allowed_paths=("normalizer.py", "utils.py"))
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "utils.py").write_text("y = 2", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "normalizer.py" in prompt
        assert "utils.py" in prompt

    @pytest.mark.unit
    def test_prompt_contains_source_file_content_with_line_numbers(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text(
            "def normalize(x):\n    return x.lower()\n", encoding="utf-8"
        )

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        # Line numbers must appear
        assert "1:" in prompt
        assert "2:" in prompt
        assert "normalize" in prompt

    @pytest.mark.unit
    def test_prompt_contains_failure_stdout(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result(stdout="AssertionError: assert 'FOO' == 'foo'")
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "AssertionError" in prompt

    @pytest.mark.unit
    def test_prompt_contains_json_output_format_instruction(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "root_cause_hypothesis" in prompt
        assert "unified_diff" in prompt

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_out_of_allowlist_files_not_in_prompt(self, tmp_path: Path) -> None:
        """SECURITY: Files outside allowed_edit_paths must NEVER appear in prompt context."""
        spec = _make_case_spec(allowed_paths=("normalizer.py",))
        baseline = _make_baseline_result()

        # Create a secret file that should NEVER be in the prompt
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "secrets.env").write_text("API_KEY=super_secret_12345", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "super_secret_12345" not in prompt, (
            "SECURITY VIOLATION: secret file content leaked into prompt!"
        )
        assert "secrets.env" not in prompt

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_git_directory_never_in_prompt(self, tmp_path: Path) -> None:
        """SECURITY: .git directory content must NEVER appear in prompt."""
        spec = _make_case_spec(allowed_paths=("normalizer.py",))
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")

        # Simulate a .git dir with commit history
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "COMMIT_EDITMSG").write_text("fix: reference solution", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "reference solution" not in prompt, (
            "SECURITY VIOLATION: .git history leaked into prompt!"
        )

    @pytest.mark.unit
    @pytest.mark.adversarial
    def test_triple_backtick_injection_sanitized(self, tmp_path: Path) -> None:
        """Prompt injection via triple backticks in source file is neutralized."""
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        # File contains triple backtick that could break prompt markdown fencing
        malicious_content = "x = '''```injected```'''\n"
        (tmp_path / "normalizer.py").write_text(malicious_content, encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        # Triple backticks should be sanitized
        assert "```injected```" not in prompt

    @pytest.mark.unit
    def test_missing_file_produces_error_marker(self, tmp_path: Path) -> None:
        """If a file in allowed_edit_paths doesn't exist, prompt includes error marker."""
        spec = _make_case_spec(allowed_paths=("normalizer.py", "missing_file.py"))
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")
        # missing_file.py intentionally NOT created

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "ERROR" in prompt or "not found" in prompt.lower() or "unreadable" in prompt.lower()

    @pytest.mark.unit
    def test_large_file_is_truncated_with_marker(self, tmp_path: Path) -> None:
        """Files exceeding max_file_chars are truncated with a visible marker."""
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        large_content = "x = 'a' * 100\n" * 2000  # ~30KB
        (tmp_path / "normalizer.py").write_text(large_content, encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path, max_file_chars=5000)
        prompt = builder.build_repair_prompt(spec, baseline)
        assert "TRUNCATED" in prompt

    @pytest.mark.unit
    def test_estimate_prompt_tokens(self, tmp_path: Path) -> None:
        spec = _make_case_spec()
        baseline = _make_baseline_result()
        (tmp_path / "normalizer.py").write_text("x = 1", encoding="utf-8")

        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        estimate = builder.estimate_prompt_tokens(prompt)
        assert estimate > 0
        assert estimate == max(1, int(len(prompt) / 4.0 + 0.999))

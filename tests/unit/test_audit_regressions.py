"""Regression tests for the M0–M3 Deep Architectural Audit fixes.

Each test corresponds to a specific bug documented in the 8-point audit
checklist and must FAIL on the pre-fix codebase and PASS after remediation.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentsentinel.domain.exceptions import HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult
from agentsentinel.llm.client import GeminiClient, OpenAICompatibleClient, _parse_llm_response
from agentsentinel.llm.exceptions import LLMGenerationError
from agentsentinel.llm.pricing import ModelUsage, PricingRegistry
from agentsentinel.policy.applier import _git_apply, _write_patch_file
from agentsentinel.policy.diff_parser import UnifiedDiffParser
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.sandbox.workspace import WorkspaceManager, _windows_rmtree_error_handler

_VALID_SHA = "a" * 40
_VALID_DT = datetime(2026, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Audit item #1 — ExecutionResult.passed must require expected tests ran
# ---------------------------------------------------------------------------


class TestAudit1ExpectedTestsRan:
    @pytest.mark.unit
    def test_empty_test_run_exit_zero_does_NOT_pass_with_expected_ids(self) -> None:
        """An empty test run that exits 0 but does NOT report any PASSED lines
        for the expected test IDs must be classified as NOT passed.

        This blocks a reward-hacking vector where a malicious conftest.py
        exits 0 while running zero tests.
        """
        result = ExecutionResult(
            case_id="c1",
            patch_diff_hash="hack",
            exit_code=ExitCode.OK,
            stdout="collected 0 items\n",  # zero tests run, exit 0 (possible with --co)
            stderr="",
            wall_seconds=0.1,
            expected_test_ids=("tests/test_x.py::test_y",),
        )
        assert result.passed is False, "empty test run must NOT count as passed"

    @pytest.mark.unit
    def test_all_expected_tests_passed_reports_passed(self) -> None:
        stdout = (
            "collected 1 item\n"
            "tests/test_x.py::test_y PASSED                          [100%]\n"
            "======================= 1 passed in 0.05s =======================\n"
        )
        result = ExecutionResult(
            case_id="c1",
            patch_diff_hash="fix",
            exit_code=ExitCode.OK,
            stdout=stdout,
            stderr="",
            wall_seconds=1.0,
            expected_test_ids=("tests/test_x.py::test_y",),
        )
        assert result.passed is True

    @pytest.mark.unit
    def test_metadata_order_independent_equality(self) -> None:
        """CaseSpec instances with same metadata in different orders must be
        equal and produce identical hashes (metadata canonicalization check)."""
        s1 = CaseSpec(
            case_id="c",
            repo_url="https://example.com/r",
            base_commit=_VALID_SHA,
            test_command="pytest",
            allowed_edit_paths=("a.py",),
            failing_test_ids=("t.py::t",),
            created_at=_VALID_DT,
            metadata=(("z", "1"), ("a", "2")),
        )
        s2 = CaseSpec(
            case_id="c",
            repo_url="https://example.com/r",
            base_commit=_VALID_SHA,
            test_command="pytest",
            allowed_edit_paths=("a.py",),
            failing_test_ids=("t.py::t",),
            created_at=_VALID_DT,
            metadata=(("a", "2"), ("z", "1")),
        )
        assert s1 == s2
        assert hash(s1) == hash(s2)

    @pytest.mark.unit
    def test_metadata_duplicate_keys_rejected(self) -> None:
        with pytest.raises(ValueError, match="Duplicate metadata key"):
            CaseSpec(
                case_id="c",
                repo_url="https://example.com/r",
                base_commit=_VALID_SHA,
                test_command="pytest",
                allowed_edit_paths=("a.py",),
                failing_test_ids=("t.py::t",),
                created_at=_VALID_DT,
                metadata=(("k", "v1"), ("k", "v2")),
            )


# ---------------------------------------------------------------------------
# Audit item #2 — workspace scrubs .git & Windows rmtree handler exists
# ---------------------------------------------------------------------------


class TestAudit2Workspace:
    @pytest.mark.unit
    def test_scrub_git_history_removes_dot_git_completely(self, tmp_path: Path) -> None:
        """scrub_git_history must delete .git/ entirely so `git log -p --all`
        cannot reveal history — not just prune reflogs/tags/remotes."""
        repo = tmp_path / "repo"
        repo.mkdir()
        git_dir = repo / ".git"
        git_dir.mkdir()
        # Simulate a pack file (which is what git prune alone would miss)
        objects = git_dir / "objects" / "pack"
        objects.mkdir(parents=True)
        (objects / "pack-abc.pack").write_bytes(b"fake-pack-bytes")
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (git_dir / "config").write_text("[core]\n\tautocrlf = true\n", encoding="utf-8")

        mgr = WorkspaceManager()
        mgr.scrub_git_history(repo)
        assert not git_dir.exists(), ".git/ must be fully removed"

    @pytest.mark.unit
    def test_windows_error_handler_clears_readonly_bit(self, tmp_path: Path) -> None:
        """The onerror handler must chmod a read-only file and retry delete."""
        target = tmp_path / "readonly.txt"
        target.write_text("x", encoding="utf-8")
        target.chmod(stat.S_IREAD)  # read-only
        try:
            _windows_rmtree_error_handler(os.unlink, str(target), None)
            assert not target.exists(), "handler must have removed the read-only file"
        finally:
            with contextlib.suppress(OSError):
                target.chmod(stat.S_IWRITE | stat.S_IREAD)
                target.unlink(missing_ok=True)

    @pytest.mark.unit
    def test_create_workspace_cleans_up_on_exit(self, tmp_path: Path) -> None:
        mgr = WorkspaceManager(base_dir=tmp_path)
        ws_name = None
        with mgr.create_workspace() as ws_path:
            ws_name = ws_path
            p = Path(ws_path)
            assert p.exists()
        assert not Path(ws_name).exists()


# ---------------------------------------------------------------------------
# Audit item #3 — bounded streaming output truncation (no OOM)
# ---------------------------------------------------------------------------


class TestAudit3ContainerStreaming:
    @pytest.mark.unit
    def test_bounded_stream_read_discards_overflow(self) -> None:
        """_bounded_stream_read must cap memory even when streams emit 100x the limit."""
        runner = HardenedContainerRunner(ContainerConfig(max_output_bytes=200))

        # Mock proc with 100KB stdout via BytesIO
        big_out = b"A" * (100 * 1024)
        mock_proc = MagicMock()
        mock_proc.stdout = io.BytesIO(big_out)
        mock_proc.stderr = io.BytesIO(b"")
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0
        mock_proc.kill.return_value = None
        mock_proc.wait.return_value = 0

        out, err, out_trunc, err_trunc = runner._bounded_stream_read(
            mock_proc, max_bytes=200, timeout=2.0
        )
        assert len(out) == 200
        assert out_trunc is True
        assert len(err) == 0
        assert err_trunc is False

    @pytest.mark.unit
    def test_workspace_mounted_read_only_tmpfs_noexec(self, tmp_path: Path) -> None:
        """Verify /workspace is :ro and /tmp is tmpfs rw,noexec,nosuid."""
        runner = HardenedContainerRunner()
        args = runner.build_docker_run_args("c", tmp_path, "pytest")
        joined = " ".join(args)
        assert ":/workspace:ro" in joined, "/workspace must be mounted read-only"
        assert "/tmp:rw,noexec,nosuid" in joined, "/tmp must be tmpfs rw,noexec,nosuid"

    @pytest.mark.unit
    def test_timeout_fires_without_relying_on_communicate(self, tmp_path: Path) -> None:
        """Ensure timeout fires even when pipes are never closed (i.e. we don't
        deadlock on communicate())."""

        runner = HardenedContainerRunner(ContainerConfig(timeout_seconds=0.2))

        import threading

        class _HangPipe:
            def __init__(self) -> None:
                self._killed_event = threading.Event()

            def read(self, size: int) -> bytes:
                self._killed_event.wait()
                return b""

            @property
            def _killed(self) -> bool:
                return self._killed_event.is_set()

            def fileno(self) -> int:
                return -1

            def kill(self) -> None:
                self._killed_event.set()

            def close(self) -> None:
                self._killed_event.set()

        out_pipe = _HangPipe()
        err_pipe = _HangPipe()
        mock_proc = MagicMock()
        mock_proc.stdout = out_pipe
        mock_proc.stderr = err_pipe
        mock_proc.pid = 1
        mock_proc.poll.side_effect = lambda: (-9 if out_pipe._killed else None)
        mock_proc.kill.side_effect = lambda: (out_pipe.kill(), err_pipe.kill())
        mock_proc.wait.return_value = -9

        with patch("subprocess.Popen", return_value=mock_proc), patch(
            "subprocess.run"
        ), pytest.raises(HarnessTimeoutError):
            runner.run_in_container(
                case_id="t",
                patch_diff_hash="b",
                workspace_host_path=tmp_path,
                command="hang",
            )

        out_pipe.close()
        err_pipe.close()


# ---------------------------------------------------------------------------
# Audit item #4 — CRLF normalization & /dev/null and rename target_paths
# ---------------------------------------------------------------------------


class TestAudit4DiffParser:
    @pytest.mark.unit
    def test_crlf_normalized_before_parsing(self) -> None:
        """Diff with CRLF line endings must parse cleanly."""
        crlf_diff = (
            "diff --git a/f.py b/f.py\r\n"
            "--- a/f.py\r\n"
            "+++ b/f.py\r\n"
            "@@ -1 +1 @@\r\n"
            "-old\r\n"
            "+new\r\n"
        )
        parsed = UnifiedDiffParser.parse(crlf_diff)
        assert len(parsed.files) == 1
        assert parsed.files[0].target_path == "f.py"

    @pytest.mark.unit
    def test_deleted_file_lists_source_path_not_dev_null(self) -> None:
        """For a deleted file (--- a/tests/test_x.py +++ /dev/null),
        target_paths must include the source path (tests/test_x.py) so the
        validator can still block test deletion."""
        diff = (
            "diff --git a/tests/test_x.py b/tests/test_x.py\n"
            "deleted file mode 100644\n"
            "--- a/tests/test_x.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-def test_x(): pass\n"
        )
        parsed = UnifiedDiffParser.parse(diff)
        assert "tests/test_x.py" in parsed.target_paths
        assert "/dev/null" not in parsed.target_paths

    @pytest.mark.unit
    def test_rename_includes_both_source_and_dest(self) -> None:
        """For a rename, target_paths must contain BOTH old and new paths
        (excluding /dev/null) so renaming a test file to src/x.py is caught."""
        diff = (
            "diff --git a/tests/test_x.py b/src/x.py\n"
            "similarity index 100%\n"
            "rename from tests/test_x.py\n"
            "rename to src/x.py\n"
        )
        parsed = UnifiedDiffParser.parse(diff)
        paths = parsed.target_paths
        assert "tests/test_x.py" in paths, "rename source path must be included"
        assert "src/x.py" in paths, "rename destination path must be included"


# ---------------------------------------------------------------------------
# Audit item #5 — applier.py newline="\n" and --ignore-space-change
# ---------------------------------------------------------------------------


class TestAudit5Applier:
    @pytest.mark.unit
    def test_git_apply_check_uses_newline_ln_and_ignore_space(
        self, tmp_path: Path
    ) -> None:
        """Verify that the patch file is written with newline='\\n' (Windows-safe)
        and that --ignore-space-change / --whitespace=nowarn flags are passed to
        ``git apply``."""
        # _write_patch_file writes the patch with explicit newline="\n"
        diff = "--- a/f\n+++ b/f\n@@\n-x\n+y\n"
        patch_path = _write_patch_file(diff)
        try:
            # Read the file in binary mode to verify no CR characters were
            # written (i.e. Python did NOT translate \n to \r\n on our behalf).
            raw = Path(patch_path).read_bytes()
            assert b"\r\n" not in raw, "patch file must be LF-only, no CRLF"
            assert raw.decode("utf-8") == diff.replace("\r\n", "\n").replace("\r", "\n")
        finally:
            Path(patch_path).unlink(missing_ok=True)

        # Intercept subprocess.run to observe the args passed to git apply
        captured_args: list[str] | None = None

        def fake_run(args: list[str], **kwargs: object) -> MagicMock:
            nonlocal captured_args
            captured_args = args
            m = MagicMock()
            m.returncode = 0
            m.stderr = ""
            m.stdout = ""
            return m

        (tmp_path / "f").write_text("x\n", encoding="utf-8")
        pf = _write_patch_file(diff)
        try:
            with patch("agentsentinel.policy.applier.subprocess.run", side_effect=fake_run):
                _git_apply(pf, tmp_path, check_only=True)
        finally:
            Path(pf).unlink(missing_ok=True)

        assert captured_args is not None
        assert "--ignore-space-change" in captured_args
        assert "--whitespace=nowarn" in captured_args
        assert "--check" in captured_args


# ---------------------------------------------------------------------------
# Audit item #6 — LLM client: no hidden retries, usage attached to failures
# ---------------------------------------------------------------------------


class TestAudit6LLMClient:
    @pytest.mark.unit
    def test_default_transport_retries_is_zero(self) -> None:
        """max_transport_retries must default to 0 for deterministic semantics."""
        assert OpenAICompatibleClient().max_transport_retries == 0
        assert GeminiClient().max_transport_retries == 0

    @pytest.mark.unit
    def test_invalid_json_does_not_retry_and_carries_usage(self) -> None:
        """When the model returns HTTP 200 with invalid JSON inside choices[0].message.content,
        _parse_llm_response must raise LLMGenerationError immediately (no retry)
        and attach a ModelUsage."""
        # Simulate the post-extraction call: content is bad JSON but usage meta
        # was extracted from the top-level response.
        with pytest.raises(LLMGenerationError) as exc:
            _parse_llm_response(
                raw_response="this is not json at all",
                case_id="c",
                model_id="gpt-4o",
                prompt_tokens=50,
                completion_tokens=20,
            )
        err = exc.value
        assert err.usage is not None, "usage must be attached even on parse failure"
        assert err.usage.prompt_tokens == 50
        assert err.usage.completion_tokens == 20

    @pytest.mark.unit
    def test_missing_schema_fields_does_not_retry(self) -> None:
        """Missing root_cause_hypothesis must raise LLMGenerationError with
        .usage set, never loop/retry."""
        payload = json.dumps({"unified_diff": "--- a/f\n+++ b/f\n"})
        with pytest.raises(LLMGenerationError) as exc:
            _parse_llm_response(
                raw_response=payload,
                case_id="c",
                model_id="m",
                prompt_tokens=10,
                completion_tokens=5,
            )
        err = exc.value
        assert err.usage is not None
        assert "root_cause_hypothesis" in err.reason


# ---------------------------------------------------------------------------
# Audit item #7 — PromptBuilder path containment (../ and absolute)
# ---------------------------------------------------------------------------


class TestAudit7Prompts:
    @pytest.mark.unit
    def test_dotdot_traversal_rejected(self, tmp_path: Path) -> None:
        """A malicious CaseSpec with ../ in allowed_edit_paths must not be
        readable into the prompt."""
        from agentsentinel.llm.prompts import PromptBuilder

        # Create a secret file OUTSIDE the workspace
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("TOP_SECRET_DATA_XYZ", encoding="utf-8")
        try:
            spec = CaseSpec(
                case_id="c",
                repo_url="https://example.com/r",
                base_commit=_VALID_SHA,
                test_command="pytest",
                allowed_edit_paths=("../secret.txt",),
                failing_test_ids=("t.py::t",),
                created_at=_VALID_DT,
            )
            baseline = ExecutionResult(
                case_id="c",
                patch_diff_hash="b",
                exit_code=ExitCode.TESTS_FAILED,
                stdout="FAILED",
                stderr="",
                wall_seconds=0.1,
            )
            builder = PromptBuilder(workspace_root=tmp_path)
            prompt = builder.build_repair_prompt(spec, baseline)
            assert "TOP_SECRET_DATA_XYZ" not in prompt, (
                "SECURITY: ../ traversal leaked host file into prompt!"
            )
        finally:
            secret.unlink(missing_ok=True)

    @pytest.mark.unit
    def test_absolute_path_rejected(self, tmp_path: Path) -> None:
        from agentsentinel.llm.prompts import PromptBuilder

        spec = CaseSpec(
            case_id="c",
            repo_url="https://example.com/r",
            base_commit=_VALID_SHA,
            test_command="pytest",
            allowed_edit_paths=("/etc/passwd",),
            failing_test_ids=("t.py::t",),
            created_at=_VALID_DT,
        )
        baseline = ExecutionResult(
            case_id="c",
            patch_diff_hash="b",
            exit_code=ExitCode.TESTS_FAILED,
            stdout="FAILED",
            stderr="",
            wall_seconds=0.1,
        )
        builder = PromptBuilder(workspace_root=tmp_path)
        prompt = builder.build_repair_prompt(spec, baseline)
        # /etc/passwd should NOT be read (root:x:0 commonly appears there)
        assert "root:x:" not in prompt


# ---------------------------------------------------------------------------
# Audit item #8 — Pricing: unknown models return None, negatives raise
# ---------------------------------------------------------------------------


class TestAudit8Pricing:
    @pytest.mark.unit
    def test_unknown_model_returns_none_not_zero(self) -> None:
        reg = PricingRegistry()
        u = ModelUsage(model_id="totally-unknown-model-xyz", prompt_tokens=100, completion_tokens=50)
        est = reg.estimate_cost(u)
        assert est.total_cost_usd is None
        assert est.prompt_cost_usd is None
        assert est.completion_cost_usd is None

    @pytest.mark.unit
    def test_negative_tokens_raise_value_error(self) -> None:
        with pytest.raises(ValueError):
            ModelUsage(model_id="m", prompt_tokens=-1, completion_tokens=0)
        with pytest.raises(ValueError):
            ModelUsage(model_id="m", prompt_tokens=0, completion_tokens=-1)

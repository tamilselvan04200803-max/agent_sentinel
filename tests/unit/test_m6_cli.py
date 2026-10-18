"""M6 CLI and exporter tests: full lifecycle + security checks."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest

from agentsentinel.cli import main as cli_main
from agentsentinel.cli.exporter import (
    export_evidence_bundle,
    sanitize_output_dir,
    sanitize_run_id,
)
from agentsentinel.cli.main import main
from agentsentinel.domain.exceptions import UnapprovedExportError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import (
    CaseSpec,
    ExecutionResult,
    PatchProposal,
)
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.checkpoint import (
    CheckpointStore,
    RunState,
)
from agentsentinel.orchestrator.state_machine import RepairStateMachine

if TYPE_CHECKING:
    from pathlib import Path

VALID_SHA = "a" * 40


class _FixedPatchLLM:
    """LLM stub that always returns a provided patch."""

    def __init__(self, patch: PatchProposal) -> None:
        self._patch = patch

    def generate_patch(self, case_id: str, prompt: str, model_id: str):
        return self._patch, ModelUsage(
            model_id="mock", prompt_tokens=10, completion_tokens=5
        )


class _LocalRunner:
    """Offline test runner (no Docker). Applies the patch from kwargs then
    checks whether patched source is correct by running a trivial check.
    For CLI tests we just short-circuit to PASSED for known patches.
    """

    def __init__(self, baseline_exit: ExitCode, patched_exit: ExitCode):
        self.baseline_exit = baseline_exit
        self.patched_exit = patched_exit
        self.calls = 0

    def run_in_container(self, **kwargs: Any) -> ExecutionResult:
        self.calls += 1
        kwargs.get("command", "")
        pdh = kwargs.get("patch_diff_hash", "")
        return ExecutionResult(
            case_id=kwargs.get("case_id", "c"),
            patch_diff_hash=str(pdh),
            exit_code=self.baseline_exit if pdh == "baseline" else self.patched_exit,
            stdout="test_m.py PASSED" if (pdh != "baseline" and self.patched_exit == ExitCode.OK)
                    else "FAILED",
            stderr="",
            wall_seconds=0.01,
            expected_test_ids=kwargs.get("expected_test_ids", ()),
        )


def _make_good_patch(tmp_path: Path) -> tuple[PatchProposal, Path]:
    src = tmp_path / "src"
    src.mkdir()
    (src / "m.py").write_text("def f(x): return x.lower()\n", encoding="utf-8")
    diff = (
        "--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n"
        "-def f(x): return x.lower()\n"
        "+def f(x): return x.strip().lower()\n"
    )
    p = PatchProposal(
        case_id="cli-case",
        unified_diff=diff,
        model_id="mock",
        prompt_tokens=10,
        completion_tokens=5,
    )
    return p, src


def _run_through_approval(tmp_path: Path, patch: PatchProposal,
                          src: Path) -> tuple[str, Path, dict[str, str]]:
    """Drive SM to AWAITING_HUMAN_APPROVAL and return (run_id, db, binding)."""
    db = tmp_path / "r.db"
    spec = CaseSpec(
        case_id="cli-case",
        repo_url="local",
        base_commit=VALID_SHA,
        test_command="pytest -q",
        allowed_edit_paths=("m.py",),
        failing_test_ids=("test_m.py",),
    )
    # Mock apply_validated_patch to actually apply our patch to workspace
    def _fake_apply(patch, source_workspace, allowed_edit_paths,
                    dest_workspace=None, **kwargs: Any):
        assert dest_workspace is not None
        (dest_workspace / "m.py").write_text(
            "def f(x): return x.strip().lower()\n", encoding="utf-8"
        )
        return dest_workspace

    import agentsentinel.orchestrator.state_machine as sm_mod
    with mock.patch.object(sm_mod, "apply_validated_patch", side_effect=_fake_apply):
        sm = RepairStateMachine(
            spec=spec,
            llm_client=_FixedPatchLLM(patch),
            container_runner=_LocalRunner(
                baseline_exit=ExitCode.TESTS_FAILED,
                patched_exit=ExitCode.OK,
            ),
            max_attempts=3,
            db_path=db,
            image_digest="sha256:test",
        )
        sm.source_workspace = src
        rid = sm.start_run()
        sm.run_to_terminal(rid)
    with CheckpointStore(db) as s:
        rec = s.get_run(rid)
        assert rec is not None
        binding = rec.approval_record or {}
    return rid, db, binding


class TestSanitizers:
    @pytest.mark.unit
    def test_run_id_rejects_traversal(self) -> None:
        with pytest.raises(ValueError):
            sanitize_run_id("../etc/passwd")
        with pytest.raises(ValueError):
            sanitize_run_id("a/b")

    @pytest.mark.unit
    def test_output_dir_resolved(self, tmp_path: Path) -> None:
        out = sanitize_output_dir(tmp_path / "sub/..")
        assert out == tmp_path.resolve()


class TestExporter:
    @pytest.mark.unit
    def test_export_unapproved_raises(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, _ = _run_through_approval(tmp_path, patch, src)
        # Don't approve — should fail
        with pytest.raises(UnapprovedExportError):
            export_evidence_bundle(db, rid, tmp_path / "out")

    @pytest.mark.unit
    def test_export_approved_writes_files(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, binding = _run_through_approval(tmp_path, patch, src)
        # Approve
        import agentsentinel.orchestrator.state_machine as sm_mod
        with mock.patch.object(sm_mod, "apply_validated_patch",
                               side_effect=lambda p, s, a, dest_workspace=None: dest_workspace or s):
            sm = RepairStateMachine(
                spec=CaseSpec(
                    case_id="cli-case", repo_url="local", base_commit=VALID_SHA,
                    test_command="pytest -q",
                    allowed_edit_paths=("m.py",),
                    failing_test_ids=("test_m.py",),
                ),
                llm_client=_FixedPatchLLM(patch),
                container_runner=_LocalRunner(ExitCode.TESTS_FAILED, ExitCode.OK),
                max_attempts=3, db_path=db, image_digest="sha256:test",
            )
            sm.approve_run(
                run_id=rid, approver_id="tester",
                expected_diff_hash=binding["diff_hash"],
                expected_image_digest=binding["image_digest"],
                expected_post_patch_result_hash=binding["post_patch_result_hash"],
            )
        out = export_evidence_bundle(db, rid, tmp_path / "out")
        assert (out / "evidence.json").exists()
        assert (out / "approved.patch").exists()
        assert (out / "REPORT.md").exists()
        ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
        assert "bundle_hash" in ev
        assert ev["state"] == "APPROVED"
        assert ev["case_spec"]["case_id"] == "cli-case"
        assert ev["post_patch_result"]["exit_code"] == 0
        assert ev["evidence_bundle"]["accepted_patch"]["unified_diff"] == patch.unified_diff
        report = (out / "REPORT.md").read_text(encoding="utf-8")
        assert "Token and Cost Ledger" in report
        assert "Fail-to-pass tests" in report


class TestCLI:
    @pytest.mark.unit
    def test_status_unknown_run_returns_nonzero(self, tmp_path: Path) -> None:
        db = tmp_path / "r.db"
        rc = main(["status", "--run-id", "nope", "--db", str(db)])
        assert rc == 1

    @pytest.mark.unit
    def test_approve_tampered_hash_fails(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, binding = _run_through_approval(tmp_path, patch, src)
        rc = main([
            "approve", "--run-id", rid, "--db", str(db),
            "--approver-id", "x",
            "--diff-hash", "tampered_hash_value_here_xxx",
            "--image-digest", binding["image_digest"],
            "--post-patch-result-hash", binding["post_patch_result_hash"],
        ])
        assert rc == 3

    @pytest.mark.unit
    def test_approve_correct_hash_succeeds(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, binding = _run_through_approval(tmp_path, patch, src)
        rc = main([
            "approve", "--run-id", rid, "--db", str(db),
            "--approver-id", "alice",
            "--diff-hash", binding["diff_hash"],
            "--image-digest", binding["image_digest"],
            "--post-patch-result-hash", binding["post_patch_result_hash"],
        ])
        assert rc == 0

    @pytest.mark.unit
    def test_approve_with_directive_two_hash_form_succeeds(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, binding = _run_through_approval(tmp_path, patch, src)
        rc = main([
            "approve", "--run-id", rid, "--db", str(db),
            "--approver-id", "alice",
            "--diff-hash", binding["diff_hash"],
            "--image-digest", binding["image_digest"],
        ])
        assert rc == 0

    @pytest.mark.unit
    def test_reject_flow(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, _ = _run_through_approval(tmp_path, patch, src)
        rc = main([
            "reject", "--run-id", rid, "--db", str(db),
            "--reviewer-id", "bob", "--reason", "insufficient tests",
        ])
        assert rc == 0
        with CheckpointStore(db) as s:
            rec = s.get_run(rid)
            assert rec is not None
            assert rec.state == RunState.REJECTED

    @pytest.mark.unit
    def test_export_via_cli_rejects_unapproved(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, _ = _run_through_approval(tmp_path, patch, src)
        rc = main([
            "export", "--run-id", rid, "--db", str(db),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert rc == 4  # unapproved

    @pytest.mark.unit
    def test_export_after_approve_succeeds(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        rid, db, binding = _run_through_approval(tmp_path, patch, src)
        assert main([
            "approve", "--run-id", rid, "--db", str(db),
            "--approver-id", "alice",
            "--diff-hash", binding["diff_hash"],
            "--image-digest", binding["image_digest"],
            "--post-patch-result-hash", binding["post_patch_result_hash"],
        ]) == 0
        rc = main([
            "export", "--run-id", rid, "--db", str(db),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert rc == 0
        assert (tmp_path / "out" / rid / "evidence.json").exists()


class TestFullCLILifecycle:
    @pytest.mark.unit
    def test_run_status_approve_export_via_cli(self, tmp_path: Path) -> None:
        patch, src = _make_good_patch(tmp_path)
        spec_path = tmp_path / "case.json"
        spec_path.write_text(json.dumps({
            "case_id": "cli-case",
            "repo_url": "local",
            "base_commit": VALID_SHA,
            "test_command": "pytest",
            "allowed_edit_paths": ["m.py"],
            "failing_test_ids": ["test_m.py"],
            "repo_source_path": str(src),
        }), encoding="utf-8")
        db = tmp_path / "runs.db"

        def _fake_apply(patch, source_workspace, allowed_edit_paths,
                        dest_workspace=None, **kwargs: Any):
            assert dest_workspace is not None
            (dest_workspace / "m.py").write_text(
                "def f(x): return x.strip().lower()\n", encoding="utf-8"
            )
            return dest_workspace

        import agentsentinel.orchestrator.state_machine as sm_mod
        with (
            mock.patch.object(
                cli_main, "HardenedContainerRunner",
                lambda config=None: _LocalRunner(
                    ExitCode.TESTS_FAILED, ExitCode.OK
                ),
            ),
            mock.patch.object(
                cli_main, "_make_llm", return_value=_FixedPatchLLM(patch)
            ),
            mock.patch.object(
                sm_mod, "apply_validated_patch", side_effect=_fake_apply
            ),
        ):
            assert main([
                "run", "--case-spec", str(spec_path), "--db", str(db),
                "--provider", "mock", "--max-attempts", "3",
            ]) == 2

        with CheckpointStore(db) as store:
            runs = store._conn.execute("SELECT run_id FROM runs").fetchall()
            assert len(runs) == 1
            rid = str(runs[0][0])
            rec = store.get_run(rid)
            assert rec is not None
            binding = rec.approval_record or {}

        assert main(["status", "--run-id", rid, "--db", str(db)]) == 0
        assert main([
            "approve", "--run-id", rid, "--db", str(db),
            "--approver-id", "alice",
            "--diff-hash", binding["diff_hash"],
            "--image-digest", binding["image_digest"],
            "--post-patch-result-hash", binding["post_patch_result_hash"],
        ]) == 0
        assert main([
            "export", "--run-id", rid, "--db", str(db),
            "--output-dir", str(tmp_path / "evidence"),
        ]) == 0
        assert (tmp_path / "evidence" / rid / "REPORT.md").exists()

    @pytest.mark.unit
    def test_benchmark_cli_writes_reports(self, tmp_path: Path) -> None:
        import shutil
        from pathlib import Path
        fixture_root = (
            Path(__file__).resolve().parent.parent
            / "fixtures" / "benchmark_cases"
        )
        suite = tmp_path / "suite"
        shutil.copytree(fixture_root / "case_01_normalizer", suite / "case_01_normalizer")
        out = tmp_path / "bench-out"
        rc = main([
            "benchmark", "--suite-dir", str(suite),
            "--output-dir", str(out), "--db", str(tmp_path / "bench.db"),
            "--provider", "mock",
        ])
        assert rc == 0
        assert (out / "benchmark_suite.json").exists()
        assert (out / "benchmark_suite.md").exists()
        payload = json.loads((out / "benchmark_suite.json").read_text(encoding="utf-8"))
        assert payload["admitted_cases_count"] == 1

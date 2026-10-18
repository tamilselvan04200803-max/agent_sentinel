"""Adversarial tests for M5/M6: reference-patch isolation, tampered approval,
path-traversal hardening in CLI/exporter.
"""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from agentsentinel.cli.exporter import sanitize_run_id
from agentsentinel.cli.main import main
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.evaluation.models import BenchmarkCase
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.state_machine import RepairStateMachine

VALID_SHA = "0" * 40


class _SpyLLM:
    """Captures every prompt sent to generate_patch for leakage inspection."""

    def __init__(self, patch: PatchProposal):
        self.patch = patch
        self.prompts: list[str] = []

    def generate_patch(self, case_id: str, prompt: str, model_id: str):
        self.prompts.append(prompt)
        return self.patch, ModelUsage(model_id="spy", prompt_tokens=1, completion_tokens=1)


class _LocalRunnerForBenchmark:
    def __init__(self, baseline_fails: bool, fix_passes: bool):
        self._baseline_fails = baseline_fails
        self._fix_passes = fix_passes
        self.calls = 0
    def run_in_container(self, **kwargs: Any) -> ExecutionResult:
        self.calls += 1
        # Harness runs baseline once per admission; repair calls use
        # patch_diff_hash != "baseline" and get _fix_passes result.
        pdh = str(kwargs.get("patch_diff_hash", ""))
        if pdh == "baseline":
            code = ExitCode.TESTS_FAILED if self._baseline_fails else ExitCode.OK
        else:
            code = ExitCode.OK if self._fix_passes else ExitCode.TESTS_FAILED
        return ExecutionResult(
            case_id=kwargs.get("case_id", "c"), patch_diff_hash=pdh,
            exit_code=code, stdout="", stderr="", wall_seconds=0.01,
            expected_test_ids=(),
        )


def test_reference_fix_patch_never_leaks_into_llm_prompt(tmp_path: Path) -> None:
    """Adversarial: reference_fix_patch content must never appear in any LLM
    prompt sent during a benchmark run (contamination / data-leak check)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "m.py").write_text("def f(x): return x.lower()\n", encoding="utf-8")
    CaseSpec(
        case_id="leak-check",
        repo_url="local", base_commit=VALID_SHA,
        test_command="python -c \"import sys; sys.exit(1)\"",  # baseline fails
        allowed_edit_paths=("m.py",),
        failing_test_ids=("test_m.py::test_x",),
    )
    # Make the reference fix cause test to pass by replacing m.py body so
    # python -c "print('ok')" is not used; simpler: construct a test command
    # that always exits 0 on the reference run and 1 on baseline.
    # For this adversarial test we bypass admission gate and directly drive
    # the harness SM path to confirm no reference content reaches prompt.

    # Build a case where baseline command fails and fixed command passes.
    spec2 = CaseSpec(
        case_id="leak-check",
        repo_url="local", base_commit=VALID_SHA,
        # Use a sentinel command that depends on a file the reference patch
        # writes.
        test_command="python -c \"import pathlib; import sys; "
                     "sys.exit(0 if pathlib.Path('m.py').read_text().find('FIXED')>=0 else 1)\"",
        allowed_edit_paths=("m.py",),
        failing_test_ids=("t",),
    )
    ref_patch2 = (
        "--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-def f(x): return x.lower()\n+FIXED_MARKER_SENTINEL_REF_NEVER_LEAK\n"
    )
    BenchmarkCase(
        case_spec=spec2,
        repo_source_path=src,
        base_commit=VALID_SHA,
        test_patch="",
        reference_fix_patch=ref_patch2,
        fail_to_pass_tests=("t",),
        pass_to_pass_tests=(),
        is_public_historical_commit=False,
    )
    # Patch returned by LLM — does NOT contain FIXED_MARKER.
    dummy_patch = PatchProposal(
        case_id="leak-check",
        unified_diff="--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-old\n+new\n",
        model_id="spy", prompt_tokens=1, completion_tokens=1,
    )
    spy = _SpyLLM(dummy_patch)
    # Provision baseline source (without reference_fix_patch applied) via
    # harness._provision. Patch apply will fail for dummy_patch; that's fine,
    # we only care about the prompt contents at PROPOSING_PATCH time.
    from agentsentinel.evaluation.harness import _provision
    source_ws = _provision(src, [""])  # only test_patch (empty)
    db = tmp_path / "r.db"
    import agentsentinel.orchestrator.state_machine as sm_mod
    def _fake_apply(p, sw, a, dest_workspace=None):
        # Don't actually apply — just write something trivial.
        if dest_workspace is None:
            return sw
        (dest_workspace / "m.py").write_text("new\n", encoding="utf-8")
        return dest_workspace
    with mock.patch.object(sm_mod, "apply_validated_patch", side_effect=_fake_apply):
        sm = RepairStateMachine(
            spec=spec2,
            llm_client=spy,
            container_runner=_LocalRunnerForBenchmark(
                baseline_fails=True, fix_passes=False,
            ),
            max_attempts=1, db_path=db,
            image_digest="sha256:t",
            auto_approve_on_fix=False,
            source_workspace_override=source_ws,
        )
        rid = sm.start_run()
        with contextlib.suppress(Exception):
            sm.run_to_terminal(rid)
    # After run, inspect every captured prompt for the reference-patch marker.
    for prompt in spy.prompts:
        assert "FIXED_MARKER_SENTINEL_REF_NEVER_LEAK" not in prompt, (
            "reference_fix_patch leaked into LLM prompt!"
        )


def test_path_traversal_in_run_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        sanitize_run_id("../../etc/passwd")
    with pytest.raises(ValueError):
        sanitize_run_id("a/../b")


def test_tampered_diff_hash_via_cli_fails(tmp_path: Path) -> None:
    """Tampering with --diff-hash on CLI approve must raise (non-zero exit)."""
    from tests.unit.test_m6_cli import _make_good_patch, _run_through_approval
    patch, src = _make_good_patch(tmp_path)
    rid, db, binding = _run_through_approval(tmp_path, patch, src)
    rc = main([
        "approve", "--run-id", rid, "--db", str(db),
        "--approver-id", "mallory",
        "--diff-hash", "0" * 64,  # forged
        "--image-digest", binding["image_digest"],
        "--post-patch-result-hash", binding["post_patch_result_hash"],
    ])
    assert rc != 0


def test_reference_patch_not_in_prompts_during_benchmark_run(tmp_path: Path) -> None:
    """End-to-end BenchmarkHarness leak check (not just a direct SM drive)."""
    from agentsentinel.evaluation.harness import BenchmarkHarness
    from agentsentinel.evaluation.models import BenchmarkCase as _BC

    fixture = (
        Path(__file__).resolve().parent.parent
        / "fixtures" / "benchmark_cases" / "case_01_normalizer"
    )
    raw = json.loads((fixture / "spec.json").read_text(encoding="utf-8"))
    spec = CaseSpec(
        case_id=raw["case_id"],
        repo_url=raw["repo_url"],
        base_commit=raw["base_commit"],
        test_command=raw["test_command"],
        allowed_edit_paths=tuple(raw["allowed_edit_paths"]),
        failing_test_ids=tuple(raw["failing_test_ids"]),
        created_at=datetime.now(UTC),
    )
    reference = (fixture / "reference.patch").read_text(encoding="utf-8")
    case = _BC(
        case_spec=spec,
        repo_source_path=fixture / "src",
        base_commit=spec.base_commit,
        test_patch=(fixture / "test.patch").read_text(encoding="utf-8"),
        reference_fix_patch=reference,
        fail_to_pass_tests=spec.failing_test_ids,
        pass_to_pass_tests=(),
        is_public_historical_commit=False,
    )
    wrong_patch = PatchProposal(
        case_id=spec.case_id,
        unified_diff=reference.replace(
            "return s.strip().lower()", "return s.upper()"
        ),
        model_id="spy",
        prompt_tokens=3,
        completion_tokens=2,
    )
    spy = _SpyLLM(wrong_patch)
    harness = BenchmarkHarness(
        llm_factory=lambda: spy,
        db_path=tmp_path / "bench.db",
        max_attempts=1,
    )
    report = harness.run_suite([case], suite_name="leak-e2e")
    assert report.admitted_cases_count == 1
    assert spy.prompts, "benchmark run never reached the LLM"
    for prompt in spy.prompts:
        assert "strip().lower()" not in prompt

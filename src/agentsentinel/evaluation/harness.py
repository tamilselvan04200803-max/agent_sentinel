"""M5: Contamination-aware benchmark harness.

Admission gates:
  Gate 1 — baseline+test_patch must FAIL with ExitCode.TESTS_FAILED (1).
  Gate 2 — baseline+test_patch+reference_fix_patch must PASS with ExitCode.OK (0).

The reference_fix_patch is applied ONLY inside the admission gate; it is
NEVER passed to RepairStateMachine or PromptBuilder.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import ExecutionResult
from agentsentinel.evaluation.metrics import (
    BenchmarkReport,
    CaseEvaluationResult,
    ComparisonReport,
    _aggregate,
)
from agentsentinel.evaluation.models import AdmissionVerdict, BenchmarkCase
from agentsentinel.orchestrator.checkpoint import (
    AttemptStatus,
    CheckpointStore,
    RunState,
    TerminationReason,
)
from agentsentinel.orchestrator.state_machine import RepairStateMachine
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.sandbox.workspace import WorkspaceManager

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class _Runner(Protocol):
    def run_in_container(
        self,
        case_id: str,
        patch_diff_hash: str,
        workspace_host_path: Path,
        command: str | list[str],
    ) -> ExecutionResult: ...


def _apply_patch_text(repo_path: Path, patch_text: str) -> None:
    if not patch_text.strip():
        return
    proc = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", "-"],
        cwd=repo_path,
        input=patch_text.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"patch application failed (code={proc.returncode}): "
            f"{proc.stderr.decode('utf-8', errors='replace')}"
        )


def _is_docker_available(image: str = "agentsentinel-runner:py311") -> bool:
    """Return True iff docker daemon is responsive and the image is available locally."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            check=False,
        )
        if res.returncode != 0:
            return False
        img = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            check=False,
        )
        return img.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _run_tests(workspace: Path, test_command: str) -> ExecutionResult:
    # Admission and verification need per-test PASSED/FAILED markers.
    if test_command.startswith("pytest") and "-v" not in test_command.split():
        test_command = f"{test_command} -v -ra"
    docker_present = _is_docker_available()
    start = time.perf_counter()
    if docker_present:
        docker_result: ExecutionResult | None = None
        try:
            runner = HardenedContainerRunner(
                config=ContainerConfig(
                    image="agentsentinel-runner:py311",
                    network_disabled=True,
                    memory_limit="2g",
                    cpus="1.0",
                    timeout_seconds=30,
                )
            )
            docker_result = runner.run_in_container(
                case_id="__admission__",
                patch_diff_hash="admission",
                workspace_host_path=workspace,
                command=test_command,
            )
        except Exception:  # noqa: BLE001
            docker_result = None
        if docker_result is not None:
            return docker_result
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(workspace) + os.pathsep + env.get("PYTHONPATH", "")
    # Use the venv's Python interpreter so `pytest` resolves correctly even
    # when the venv is not activated in PATH.
    if isinstance(test_command, str):
        if test_command.startswith("pytest"):
            cmd_args = test_command.split()[1:]
            if "no:schemathesis" not in cmd_args:
                cmd_args = ["-p", "no:schemathesis", *cmd_args]
            argv: list[str] | str = [sys.executable, "-m", "pytest", *cmd_args]
            use_shell = False
        else:
            argv = test_command
            use_shell = True
    else:
        argv = list(test_command)
        if argv and argv[0] == "pytest":
            cmd_args = argv[1:]
            if "no:schemathesis" not in cmd_args:
                cmd_args = ["-p", "no:schemathesis", *cmd_args]
            argv = [sys.executable, "-m", "pytest", *cmd_args]
        use_shell = False
    proc = subprocess.run(
        argv,
        cwd=workspace,
        shell=use_shell,
        env=env,
        capture_output=True,
        timeout=60,
    )
    elapsed = time.perf_counter() - start
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode == 0:
        exit_code = ExitCode.OK
    elif proc.returncode == 1:
        exit_code = ExitCode.TESTS_FAILED
    else:
        exit_code = ExitCode.INTERNAL_ERROR
    return ExecutionResult(
        case_id="__admission__",
        patch_diff_hash="admission",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        wall_seconds=elapsed,
        expected_test_ids=(),
    )


def _test_reported(output: str, test_id: str, marker: str) -> bool:
    """Return True when pytest output reports ``test_id`` with ``marker``.

    Supports verbose lines (``test_id PASSED``) and short summary lines
    (``FAILED test_id - ...``).
    """
    escaped = re.escape(test_id)
    return bool(
        re.search(rf"{escaped}\s+{marker}\b", output)
        or re.search(rf"\b{marker}\s+{escaped}\b", output)
    )


def _all_reported(output: str, test_ids: tuple[str, ...], marker: str) -> bool:
    return all(_test_reported(output, tid, marker) for tid in test_ids)


def _provision(src: Path, patches: Sequence[str]) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="agentsentinel_harness_"))
    subprocess.run(["git", "init"], cwd=tmp, capture_output=True, check=False)
    for item in src.iterdir():
        if item.name == ".git":
            continue
        dest = tmp / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)
    subprocess.run(["git", "add", "."], cwd=tmp, capture_output=True, check=False)
    for p in patches:
        _apply_patch_text(tmp, p)
    WorkspaceManager().scrub_git_history(tmp)
    return tmp


def verify_case_admission(case: BenchmarkCase) -> AdmissionVerdict:
    t0 = time.perf_counter()

    ws1: Path | None = None
    base_exit: int | None = None
    try:
        ws1 = _provision(case.repo_source_path, [case.test_patch])
        base_result = _run_tests(ws1, case.case_spec.test_command)
        base_exit = int(base_result.exit_code)
        if base_result.exit_code != ExitCode.TESTS_FAILED:
            elapsed = time.perf_counter() - t0
            return AdmissionVerdict(
                case_id=case.case_spec.case_id,
                admitted=False,
                reason=f"Gate 1 failed: baseline+test_patch exited {base_result.exit_code!r}, "
                       f"expected TESTS_FAILED (1). stderr={base_result.stderr[:200]}",
                baseline_exit_code=int(base_result.exit_code),
                reference_exit_code=None,
                prep_duration_seconds=elapsed,
            )
        combined = base_result.stdout + "\n" + base_result.stderr
        if case.fail_to_pass_tests and not _all_reported(
            combined, case.fail_to_pass_tests, "FAILED"
        ):
            elapsed = time.perf_counter() - t0
            return AdmissionVerdict(
                case_id=case.case_spec.case_id,
                admitted=False,
                reason="Gate 1 failed: declared fail_to_pass_tests were not "
                       "all reported FAILED at baseline",
                baseline_exit_code=int(base_result.exit_code),
                reference_exit_code=None,
                prep_duration_seconds=elapsed,
            )
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return AdmissionVerdict(
            case_id=case.case_spec.case_id,
            admitted=False,
            reason=f"Gate 1 setup error: {exc}",
            baseline_exit_code=None,
            reference_exit_code=None,
            prep_duration_seconds=elapsed,
        )
    finally:
        if ws1 is not None:
            shutil.rmtree(ws1, ignore_errors=True)

    ws2: Path | None = None
    ref_exit: int | None = None
    try:
        ws2 = _provision(case.repo_source_path, [case.test_patch, case.reference_fix_patch])
        ref_result = _run_tests(ws2, case.case_spec.test_command)
        ref_exit = int(ref_result.exit_code)
        if ref_result.exit_code != ExitCode.OK:
            elapsed = time.perf_counter() - t0
            return AdmissionVerdict(
                case_id=case.case_spec.case_id,
                admitted=False,
                reason=f"Gate 2 failed: reference fix exited {ref_result.exit_code!r}, "
                       f"expected OK (0). stderr={ref_result.stderr[:200]}",
                baseline_exit_code=base_exit,
                reference_exit_code=int(ref_result.exit_code),
                prep_duration_seconds=elapsed,
            )
        combined_ref = ref_result.stdout + "\n" + ref_result.stderr
        expected_pass = case.fail_to_pass_tests + case.pass_to_pass_tests
        if expected_pass and not _all_reported(combined_ref, expected_pass, "PASSED"):
            elapsed = time.perf_counter() - t0
            return AdmissionVerdict(
                case_id=case.case_spec.case_id,
                admitted=False,
                reason="Gate 2 failed: declared fail_to_pass/pass_to_pass tests "
                       "were not all reported PASSED with reference fix",
                baseline_exit_code=base_exit,
                reference_exit_code=int(ref_result.exit_code),
                prep_duration_seconds=elapsed,
            )
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return AdmissionVerdict(
            case_id=case.case_spec.case_id,
            admitted=False,
            reason=f"Gate 2 setup error: {exc}",
            baseline_exit_code=base_exit,
            reference_exit_code=None,
            prep_duration_seconds=elapsed,
        )
    finally:
        if ws2 is not None:
            shutil.rmtree(ws2, ignore_errors=True)

    elapsed = time.perf_counter() - t0
    return AdmissionVerdict(
        case_id=case.case_spec.case_id,
        admitted=True,
        reason="admitted",
        baseline_exit_code=base_exit,
        reference_exit_code=ref_exit,
        prep_duration_seconds=elapsed,
    )


class _LocalBenchRunner:
    """Offline runner: executes the real test command in the workspace.

    This preserves honest F2P/P2P semantics offline (the LLM patch must
    actually make the tests pass) without requiring a Docker daemon.
    """

    def __init__(self) -> None:
        self.calls = 0

    def run_in_container(
        self,
        case_id: str,
        patch_diff_hash: str,
        workspace_host_path: Path,
        command: str | list[str],
    ) -> ExecutionResult:
        self.calls += 1
        cmd = command if isinstance(command, str) else " ".join(command)
        result = _run_tests(workspace_host_path, cmd)
        return ExecutionResult(
            case_id=case_id,
            patch_diff_hash=patch_diff_hash,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            wall_seconds=result.wall_seconds,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            expected_test_ids=(),
        )


class BenchmarkHarness:
    def __init__(
        self,
        llm_factory: Callable[[], Any],
        db_path: Path | None = None,
        max_attempts: int = 3,
        image_digest: str = "sha256:local",
        use_docker: bool = False,
    ) -> None:
        self._llm_factory = llm_factory
        self._db_path = db_path
        self._max_attempts = max_attempts
        self._image_digest = image_digest
        self._use_docker = use_docker

    def _make_runner(self) -> _Runner:
        if self._use_docker and _is_docker_available():
            return HardenedContainerRunner(ContainerConfig(
                image="agentsentinel-runner:py311",
                network_disabled=True,
                memory_limit="2g",
                cpus="1.0",
                timeout_seconds=60,
            ))
        return _LocalBenchRunner()

    def _run_one_case(self, case: BenchmarkCase, verdict: AdmissionVerdict) -> CaseEvaluationResult:
        llm = self._llm_factory()
        source_ws = _provision(case.repo_source_path, [case.test_patch])
        bench_tmp: Path | None = None
        if self._db_path is not None:
            case_slug = re.sub(r"[^\w\-]", "_", case.case_spec.case_id)
            db = self._db_path.parent / f"{self._db_path.stem}_{case_slug}{self._db_path.suffix}"
        else:
            bench_tmp = Path(tempfile.mkdtemp(prefix="as_bench_"))
            db = bench_tmp / "c.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        runner = self._make_runner()
        sm = RepairStateMachine(
            spec=case.case_spec,
            llm_client=llm,
            container_runner=runner,  # type: ignore[arg-type]
            max_attempts=self._max_attempts,
            db_path=db,
            image_digest=self._image_digest,
            auto_approve_on_fix=True,
            source_workspace_override=source_ws,
        )
        t0 = time.perf_counter()
        rid = sm.start_run()
        termination_reason: str | None = None
        state = RunState.TERMINATED_FAILED
        attempts_used = 0
        try:
            sm.run_to_terminal(rid)
        except Exception as exc:
            termination_reason = type(exc).__name__
        rec = sm.resume_run(rid)
        state = rec.state
        attempts_used = rec.attempts_used
        if rec.termination_reason is not None and rec.termination_reason != TerminationReason.NONE:
            termination_reason = rec.termination_reason.value
        elapsed = time.perf_counter() - t0
        in_tok = 0
        out_tok = 0
        any_unknown = False
        cost_total: float = 0.0
        policy_violations = 0
        with CheckpointStore(db) as s:
            for att in s.get_attempts(rid):
                usage = att.usage_json or {}
                in_tok += int(usage.get("prompt_tokens", 0))
                out_tok += int(usage.get("completion_tokens", 0))
                is_policy = att.status == AttemptStatus.POLICY_REJECTED
                if is_policy or "Policy" in (att.error_type or ""):
                    policy_violations += 1
                if att.cost_usd is None:
                    any_unknown = True
                else:
                    cost_total += att.cost_usd
        cost_val: float | None = None if any_unknown else cost_total
        shutil.rmtree(source_ws, ignore_errors=True)
        if bench_tmp is not None:
            shutil.rmtree(bench_tmp, ignore_errors=True)
        return CaseEvaluationResult(
            case_id=case.case_spec.case_id,
            admitted=True,
            repair_duration_seconds=elapsed,
            prep_duration_seconds=verdict.prep_duration_seconds,
            terminated_state=state,
            termination_reason=termination_reason,
            attempts_used=attempts_used,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost_val,
            is_public=case.is_public_historical_commit,
            policy_violation_count=policy_violations,
        )

    def run_suite(
        self,
        cases: Sequence[BenchmarkCase],
        suite_name: str = "benchmark",
    ) -> BenchmarkReport:
        cases_list = list(cases)
        verdicts: list[AdmissionVerdict] = []
        results: list[CaseEvaluationResult] = []
        total_policy_violations = 0
        total_attempts = 0
        for case in cases_list:
            verdict = verify_case_admission(case)
            verdicts.append(verdict)
            if not verdict.admitted:
                results.append(CaseEvaluationResult(
                    case_id=case.case_spec.case_id,
                    admitted=False,
                    repair_duration_seconds=0.0,
                    prep_duration_seconds=verdict.prep_duration_seconds,
                    terminated_state="EXCLUDED",
                    termination_reason="EXCLUDED",
                    attempts_used=0,
                    input_tokens=0,
                    output_tokens=0,
                    cost_usd=None,
                    is_public=case.is_public_historical_commit,
                ))
                continue
            res = self._run_one_case(case, verdict)
            results.append(res)
            total_attempts += res.attempts_used
            total_policy_violations += res.policy_violation_count
        generated = datetime.now(UTC).isoformat()
        return _aggregate(
            verdicts=verdicts,
            case_results=results,
            total_policy_violations=total_policy_violations,
            total_attempts=total_attempts,
            suite_name=suite_name,
            generated_at_utc=generated,
        )


def compare_baseline_vs_bounded_retry(
    cases: Sequence[BenchmarkCase],
    llm_factory: Callable[[], Any],
    max_attempts_baseline: int = 1,
    max_attempts_bounded: int = 5,
) -> ComparisonReport:
    cases = list(cases)
    bench_dir1 = Path(tempfile.mkdtemp(prefix="as_bench_baseline_"))
    bench_dir2 = Path(tempfile.mkdtemp(prefix="as_bench_bounded_"))
    try:
        h1 = BenchmarkHarness(
            llm_factory=llm_factory,
            db_path=bench_dir1 / "baseline.db",
            max_attempts=max_attempts_baseline,
        )
        r1 = h1.run_suite(cases, suite_name="single-proposal")
        h2 = BenchmarkHarness(
            llm_factory=llm_factory,
            db_path=bench_dir2 / "bounded.db",
            max_attempts=max_attempts_bounded,
        )
        r2 = h2.run_suite(cases, suite_name="bounded-retry")
    finally:
        shutil.rmtree(bench_dir1, ignore_errors=True)
        shutil.rmtree(bench_dir2, ignore_errors=True)
    calls1 = sum(r.attempts_used for r in r1.per_case_results if r.admitted)
    calls2 = sum(r.attempts_used for r in r2.per_case_results if r.admitted)
    return ComparisonReport(
        baseline_max_attempts=max_attempts_baseline,
        bounded_max_attempts=max_attempts_bounded,
        cases_count=len(cases),
        baseline_repair_rate=r1.verified_repair_rate,
        bounded_repair_rate=r2.verified_repair_rate,
        baseline_total_llm_calls=calls1,
        bounded_total_llm_calls=calls2,
        baseline_total_input_tokens=r1.total_input_tokens,
        bounded_total_input_tokens=r2.total_input_tokens,
        baseline_total_output_tokens=r1.total_output_tokens,
        bounded_total_output_tokens=r2.total_output_tokens,
        baseline_total_latency_seconds=r1.total_repair_latency_seconds,
        bounded_total_latency_seconds=r2.total_repair_latency_seconds,
        delta_repair_rate=r2.verified_repair_rate - r1.verified_repair_rate,
        delta_llm_calls=calls2 - calls1,
        delta_input_tokens=r2.total_input_tokens - r1.total_input_tokens,
        delta_output_tokens=r2.total_output_tokens - r1.total_output_tokens,
        delta_latency_seconds=r2.total_repair_latency_seconds - r1.total_repair_latency_seconds,
    )

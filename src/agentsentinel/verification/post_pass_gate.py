"""Sandbox-backed, bounded post-pass minimization and mutation evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import (
    HarnessSetupError,
    HarnessTimeoutError,
    PatchPolicyError,
    PathTraversalError,
    SymlinkEscapeError,
)
from agentsentinel.domain.exit_codes import ExitCode, is_harness_broken
from agentsentinel.domain.models import (
    ExecutionResult,
    MinimizationSummary,
    MutationAdequacySummary,
    PatchProposal,
    SurvivedMutantDetail,
)
from agentsentinel.policy.applier import PatchApplicationError, apply_validated_patch
from agentsentinel.policy.diff_parser import UnifiedDiffParser
from agentsentinel.policy.validator import PatchPolicyValidator
from agentsentinel.sandbox.workspace import WorkspaceManager
from agentsentinel.verification.differential_mutation import generate_differential_patch_mutants
from agentsentinel.verification.overfit_guard import verify_not_overfitted
from agentsentinel.verification.patch_minimizer import generate_minimal_hunk_subsets

if TYPE_CHECKING:
    from agentsentinel.domain.models import CaseSpec
    from agentsentinel.verification.differential_mutation import DifferentialPatchMutant
    from agentsentinel.verification.mutation_batch import ContainerRunnerProtocol

__all__ = [
    "MinimizationSummary",
    "MutationAdequacySummary",
    "PostPassVerificationReport",
    "SurvivedMutantDetail",
    "run_ddmin_hunk_minimization",
    "run_mutation_adequacy_probe",
]


def _has_passing_evidence(result: ExecutionResult, expected_ids: tuple[str, ...]) -> bool:
    # Parameter IDs may contain spaces. Anchor the complete escaped ID to reject
    # prefixed lookalikes while accepting normal verbose pytest output.
    return result.exit_code == ExitCode.OK and all(
        re.search(rf"^{re.escape(node)}\s+PASSED(?:\s|$)", result.stdout, re.MULTILINE)
        is not None
        for node in expected_ids
    )


def _test_command(spec: CaseSpec) -> list[str]:
    return ["python", "-m", "pytest", "-v", "-ra", *spec.failing_test_ids]


def _source(workspace: Path, relative: str, *, missing_allowed: bool = False) -> str:
    path = Path(relative)
    if (
        path.is_absolute()
        or PureWindowsPath(relative).drive
        or ".." in relative.replace("\\", "/").split("/")
    ):
        raise PathTraversalError(relative)
    root = workspace.resolve()
    target = (root / path).resolve()
    if not target.is_relative_to(root):
        raise SymlinkEscapeError(relative, str(target), str(root))
    try:
        return target.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        if missing_allowed:
            return ""
        raise HarnessSetupError(f"Expected source file is missing: {relative}") from error
    except (OSError, UnicodeError) as error:
        raise HarnessSetupError(f"Cannot read source file {relative}: {error}") from error


def run_ddmin_hunk_minimization(
    *,
    raw_diff: str,
    baseline_workspace: Path,
    spec: CaseSpec,
    runner: ContainerRunnerProtocol,
    original_result: ExecutionResult,
    iterative: bool = False,
) -> tuple[str, ExecutionResult, MinimizationSummary]:
    """Select the first passing generated subset using pristine candidate copies.

    Singleton candidates precede drop-one candidates in deterministic order.
    This bounded single pass guarantees neither a global nor a 1-minimal patch.
    The caller must already hold visibly passing evidence for every failing ID.

    ``iterative=True`` restarts after each accepted reduction. On a deterministic
    policy/test oracle the result is 1-minimal among applicable, policy-accepted
    nonempty hunk deletions. This does not prove a global optimum, essential
    execution paths, or that individual mutants cannot be equivalent.
    """
    if not _has_passing_evidence(original_result, spec.failing_test_ids):
        raise ValueError("Minimization requires passing original test-node evidence")
    count = (
        sum(len(file.hunks) for file in UnifiedDiffParser.parse(raw_diff).files)
        if raw_diff.strip()
        else 0
    )
    unchanged = MinimizationSummary(count, count, 0, False)
    if count <= 1:
        return raw_diff, original_result, unchanged
    if iterative:
        selected, execution, selected_count = raw_diff, original_result, count
        while selected_count > 1:
            candidate, candidate_result, summary = run_ddmin_hunk_minimization(
                raw_diff=selected, baseline_workspace=baseline_workspace, spec=spec,
                runner=runner, original_result=execution,
            )
            if summary.minimized_hunks_count >= selected_count:
                break
            selected, execution = candidate, candidate_result
            selected_count = summary.minimized_hunks_count
        return selected, execution, MinimizationSummary(
            count, selected_count, count - selected_count, selected_count < count,
        )

    manager = WorkspaceManager()
    validator = PatchPolicyValidator(spec.allowed_edit_paths)
    for candidate in generate_minimal_hunk_subsets(raw_diff):
        try:
            validator.validate_diff(candidate, workspace_root=baseline_workspace)
            candidate_files = UnifiedDiffParser.parse(candidate).files
            pre_sources = {
                path: _source(baseline_workspace, path, missing_allowed=file.is_new)
                for file in candidate_files
                for path in file.target_paths
                if path.endswith(".py")
            }
            proposal = PatchProposal(spec.case_id, candidate, "post-pass-minimizer", 0, 0)
            with manager.create_workspace() as scratch:
                workspace = Path(scratch)
                manager.populate_from_directory(baseline_workspace, workspace)
                manager.scrub_git_history(workspace)
                apply_validated_patch(
                    patch=proposal,
                    source_workspace=baseline_workspace,
                    allowed_edit_paths=spec.allowed_edit_paths,
                    dest_workspace=workspace,
                )
                post_sources = {
                    path: _source(workspace, path, missing_allowed=file.is_delete)
                    for file in candidate_files
                    for path in file.target_paths
                    if path.endswith(".py")
                }
                verify_not_overfitted(
                    baseline_workspace, pre_sources, post_sources, raw_diff=candidate
                )
                execution = runner.run_in_container(
                    case_id=spec.case_id,
                    patch_diff_hash=proposal.diff_hash,
                    workspace_host_path=workspace,
                    command=_test_command(spec),
                )
                if is_harness_broken(execution.exit_code):
                    raise HarnessSetupError(
                        f"Candidate sandbox test harness exited {execution.exit_code}",
                        stderr=execution.stderr,
                    )
                if not _has_passing_evidence(execution, spec.failing_test_ids):
                    continue
                selected_count = sum(len(file.hunks) for file in candidate_files)
                return (
                    candidate,
                    replace(
                        execution,
                        case_id=spec.case_id,
                        patch_diff_hash=proposal.diff_hash,
                        expected_test_ids=spec.failing_test_ids,
                    ),
                    MinimizationSummary(count, selected_count, count - selected_count, True),
                )
        except (
            PatchPolicyError,
            PathTraversalError,
            SymlinkEscapeError,
            PatchApplicationError,
            HarnessTimeoutError,
        ):
            continue
    return raw_diff, original_result, unchanged


@dataclass(frozen=True)
class PostPassVerificationReport:
    """Accepted diff/result and their immutable post-pass evidence."""

    minimized_diff: str
    minimized_execution_result: ExecutionResult
    minimization_summary: MinimizationSummary
    mutation_adequacy_summary: MutationAdequacySummary


def _mutant_id(mutant: DifferentialPatchMutant) -> str:
    payload = json.dumps(
        [
            mutant.file_path, mutant.function_name,
            mutant.mutation_description, mutant.mutated_source,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def run_mutation_adequacy_probe(
    *,
    minimized_diff: str,
    baseline_workspace: Path,
    patched_workspace: Path,
    spec: CaseSpec,
    runner: ContainerRunnerProtocol,
    max_mutants: int = 3,
    post_patch_result: ExecutionResult | None = None,
    single_container_batch: bool = False,
) -> MutationAdequacySummary:
    """Evaluate a total capped set of selected-patch mutants through the sandbox.

    ``post_patch_result`` reuses the selected passing result and its measured
    wall time. Standalone callers may omit it to run one baseline verification.
    No baseline or mutant execution occurs when no eligible mutants exist.
    ``single_container_batch=True`` opts into one verified V2 batch. Legacy
    callers and protocol doubles retain singleton execution by default.
    """
    if max_mutants < 0:
        raise ValueError("max_mutants must be non-negative")
    if not max_mutants or not minimized_diff.strip():
        return MutationAdequacySummary(False, 0, 0, 0, 1.0, ())
    mutants: list[DifferentialPatchMutant] = []
    budget = max_mutants
    parsed = UnifiedDiffParser.parse(minimized_diff)
    changed = {file.target_path: file for file in parsed.files if file.target_path.endswith(".py")}
    if budget and changed:
        PatchPolicyValidator(spec.allowed_edit_paths).validate_diff(
            minimized_diff, workspace_root=baseline_workspace
        )
        for relative, file in sorted(changed.items()):
            before = _source(baseline_workspace, relative, missing_allowed=file.is_new)
            after = _source(patched_workspace, relative, missing_allowed=file.is_delete)
            generated = generate_differential_patch_mutants(relative, before, after, budget)
            mutants.extend(generated)
            budget -= len(generated)
            if budget == 0:
                break
    if not mutants:
        return MutationAdequacySummary(False, 0, 0, 0, 1.0, ())

    # Lazy import keeps pure minimization independent of the mutation wrapper.
    from agentsentinel.verification.mutation_batch import run_in_container_mutation_batch

    proposal = PatchProposal(spec.case_id, minimized_diff, "post-pass-mutation", 0, 0)
    baseline_result = post_patch_result
    if baseline_result is None:
        baseline_result = runner.run_in_container(
            case_id=spec.case_id,
            patch_diff_hash=proposal.diff_hash,
            workspace_host_path=patched_workspace,
            command=_test_command(spec),
        )
    if not _has_passing_evidence(baseline_result, spec.failing_test_ids):
        raise ValueError("Mutation probing requires passing selected-patch test-node evidence")

    if single_container_batch:
        verdicts = run_in_container_mutation_batch(
            runner=runner, case_id=spec.case_id, patch_diff_hash=proposal.diff_hash,
            workspace_host_path=patched_workspace, mutants=tuple(mutants),
            failing_test_ids=spec.failing_test_ids,
            baseline_wall_seconds=baseline_result.wall_seconds, single_container=True,
        )
        if len(verdicts) != len(mutants) or any(type(verdict) is not bool for verdict in verdicts):
            raise HarnessSetupError("Mutation wrapper returned invalid batch verdicts")
    else:
        singleton_verdicts = []
        for mutant in mutants:
            try:
                singleton = run_in_container_mutation_batch(
                    runner=runner,
                    case_id=spec.case_id,
                    patch_diff_hash=proposal.diff_hash,
                    workspace_host_path=patched_workspace,
                    mutants=(mutant,),
                    failing_test_ids=spec.failing_test_ids,
                    baseline_wall_seconds=baseline_result.wall_seconds,
                )
                if len(singleton) != 1 or type(singleton[0]) is not bool:
                    raise HarnessSetupError("Mutation wrapper returned invalid singleton verdict")
                singleton_verdicts.append(singleton[0])
            except HarnessTimeoutError:
                singleton_verdicts.append(True)
        verdicts = tuple(singleton_verdicts)
    killed = 0
    survived: list[SurvivedMutantDetail] = []
    for mutant, is_killed in zip(mutants, verdicts, strict=True):
        if is_killed:
            killed += 1
        else:
            survived.append(SurvivedMutantDetail(
                _mutant_id(mutant),
                mutant.file_path,
                mutant.function_name,
                mutant.mutation_description,
            ))
    total = len(mutants)
    return MutationAdequacySummary(
        low_mutation_adequacy=killed == 0,
        total_mutants_evaluated=total,
        mutants_killed=killed,
        mutants_survived=len(survived),
        mutation_score=killed / total,
        survived_mutant_details=tuple(survived),
    )

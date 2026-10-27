"""M6: argparse-based CLI entrypoint for AgentSentinel."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

from agentsentinel.cli.bundle_verifier import verify_exported_bundle
from agentsentinel.cli.exporter import export_evidence_bundle
from agentsentinel.domain.models import CaseSpec
from agentsentinel.evaluation.harness import BenchmarkHarness
from agentsentinel.evaluation.models import BenchmarkCase
from agentsentinel.llm.client import GeminiClient, LLMClient, OpenAICompatibleClient
from agentsentinel.orchestrator.checkpoint import CheckpointStore, RunState, TerminationReason
from agentsentinel.orchestrator.state_machine import RepairStateMachine
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner
from agentsentinel.verification.ci_gate import (
    render_ci_gate_json,
    render_ci_gate_markdown,
    run_ci_gate_audit,
    usage_error_report,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


def _load_case_spec(path: Path) -> CaseSpec:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return CaseSpec(
        case_id=str(raw["case_id"]),
        repo_url=str(raw["repo_url"]),
        base_commit=str(raw["base_commit"]),
        test_command=str(raw["test_command"]),
        allowed_edit_paths=tuple(raw["allowed_edit_paths"]),
        failing_test_ids=tuple(raw["failing_test_ids"]),
        created_at=datetime.now(UTC),
    )


class _MockLLM:
    """Trivial mock LLM that returns a placeholder proposal. Used only when
    ``--provider mock`` is selected (e.g. dry-runs and tests)."""

    def generate_patch(
        self, case_id: str, prompt: str, model_id: str
    ) -> tuple[Any, Any]:
        from agentsentinel.domain.models import PatchProposal
        from agentsentinel.llm.pricing import ModelUsage
        return (
            PatchProposal(
                case_id=case_id,
                unified_diff="--- a/fake\n+++ b/fake\n@@ -1 +1 @@\n-old\n+new\n",
                model_id="mock",
                prompt_tokens=1,
                completion_tokens=1,
            ),
            ModelUsage(model_id="mock", prompt_tokens=1, completion_tokens=1),
        )


class _FixtureLLM:
    """Fixture mock LLM that returns a valid fix patch if a reference.patch
    exists alongside the case_spec, or a given patch string."""

    def __init__(self, patch_diff: str) -> None:
        self.patch_diff = patch_diff

    def generate_patch(
        self, case_id: str, prompt: str, model_id: str
    ) -> tuple[Any, Any]:
        from agentsentinel.domain.models import PatchProposal
        from agentsentinel.llm.pricing import ModelUsage
        return (
            PatchProposal(
                case_id=case_id,
                unified_diff=self.patch_diff,
                model_id="fixture-llm",
                prompt_tokens=10,
                completion_tokens=10,
            ),
            ModelUsage(model_id="fixture-llm", prompt_tokens=10, completion_tokens=10),
        )


def _make_llm(provider: str, model_id: str | None, patch_diff: str = "") -> LLMClient:
    """Construct an LLM client. The concrete OpenAI/Gemini clients pick the
    model per call via generate_patch(model_id=...); here we just return a
    default-constructed client (API keys from env)."""
    if provider == "mock":
        return _MockLLM()
    if provider == "fixture":
        return _FixtureLLM(patch_diff)
    if provider == "openai":
        return OpenAICompatibleClient()
    if provider == "gemini":
        return GeminiClient()
    raise ValueError(f"Unknown provider: {provider!r}")


def _cmd_run(args: argparse.Namespace) -> int:
    spec = _load_case_spec(Path(args.case_spec))
    patch_diff = ""
    if args.patch:
        patch_diff = Path(args.patch).read_text(encoding="utf-8")
    elif (Path(args.case_spec).parent / "reference.patch").exists():
        patch_diff = (Path(args.case_spec).parent / "reference.patch").read_text(encoding="utf-8")
    llm = _make_llm(args.provider, args.model, patch_diff=patch_diff)
    db = Path(args.db)
    runner = HardenedContainerRunner(ContainerConfig(
        image=args.image or "agentsentinel-runner:py311",
        network_disabled=True,
        memory_limit="2g",
        cpus="1.0",
        timeout_seconds=args.timeout,
    ))
    raw = json.loads(Path(args.case_spec).read_text(encoding="utf-8"))
    source_value = raw.get("repo_source_path") or raw.get("local_repo_path")
    source_override = Path(str(source_value)) if source_value else None
    sm = RepairStateMachine(
        spec=spec,
        llm_client=llm,
        container_runner=runner,
        max_attempts=args.max_attempts,
        db_path=db,
        image_digest=args.image_digest or f"sha256:{args.image or 'local'}",
        source_workspace_override=source_override,
    )
    rid = sm.start_run()
    print(f"run_id={rid}")
    final = sm.run_to_terminal(rid)
    print(json.dumps({
        "run_id": rid,
        "state": final.state.value,
        "attempts_used": final.attempts_used,
        "termination_reason": final.termination_reason.value,
    }, indent=2))
    if final.state == RunState.AWAITING_HUMAN_APPROVAL:
        binding = final.approval_record or {}
        print("PENDING APPROVAL:")
        print(json.dumps(binding, indent=2, sort_keys=True))
        return 2
    return 0 if final.state == RunState.APPROVED else 1


def _cmd_status(args: argparse.Namespace) -> int:
    db = Path(args.db)
    with CheckpointStore(db) as s:
        rec = s.get_run(args.run_id)
        if rec is None:
            print(json.dumps({"error": "run_not_found", "run_id": args.run_id}))
            return 1
        out: dict[str, Any] = {
            "run_id": rec.run_id,
            "case_id": rec.case_id,
            "state": rec.state.value,
            "attempts_used": rec.attempts_used,
            "max_attempts": rec.max_attempts,
            "termination_reason": rec.termination_reason.value,
        }
        if rec.state == RunState.AWAITING_HUMAN_APPROVAL and rec.approval_record:
            out["pending_approval"] = rec.approval_record
        print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    db = Path(args.db)
    with CheckpointStore(db) as s:
        rec = s.get_run(args.run_id)
        if rec is None:
            print(json.dumps({"error": "run_not_found"}))
            return 1
    sm = RepairStateMachine(
        spec=CaseSpec(
            case_id=rec.case_id,
            repo_url="local://unused",
            base_commit="0" * 40,
            test_command="true",
            allowed_edit_paths=("__approval_only__.py",),
            failing_test_ids=("__approval_only__::test",),
        ),
        llm_client=_MockLLM(),
        container_runner=MagicMock(),
        max_attempts=1,
        db_path=db,
    )
    stored_post_hash = str((rec.approval_record or {}).get(
        "post_patch_result_hash", ""
    ))
    try:
        sm.approve_run(
            run_id=args.run_id,
            approver_id=args.approver_id,
            expected_diff_hash=args.diff_hash,
            expected_image_digest=args.image_digest,
            expected_post_patch_result_hash=(
                args.post_patch_result_hash or stored_post_hash
            ),
        )
    except Exception as exc:
        print(json.dumps({"error": "approval_failed", "detail": str(exc)}))
        return 3
    print(json.dumps({"approved": True, "run_id": args.run_id}))
    return 0


def _cmd_reject(args: argparse.Namespace) -> int:
    db = Path(args.db)
    with CheckpointStore(db) as s:
        rec = s.get_run(args.run_id)
        if rec is None:
            print(json.dumps({"error": "run_not_found"}))
            return 1
        if rec.state != RunState.AWAITING_HUMAN_APPROVAL:
            print(json.dumps({"error": "not_pending_approval", "state": rec.state.value}))
            return 1
        s.set_termination(args.run_id, RunState.REJECTED, TerminationReason.REJECTED_BY_REVIEWER)
        with s._conn:
            s._conn.execute(
                "UPDATE runs SET approval_record_json = json_set("
                "COALESCE(approval_record_json, '{}'), '$.rejected_by', ?, "
                "'$.reject_reason', ?, '$.rejected_at_utc', ?) "
                "WHERE run_id = ?",
                (args.reviewer_id, args.reason, datetime.now(UTC).isoformat(), args.run_id),
            )
    print(json.dumps({"rejected": True, "run_id": args.run_id, "reason": args.reason}))
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    from agentsentinel.domain.exceptions import UnapprovedExportError
    try:
        path = export_evidence_bundle(
            db_path=Path(args.db),
            run_id=args.run_id,
            output_dir=Path(args.output_dir),
        )
    except UnapprovedExportError as exc:
        print(json.dumps({"error": "unapproved", "detail": str(exc)}))
        return 4
    except KeyError as exc:
        print(json.dumps({"error": "run_not_found", "detail": str(exc)}))
        return 1
    except ValueError as exc:
        print(json.dumps({"error": "invalid_argument", "detail": str(exc)}))
        return 5
    print(json.dumps({"exported": True, "path": str(path)}))
    return 0


def _cmd_verify_bundle(args: argparse.Namespace) -> int:
    if bool(args.bundle_dir) == bool(args.bundle_dir_positional):
        print(json.dumps({
            "error": "invalid_argument",
            "detail": "Provide one bundle directory, positionally or with --bundle-dir",
        }))
        return 2
    report = verify_exported_bundle(
        Path(args.bundle_dir or args.bundle_dir_positional),
        require_keyed=args.require_keyed, signing_key=args.signing_key,
    )
    print(json.dumps(report.to_dict(), sort_keys=True))
    return report.exit_code


def _cmd_ci_gate(args: argparse.Namespace) -> int:
    """Audit a base checkout without invoking repair, sandbox or provider clients."""
    try:
        workspace = Path(args.workspace).resolve()
        diff_path = Path(args.diff).resolve()
        outputs = [Path(value) for value in (args.json_out, args.markdown_out) if value]
        resolved = [path.resolve() for path in outputs]
        if len(set(resolved)) != len(resolved):
            raise ValueError("JSON and Markdown outputs must be different files")
        for path, target in zip(outputs, resolved, strict=True):
            if (
                path.is_symlink() or target.is_relative_to(workspace) or target == diff_path
                or (path.exists() and path.stat().st_nlink > 1)
            ):
                raise ValueError(
                    "Report output must be outside the workspace and separate from input"
                )
        raw_diff = diff_path.read_bytes().decode("utf-8")
        report = run_ci_gate_audit(
            raw_diff, workspace, strict_warnings=args.strict_warnings,
            max_cc_delta=args.max_cc_delta,
        )
        if args.json_out:
            target = Path(args.json_out)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(render_ci_gate_json(report), encoding="utf-8", newline="\n")
        if args.markdown_out:
            target = Path(args.markdown_out)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(render_ci_gate_markdown(report), encoding="utf-8", newline="\n")
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        message = (
            str(exc) if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError)
            else "Diff input or report output is missing, unreadable or invalid"
        )
        report = usage_error_report(message)
    print(render_ci_gate_json(report))
    return report.exit_code


def _cmd_benchmark(args: argparse.Namespace) -> int:
    suite_dir = Path(args.suite_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases: list[BenchmarkCase] = []
    for case_dir in sorted(p for p in suite_dir.iterdir() if p.is_dir()):
        spec = _load_case_spec(case_dir / "spec.json")
        cases.append(BenchmarkCase(
            case_spec=spec,
            repo_source_path=case_dir / "src",
            base_commit=spec.base_commit,
            test_patch=(case_dir / "test.patch").read_text(encoding="utf-8"),
            reference_fix_patch=(case_dir / "reference.patch").read_text(encoding="utf-8"),
            fail_to_pass_tests=spec.failing_test_ids,
            pass_to_pass_tests=(),
            is_public_historical_commit=False,
        ))

    def _llm_factory() -> LLMClient:
        return _make_llm(args.provider, args.model)

    harness = BenchmarkHarness(
        llm_factory=_llm_factory,
        db_path=Path(args.db) if args.db else None,
        max_attempts=args.max_attempts,
    )
    report = harness.run_suite(cases, suite_name=suite_dir.name)
    report_path = out_dir / f"benchmark_{suite_dir.name}.json"
    report_path.write_text(report.to_json(), encoding="utf-8")
    (out_dir / f"benchmark_{suite_dir.name}.md").write_text(
        report.to_markdown(), encoding="utf-8"
    )
    print(json.dumps({
        "verified_repair_rate": report.verified_repair_rate,
        "admitted_cases": report.admitted_cases_count,
        "excluded_cases": report.excluded_cases_count,
        "report_json": str(report_path),
    }, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentsentinel", description="AgentSentinel CLI")
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="Start a bounded repair run")
    pr.add_argument("--case-spec", required=True)
    pr.add_argument("--db", required=True)
    pr.add_argument("--max-attempts", type=int, default=3)
    pr.add_argument("--provider", default="mock", choices=["mock", "fixture", "openai", "gemini"])
    pr.add_argument(
        "--patch",
        default=None,
        help="Explicit unified diff file to return (for deterministic runs)",
    )
    pr.add_argument("--model", default=None)
    pr.add_argument("--image", default=None)
    pr.add_argument("--image-digest", default=None)
    pr.add_argument("--timeout", type=int, default=300)
    pr.set_defaults(func=_cmd_run)

    ps = sub.add_parser("status", help="Inspect a run's state")
    ps.add_argument("--run-id", required=True)
    ps.add_argument("--db", required=True)
    ps.set_defaults(func=_cmd_status)

    pa = sub.add_parser("approve", help="Approve a pending run")
    pa.add_argument("--run-id", required=True)
    pa.add_argument("--approver-id", required=True)
    pa.add_argument("--diff-hash", required=True)
    pa.add_argument("--image-digest", required=True)
    pa.add_argument("--post-patch-result-hash", required=False, default=None)
    pa.add_argument("--db", required=True)
    pa.set_defaults(func=_cmd_approve)

    pj = sub.add_parser("reject", help="Reject a pending run")
    pj.add_argument("--run-id", required=True)
    pj.add_argument("--reviewer-id", required=True)
    pj.add_argument("--reason", required=True)
    pj.add_argument("--db", required=True)
    pj.set_defaults(func=_cmd_reject)

    pe = sub.add_parser("export", help="Export evidence bundle for APPROVED run")
    pe.add_argument("--run-id", required=True)
    pe.add_argument("--output-dir", required=True)
    pe.add_argument("--db", required=True)
    pe.set_defaults(func=_cmd_export)

    pv = sub.add_parser("verify-bundle", help="Verify an exported bundle offline")
    pv.add_argument("bundle_dir_positional", nargs="?", help="Exported bundle directory")
    pv.add_argument("--bundle-dir", default=None, help="Legacy bundle directory option")
    pv.add_argument("--require-keyed", action="store_true")
    pv.add_argument("--signing-key", default=None)
    pv.set_defaults(func=_cmd_verify_bundle)

    pc = sub.add_parser("ci-gate", help="Audit a pull-request diff offline without changing source")
    pc.add_argument("--workspace", required=True)
    pc.add_argument("--diff", required=True)
    pc.add_argument("--json-out", default=None)
    pc.add_argument("--markdown-out", default=None)
    pc.add_argument("--strict-warnings", action="store_true")
    pc.add_argument("--max-cc-delta", type=int, default=10)
    pc.set_defaults(func=_cmd_ci_gate)

    pb = sub.add_parser("benchmark", help="Run an M5 benchmark suite")
    pb.add_argument("--suite-dir", required=True)
    pb.add_argument("--output-dir", required=True)
    pb.add_argument("--db", required=False, default=None)
    pb.add_argument("--max-attempts", type=int, default=3)
    pb.add_argument("--provider", default="mock", choices=["mock", "openai", "gemini"])
    pb.add_argument("--model", default=None)
    pb.set_defaults(func=_cmd_benchmark)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = list(argv) if argv is not None else sys.argv[1:]
    try:
        args = parser.parse_args(arguments)
    except SystemExit as exc:
        if arguments and arguments[0] == "ci-gate" and exc.code == 2:
            print(render_ci_gate_json(usage_error_report("Invalid or missing ci-gate arguments")))
            return 2
        raise
    return int(args.func(args))


def cli_entrypoint() -> None:  # pragma: no cover
    sys.exit(main())


if __name__ == "__main__":
    cli_entrypoint()

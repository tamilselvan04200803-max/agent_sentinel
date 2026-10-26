"""M6: Deterministic evidence-bundle exporter for APPROVED runs."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from agentsentinel.domain.exceptions import UnapprovedExportError
from agentsentinel.llm.prompts import sanitize_diagnostic
from agentsentinel.orchestrator.checkpoint import (
    AttemptStatus,
    CheckpointStore,
    RunState,
)

if TYPE_CHECKING:
    from pathlib import Path

_UNSAFE_RUN_ID = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_run_id(run_id: str) -> str:
    """Reject path traversal/unsafe characters in CLI-supplied run_id."""
    if not run_id or _UNSAFE_RUN_ID.search(run_id) or run_id in (".", ".."):
        raise ValueError(f"Invalid run_id (contains unsafe characters): {run_id!r}")
    return run_id


def sanitize_output_dir(output_dir: Path) -> Path:
    """Resolve output_dir and reject traversal attempts beyond working tree."""
    resolved = output_dir.resolve()
    return resolved


def export_evidence_bundle(
    db_path: Path,
    run_id: str,
    output_dir: Path,
) -> Path:
    """Export an APPROVED run as a deterministic evidence bundle.

    Produces under ``<output_dir>/<run_id>/``:
      * ``evidence.json`` — canonical JSON (indent=2, sort_keys) with full
        metadata, attempts ledger, approval record, and ``bundle_hash``.
      * ``approved.patch`` — exact unified diff (LF newlines).
      * ``REPORT.md`` — human-readable Markdown summary.

    Raises :class:`UnapprovedExportError` if the run is not in APPROVED state.
    Returns the path to the created bundle directory.
    """
    run_id = sanitize_run_id(run_id)
    out_root = sanitize_output_dir(output_dir)
    bundle_dir = out_root / run_id

    with CheckpointStore(db_path) as store:
        rec = store.get_run(run_id)
        if rec is None:
            raise KeyError(f"run_id {run_id!r} not found")
        if rec.state != RunState.APPROVED:
            raise UnapprovedExportError(
                f"Cannot export run in state {rec.state.value}; only APPROVED runs"
            )
        attempts = store.get_attempts(run_id)
        passed = next(
            (a for a in reversed(attempts)
             if a.status == AttemptStatus.PASSED_PENDING_APPROVAL),
            None,
        )
        approved_diff = ""
        if passed is not None and passed.proposal_json is not None:
            proposal: dict[str, Any] = passed.proposal_json
            approved_diff = str(proposal.get("unified_diff", ""))
        approval: dict[str, Any] = rec.approval_record or {}
        attempts_list: list[dict[str, Any]] = []
        total_input_tokens = 0
        total_output_tokens = 0
        known_cost_total = 0.0
        unknown_cost_attempts = 0
        for a in attempts:
            usage: dict[str, Any] = a.usage_json or {}
            total_input_tokens += int(usage.get("prompt_tokens", 0))
            total_output_tokens += int(usage.get("completion_tokens", 0))
            if a.cost_usd is None:
                unknown_cost_attempts += 1
            else:
                known_cost_total += a.cost_usd
            attempts_list.append({
                "attempt_index": a.attempt_index,
                "status": a.status.value,
                "diff_hash": a.diff_hash,
                "ast_hash": a.ast_hash,
                "cost_usd": a.cost_usd,
                "error_type": a.error_type,
                "error_detail": a.error_detail,
                "usage": a.usage_json,
                "proposal": a.proposal_json,
                "execution_result": a.execution_result_json,
                "timestamp_utc": a.timestamp_utc,
            })
        post_patch_result = (
            passed.execution_result_json if passed is not None else None
        )
        accepted_patch = passed.proposal_json if passed is not None else None
        evidence_bundle: dict[str, Any] = {
            "case_id": rec.case_id,
            "spec": rec.spec_json,
            "baseline_result": rec.baseline_result_json,
            "accepted_patch": accepted_patch,
            "final_result": post_patch_result,
            "attempts": rec.attempts_used,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "known_cost_usd_total": (
                None if unknown_cost_attempts else known_cost_total
            ),
            "unknown_cost_attempts": unknown_cost_attempts,
        }
        for summary_key in ("minimization_summary", "mutation_adequacy_summary"):
            if summary_key in approval:
                evidence_bundle[summary_key] = approval[summary_key]
        evidence: dict[str, Any] = {
            "run_id": rec.run_id,
            "case_id": rec.case_id,
            "case_spec": rec.spec_json,
            "evidence_bundle": evidence_bundle,
            "state": rec.state.value,
            "attempts_used": rec.attempts_used,
            "max_attempts": rec.max_attempts,
            "termination_reason": rec.termination_reason.value,
            "baseline_result": rec.baseline_result_json,
            "post_patch_result": post_patch_result,
            "approval_record": approval,
            "attempts": attempts_list,
            "approved_diff": approved_diff,
            "created_at_utc": rec.created_at_utc,
            "approved_at_utc": approval.get("approved_at_utc"),
            "approver_id": approval.get("approver_id"),
        }
        # Deterministic JSON
        evidence_json = json.dumps(evidence, indent=2, sort_keys=True)
        bundle_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
        evidence["bundle_hash"] = bundle_hash
        evidence_json = json.dumps(evidence, indent=2, sort_keys=True)

    # Write files only after the APPROVED gate has passed.
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "evidence.json").write_text(evidence_json, encoding="utf-8", newline="\n")
    (bundle_dir / "approved.patch").write_text(approved_diff, encoding="utf-8", newline="\n")
    (bundle_dir / "REPORT.md").write_text(
        _render_report_md(evidence),
        encoding="utf-8",
        newline="\n",
    )
    return bundle_dir


def _render_report_md(ev: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# AgentSentinel Evidence Bundle — run `{ev['run_id']}`")
    lines.append("")
    lines.append(f"- Case: `{ev['case_id']}`")
    lines.append(f"- State: **{ev['state']}**")
    lines.append(f"- Attempts used: {ev['attempts_used']} / {ev['max_attempts']}")
    lines.append(f"- Termination reason: `{ev['termination_reason']}`")
    lines.append(f"- Bundle hash (SHA-256): `{ev.get('bundle_hash', '')}`")
    approval = ev.get("approval_record") or {}
    if approval:
        lines.append("")
        lines.append("## Approval")
        lines.append("")
        lines.append(f"- Approver: `{approval.get('approver_id')}`")
        lines.append(f"- Approved at (UTC): {approval.get('approved_at_utc')}")
        lines.append(f"- Diff hash: `{approval.get('diff_hash')}`")
        lines.append(f"- Image digest: `{approval.get('image_digest')}`")
        lines.append(f"- Post-patch result hash: `{approval.get('post_patch_result_hash')}`")
        lines.append(f"- Approval signature: `{approval.get('approval_hash')}`")
    minimization = approval.get("minimization_summary")
    mutation = approval.get("mutation_adequacy_summary")
    if minimization is not None:
        lines.extend(["", "## Post-pass Minimization", ""])
        lines.append(
            f"- Hunks: {minimization['raw_hunks_count']} -> "
            f"{minimization['minimized_hunks_count']} "
            f"({minimization['codeslop_hunks_removed']} removed)."
        )
        lines.append("- Single-pass subset search; global minimality is not guaranteed.")
    if mutation is not None:
        lines.extend(["", "## Mutation Adequacy", ""])
        lines.append(
            f"- Evaluated: {mutation['total_mutants_evaluated']}; "
            f"killed: {mutation['mutants_killed']}; survived: {mutation['mutants_survived']}; "
            f"score: {mutation['mutation_score']:.3f}."
        )
        if mutation["low_mutation_adequacy"]:
            lines.append("- **Low mutation adequacy: all evaluated mutants survived.**")
        for detail in mutation["survived_mutant_details"]:
            text = " | ".join(str(detail[key]) for key in (
                "mutant_id", "file_path", "function_name", "mutation_description",
            ))
            safe_text = sanitize_diagnostic(text, max_chars=1000).replace("\n", " ")
            lines.append(f"- Survivor: {safe_text}")
        lines.append(
            "- Equivalent mutants and weak test oracles limit interpretation of this score."
        )
    attempts = ev.get("attempts") or []
    if attempts:
        lines.append("")
        lines.append("## Attempt Ledger")
        lines.append("")
        lines.append("| # | Status | Cost (USD) | Error |")
        lines.append("|---|---|---|---|")
        for a in attempts:
            cost = a["cost_usd"] if a["cost_usd"] is not None else "unknown"
            err = (a.get("error_type") or "-").replace("|", "/")
            lines.append(f"| {a['attempt_index']} | {a['status']} | {cost} | {err} |")
    baseline = ev.get("baseline_result") or {}
    post = ev.get("post_patch_result") or {}
    spec = ev.get("case_spec") or {}
    if baseline or post:
        lines.append("")
        lines.append("## Failure and Verification")
        lines.append("")
        lines.append(
            f"- Baseline exit code: `{baseline.get('exit_code', 'unknown')}`"
        )
        lines.append(
            f"- Post-patch exit code: `{post.get('exit_code', 'unknown')}`"
        )
        if spec.get("failing_test_ids"):
            lines.append(
                "- Fail-to-pass tests: "
                + ", ".join(f"`{x}`" for x in spec["failing_test_ids"])
            )
        lines.append(
            "- Root-cause hypothesis: the approved diff below is the minimal "
            "reviewed change that transitions the baseline failure to a pass; "
            "see baseline/post-patch execution records in evidence.json."
        )
        if baseline.get("stderr") or baseline.get("stdout"):
            lines.append("")
            lines.append("Baseline output (tail):")
            lines.append("")
            lines.append("```text")
            lines.append(str(baseline.get("stderr") or baseline.get("stdout"))[-2000:])
            lines.append("```")
    bundle = ev.get("evidence_bundle") or {}
    lines.append("")
    lines.append("## Token and Cost Ledger")
    lines.append("")
    lines.append(f"- Total input tokens: {bundle.get('total_input_tokens', 0)}")
    lines.append(f"- Total output tokens: {bundle.get('total_output_tokens', 0)}")
    if bundle.get("known_cost_usd_total") is None:
        lines.append("- Known cost total: PARTIAL / UNKNOWN")
    else:
        lines.append(f"- Known cost total: ${bundle['known_cost_usd_total']:.4f} USD")
    diff_text = str(ev.get("approved_diff", ""))
    if diff_text:
        lines.append("")
        lines.append("## Approved Patch")
        lines.append("")
        lines.append("```diff")
        lines.append(diff_text.rstrip("\n"))
        lines.append("```")
    lines.append("")
    return "\n".join(lines)

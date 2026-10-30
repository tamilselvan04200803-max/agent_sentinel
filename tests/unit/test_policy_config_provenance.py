"""Canonical policy metadata persists with verified evidence, including after reopen."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from unittest import TestCase
from unittest.mock import patch

from agentsentinel.cli.bundle_verifier import verify_exported_bundle
from agentsentinel.cli.exporter import export_evidence_bundle
from agentsentinel.cli.provenance import attest_payload, canonicalize_jcs
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.state_machine import RepairStateMachine
from agentsentinel.sandbox.container import ContainerConfig, HardenedContainerRunner

PATCH = "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n def f(s):\n-    return s.lower()\n+    return s.strip().lower()\n"


def policy_hash(config):
    from agentsentinel.cli.provenance import compute_policy_config_hash

    return compute_policy_config_hash(config)


def write_bundle(root, **extra):
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": "run", "case_id": "case", "base_commit": "a" * 40,
        "status": "APPROVED", "diff_hash": hashlib.sha256(PATCH.encode()).hexdigest(),
        "canonical_diff_sha256": hashlib.sha256(PATCH.encode()).hexdigest(),
        "image_digest": "sha256:test", "baseline_result_hash": "b" * 64,
        "post_patch_result_hash": "c" * 64, "baseline_exit_code": 1,
        "post_patch_exit_code": 0, "minimization_summary": None,
        "mutation_adequacy_summary": None, "attempts_used": 1,
        "approved_by": "reviewer", "approved_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        **extra,
    }
    (root / "approved.patch").write_text(PATCH, encoding="utf-8", newline="\n")
    (root / "REPORT.md").write_text("# Evidence\n", encoding="utf-8", newline="\n")
    envelope = attest_payload(payload, signing_key="test-policy-key")
    (root / "evidence.json").write_text(canonicalize_jcs(envelope).decode("utf-8"), encoding="utf-8", newline="\n")
    return root


def make_machine(root, **options):
    source = root / "source"
    source.mkdir()
    (source / "f.py").write_text("def f(s):\n    return s.lower()\n", encoding="utf-8", newline="\n")
    spec = CaseSpec("case", "local", "a" * 40, "python -m pytest", ("f.py",), ("test_f.py::test_fix",))

    class LLM:
        def generate_patch(self, case_id, prompt, model_id):
            return PatchProposal(case_id, PATCH, "test", 1, 1), ModelUsage("test", 1, 1)

    class Runner:
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            return ExecutionResult(case_id, patch_diff_hash,
                                   ExitCode.TESTS_FAILED if patch_diff_hash == "baseline" else ExitCode.OK,
                                   "test_f.py::test_fix PASSED", "", 0.1)

    return RepairStateMachine(spec, LLM(), Runner(), image_digest="sha256:test", db_path=root / "run.db", source_workspace_override=source, **options)


def test_policy_hash_is_jcs_based_order_independent_and_settings_sensitive():
    config = {"z": [True, 3], "??": {"max_mutants": 7}, "a": "strict"}
    digest = policy_hash(config)
    assert digest == hashlib.sha256(canonicalize_jcs(config)).hexdigest()
    assert digest == policy_hash(dict(reversed(list(config.items()))))
    assert digest != policy_hash({**config, "a": "relaxed"})


def test_policy_metadata_is_persisted_exported_and_survives_reopen(tmp_path):
    machine = make_machine(tmp_path, max_mutants=7)
    try:
        record = machine.run_to_terminal(machine.start_run())
        binding = record.approval_record
        snapshot = binding["policy_config"]
        assert snapshot["max_mutants"] == 7
        assert snapshot["enforce_overfit_guard"] is True
        assert snapshot["allowed_edit_paths"] == ["f.py"]
        assert snapshot["sandbox"] is None  # External runner configuration is not invented.
        assert binding["policy_config_hash"] == policy_hash(snapshot)
        machine.approve_run(record.run_id, "reviewer", binding["diff_hash"], binding["image_digest"], binding["post_patch_result_hash"])
        run_id = record.run_id
    finally:
        machine._store.close()
    # New instances/default settings must never replace the accepted snapshot.
    bundle = export_evidence_bundle(tmp_path / "run.db", run_id, tmp_path / "exports", signing_key="test-policy-key")
    evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["policy_config"] == snapshot
    assert evidence["policy_config_hash"] == binding["policy_config_hash"]
    assert verify_exported_bundle(bundle, signing_key="test-policy-key").exit_code == 0


def test_policy_schema_rejects_incomplete_or_bad_metadata(tmp_path):
    cases = [
        {"policy_config_hash": "0" * 64}, {"policy_config": {}},
        {"policy_config": [], "policy_config_hash": "0" * 64},
        {"policy_config": {}, "policy_config_hash": "not-a-digest"},
    ]
    for index, values in enumerate(cases):
        bundle = write_bundle(tmp_path / str(index), **values)
        report = verify_exported_bundle(bundle, signing_key="test-policy-key")
        assert report.exit_code == 10, values


def test_policy_hash_mismatch_fails_gate_three_even_with_valid_outer_attestation(tmp_path):
    bundle = write_bundle(tmp_path / "bundle", policy_config={"max_mutants": 7}, policy_config_hash="0" * 64)
    report = verify_exported_bundle(bundle, signing_key="test-policy-key")
    assert report.exit_code == 30
    assert report.failure_reason == "ERR_G3_POLICY_CONFIG_MISMATCH"


def test_old_bundle_without_policy_metadata_remains_supported(tmp_path):
    bundle = write_bundle(tmp_path / "legacy")
    assert verify_exported_bundle(bundle, signing_key="test-policy-key").exit_code == 0
    evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
    assert "policy_config_hash" not in evidence


def test_export_rejects_corrupted_persisted_policy_snapshot(tmp_path):
    machine = make_machine(tmp_path)
    try:
        record = machine.run_to_terminal(machine.start_run())
        binding = record.approval_record
        machine.approve_run(record.run_id, "reviewer", binding["diff_hash"], binding["image_digest"], binding["post_patch_result_hash"])
        binding = machine._store.get_run(record.run_id).approval_record
        binding["policy_config"] = {"changed": True}
        machine._store.set_approval_record(record.run_id, approval_record=binding)
        with TestCase().assertRaises(ValueError):
            export_evidence_bundle(tmp_path / "run.db", record.run_id, tmp_path / "exports")
    finally:
        machine._store.close()


def test_snapshot_uses_actual_runner_settings_and_changed_controls(tmp_path):
    root = tmp_path / "actual"
    root.mkdir()
    machine = make_machine(root, max_mutants=9, enforce_overfit_guard=False)
    actual_runner = HardenedContainerRunner(ContainerConfig(cpus="0.5", memory_limit="256m"))

    def run(case_id, patch_diff_hash, workspace_host_path, command):
        return ExecutionResult(case_id, patch_diff_hash,
                               ExitCode.TESTS_FAILED if patch_diff_hash == "baseline" else ExitCode.OK,
                               "test_f.py::test_fix PASSED", "", 0.1)

    machine.container_runner = actual_runner
    try:
        with patch.object(actual_runner, "run_in_container", side_effect=run):
            record = machine.run_to_terminal(machine.start_run())
        snapshot = record.approval_record["policy_config"]
        assert snapshot["sandbox"]["cpus"] == "0.5"
        assert snapshot["sandbox"]["memory_limit"] == "256m"
        assert snapshot["sandbox"]["network_disabled"] is True
        assert snapshot["enforce_overfit_guard"] is False
        assert snapshot["max_mutants"] == 9
        assert policy_hash(snapshot) != policy_hash({**snapshot, "enforce_overfit_guard": True})
    finally:
        machine._store.close()

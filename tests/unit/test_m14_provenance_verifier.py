"""M14 standards vectors, strict parsing, attestation, and export round trips."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import struct
from typing import TYPE_CHECKING

import pytest

from agentsentinel.cli.bundle_verifier import verify_exported_bundle
from agentsentinel.cli.exporter import export_evidence_bundle
from agentsentinel.cli.main import main
from agentsentinel.cli.provenance import (
    DOMAIN_APPROVAL_V1,
    DOMAIN_EVIDENCE_BUNDLE_V1,
    ENVELOPE_EXCLUDED_KEYS,
    ProvenanceSchemaError,
    attest_payload,
    canonicalize_jcs,
    compute_dsse_pae,
    compute_key_id,
    loads_strict_jcs,
    resolve_signing_key,
    resolve_trusted_key,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("bits", "expected"),
    [
        ("0000000000000000", "0"), ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"), ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"), ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ],
)
def test_rfc8785_appendix_b_numbers(bits: str, expected: str) -> None:
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert canonicalize_jcs(value) == expected.encode("ascii")


def test_utf16_sorting_is_recursive_and_does_not_normalize_unicode() -> None:
    obj = {"\ue000": 1, "😀": [{"z": 2, "a": "é"}], "a": "e\u0301"}
    assert canonicalize_jcs(obj) == '{"a":"é","😀":[{"a":"é","z":2}],"":1}'.encode()


def test_jcs_string_escaping_and_literals() -> None:
    assert canonicalize_jcs({"x": [None, True, False, "\x00\b\t\n\f\r\"\\/", -0.0]}) == (
        b'{"x":[null,true,false,"\\u0000\\b\\t\\n\\f\\r\\"\\\\/",0]}'
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 2**53, -(2**53), {1: "x"}, {"x": "\ud800"}, object()])
def test_canonicalizer_rejects_non_i_json_values(value: object) -> None:
    with pytest.raises(ProvenanceSchemaError):
        canonicalize_jcs(value)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"a":{"x":1,"x":2}}', b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}', b'{"n":1e999}', b'{"n":9007199254740992}', b'{"n":-9007199254740992}', b'[]', b'null', b'{"x":"\\ud800"}', b'\xef\xbb\xbf{}', b'\xff', b'{'])
def test_strict_parser_rejects_invalid_or_ambiguous_json(raw: bytes) -> None:
    with pytest.raises(ProvenanceSchemaError):
        loads_strict_jcs(raw)


def test_strict_parser_normalizes_negative_zero_and_accepts_safe_integers() -> None:
    result = loads_strict_jcs(b'{"n":-0.0,"i":9007199254740991,"flag":true}')
    assert result == {"n": 0.0, "i": 2**53 - 1, "flag": True}
    assert math.copysign(1.0, result["n"]) == 1.0


def test_depth_boundary_and_predecode_depth_bomb() -> None:
    valid = b'{"x":' + b'[' * 127 + b'0' + b']' * 127 + b'}'
    assert loads_strict_jcs(valid)
    with pytest.raises(ProvenanceSchemaError):
        loads_strict_jcs(b'{"x":' + b'[' * 128 + b'0' + b']' * 128 + b'}')
    with pytest.raises(ProvenanceSchemaError):
        loads_strict_jcs(b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}')
    assert loads_strict_jcs(b'{"x":"[\\\"{]"}', max_depth=1) == {"x": '["{]'}


def test_cyclic_input_has_bounded_failure() -> None:
    value: dict[str, object] = {}
    value["self"] = value
    with pytest.raises(ProvenanceSchemaError):
        canonicalize_jcs(value)


def test_dsse_reference_vector_and_utf8_byte_lengths() -> None:
    assert compute_dsse_pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )
    assert compute_dsse_pae("é", "😀".encode()) == b"DSSEv1 2 \xc3\xa9 4 \xf0\x9f\x98\x80"
    assert compute_dsse_pae("a", b"bc") != compute_dsse_pae("ab", b"c")
    assert compute_dsse_pae(DOMAIN_APPROVAL_V1, b"x") != compute_dsse_pae(DOMAIN_EVIDENCE_BUNDLE_V1, b"x")


def test_key_fingerprint_and_resolution_precedence(monkeypatch) -> None:
    monkeypatch.setenv("AGENTSENTINEL_SIGNING_KEY", "environment-secret")
    assert resolve_signing_key("explicit-secret") == b"explicit-secret"
    assert resolve_signing_key(None) == b"environment-secret"
    assert compute_key_id(b"abc") == "ba7816bf8f01cfea"
    assert compute_key_id("é") == hashlib.sha256("é".encode()).hexdigest()[:16]
    with pytest.raises(ProvenanceSchemaError):
        resolve_signing_key("")


def test_rotated_key_resolution_checks_fingerprints(monkeypatch) -> None:
    old_id = compute_key_id("old-secret")
    monkeypatch.setenv("AGENTSENTINEL_SIGNING_KEY", "new-secret")
    monkeypatch.setenv("AGENTSENTINEL_TRUSTED_KEYS", json.dumps({old_id: "old-secret"}))
    assert resolve_trusted_key(old_id) == b"old-secret"
    assert resolve_trusted_key(old_id, trusted_keys={old_id: "wrong-secret"}) is None
    assert resolve_trusted_key("0" * 16, trusted_keys={}) is None


@pytest.mark.parametrize("key", [None, "test-signing-secret", b"test-signing-secret"])
def test_attestation_binds_mode_key_and_only_excludes_envelope_fields(monkeypatch, key) -> None:
    monkeypatch.delenv("AGENTSENTINEL_SIGNING_KEY", raising=False)
    envelope = attest_payload({"case_id": "case", "approval_record": {"approval_hash": "legacy"}}, signing_key=key)
    assert frozenset({"bundle_hash", "approval_hash", "hmac_signature"}) == ENVELOPE_EXCLUDED_KEYS
    payload = {name: value for name, value in envelope.items() if name not in ENVELOPE_EXCLUDED_KEYS}
    canonical = canonicalize_jcs(payload)
    pae = compute_dsse_pae(DOMAIN_EVIDENCE_BUNDLE_V1, canonical)
    assert envelope["bundle_hash"] == hashlib.sha256(canonical).hexdigest()
    assert envelope["approval_hash"] == hashlib.sha256(pae).hexdigest()
    if key is None:
        assert envelope["attestation_mode"] == "sha256-unkeyed-v1"
        assert envelope["key_id"] is envelope["hmac_signature"] is None
    else:
        secret = key.encode() if isinstance(key, str) else key
        assert envelope["attestation_mode"] == "hmac-sha256-v1"
        assert envelope["key_id"] == compute_key_id(secret)
        assert envelope["hmac_signature"] == hmac.new(secret, pae, hashlib.sha256).hexdigest()


def make_bundle(tmp_path: Path, key: str | None = None, **changes: object) -> Path:
    """Signed fixture consumed by verifier/adversarial tests; never executes a patch."""
    from datetime import UTC, datetime

    patch = b"--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-old\n+new\n"
    payload: dict[str, object] = {
        "run_id": "run", "case_id": "case", "base_commit": "a" * 40,
        "status": "APPROVED", "diff_hash": hashlib.sha256(patch).hexdigest(),
        "canonical_diff_sha256": hashlib.sha256(patch).hexdigest(),
        "image_digest": "sha256:image", "baseline_result_hash": "b" * 64,
        "post_patch_result_hash": "c" * 64, "baseline_exit_code": 1,
        "post_patch_exit_code": 0, "minimization_summary": None,
        "mutation_adequacy_summary": None, "attempts_used": 1,
        "approved_by": "alice", "approved_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    payload.update(changes)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "approved.patch").write_bytes(patch)
    (tmp_path / "REPORT.md").write_text("# Evidence\n", encoding="utf-8", newline="\n")
    (tmp_path / "evidence.json").write_bytes(canonicalize_jcs(attest_payload(payload, signing_key=key)))
    return tmp_path


@pytest.fixture(autouse=True)
def clear_signing_environment(monkeypatch) -> None:
    for name in ("AGENTSENTINEL_SIGNING_KEY", "AGENTSENTINEL_TRUSTED_KEYS", "AGENTSENTINEL_REQUIRE_KEYED"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("key", [None, "test-secret"])
def test_verifier_round_trip_and_telemetry(tmp_path: Path, key: str | None) -> None:
    from dataclasses import FrozenInstanceError

    report = verify_exported_bundle(make_bundle(tmp_path / "bundle", key), signing_key=key)
    assert report.exit_code == 0
    assert report.overall_verdict == "PASSED"
    assert report.gates_evaluated == (1, 2, 3, 4, 5)
    assert report.failure_reason is None
    assert report.warnings == ()
    assert report.key_id == (compute_key_id(key) if key else None)
    assert report.to_dict()["verification_mode"] == ("hmac-sha256-v1" if key else "sha256-unkeyed-v1")
    with pytest.raises(FrozenInstanceError):
        report.exit_code = 10


@pytest.mark.parametrize("age", ["2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"])
def test_timestamp_skew_is_a_warning(tmp_path: Path, age: str) -> None:
    report = verify_exported_bundle(make_bundle(tmp_path / "bundle", approved_at_utc=age))
    assert report.exit_code == 0
    assert report.overall_verdict == "PASSED"
    assert report.warnings == ("WARN_G5_TIMESTAMP_SKEW",)


@pytest.mark.parametrize("field", ["run_id", "diff_hash", "approved_by", "bundle_hash", "hmac_signature"])
def test_missing_required_field_is_gate1(tmp_path: Path, field: str) -> None:
    bundle = make_bundle(tmp_path / "bundle")
    evidence = loads_strict_jcs((bundle / "evidence.json").read_bytes())
    evidence.pop(field)
    (bundle / "evidence.json").write_bytes(canonicalize_jcs(evidence))
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_INVALID_SCHEMA")
    assert report.gates_evaluated == (1,)


@pytest.mark.parametrize("field,value", [("baseline_exit_code", True), ("post_patch_exit_code", False), ("attempts_used", True), ("approved_at_utc", "2026-10-27"), ("minimization_summary", []), ("key_id", 5)])
def test_required_schema_types_are_strict(tmp_path: Path, field: str, value: object) -> None:
    bundle = make_bundle(tmp_path / "bundle", **{field: value})
    if field == "key_id":
        evidence = loads_strict_jcs((bundle / "evidence.json").read_bytes())
        evidence[field] = value
        (bundle / "evidence.json").write_bytes(canonicalize_jcs(evidence))
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_INVALID_SCHEMA")


def test_environment_signing_key_enforces_keyed_verification(tmp_path: Path, monkeypatch) -> None:
    bundle = make_bundle(tmp_path / "bundle")
    monkeypatch.setenv("AGENTSENTINEL_SIGNING_KEY", "configured-key")
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_UNKEYED_DISALLOWED")


@pytest.mark.parametrize("limit", [-1.0, float("nan"), float("inf")])
def test_invalid_clock_policy_is_rejected(tmp_path: Path, limit: float) -> None:
    with pytest.raises(ValueError):
        verify_exported_bundle(tmp_path, max_clock_skew_seconds=limit)


def make_approved_db(tmp_path: Path, diff: str | None = None) -> tuple[Path, str]:
    from datetime import UTC, datetime

    from agentsentinel.orchestrator.checkpoint import CheckpointStore

    if diff is None:
        diff = "--- a/m.py\r\n+++ b/m.py\r\n@@ -1 +1 @@\r\n-old\r\n+new\r\n"
    db = tmp_path / "run.db"
    with CheckpointStore(db) as store:
        run_id = store.create_run("case", 3, spec_json={"case_id": "case", "base_commit": "a" * 40, "allowed_edit_paths": ["m.py"], "failing_test_ids": ["test_m.py::test_fix"]})
        store.increment_attempts(run_id)
        baseline = {"exit_code": 1, "stdout": "FAILED", "stderr": "", "wall_seconds": 0.1}
        result = {"exit_code": 0, "stdout": "PASSED", "stderr": "", "wall_seconds": 0.2}
        store.set_baseline_result(run_id, baseline)
        store.record_attempt_start(run_id, 1)
        proposal = {"unified_diff": diff, "model_id": "test", "prompt_tokens": 2, "completion_tokens": 3}
        digest = hashlib.sha256(diff.encode()).hexdigest()
        store.record_attempt_generated(run_id, 1, proposal, {"prompt_tokens": 2, "completion_tokens": 3}, 0.01, digest)
        approval = {"diff_hash": digest, "image_digest": "sha256:image", "post_patch_result_hash": "c" * 64, "approval_hash": "d" * 64, "approver_id": "alice", "approved_at_utc": datetime.now(UTC).isoformat()}
        store.record_verified_patch(run_id, 1, proposal_json=proposal, execution_result_json=result, diff_hash=digest, ast_hash=None, approval_record=approval)
        store.set_approval_record(run_id, approval)
    return db, run_id


@pytest.mark.parametrize("key", [None, "export-secret"])
def test_real_checkpoint_export_has_canonical_attestation_and_legacy_fields(tmp_path: Path, key: str | None) -> None:
    db, run_id = make_approved_db(tmp_path)
    bundle = export_evidence_bundle(db, run_id, tmp_path / "out", signing_key=key)
    patch = (bundle / "approved.patch").read_bytes()
    raw = (bundle / "evidence.json").read_bytes()
    evidence = loads_strict_jcs(raw)
    assert patch == b"--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-old\n+new\n"
    assert raw == canonicalize_jcs(evidence)
    assert evidence["diff_hash"] == hashlib.sha256(patch).hexdigest()
    assert evidence["canonical_diff_sha256"] == hashlib.sha256(patch.replace(b"\r\n", b"\n")).hexdigest()
    assert evidence["status"] == evidence["state"] == "APPROVED"
    assert evidence["base_commit"] == "a" * 40
    assert evidence["approved_by"] == evidence["approver_id"] == "alice"
    assert str(evidence["approved_at_utc"]).endswith("Z")
    assert evidence["baseline_exit_code"] == 1
    assert evidence["post_patch_exit_code"] == 0
    assert evidence["baseline_result_hash"] == hashlib.sha256(canonicalize_jcs(evidence["baseline_result"])).hexdigest()
    assert evidence["post_patch_result_hash"] == hashlib.sha256(canonicalize_jcs(evidence["post_patch_result"])).hexdigest()
    assert evidence["approval_record"]["approval_hash"] == "d" * 64
    assert evidence["evidence_bundle"]["accepted_patch"]["model_id"] == "test"
    assert evidence["minimization_summary"] is evidence["mutation_adequacy_summary"] is None
    assert verify_exported_bundle(bundle, signing_key=key).exit_code == 0
    assert "Attestation" in (bundle / "REPORT.md").read_text(encoding="utf-8")
    export_evidence_bundle(db, run_id, tmp_path / "out", signing_key=key)
    assert (bundle / "evidence.json").read_bytes() == raw
    assert key is None or key.encode() not in raw


def test_environment_key_signs_export(tmp_path: Path, monkeypatch) -> None:
    db, run_id = make_approved_db(tmp_path)
    monkeypatch.setenv("AGENTSENTINEL_SIGNING_KEY", "environment-key")
    bundle = export_evidence_bundle(db, run_id, tmp_path / "out")
    evidence = loads_strict_jcs((bundle / "evidence.json").read_bytes())
    assert evidence["attestation_mode"] == "hmac-sha256-v1"
    assert evidence["key_id"] == compute_key_id("environment-key")
    assert verify_exported_bundle(bundle).exit_code == 0


@pytest.mark.parametrize("code", [0, 10, 20, 30, 40, 50])
def test_cli_verifier_json_and_exact_gate_exit_codes(tmp_path: Path, capsys, code: int) -> None:
    changes = {"status": "REJECTED"} if code == 50 else {}
    bundle = make_bundle(tmp_path, **changes)
    args = ["verify-bundle", "--bundle-dir", str(bundle)]
    if code == 10:
        (bundle / "REPORT.md").unlink()
    elif code == 20:
        (bundle / "approved.patch").write_bytes(b"changed")
    elif code == 30:
        with (bundle / "evidence.json").open("ab") as stream:
            stream.write(b"\n")
    elif code == 40:
        args.append("--require-keyed")
    assert main(args) == code
    telemetry = json.loads(capsys.readouterr().out)
    assert telemetry["overall_verdict"] == ("PASSED" if code == 0 else "FAILED")
    assert telemetry["gates_evaluated"] == list(range(1, (code // 10 if code else 5) + 1))
    assert {"timestamp_utc", "bundle_path", "verification_mode", "key_id", "warnings", "failure_reason"} <= telemetry.keys()


def test_cli_explicit_signing_key_is_not_rendered(tmp_path: Path, capsys) -> None:
    bundle = make_bundle(tmp_path, "cli-secret")
    assert main(["verify-bundle", "--bundle-dir", str(bundle), "--require-keyed", "--signing-key", "cli-secret"]) == 0
    assert "cli-secret" not in capsys.readouterr().out


def test_legacy_approval_comparison_is_constant_time(tmp_path: Path, monkeypatch) -> None:
    from agentsentinel.cli import main as cli_module
    from agentsentinel.orchestrator.checkpoint import CheckpointStore, RunState
    from agentsentinel.orchestrator.state_machine import _sha256

    db, run_id = make_approved_db(tmp_path)
    binding = {"diff_hash": "a" * 64, "image_digest": "image", "post_patch_result_hash": "b" * 64}
    expected = _sha256(*binding.values())
    with CheckpointStore(db) as store:
        store.set_approval_record(run_id, {**binding, "approval_hash": expected})
        store.transition_state(run_id, RunState.AWAITING_HUMAN_APPROVAL)
    comparisons: list[tuple[object, object]] = []
    original = hmac.compare_digest

    def compare(left, right):
        comparisons.append((left, right))
        return original(left, right)

    monkeypatch.setattr(hmac, "compare_digest", compare)
    args = ["approve", "--run-id", run_id, "--db", str(db), "--approver-id", "alice", "--diff-hash", binding["diff_hash"], "--image-digest", binding["image_digest"], "--post-patch-result-hash", binding["post_patch_result_hash"]]
    assert cli_module.main(args) == 0
    assert comparisons

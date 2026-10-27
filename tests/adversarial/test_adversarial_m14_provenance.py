"""M14: attack all five offline verification gates without executing source."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from agentsentinel.cli.bundle_verifier import verify_exported_bundle
from agentsentinel.cli.provenance import (
    DOMAIN_APPROVAL_V1,
    DOMAIN_EVIDENCE_BUNDLE_V1,
    ENVELOPE_EXCLUDED_KEYS,
    attest_payload,
    canonicalize_jcs,
    compute_dsse_pae,
    compute_key_id,
    loads_strict_jcs,
)
from tests.unit.test_m14_provenance_verifier import make_bundle

pytestmark = [pytest.mark.unit, pytest.mark.adversarial]


@pytest.fixture(autouse=True)
def clear_keys(monkeypatch) -> None:
    for name in ("AGENTSENTINEL_SIGNING_KEY", "AGENTSENTINEL_TRUSTED_KEYS", "AGENTSENTINEL_REQUIRE_KEYED"):
        monkeypatch.delenv(name, raising=False)


def _read(bundle: Path) -> dict[str, object]:
    return loads_strict_jcs((bundle / "evidence.json").read_bytes())


def _write(bundle: Path, evidence: dict[str, object]) -> None:
    (bundle / "evidence.json").write_bytes(canonicalize_jcs(evidence))


def test_attack01_field_boundary_shifting_changes_structured_binding(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    evidence = _read(bundle)
    evidence["image_digest"] = "sha256:image" + str(evidence["post_patch_result_hash"])[:1]
    evidence["post_patch_result_hash"] = str(evidence["post_patch_result_hash"])[1:]
    _write(bundle, evidence)
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (30, "ERR_G3_CANONICAL_BINDING_FAILED")


def test_attack02_single_patch_byte_change_fails_gate2(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    patch = bundle / "approved.patch"
    patch.write_bytes(patch.read_bytes().replace(b"+new", b"+NEW"))
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (20, "ERR_G2_PATCH_MISMATCH")
    assert report.gates_evaluated == (1, 2)


def test_gate2_canonical_patch_hash_is_separately_checked(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    evidence = _read(bundle)
    evidence["canonical_diff_sha256"] = "0" * 64
    _write(bundle, evidence)
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (20, "ERR_G2_CANONICAL_PATCH_MISMATCH")


def test_attack03_resigned_unkeyed_downgrade_is_disallowed(tmp_path: Path, monkeypatch) -> None:
    bundle = make_bundle(tmp_path, "signing-key")
    downgraded = attest_payload(_read(bundle))
    _write(bundle, downgraded)
    for policy in (True, False):
        if not policy:
            monkeypatch.setenv("AGENTSENTINEL_REQUIRE_KEYED", "1")
        report = verify_exported_bundle(bundle, require_keyed=policy)
        assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_UNKEYED_DISALLOWED")


def test_attack04_key_rotation_and_unknown_fingerprint(tmp_path: Path, monkeypatch) -> None:
    bundle = make_bundle(tmp_path, "old-key")
    report = verify_exported_bundle(bundle, signing_key="new-key")
    assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_KEY_NOT_FOUND")
    old_id = compute_key_id("old-key")
    assert verify_exported_bundle(bundle, signing_key="new-key", trusted_keys={old_id: "old-key"}).exit_code == 0
    monkeypatch.setenv("AGENTSENTINEL_TRUSTED_KEYS", json.dumps({old_id: "old-key"}))
    assert verify_exported_bundle(bundle, signing_key="new-key").exit_code == 0
    assert verify_exported_bundle(bundle, trusted_keys={old_id: "wrong-key"}).failure_reason == "ERR_G4_KEY_NOT_FOUND"


def test_attack05_unresigned_execution_change_fails_gate3(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    evidence = _read(bundle)
    evidence["post_patch_exit_code"] = 1
    _write(bundle, evidence)
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (30, "ERR_G3_CANONICAL_BINDING_FAILED")


@pytest.mark.parametrize("changes,reason", [({"baseline_exit_code": 0}, "ERR_G5_INVALID_BASELINE"), ({"post_patch_exit_code": 1}, "ERR_G5_POST_PATCH_FAILURE"), ({"status": "REJECTED"}, "ERR_G5_STATUS_NOT_APPROVED")])
def test_attack05_valid_attestation_cannot_bypass_execution_invariants(tmp_path: Path, changes: dict[str, object], reason: str) -> None:
    bundle = make_bundle(tmp_path, "key", **changes)
    report = verify_exported_bundle(bundle, signing_key="key")
    assert (report.exit_code, report.failure_reason) == (50, reason)
    assert report.gates_evaluated == (1, 2, 3, 4, 5)


@pytest.mark.parametrize("name", ["evidence.json", "REPORT.md", "approved.patch"])
def test_attack06_missing_file(tmp_path: Path, name: str) -> None:
    bundle = make_bundle(tmp_path)
    (bundle / name).unlink()
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_MISSING_FILE")


def test_attack06_symlinked_patch_is_rejected_before_read(tmp_path: Path, monkeypatch) -> None:
    bundle = make_bundle(tmp_path)
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == "approved.patch" or original(path))
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_PATH_TRAVERSAL")


@pytest.mark.parametrize("path", ["../outside.py", "a/../../secret", "..\\outside.py", "/etc/passwd", "C:\\secret.py"])
def test_attack06_nested_path_fields_are_contained(tmp_path: Path, path: str) -> None:
    bundle = make_bundle(tmp_path, mutation_adequacy_summary={"survived_mutant_details": [{"file_path": path}]})
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_PATH_TRAVERSAL")


def test_attack06_bundle_directory_traversal_is_rejected(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path / "bundle")
    report = verify_exported_bundle(bundle / ".." / "bundle")
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_PATH_TRAVERSAL")


def test_attack07_digest_comparisons_use_constant_time_primitive(tmp_path: Path, monkeypatch) -> None:
    bundle = make_bundle(tmp_path, "key")
    original = hmac.compare_digest
    calls: list[tuple[object, object]] = []

    def compare(left, right):
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(hmac, "compare_digest", compare)
    assert verify_exported_bundle(bundle, signing_key="key").exit_code == 0
    assert len(calls) >= 7  # raw, canonical, formatting, bundle, PAE, key routing, HMAC
    assert len({bytes(left) for left, _ in calls}) >= 5


def test_attack08_approval_domain_attestation_cannot_be_replayed(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path, "key")
    evidence = _read(bundle)
    payload = {name: value for name, value in evidence.items() if name not in ENVELOPE_EXCLUDED_KEYS}
    wrong_pae = compute_dsse_pae(DOMAIN_APPROVAL_V1, canonicalize_jcs(payload))
    evidence["approval_hash"] = hashlib.sha256(wrong_pae).hexdigest()
    evidence["hmac_signature"] = hmac.new(b"key", wrong_pae, hashlib.sha256).hexdigest()
    _write(bundle, evidence)
    report = verify_exported_bundle(bundle, signing_key="key")
    assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_ATTESTATION_FAILED")


@pytest.mark.parametrize("raw", [b'{"run_id":"a","run_id":"b"}', b'{"n":9007199254740992}', b'{"n":NaN}', b'{"x":' + b'[' * 128 + b'0' + b']' * 128 + b'}'])
def test_attack09_invalid_i_json_is_gate1(tmp_path: Path, raw: bytes) -> None:
    bundle = make_bundle(tmp_path)
    (bundle / "evidence.json").write_bytes(raw)
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_INVALID_SCHEMA")


@pytest.mark.parametrize("formatting", ["pretty", "newline", "crlf", "reordered"])
def test_attack10_noncanonical_disk_json_fails_gate3(tmp_path: Path, formatting: str) -> None:
    bundle = make_bundle(tmp_path)
    evidence = _read(bundle)
    if formatting == "pretty":
        raw = json.dumps(evidence, indent=2).encode()
    elif formatting == "reordered":
        raw = json.dumps(dict(reversed(list(evidence.items()))), separators=(",", ":")).encode()
    else:
        raw = (bundle / "evidence.json").read_bytes() + (b"\r\n" if formatting == "crlf" else b"\n")
    (bundle / "evidence.json").write_bytes(raw)
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (30, "ERR_G3_CANONICAL_BINDING_FAILED")


def test_recomputed_public_hashes_cannot_hide_bad_hmac(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path, "key")
    evidence = _read(bundle)
    evidence["approved_by"] = "attacker"
    payload = {name: value for name, value in evidence.items() if name not in ENVELOPE_EXCLUDED_KEYS}
    canonical = canonicalize_jcs(payload)
    evidence["bundle_hash"] = hashlib.sha256(canonical).hexdigest()
    evidence["approval_hash"] = hashlib.sha256(compute_dsse_pae(DOMAIN_EVIDENCE_BUNDLE_V1, canonical)).hexdigest()
    _write(bundle, evidence)
    assert verify_exported_bundle(bundle, signing_key="key").failure_reason == "ERR_G4_ATTESTATION_FAILED"


def test_gate_precedence_stops_before_later_tampering(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path, status="REJECTED")
    (bundle / "approved.patch").write_bytes(b"tampered")
    report = verify_exported_bundle(bundle, require_keyed=True)
    assert report.exit_code == 20
    assert report.gates_evaluated == (1, 2)


def test_windows_reparse_point_directory_is_not_traversed(tmp_path: Path, monkeypatch) -> None:
    from types import SimpleNamespace

    bundle = make_bundle(tmp_path)
    (bundle / "junction").mkdir()
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: SimpleNamespace(st_file_attributes=0x400, st_mode=original(path).st_mode) if path.name == "junction" else original(path))
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_PATH_TRAVERSAL")


def test_malformed_trusted_fingerprint_returns_structured_gate4_failure(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path, "old-key")
    report = verify_exported_bundle(bundle, trusted_keys={"\ud800": "old-key"})
    assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_KEY_NOT_FOUND")


def test_malformed_environment_keyring_returns_structured_gate4_failure(tmp_path: Path, monkeypatch) -> None:
    import agentsentinel.cli.provenance as provenance

    bundle = make_bundle(tmp_path, "old-key")
    monkeypatch.setattr(provenance.os, "environ", {"AGENTSENTINEL_TRUSTED_KEYS": '{"x":"\ud800"}'})
    report = verify_exported_bundle(bundle)
    assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_KEY_NOT_FOUND")

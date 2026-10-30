"""A caller's trusted policy digest is enforced after existing provenance gates."""

from __future__ import annotations

import json
from typing import cast

import pytest

from agentsentinel.cli.bundle_verifier import verify_exported_bundle
from agentsentinel.cli.main import main
from agentsentinel.cli.provenance import compute_policy_config_hash
from tests.unit.test_m14_provenance_verifier import make_bundle

pytestmark = pytest.mark.unit

POLICY = {"enforce_overfit_guard": True, "max_mutants": 7}


@pytest.fixture(autouse=True)
def clear_keys(monkeypatch) -> None:
    for name in ("AGENTSENTINEL_SIGNING_KEY", "AGENTSENTINEL_TRUSTED_KEYS", "AGENTSENTINEL_REQUIRE_KEYED"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("key", [None, "m18-trusted-key"])
def test_expected_policy_matches_verified_snapshot(tmp_path, key) -> None:
    digest = compute_policy_config_hash(POLICY)
    bundle = make_bundle(tmp_path / "bundle", key, policy_config=POLICY, policy_config_hash=digest)
    report = verify_exported_bundle(bundle, signing_key=key, expected_policy_config_hash=digest)
    assert report.exit_code == 0
    assert report.gates_evaluated == (1, 2, 3, 4, 5)


def test_different_trusted_policy_expectation_fails_gate_five(tmp_path) -> None:
    digest = compute_policy_config_hash(POLICY)
    bundle = make_bundle(tmp_path / "bundle", policy_config=POLICY, policy_config_hash=digest)
    report = verify_exported_bundle(bundle, expected_policy_config_hash="0" * 64)
    assert (report.exit_code, report.failure_reason) == (50, "ERR_G5_POLICY_CONFIG_MISMATCH")
    assert report.gates_evaluated == (1, 2, 3, 4, 5)
    assert report.event == "EVENT_G5_FAILED"


def test_legacy_bundle_requires_snapshot_only_when_expectation_is_supplied(tmp_path) -> None:
    bundle = make_bundle(tmp_path / "legacy")
    assert verify_exported_bundle(bundle).exit_code == 0
    report = verify_exported_bundle(bundle, expected_policy_config_hash="0" * 64)
    assert (report.exit_code, report.failure_reason) == (50, "ERR_G5_POLICY_CONFIG_MISMATCH")


def test_gate_three_pair_mismatch_precedes_trusted_expectation(tmp_path) -> None:
    bundle = make_bundle(tmp_path / "bundle", policy_config=POLICY, policy_config_hash="0" * 64)
    report = verify_exported_bundle(bundle, expected_policy_config_hash="0" * 64)
    assert (report.exit_code, report.failure_reason) == (30, "ERR_G3_POLICY_CONFIG_MISMATCH")
    assert report.gates_evaluated == (1, 2, 3)


def test_incomplete_policy_pair_remains_gate_one_schema_failure(tmp_path) -> None:
    bundle = make_bundle(tmp_path / "bundle", policy_config_hash="0" * 64)
    report = verify_exported_bundle(bundle, expected_policy_config_hash="0" * 64)
    assert (report.exit_code, report.failure_reason) == (10, "ERR_G1_INVALID_SCHEMA")
    assert report.gates_evaluated == (1,)


def test_patch_integrity_failure_precedes_trusted_expectation(tmp_path) -> None:
    bundle = make_bundle(tmp_path / "bundle")
    (bundle / "approved.patch").write_bytes(b"tampered\n")
    report = verify_exported_bundle(bundle, expected_policy_config_hash="0" * 64)
    assert (report.exit_code, report.failure_reason) == (20, "ERR_G2_PATCH_MISMATCH")
    assert report.gates_evaluated == (1, 2)


def test_attestation_policy_failure_precedes_trusted_expectation(tmp_path) -> None:
    bundle = make_bundle(tmp_path / "bundle")
    report = verify_exported_bundle(bundle, require_keyed=True, expected_policy_config_hash="0" * 64)
    assert (report.exit_code, report.failure_reason) == (40, "ERR_G4_UNKEYED_DISALLOWED")
    assert report.gates_evaluated == (1, 2, 3, 4)


@pytest.mark.parametrize("expected", ["", "0" * 63, "0" * 65, "A" * 64, "g" * 64, "\u00e9" * 64, 1, False, b"0" * 64])
def test_invalid_expected_digest_is_a_caller_error_before_bundle_io(tmp_path, expected) -> None:
    with pytest.raises(ValueError, match="expected_policy_config_hash"):
        verify_exported_bundle(tmp_path / "absent", expected_policy_config_hash=cast("str", expected))


@pytest.mark.parametrize("matching", [False, True])
def test_cli_enforces_expected_policy_hash(tmp_path, capsys, matching) -> None:
    digest = compute_policy_config_hash(POLICY)
    bundle = make_bundle(tmp_path / "bundle", policy_config=POLICY, policy_config_hash=digest)
    expected = digest if matching else "0" * 64
    result = main(["verify-bundle", str(bundle), "--expected-policy-config-hash", expected])
    assert result == (0 if matching else 50)
    report = json.loads(capsys.readouterr().out)
    assert report["exit_code"] == result
    assert report["failure_reason"] == (None if matching else "ERR_G5_POLICY_CONFIG_MISMATCH")


def test_cli_reports_invalid_digest_as_usage_error(tmp_path, capsys) -> None:
    assert main([
        "verify-bundle", "--bundle-dir", str(tmp_path / "absent"),
        "--expected-policy-config-hash", "invalid",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_argument"

"""Five ordered offline provenance gates; reads artifacts without executing them."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, cast

from agentsentinel.cli.provenance import (
    DOMAIN_EVIDENCE_BUNDLE_V1,
    ENVELOPE_EXCLUDED_KEYS,
    ProvenanceSchemaError,
    canonicalize_jcs,
    compute_dsse_pae,
    compute_policy_config_hash,
    digest_matches,
    loads_strict_jcs,
    resolve_signing_key,
    resolve_trusted_key,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)")


@dataclass(frozen=True)
class BundleVerificationReport:
    """Stable JSON telemetry with the first failing gate's numerical exit code."""

    timestamp_utc: str
    bundle_path: str
    verification_mode: str
    key_id: str | None
    gates_evaluated: tuple[int, ...]
    overall_verdict: str
    failure_reason: str | None
    warnings: tuple[str, ...]
    exit_code: int

    @property
    def event(self) -> str | None:
        """Derived failure telemetry; does not enter signed evidence payloads."""
        return (
            f"EVENT_G{self.exit_code // 10}_FAILED"
            if self.exit_code in {10, 20, 30, 40, 50} else None
        )

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "event": self.event}


class _PathViolation(ValueError):
    """A file or metadata path escapes the bundle's containment policy."""


def _safe_path(value: object) -> None:
    if isinstance(value, list):
        for child in value:
            _safe_path(child)
        return
    if value is None:
        return
    if not isinstance(value, str):
        raise ProvenanceSchemaError("Path fields must contain strings")
    normalized = value.replace("\\", "/")
    if (
        "\x00" in value or ".." in PurePosixPath(normalized).parts
        or PurePosixPath(normalized).is_absolute() or PureWindowsPath(value).drive
    ):
        raise _PathViolation("Invalid artifact path")


def _check_metadata_paths(evidence: dict[str, object]) -> None:
    pending: list[object] = [evidence]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for name, value in current.items():
                if name in ("path", "filename") or name.endswith(("_path", "_paths")):
                    _safe_path(value)
                pending.append(value)
        elif isinstance(current, list):
            pending.extend(current)


def _bundle_root(bundle_dir: Path) -> Path:
    if (
        ".." in bundle_dir.parts or bundle_dir.is_symlink()
        or (bundle_dir.exists() and getattr(bundle_dir.lstat(), "st_file_attributes", 0) & 0x400)
    ):
        raise _PathViolation("Invalid bundle directory")
    root = bundle_dir.resolve(strict=True)
    if not root.is_dir():
        raise FileNotFoundError("Bundle directory not found")
    # Walk explicitly without following symlinks/junctions, including extra files.
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in directory.iterdir():
            if (
                entry.is_symlink() or getattr(entry.lstat(), "st_file_attributes", 0) & 0x400
                or not entry.resolve().is_relative_to(root)
            ):
                raise _PathViolation("Linked or escaping bundle artifact")
            if entry.is_dir():
                pending.append(entry)
    for name in ("evidence.json", "REPORT.md", "approved.patch"):
        if not (root / name).is_file():
            raise FileNotFoundError("Required bundle artifact not found")
    return root


def _approved_timestamp(value: str) -> datetime:
    if not _TIMESTAMP.fullmatch(value):
        raise ProvenanceSchemaError("approved_at_utc must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProvenanceSchemaError("Invalid approval timestamp") from exc


def _validate_schema(evidence: dict[str, object]) -> None:
    string_fields = (
        "run_id", "case_id", "base_commit", "status", "diff_hash", "canonical_diff_sha256",
        "image_digest", "baseline_result_hash", "post_patch_result_hash", "approved_by",
        "approved_at_utc", "attestation_mode", "bundle_hash", "approval_hash",
    )
    if any(not isinstance(evidence.get(name), str) for name in string_fields):
        raise ProvenanceSchemaError("Missing or invalid string field")
    for name in ("baseline_exit_code", "post_patch_exit_code", "attempts_used"):
        if type(evidence.get(name)) is not int:
            raise ProvenanceSchemaError("Missing or invalid integer field")
    for name in ("minimization_summary", "mutation_adequacy_summary"):
        if name not in evidence or (
            evidence[name] is not None and not isinstance(evidence[name], dict)
        ):
            raise ProvenanceSchemaError("Missing or invalid summary")
    for name in ("key_id", "hmac_signature"):
        if name not in evidence or (
            evidence[name] is not None and not isinstance(evidence[name], str)
        ):
            raise ProvenanceSchemaError("Missing or invalid attestation field")
    if "policy_config" in evidence or "policy_config_hash" in evidence:
        policy_config = evidence.get("policy_config")
        policy_hash = evidence.get("policy_config_hash")
        if (
            not isinstance(policy_config, dict) or not isinstance(policy_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", policy_hash) is None
        ):
            raise ProvenanceSchemaError("Missing or invalid policy configuration metadata")
    _approved_timestamp(cast("str", evidence["approved_at_utc"]))


def verify_exported_bundle(
    bundle_dir: Path,
    *,
    require_keyed: bool = False,
    signing_key: str | bytes | None = None,
    trusted_keys: Mapping[str, str | bytes] | None = None,
    max_clock_skew_seconds: float = 300.0,
) -> BundleVerificationReport:
    """Return first failure at gates 1..5, without a database, network or sandbox."""
    if not math.isfinite(max_clock_skew_seconds) or max_clock_skew_seconds < 0:
        raise ValueError("max_clock_skew_seconds must be finite and nonnegative")
    mode = "unknown"
    key_id: str | None = None
    gates: list[int] = []

    def report(
        code: int = 0, reason: str | None = None, *, skew: bool = False,
    ) -> BundleVerificationReport:
        return BundleVerificationReport(
            datetime.now(UTC).isoformat().replace("+00:00", "Z"), str(bundle_dir), mode,
            key_id, tuple(gates), "FAILED" if code else "PASSED", reason,
            ("WARN_G5_TIMESTAMP_SKEW",) if skew else (), code,
        )

    gates.append(1)
    try:
        root = _bundle_root(bundle_dir)
        raw_evidence = (root / "evidence.json").read_bytes()
        patch = (root / "approved.patch").read_bytes()
        evidence = loads_strict_jcs(raw_evidence)
        _check_metadata_paths(evidence)
        _validate_schema(evidence)
    except _PathViolation:
        return report(10, "ERR_G1_PATH_TRAVERSAL")
    except OSError:
        return report(10, "ERR_G1_MISSING_FILE")
    except ProvenanceSchemaError:
        return report(10, "ERR_G1_INVALID_SCHEMA")
    mode = cast("str", evidence["attestation_mode"])
    key_id = cast("str | None", evidence["key_id"])

    gates.append(2)
    if not digest_matches(hashlib.sha256(patch).hexdigest(), cast("str", evidence["diff_hash"])):
        return report(20, "ERR_G2_PATCH_MISMATCH")
    canonical_patch_hash = hashlib.sha256(patch.replace(b"\r\n", b"\n")).hexdigest()
    if not digest_matches(canonical_patch_hash, cast("str", evidence["canonical_diff_sha256"])):
        return report(20, "ERR_G2_CANONICAL_PATCH_MISMATCH")

    gates.append(3)
    if not hmac.compare_digest(raw_evidence, canonicalize_jcs(evidence)):
        return report(30, "ERR_G3_CANONICAL_BINDING_FAILED")
    payload = {
        name: value for name, value in evidence.items() if name not in ENVELOPE_EXCLUDED_KEYS
    }
    canonical = canonicalize_jcs(payload)
    if not digest_matches(
        hashlib.sha256(canonical).hexdigest(), cast("str", evidence["bundle_hash"]),
    ):
        return report(30, "ERR_G3_CANONICAL_BINDING_FAILED")

    policy_config = evidence.get("policy_config")
    if isinstance(policy_config, dict) and not digest_matches(
        compute_policy_config_hash(policy_config), cast("str", evidence["policy_config_hash"]),
    ):
        return report(30, "ERR_G3_POLICY_CONFIG_MISMATCH")

    gates.append(4)
    try:
        configured_key = resolve_signing_key(signing_key)
    except ProvenanceSchemaError:
        return report(40, "ERR_G4_ATTESTATION_FAILED")
    keyed_policy = require_keyed or os.environ.get("AGENTSENTINEL_REQUIRE_KEYED") == "1"
    keyed_policy = keyed_policy or configured_key is not None
    if keyed_policy and mode == "sha256-unkeyed-v1":
        return report(40, "ERR_G4_UNKEYED_DISALLOWED")
    pae = compute_dsse_pae(DOMAIN_EVIDENCE_BUNDLE_V1, canonical)
    if not digest_matches(hashlib.sha256(pae).hexdigest(), cast("str", evidence["approval_hash"])):
        return report(40, "ERR_G4_ATTESTATION_FAILED")
    signature = evidence["hmac_signature"]
    if mode == "hmac-sha256-v1":
        if not key_id:
            return report(40, "ERR_G4_KEY_NOT_FOUND")
        try:
            key = resolve_trusted_key(key_id, signing_key=signing_key, trusted_keys=trusted_keys)
        except ProvenanceSchemaError:
            return report(40, "ERR_G4_KEY_NOT_FOUND")
        if key is None:
            return report(40, "ERR_G4_KEY_NOT_FOUND")
        expected = hmac.new(key, pae, hashlib.sha256).hexdigest()
        if not isinstance(signature, str) or not digest_matches(expected, signature):
            return report(40, "ERR_G4_ATTESTATION_FAILED")
    elif mode != "sha256-unkeyed-v1" or key_id not in (None, "") or signature is not None:
        return report(40, "ERR_G4_ATTESTATION_FAILED")

    gates.append(5)
    if evidence["baseline_exit_code"] == 0:
        return report(50, "ERR_G5_INVALID_BASELINE")
    if evidence["post_patch_exit_code"] != 0:
        return report(50, "ERR_G5_POST_PATCH_FAILURE")
    if evidence["status"] != "APPROVED":
        return report(50, "ERR_G5_STATUS_NOT_APPROVED")
    approved = _approved_timestamp(cast("str", evidence["approved_at_utc"]))
    skew = abs((datetime.now(UTC) - approved).total_seconds()) > max_clock_skew_seconds
    return report(skew=skew)

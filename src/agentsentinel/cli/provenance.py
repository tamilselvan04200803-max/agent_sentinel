"""M14 canonical JSON and shared-secret attestations over DSSE PAE bytes.

RFC 8785 number serialization uses Python's shortest binary64 representation
with ECMAScript fixed/exponent thresholds. The application additionally rejects
integer tokens outside the safe integer range. No inspected code is executed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

DOMAIN_APPROVAL_V1 = "agentsentinel.approval.v1"
DOMAIN_EVIDENCE_BUNDLE_V1 = "agentsentinel.evidence_bundle.v1"
ENVELOPE_EXCLUDED_KEYS = frozenset({"bundle_hash", "approval_hash", "hmac_signature"})
MAX_DEPTH = 128


class ProvenanceSchemaError(ValueError):
    """Malformed I-JSON/provenance data; messages never include signing secrets."""


def _validate(value: object, max_depth: int = MAX_DEPTH) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, (dict, list)):
            depth += 1
            if depth > max_depth:
                raise ProvenanceSchemaError("Maximum JSON nesting depth exceeded")
            if isinstance(current, dict):
                for key, child in current.items():
                    if not isinstance(key, str):
                        raise ProvenanceSchemaError("JSON object keys must be strings")
                    key.encode("utf-8")
                    pending.append((child, depth))
            else:
                pending.extend((child, depth) for child in current)
        elif isinstance(current, str):
            current.encode("utf-8")
        elif isinstance(current, bool) or current is None:
            continue
        elif isinstance(current, int):
            if abs(current) >= 2**53:
                raise ProvenanceSchemaError("Integer exceeds the IEEE-754 safe range")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ProvenanceSchemaError("Non-finite JSON number")
        else:
            raise ProvenanceSchemaError("Unsupported JSON value type")


def _float_text(value: float) -> str:
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).lower().partition("e")
    point = mantissa.find(".")
    if point < 0:
        point = len(mantissa)
    point += int(exponent or "0")
    digits = mantissa.replace(".", "")
    leading = len(digits) - len(digits.lstrip("0"))
    point -= leading
    digits = digits.lstrip("0").rstrip("0")
    if 0 < point <= 21:
        if point >= len(digits):
            return sign + digits + "0" * (point - len(digits))
        return sign + digits[:point] + "." + digits[point:]
    if -6 < point <= 0:
        return sign + "0." + "0" * (-point) + digits
    coefficient = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
    return sign + coefficient + "e" + ("+" if point > 0 else "") + str(point - 1)


def _encode(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _float_text(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(child) for child in value) + "]"
    if isinstance(value, dict):
        obj = cast("dict[str, object]", value)
        keys = sorted(obj, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_encode(key) + ":" + _encode(obj[key]) for key in keys) + "}"
    raise ProvenanceSchemaError("Unsupported JSON value type")


def canonicalize_jcs(obj: object) -> bytes:
    """Serialize I-JSON with UTF-16 sorting, ECMAScript numbers and UTF-8 bytes."""
    try:
        _validate(obj)
        return _encode(obj).encode("utf-8")
    except (UnicodeError, RecursionError) as exc:
        raise ProvenanceSchemaError("Invalid Unicode or excessive JSON depth") from exc


def compute_policy_config_hash(policy_config: Mapping[str, object]) -> str:
    """Hash canonical configuration metadata, without reading live process state."""
    return hashlib.sha256(canonicalize_jcs(dict(policy_config))).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceSchemaError("Duplicate JSON object key")
        result[key] = value
    return result


def _constant(_value: str) -> object:
    raise ProvenanceSchemaError("Non-finite JSON number")


def _parse_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ProvenanceSchemaError("Non-finite JSON number")
    return 0.0 if number == 0 else number


def loads_strict_jcs(raw_bytes: bytes, max_depth: int = MAX_DEPTH) -> dict[str, object]:
    """Parse an object, rejecting ambiguous keys, invalid Unicode and depth bombs."""
    if isinstance(max_depth, bool) or not 1 <= max_depth <= MAX_DEPTH:
        raise ProvenanceSchemaError("max_depth must be between 1 and 128")
    try:
        text = raw_bytes.decode("utf-8")
        # Bound structure before json.loads can recurse; quoted brackets do not count.
        depth = 0
        quoted = False
        escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > max_depth:
                    raise ProvenanceSchemaError("Maximum JSON nesting depth exceeded")
            elif char in "]}":
                depth -= 1
        value: object = json.loads(
            text, object_pairs_hook=_unique_object,
            parse_constant=_constant, parse_float=_parse_float,
        )
        if not isinstance(value, dict):
            raise ProvenanceSchemaError("JSON root must be an object")
        _validate(value, max_depth)
        return cast("dict[str, object]", value)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProvenanceSchemaError("Invalid strict I-JSON object") from exc


def compute_dsse_pae(domain: str, payload_bytes: bytes) -> bytes:
    """Encode the payload type and body using their UTF-8 byte lengths."""
    domain_bytes = domain.encode("utf-8")
    return (
        b"DSSEv1 " + str(len(domain_bytes)).encode("ascii") + b" " + domain_bytes
        + b" " + str(len(payload_bytes)).encode("ascii") + b" " + payload_bytes
    )


def resolve_signing_key(signing_key: str | bytes | None = None) -> bytes | None:
    """Explicit key takes precedence; an unset/empty environment selects unkeyed mode."""
    key = signing_key if signing_key is not None else os.environ.get("AGENTSENTINEL_SIGNING_KEY")
    if key is None or (signing_key is None and key == ""):
        return None
    if not isinstance(key, (str, bytes)):
        raise ProvenanceSchemaError("Signing key must be text or bytes")
    try:
        raw = key.encode("utf-8") if isinstance(key, str) else key
    except UnicodeError as exc:
        raise ProvenanceSchemaError("Signing key is not valid UTF-8") from exc
    if not raw:
        raise ProvenanceSchemaError("Signing key must not be empty")
    return raw


def compute_key_id(signing_key: str | bytes) -> str:
    raw = resolve_signing_key(signing_key)
    assert raw is not None
    return hashlib.sha256(raw).hexdigest()[:16]


def digest_matches(actual: str, expected: str) -> bool:
    """Compare encoded digest strings without ASCII-only compare_digest failures."""
    try:
        return hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))
    except UnicodeError as exc:
        raise ProvenanceSchemaError("Invalid Unicode in digest or fingerprint") from exc


def resolve_trusted_key(
    key_id: str,
    *,
    signing_key: str | bytes | None = None,
    trusted_keys: Mapping[str, str | bytes] | None = None,
) -> bytes | None:
    current = resolve_signing_key(signing_key)
    if current is not None and digest_matches(compute_key_id(current), key_id):
        return current
    if trusted_keys is None:
        configured = os.environ.get("AGENTSENTINEL_TRUSTED_KEYS")
        try:
            values = loads_strict_jcs(configured.encode("utf-8")) if configured else {}
        except UnicodeError as exc:
            raise ProvenanceSchemaError("Invalid trusted key configuration") from exc
        if not all(isinstance(value, str) for value in values.values()):
            raise ProvenanceSchemaError("Invalid trusted key configuration")
        trusted_keys = cast("dict[str, str]", values)
    for fingerprint, secret in trusted_keys.items():
        if not isinstance(fingerprint, str) or not isinstance(secret, (str, bytes)):
            raise ProvenanceSchemaError("Invalid trusted key configuration")
        if digest_matches(fingerprint, key_id):
            if digest_matches(compute_key_id(secret), key_id):
                return resolve_signing_key(secret)
            return None
    return None


def attest_payload(
    payload: dict[str, object],
    *,
    signing_key: str | bytes | None = None,
    domain: str = DOMAIN_EVIDENCE_BUNDLE_V1,
) -> dict[str, object]:
    """Bind all top-level metadata except the three detached envelope digests."""
    key = resolve_signing_key(signing_key)
    result = {name: value for name, value in payload.items() if name not in ENVELOPE_EXCLUDED_KEYS}
    result["attestation_mode"] = "hmac-sha256-v1" if key is not None else "sha256-unkeyed-v1"
    result["key_id"] = compute_key_id(key) if key is not None else None
    canonical = canonicalize_jcs(result)
    pae = compute_dsse_pae(domain, canonical)
    result["bundle_hash"] = hashlib.sha256(canonical).hexdigest()
    result["approval_hash"] = hashlib.sha256(pae).hexdigest()
    result["hmac_signature"] = hmac.new(key, pae, hashlib.sha256).hexdigest() if key else None
    return result

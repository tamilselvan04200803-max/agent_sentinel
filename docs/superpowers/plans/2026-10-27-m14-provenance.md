# AgentSentinel M14 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline, test first, and one read-only final reviewer.

**Goal:** Export canonical, optionally authenticated provenance and verify it offline through five ordered gates.

**Architecture:** Keep existing checkpoint/domain/approval formats compatible. A stdlib provenance module canonicalizes JSON and computes domain-separated DSSE PAE SHA-256/HMAC attestations. A separate verifier consumes immutable file snapshots and emits structured gate telemetry. CLI export adds the envelope; verify-bundle requires no database, Docker or repository execution.

**Spec:** User M14 attachment `73efa8c7-e13d-4e47-a00a-d1d84f26b6f1/Pasted text.txt`.

**Tech Stack:** Python 3.11+, stdlib only, existing virtual environment, pytest, Ruff, strict mypy, PowerShell.

## Global Constraints

- Preserve every existing assertion and caller; no dependencies or SQLite schema changes.
- Write UTF-8/LF. Never run inspected patch/source on the host; offline verification reads artifacts only.
- Preserve pre-existing AGENTS.md, tracked cache changes and `.pytest_tmp` in the primary checkout.
- Explicit key overrides environment. Never include secrets in payloads, telemetry, diagnostics or reports.
- Compare digests, signatures and key fingerprints with hmac.compare_digest.
- Preserve nested legacy approval_record for compatibility; the new envelope authenticates that metadata but does not migrate historical internal approval hashes.

## Decisions and Review Focus

- Follow RFC 8785 UTF-16 sorting, Unicode scalar validation and ECMAScript number spellings; negative zero serializes as `0`. Use RFC Appendix B vectors, including exponent/fixed thresholds.
- Enforce the directive's stricter integer-token bound abs(int) < 2**53 and a maximum of 128 nested containers; reject duplicate keys before accepting parsed data.
- `attestation_mode` and `key_id` remain inside the signed payload. Exactly bundle_hash, approval_hash and hmac_signature are excluded at the top level.
- Existing approval hashes remain nested legacy metadata. Exported approval_hash is the evidence-bundle PAE digest; no claim that unkeyed mode authenticates a signer.
- Explicit/environment signing keys also require keyed verification, preventing silent downgrade. Trusted key rings support rotation without selecting an arbitrary first key.
- Keep REPORT.md as human-readable output required by Gate 1; the specified envelope binds JSON metadata and patch hashes, not independent report contents.
- Check containment and symlinks before reading; inspect nested path fields, not arbitrary stdout/diff text. Reject malformed config without disclosing its contents.
- Gate 1 validates types, including int-versus-bool; semantic baseline/post/status checks remain Gate 5 so validly signed failures have the specified exit codes.
- Timestamp skew is a warning, not expiry/replay prevention. Limits are explicit in STATE.md.

## Task 1: Canonicalization and attestation primitives

**Files:** new `src/agentsentinel/cli/provenance.py`; new `tests/unit/test_m14_provenance_verifier.py`.

**Interfaces:** `canonicalize_jcs(obj: object) -> bytes`; `loads_strict_jcs(raw_bytes: bytes, max_depth: int = 128) -> dict[str, object]`; `compute_dsse_pae(domain: str, payload_bytes: bytes) -> bytes`; `compute_key_id(signing_key: str | bytes) -> str`; `ProvenanceSchemaError`; domain and exclusion constants. Internal typed helpers resolve keys and produce the envelope.

- [x] Add failing RFC number/string/sorting, strict-parser/depth, PAE/domain and keyed/unkeyed/key-precedence tests.
- [x] Implement and run focused tests, Ruff and strict mypy.

## Task 2: Five-gate offline verifier

**Files:** new `src/agentsentinel/cli/bundle_verifier.py`; unit test above; new `tests/adversarial/test_adversarial_m14_provenance.py`.

**Interfaces:** frozen `BundleVerificationReport` with telemetry fields and exit_code; `verify_exported_bundle(bundle_dir: Path, *, require_keyed=False, signing_key=None, trusted_keys=None, max_clock_skew_seconds=300.0) -> BundleVerificationReport`.

- [x] Add failing tests for all ATTACK-01..ATTACK-10 scenarios, all gate exit codes, precedence, timestamp warnings and missing/invalid schema/path evidence.
- [x] Implement sequential gates, key routing and environment policy. Return the first failure; never execute source or load checkpoint databases.
- [x] Run focused tests, Ruff and strict mypy.

## Task 3: Export and CLI integration

**Files:** `src/agentsentinel/cli/exporter.py`, `src/agentsentinel/cli/main.py`, `src/agentsentinel/orchestrator/state_machine.py`; both new test files.

- [x] Add failing real-checkpoint exporter round trips, legacy field preservation, LF byte integrity, deterministic re-export and CLI passing/failing telemetry tests.
- [x] Add keyword-only signing_key to exporter; enrich fields and write canonical evidence bytes plus exact LF patch bytes. Preserve the APPROVED gate and old nested fields.
- [x] Add verify-bundle CLI and constant-time legacy approval comparison without altering the persisted binding format.
- [x] Run M14 plus M4/M6/M13A regression tests, Ruff and strict mypy.

## Task 4: Final review and release

**Files:** `STATE.md`, this plan, reviewed fixes within the approved nine-file scope.

- [x] Dispatch one read-only reviewer, reproduce and fix material findings with tests.
- [x] Run separate Ruff, strict mypy and full pytest commands; record actual Docker results and skip reasons.
- [x] Mark Approval-1 resolved for M14 export attestations, document legacy compatibility and unkeyed/HMAC limitations, and commit conventionally.
- Release operation: fast-forward main, push normally to origin/main, and verify the remote revision.

## Execution Record

- Base: `ae3a2e4`; M4/M6/M13A baseline: **40 passed**.
- Isolated worktree: `agent_sentinel_m14`, branch `feat/m14-provenance`.
- References: [RFC 8785](https://www.rfc-editor.org/info/rfc8785/) and [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
- Task 1: missing module observed, then **57 primitive tests passed**; strict mypy **42 files**. One test assertion ordering lint finding fixed.
- Task 2: missing verifier module observed, then **107 tests passed**; strict mypy **43 files**. Three line-length findings corrected during integration.
- Task 3: **11 expected integration failures**, plus Windows reparse-point guard failure reproduced separately after correcting the OS-stat test fixture. Then **159 integrated M14/M4/M6/M13A tests passed**. Ruff and strict mypy clean.
- Pre-review full suite: **844 passed, 1 skipped**, all **10 live Docker tests passed** in **195.72 seconds**.
- Final review: malformed trusted fingerprint could raise UnicodeEncodeError. Regraded as a structured-verifier error-path defect despite no authentication bypass; that case and an adjacent environment-keyring encoding case failed first, then were fixed within the same review pass. No findings deferred.
- Review rulings: legacy approval-record migration, unbound report text, warning-only timestamps, safe-integer token policy and old-export re-export requirements are documented directive/design boundaries. Verifier reads assume stable filesystem artifacts; concurrent writers and resource limits beyond JSON nesting depth are not claimed. The independent reviewer reported zero mismatches for 199,921 finite binary64 values against Node JSON.stringify.
- Final fix verification: **161 focused tests passed**. Final full suite: **846 passed, 1 Windows symlink privilege skip, 0 failures** in **199.12 seconds**; all **10 live Docker integration tests** and all **121 M14 tests** passed. Ruff clean; strict mypy clean across **43 source files**. No original tests/assertions changed.
- Verified implementation commit: `8f40cd2`. Release evidence is recorded in a following documentation-only commit.

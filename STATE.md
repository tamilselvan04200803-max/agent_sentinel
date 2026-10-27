# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M14 complete; independent review findings resolved and release gates passed.
- **Previous Milestones:** M0-M13B complete, with live Docker milestone gates passing.
- **Release Base:** `56d78e4`; existing history, including `fdfa7cf`, is preserved.

## Executive architecture (M0-M14)

| Milestone | Capability | Status |
|---|---|---|
| M0 | Immutable domain records and pytest verdicts | Complete |
| M1 | Ephemeral workspaces and hardened Docker execution | Complete |
| M2 | Diff parsing, path policy and hard-fail patch application | Complete |
| M3 | Provider protocol, prompt construction and cost accounting | Complete |
| M4 | Bounded lifecycle, deduplication and SQLite checkpoints | Complete |
| M5 | Two-gate, reference-withholding benchmark admission | Complete |
| M6 | CLI and approval-gated evidence export | Complete |
| M7 | AST fault localization and image-digest resolution | Complete |
| M8 | Literal-overfit, reflection and source-poisoning checks | Complete |
| M9A | Unique exact-preimage healing with per-file cumulative offsets | Verified |
| M9B | Complexity/debug/exception guards; rebased hunk candidates | Verified |
| M10 | Additive, bounded changed-function mutation generator | Verified |
| M11 | Declared public call-contract preservation | Verified |
| M12 | Typed diagnostics and sanitized per-run retry feedback | Verified |
| M13A | Post-pass subset search, mutation adequacy and approval-bound evidence | Verified |
| M13B | Deterministic AST skeletons and tiered localized prompt context | Verified |
| M14 | Canonical keyed provenance and five-gate offline verification | Verified |

## M14 architecture and verification (2026-10-27)

- `cli.provenance` adds `canonicalize_jcs`, `loads_strict_jcs`, `compute_dsse_pae`,
  `compute_key_id` and typed key/attestation helpers. RFC 8785 UTF-16 key sorting,
  Unicode scalar validation and ECMAScript binary64 number spellings are tested
  against Appendix B vectors. Negative zero emits `0`. The parser additionally
  rejects duplicate keys, non-finite numbers, integer tokens with abs(value) >=
  2**53, non-object roots and container nesting beyond 128, before decode recursion.
- DSSE PAE domain separation distinguishes `agentsentinel.approval.v1` and
  `agentsentinel.evidence_bundle.v1`. Exported envelopes bind every top-level
  field except exactly `bundle_hash`, `approval_hash`, and `hmac_signature`.
- `export_evidence_bundle(..., *, signing_key=None)` retains legacy metadata,
  writes exact LF-normalized UTF-8 patch bytes and canonical evidence JSON, and
  binds raw/canonical patch digests, execution-record digests, approval identity,
  timestamp and M13A summaries. Re-export with the same record/key is deterministic.
- Explicit signing keys override `AGENTSENTINEL_SIGNING_KEY`; no key selects
  `sha256-unkeyed-v1`. Configured keys select `hmac-sha256-v1`; key IDs are the
  first 16 hex characters of SHA-256(key). Secrets never enter the envelope/report.
  Rotation uses explicit trusted_keys or a JSON object in AGENTSENTINEL_TRUSTED_KEYS;
  routing also verifies each secret's fingerprint. Digest/signature checks use
  hmac.compare_digest, including legacy approval comparisons.
- `cli.bundle_verifier.verify_exported_bundle` returns a frozen
  `BundleVerificationReport`. Gates fail in order: structure/schema/containment
  (10), physical/canonical patch (20), canonical formatting/payload (30), PAE/HMAC
  and key policy (40), execution/status invariants (50). Success returns 0.
- CLI: `agentsentinel verify-bundle --bundle-dir <path> [--require-keyed]
  [--signing-key <key>]`. Output is one JSON telemetry record. Verification reads
  files only: no database, Docker, network, imports of inspected code or test runs.
  Explicit/environment signing keys enforce keyed verification; REQUIRE_KEYED=1
  (full variable: AGENTSENTINEL_REQUIRE_KEYED) also prevents unkeyed downgrade.
- Historical `[Approval-1]` is resolved for exported M14 provenance through
  RFC 8785 + DSSE PAE + HMAC-SHA256 and the offline verifier. Existing SQLite
  approval hashes and EvidenceBundle domain hashes retain their legacy format;
  nested approval_record is signed metadata, not a migrated historical signature.
  Older export directories lack M14 schema and must be re-exported from their
  approved database record. No schema migration or approval-call API changes.
- Limits: unkeyed mode detects accidental corruption but cannot authenticate a
  producer; HMAC authenticates shared-key possession, not public-key identity or
  non-repudiation. Keys are operator-managed. The verifier checks declared execution
  results, not genuine execution. Timestamp skew is warning-only, not expiration
  or replay prevention. REPORT.md must exist but its independent text is not hashed;
  authenticated JSON and patch digests are authoritative. Verification assumes
  stable artifacts during the read; concurrent filesystem writers and resource
  bounds beyond structural JSON depth are outside this milestone's guarantee.
- Baseline M4/M6/M13A: **40 passed**. Primitive tests first failed with a missing
  module, then **57 passed**. Verifier tests first failed with its missing module,
  then **107 passed**. Integration produced 11 expected missing-feature failures;
  a Windows junction guard also had a separately reproduced failing test.
- Integrated M14/M4/M6/M13A: **159 passed** before review fixes; **161 passed**
  afterward. Ruff: clean. Strict mypy: **43 source files**, no errors.
- Pre-review full suite: **844 passed, 1 Windows symlink skip** in **195.72 seconds**,
  including all **10 live Docker tests**. One read-only independent review found
  malformed Unicode trusted-key configuration escaping Gate 4 telemetry. That
  finding and an adjacent environment-keyring boundary were reproduced by two
  failing tests and fixed with bounded schema-error conversion. No findings are
  deferred. The reviewer also compared **199,921 finite binary64 values** against
  Node JSON.stringify and reported zero serialization discrepancies.
- Final suite after fixes: **846 passed, 1 skipped, 0 failures** in **199.12 seconds**.
  All **10 live Docker integration tests passed** and all **121 M14 tests passed**.
  The sole skip is the existing Windows `test_block_symlink_escape`, because this
  user environment lacks symlink creation privileges. No original assertions changed.
- Verification used the existing virtual environment with `-B`, disabled pytest's
  cache provider, and a fresh workspace-owned external basetemp to preserve the
  existing ACL-locked `.pytest_tmp`. Log: `m14-final-tests.log` in the parent workspace.
  Release base: `ae3a2e4`; verified implementation commit: `8f40cd2`.
  Publication target: `origin/main` via normal push.
  Pre-existing primary-checkout AGENTS.md and tracked cache edits are excluded.
- References: [RFC 8785](https://www.rfc-editor.org/info/rfc8785/) and the
  [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).

## M13B architecture and verification (2026-10-27)

- Additive localization APIs: `merge_keep_spans`, `skeletonize_python_source`,
  `pack_file_with_skeleton`, and frozen `SkeletonPackResult`, exported through
  `agentsentinel.localization`. Existing localization interfaces are unchanged.
- AST folding preserves module/class interfaces, decorators, complete signatures,
  and first docstring lines. Kept outer scopes still fold unselected nested siblings.
  Default mode retains physical line count; compact mode retains original disk prefixes.
- Signature tokenization returns immediately at the depth-zero colon, before
  tokenizing a potentially incomplete multiline docstring. Syntax failures return
  numbered raw source; null bytes/non-string input fail explicitly.
- Packing keeps hop-0/hop-1 bodies, evicts hop-1, forces compact hop-0 output, then
  folds all bodies. With default compact=True, Tiers 2/3 coincide; Tier 3 is useful
  with compact=False. Tier 0 is reserved. A Tier 4 interface view can still exceed
  budget; PromptBuilder then uses its legacy raw truncation and visible marker.
- Both prompt entry points pack oversized Python files when localization is
  supplied, including an empty slice sequence. Only matching file slices keep
  bodies. Existing allowlist/path checks and prompt sanitization remain in effect.
- These are character budgets, not exact token counts. Skeletons are context
  views, not executable Python; folded multiline docstrings may remain open.
  The cap applies to packed per-file source, not the entire prompt or its
  existing separately rendered localization hints.
- Baseline prompt/localization tests: **40 passed**. New skeletonizer tests were
  observed failing before implementation: **27 missing-API failures**. Packing/
  prompt tests then produced **15 expected failures** before integration.
- Focused M13B plus existing prompt/localization verification: **89 passed**.
  Ruff is clean; strict mypy checks **41 source files** without errors.
- One independent final review found recursive traversal failing on a valid deep
  expression and path normalization conflating `.config` with `config`. Three
  regression tests reproduced these failures, then passed after iterative AST
  traversal and component-aware POSIX path matching. **92 focused tests passed**;
  Ruff and strict mypy remain clean. No review findings are deferred.
- The initial sandboxed full suite had **712 passed, 11 skipped** in 144.19 seconds:
  ten live Docker tests lacked named-pipe access, plus the existing Windows
  symlink privilege skip. Docker 29.4.1 was verified outside that sandbox.
- Final suite after review fixes, with Docker access: **725 passed, 1 skipped,
  0 failures** in **157.77 seconds**. All **10 live Docker integration tests passed**.
  The sole skip is `tests/unit/test_validator.py::test_block_symlink_escape`, because
  this Windows user lacks symlink creation privileges. All **52 new M13B tests** pass.
- Final checks use the existing virtual environment with `-B`, disable pytest's
  cache provider and use a fresh workspace-owned external basetemp rather than
  the pre-existing ACL-locked `.pytest_tmp`. Final log: `m13b-final-tests.log` in
  the parent workspace. Ruff: clean; strict mypy: **41 source files**, no errors.
- Release base: `646bb4a`; verified implementation commit: `716dc39`.
  Publication target: `origin/main` via a normal push.
  Pre-existing primary-checkout AGENTS.md and tracked cache modifications are excluded.

## M13A architecture and verification (2026-10-26)

- Opt-in keyword-only state-machine flags default to disabled; `max_mutants=3`
  is a total patch budget, with negative values rejected before setup.
- Minimize before probing. Every candidate gets a fresh baseline copy and the
  full policy, apply and overfit checks. Expected pytest IDs must visibly pass.
  The single-pass singleton/drop-one search does not guarantee global or 1-minimality.
- Differential mutants are generated only from the selected patch's changed
  Python files. Every mutant runs in a separate hardened container and a writable
  `/tmp/mut_workspace` shadow; `/workspace:ro` and read-only rootfs remain unchanged.
- Child pytest uses fast-fail and a timeout of twice the accepted passing wall
  time, with a one-second floor. Process groups and adopted children are reaped.
  Test nonzero exits/timeouts count as kills; wrapper errors remain infrastructure errors.
- Zero mutants score 1.0 without warning. All surviving mutants set a soft warning
  and force human approval even in benchmark auto-approve mode.
- Accepted proposal/result, hashes, summaries and awaiting-approval state are
  checkpointed atomically without changing the SQLite schema. Original proposal
  and result are retained. Programmatic/CLI exports retain summaries after reopen.
- Canonical summary dataclasses live in `domain.models` and are reexported by
  `verification.post_pass_gate`; this prevents duplicate types and circular imports.
- Probe accepts optional `post_patch_result` to reuse actual passing evidence and
  timing. Standalone calls without it measure once only when eligible mutants exist.
- Initial integrated M13A verification: **102 passed**, including two live Docker
  tests. Pre-review full suite: **668 passed, 1 skipped**, all nine live tests passed.
- One final independent implementation review found two issues: whitespace in
  parameterized test IDs and Windows command limits for full-module mutant payloads.
  Both were reproduced failing, fixed, and verified: **88 focused tests** and all
  **three M13A live Docker tests** passed. Large payloads use a disposable mounted
  JSON control file that is excluded from the child shadow; small payloads retain
  bounded direct arguments. Original source and read-only mounts remain intact.
- Ruff is clean; strict mypy checks **41 source files** without errors.
- Final verbose suite after both review fixes: **673 passed, 1 skipped, 0 failures** in **195.77 seconds**. All **10 live Docker tests passed** (7 existing + 3 M13A). The skip remains the unprivileged Windows symlink test. Code revision: `1430f09`; release publication target: `origin/main` via a normal push. No minor findings are deferred.

## Historical M9-M12 verification evidence (2026-10-26)

- M9: **445 passed, 1 skipped**, including all 7 live Docker tests.
- M10: **472 passed, 1 skipped**, including all 7 live Docker tests.
- M11: **513 passed, 1 skipped**, including all 7 live Docker tests.
- M12 focused state-machine, taxonomy and adversarial verification: **54 passed**.
- Ruff: clean. Strict mypy: **39 source files**, no errors.
- M12 pre-review full suite: **537 passed, 1 skipped**, including all 7 live Docker tests.
- Final verbose release suite after review fixes: **566 passed, 1 skipped, 0 failures**
  in **125.83 seconds**; all **7 live Docker integration tests passed**.
- Skip: `test_block_symlink_escape`, expected without Windows symlink privileges.
- Independent whole-feature review completed once; all findings were reproduced,
  fixed and verified. No minor findings are deferred.
- Docker Desktop was initially stopped and was started with approval. Docker-enabled
  pytest uses a dedicated workspace temp directory and disables pytest's cache
  to avoid Windows ACL conflicts with sandbox-created temporary/cache directories.

## M9-M12 independent review closure

- Public API extraction now follows effective statement-order bindings, including
  assignment/import/deletion and property replacement. Getter updates retain setters.
- Broad-handler flow analysis accounts for loops, with, try/finally and match;
  nested function exits cannot establish safety for the containing handler.
- Diagnostic control/format characters are removed before neutralizing fences,
  preventing removal from recreating a triple-backtick boundary.
- Typed assertions receive assertion guidance. This was treated as a required
  classifier correction because runtime guidance misdirected repair retries.
- The inherited diff-parser ambiguity for removed text beginning `--- ` was
  fixed because it prevented the healer from handling valid unified diffs.
- Review regressions were observed failing before their fixes. The focused
  review verification passed **144 tests**, followed by the full release run above.

## Design boundaries

- M10 is generation-only, with a separate additive API in `differential_mutation.py`;
  the legacy mutation API is unchanged. Generated mutants are not an adequacy proof.
- M9 hunk candidates do not implement an oracle-driven ddmin minimization loop.
- M13A evaluates those candidates in a bounded single pass. Removed hunks are not
  proven dead code, and mutation scores do not establish correctness or test adequacy.
- M11 is a bounded static call-signature check, not a semantic or dynamic API proof.
- M12 retries consume feedback scoped to the run; transport handling and attempt
  accounting are preserved. Feedback remains process-local; SQLite schemas are unchanged.
- Persisted legacy approvals remain **unkeyed SHA-256 integrity bindings**.
  M14 adds optional HMAC authentication to exported provenance; key custody and
  historical approval-record migration remain operator/deferred responsibilities.

## Completed & Verified Components

| File | Description |
|---|---|
| `src/agentsentinel/orchestrator/dedup.py` | Hardened Tier-2 AST dedup: `tier2_fingerprint` and `check_tier2_duplicate_or_noop` return `None` when zero `.py` files match in `allowed_edit_paths`, preventing false-positive empty-set hash collisions with baseline on Attempt 1. |
| `src/agentsentinel/orchestrator/state_machine.py` | Captured pristine baseline AST hash prior to patch application in `_step_reproduce_baseline` and `_step_apply_patch`; handles `None` AST hashes gracefully by falling back to Tier-1 diff dedup. |
| `src/agentsentinel/evaluation/harness.py` | Isolated SQLite databases per benchmark case in `_run_one_case` and per condition in `compare_baseline_vs_bounded_retry`, preventing cross-run hash collisions; enforced `PYTHONDONTWRITEBYTECODE=1` in test execution env. |
| `src/agentsentinel/sandbox/container.py` | Real Docker image digest pinning via `resolve_image_digest(image_name)` executing `docker image inspect --format {{.Id}}`; gracefully returns `sha256:<64hex>` or `"sha256:unavailable"` when offline/mocked. |
| `src/agentsentinel/localization/traceback_parser.py` | Deterministic traceback parser extracting repository frames from pytest output; normalizes Windows paths (`\` to `/`), filters out `tests/` and external `site-packages`, and restricts to `allowed_edit_paths`. |
| `src/agentsentinel/localization/ast_slicer.py` | Hop-0 (enclosing FunctionDef/AsyncFunctionDef/ClassDef) and Hop-1 (intra-repo called symbols in allowlist) AST slicer extracting localized code snippets with 1-indexed line numbers. |
| `src/agentsentinel/llm/prompts.py` | Upgraded `_sanitize_content`: replaces triple-backticks with non-functional quotes, strips Unicode BiDi control characters (`\u202a`–`\u202e`, `\u2066`–`\u2069`) and zero-width characters (`\u200b`–`\u200d`, `\ufeff`). Injects sanitized fault localization hints into prompt. |
| `src/agentsentinel/domain/exceptions.py` | Added `OverfitPolicyError(PatchPolicyError)` carrying `leaked_literal` and `file_path`. |
| `src/agentsentinel/verification/overfit_guard.py` | Complete anti-overfitting, anti-poisoning, and anti-reflection guard:<br>• `check_patch_hygiene`: Rejects BiDi Trojan Source, zero-width chars, bare `\r` carriage returns, mixed tab/space indentation, and non-ASCII AST identifiers.<br>• `check_forbidden_reflection`: Blocks imports or calls to `sys._getframe`, `inspect.stack`, `inspect.currentframe`, `pytest`, `_pytest`, `unittest.mock`, `os._exit`, `ctypes`, and `builtins.__dict__`.<br>• Constant folder resolving static string concatenation (`"  HEL" + "LO  "`), bytes `.decode()`, and `"".join([...])`.<br>• `verify_not_overfitted`: Flags newly added branches or dictionary lookup tables comparing against test assertion literals extracted from `Assert` and `parametrize` nodes. |
| `src/agentsentinel/orchestrator/state_machine.py` | Wired `resolve_image_digest` to dynamically bind `ApprovalRecord.image_digest` to container SHA-256; wired `verify_not_overfitted` between Tier-2 AST dedup and container sandbox execution; on `OverfitPolicyError`, increments `attempts_used`, skips Docker execution, and passes diagnostic to next attempt's `AttemptFeedback`. |
| `src/agentsentinel/policy/applier.py` | Auto-initializes temporary git tracking in non-git ephemeral workspaces during `git apply` and safely scrubs `.git/` in `finally`, preventing silent patch skipping. |
| `src/agentsentinel/evaluation/harness.py` | Fixed `_provision` to initialize git tracking before applying test patches so benchmark admission Gate 1 and Gate 2 tests run cleanly across all benchmark fixtures. |
| `tests/unit/test_m7_localization.py` | Unit test suite for `resolve_image_digest`, `extract_traceback_frames`, and `localize_faults` (Hop-0 & Hop-1). |
| `tests/unit/test_m8_overfit_guard.py` | Comprehensive test suite for test literal extraction, constant folding (concat, decode, join), dictionary lookup tables, forbidden reflection, and patch hygiene checks. |
| `tests/adversarial/test_adversarial_m8_overfit.py` | Adversarial attacks testing direct literal overfitting, obfuscated string-concatenation overfitting, runtime stack inspection cheating, BiDi/zero-width/homoglyph/mixed-indentation poisoning, and end-to-end multi-attempt state machine recovery. |

## Historical verification evidence (M8)
- Full Test Suite: `python -m pytest -p no:schemathesis -v` -> **368 passed, 1 skipped, 0 failed** in 63.07s.
  - Live Docker integration tests (`TestDockerLiveM1`, `TestDockerLiveM2PatchApplier`, `TestDockerLiveM5BenchmarkAdmission`) all **PASSED** against active Docker daemon.
  - 1 skipped test is Windows-expected unprivileged symlink creation.
- Linter: `python -m ruff check src tests` -> **All checks passed (0 errors)**.
- Typecheck: `python -m mypy --strict src` -> **Success: no issues found in 33 source files**.
- End-to-end State Machine Recovery:
  - Attempt 1 proposed an overfitted patch matching test literals; `OverfitGuard` rejected it as `POLICY_REJECTED` and skipped container execution.
  - Attempt 2 proposed a generic fix (`return s.strip().lower()`), passed policy, executed in sandbox container, and transitioned to `AWAITING_HUMAN_APPROVAL` with pinned Docker image digest.

## Architectural Decision Log (ADR)

- **[2026-10-25 M7-1] Decision:** Live container image digest is resolved dynamically via `docker image inspect --format {{.Id}}` and bound into the approval record. Offline test runs preserve explicit or mock digests (`sha256:unavailable`). Rationale: guarantees tamper-proof verification linking the exact immutable image digest to the approved diff.
- **[2026-10-25 M7-2] Decision:** Fault localization hints are provided as read-only AST slices (Hop-0 and Hop-1) with prompt injection sanitization. Rationale: gives models targeted visibility into failure call stacks without exposing test fixtures or polluting context windows.
- **[2026-10-25 M8-1] Decision:** Test-literal overfitting is checked by static constant folding and AST comparison analysis rather than dynamic runtime tracing. Rationale: static AST analysis catches obfuscated test leaks (string concat, decode, join, lookup tables) prior to container execution, eliminating runtime side-effects and saving container spin-up overhead.
- **[2026-10-25 M8-2] Decision:** Unicode BiDi Trojan Source characters, zero-width characters, mixed tab-and-space indentation, and non-ASCII identifiers are rejected at policy validation. Rationale: prevents malicious visual spoofing, terminal output tampering, and Cyrillic/Greek homoglyph identifier backdoors.

- **[2026-10-26 M9-1] Decision:** Heal only coordinates supported by unique exact
  preimages; track hunk identity per file and accumulate every preceding line delta.
  Revalidate the healed patch before git application. Empty insertion preimages do
  not authorize relocation.
- **[2026-10-26 M9-2] Decision:** Structural checks are independent of test literals.
  Count debugger calls per scope, resolve direct import aliases, and reject newly
  introduced bare or statically swallowing broad handlers.
- **[2026-10-26 M10-1] Decision:** Preserve the whole-source mutation API and add a
  deterministic changed-function generator capped at three results by default.
  Validation parses/compiles ASTs without executing source; mutant execution is deferred.
- **[2026-10-26 M11-1] Decision:** Preserve explicit public call contracts with
  optional additions, descriptor checks and a default-on API guard.
- **[2026-10-26 M12-1] Decision:** Classify typed failures before output evidence,
  render fixed guidance and sanitize every retry diagnostic. Connect feedback
  consumption by run ID, closing the earlier stored-but-unused feedback path.
- **[2026-10-26 Approval-1] Decision:** Retain the existing SHA-256 approval format.
  Do not describe it as a keyed signature; HMAC migration is outside this release.

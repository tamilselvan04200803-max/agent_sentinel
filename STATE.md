# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M8 (Anti-Overfitting, Anti-Poisoning & Anti-Reflection Guard) — complete
- **Previous Milestones:** M7 (AST Fault Localizer & Image Digest Pinning), M6 (Production CLI & Exporter), M5 (Evaluation Harness) — complete
- **Milestone Gate Status:** VERIFIED (Full ground-truth verification on Windows + live Docker Desktop: 368 passed, 1 skipped, 0 failures)

## Completed & Verified Components

| File | Description |
|---|---|
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

## Verification Evidence
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

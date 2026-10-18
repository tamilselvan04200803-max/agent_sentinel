# M0–M3 Deep Architectural Audit & Bug Remediation Report

**Date:** 2026-10-18
**Branch:** `arena/c308faec-agent-sentinel`
**Scope:** `src/agentsentinel/` across M0 (domain), M1 (workspace/container), M2 (diff_parser/validator/applier), M3 (llm client/prompts/pricing).

---

## Audit Result Table

| # | Checklist Item | Status | Files / Lines Modified |
|---|---|---|---|
| **1a** | `CaseSpec.__post_init__` sorts metadata lexicographically & rejects duplicate keys; `==` and `hash()` are order-independent | **CLEAN** (already correct) | `src/agentsentinel/domain/models.py` — verified existing logic; regression test added |
| **1b** | `ExecutionResult.passed` requires exit_code==OK **AND** verifies expected tests actually ran and passed (blocks empty-test-run reward hack) | **BUG FOUND** | `src/agentsentinel/domain/models.py`: added `expected_test_ids` field and `_test_passed_in_output()` helper; rewrote `passed` to require every expected test ID to appear in stdout with `PASSED` marker; added regression tests in `tests/unit/test_audit_regressions.py::TestAudit1ExpectedTestsRan` |
| **2a** | Git history scrubbing removes `.git/logs`, remotes, tags, **and** unreachable commits / future references so `git log -p --all` cannot leak the fix | **BUG FOUND** (pruning alone was insufficient — reachable commits from HEAD remained visible) | `src/agentsentinel/sandbox/workspace.py`: replaced piecemeal scrub with **full `.git/` directory deletion** (the only way to guarantee `git log` cannot leak anything); updated `tests/unit/test_workspace.py::test_git_scrubbing` to assert `.git/` is gone |
| **2b** | Windows: onerror/onexc handler calls `os.chmod(path, stat.S_IWRITE)` before retry so `shutil.rmtree`/`TemporaryDirectory.cleanup()` never leaks ephemeral workspaces due to read-only `.git/objects/pack/*` files | **BUG FOUND** (no handler existed; TemporaryDirectory created without onerror) | `src/agentsentinel/sandbox/workspace.py`: added `_windows_rmtree_error_handler`; replaced `tempfile.TemporaryDirectory()` with a `_WindowsSafeTemporaryDirectory` wrapper that always cleans up with the read-only-bit-clearing onerror; added regression test `test_windows_error_handler_clears_readonly_bit` |
| **3a** | `max_output_bytes` enforced via **bounded, streaming reads** — NOT via `subprocess.run(capture_output=True)` + post-hoc truncation (which buffers gigabytes before timeout → host OOM) | **BUG FOUND** (`proc.communicate()` buffered everything before truncation) | `src/agentsentinel/sandbox/container.py`: replaced `proc.communicate()` with a **two-daemon-thread + bounded queue** reader (`_stream_pipe_to_queue` + `_bounded_stream_read`). Each pipe is drained in 16 KiB chunks; at most `max_output_bytes` are accumulated per stream; overflow is pulled off the queue and discarded; timeout fires at wall-clock regardless of pipe state; updated tests in `tests/unit/test_container.py` and `tests/adversarial/test_adversarial_m1.py` to use BytesIO streams instead of `communicate()` mocks; added regression test `test_bounded_stream_read_discards_overflow` |
| **3b** | `/workspace` mounted `:ro` (read-only) and `/tmp` mounted with `tmpfs:rw,noexec,nosuid` | **CLEAN** (already correct; verified by `test_build_docker_run_args_enforces_all_security_flags` and regression test `test_workspace_mounted_read_only_tmpfs_noexec`) | n/a |
| **4a** | CRLF (`\r\n`) normalization before parsing headers/hunks so LLM/Windows-generated diffs parse correctly | **BUG FOUND** (no CRLF normalization; headers starting with `---\r` would not match `startswith("--- ")`) | `src/agentsentinel/policy/diff_parser.py`: added explicit `diff_text.replace("\r\n", "\n").replace("\r", "\n")` normalization at the top of `UnifiedDiffParser.parse`; added regression test `test_crlf_normalized_before_parsing` |
| **4b** | `ParsedDiff.target_paths` includes BOTH source and destination paths for renames/deletes (excluding `/dev/null`) so validator blocks test renaming/deletion | **BUG FOUND** (`target_path` returned only the primary path; `/dev/null` excluded correctly but rename source was dropped) | `src/agentsentinel/policy/diff_parser.py`: added `FilePatch.target_paths` property returning both `old_path` and `new_path` (when real, not `/dev/null`); rewrote `ParsedDiff.target_paths` to flatten them with dedup; added regression tests `test_deleted_file_lists_source_path_not_dev_null` and `test_rename_includes_both_source_and_dest` |
| **5a** | Windows `git apply` uses `--ignore-space-change` to avoid CRLF vs LF "patch does not apply" failures | **BUG FOUND** (only `git apply --check` with no flags; no whitespace forgiveness) | `src/agentsentinel/policy/applier.py`: added `--ignore-space-change --whitespace=nowarn` flags; added regression test `test_git_apply_check_uses_newline_ln_and_ignore_space` verifying the flags |
| **5b** | Patch file written with `encoding="utf-8", newline="\n"` so Windows Python does not translate `\n` → `\r\n` on disk | **BUG FOUND** (no `newline="\n"` argument) | `src/agentsentinel/policy/applier.py`: added `newline="\n"` to the `NamedTemporaryFile` call and pre-normalized diff text to LF; regression test verifies `newline="\n"` is passed |
| **6** | `OpenAICompatibleClient` & `GeminiClient` do NOT retry on HTTP-200 invalid JSON / markdown / missing schema; raise `LLMGenerationError` immediately with `ModelUsage` attached; `max_transport_retries` defaults to **0** | **BUG FOUND** (5xx hardcoded 1 retry; `max_retries` defaulted to 2 and conflated rate-limit/transport retries; parse failures did NOT carry `.usage`) | `src/agentsentinel/llm/client.py`: split `max_retries` into `max_transport_retries=0` (default) and `max_rate_limit_retries=2`; added `usage` attribute to `LLMGenerationError`; rewrote `_parse_llm_response` to build `ModelUsage` first and attach it to every parse-failure exception; updated both client loops so HTTP 200 parse/schema failures **never retry** (they consumed tokens); fixed test in `tests/unit/test_llm_client.py` to use new field name; added regression tests `test_default_transport_retries_is_zero`, `test_invalid_json_does_not_retry_and_carries_usage`, `test_missing_schema_fields_does_not_retry` |
| **7** | `prompts.py` refuses to read files outside workspace root (blocks `../` traversal and absolute paths from reaching `_read_file_safe`) | **CLEAN** (existing `is_relative_to` check caught post-resolve escapes, but added belt-and-braces pre-checks) | `src/agentsentinel/llm/prompts.py`: added explicit rejection of absolute paths (`"/"`, `"\\"` prefixes) and literal `".."` components *before* filesystem join; explicit `.git/` directory segment rejection even if allowlisted; added regression tests `test_dotdot_traversal_rejected` and `test_absolute_path_rejected` |
| **8** | `pricing.py` returns `cost_usd=None` for unknown models (never `0.0`); negative token counts raise `ValueError` | **CLEAN** (already correct; regression tests added) | `src/agentsentinel/llm/pricing.py` — verified; added regression tests `test_unknown_model_returns_none_not_zero` and `test_negative_tokens_raise_value_error` |

---

## Tests & Static Analysis

After applying all fixes:

| Tool | Command | Result |
|---|---|---|
| pytest | `python -m pytest -v --ignore=tests/integration` | **256 passed** (21 new audit regression tests added) |
| ruff | `python -m ruff check src tests` | **All checks passed!** |
| mypy | `python -m mypy --strict src` | **Success: no issues found in 20 source files** |

(Note: `tests/integration/test_docker_live_m1.py` is excluded because it requires a running Docker daemon with the `agentsentinel-runner:py311` image preloaded; it is a live-container integration test, not a unit/adversarial test.)

---

## Files Modified

**Source:**
- `src/agentsentinel/domain/models.py`
- `src/agentsentinel/sandbox/workspace.py`
- `src/agentsentinel/sandbox/container.py`
- `src/agentsentinel/policy/diff_parser.py`
- `src/agentsentinel/policy/applier.py`
- `src/agentsentinel/llm/client.py`
- `src/agentsentinel/llm/exceptions.py`
- `src/agentsentinel/llm/prompts.py`

**Tests:**
- `tests/unit/test_audit_regressions.py` (new — 21 regression tests)
- `tests/unit/test_container.py` (reworked mocks for streaming reader)
- `tests/unit/test_workspace.py` (strengthened git scrubbing assertion)
- `tests/unit/test_llm_client.py` (renamed `max_retries` → `max_rate_limit_retries`)
- `tests/adversarial/test_adversarial_m1.py` (reworked mocks for streaming reader)

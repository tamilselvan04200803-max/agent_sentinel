# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M3
- **Current Sub-Task:** COMPLETE — Milestone 3 (LLM Client, Pricing/Cost Accounting, Prompt Builder) & M1/M2 Gap Closures
- **Milestone Gate Status:** VERIFIED_READY_FOR_REVIEW

## Completed & Verified Components

| File | Description | Verified by |
|---|---|---|
| `pyproject.toml` | Strict ruff, mypy, pytest configuration (`-p no:schemathesis`, `--import-mode=importlib`) | `pytest` and `ruff` passing cleanly |
| `Dockerfile.runner` | Pre-built container runner image `agentsentinel-runner:py311` based on `python:3.11-slim` with `pytest==8.4.2` | Docker build and live execution |
| `src/agentsentinel/sandbox/container.py` | Hardened Docker runner with `:ro` workspace mount, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, Windows POSIX path translation (`as_posix()`), deterministic naming (`agentsentinel-<hex>`), `PYTEST_ADDOPTS` cache redirect to writable tmpfs, and guaranteed container reaping in `finally` | `tests/unit/test_container.py`, `tests/adversarial/test_adversarial_m1.py`, `tests/integration/test_docker_live_m1.py` |
| `src/agentsentinel/policy/applier.py` | Deterministic patch application routine (`apply_validated_patch`): parses via M2 diff parser, checks policy via M2 validator, creates isolated workspace clone, runs `git apply --check` dry-run, applies hunks, verifies post-apply symlink containment (`is_relative_to`), atomic writes | `tests/unit/test_applier.py`, `tests/integration/test_docker_live_m1.py` |
| `src/agentsentinel/policy/diff_parser.py` | Formal unified diff parser & canonicalizer (`ParsedDiff`, `FilePatch`, `Hunk`, `HunkLine`), extracting both old/new paths plus rename/copy headers | `tests/unit/test_diff_parser.py`, `tests/adversarial/test_adversarial_m2.py` |
| `src/agentsentinel/policy/validator.py` | Multi-tier policy validator enforcing allowlist, test file bans (`tests/**`), infrastructure bans (`Dockerfile*`, `pyproject.toml`), and symlink escape detection (`is_relative_to`) | `tests/unit/test_validator.py`, `tests/adversarial/test_adversarial_m2.py` |
| `src/agentsentinel/llm/pricing.py` | Immutable token accounting schemas (`ModelUsage`, `ModelPrice`, `CostEstimate`) and dated registry with 14+ models. Strictly enforces that unpriced or unknown models return `None` (NEVER `0.0`) | `tests/unit/test_pricing.py`, `tests/adversarial/test_adversarial_m3.py` |
| `src/agentsentinel/llm/prompts.py` | Deterministic prompt builder assembling `CaseSpec`, execution failures (tracebacks), and line-numbered source code. Enforces security boundaries: blocks `.git`, files outside `allowed_edit_paths`, sanitizes triple-backtick injections, truncates large files with markers | `tests/unit/test_prompts.py`, `tests/adversarial/test_adversarial_m3.py` |
| `src/agentsentinel/llm/exceptions.py` | Typed hierarchy for LLM failures (`LLMError`, `LLMGenerationError`, `LLMTimeoutError`, `LLMRateLimitError`, `LLMAuthenticationError`, `LLMServerError`) | `tests/unit/test_llm_client.py`, `tests/adversarial/test_adversarial_m3.py` |
| `src/agentsentinel/llm/client.py` | `LLMClient` Protocol (structural typing) + `OpenAICompatibleClient` and `GeminiClient` REST implementations using standard library `urllib.request`. Structured JSON output parsing into `PatchProposal` with exponential backoff retry on 429/5xx | `tests/unit/test_llm_client.py`, `tests/adversarial/test_adversarial_m3.py` |
| `tests/integration/test_docker_live_m1.py` | 6 live integration tests against Docker Desktop WSL2 running real `python -m pytest -q` in `--network=none` with `:ro` workspace, testing broken normalizer fail, fixed normalizer pass, read-only VFS enforcement, network isolation, timeout reaping, and full M2 patch transition from failed to passed | All 6 tests passing live |
| `STATE.md` | Continuous context anchor and ADR record | Maintained on every step |

**Milestone Verification Evidence:**
- **M1 Live Docker Hardening Status:** `VERIFIED_LIVE_DOCKER`
  - Real Docker Daemon Execution: All 6 live integration tests in `tests/integration/test_docker_live_m1.py` passed against Docker Desktop (WSL2 engine).
  - Pytest in Container: Uses `agentsentinel-runner:py311` with real `pytest` pre-baked; no reliance on stdlib `unittest`.
  - Workspace `:ro` Mount: Container mounts workspace as `:ro`, verified by direct write failure test. Pytest cache redirected to `/tmp/.pytest_cache` in RAM-backed tmpfs.
  - Normalizer transition: Broken fixture fails (`ExitCode.TESTS_FAILED`), patched fixture passes (`ExitCode.OK`).
- **M2 Patch Applier & Policy Engine:** `VERIFIED`
  - `apply_validated_patch` applies valid diff to fresh workspace clone, verifies `git apply --check`, and passes container pytest.
- **M3 LLM Client, Pricing & Prompts:** `VERIFIED`
  - Full Test Suite: **240 passed, 1 skipped** (Windows unprivileged symlink test) in 8.28s.
  - Linter: `ruff check src tests` (All checks passed, 0 errors).
  - Typecheck: `mypy --strict src` (Success: no issues found in 20 source files).
  - Adversarial Suite (`test_adversarial_m3.py`): 9 tests covering prompt injection, unknown model cost integrity, malformed JSON, markdown fences, empty diffs, token arithmetic invariants, and out-of-bounds line numbers.

## Active Blockers / Pending Human Verification
- None. Milestone 3 is complete, fully tested, and passing all static and dynamic quality gates. Ready for M4 unlock.

## Next Immediate Engineering Action
- **M4 Unlock:** Implement Orchestrator & Evaluation Loop (`src/agentsentinel/orchestrator/runner.py`, `evidence.py`, multi-attempt repair loop, and end-to-end benchmark evaluation).

## Architectural Decision Log (ADR)
- [2026-10-18 M0-1] Decision: Use `@dataclass(frozen=True)` for all domain models | Rationale: Immutability prevents accidental mutation of shared state across orchestrator nodes; hashable for dedup sets | Tradeoff: Cannot use default_factory on mutable fields — use `tuple` not `list` everywhere.
- [2026-10-18 M0-2] Decision: Single `AgentSentinelError` root → typed sub-hierarchy | Rationale: `except AgentSentinelError` gives a clean catch-all at the orchestrator boundary while preserving semantic specificity | Tradeoff: More exception classes to maintain.
- [2026-10-18 M0-3] Decision: Pin all dev deps in `pyproject.toml` extras, not a separate requirements.txt | Rationale: Single source of truth; `pip install -e ".[dev]"` reproducible across CI and local | Tradeoff: Slightly less familiar to teams using requirements.txt.
- [2026-10-18 M0-4] Decision: `ExitCode` enum derived from `pytest`'s actual integer semantics | Rationale: The orchestrator must distinguish FAIL (1) from NO_TESTS_COLLECTED (5) — treating 5 as success is a reward-hacking vector | Tradeoff: Enum values must be kept in sync with pytest releases.
- [2026-10-18 M0-5] Decision: `metadata` field on `CaseSpec` uses `tuple[tuple[str,str],...]` not `MappingProxyType` | Rationale: `MappingProxyType` is not hashable, breaking `CaseSpec`'s use in dedup sets and `frozenset` in the orchestrator | Tradeoff: Lose O(1) key lookup by name — callers must `dict(spec.metadata)` to convert if needed.
- [2026-10-18 M0-6] Decision: Build backend changed from `setuptools.backends.legacy:build` to `setuptools.build_meta` | Rationale: The `backends.legacy` submodule does not exist in older setuptools versions; `build_meta` is the stable PEP 517 entry point since setuptools 40 | Tradeoff: None.
- [2026-10-18 M0-7] Decision: CaseSpec metadata canonicalization in `__post_init__` | Rationale: Guarantees deterministic `hash()` and equality across CaseSpecs constructed with differing key orders, and guards against duplicate keys | Tradeoff: Minor allocation overhead on construction.
- [2026-10-18 M1-1] Decision: Hardened container execution runner uses strict argument isolation and streaming pipe cap | Rationale: Enforcing `--network=none`, `--read-only`, `--tmpfs /tmp`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit=64`, `--memory=512m` protects host, while 256KB stream truncation prevents host OOM | Tradeoff: Long stdout traces are truncated with explicit metadata flag.
- [2026-10-18 M1-2] Decision: Ephemeral workspace git history scrubbing removes reflogs, remotes, and tags | Rationale: Prevents an LLM agent from cheating by running `git log` or inspecting dangling git commits inside the container to uncover reference patches | Tradeoff: Loss of git history inside the ephemeral evaluation workspace.
- [2026-10-18 M1-3] Decision: Windows-to-Linux path normalization & pytest tmpfs cache redirection | Rationale: Binding `C:/...` ensures Docker daemon compatibility on Windows, while `PYTEST_ADDOPTS=-o cache_dir=/tmp/.pytest_cache` prevents pytest from failing on `--read-only` rootfs | Tradeoff: Cache does not persist across container invocations.
- [2026-10-18 M1-4] Decision: Container runner uses custom pre-baked image `agentsentinel-runner:py311` with pytest 8.4.2 | Rationale: Python slim images lack pytest; runner container cannot download packages at runtime due to `--network=none` isolation | Tradeoff: One-time build step required on deployment.
- [2026-10-18 M1-5] Decision: Workspace volume mounted as `:ro` (read-only) during test execution | Rationale: Guarantees via Linux VFS that running test suites or untrusted patches cannot tamper with files on disk; cache redirected to `/tmp` | Tradeoff: Workspace changes require fresh ephemeral container run.
- [2026-10-18 M2-1] Decision: Custom formal line-based parser in `diff_parser.py` rather than third-party parsing libraries | Rationale: Eliminates untrusted external parser dependencies and guarantees exact rejection of binary diffs and malformed hunk lines | Tradeoff: Custom parsing code to maintain.
- [2026-10-18 M2-2] Decision: Multi-tier path validation in `validator.py` (allowlist + test file ban + infrastructure ban + symlink `is_relative_to`) | Rationale: Blocks path traversal (`../../`), reward-hacking via test tampering, CI/environment poisoning, and symlink breakout to host secrets | Tradeoff: Rigid enforcement requires any valid edited path to be explicitly enumerated in `allowed_edit_paths`.
- [2026-10-18 M2-3] Decision: Safe patch applier (`applier.py`) provisions fresh workspace snapshot and executes dry-run validation prior to application | Rationale: Prevents partial writes, verifies patch compatibility via `git apply --check`, and re-checks post-apply symlink containment before container execution | Tradeoff: Duplication of workspace directory on disk.
- [2026-10-18 M3-1] Decision: `LLMClient` implemented as runtime-checkable `typing.Protocol` rather than ABC | Rationale: Allows structural subtyping so mock/stub providers in tests and custom production backends do not require inheritance coupling | Tradeoff: Mypy checks structure only, cannot enforce inheritance hierarchies.
- [2026-10-18 M3-2] Decision: LLM clients use Python stdlib `urllib.request` instead of heavyweight external SDKs | Rationale: Avoids external SDK dependency drift, pinned version conflicts, and keeps dependencies minimal while enforcing strict timeout controls | Tradeoff: Manual parsing of HTTP response status and JSON payloads.
- [2026-10-18 M3-3] Decision: Unpriced or unknown model costs are strictly returned as `None`, NEVER coerced to `0.0` | Rationale: Silent zero-cost aliasing would corrupt benchmark accounting and cost auditing; unpriced models must be tracked explicitly as unknown | Tradeoff: Downstream aggregation logic must handle optional float types.
- [2026-10-18 M3-4] Decision: Prompt builder strips triple backticks and enforces strict file allowlists without `.git` | Rationale: Prevents prompt injection attacks that break out of markdown code blocks or leak sensitive version control / reference solution metadata | Tradeoff: Code containing literal triple-backticks is sanitized with single quotes.

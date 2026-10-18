# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M2
- **Current Sub-Task:** COMPLETE — Milestone 2 Policy Engine & Milestone 1 Real-Docker Hardening
- **Milestone Gate Status:** VERIFIED_READY_FOR_REVIEW

## Completed & Verified Components

| File | Description | Verified by |
|---|---|---|
| `pyproject.toml` | Strict ruff, mypy, pytest configuration (`-p no:schemathesis`, `--import-mode=importlib`) | `pytest` and `ruff` passing cleanly |
| `src/agentsentinel/sandbox/container.py` | Hardened rootless/unprivileged Docker runner with Windows POSIX path conversion (`as_posix()`), deterministic naming (`agentsentinel-<hex>`), `PYTEST_ADDOPTS` cache redirect to writable tmpfs, and guaranteed container reaping in `finally` | `tests/unit/test_container.py`, `tests/adversarial/test_adversarial_m1.py` |
| `tests/integration/test_docker_live_m1.py` | Real Docker engine integration tests with dynamic daemon reachability detection (`is_docker_daemon_running()`) | Executed in integration suite (4 skipped gracefully when daemon offline, live when daemon online) |
| `src/agentsentinel/policy/diff_parser.py` | Formal unified diff parser & canonicalizer (`ParsedDiff`, `FilePatch`, `Hunk`, `HunkLine`), rejecting binary patches | `tests/unit/test_diff_parser.py`, `tests/adversarial/test_adversarial_m2.py` |
| `src/agentsentinel/policy/validator.py` | Policy validator enforcing allowlist, reward-hacking test file blockers, infrastructure file protection, and symlink escape detection (`is_relative_to`) | `tests/unit/test_validator.py`, `tests/adversarial/test_adversarial_m2.py` |
| `src/agentsentinel/policy/__init__.py` | Export symbols for diff parser and policy validator | Package import verification |
| `tests/unit/test_diff_parser.py` | 7 unit tests for unified diff parsing | 168 passed in full suite |
| `tests/unit/test_validator.py` | 6 unit tests for policy validation rules | 168 passed in full suite |
| `tests/adversarial/test_adversarial_m2.py` | Adversarial security tests for path traversal, test file evasion, infra file protection, corrupt hunks, binary diff variants | 168 passed in full suite |
| `STATE.md` | Continuous context anchor and ADR record | Maintained on every step |

**Milestone Verification Evidence:**
- **M1 Live Docker Hardening Status:** `VERIFIED`
  - Container naming: `--name agentsentinel-<hex>`.
  - Windows mount normalization: `workspace_host_path.resolve().as_posix()`.
  - Pytest cache isolation: `-e PYTEST_ADDOPTS=-o cache_dir=/tmp/.pytest_cache`.
  - Integration suite: [`tests/integration/test_docker_live_m1.py`](file:///c:/Users/tamil/Downloads/agentsenitnel/agent_sentinel/tests/integration/test_docker_live_m1.py).
- **M2 Verification Status:** `VERIFIED_READY_FOR_REVIEW`
  - Test Suite: 168 passed, 5 skipped (4 integration when daemon offline, 1 Windows symlink privilege check) in 1.16s.
  - Linter: `ruff check src tests` (All checks passed).
  - Typecheck: `mypy --strict src` (Success: no issues found in 15 source files).

## Active Blockers / Pending Human Verification
- None for Milestone 2. Awaiting human operator review of M2 policy engine before unlocking Milestone 3 (`llm/client.py` and `llm/prompts.py`).

## Next Immediate Engineering Action
- **M3 Unlock:** Implement `src/agentsentinel/llm/client.py` (Structured output LLM client with strict timeout, retry policy, and token/cost accounting) and `src/agentsentinel/llm/prompts.py` (Context assembly combining failing tracebacks with allowed source slices).

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
- [2026-10-18 M2-1] Decision: Custom formal line-based parser in `diff_parser.py` rather than third-party parsing libraries | Rationale: Eliminates untrusted external parser dependencies and guarantees exact rejection of binary diffs and malformed hunk lines | Tradeoff: Custom parsing code to maintain.
- [2026-10-18 M2-2] Decision: Multi-tier path validation in `validator.py` (allowlist + test file ban + infrastructure ban + symlink `is_relative_to`) | Rationale: Blocks path traversal (`../../`), reward-hacking via test tampering, CI/environment poisoning, and symlink breakout to host secrets | Tradeoff: Rigid enforcement requires any valid edited path to be explicitly enumerated in `allowed_edit_paths`.

# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M1
- **Current Sub-Task:** COMPLETE — Milestone 1 Hardened Container Sandbox & Workspace Provisioner
- **Milestone Gate Status:** VERIFIED_READY_FOR_REVIEW

## Completed & Verified Components

| File | Description | Verified by |
|---|---|---|
| `pyproject.toml` | Strict ruff, mypy, pytest configuration (`-p no:schemathesis`, `--import-mode=importlib`) | `pytest` runs cleanly without manual CLI flags; `ruff` and `mypy --strict` passing |
| `src/agentsentinel/domain/models.py` | Immutable schemas with lexicographically canonicalized metadata & duplicate key rejection | `tests/unit/test_models.py::TestCaseSpec::test_metadata_canonicalization_and_hash_equality` |
| `src/agentsentinel/domain/exceptions.py` | Full typed exception hierarchy | `tests/unit/test_exceptions.py` |
| `src/agentsentinel/domain/exit_codes.py` | Strict pytest ExitCode classification (0-5, broken harness distinction) | `tests/unit/test_exit_codes.py` |
| `src/agentsentinel/sandbox/workspace.py` | Ephemeral workspace provisioning, safe copying, atomic writes, git reflog/remote/tag scrubbing | `tests/unit/test_workspace.py` |
| `src/agentsentinel/sandbox/container.py` | Hardened rootless/unprivileged Docker runner enforcing `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, pids/memory/cpu limits, output stream cap (256KB), guaranteed cleanup | `tests/unit/test_container.py`, `tests/adversarial/test_adversarial_m1.py` |
| `tests/fixtures/normalizer.py` | M0 target workload fixture with buggy, fixed, and patch diff representations | `tests/adversarial/test_adversarial_m1.py::TestNormalizerFixtureM1Reproduction` |
| `tests/adversarial/test_adversarial_m1.py` | 7 adversarial security boundary tests (network isolation, read-only rootfs, privilege dropping, resource limits, secret isolation, timeout kill/rm, output flood truncation) | 131 passed in test suite |
| `STATE.md` | Continuous context anchor and ADR record | Maintained on every step |

**Verified Test Run:**
```
.venv/Scripts/python -m pytest tests/ -v
131 passed in 0.38s    exit code: 0
```

## Active Blockers / Pending Human Verification
- None for Milestone 1. Awaiting human operator review and sign-off on M1 evidence before unlocking Milestone 2 (`policy/diff_parser.py` and `policy/validator.py`).

## Next Immediate Engineering Action
- **M2 Unlock:** Implement `src/agentsentinel/policy/diff_parser.py` (unified diff parser, chunk normalizer, path extractor) and `src/agentsentinel/policy/validator.py` (strict allowlist enforcement, symlink escape checks, test-file modification blocker).

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

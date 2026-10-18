# AGENTSENTINEL EXECUTION STATE

- **Current Active Milestone:** M0
- **Current Sub-Task:** COMPLETE — M0 scaffold verified
- **Milestone Gate Status:** VERIFIED_READY_FOR_REVIEW

## Completed & Verified Components

| File | Description | Verified by |
|---|---|---|
| `pyproject.toml` | Strict ruff/mypy/pytest config, pinned dev deps | `pip install -e ".[dev]"` succeeded |
| `src/agentsentinel/__init__.py` | Package init, `__version__` via importlib.metadata | `109 passed` |
| `src/agentsentinel/domain/exceptions.py` | Full exception hierarchy (12 classes, all derive AgentSentinelError) | `tests/unit/test_exceptions.py` — 16 tests |
| `src/agentsentinel/domain/exit_codes.py` | ExitCode enum + `classify()`, `is_harness_broken()`, `is_genuine_verdict()` | `tests/unit/test_exit_codes.py` — 20 tests |
| `src/agentsentinel/domain/models.py` | 4 frozen dataclasses: CaseSpec, PatchProposal, ExecutionResult, EvidenceBundle | `tests/unit/test_models.py` — 24 tests |
| `src/agentsentinel/domain/__init__.py` | Clean re-exports of all domain symbols | Import-level verified |
| `tests/conftest.py` | Shared fixtures: valid_case_spec, valid_patch, baseline_result, passing_result | Used by all test files |
| `tests/unit/test_exit_codes.py` | 20 unit tests for ExitCode semantics | `109 passed, 0 failed` |
| `tests/unit/test_exceptions.py` | 16 unit tests for exception hierarchy | `109 passed, 0 failed` |
| `tests/unit/test_models.py` | 24 unit tests for all four domain models | `109 passed, 0 failed` |
| `tests/adversarial/test_adversarial_m0.py` | 49 adversarial tests: path traversal, null bytes, 10MB diffs, reward-hacking guard, output floods, out-of-range codes | `109 passed, 0 failed` |
| `STATE.md` | Live execution state (this file) | Always current |

**Verified test run:**
```
pytest tests/ -v --tb=short -p no:schemathesis
109 passed, 2 warnings in 0.49s    exit code: 0
```
*(The 2 warnings are harmless PytestCollectionWarnings about the exception class `TestFileModificationError` — its name begins with "Test" but has a constructor, so pytest skips it; this is expected behaviour.)*

## Active Blockers / Pending Human Verification

- ⚠️ **`schemathesis` global conflict:** `schemathesis==4.27.5` installed globally requires `pytest>=9` but we pin `pytest<9,>=8.2`. Current workaround: `-p no:schemathesis`. Add this flag to `[tool.pytest.ini_options] addopts` or uninstall schemathesis from the global Python to make `python -m pytest` work without the flag. **Human must decide.**
- Run full test suite after human resolves schemathesis conflict and paste exit code.

## Next Immediate Engineering Action

- **M1 unlock:** Implement `sandbox/container.py` (rootless Docker runner with `--network=none`, `--read-only`, `--pids-limit`, `--memory`) and `sandbox/workspace.py` (ephemeral workspace provisioning, git history scrubbing). Gate on: Docker daemon reachable from CI, `--rootless` support verified.

## Architectural Decision Log (ADR)

- [2026-10-18 M0-1] Decision: Use `@dataclass(frozen=True)` for all domain models | Rationale: Immutability prevents accidental mutation of shared state across orchestrator nodes; hashable for dedup sets | Tradeoff: Cannot use default_factory on mutable fields — use `tuple` not `list` everywhere.
- [2026-10-18 M0-2] Decision: Single `AgentSentinelError` root → typed sub-hierarchy | Rationale: `except AgentSentinelError` gives a clean catch-all at the orchestrator boundary while preserving semantic specificity | Tradeoff: More exception classes to maintain.
- [2026-10-18 M0-3] Decision: Pin all dev deps in `pyproject.toml` extras, not a separate requirements.txt | Rationale: Single source of truth; `pip install -e ".[dev]"` reproducible across CI and local | Tradeoff: Slightly less familiar to teams using requirements.txt.
- [2026-10-18 M0-4] Decision: `ExitCode` enum derived from `pytest`'s actual integer semantics | Rationale: The orchestrator must distinguish FAIL (1) from NO_TESTS_COLLECTED (5) — treating 5 as success is a reward-hacking vector | Tradeoff: Enum values must be kept in sync with pytest releases.
- [2026-10-18 M0-5] Decision: `metadata` field on `CaseSpec` uses `tuple[tuple[str,str],...]` not `MappingProxyType` | Rationale: `MappingProxyType` is not hashable, breaking `CaseSpec`'s use in dedup sets and `frozenset` in the orchestrator | Tradeoff: Lose O(1) key lookup by name — callers must `dict(spec.metadata)` to convert if needed.
- [2026-10-18 M0-6] Decision: Build backend changed from `setuptools.backends.legacy:build` to `setuptools.build_meta` | Rationale: The `backends.legacy` submodule does not exist in older setuptools versions; `build_meta` is the stable PEP 517 entry point since setuptools 40 | Tradeoff: None.

# AgentSentinel

AgentSentinel is a deterministic, sandboxed, evidence-first automated software
repair engine. It proposes a bounded number of patches with an LLM, validates
each patch against a strict policy, applies it only with `git apply`, verifies
it in an isolated execution environment, and requires explicit human
approval bound to the verification evidence before an evidence bundle can be exported.

The design goal is not to claim that an LLM is usually right. The goal is to
make every repair attempt reproducible, attributable, cost-accounted, and
auditable — including the failures.

## Architecture

```text
CaseSpec
  -> baseline reproduction gate (tests must fail for the declared reason)
  -> AST fault localization (Hop-0 and Hop-1 repository call frames)
  -> sanitized prompt generation (BiDi / injection strip)
  -> LLM patch proposal
  -> policy validation (allowlist, diff structure, protected paths)
  -> patch hygiene check (BiDi, zero-width, non-ASCII ids, mixed indentation)
  -> Tier-1 canonical-diff dedup
  -> unique-preimage hunk-coordinate healing, then strict git apply validation
  -> Tier-2 Python AST equivalence dedup (rejects semantic no-ops)
  -> M8 anti-overfitting & anti-reflection guard (constant-folding test literal match)
  -> M9 structural bloat, debugger and exception-swallowing checks
  -> M11 public call-signature preservation
  -> sandbox verification (fresh workspace per attempt, pinned image digest)
  -> M12 categorized, sanitized retry feedback on failure
  -> AWAITING_HUMAN_APPROVAL on passing verification
  -> approve / reject using sha256(diff_hash + image_digest + post_patch_hash)
  -> deterministic evidence bundle export (APPROVED runs only)
```

### Milestones

| Milestone | Scope | Status |
|---|---|---|
| M0 | Domain models, exit codes, fixtures | Complete |
| M1 | Hardened sandbox and workspace isolation | Complete |
| M2 | Diff parsing, patch policy, and `git apply` applier | Complete |
| M3 | LLM clients, pricing, and prompt construction | Complete |
| M4 | Bounded repair state machine and SQLite checkpoints | Complete |
| M5 | Contamination-aware evaluation harness | Complete |
| M6 | Production CLI and deterministic evidence exporter | Complete |
| M7 | Deterministic AST fault localizer & live image digest pinning | Complete |
| M8 | Anti-overfitting, anti-poisoning & anti-reflection security kernel | Complete |
| M9A | File-aware, unique-preimage hunk-coordinate healing | Complete |
| M9B | Structural bloat/debug/exception guards and hunk-subset generation | Complete |
| M10 | Bounded differential AST mutant generation; legacy API retained | Complete |
| M11 | Public symbol, signature and descriptor preservation | Complete |
| M12 | Typed failure taxonomy and sanitized per-run retry feedback | Complete |

### M9-M12 interfaces and limits

`generate_minimal_hunk_subsets(raw_diff)` emits deterministic single-hunk and
unique drop-one candidates with rebased offsets. It does not run a test oracle
or establish ddmin 1-minimality. Structural guards run even when no assertion
literals are available; cyclomatic growth is limited to +5 by default.
New bare handlers are rejected. Broad exception handlers must have statically
recognized raising or explicit non-None return paths; this is a conservative
syntax policy, not proof of semantic correctness.

`generate_differential_patch_mutants(file_path, pre_source, post_source,
max_mutants=3)` returns frozen `DifferentialPatchMutant` records with
`file_path`, `function_name`, `mutation_description`, and `mutated_source`.
It operates on changed or newly added function bodies, treats nested scopes
separately, and validates generated syntax without executing it. Zero budget
returns no mutants, negative budgets raise `ValueError`, and invalid source
raises `SyntaxError`. The older whole-source `generate_patch_mutants` API and
`PatchMutant` record remain available. Mutants are not automatically executed
and their generation does not establish test adequacy.

`verify_public_api_compatibility(file_path, pre_source, post_source)` preserves
explicit public functions/classes, directly declared public methods and
constructors, defaults, calling conventions, variadics and descriptor binding.
Optional additions are allowed; existing `*args` payloads cannot be captured by
new positional parameters. Dynamic/inherited APIs, arbitrary decorators,
annotations, default-value semantics and behavioral contracts are outside the
static model. `verify_not_overfitted(..., enforce_api_contract=False)` is an
explicit opt-out for this guard; the default is `True`.

`classify_attempt_failure(error, execution_result)` returns one of seven
`FailureCategory` values and fixed corrective guidance. Typed exceptions take
precedence over untrusted output. Retry diagnostics are bounded and sanitized,
and feedback is isolated by run ID. Feedback is held in memory for the active
process; the existing SQLite audit schema is unchanged. Transport and
infrastructure lifecycle rules remain separate from repair classification.

Approval records retain the existing unkeyed SHA-256 binding of the diff,
image digest and execution-result hash. This is **not keyed HMAC authentication**
and does not establish signer identity against an actor able to rewrite the
stored record. Key management and approval-record migration are deferred.

## Safety and correctness invariants

- A run is bounded by `max_attempts`; malformed proposals, policy violations,
  patch-application failures, duplicates, and test failures consume attempts.
- HTTP 429 and Docker infrastructure failures terminate as
  `INFRASTRUCTURE_FAILURE` without being misreported as model repair failures.
- Duplicate and AST-equivalent no-op patches are rejected before another
  sandbox verification run.
- Every attempt uses a fresh workspace.
- Baseline reproduction is mandatory. If the declared failing tests do not
  fail at baseline, the run stops before an LLM repair attempt.
- A passing patch does not become approved automatically in normal CLI use.
  A human must present the exact diff hash, image digest, and post-patch
  result hash returned for the pending approval.
- Evidence can be exported only from `APPROVED` state.

## Installation

Python 3.11 or newer is required.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
agentsentinel --help
```

Docker is required for the hardened production sandbox path. Offline unit
tests and the local benchmark runner can execute without a Docker daemon, but
that local execution mode is a test harness convenience — it is not a security
boundary.

## CLI usage

The CLI stores durable run state in SQLite. A run can therefore be inspected,
approved, rejected, or exported by separate process invocations.

### Start a run

```bash
agentsentinel run \
  --case-spec case.json \
  --db runs.db \
  --max-attempts 3 \
  --provider openai
```

Set the provider API key in the environment (`AGENTSENTINEL_LLM_API_KEY` for
OpenAI-compatible providers or `AGENTSENTINEL_GEMINI_API_KEY` for Gemini).
`--provider mock` is intended for dry runs and tests.

The `CaseSpec` JSON contains `case_id`, `repo_url`, `base_commit`,
`test_command`, `allowed_edit_paths`, and `failing_test_ids`. It may also
contain `repo_source_path` pointing to a local scrubbed checkout; otherwise
the orchestrator resolves the source workspace from the current working
directory, so run the command from the target checkout.

When a patch passes verification, `run` exits with status `2` and prints the
pending approval binding. Do not edit that binding: it is the cryptographic
link between the exact diff, container image, and passing test result.

### Inspect a run

```bash
agentsentinel status --run-id <run_id> --db runs.db
```

### Approve a run

Copy the three values from the pending approval record:

```bash
agentsentinel approve \
  --run-id <run_id> \
  --approver-id alice \
  --diff-hash <sha256> \
  --image-digest <image_digest> \
  --post-patch-result-hash <sha256> \
  --db runs.db
```

Any tampered hash fails approval and leaves the run unapproved.

### Reject a run

```bash
agentsentinel reject \
  --run-id <run_id> \
  --reviewer-id bob \
  --reason "insufficient regression coverage" \
  --db runs.db
```

### Export evidence

Only an approved run can be exported:

```bash
agentsentinel export \
  --run-id <run_id> \
  --output-dir evidence \
  --db runs.db
```

This creates:

```text
evidence/<run_id>/
  evidence.json   # canonical sorted JSON, CaseSpec, results, ledger, bundle_hash
  approved.patch  # exact approved unified diff, LF newlines
  REPORT.md       # human-auditable approval, failure, test, token/cost report
```

## Benchmark methodology (M5)

The benchmark harness is contamination-aware and admission-gated. A case is
not counted merely because it was submitted.

For every `BenchmarkCase` the harness:

1. Creates a clean workspace, applies only `test_patch`, and requires the
   baseline to fail with pytest exit code `1`.
2. Creates a second clean workspace, applies `test_patch` plus
   `reference_fix_patch`, and requires all tests to pass with exit code `0`.
3. Records excluded cases in `exclusion_log`; excluded cases are never
   silently omitted.
4. Runs only admitted cases through `RepairStateMachine`.
5. Reports prep latency (admission) separately from repair latency.
6. Reports infrastructure failures separately from model/test failures.
7. Never coerces unknown model cost to zero. If any admitted run has unknown
   cost, `known_cost_usd_total` is `null` and the report flags partial cost.
8. Marks public historical cases with `is_public_historical_commit`, because
   such cases may be present in LLM pre-training data and repair rates on them
   may overstate generalisation.

`reference_fix_patch` is trusted benchmark data used only by admission Gate 2.
It is never passed to `RepairStateMachine` or `PromptBuilder`.

### Frozen offline fixtures

Three small deterministic fixtures live in
`tests/fixtures/benchmark_cases/`:

- `case_01_normalizer` — whitespace normalisation bug
- `case_02_boundary_off_by_one` — pagination slice off-by-one bug
- `case_03_none_coalescing` — `value or default` falsy-value bug

Run a benchmark directory with:

```bash
agentsentinel benchmark \
  --suite-dir tests/fixtures/benchmark_cases \
  --output-dir benchmark-out \
  --db benchmark.db \
  --provider mock
```

The mock provider is not expected to repair these cases; use a real provider
or a programmatic `BenchmarkHarness(llm_factory=...)` for measured repair
rates. `compare_baseline_vs_bounded_retry` compares `max_attempts=1` with a
bounded retry budget under the same cases and reports deltas in repair rate,
LLM calls, tokens, and latency.

## Development and verification

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy --strict src
.\.venv\Scripts\python.exe -m pytest -p no:schemathesis -v
```

Verified on 2026-10-26 with Python 3.13.7 and live Docker Desktop:
**566 passed, 1 skipped**, all seven live Docker tests passed, Ruff clean,
and strict mypy clean across 39 source files. The skip is the expected
unprivileged Windows symlink test. The release run disabled pytest's cache and
used a dedicated `--basetemp` directory to avoid Windows permission conflicts.
The final independent review findings were reproduced and fixed before this run.

## Honest limitations

- Public historical benchmark cases may be contaminated by LLM pre-training;
  AgentSentinel flags them rather than pretending the problem away.
- Unknown-priced models produce partial cost reporting, not invented zeroes.
- Local/offline execution is for deterministic tests. Production repair should
  use the hardened Docker sandbox.
- AgentSentinel verifies declared tests. It cannot prove that an incomplete
  test suite captures every requirement, which is why human approval remains
  a hard gate.

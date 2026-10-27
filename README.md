# AgentSentinel

AgentSentinel is a deterministic, sandboxed, evidence-first automated software
repair engine. It proposes a bounded number of patches with an LLM, validates
each patch against a strict policy, applies it only with `git apply`, verifies
it in an isolated execution environment, and requires explicit human
approval bound to the verification evidence before an evidence bundle can be exported.

The standalone `agentsentinel ci-gate` command audits pull-request diffs without
LLM calls, Docker, network access or executing repository code.

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
  -> optional M13A passing-subset search, then mutation adequacy probing
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
| M13A | Live post-pass subset minimization and mutation adequacy evidence | Complete |
| M13B | Line-accurate AST skeletonization and tiered prompt context | Complete |
| M13C | Differential second-order AST evasion guards and symbolic de-obfuscation | Complete |
| M14 | Canonical JCS/DSSE PAE provenance and optional HMAC offline verification | Complete |
| M15 | Standalone read-only PR audit with complete staged diagnostics | Complete |

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
`PatchMutant` record remain available. Generation alone does not establish test
adequacy; M13A optionally evaluates these mutants in the sandbox.

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
M14 exports additionally support HMAC-SHA256 over domain-separated DSSE PAE and
RFC 8785 canonical JSON. Configure `AGENTSENTINEL_SIGNING_KEY` and verify with
`agentsentinel verify-bundle --bundle-dir <path> --require-keyed`; legacy internal
approval records keep their original format. See STATE.md for the trust boundaries.

### M13A post-pass verification

Construct `RepairStateMachine(..., enable_ddmin_minimization=True,
enable_mutation_probe=True, max_mutants=3)` to enable the optional stages.
Both flags default to `False`; the existing CLI does not enable them.
The keyword-only `max_mutants` bounds the total across all changed Python files.

Minimization tests existing singleton and drop-one candidates in order, using
fresh baseline workspaces and full policy/overfit guards. The first passing
candidate is selected, with every expected test ID required to pass. This is a
single-pass search and does not establish global minimum or ddmin 1-minimality.
`codeslop_hunks_removed` counts removed hunks; it does not prove they were dead code.

Opt into repeated reductions with `enable_iterative_ddmin=True` on the state
machine (alongside minimization), or `run_ddmin_hunk_minimization(..., iterative=True)`.
Each accepted reduction strictly decreases the hunk count. Exhausting nonempty
one-hunk deletions establishes only 1-minimality relative to the deterministic
test/policy/application oracle. It does not prove global optimality or that every
statement/operator inside a retained hunk is exercised.

Mutation probing uses only the selected patch and a fresh container per mutant.
The read-only `/workspace` is copied into `/tmp/mut_workspace`; pytest runs with
`-x --tb=no -q` and a child timeout of `max(1.0, 2 * accepted_result.wall_seconds)`.
Child processes are reaped and the shadow tree is removed between mutants.
Shadow copying remains subject to the runner's existing `/tmp` quota.
Test nonzero exits and timeouts count as kills. Wrapper setup errors remain
infrastructure failures. Zero mutants yield score `1.0` and no warning.

For actual batching, enable `enable_single_container_mutation_batch=True`
alongside mutation probing, or call the probe with `single_container_batch=True`.
`run_in_container_mutation_batch_detailed()` returns ordered frozen
`MutantExecutionResult` records with stable IDs, `SURVIVED`/`KILLED`/
`KILLED_BY_TIMEOUT`, exit codes and child runtime. One Docker invocation evaluates
the batch with a fresh shadow tree per mutant. V2 rejects incomplete/duplicate
reports and pytest setup/collection/usage failures; an outer container timeout
is infrastructure failure and cannot create kills for unexecuted mutants.
Detached descendants are killed and reaped before the next mutant, even after
changing sessions. The runner's outer timeout and tmpfs quotas remain fixed, so
keep batches small. Legacy singleton behavior remains the default. Timeout
scaling still uses the accepted result's Docker-inclusive wall time; it is not
a pure pytest benchmark.

When every evaluated mutant survives, `low_mutation_adequacy=True` requires human
approval, including benchmark runs configured for auto-approval. This warning
does not reject the passing repair. Equivalent mutants and weak test oracles
limit the meaning of the score.

The selected proposal/result and summaries are checkpointed atomically before
approval binding. Original proposal/result records are retained for audit.
`EvidenceBundle`, exported `evidence.json`, and `REPORT.md` include the optional
`MinimizationSummary` and `MutationAdequacySummary`, including survivor details.
Runs created before M13A retain their export behavior and database schema.
Large mutant payloads travel through a disposable JSON control file to stay
within Windows command limits. Control files are excluded from the test shadow.

### M13B bounded context and measured telemetry

The legacy character packer is retained. The additive
`pack_file_with_token_budget(source, slices, budget, count_tokens=counter)` uses
the caller's deterministic tokenizer counter and returns a frozen
`TokenBudgetPackResult`. It evicts hop-1 bodies before hop-0 bodies, then uses
interfaces only. If these still exceed the budget, it returns a complete
omission marker or empty text, with explicit loss metadata. It never truncates
a source line or signature. Python physical-line splitting preserves coordinates
even when Unicode separators appear inside strings.

`SkeletonTelemetry` records actual emitted-coordinate divergence, input/output
token counts, compression, syntax fallback counts and measured elapsed time.
No patch-success rate is invented before an application outcome exists.
`PromptBuilder(..., max_file_tokens=budget, count_tokens=counter)` optionally
bounds each sanitized Python source body; prompt wrappers, evidence, metadata
and non-Python files are outside that per-file bound. This requires a trusted
counter for the consumer's tokenizer; no tokenization dependency was added.
Neither 80% compression on every file nor a universal latency bound is possible
when interfaces/selected content dominate.

### M13C second-order AST policy

`verification.second_order_guard` exposes `analyze_second_order_evasion()` for
aggregated findings and `verify_second_order_evasion()` for typed enforcement.
`fold_symbolic_constant()` supports bounded character synthesis, bytes/hex/base64,
fixed codecs, slicing, string chains and deterministic digests without importing
or executing inspected source. Reflection aliases, module-table access, match
guards, escaping finally exits, broad suppression and definition-time execution
are checked by lexical scope and occurrence against the baseline.
Eager annotation calls are audited; postponed annotations retain lazy behavior.

Repair attempts run these checks before Docker; CI includes them in stages 3/4.
Five `ERR_M13C_*` codes survive retry feedback with fixed corrective guidance.
`get_second_order_evasion_metrics()` returns a frozen process-local detection
snapshot; `reset_second_order_evasion_metrics()` resets it.

The standalone analyzer rejects new module assignments by default. Existing
repair/CI APIs retain a narrow numeric-constant compatibility exemption required
by legacy M13A/M15 callers; pass `allow_numeric_module_constants=False` to those
guard/audit APIs for strict assignment rejection. Boolean/string overrides,
attribute/subscript writes and import-time calls remain rejected. Existing
hazards are grandfathered differentially. This is a bounded static policy, not
proof of semantic purity, universal detection or zero false positives. Folding
limits are 48 nested evaluations, 4,096 operations, 256 comprehension iterations,
1,024 repetitions and 65,536 materialized characters/bytes per value. Unordered
multi-element sets and randomized `hash()` values are not evaluated; hash
comparisons are identified structurally. Latency targets apply to test fixtures.

### M15 standalone CI gate

Usage failures return `status="USAGE_ERROR"`, exit 2. CI fails closed when a
discovered test file cannot be decoded or parsed for assertion analysis; the
legacy assertion collector retains soft failure unless `strict=True` is supplied.
Offline verification accepts both `verify-bundle <bundle_dir>` and the legacy
`--bundle-dir` form, and emits derived `EVENT_G1_FAILED` through `EVENT_G5_FAILED`
telemetry without changing signed payloads.

```powershell
agentsentinel ci-gate --workspace C:\checkouts\base --diff C:\ci\change.diff --json-out C:\ci\audit.json --markdown-out C:\ci\summary.md
```

`--workspace` must contain the exact **pre-patch/base revision**, not the PR head.
The diff is parsed, coordinate drift is healed in memory, and modified/created/
deleted/renamed source buffers are reconstructed without writing source files or
calling `git apply`. Report destinations must be outside that workspace and must
not overwrite the input diff or each other. JSON is also emitted to stdout.
Use `--markdown-out $env:GITHUB_STEP_SUMMARY` on a configured GitHub runner to
write the step-summary table; the gate itself makes no GitHub API calls.

Five stages aggregate path/test/allowlist, lexical/debugger, test-literal and
reflection, complexity/exception, and public API violations across all files.
Results sort by file, line, stage and rule. JSON includes version `15.0.0`, raw
input diff SHA-256 after CRLF normalization, metrics, counts and measured runtime.
The Markdown summary includes per-file CC growth, API status and corrective advice.

- Exit **0**: no errors; warnings are permitted.
- Exit **1**: errors, or warnings with `--strict-warnings`.
- Exit **2**: invalid workspace/diff, unsafe paths, reconstruction failure or invalid output arguments.

`--max-cc-delta` defaults to **10** for this command. Both per-file and per-function
growth are checked; complexity warnings keep their WARNING severity when strict
mode makes the command fail. The repair pipeline's separate +5 default is unchanged.
Programmatic `run_ci_gate_audit(raw_diff, workspace_root, *, allowed_edit_paths=None,
allow_test_edits=False, max_cc_delta=10, strict_warnings=False)` and both renderers
are exported from `agentsentinel.verification`.

Infrastructure paths are protected, and both rename endpoints are checked.
Windows casing aliases receive the same policy/language checks; ambiguous Win32
dot/space/stream aliases fail as usage errors. Occupied rename destinations must
be vacated by another audited section, with case-only renames preserved.
Existing test-file modification/deletion is protected; `allow_test_edits=True`
relaxes only that path rule, not the other static policies. New test files are
not classified as modified tests. Non-Python files still receive path/hygiene
checks. Invalid post-Python produces SYN-001. Test-literal collection excludes
VCS, environment, cache and vendor directories and does not execute tests.

This is bounded static policy, not a sandbox, a behavioral compatibility proof,
or a guarantee of complete dynamic-alias detection. Literal matching can flag
intentional constants. M15 allows recognized logging in broad handlers; bare
handlers remain errors. Missing prerequisites prevent a complete audit and use
exit 2. Git C-quoted path names are currently rejected as unsupported. Inputs
must remain stable while read. The <500ms SLA is tested on a representative
40-function fixture, not guaranteed for arbitrarily large repositories.
Only regular text-file modes/preimages are supported; symlink, directory and
submodule mode records fail with usage code 2 instead of being treated as code.

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

Verified on 2026-10-27 with Python 3.13.7 and live Docker Desktop:
**1,160 passed, 1 skipped** in **128.05 seconds**, all 13 live Docker tests passed,
Ruff clean, and strict mypy clean across 49 source files. The skip is the expected
unprivileged Windows symlink test. The release run disabled pytest's cache and
used a dedicated `--basetemp` directory to avoid Windows permission conflicts.
The final independent review findings were reproduced and fixed before this run.
The suite includes all 12 named M13C adversarial scenarios, positive controls,
bounded context, iterative minimization, batch isolation and legacy M15 tests.
See STATE.md for release evidence, compatibility adaptations and deferred fields.

## Honest limitations

- Public historical benchmark cases may be contaminated by LLM pre-training;
  AgentSentinel flags them rather than pretending the problem away.
- Unknown-priced models produce partial cost reporting, not invented zeroes.
- Local/offline execution is for deterministic tests. Production repair should
  use the hardened Docker sandbox.
- AgentSentinel verifies declared tests. It cannot prove that an incomplete
  test suite captures every requirement, which is why human approval remains
  a hard gate.

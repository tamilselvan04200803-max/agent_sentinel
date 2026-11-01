# AgentSentinel scope and security readiness review

Date: 2026-10-30. Reviewed revision: `a2f9c8b75bd58428125cfad6b5817c8314f04590` (`main`).
Status: local review and proposed specifications; no implementation or release approval.

## Decision

The project is **not fully complete against every original requirement, and this review does not support a hostile-input production-readiness claim**. The core M0-M15 capabilities exist and have substantial recorded verification. Several requirements were deliberately adapted or deferred, and the wider security review below found actionable boundary failures.

This does not mean the milestones are wholly absent. It means three different claims must remain separate: implemented functionality, conformance to all agreed requirements, and security under a specified deployment threat model. Passing the release suite supports the first claim within its coverage. It does not establish the other two.

M16, M17 and M18 have **no existing agreed definitions** in the repository or supplied directives reviewed. The specifications below are proposals, pending deployment and trust decisions. They must not be presented as previously promised milestones or already completed work.

## Evidence and review limits

Reviewed sources include `STATE.md`, `README.md`, `AGENTS.md`, `AUDIT_REPORT_M0_M3.md`, the M13A/M13B/M13C/M14/M15 and repository-integrity plans under `docs/superpowers/plans/`, original executive requirements, the master R&D directive, the latest execution constitution, commit `a2f9c8b`, and relevant implementation paths. A read-only scout compared scope and milestone definitions; an independent read-only security reviewer inspected workspace intake, sandbox execution and Git preparation. The coordinator reviewed approval/export/provenance and consolidated the findings.

The recorded release results at `STATE.md:63` are **historical evidence from the release preceding this review**: Ruff passed; strict mypy passed across 49 source files; pytest reported **1,180 passed, 1 skipped in 141.98 seconds**; all **14 live Docker tests passed**. The skip was Windows symlink creation at `tests/unit/test_validator.py:93`. This review did not rerun those gates or Docker, and does not convert that skip into coverage.

Fresh work here consisted of source/commit inspection, trusted stdlib checks, and an in-memory rehearsal of export and verification. No hostile repository code was executed on the host. No container escape, remote exploit or actual secret exfiltration was demonstrated. No source, existing tests, `STATE.md`, dependencies or pre-existing dirty files were changed. This document is the only new file, and has not been committed or published.

## Completion against the agreed scope

| Area | What is established | Qualification or remaining work |
|---|---|---|
| M0-M12 | Domain records, sandbox runner, patch policy, retries/checkpoints, evaluation admission, CLI/export, localization, overfit/contract guards, differential mutants and retry diagnostics exist. | Static policies are bounded; declared tests and signatures do not prove arbitrary behavioral correctness. Sandbox security qualifications below remain. |
| M13A | Optional post-pass subset search, iterative mode, mutation probing, single-container batching, persisted summaries and selected-patch rebinding exist. | Defaults remain disabled; normal CLI does not enable these stages. Targeted baseline timing and richer historical telemetry remain incomplete. |
| M13B | AST skeletonization, localized packing and additive measured telemetry exist. | Whole-prompt token guarantees and universal compression/latency targets are not established. Patch-application success telemetry needs actual attributed outcomes. |
| M13C | Second-order AST guards, symbolic decoding and typed retry integration exist. | A bounded static detector is not a complete Python malicious-code detector. Existing compatibility exceptions must remain explicit. |
| M14 | JCS/DSSE PAE, optional HMAC export, key lookup, offline verification and policy snapshots exist. | Internal approval records remain unkeyed by explicit later agreement. Approval-to-export identity is insufficiently checked; see R4. |
| M15 | Standalone read-only CI gate, source-map reconstruction, aggregated findings and JSON/Markdown output exist. | This is a CLI capability, not a reviewed secure GitHub workflow deployment. No repository CI workflow was found in the documentation/workflow inventory. |
| M16-M18 | No supplied definitions found. `STATE.md:54` and the integrity plan explicitly say so. | Define threat model and acceptance contracts before implementation. |

Existing debt should retain its original milestone attribution:

- **M13A timeout baseline:** the master R&D directive requires measuring the selected patch's failing-ID test runtime, then applying `max(1.0, 2 * targeted_baseline_seconds)`. Current code supplies the accepted execution result's Docker-inclusive wall time (`verification/post_pass_gate.py:318`, `:333`), which can now be a full-suite result. This is documented at `README.md:139` and `:158`; it is not the specified separately measured targeted baseline.
- **M13A selector support:** raw `-k` selectors remain unsupported as exact node IDs. Adding them needs attested collection/selection rather than guessing which tests ran (`STATE.md:103`).
- **M13A/M14 persisted details:** requested `gate_results` and survivor line/operator/cause fields are not all present in the legacy signed structures. Detailed additive runtime records exist; a versioned persisted payload remains to be specified (`STATE.md:106`).
- **M13B outcome telemetry:** attributed patch-application success measurement remains deferred (`STATE.md:109`). Universal compression, latency and essential-execution-path guarantees are not justified by a subset generator or hunk minimality.
- **Approval authentication:** the original executive directive, lines 68-81, requested keyed internal approval and refusal to export on failed signature verification. Later explicit approval-format decisions retained unkeyed SHA-256 (`README.md:100`, `STATE.md:405`). That agreed deferral is not secretly completed by optional HMAC on exported bundles.

These are useful specification-closure tasks, not justification for inventing a broad new research roadmap. Resolve each by implementing a bounded requirement or obtaining an explicit acceptance of its documented limitation.

## Assessment of commit a2f9c8b

The commit contains 12 changed files, 686 insertions and 5 deletions. It adds mechanical repository-integrity checks, full-case-suite verification after the minimizer's failing-ID filter, and persisted/attested canonical policy settings. The corresponding unit and live Docker regression coverage addresses concrete gaps.

Those changes are useful and scoped. Their limits matter:

- The integrity guard checks particular static source patterns; it is not dependency supply-chain verification or a malicious-code proof.
- The full-suite gate covers the configured `CaseSpec.test_command`, not an independently complete test oracle. Legacy standalone callers can still omit `full_suite_command` by design.
- A matching policy snapshot/hash establishes internal consistency. HMAC can authenticate what the signer signed; neither establishes that every recorded setting was enforced or that the correct image/approved patch was used.
- The new commit does not close the workspace, buffering, image-identity or approval/export findings below. These findings were outside the narrower feature checks; historical reviewers' clean results are not universal security certificates.

## Security findings requiring work

Severity assumes potentially hostile repository content. Preconditions and evidence are stated so that a conditional concern is not represented as a demonstrated remote exploit.

### R1 - High: workspace intake can include host-external and sensitive content

`src/agentsentinel/sandbox/workspace.py:146` resolves only the roots, then `:154` copies the entire tree with `symlinks=False`. There is no per-entry containment policy, secret/reference exclusion manifest or intake quota. With this option, Python copies symlink targets' content; an external target can therefore enter the supposedly isolated workspace. This behavior is documented in the [Python copytree reference](https://docs.python.org/3.13/library/shutil.html#shutil.copytree).

Even without links, ordinary repository `.env` files, credentials or reference artifacts can be copied. Read-only mounting prevents modification; it does not prevent repository tests from reading mounted files. Failure output then reaches prompt construction (`llm/prompts.py:219`, `orchestrator/state_machine.py:611`). Formatting sanitization is not secret redaction. This creates a credible host-file/provider-disclosure path before patch policy can help: baseline repository tests execute too.

`localization/ast_slicer.py:133` also joins an allowed path to the original root and reads it without a local containment check. Safe intake and safe source reads need one consistent boundary.

Evidence: source/dataflow review and trusted stdlib inspection. No filesystem/exfiltration exploit was run; Windows external-link coverage is incomplete. Required fix: an operator-controlled, bounded input manifest; containment and entry-type checks; explicit link/junction/reparse-point policy; secret/reference exclusions; and a provider disclosure policy. Filename deny-lists alone cannot guarantee that arbitrary files contain no secrets.

### R2 - High: stdout/stderr capture does not have the advertised memory bound

`src/agentsentinel/sandbox/container.py:430` constructs `queue.Queue()` without a capacity. Reader threads enqueue every 16 KiB chunk at `:387`. Only the final bytearrays at `:462` are capped. A producer that outruns consumption can grow the host-side queue despite capped retained output. Container memory limits do not bound this host queue.

The `finally` block at `:474` joins daemon readers briefly; it does not implement the queue drain described by its comment. A naive bounded-queue change could introduce shutdown deadlocks, so overflow, timeout, pipe closure and worker termination must be designed together.

Evidence: source review and a small trusted stdlib queue check, not a live output-flood attack. Required fix: bounded backpressure or bounded discard with explicit overflow semantics; deterministic stop/close/join behavior; tests covering simultaneous streams, timeout and EOF.

### R3 - High for evidence integrity: the recorded image is not bound to the image executed

`src/agentsentinel/cli/main.py:131` supplies `args.image_digest or f"sha256:{args.image or 'local'}"`. This can produce a synthetic value such as `sha256:local` and bypass automatic resolution at `orchestrator/state_machine.py:263`. The runner still executes `self.config.image` at `sandbox/container.py:214`, ordinarily a mutable tag. Resolving a separate configuration also does not establish the identity of a separately supplied runner.

A tag can identify different image content over time. Docker supports execution by a content digest; recording a string beside a tag is not pinning. See the [Docker image digest documentation](https://docs.docker.com/engine/containers/run/#image-digests).

Evidence: source inspection; no live image substitution was attempted. Required fix: resolve the actual runner image to an immutable identity, execute that same identity, reject requested/resolved mismatches, and persist it consistently. Unknown identities must remain explicitly unknown and fail a strict production profile.

### R4 - High where checkpoint data is writable: export can authenticate a patch that was not approved

`src/agentsentinel/cli/exporter.py:69` checks the run state, then `:74` selects a passing attempt and `:82` takes its current proposal text. It recomputes root patch/result hashes and attests the assembled payload at `:186`, without checking the stored human approval against the actual selected proposal/result first. `approve_run` compares caller-supplied hashes to the stored aggregate at `orchestrator/state_machine.py:344`; it also does not reconstruct the passing attempt's current evidence there.

The offline verifier checks the exported patch against its newly computed root hash and verifies the envelope, but its final gate at `cli/bundle_verifier.py:257` checks root verdict/status fields, not this nested approval/attempt identity.

Fresh safe rehearsal: the real exporter and real cryptographic verifier were invoked with an in-memory checkpoint substitute and in-memory artifact paths. The proposal was changed while the original approval hash remained. Export produced the changed patch with `hmac-sha256-v1`; the root patch hash disagreed with the original approval's diff hash; offline verification returned **exit 0**. Filesystem writes: **0**. This demonstrates re-attestation of inconsistent stored approval evidence, not an on-disk database intrusion or an HMAC forgery.

Precondition: checkpoint modification/corruption before export, with an exporter later signing the contents. Protecting the signing key separately makes this distinction especially important. Required fix: validate the actual selected attempt, proposal, result, image and approval binding at approval and export; reject missing/inconsistent records before signing; define a versioned authenticated approval profile and protected checkpoint trust boundary. Cross-checking unkeyed hashes alone cannot resist an actor who can rewrite every record.

### R5 - Medium: Git metadata removal and host preparation are not fail closed

`src/agentsentinel/sandbox/workspace.py:181` applies `rmtree` to `.git` regardless of type, swallows retry errors at `:189`, and has no removal postcondition. A regular `.git` worktree pointer can survive. A mocked-filesystem stdlib rehearsal confirmed normal return with zero unlink calls for this case.

`src/agentsentinel/policy/applier.py:137` trusts existing metadata. Its host `git init` and `git add` at `:139` inherit configuration/environment, with no timeout or bounded capture. Configured clean filters can run during staging; **a repository `.gitattributes` file alone does not establish arbitrary host execution**.

Required fix: type-aware removal and checked postconditions, isolated Git configuration/templates/environment/filter policy, and bounded host preparation. Treat special files, unreadable metadata and cleanup failure as admission/infrastructure failure, not successful isolation.

### Deployment hardening and additional review items

- The default runner has no `--user`; `Dockerfile.runner` has no `USER`. A non-root container UID and a rootless Docker daemon are distinct requirements. Neither is enforced here. Docker documents its [default container user](https://docs.docker.com/engine/containers/run/#user) and the separate [rootless daemon mode](https://docs.docker.com/engine/security/rootless/). Existing capability, network, rootfs and mount flags are valuable, but do not prove either property. No container escape was demonstrated.
- Export target checks at `cli/exporter.py:190` reject symlinks, but ordinary writes at `:197` can overwrite pre-existing hard-linked files. This is a conditional concern when another actor controls the output directory; it was not filesystem-exploited in this review. Specify fresh atomic output and link/ownership policy.
- `cli/bundle_verifier.py:190` reads artifacts before size bounds. Untrusted bundle size/file-count limits and bounded parsing should be specified and adversarially tested. This review did not establish an exhaustive parser/denial-of-service audit.

## Proposed M16-M18 specifications

Recommended sequence: close hostile input/execution boundaries, close approval/evidence trust, then qualify and release a documented deployment profile. Do not add unrelated features while these issues remain. Existing dependencies, strict typing, immutable tests, read-only/no-network execution and bounded retries remain constraints. Any compatibility changes require an explicit migration contract.

### Proposed M16 - Hostile workspace and execution boundary

**Goal:** accepted repository content cannot expand host reads, host execution or resource use beyond an explicit operator-controlled boundary.

Before implementation, specify supported host OS/Docker modes; who supplies repository trees and `CaseSpec`; permitted entry types and links; trusted test commands; provider disclosure rules; exact file/byte/time/output quotas; image resolution/pull policy; and the required runtime UID/daemon profile.

Acceptance contract:

1. Build one bounded manifest shared by workspace copying and source localization. Reject traversal, external links, unsafe junctions/reparse points, special files and race/containment failures according to the supported platform policy.
2. Keep operator secrets, checkpoint/signing material and evaluation reference artifacts outside admitted input. Test with synthetic canaries, including the failure-output-to-provider path. Document the residual risk of secrets embedded in otherwise allowed source.
3. Remove `.git` metadata safely for directory, regular-file and link cases; verify absence. Run required host Git preparation with isolated settings, finite time/output bounds and no repository-selected execution hooks/filters.
4. Execute the immutable identity of the actual runner image; reject mismatch and unknown identity in strict mode. Record the executed identity, not a caller assertion.
5. Bound all output buffers/queues and intake work; prove timeout cleanup without deadlock or surviving readers. Preserve container resource/network/mount controls.
6. Run adversarial intake and actual Docker tests on every supported profile. A Windows link skip cannot satisfy Linux link coverage or an untested Windows reparse-point promise.

Completion evidence: targeted regressions, Ruff/strict mypy/full suite, live supported-profile Docker results, and a documented independent review. No generic container-escape immunity claim.

### Proposed M17 - End-to-end approval and evidence trust

**Goal:** the bytes exported and authenticated are precisely the patch/result/image/policy that the authorized human approved.

Specify the trusted checkpoint writer, database ACL expectations, approver identity mechanism, signing-key custody, key identifiers/rotation/revocation, payload versions, and legacy-record handling. Shared-key HMAC authenticates key possession; it is not a public-key identity signature.

Acceptance contract:

1. Reconstruct and compare actual proposal/result/attempt identity at approval and export; bind policy and executed image. Fail before signing or writing on inconsistency. Version the distinct legacy and canonical result-hash formulas explicitly.
2. Add an authenticated, domain-separated approval representation for a strict profile with protected key custody. Preserve old records through explicit legacy verification/migration behavior; never label unauthenticated history as authenticated.
3. Validate exported nested/root identities and verdict consistency as part of the versioned verifier contract. Preserve documented failure codes or introduce an explicit versioned extension.
4. Reproduce R4 as a regression, plus altered result/image/policy, stale approvals, replay across runs, restart and partial-write cases. Require strict keyed verification for production acceptance; do not claim this proves test execution honesty.
5. Produce bundles atomically in a safe output location; reject unsafe existing link targets. Bound untrusted bundle sizes/counts and parser work before expensive processing.
6. Document operator trust assumptions: an attacker controlling both the signing process/key and evidence store is outside an integrity guarantee based on that same key.

Completion evidence: tamper/restart/export regressions, deterministic legacy compatibility, full verification and independent review. No dependencies or SQLite schema change should be assumed necessary before the design is inspected.

### Proposed M18 - Supported release profile and security qualification

**Goal:** make the security contract enforceable and repeatable for the selected deployment, with honest supported limits.

Specify one first supported profile rather than claiming local, CI and multi-user security simultaneously. If GitHub PR CI is selected, the gate code/configuration must come from a trusted source, privileged credentials must be separated from untrusted PR execution, and the exact event/permission/artifact flow needs a separate reviewed workflow design. Multi-user service authentication/authorization and tenant isolation are additional scope, not capabilities implied by today's CLI.

Acceptance contract:

1. Publish a threat model, architecture trust boundaries, data/provider policy, supported versions/platforms, vulnerability-reporting process and release-support policy.
2. Make CI run Ruff, strict mypy, full tests and required actual Docker adversarial scenarios. Required live tests fail or block the release when unavailable; skip reports must identify the unsupported capability.
3. Add a bounded hostile fixture corpus for link/metadata/secret intake, output pressure, image mismatch, approval tampering and wrapper/test-record forgery. Execute untrusted fixtures only in the appropriate sandbox.
4. Check release artifact identity and dependency/image inventory with existing tools; record known limits and update procedures. Commission a fresh independent review after M16/M17 fixes.
5. Resolve or explicitly accept the M13-M15 debt listed above. Keep post-pass features opt-in unless a separately agreed supported profile changes their defaults and budgets.
6. Define release blockers, severity handling and security regression ownership. Mark the release qualified only for the tested profile; test counts alone are not the acceptance criterion.

## Decisions needed from the owner

The deployment question has already been sent interactively and remains unanswered at the time of writing. These decisions should be settled before locking an implementation plan:

| Decision | Recommended starting point, pending your answer |
|---|---|
| First deployment | Single operator on an isolated local worker processing potentially hostile repositories; assess CI separately if it is the actual first goal. |
| Trust in inputs | Repository trees and test code hostile; case policy, gate implementation, image choice and signing configuration controlled by the operator. |
| Host/platform promise | Name the supported Windows/Docker Desktop and/or Linux/rootless profiles; require real coverage for each claim. |
| Secrets and providers | No credentials/reference artifacts in admitted workspaces; explicitly approve what source/output may leave for an LLM provider. Never send actual secret values for this discussion. |
| Checkpoints and approvals | Protect database and signing key; choose strict authenticated new records with explicit legacy compatibility. Decide who may approve if more than one user exists. |
| Compatibility | Preserve existing APIs and tests; make strict modes additive unless you explicitly choose a breaking release. |

While specifications are being finalized, use disposable copies of repositories without secrets on an isolated worker. Keep approval/signing material outside those trees and avoid advertising secure hostile-PR or multi-user production support. This reduces exposure; it does not close the findings.

The next useful work is to approve a concrete threat model and M16 acceptance contract, then implement and verify one boundary at a time. The requested goal is achievable as a defined, tested security posture; a promise that no human can ever discover a vulnerability is not a verifiable completion condition.

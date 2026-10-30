# Repository integrity and verification hardening plan

Spec: user attachment dfa84be8-100b-4ddd-8b08-cde7c38e32cc/Pasted text.txt.
Base: c36d6fb. Locked plan table was output before any writes on 2026-10-30.

## Ordered work

1. Add the three mechanical source-integrity guards; test them against real source and synthetic violations.
2. M13A: add optional full-suite command to the minimizer; production state-machine minimization supplies the declared CaseSpec command. Preserve legacy standalone defaults, existing assertions and approval formula. Targeted checks remain first; candidate adoption requires full-suite success with matching identity, visible expected IDs and untruncated evidence.
3. M14: persist a typed policy snapshot with verified evidence; hash canonical JCS. Export and verify optional paired policy metadata. Old runs/bundles remain valid without fabricated snapshots. This attests configured policy metadata, not arbitrary behavior or inherited code guarantees.
4. Add isolated live Docker pass-to-pass regression protection. Run focused checks after each module. One final independent reviewer; resolve concrete findings.
5. Run Ruff, strict mypy and full pytest separately. Only after exit code 0 for all three update README/STATE, conventionally commit and normally push main.

## Scope

Only the files in the locked table: this plan; new tests/unit/test_repo_integrity_guard.py, test_m13a_full_suite.py, test_policy_config_provenance.py; new tests/integration/test_docker_live_full_suite.py; verification/post_pass_gate.py; orchestrator/state_machine.py; cli/provenance.py, exporter.py, bundle_verifier.py; README.md and STATE.md.

## Boundaries

- Existing venv, PowerShell, UTF-8/LF writes, Python -B, no dependencies/new Any/type ignores.
- No existing tests/assertions, user AGENTS.md, tracked bytecode or primary .pytest_tmp changes.
- No host execution of inspected source/tests; candidates execute only in hardened Docker.
- Existing SQLite schema and approval hash formula remain unchanged.
- Full-suite means the configured case command, not proof of test-oracle completeness.
- M16-M18 have no supplied requirements and are not fabricated.
- Two failed fixes maximum per conflict before reverting only the owned failing hunk; never overwrite pre-existing work.

## Evidence

Read-only audit: 49 source files, zero unapproved import/legacy AST/shell=True/bare-handler findings. Historical c36d6fb release: 1160 passed, one Windows symlink skip; not a fresh baseline claim.

- Phase 2: all four repository-integrity tests pass; synthetic forbidden constructs were detected. Ruff/mypy passed after a type-only import adjustment.
- M13A RED: six missing-feature failures, one legacy default control passed. After implementation: 77 focused tests passed, Ruff/mypy passed. Live Docker case initially skipped because the daemon was stopped; Docker Desktop was started without dependency installation, then the real regression test passed (11.47s).
- M14 RED: missing hash/snapshot, incomplete schema and internal hash mismatch reproduced. After implementation: 140 focused tests passed; existing approval hash formula and schema retained. Final expanded verification pending.

- Independent final review: no actionable findings, 19 focused tests passed (4.40s).
- Final separate gates all exit 0: Ruff "All checks passed!"; strict mypy "Success: no issues found in 49 source files"; full pytest "1180 passed, 1 skipped in 141.98s (0:02:21)". All 14 live Docker tests passed; sole Windows symlink skip. README/STATE updated only after these results. Final conventional commit and normal origin/main push follow; no force push.

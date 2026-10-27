# AgentSentinel M13B Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. Run one read-only whole-feature review before release.

**Goal:** Preserve useful Python interfaces and localized function bodies in bounded repair context.

**Architecture:** Add deterministic AST folding and a four-tier context packer to the existing localization module. PromptBuilder opts into packing oversized Python files when localization is supplied, while retaining its legacy truncation fallback.

**Tech Stack:** Python 3.11+, stdlib AST/tokenize, existing pytest/Ruff/strict mypy environment, PowerShell.

**Spec:** User M13B execution directive, attachment `7f8204d1-9883-485f-996a-70236a21949e/Pasted text.txt`.

## Global Constraints

- Six-file scope approved by the user; no dependencies or existing test changes.
- Preserve M13A, sandbox isolation, approval binding and all existing public callers.
- Parse source only; never import or execute inspected repository source.
- Use UTF-8/LF writes, PowerShell commands without `&&`, existing virtual environment.
- Preserve pre-existing AGENTS.md/cache edits in the primary checkout.

## Decisions and Review Focus

- Follow the explicit tier algorithm: Tier 4 is a pure interface skeleton. Tier 0 remains reserved.
- Tiers 2 and 3 coincide with default `compact=True`; test the Tier 3 transition using `compact=False`.
- The packer returns oversized Tier 4 content when interfaces alone exceed budget; PromptBuilder falls back to its existing raw truncation plus marker.
- Reject nonpositive span bounds and negative character budgets with ValueError; normalize reversed positive spans.
- Test decorator/nested-scope overlap, multiline signatures/docstrings, CRLF/Unicode, empty files and exact original line numbers.
- Test file-specific slice matching, sanitization, oversized invalid/null-byte source and unchanged non-Python/no-localization behavior.
- Skeletons are prompt context, not executable Python; retained docstring first lines can be unterminated after folding.

## Task 1: AST skeletonizer

**Files:** `localization/ast_slicer.py`, `tests/unit/test_m13b_ast_skeletonizer.py` (under existing src/tests roots).

**Interfaces:** `merge_keep_spans(Sequence[tuple[int, int]]) -> list[tuple[int, int]]`; `_get_function_signature_end(FunctionDef | AsyncFunctionDef, Sequence[str]) -> int`; `skeletonize_python_source(source, keep_spans=(), *, compact=False, line_number_width=5) -> str`.

- [x] Write AC-01..AC-10 and physical/compact line-number tests; observe missing-API failures.
- [x] Implement span normalization, immediate-token signature detection, top-down folding and numbered reconstruction.
- [x] Run focused tests, Ruff and strict mypy; preserve all existing assertions.

## Task 2: Tiered packing and prompt integration

**Files:** same source/test files, `localization/__init__.py`, `llm/prompts.py`.

**Interfaces:** frozen `SkeletonPackResult(formatted_content, raw_line_count, output_line_count, compression_ratio, pruning_tier_used, used_syntax_fallback)`; `pack_file_with_skeleton(source, slices, max_chars, *, compact=True) -> SkeletonPackResult`.

- [x] Add failing tests for tier ordering, stats, fallback, bounds, exports and both prompt entry points.
- [x] Implement deterministic tiers; retain the public `max_file_chars` attribute and existing numbering on the legacy branch.
- [x] Match each file's slices using normalized relative paths; sanitize packed output without numbering it twice.
- [x] Run the new suite plus existing prompt/localization tests, Ruff and strict mypy.

## Task 3: Review and release

**Files:** `STATE.md`, this plan, reviewed fixes within the approved scope.

- [x] Dispatch one read-only reviewer against the complete diff; resolve material findings with reproducing tests.
- [x] Run separate Ruff, strict mypy and full pytest commands, including actual Docker tests when available.
- [x] Record observed totals/skips and limitations in STATE.md; inspect diff/status and commit conventionally.
- Release operation: fast-forward main and push normally to origin/main; verify remote revision and preserve pre-existing edits.

## Execution Record

- Base: `646bb4a`; prompt/localization baseline: **40 passed**.
- Worktree: `agent_sentinel_m13b`, branch `feat/m13b-ast-skeletonizer`.
- Task 1: 27 expected missing-API failures, then **67 focused tests passed**, Ruff clean and strict mypy clean.
- Task 2: 15 expected missing-packer/integration failures, then **89 focused tests passed**. Strict mypy required an explicit tier tuple annotation; **41 source files** now pass. Ruff clean.
- Final review: two P2 findings reproduced by three failing tests, then fixed (iterative AST traversal and component-aware slice path matching). **92 focused tests passed**; Ruff and strict mypy clean. No deferred findings.
- Review rulings: keep prescribed splitlines semantics, single-line bodies, open retained docstrings, Tier 4 overflow and coincident default Tiers 2/3. These are explicit directive boundaries. Existing localization hints retain their separate rendering and security behavior; this change bounds only packed per-file context, not the entire prompt.
- Initial full run: **712 passed, 11 skipped** (ten Docker tests blocked by sandbox pipe permissions plus the Windows symlink test). Docker 29.4.1 verified outside the sandbox; final run uses that access and a fresh external basetemp to preserve the existing ACL-locked `.pytest_tmp` directory.
- Final suite after fixes: **725 passed, 1 skipped, 0 failures** in **157.77 seconds**. All **10 live Docker tests passed**. The sole skip is the existing Windows symlink privilege test. All **52 M13B tests** pass. Final Ruff and strict mypy: clean, **41 source files**.
- Verified implementation commit: `716dc39`. Release documentation follows in a separate conventional commit; only documentation changes after verification.

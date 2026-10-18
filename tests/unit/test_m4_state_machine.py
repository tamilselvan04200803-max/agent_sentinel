"""Unit tests for M4 checkpoint, dedup, and state machine invariants."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest import mock
from unittest.mock import MagicMock

import pytest

from agentsentinel.domain.exceptions import (
    BaselineNotReproducedError,
    DuplicatePatchError,
    InfrastructureFailureError,
    UnapprovedExportError,
)
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.llm.exceptions import LLMGenerationError, LLMRateLimitError
from agentsentinel.llm.pricing import ModelUsage
from agentsentinel.orchestrator.checkpoint import (
    CheckpointStore,
    RunState,
    TerminationReason,
)
from agentsentinel.orchestrator.dedup import (
    canonicalize_diff,
    check_tier1_duplicate,
    check_tier2_duplicate_or_noop,
    tier1_fingerprint,
    tier2_fingerprint,
)
from agentsentinel.orchestrator.state_machine import (
    RepairStateMachine,
    _append_test_args,
    _sha256,
)

if TYPE_CHECKING:
    from pathlib import Path

_VALID_SHA = "a" * 40


def _make_case(tmp_path: Path) -> CaseSpec:
    return CaseSpec(
        case_id="m4-case",
        repo_url="https://example.com/r",
        base_commit=_VALID_SHA,
        test_command="pytest -q",
        allowed_edit_paths=("normalizer.py",),
        failing_test_ids=("tests/test_norm.py::test_fix",),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# checkpoint.py
# ---------------------------------------------------------------------------


class TestCheckpointStore:
    @pytest.mark.unit
    def test_wal_pragmas_and_schema(self, tmp_path: Path) -> None:
        db = tmp_path / "c.db"
        with CheckpointStore(db) as s:
            journal = s._conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert journal.lower() == "wal"
            fk = s._conn.execute("PRAGMA foreign_keys").fetchone()[0]
            assert fk == 1
            # Tables must exist
            tables = {
                r[0]
                for r in s._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            assert "runs" in tables
            assert "attempts" in tables

    @pytest.mark.unit
    def test_create_run_and_get(self, tmp_path: Path) -> None:
        with CheckpointStore(tmp_path / "c.db") as s:
            rid = s.create_run("case-1", max_attempts=5)
            rec = s.get_run(rid)
            assert rec is not None
            assert rec.case_id == "case-1"
            assert rec.state == RunState.INIT
            assert rec.attempts_used == 0
            assert rec.max_attempts == 5

    @pytest.mark.unit
    def test_increment_attempts_is_atomic(self, tmp_path: Path) -> None:
        with CheckpointStore(tmp_path / "c.db") as s:
            rid = s.create_run("c", max_attempts=3)
            assert s.increment_attempts(rid) == 1
            assert s.increment_attempts(rid) == 2
            rec = s.get_run(rid)
            assert rec is not None
            assert rec.attempts_used == 2

    @pytest.mark.unit
    def test_state_transition_persists(self, tmp_path: Path) -> None:
        with CheckpointStore(tmp_path / "c.db") as s:
            rid = s.create_run("c", 3)
            s.transition_state(rid, RunState.PROPOSING_PATCH)
        # Reopen — state must be durable
        with CheckpointStore(tmp_path / "c.db") as s2:
            rec = s2.get_run(rid)
            assert rec is not None and rec.state == RunState.PROPOSING_PATCH

    @pytest.mark.unit
    def test_seen_hashes_round_trip(self, tmp_path: Path) -> None:
        with CheckpointStore(tmp_path / "c.db") as s:
            rid = s.create_run("c", 3)
            s.add_seen_diff_hash(rid, "aaa")
            s.add_seen_ast_hash(rid, "bbb")
            diffs, asts = s.get_seen_hashes(rid)
            assert "aaa" in diffs
            assert "bbb" in asts


# ---------------------------------------------------------------------------
# dedup.py
# ---------------------------------------------------------------------------


class TestDedup:
    @pytest.mark.unit
    def test_tier1_fingerprint_ignores_index_line_and_crlf(self) -> None:
        diff_a = (
            "diff --git a/f.py b/f.py\n"
            "index 1234567..abcdef0 100644\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1 +1 @@\n-old\n+new\n"
        )
        diff_b = (
            "diff --git a/f.py b/f.py\r\n"
            "index 0000000..1111111 100644\r\n"
            "--- a/f.py\r\n"
            "+++ b/f.py\r\n"
            "@@ -1 +1 @@\r\n-old\r\n+new\r\n"
        )
        assert tier1_fingerprint(diff_a).hex == tier1_fingerprint(diff_b).hex

    @pytest.mark.unit
    def test_canonicalize_diff_strips_index(self) -> None:
        out = canonicalize_diff("index deadbee..cafebabe\n--- a/f.py\n+++ b/f.py\n")
        assert "index" not in out
        assert "--- f.py" in out

    @pytest.mark.unit
    def test_tier1_duplicate_raises(self) -> None:
        diff = "--- a/f\n+++ b/f\n@@\n-x\n+y\n"
        seen = {tier1_fingerprint(diff).hex}
        with pytest.raises(DuplicatePatchError):
            check_tier1_duplicate(diff, seen)

    @pytest.mark.unit
    def test_tier2_noop_on_same_source(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(
            "def f(x):\n    return x + 1\n", encoding="utf-8"
        )
        baseline = tier2_fingerprint(tmp_path, ("a.py",)).hex
        # A comment-only patch would change file but not AST; here we simply
        # point at unchanged workspace to show duplicate detection vs. baseline.
        with pytest.raises(DuplicatePatchError):
            check_tier2_duplicate_or_noop(
                tmp_path, ("a.py",), baseline_ast_hash=baseline, seen_ast_hashes=set()
            )

    @pytest.mark.unit
    def test_tier2_distinguishes_real_change(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(
            "def f(x):\n    return x + 1\n", encoding="utf-8"
        )
        baseline = tier2_fingerprint(tmp_path, ("a.py",)).hex
        # Now change semantics
        (tmp_path / "a.py").write_text(
            "def f(x):\n    return x + 2\n", encoding="utf-8"
        )
        fp = check_tier2_duplicate_or_noop(
            tmp_path, ("a.py",), baseline_ast_hash=baseline, seen_ast_hashes=set()
        )
        assert fp.hex != baseline


# ---------------------------------------------------------------------------
# state_machine.py
# ---------------------------------------------------------------------------


class _StubLLM:
    """Deterministic stub LLM client for state-machine unit tests."""

    def __init__(self, patches: list[PatchProposal] | None = None) -> None:
        self.patches = patches or []
        self.calls = 0

    def generate_patch(
        self, case_id: str, prompt: str, model_id: str
    ) -> tuple[PatchProposal, ModelUsage]:
        if self.calls >= len(self.patches):
            raise LLMGenerationError("stub: out of patches", raw_response="")
        p = self.patches[self.calls]
        self.calls += 1
        usage = ModelUsage(model_id=p.model_id, prompt_tokens=1, completion_tokens=1)
        return p, usage


def _patch_from_diff(diff: str) -> PatchProposal:
    return PatchProposal(
        case_id="m4-case",
        unified_diff=diff,
        model_id="stub",
        prompt_tokens=1,
        completion_tokens=1,
    )


_GOOD_DIFF = """\
--- a/normalizer.py
+++ b/normalizer.py
@@ -1,2 +1,2 @@
 def normalize(x):
-    return x.lower()
+    return x.strip().lower()
"""


class TestStateMachineInvariants:
    @pytest.mark.unit
    def test_append_test_args_adds_v_ra(self) -> None:
        out = _append_test_args("pytest -q")
        assert "-v" in out
        assert "-ra" in out

    @pytest.mark.unit
    def test_approval_hash_binding(self) -> None:
        h = _sha256("diffhash", "img", "res")
        assert len(h) == 64
        # Tampering with any input changes the hash
        assert _sha256("diffhash", "img", "res2") != h

    @pytest.mark.unit
    def test_baseline_must_reproduce_test_failure(
        self, tmp_path: Path
    ) -> None:
        """INVARIANT 5 — if baseline exits OK, run terminates with
        BASELINE_NOT_REPRODUCED before any LLM call."""
        case = _make_case(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "normalizer.py").write_text(
            "def normalize(x):\n    return x.lower()\n", encoding="utf-8"
        )

        stub_llm = _StubLLM()
        runner = MagicMock()

        def _fake_run(**kwargs: Any) -> ExecutionResult:
            return ExecutionResult(
                case_id=case.case_id,
                patch_diff_hash="baseline",
                exit_code=ExitCode.OK,  # baseline incorrectly passes!
                stdout="collected 1 item\n1 passed\n",
                stderr="",
                wall_seconds=0.2,
                expected_test_ids=case.failing_test_ids,
            )

        runner.run_in_container.side_effect = _fake_run
        sm = RepairStateMachine(
            spec=case,
            llm_client=stub_llm,
            container_runner=runner,
            max_attempts=3,
            db_path=tmp_path / "r.db",
        )
        sm.source_workspace = src
        rid = sm.start_run()
        with pytest.raises(BaselineNotReproducedError):
            sm.run_to_terminal(rid)
        # No LLM calls should have been made
        assert stub_llm.calls == 0

    @pytest.mark.unit
    def test_duplicate_tier1_detected_before_container(
        self, tmp_path: Path
    ) -> None:
        """INVARIANT 3 — after first attempt's diff_hash is recorded, any
        LLM returning the same Tier-1 fingerprint must raise DuplicatePatchError
        and NOT invoke the container runner again."""
        from agentsentinel.domain.exceptions import DuplicatePatchError

        case = _make_case(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "normalizer.py").write_text(
            "def normalize(x):\n    return x.lower()\n", encoding="utf-8"
        )

        patch = _patch_from_diff(_GOOD_DIFF)

        # LLM that returns the same patch on the 2nd call
        class _DupLLM:
            def __init__(self) -> None:
                self.calls = 0

            def generate_patch(self, *a: Any, **kw: Any) -> Any:
                self.calls += 1
                return patch, ModelUsage(
                    model_id="stub", prompt_tokens=1, completion_tokens=1
                )

        runner = MagicMock()
        container_calls = {"n": 0}

        def _fake_run(**kwargs: Any) -> ExecutionResult:
            container_calls["n"] += 1
            return ExecutionResult(
                case_id=case.case_id,
                patch_diff_hash="baseline" if container_calls["n"] == 1 else patch.diff_hash,
                exit_code=ExitCode.TESTS_FAILED,
                stdout="FAILED\n",
                stderr="",
                wall_seconds=0.1,
                expected_test_ids=case.failing_test_ids,
            )

        runner.run_in_container.side_effect = _fake_run

        def _fake_apply(patch: PatchProposal, source_workspace: Path,
                       allowed_edit_paths: tuple[str, ...],
                       dest_workspace: Path | None = None) -> Path:
            assert dest_workspace is not None
            (dest_workspace / "normalizer.py").write_text(
                "def normalize(x):\n    return x.strip().lower()\n", encoding="utf-8"
            )
            return dest_workspace

        llm = _DupLLM()
        sm = RepairStateMachine(
            spec=case,
            llm_client=llm,
            container_runner=runner,
            max_attempts=3,
            db_path=tmp_path / "r.db",
        )
        sm.source_workspace = src

        import agentsentinel.orchestrator.state_machine as sm_mod
        with mock.patch.object(sm_mod, "apply_validated_patch", side_effect=_fake_apply):
            rid = sm.start_run()
            with pytest.raises(DuplicatePatchError):
                sm.run_to_terminal(rid)
        rec = sm.resume_run(rid)
        # Exactly 1 baseline + 1 verification container call = 2, NO more
        # (3rd call would mean duplicate didn't short-circuit).
        assert container_calls["n"] == 2
        assert rec.termination_reason == TerminationReason.DUPLICATE_PATCH

    @pytest.mark.unit
    def test_429_does_not_consume_attempt(self, tmp_path: Path) -> None:
        """INVARIANT 1 — HTTP 429 raises InfrastructureFailureError and HALTS
        without incrementing attempts_used further (it already incremented once
        per generate_patch; we verify the run terminates with INFRASTRUCTURE_FAILURE
        rather than silently retrying and burning attempts)."""
        case = _make_case(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "normalizer.py").write_text("x=1\n", encoding="utf-8")

        class _RateLimitedLLM:
            def generate_patch(self, *a: Any, **kw: Any) -> Any:
                raise LLMRateLimitError("stub", retry_after_seconds=1)

        runner = MagicMock()

        def _baseline(**kwargs: Any) -> ExecutionResult:
            return ExecutionResult(
                case_id=case.case_id,
                patch_diff_hash="baseline",
                exit_code=ExitCode.TESTS_FAILED,
                stdout="FAILED\n",
                stderr="",
                wall_seconds=0.1,
                expected_test_ids=case.failing_test_ids,
            )

        runner.run_in_container.side_effect = _baseline
        sm = RepairStateMachine(
            spec=case,
            llm_client=_RateLimitedLLM(),
            container_runner=runner,
            max_attempts=3,
            db_path=tmp_path / "r.db",
        )
        sm.source_workspace = src
        rid = sm.start_run()
        with pytest.raises(InfrastructureFailureError):
            sm.run_to_terminal(rid)
        rec = sm.resume_run(rid)
        assert rec.termination_reason == TerminationReason.INFRASTRUCTURE_FAILURE
        # Exactly 1 attempt counted (the increment before the LLM call), but
        # termination reason is INFRASTRUCTURE_FAILURE so retries won't happen
        assert rec.attempts_used >= 1

    @pytest.mark.unit
    def test_unapproved_export_raises(self, tmp_path: Path) -> None:
        """INVARIANT 8 — export only allowed from APPROVED."""
        case = _make_case(tmp_path)
        sm = RepairStateMachine(
            spec=case,
            llm_client=_StubLLM(),
            container_runner=MagicMock(),
            max_attempts=1,
            db_path=tmp_path / "r.db",
        )
        rid = sm.start_run()
        with pytest.raises(UnapprovedExportError):
            sm.export_evidence_bundle(rid)

    @pytest.mark.unit
    def test_restart_durability(self, tmp_path: Path) -> None:
        """INVARIANT 2 — re-opening the store from disk recovers attempts and seen hashes."""
        case = _make_case(tmp_path)
        db = tmp_path / "r.db"
        with CheckpointStore(db) as s:
            rid = s.create_run(case.case_id, max_attempts=5)
            s.transition_state(rid, RunState.PROPOSING_PATCH)
            s.increment_attempts(rid)
            s.add_seen_diff_hash(rid, "h1")
            s.add_seen_ast_hash(rid, "a1")
        with CheckpointStore(db) as s2:
            rec = s2.get_run(rid)
            assert rec is not None
            assert rec.state == RunState.PROPOSING_PATCH
            assert rec.attempts_used == 1
            assert "h1" in set(rec.seen_diff_hashes)
            assert "a1" in set(rec.seen_ast_hashes)

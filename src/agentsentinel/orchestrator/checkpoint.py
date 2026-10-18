"""Durable SQLite-backed state store for Milestone 4.

Uses Python stdlib :mod:`sqlite3` with:
- ``PRAGMA journal_mode=WAL``       (concurrent readers + single writer)
- ``PRAGMA synchronous=NORMAL``     (durable across power loss without fsync-per-tx)
- ``PRAGMA foreign_keys=ON``        (enforce FK between runs <-> attempts)

Schema
------
``runs``        : one row per repair run, keyed by ``run_id`` (UUID text).
``attempts``    : one row per patch attempt within a run, keyed by
                  ``(run_id, attempt_index)``.

Every state transition and attempt increment is committed atomically
(``with conn:``) at the exact boundary so killing the process mid-run never
loses the attempt count or token ledger.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import Any

# ---------------------------------------------------------------------------
# Enums for run/attempt state
# ---------------------------------------------------------------------------


class RunState(StrEnum):
    """Lifecycle states of a repair run."""

    INIT = "INIT"
    REPRODUCING_BASELINE = "REPRODUCING_BASELINE"
    PROPOSING_PATCH = "PROPOSING_PATCH"
    VALIDATING_POLICY = "VALIDATING_POLICY"
    APPLYING_PATCH = "APPLYING_PATCH"
    VERIFYING_IN_SANDBOX = "VERIFYING_IN_SANDBOX"
    AWAITING_HUMAN_APPROVAL = "AWAITING_HUMAN_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    TERMINATED_FAILED = "TERMINATED_FAILED"


class AttemptStatus(StrEnum):
    """Terminal/non-terminal statuses for a single patch attempt."""

    PENDING = "PENDING"
    GENERATED = "GENERATED"
    POLICY_REJECTED = "POLICY_REJECTED"
    APPLY_FAILED = "APPLY_FAILED"
    TEST_FAILED = "TEST_FAILED"
    PASSED_PENDING_APPROVAL = "PASSED_PENDING_APPROVAL"
    DUPLICATE = "DUPLICATE"
    LLM_ERROR = "LLM_ERROR"


class TerminationReason(StrEnum):
    """Why a run reached TERMINATED_FAILED (or REJECTED)."""

    NONE = "NONE"
    MAX_ATTEMPTS_EXHAUSTED = "MAX_ATTEMPTS_EXHAUSTED"
    BASELINE_NOT_REPRODUCED = "BASELINE_NOT_REPRODUCED"
    HARNESS_BROKEN = "HARNESS_BROKEN"
    DUPLICATE_PATCH = "DUPLICATE_PATCH"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"
    HUMAN_REJECTED = "HUMAN_REJECTED"
    REJECTED_BY_REVIEWER = "REJECTED_BY_REVIEWER"
    FIX_VERIFIED = "FIX_VERIFIED"


# ---------------------------------------------------------------------------
# JSON serde helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _dumps(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def _loads(s: str | None) -> object:
    """Parse JSON string to a Python value; returns None for empty/None input."""
    if s is None or s == "":
        return cast("object", None)
    return cast("object", json.loads(s))


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunRecord:
    """In-memory view of a ``runs`` row."""

    run_id: str
    case_id: str
    state: RunState
    termination_reason: TerminationReason
    attempts_used: int
    max_attempts: int
    baseline_result_json: dict[str, Any] | None
    seen_diff_hashes: list[str]
    seen_ast_hashes: list[str]
    approval_record: dict[str, Any] | None
    created_at_utc: str
    updated_at_utc: str
    spec_json: dict[str, Any] | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id              TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL,
    state               TEXT NOT NULL,
    termination_reason  TEXT NOT NULL DEFAULT 'NONE',
    attempts_used       INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL,
    baseline_result_json TEXT,
    seen_diff_hashes_json TEXT NOT NULL DEFAULT '[]',
    seen_ast_hashes_json TEXT NOT NULL DEFAULT '[]',
    approval_record_json TEXT,
    created_at_utc      TEXT NOT NULL,
    updated_at_utc      TEXT NOT NULL,
    spec_json           TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    run_id              TEXT NOT NULL,
    attempt_index       INTEGER NOT NULL,
    status              TEXT NOT NULL,
    proposal_json       TEXT,
    usage_json          TEXT,
    cost_usd            REAL,
    error_type          TEXT,
    error_detail        TEXT,
    execution_result_json TEXT,
    diff_hash           TEXT,
    ast_hash            TEXT,
    timestamp_utc       TEXT NOT NULL,
    PRIMARY KEY (run_id, attempt_index),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id);
"""


# ---------------------------------------------------------------------------
# CheckpointStore
# ---------------------------------------------------------------------------


class CheckpointStore:
    """A thin, strictly-typed wrapper over a single SQLite database file.

    The store owns the connection lifecycle. All public methods that mutate
    state use ``with self._conn:`` context managers to commit atomically.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.executescript(_SCHEMA)
        # Migration for databases created before M6 persisted CaseSpec.
        cols = {
            str(r[1]) for r in self._conn.execute("PRAGMA table_info(runs)").fetchall()
        }
        if "spec_json" not in cols:
            self._conn.execute("ALTER TABLE runs ADD COLUMN spec_json TEXT")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()

    def __enter__(self) -> CheckpointStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Run creation / retrieval
    # ------------------------------------------------------------------

    def create_run(
        self,
        case_id: str,
        max_attempts: int,
        spec_json: dict[str, Any] | None = None,
    ) -> str:
        """Create a new run row in INIT state and return its run_id."""
        run_id = uuid.uuid4().hex
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO runs (run_id, case_id, state, termination_reason,
                                  attempts_used, max_attempts, created_at_utc,
                                  updated_at_utc, spec_json)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    case_id,
                    RunState.INIT.value,
                    TerminationReason.NONE.value,
                    max_attempts,
                    now,
                    now,
                    _dumps(spec_json) if spec_json is not None else None,
                ),
            )
        return run_id

    def get_run(self, run_id: str) -> RunRecord | None:
        cur = self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?",
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return _row_to_run_record(row)

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def transition_state(self, run_id: str, new_state: RunState) -> None:
        """Atomically update the state and updated_at for a run."""
        now = _now_iso()
        with self._conn:
            cur = self._conn.execute(
                "UPDATE runs SET state = ?, updated_at_utc = ? WHERE run_id = ?",
                (new_state.value, now, run_id),
            )
            if cur.rowcount != 1:
                raise KeyError(f"run_id {run_id!r} not found")

    def set_termination(
        self,
        run_id: str,
        end_state: RunState,
        reason: TerminationReason,
    ) -> None:
        now = _now_iso()
        with self._conn:
            cur = self._conn.execute(
                """
                UPDATE runs
                SET state = ?, termination_reason = ?, updated_at_utc = ?
                WHERE run_id = ?
                """,
                (end_state.value, reason.value, now, run_id),
            )
            if cur.rowcount != 1:
                raise KeyError(f"run_id {run_id!r} not found")

    def set_baseline_result(self, run_id: str, result_json: dict[str, Any]) -> None:
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE runs SET baseline_result_json = ?, updated_at_utc = ? WHERE run_id = ?",
                (_dumps(result_json), now, run_id),
            )

    def set_approval_record(
        self, run_id: str, approval_record: dict[str, Any]
    ) -> None:
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE runs SET approval_record_json = ?, state = ?, "
                "updated_at_utc = ? WHERE run_id = ?",
                (
                    _dumps(approval_record),
                    RunState.APPROVED.value,
                    now,
                    run_id,
                ),
            )

    # ------------------------------------------------------------------
    # Seen-hash bookkeeping (for dedup)
    # ------------------------------------------------------------------

    def get_seen_hashes(self, run_id: str) -> tuple[set[str], set[str]]:
        cur = self._conn.execute(
            "SELECT seen_diff_hashes_json, seen_ast_hashes_json FROM runs WHERE run_id = ?",
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(f"run_id {run_id!r} not found")
        diff_list = cast("list[str]", _loads(row[0]) or [])
        ast_list = cast("list[str]", _loads(row[1]) or [])
        return set(diff_list), set(ast_list)

    def add_seen_diff_hash(self, run_id: str, diff_hash: str) -> None:
        diffs, asts = self.get_seen_hashes(run_id)
        diffs.add(diff_hash)
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE runs SET seen_diff_hashes_json = ?, updated_at_utc = ? WHERE run_id = ?",
                (_dumps(sorted(diffs)), now, run_id),
            )

    def add_seen_ast_hash(self, run_id: str, ast_hash: str) -> None:
        diffs, asts = self.get_seen_hashes(run_id)
        asts.add(ast_hash)
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE runs SET seen_ast_hashes_json = ?, updated_at_utc = ? WHERE run_id = ?",
                (_dumps(sorted(asts)), now, run_id),
            )

    def increment_attempts(self, run_id: str) -> int:
        """Atomically increment attempts_used and return the new attempt_index
        (1-based) that the caller should use to record the next attempt."""
        now = _now_iso()
        with self._conn:
            cur = self._conn.execute(
                "UPDATE runs SET attempts_used = attempts_used + 1, "
                "updated_at_utc = ? WHERE run_id = ?",
                (now, run_id),
            )
            if cur.rowcount != 1:
                raise KeyError(f"run_id {run_id!r} not found")
        cur = self._conn.execute(
            "SELECT attempts_used FROM runs WHERE run_id = ?", (run_id,)
        )
        return int(cur.fetchone()[0])

    # ------------------------------------------------------------------
    # Attempt recording
    # ------------------------------------------------------------------

    def record_attempt_start(self, run_id: str, attempt_index: int) -> None:
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO attempts (run_id, attempt_index, status, timestamp_utc)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id, attempt_index) DO UPDATE SET
                    status=excluded.status,
                    timestamp_utc=excluded.timestamp_utc
                """,
                (run_id, attempt_index, AttemptStatus.PENDING.value, now),
            )

    def record_attempt_generated(
        self,
        run_id: str,
        attempt_index: int,
        proposal_json: dict[str, Any],
        usage_json: dict[str, Any],
        cost_usd: float | None,
        diff_hash: str,
    ) -> None:
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE attempts
                   SET status = ?, proposal_json = ?, usage_json = ?,
                       cost_usd = ?, diff_hash = ?, timestamp_utc = ?
                 WHERE run_id = ? AND attempt_index = ?
                """,
                (
                    AttemptStatus.GENERATED.value,
                    _dumps(proposal_json),
                    _dumps(usage_json),
                    cost_usd,
                    diff_hash,
                    now,
                    run_id,
                    attempt_index,
                ),
            )

    def get_attempts(self, run_id: str) -> list[AttemptRecord]:
        """Return all attempts for a run ordered by attempt_index."""
        cur = self._conn.execute(
            """
            SELECT run_id, attempt_index, status, proposal_json, usage_json,
                   cost_usd, error_type, error_detail, execution_result_json,
                   diff_hash, ast_hash, timestamp_utc
              FROM attempts
             WHERE run_id = ?
             ORDER BY attempt_index ASC
            """,
            (run_id,),
        )
        return [_row_to_attempt_record(r) for r in cur.fetchall()]

    def record_attempt_outcome(
        self,
        run_id: str,
        attempt_index: int,
        status: AttemptStatus,
        error_type: str | None = None,
        error_detail: str | None = None,
        execution_result_json: dict[str, Any] | None = None,
        ast_hash: str | None = None,
    ) -> None:
        now = _now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE attempts
                   SET status = ?, error_type = ?, error_detail = ?,
                       execution_result_json = ?, ast_hash = ?, timestamp_utc = ?
                 WHERE run_id = ? AND attempt_index = ?
                """,
                (
                    status.value,
                    error_type,
                    error_detail,
                    _dumps(execution_result_json) if execution_result_json is not None else None,
                    ast_hash,
                    now,
                    run_id,
                    attempt_index,
                ),
            )


# ---------------------------------------------------------------------------
# Row decoding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttemptRecord:
    """In-memory view of an ``attempts`` row."""

    run_id: str
    attempt_index: int
    status: AttemptStatus
    proposal_json: dict[str, Any] | None
    usage_json: dict[str, Any] | None
    cost_usd: float | None
    error_type: str | None
    error_detail: str | None
    execution_result_json: dict[str, Any] | None
    diff_hash: str | None
    ast_hash: str | None
    timestamp_utc: str


def _row_to_attempt_record(row: sqlite3.Row | tuple[Any, ...]) -> AttemptRecord:
    (
        run_id,
        attempt_index,
        status,
        proposal_json,
        usage_json,
        cost_usd,
        error_type,
        error_detail,
        execution_result_json,
        diff_hash,
        ast_hash,
        timestamp_utc,
    ) = tuple(row)
    return AttemptRecord(
        run_id=str(run_id),
        attempt_index=int(attempt_index),
        status=AttemptStatus(status),
        proposal_json=cast("dict[str, Any] | None", _loads(proposal_json)),
        usage_json=cast("dict[str, Any] | None", _loads(usage_json)),
        cost_usd=float(cost_usd) if cost_usd is not None else None,
        error_type=None if error_type is None else str(error_type),
        error_detail=None if error_detail is None else str(error_detail),
        execution_result_json=cast(
            "dict[str, Any] | None", _loads(execution_result_json)
        ),
        diff_hash=None if diff_hash is None else str(diff_hash),
        ast_hash=None if ast_hash is None else str(ast_hash),
        timestamp_utc=str(timestamp_utc),
    )


def _row_to_run_record(row: sqlite3.Row | tuple[Any, ...]) -> RunRecord:
    # sqlite3.Row supports indexing; plain tuple from connect() without row_factory
    values = tuple(row)
    (
        run_id,
        case_id,
        state,
        termination_reason,
        attempts_used,
        max_attempts,
        baseline_result_json,
        seen_diff_hashes_json,
        seen_ast_hashes_json,
        approval_record_json,
        created_at_utc,
        updated_at_utc,
    ) = values[:12]
    spec_json = values[12] if len(values) > 12 else None
    return RunRecord(
        run_id=run_id,
        case_id=case_id,
        state=RunState(state),
        termination_reason=TerminationReason(termination_reason),
        attempts_used=int(attempts_used),
        max_attempts=int(max_attempts),
        baseline_result_json=cast(
            "dict[str, Any] | None", _loads(baseline_result_json)
        ),
        seen_diff_hashes=cast(
            "list[str]", list(cast("list[str]", _loads(seen_diff_hashes_json)) or [])
        ),
        seen_ast_hashes=cast(
            "list[str]", list(cast("list[str]", _loads(seen_ast_hashes_json)) or [])
        ),
        approval_record=cast("dict[str, Any] | None", _loads(approval_record_json)),
        created_at_utc=created_at_utc,
        updated_at_utc=updated_at_utc,
        spec_json=cast("dict[str, Any] | None", _loads(spec_json)),
    )


__all__ = [
    "AttemptRecord",
    "AttemptStatus",
    "CheckpointStore",
    "RunRecord",
    "RunState",
    "TerminationReason",
]

"""R&D requirements not covered by the original M14/M15 schema tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from agentsentinel.cli.bundle_verifier import BundleVerificationReport
from agentsentinel.cli.main import main
from agentsentinel.verification.ci_gate import run_ci_gate_audit, usage_error_report

if TYPE_CHECKING:
    from pathlib import Path


def test_ci_usage_status_matches_exit_code(tmp_path: Path, capsys) -> None:
    assert usage_error_report("bad input").status == "USAGE_ERROR"
    assert run_ci_gate_audit("not a diff", tmp_path).status == "USAGE_ERROR"
    assert main(["ci-gate"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "USAGE_ERROR"


@pytest.mark.parametrize("code", [0, 10, 20, 30, 40, 50])
def test_verifier_gate_failure_event_is_derived_without_changing_old_constructors(
    code: int,
) -> None:
    report = BundleVerificationReport(
        "2026-10-27T00:00:00Z",
        "bundle",
        "unknown",
        None,
        (1,),
        "FAILED" if code else "PASSED",
        None,
        (),
        code,
    )
    assert report.to_dict()["event"] == (f"EVENT_G{code // 10}_FAILED" if code else None)


def test_positional_verifier_bundle_path_and_legacy_flag_both_work(tmp_path: Path, capsys) -> None:
    for args in (
        ["verify-bundle", str(tmp_path)],
        ["verify-bundle", "--bundle-dir", str(tmp_path)],
    ):
        assert main(args) == 10
        assert json.loads(capsys.readouterr().out)["event"] == "EVENT_G1_FAILED"


def test_conflicting_verifier_bundle_path_forms_are_usage_error(tmp_path: Path, capsys) -> None:
    assert main(["verify-bundle", str(tmp_path), "--bundle-dir", str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_argument"


@pytest.mark.parametrize("test_source", ["def broken(:\n", "\ud800"])
def test_ci_fails_closed_when_discovered_test_oracle_cannot_be_read(
    tmp_path: Path, test_source: str
) -> None:
    (tmp_path / "test_app.py").write_bytes(test_source.encode("utf-8", errors="surrogatepass"))
    (tmp_path / "app.py").write_text("def f(): return 1\n", encoding="utf-8", newline="\n")
    raw = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-def f(): return 1\n+def f(): return 2\n"
    assert run_ci_gate_audit(raw, tmp_path).exit_code == 2


def test_legacy_literal_collector_can_still_ignore_unparseable_test_files(tmp_path: Path) -> None:
    from agentsentinel.verification.overfit_guard import extract_test_assertion_literals

    (tmp_path / "test_app.py").write_text("def broken(:\n", encoding="utf-8", newline="\n")
    assert extract_test_assertion_literals(tmp_path) == frozenset()

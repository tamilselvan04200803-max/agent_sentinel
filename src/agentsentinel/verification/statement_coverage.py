"""Optional statement-start coverage, executed exclusively by a container runner."""
from __future__ import annotations

import json
import math
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import HarnessSetupError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import StatementCoverageReport
from agentsentinel.verification.mutation_batch import (
    _execute_payload,
    _validate_relative_path,
    build_shadow_workspace_prelude,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentsentinel.verification.mutation_batch import ContainerRunnerProtocol

_MARKER = "AGENTSENTINEL_COVERAGE_V1:"
_MAX_STATEMENTS = 2_000


def build_statement_coverage_script() -> str:
    """Build trusted wrapper text; never execute it on the host."""
    return build_shadow_workspace_prelude() + r'''
MARKER = "AGENTSENTINEL_COVERAGE_V1:"
REPORT = Path("/tmp/agentsentinel_coverage_child.json")
CHILD = r"""
import json
from pathlib import Path
import sys
import threading
import pytest

root = Path("/tmp/mut_workspace")
payload = json.loads(sys.argv[1])
wanted = {(str(root / path), line): (path, line) for path, line in payload["statements"]}
hits = set()
passed = set()

class Recorder:
    def pytest_runtest_logreport(self, report):
        if report.when == "call" and report.passed:
            passed.add(report.nodeid)

def observe(frame, event, arg):
    if event == "line":
        key = (frame.f_code.co_filename, frame.f_lineno)
        if key in wanted:
            hits.add(wanted[key])
    return observe

sys.path[:0] = [str(root / "src"), str(root)]
sys.settrace(observe)
threading.settrace(observe)
try:
    code = int(pytest.main(["-x", "--tb=no", "-q", "--", *payload["test_ids"]],
                           plugins=[Recorder()]))
finally:
    sys.settrace(None)
    threading.settrace(None)
Path("/tmp/agentsentinel_coverage_child.json").write_text(
    json.dumps({"hits": sorted(hits), "passed_ids": sorted(passed)}, separators=(",", ":")),
    encoding="utf-8", newline="\n",
)
sys.exit(code)
"""


def main(serialized):
    global PAYLOAD_FILE
    status = {"status": "setup_error"}
    exit_code = 3
    try:
        if serialized.startswith("/workspace/"):
            path = Path(serialized)
            if path.parent != SOURCE or not path.resolve().is_relative_to(SOURCE):
                raise ValueError("invalid control file")
            PAYLOAD_FILE = path.name
            serialized = path.read_text(encoding="utf-8")
        payload = json.loads(serialized)
        for path, line in payload["statements"]:
            relative_path(path)
            if not isinstance(line, int) or line < 1:
                raise ValueError("invalid statement")
        for node in payload["test_ids"]:
            relative_path(node.split("::", 1)[0])
        become_subreaper()
        reset_shadow()
        REPORT.unlink(missing_ok=True)
        copy_shadow()
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", CHILD, json.dumps(payload)],
            cwd=SHADOW, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        code, timed_out = None, False
        try:
            try:
                code = process.wait(timeout=payload["timeout_seconds"])
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            stop_group(process, True)
        hits, passed = [], []
        if not timed_out:
            if code not in (0, 1) or REPORT.stat().st_size > 200000:
                raise ValueError("pytest or coverage harness failed")
            record = json.loads(REPORT.read_text(encoding="utf-8"))
            hits, passed = record["hits"], record["passed_ids"]
        status = {"status": "ok", "hits": hits, "test_exit_code": code,
                  "timed_out": timed_out, "passed_ids": passed}
        exit_code = 0
    except Exception:
        status = {"status": "setup_error"}
        exit_code = 3
    finally:
        try:
            reset_shadow()
            REPORT.unlink(missing_ok=True)
        except Exception:
            status = {"status": "setup_error"}
            exit_code = 3
    print(MARKER + json.dumps(status, separators=(",", ":")), flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
'''


def run_statement_coverage_probe(
    *, runner: ContainerRunnerProtocol, case_id: str, patch_diff_hash: str,
    workspace_host_path: Path, failing_test_ids: tuple[str, ...],
    statement_lines: tuple[tuple[str, int], ...], timeout_seconds: float = 30.0,
) -> StatementCoverageReport:
    """Report advisory line observations; infrastructure failures never imply success."""
    if not math.isfinite(timeout_seconds) or timeout_seconds < 1:
        raise ValueError("timeout_seconds must be finite and at least one")
    if not failing_test_ids or len(failing_test_ids) > 2_000:
        raise ValueError("A bounded nonempty test selection is required")
    for node in failing_test_ids:
        if not isinstance(node, str) or len(node) > 4096 or "\0" in node:
            raise ValueError("Invalid test id")
        _validate_relative_path(node.split("::", 1)[0])
        if node.startswith("-"):
            raise ValueError("Expected an exact test node ID")
    if len(statement_lines) > _MAX_STATEMENTS:
        raise ValueError("Statement coverage budget exceeded")
    for path, line in statement_lines:
        _validate_relative_path(path)
        if type(line) is not int or line < 1:
            raise ValueError("Invalid statement start")
    expected = set(statement_lines)
    if not expected:
        return StatementCoverageReport((), (), 0, False)
    payload = json.dumps({"statements": sorted(expected), "test_ids": failing_test_ids,
                          "timeout_seconds": timeout_seconds}, separators=(",", ":"))
    result = _execute_payload(runner, case_id, patch_diff_hash, workspace_host_path,
                              build_statement_coverage_script(), payload)
    if (result.exit_code != ExitCode.OK or result.stdout_truncated or result.stderr_truncated
            or result.case_id != case_id or result.patch_diff_hash != patch_diff_hash
            or not result.stdout.startswith(_MARKER)):
        raise HarnessSetupError("Statement coverage wrapper failed")
    serialized = result.stdout[len(_MARKER):].removesuffix("\n")
    try:
        record = json.loads(serialized)
        if json.dumps(record, separators=(",", ":"), allow_nan=False) != serialized:
            raise ValueError("Noncanonical coverage record")
        if not isinstance(record, dict) or set(record) != {
            "status", "hits", "test_exit_code", "timed_out", "passed_ids",
        } or record["status"] != "ok":
            raise ValueError("Incomplete coverage record")
        hits, passed = record["hits"], record["passed_ids"]
        if not isinstance(hits, list) or len(hits) > _MAX_STATEMENTS:
            raise ValueError("Invalid observations")
        observed: set[tuple[str, int]] = set()
        for row in hits:
            if (not isinstance(row, list) or len(row) != 2 or not isinstance(row[0], str)
                    or type(row[1]) is not int or (row[0], row[1]) not in expected):
                raise ValueError("Unexpected observation")
            observed.add((row[0], row[1]))
        if len(observed) != len(hits):
            raise ValueError("Duplicate observations")
        code, timed_out = record["test_exit_code"], record["timed_out"]
        if type(timed_out) is not bool or (
            (timed_out and code is not None) or
            (not timed_out and (type(code) is not int or code not in (0, 1)))
        ):
            raise ValueError("Invalid test outcome")
        if (not isinstance(passed, list) or not all(isinstance(node, str) for node in passed)
                or (code == 0 and not set(failing_test_ids).issubset(passed))):
            raise ValueError("Missing expected test evidence")
    except (ValueError, TypeError, RecursionError) as error:
        raise HarnessSetupError("Invalid statement coverage report") from error
    return StatementCoverageReport(tuple(sorted(observed)), tuple(sorted(expected - observed)),
                                   code, timed_out)

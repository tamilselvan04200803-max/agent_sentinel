"""Execute mutation probes in disposable container-only shadow workspaces."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Literal, Protocol, cast

from agentsentinel.domain.exceptions import HarnessSetupError, HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.sandbox.workspace import WorkspaceManager

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentsentinel.domain.models import ExecutionResult
    from agentsentinel.verification.differential_mutation import DifferentialPatchMutant

_MARKER = "AGENTSENTINEL_MUTATION_V1:"
_DETAILED_MARKER = "AGENTSENTINEL_MUTATION_V2:"


@dataclass(frozen=True)
class MutantExecutionResult:
    """One verified result from the opt-in ordered batch protocol."""

    mutant_id: str
    status: Literal["SURVIVED", "KILLED", "KILLED_BY_TIMEOUT"]
    exit_code: int | None
    runtime_sec: float

    @property
    def killed(self) -> bool:
        """Whether the child test oracle killed this mutant."""
        return self.status != "SURVIVED"


class ContainerRunnerProtocol(Protocol):
    """Existing sandbox boundary; this helper never executes project code locally."""

    def run_in_container(
        self,
        case_id: str,
        patch_diff_hash: str,
        workspace_host_path: Path,
        command: str | list[str],
    ) -> ExecutionResult: ...


def build_mutation_batch_script() -> str:
    """Return a standalone stdlib wrapper intended exclusively for a Linux container.

    Child streams never reach the reserved protocol channel. A new copy is made
    for every mutant, and all members of its process group die before cleanup.
    """
    return r'''
import ctypes
import importlib
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import signal
import subprocess
import sys
import time

SOURCE = Path("/workspace")
SHADOW = Path("/tmp/mut_workspace")
MARKER = "AGENTSENTINEL_MUTATION_V1:"
PAYLOAD_FILE = None


def relative_path(value):
    if (not isinstance(value, str) or not value or "\\" in value
            or "\0" in value or PurePosixPath(value).is_absolute()
            or PureWindowsPath(value).drive
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("unsafe relative path")
    return value


def become_subreaper():
    # Linux PR_SET_CHILD_SUBREAPER: adopt grandchildren so they can be reaped.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper setup failed")


def reset_shadow():
    if SHADOW.is_symlink():
        SHADOW.unlink()
    elif SHADOW.exists():
        shutil.rmtree(SHADOW)


def copy_shadow():
    root = SOURCE.resolve(strict=True)
    links = []
    # Inspect links without following directory links, preventing cycles and
    # accidental reads outside the read-only mount during the actual copy.
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    raise ValueError("source symlink escapes workspace")
                links.append((path.relative_to(root), resolved.relative_to(root)))
    shutil.copytree(root, SHADOW, symlinks=True)
    if PAYLOAD_FILE is not None:
        (SHADOW / PAYLOAD_FILE).unlink()
    # Remap even absolute internal source links into the disposable tree.
    for relative, target in links:
        copied = SHADOW / relative
        copied.unlink()
        copied.symlink_to(os.path.relpath(SHADOW / target, copied.parent))


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        # A child without descendants may already have been fully reaped.
        ...
    process.wait(timeout=2.0)
    # The subreaper owns surviving grandchildren after their parent exits.
    while True:
        try:
            os.waitpid(-process.pid, 0)
        except ChildProcessError:
            break


def evaluate(mutant, test_ids, timeout, detailed=False):
    reset_shadow()
    try:
        copy_shadow()
        relative = relative_path(mutant["file_path"])
        target = (SHADOW / relative).resolve(strict=True)
        if not target.is_relative_to(SHADOW.resolve()) or not target.is_file():
            raise ValueError("mutant target escapes shadow workspace")
        source = mutant["mutated_source"]
        if not isinstance(source, str):
            raise ValueError("mutated source must be text")
        target.write_text(source, encoding="utf-8")
        for directory, dirs, files in os.walk(SHADOW, followlinks=False):
            if "__pycache__" in dirs:
                cache = Path(directory) / "__pycache__"
                if cache.is_symlink():
                    cache.unlink()
                else:
                    shutil.rmtree(cache)
                dirs.remove("__pycache__")
        importlib.invalidate_caches()
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join((str(SHADOW / "src"), str(SHADOW)))
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        started = time.perf_counter()
        process = subprocess.Popen(
            [sys.executable, "-B", "-m", "pytest", "-x", "--tb=no", "-q", "--", *test_ids],
            cwd=SHADOW, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        try:
            try:
                code = process.wait(timeout=timeout)
                runtime = time.perf_counter() - started
                outcome = "survived" if code == 0 else "killed"
                status = "SURVIVED" if code == 0 else "KILLED"
                if detailed and code in (2, 3, 4, 5):
                    raise ValueError("pytest harness failed")
            except subprocess.TimeoutExpired:
                outcome = "killed"
                status, code, runtime = "KILLED_BY_TIMEOUT", None, timeout
        finally:
            stop_group(process)
        if detailed:
            return {"mutant_id": mutant["id"], "status": status,
                    "exit_code": code, "runtime_sec": runtime}
        return outcome
    finally:
        reset_shadow()


def main(serialized):
    global PAYLOAD_FILE
    status = {"status": "setup_error"}
    code = 3
    marker = MARKER
    try:
        if serialized.startswith("/workspace/"):
            payload_path = Path(serialized)
            if payload_path.parent != SOURCE or not payload_path.resolve().is_relative_to(SOURCE):
                raise ValueError("invalid payload file")
            PAYLOAD_FILE = payload_path.name
            serialized = payload_path.read_text(encoding="utf-8")
        payload = json.loads(serialized)
        detailed = payload.get("protocol_version") == 2
        if detailed:
            marker = "AGENTSENTINEL_MUTATION_V2:"
        timeout = payload["timeout_seconds"]
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 1:
            raise ValueError("invalid timeout")
        test_ids = payload["failing_test_ids"]
        if not isinstance(test_ids, list) or not test_ids:
            raise ValueError("missing tests")
        for test_id in test_ids:
            if not isinstance(test_id, str) or "\0" in test_id:
                raise ValueError("invalid test id")
            relative_path(test_id.split("::", 1)[0])
        mutants = payload["mutants"]
        if not isinstance(mutants, list):
            raise ValueError("invalid mutants")
        if detailed:
            identifiers = [mutant["id"] for mutant in mutants]
            if (not all(isinstance(identifier, str) and identifier for identifier in identifiers)
                    or len(set(identifiers)) != len(identifiers)):
                raise ValueError("invalid mutant ids")
        become_subreaper()
        outcomes = [evaluate(mutant, test_ids, timeout, detailed) for mutant in mutants]
        status = {"status": "ok", "outcomes": outcomes}
        code = 0
    except Exception:
        # Exception messages and child-controlled output are never protocol data.
        status = {"status": "setup_error"}
        code = 3
    finally:
        try:
            reset_shadow()
        except Exception:
            status = {"status": "setup_error"}
            code = 3
    print(marker + json.dumps(status, separators=(",", ":")), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
'''.lstrip()


def _validate_relative_path(value: str) -> None:
    if (
        not value
        or "\\" in value
        or "\0" in value
        or PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).drive
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise ValueError(f"Unsafe mutation probe path: {value!r}")


def _read_outcome(result: ExecutionResult, case_id: str, patch_diff_hash: str) -> bool:
    if (
        result.exit_code != ExitCode.OK
        or result.stdout_truncated
        or result.stderr_truncated
        or result.case_id != case_id
        or result.patch_diff_hash != patch_diff_hash
        or not result.stdout.startswith(_MARKER)
    ):
        raise HarnessSetupError("Mutation wrapper failed or returned an untrusted report")
    # The wrapper has two canonical success records. Exact comparison rejects
    # duplicate JSON keys, appended/spoofed reports, and every partial record.
    reports = {
        _MARKER + '{"status":"ok","outcomes":["killed"]}': True,
        _MARKER + '{"status":"ok","outcomes":["survived"]}': False,
    }
    record = result.stdout.removesuffix("\n")
    if record not in reports:
        raise HarnessSetupError("Mutation wrapper did not return a complete singleton verdict")
    return reports[record]


def _execute_payload(
    runner: ContainerRunnerProtocol,
    case_id: str,
    patch_diff_hash: str,
    workspace: Path,
    script: str,
    payload: str,
) -> ExecutionResult:
    """Keep command arguments below Windows limits without modifying source."""
    command = ["python", "-I", "-B", "-c", script, payload]
    units = len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2
    # Reserve room for Docker flags and its workspace mount on Windows. This
    # also avoids per-argument limits on Unix for large generated modules.
    if units < 20000:
        return runner.run_in_container(case_id, patch_diff_hash, workspace, command)
    manager = WorkspaceManager()
    with manager.create_workspace() as scratch:
        destination = Path(scratch)
        try:
            root = workspace.resolve(strict=True)
            links: list[tuple[Path, Path, bool]] = []
            for directory, dirs, files in os.walk(root, followlinks=False):
                for name in dirs + files:
                    path = Path(directory) / name
                    if path.is_symlink():
                        resolved = path.resolve(strict=True)
                        if not resolved.is_relative_to(root):
                            raise ValueError("source symlink escapes workspace")
                        links.append((path.relative_to(root), resolved.relative_to(root),
                                      resolved.is_dir()))
            shutil.copytree(root, destination, symlinks=True, dirs_exist_ok=True)
            for relative, target, is_directory in links:
                copied = destination / relative
                copied.unlink()
                copied.symlink_to(
                    os.path.relpath(destination / target, copied.parent),
                    target_is_directory=is_directory,
                )
            manager.scrub_git_history(destination)
            name = f".agentsentinel_mutation_{uuid.uuid4().hex}.json"
            with (destination / name).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
        except (OSError, ValueError) as error:
            raise HarnessSetupError("Cannot stage mutation payload") from error
        command[-1] = f"/workspace/{name}"
        return runner.run_in_container(case_id, patch_diff_hash, destination, command)


def run_in_container_mutation_batch(
    *,
    runner: ContainerRunnerProtocol,
    case_id: str,
    patch_diff_hash: str,
    workspace_host_path: Path,
    mutants: Sequence[DifferentialPatchMutant],
    failing_test_ids: tuple[str, ...],
    baseline_wall_seconds: float,
    single_container: bool = False,
) -> tuple[bool, ...]:
    """Return ordered kill verdicts, with infrastructure failures left explicit.

    Singleton containers make outer harness timeouts attributable to exactly one
    mutant. Repository source and tests are only interpreted inside that boundary.
    Opting into ``single_container`` uses verified V2 reports and propagates an
    outer timeout: it cannot be attributed to any particular mutant in a batch.
    """
    if single_container:
        return tuple(outcome.killed for outcome in run_in_container_mutation_batch_detailed(
            runner=runner, case_id=case_id, patch_diff_hash=patch_diff_hash,
            workspace_host_path=workspace_host_path, mutants=mutants,
            failing_test_ids=failing_test_ids, baseline_wall_seconds=baseline_wall_seconds,
        ))
    if not mutants:
        return ()
    if not math.isfinite(baseline_wall_seconds) or baseline_wall_seconds < 0:
        raise ValueError("baseline_wall_seconds must be finite and nonnegative")
    timeout = max(1.0, 2.0 * baseline_wall_seconds)
    if not math.isfinite(timeout):
        raise ValueError("mutation timeout exceeds finite range")
    if not failing_test_ids:
        raise ValueError("mutation probing requires failing test ids")
    for test_id in failing_test_ids:
        if "\0" in test_id:
            raise ValueError("invalid failing test id")
        _validate_relative_path(test_id.split("::", 1)[0])
    for mutant in mutants:
        _validate_relative_path(mutant.file_path)
    script = build_mutation_batch_script()
    outcomes: list[bool] = []
    for mutant in mutants:
        payload = json.dumps(
            {
                "mutants": [
                    {"file_path": mutant.file_path, "mutated_source": mutant.mutated_source}
                ],
                "failing_test_ids": failing_test_ids,
                "timeout_seconds": timeout,
            },
            separators=(",", ":"),
        )
        try:
            result = _execute_payload(
                runner, case_id, patch_diff_hash, workspace_host_path, script, payload,
            )
        except HarnessTimeoutError:
            outcomes.append(True)
        else:
            outcomes.append(_read_outcome(result, case_id, patch_diff_hash))
    return tuple(outcomes)


def _read_detailed_outcomes(
    result: ExecutionResult, case_id: str, patch_diff_hash: str, identifiers: tuple[str, ...],
    timeout_seconds: float,
) -> tuple[MutantExecutionResult, ...]:
    if (
        result.exit_code != ExitCode.OK
        or result.stdout_truncated or result.stderr_truncated
        or result.case_id != case_id or result.patch_diff_hash != patch_diff_hash
        or not result.stdout.startswith(_DETAILED_MARKER)
    ):
        raise HarnessSetupError("Mutation batch failed or returned an untrusted report")
    serialized = result.stdout.removesuffix("\n").removeprefix(_DETAILED_MARKER)
    try:
        report = json.loads(serialized)
        # Exact round-trip rejects duplicate keys, trailing records and NaN.
        if json.dumps(report, separators=(",", ":"), allow_nan=False) != serialized:
            raise ValueError("noncanonical report")
        if not isinstance(report, dict) or set(report) != {"status", "outcomes"}:
            raise ValueError("invalid report fields")
        rows = report["outcomes"]
        if report["status"] != "ok" or not isinstance(rows, list) or len(rows) != len(identifiers):
            raise ValueError("incomplete batch")
        outcomes = []
        for identifier, row in zip(identifiers, rows, strict=True):
            if not isinstance(row, dict) or set(row) != {
                "mutant_id", "status", "exit_code", "runtime_sec",
            }:
                raise ValueError("invalid result fields")
            status, code, runtime = row["status"], row["exit_code"], row["runtime_sec"]
            if (
                row["mutant_id"] != identifier
                or status not in ("SURVIVED", "KILLED", "KILLED_BY_TIMEOUT")
                or type(runtime) not in (int, float) or not math.isfinite(runtime) or runtime < 0
                or (code is not None and type(code) is not int)
                or (status == "SURVIVED" and code != 0)
                or (status == "KILLED" and (code is None or code in (0, 2, 3, 4, 5)))
                or (status == "KILLED_BY_TIMEOUT"
                    and (code is not None or runtime != timeout_seconds))
            ):
                raise ValueError("invalid result values")
            outcomes.append(MutantExecutionResult(
                identifier, cast("Literal['SURVIVED', 'KILLED', 'KILLED_BY_TIMEOUT']", status),
                code, float(runtime),
            ))
        return tuple(outcomes)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
        raise HarnessSetupError("Mutation batch did not return complete ordered results") from error


def run_in_container_mutation_batch_detailed(
    *,
    runner: ContainerRunnerProtocol,
    case_id: str,
    patch_diff_hash: str,
    workspace_host_path: Path,
    mutants: Sequence[DifferentialPatchMutant],
    failing_test_ids: tuple[str, ...],
    baseline_wall_seconds: float,
) -> tuple[MutantExecutionResult, ...]:
    """Evaluate all mutants in one container, retaining detailed ordered results.

    This is an explicit capability opt-in. The runner signature and its outer
    resource/time limits remain unchanged; batches must fit that outer limit.
    Missing reports and outer timeouts are infrastructure failures, never kills.
    Pytest setup/usage/collection/interruption exit codes also fail the batch.
    """
    if not mutants:
        return ()
    if not math.isfinite(baseline_wall_seconds) or baseline_wall_seconds < 0:
        raise ValueError("baseline_wall_seconds must be finite and nonnegative")
    timeout = max(1.0, 2.0 * baseline_wall_seconds)
    if not math.isfinite(timeout):
        raise ValueError("mutation timeout exceeds finite range")
    if not failing_test_ids:
        raise ValueError("mutation probing requires failing test ids")
    for test_id in failing_test_ids:
        if "\0" in test_id:
            raise ValueError("invalid failing test id")
        _validate_relative_path(test_id.split("::", 1)[0])
    entries = []
    for index, mutant in enumerate(mutants):
        _validate_relative_path(mutant.file_path)
        identity = json.dumps(
            [index, mutant.file_path, mutant.function_name,
             mutant.mutation_description, mutant.mutated_source], separators=(",", ":"),
        )
        entries.append({
            "id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "file_path": mutant.file_path, "mutated_source": mutant.mutated_source,
        })
    payload = json.dumps({
        "protocol_version": 2, "mutants": entries,
        "failing_test_ids": failing_test_ids, "timeout_seconds": timeout,
    }, separators=(",", ":"))
    result = _execute_payload(
        runner, case_id, patch_diff_hash, workspace_host_path,
        build_mutation_batch_script(), payload,
    )
    return _read_detailed_outcomes(
        result, case_id, patch_diff_hash, tuple(entry["id"] for entry in entries), timeout,
    )

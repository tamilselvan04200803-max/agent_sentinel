"""Mutation wrapper tests execute trusted wrapper code with inert child doubles only."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentsentinel.domain.exceptions import HarnessSetupError, HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import ExecutionResult
from agentsentinel.verification.differential_mutation import DifferentialPatchMutant
from agentsentinel.verification.mutation_batch import (
    build_mutation_batch_script,
    run_in_container_mutation_batch,
)

MARKER = "AGENTSENTINEL_MUTATION_V1:"
MUTANT = DifferentialPatchMutant("pkg/mod.py", "check", "invert", "MUTATED = True\n")


def result(stdout=None, **changes):
    values = {
        "case_id": "case", "patch_diff_hash": "hash", "exit_code": ExitCode.OK,
        "stdout": stdout if stdout is not None else MARKER + '{"status":"ok","outcomes":["killed"]}\n',
        "stderr": "", "wall_seconds": 0.1,
    }
    values.update(changes)
    return ExecutionResult(**values)


def run(runner, mutants=(MUTANT,), baseline=0.1):
    return run_in_container_mutation_batch(
        runner=runner, case_id="case", patch_diff_hash="hash",
        workspace_host_path=Path("workspace"), mutants=mutants,
        failing_test_ids=("tests/test_mod.py::test_check",), baseline_wall_seconds=baseline,
    )


def test_zero_mutants_make_no_container_calls():
    runner = Mock()
    assert run(runner, mutants=()) == ()
    runner.run_in_container.assert_not_called()


def test_singleton_container_calls_preserve_order_and_use_safe_argv():
    runner = Mock()
    runner.run_in_container.side_effect = [
        result(), result(MARKER + '{"status":"ok","outcomes":["survived"]}\n'),
    ]
    assert run(runner, mutants=(MUTANT, MUTANT), baseline=2.5) == (True, False)
    assert runner.run_in_container.call_count == 2
    args = runner.run_in_container.call_args_list[0].args
    assert args[:3] == ("case", "hash", Path("workspace"))
    assert isinstance(args[3], list)
    assert args[3][:4] == ["python", "-I", "-B", "-c"]
    payload = json.loads(args[3][-1])
    assert payload == {
        "mutants": [{"file_path": "pkg/mod.py", "mutated_source": "MUTATED = True\n"}],
        "failing_test_ids": ["tests/test_mod.py::test_check"], "timeout_seconds": 5.0,
    }


def test_large_module_payload_uses_disposable_file_transport(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "mod.py").write_text("ORIGINAL = True\n", encoding="utf-8", newline="\n")
    large = DifferentialPatchMutant("mod.py", "check", "large", "#" + "x" * 45000 + "\n")
    mounted_paths = []

    def container(case_id, patch_hash, mounted, command):
        assert len(subprocess.list2cmdline(command)) < 20000
        assert command[-1].startswith("/workspace/")
        assert mounted != source
        mounted_paths.append(mounted)
        data = json.loads((mounted / Path(command[-1]).name).read_text(encoding="utf-8"))
        assert data["mutants"][0]["mutated_source"] == large.mutated_source
        assert (mounted / "mod.py").read_text(encoding="utf-8") == "ORIGINAL = True\n"
        return result()

    runner = Mock()
    runner.run_in_container.side_effect = container
    assert run_in_container_mutation_batch(
        runner=runner, case_id="case", patch_diff_hash="hash", workspace_host_path=source,
        mutants=(large,), failing_test_ids=("test_mod.py::test_check",), baseline_wall_seconds=0.2,
    ) == (True,)
    assert list(source.iterdir()) == [source / "mod.py"]
    assert all(not path.exists() for path in mounted_paths)


@pytest.mark.parametrize("stdout", [
    "", "pytest failed", MARKER + "{}", MARKER + "not json",
    MARKER + '{"status":"setup_error"}',
    MARKER + '{"status":"ok","outcomes":[]}',
    MARKER + '{"status":"ok","outcomes":[true]}',
    MARKER + '{"status":"ok","outcomes":["killed","survived"]}',
    MARKER + '{"status":"ok","outcomes":["killed"],"extra":1}',
    MARKER + '{"status":"ok","status":"ok","outcomes":["killed"]}',
    MARKER + '{"status":"ok","outcomes":["killed"]}\n' + MARKER + '{}',
])
def test_malformed_or_missing_reports_are_infrastructure_failures(stdout):
    runner = Mock()
    runner.run_in_container.return_value = result(stdout)
    with pytest.raises(HarnessSetupError):
        run(runner)


@pytest.mark.parametrize("changes", [
    {"stdout_truncated": True}, {"stderr_truncated": True},
    {"exit_code": ExitCode.INTERNAL_ERROR}, {"case_id": "wrong"},
    {"patch_diff_hash": "wrong"},
])
def test_untrusted_execution_metadata_cannot_count_as_kill(changes):
    runner = Mock()
    runner.run_in_container.return_value = result(**changes)
    with pytest.raises(HarnessSetupError):
        run(runner)


def test_outer_timeout_is_attributed_only_to_current_singleton():
    runner = Mock()
    runner.run_in_container.side_effect = [
        HarnessTimeoutError(5, "container"),
        result(MARKER + '{"status":"ok","outcomes":["survived"]}'),
    ]
    assert run(runner, mutants=(MUTANT, MUTANT)) == (True, False)


def test_container_infrastructure_exception_propagates():
    runner = Mock()
    error = HarnessSetupError("daemon unavailable")
    runner.run_in_container.side_effect = error
    with pytest.raises(HarnessSetupError) as raised:
        run(runner)
    assert raised.value is error


@pytest.mark.parametrize("path", ["../mod.py", "/mod.py", "C:/mod.py", "a/../mod.py", "a\\mod.py", "./mod.py", "a//mod.py"])
def test_bad_mutant_paths_are_rejected_before_container(path):
    runner = Mock()
    mutant = DifferentialPatchMutant(path, "check", "invert", "x = 1")
    with pytest.raises(ValueError):
        run(runner, mutants=(mutant,))
    runner.run_in_container.assert_not_called()


@pytest.mark.parametrize("baseline", [-1.0, float("inf"), float("nan")])
def test_invalid_baseline_is_rejected(baseline):
    with pytest.raises(ValueError):
        run(Mock(), baseline=baseline)


@pytest.fixture
def wrapper(tmp_path, monkeypatch):
    # Only our trusted wrapper executes here; pytest and repository code never do.
    namespace = {"__name__": "wrapper_test"}
    exec(compile(build_mutation_batch_script(), "<mutation-wrapper>", "exec"), namespace)
    source = tmp_path / "source"
    (source / "pkg" / "__pycache__").mkdir(parents=True)
    (source / "pkg" / "mod.py").write_text("ORIGINAL = True\n", encoding="utf-8")
    (source / "pkg" / "__pycache__" / "mod.pyc").write_bytes(b"stale")
    shadow = tmp_path / "mut_workspace"
    namespace["SOURCE"] = source
    namespace["SHADOW"] = shadow
    namespace["become_subreaper"] = Mock()
    monkeypatch.setattr(namespace["os"], "killpg", Mock(), raising=False)
    monkeypatch.setattr(namespace["os"], "waitpid", Mock(side_effect=ChildProcessError), raising=False)
    monkeypatch.setattr(namespace["signal"], "SIGKILL", 9, raising=False)
    payload = {
        "mutants": [{"file_path": "pkg/mod.py", "mutated_source": "MUTATED = True\n"}],
        "failing_test_ids": ["tests/test_mod.py::test_check"], "timeout_seconds": 1.0,
    }
    return SimpleNamespace(ns=namespace, source=source, shadow=shadow, payload=payload)


@pytest.mark.parametrize("child_exit, expected", [(0, "survived"), (1, "killed"), (5, "killed")])
def test_script_mutates_only_shadow_suppresses_output_and_cleans(wrapper, monkeypatch, capsys, child_exit, expected):
    observed = []

    def spawn(command, **kwargs):
        observed.append((wrapper.shadow / "pkg" / "mod.py").read_text(encoding="utf-8"))
        assert not (wrapper.shadow / "pkg" / "__pycache__").exists()
        assert command[1:] == ["-B", "-m", "pytest", "-x", "--tb=no", "-q", "--", "tests/test_mod.py::test_check"]
        assert kwargs["cwd"] == wrapper.shadow
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["start_new_session"] is True
        return SimpleNamespace(pid=321, wait=Mock(return_value=child_exit))

    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", spawn)
    assert wrapper.ns["main"](json.dumps(wrapper.payload)) == 0
    assert observed == ["MUTATED = True\n"]
    assert (wrapper.source / "pkg" / "mod.py").read_text(encoding="utf-8") == "ORIGINAL = True\n"
    assert not wrapper.shadow.exists()
    report = json.loads(capsys.readouterr().out.removeprefix(MARKER))
    assert report == {"status": "ok", "outcomes": [expected]}
    wrapper.ns["os"].killpg.assert_called_once_with(321, wrapper.ns["signal"].SIGKILL)


def test_timeout_kills_and_reaps_before_next_shadow_copy(wrapper, monkeypatch, capsys):
    events = []
    waits = iter([subprocess.TimeoutExpired("pytest", 1), -9])

    def wait(**kwargs):
        events.append("wait")
        value = next(waits)
        if isinstance(value, Exception):
            raise value
        return value

    def killpg(*args):
        events.append("kill")

    def spawn(*args, **kwargs):
        events.append("spawn")
        return SimpleNamespace(pid=321, wait=wait)

    monkeypatch.setattr(wrapper.ns["os"], "killpg", killpg)
    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", spawn)
    assert wrapper.ns["main"](json.dumps(wrapper.payload)) == 0
    assert events == ["spawn", "wait", "kill", "wait"]
    assert not wrapper.shadow.exists()
    assert '"killed"' in capsys.readouterr().out


@pytest.mark.parametrize("failure", ["copy", "spawn", "path"])
def test_script_setup_failure_is_reserved_status_not_kill(wrapper, monkeypatch, capsys, failure):
    if failure == "copy":
        monkeypatch.setattr(wrapper.ns["shutil"], "copytree", Mock(side_effect=OSError("copy")))
    elif failure == "spawn":
        monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", Mock(side_effect=OSError("spawn")))
    else:
        wrapper.payload["mutants"][0]["file_path"] = "../escape.py"
    assert wrapper.ns["main"](json.dumps(wrapper.payload)) == 3
    assert json.loads(capsys.readouterr().out.removeprefix(MARKER)) == {"status": "setup_error"}
    assert not wrapper.shadow.exists()


def test_batch_restores_pristine_shadow_between_mutants(wrapper, monkeypatch, capsys):
    wrapper.payload["mutants"].append({"file_path": "pkg/mod.py", "mutated_source": "SECOND = True\n"})
    observed = []

    def spawn(*args, **kwargs):
        assert not (wrapper.shadow / "created_by_child").exists()
        observed.append((wrapper.shadow / "pkg" / "mod.py").read_text(encoding="utf-8"))
        (wrapper.shadow / "created_by_child").write_text("inert", encoding="utf-8")
        return SimpleNamespace(pid=321, wait=Mock(return_value=0))

    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", spawn)
    assert wrapper.ns["main"](json.dumps(wrapper.payload)) == 0
    assert observed == ["MUTATED = True\n", "SECOND = True\n"]
    assert json.loads(capsys.readouterr().out.removeprefix(MARKER))["outcomes"] == ["survived", "survived"]


def test_source_symlink_escape_is_rejected_before_copy(wrapper, monkeypatch, capsys):
    link = wrapper.source / "pkg"
    outside = wrapper.source.parent / "outside"
    original_resolve = Path.resolve
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == link or original_is_symlink(self))
    monkeypatch.setattr(
        Path, "resolve",
        lambda self, **kwargs: outside if self == link else original_resolve(self, **kwargs),
    )
    copy = Mock(side_effect=AssertionError("unsafe source reached copy"))
    spawn = Mock(side_effect=AssertionError("unsafe source reached child"))
    monkeypatch.setattr(wrapper.ns["shutil"], "copytree", copy)
    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", spawn)
    assert wrapper.ns["main"](json.dumps(wrapper.payload)) == 3
    assert json.loads(capsys.readouterr().out.removeprefix(MARKER)) == {"status": "setup_error"}
    copy.assert_not_called()
    spawn.assert_not_called()


def test_mutant_target_symlink_escape_cannot_write_outside_shadow(wrapper, monkeypatch, capsys):
    target = wrapper.shadow / "pkg" / "mod.py"
    outside = wrapper.source.parent / "outside.py"
    outside.write_text("UNCHANGED\n", encoding="utf-8")
    original_resolve = Path.resolve
    monkeypatch.setattr(
        Path, "resolve",
        lambda self, **kwargs: outside if self == target else original_resolve(self, **kwargs),
    )
    spawn = Mock(side_effect=AssertionError("unsafe target reached child"))
    monkeypatch.setattr(wrapper.ns["subprocess"], "Popen", spawn)
    assert wrapper.ns["main"](json.dumps(wrapper.payload)) == 3
    assert outside.read_text(encoding="utf-8") == "UNCHANGED\n"
    assert not wrapper.shadow.exists()
    assert json.loads(capsys.readouterr().out.removeprefix(MARKER)) == {"status": "setup_error"}
    spawn.assert_not_called()

"""Live gate selection with real policy/application and sandbox boundary doubles."""

from dataclasses import replace
from difflib import unified_diff

import pytest

from agentsentinel.domain.exceptions import HarnessSetupError, HarnessTimeoutError
from agentsentinel.domain.exit_codes import ExitCode
from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
from agentsentinel.verification.post_pass_gate import run_ddmin_hunk_minimization

TEST_ID = "tests/test_calc.py::test_fix"
PRE = "def calculate(value):\n    return value - 1\n\n\n# retained context\n# retained context\n# retained context\n# original comment\n"
POST = PRE.replace("value - 1", "value + 1").replace("original comment", "new comment")


def diff(before=PRE, after=POST, path="calc.py"):
    return "".join(unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"a/{path}", tofile=f"b/{path}", n=1))


def spec(paths=("calc.py",)):
    return CaseSpec("case", "https://example.test/repo", "a" * 40, "pytest", paths, (TEST_ID,))


def result(*, stdout=f"{TEST_ID} PASSED\n", code=ExitCode.OK):
    return ExecutionResult("case", "original", code, stdout, "", 0.25)


class Runner:
    def __init__(self, verdict=None):
        self.calls = []
        self.verdict = verdict

    def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
        source = (workspace_host_path / "calc.py").read_text(encoding="utf-8")
        self.calls.append((workspace_host_path, source, command, patch_diff_hash))
        if isinstance(self.verdict, Exception):
            raise self.verdict
        if self.verdict is not None:
            return self.verdict
        return result(code=ExitCode.OK if "value + 1" in source else ExitCode.TESTS_FAILED)


@pytest.fixture
def baseline(tmp_path):
    root = tmp_path / "baseline"
    root.mkdir()
    (root / "calc.py").write_text(PRE, encoding="utf-8")
    return root


def minimize(baseline, runner, raw=None, original=None, case=None):
    return run_ddmin_hunk_minimization(raw_diff=diff() if raw is None else raw, baseline_workspace=baseline, spec=spec() if case is None else case, runner=runner, original_result=result() if original is None else original)


def test_selects_first_passing_singleton_and_rebinds_result(baseline):
    runner = Runner()
    selected, execution, summary = minimize(baseline, runner)
    assert "value + 1" in selected
    assert "new comment" not in selected
    assert summary.raw_hunks_count == 2
    assert summary.minimized_hunks_count == 1
    assert summary.codeslop_hunks_removed == 1
    assert summary.was_minimized
    assert execution.passed
    assert execution.expected_test_ids == (TEST_ID,)
    assert execution.patch_diff_hash == PatchProposal("case", selected, "gate", 0, 0).diff_hash
    assert runner.calls[0][2] == ["python", "-m", "pytest", "-v", "-ra", TEST_ID]
    assert len(runner.calls) == 1
    assert not runner.calls[0][0].exists()
    assert (baseline / "calc.py").read_text(encoding="utf-8") == PRE


@pytest.mark.parametrize("raw", ["", diff(PRE, PRE.replace("value - 1", "value + 1"))])
def test_zero_or_one_hunk_reuses_original_without_execution(baseline, raw):
    runner = Runner()
    original = result()
    selected, execution, summary = minimize(baseline, runner, raw=raw, original=original)
    assert selected == raw
    assert execution is original
    assert not summary.was_minimized
    assert summary.codeslop_hunks_removed == 0
    assert runner.calls == []


@pytest.mark.parametrize("original", [result(code=ExitCode.TESTS_FAILED), result(stdout="0 tests collected"), result(stdout=f"prefix{TEST_ID} PASSED\n")])
def test_requires_original_passing_expected_nodes_before_short_circuit(baseline, original):
    with pytest.raises(ValueError, match="passing"):
        minimize(baseline, Runner(), raw="", original=original)


@pytest.mark.parametrize("verdict", [result(code=ExitCode.TESTS_FAILED), result(stdout="all good"), result(stdout=f"prefix{TEST_ID} PASSED\n"), HarnessTimeoutError(1, "pytest")])
def test_rejected_candidates_fall_back_and_always_cleanup(baseline, verdict):
    runner = Runner(verdict)
    original = result()
    selected, execution, summary = minimize(baseline, runner, original=original)
    assert selected == diff()
    assert execution is original
    assert not summary.was_minimized
    assert len(runner.calls) == 2
    assert len({call[0] for call in runner.calls}) == 2
    assert all(not call[0].exists() for call in runner.calls)
    assert "new comment" not in runner.calls[0][1]
    assert "value - 1" in runner.calls[1][1]


def test_policy_rejection_never_reaches_runner(baseline):
    runner = Runner()
    selected, _, summary = minimize(baseline, runner, case=spec(("other.py",)))
    assert selected == diff()
    assert not summary.was_minimized
    assert runner.calls == []


def test_application_rejection_never_reaches_runner(baseline):
    (baseline / "calc.py").write_text("unrelated = 0\n", encoding="utf-8")
    runner = Runner()
    _, _, summary = minimize(baseline, runner)
    assert not summary.was_minimized
    assert runner.calls == []


def test_overfit_rejection_including_public_deletion_before_runner(baseline):
    pre = PRE + "\ndef public_api():\n    return True\n"
    post = pre.replace("def calculate(value):", "def calculate(value, extra):").replace("\ndef public_api():\n    return True\n", "")
    (baseline / "calc.py").write_text(pre, encoding="utf-8")
    runner = Runner()
    selected, _, summary = minimize(baseline, runner, raw=diff(pre, post))
    assert selected == diff(pre, post)
    assert not summary.was_minimized
    assert runner.calls == []


@pytest.mark.parametrize("error", [HarnessSetupError("docker unavailable"), OSError("disk unavailable")])
def test_infrastructure_error_propagates_after_scratch_cleanup(baseline, error):
    runner = Runner(error)
    with pytest.raises(type(error)):
        minimize(baseline, runner)
    assert len(runner.calls) == 1
    assert not runner.calls[0][0].exists()


def test_drop_one_candidates_follow_all_singletons_in_generator_order(baseline):
    pre = PRE + "\n\n# gap\n# gap\n# last old\n"
    post = POST + "\n\n# gap\n# gap\n# last new\n"
    (baseline / "calc.py").write_text(pre, encoding="utf-8")

    class PairRunner(Runner):
        def run_in_container(self, case_id, patch_diff_hash, workspace_host_path, command):
            super().run_in_container(case_id, patch_diff_hash, workspace_host_path, command)
            source = self.calls[-1][1]
            return result(code=ExitCode.OK if "new comment" in source and "last new" in source else ExitCode.TESTS_FAILED)

    runner = PairRunner()
    selected, _, summary = minimize(baseline, runner, raw=diff(pre, post))
    assert summary.minimized_hunks_count == 2
    assert "value + 1" not in selected
    assert len(runner.calls) == 4


def test_original_explicit_expected_nodes_cannot_hide_missing_case_nodes(baseline):
    original = replace(result(stdout="unrelated PASSED\n"), expected_test_ids=("unrelated",))
    with pytest.raises(ValueError, match="passing"):
        minimize(baseline, Runner(), original=original)


@pytest.mark.parametrize("code", [ExitCode.INTERNAL_ERROR, ExitCode.USAGE_ERROR, ExitCode.NO_TESTS_COLLECTED, ExitCode.INTERRUPTED])
def test_candidate_broken_harness_propagates_instead_of_choosing_another_subset(baseline, code):
    runner = Runner(result(code=code))
    with pytest.raises(HarnessSetupError):
        minimize(baseline, runner)
    assert len(runner.calls) == 1
    assert not runner.calls[0][0].exists()

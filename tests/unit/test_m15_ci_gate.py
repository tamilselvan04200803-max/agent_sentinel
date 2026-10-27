"""M15 in-memory reconstruction, complete auditing and CI integration."""

from __future__ import annotations

import difflib
import hashlib
import json
import subprocess
from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING

import pytest

from agentsentinel.cli import main as cli_module
from agentsentinel.verification import run_ci_gate_audit
from agentsentinel.verification.ci_gate import (
    CIGateViolation,
    render_ci_gate_json,
    render_ci_gate_markdown,
)
from agentsentinel.verification.ci_source_map import (
    CIGateUsageError,
    FileLifecycleStatus,
    reconstruct_in_memory_source_map,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


def change(workspace: Path, before: str | None, after: str | None, name: str = "module.py", *, new_name: str | None = None) -> str:
    """Produce diff text and a pristine preimage; never apply the diff on disk."""
    workspace.mkdir(parents=True, exist_ok=True)
    if before is not None:
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(before.encode("utf-8"))
    return "\n".join(difflib.unified_diff(
        (before or "").replace("\r\n", "\n").splitlines(),
        (after or "").replace("\r\n", "\n").splitlines(),
        fromfile=f"a/{name}" if before is not None else "/dev/null",
        tofile=f"b/{new_name or name}" if after is not None else "/dev/null",
        lineterm="",
    )) + "\n"


def snapshot(workspace: Path) -> dict[str, bytes]:
    return {path.relative_to(workspace).as_posix(): path.read_bytes() for path in workspace.rglob("*") if path.is_file()}


def test_modified_source_map_and_exact_surviving_line_coordinates(tmp_path: Path) -> None:
    before = "first\nsecond\nthird\nfourth\n"
    after = "first\ninserted\nsecond\nfourth\nlast\n"
    diff = change(tmp_path, before, after)
    disk = snapshot(tmp_path)
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.status is FileLifecycleStatus.MODIFIED
    assert entry.file_path == entry.old_path == "module.py"
    assert entry.pre_buffer == before
    assert entry.post_buffer == after
    assert entry.added_lines == ((2, "inserted"), (5, "last"))
    assert entry.line_map == {1: 1, 2: 3, 4: 4}
    assert snapshot(tmp_path) == disk
    with pytest.raises(FrozenInstanceError):
        entry.file_path = "changed.py"


def test_created_and_deleted_files_have_empty_opposite_buffers(tmp_path: Path) -> None:
    diff = change(tmp_path, None, "def new():\n    return 1\n", "new.py")
    diff += change(tmp_path, "def old():\n    return 2\n", None, "old.py")
    disk = snapshot(tmp_path)
    created, deleted = reconstruct_in_memory_source_map(diff, tmp_path)
    assert created.status is FileLifecycleStatus.CREATED
    assert created.old_path is None
    assert created.pre_buffer == ""
    assert created.post_buffer == "def new():\n    return 1\n"
    assert created.added_lines == ((1, "def new():"), (2, "    return 1"))
    assert deleted.status is FileLifecycleStatus.DELETED
    assert deleted.file_path == deleted.old_path == "old.py"
    assert deleted.post_buffer == ""
    assert deleted.added_lines == ()
    assert created.line_map == deleted.line_map == {}
    assert snapshot(tmp_path) == disk


def test_rename_with_hunks_reads_old_path(tmp_path: Path) -> None:
    diff = change(tmp_path, "def f():\n    return 1\n", "def f():\n    return 2\n", "old.py", new_name="new.py")
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.status is FileLifecycleStatus.RENAMED
    assert entry.old_path == "old.py"
    assert entry.file_path == "new.py"
    assert entry.post_buffer.endswith("return 2\n")
    assert not (tmp_path / "new.py").exists()


def test_pure_rename_keeps_contents_and_identity_map(tmp_path: Path) -> None:
    (tmp_path / "old.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    diff = "diff --git a/old.py b/new.py\nsimilarity index 100%\nrename from old.py\nrename to new.py\n"
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.status is FileLifecycleStatus.RENAMED
    assert entry.pre_buffer == entry.post_buffer == "value = 1\n"
    assert entry.line_map == {1: 1}


def test_multi_hunk_offsets_and_line_drift_are_healed(tmp_path: Path) -> None:
    before = "\n".join(f"line {i}" for i in range(1, 21)) + "\n"
    change(tmp_path, before, before)
    diff = (
        "--- a/module.py\n+++ b/module.py\n"
        "@@ -1 +1,2 @@\n line 1\n+inserted\n"
        "@@ -90,2 +91,2 @@\n-line 18\n+replacement\n line 19\n"
    )
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.added_lines == ((2, "inserted"), (19, "replacement"))
    assert entry.line_map[20] == 21
    assert entry.post_buffer.splitlines()[18] == "replacement"


def test_crlf_diff_and_source_normalize_without_disk_mutation(tmp_path: Path) -> None:
    diff = change(tmp_path, "x = 1\r\n", "x = 2\r\n").replace("\n", "\r\n")
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.pre_buffer == "x = 1\n"
    assert entry.post_buffer == "x = 2\n"
    assert (tmp_path / "module.py").read_bytes() == b"x = 1\r\n"


def test_no_newline_markers_preserve_both_eof_states(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_bytes(b"old")
    diff = "--- a/module.py\n+++ b/module.py\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.pre_buffer == "old"
    assert entry.post_buffer == "new"
    assert entry.added_lines == ((1, "new"),)


def test_insertion_only_hunk_uses_line_preceding_insertion(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_bytes(b"a\nb\n")
    diff = "--- a/module.py\n+++ b/module.py\n@@ -1,0 +2 @@\n+x\n"
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.post_buffer == "a\nx\nb\n"
    assert entry.line_map == {1: 1, 2: 3}


@pytest.mark.parametrize("diff", ["", "garbage", "GIT binary patch\n", "--- a/x\n+++ b/x\n", "--- a/x\n+++ b/x\n@@ -1,7 +1 @@\n-old\n+new\n", "--- a/x\n+++ b/x\n@@ bad @@\n+new\n", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\ntrailing garbage\n", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+\x00\n"])
def test_empty_binary_and_structurally_corrupt_diffs_are_usage_errors(tmp_path: Path, diff: str) -> None:
    (tmp_path / "x").write_bytes(b"old\n")
    with pytest.raises(CIGateUsageError):
        reconstruct_in_memory_source_map(diff, tmp_path)


def test_unreconstructable_context_is_a_usage_error(tmp_path: Path) -> None:
    change(tmp_path, "x = 1\n", "x = 2\n")
    diff = "--- a/module.py\n+++ b/module.py\n@@ -1 +1 @@\n-no match\n+new\n"
    with pytest.raises(CIGateUsageError):
        reconstruct_in_memory_source_map(diff, tmp_path)


@pytest.mark.parametrize("path", ["../outside.py", "/absolute.py", "C:\\escape.py", "dir/../../escape.py", "dir\\..\\escape.py"])
def test_both_file_paths_are_validated_before_read(tmp_path: Path, path: str) -> None:
    diff = f"--- a/{path}\n+++ b/new.py\n@@ -1 +1 @@\n-old\n+new\n"
    with pytest.raises(CIGateUsageError):
        reconstruct_in_memory_source_map(diff, tmp_path)


def test_deleted_missing_file_is_usage_error(tmp_path: Path) -> None:
    diff = "--- a/missing.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
    with pytest.raises(CIGateUsageError):
        reconstruct_in_memory_source_map(diff, tmp_path)


def test_deletion_cannot_silently_discard_unremoved_source(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_bytes(b"first\nlast\n")
    diff = "--- a/module.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-first\n"
    with pytest.raises(CIGateUsageError):
        reconstruct_in_memory_source_map(diff, tmp_path)


def test_bare_cr_added_line_is_preserved_for_hygiene_stage(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_bytes(b"x = 1\n")
    diff = "--- a/module.py\n+++ b/module.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\r# poison\n"
    (entry,) = reconstruct_in_memory_source_map(diff, tmp_path)
    assert entry.added_lines == ((1, "x = 2\r# poison"),)
    assert entry.post_buffer == "x = 2\r# poison\n"


def test_report_schema_frozen_model_and_deterministic_rendering(tmp_path: Path) -> None:
    diff = change(tmp_path, "x = 1\n", "x = 2\n")
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.status == "PASSED"
    assert report.exit_code == 0
    assert report.gatekeeper_version == "15.0.0"
    assert report.diff_sha256 == hashlib.sha256(diff.encode()).hexdigest()
    assert report.summary == {"error_count": 0, "warning_count": 0}
    assert report.total_violations == 0
    assert report.execution_time_ms >= 0
    with pytest.raises(FrozenInstanceError):
        report.status = "FAILED"
    raw = render_ci_gate_json(report)
    assert render_ci_gate_json(report) == raw
    assert set(json.loads(raw)) == {"gatekeeper_version", "status", "exit_code", "execution_time_ms", "total_violations", "summary", "violations", "file_metrics", "diff_sha256"}
    markdown = render_ci_gate_markdown(report)
    assert markdown.startswith("## 🛡️ AgentSentinel CI Gatekeeper Summary\n")
    assert "**Status:** ✅ PASSED | **Execution Time:** " in markdown
    assert "| File Path | Stage | CC Delta (Pre -> Post) | API Contract Status | Action Item |" in markdown


def test_markdown_escapes_untrusted_fields(tmp_path: Path) -> None:
    from dataclasses import replace

    report = run_ci_gate_audit(change(tmp_path, "x = 1\n", "x = 2\n"), tmp_path)
    attack = CIGateViolation("bad|<script>\u202e", 1, "stage", "RULE", "ERROR", "```\n| injected", "fix <x>")
    markdown = render_ci_gate_markdown(replace(report, violations=(attack,), total_violations=1))
    assert "<script>" not in markdown
    assert "\u202e" not in markdown
    assert "\\|" in markdown
    assert "&lt;script&gt;" in markdown
    assert "```" not in markdown


def test_optional_allowlist_and_test_edit_switch(tmp_path: Path) -> None:
    diff = change(tmp_path, "x = 1\n", "x = 2\n", "tests/test_x.py")
    report = run_ci_gate_audit(diff, tmp_path, allowed_edit_paths=("other.py",))
    assert {v.rule_id for v in report.violations} >= {"PATH-002", "PATH-003"}
    assert run_ci_gate_audit(diff, tmp_path, allow_test_edits=True).exit_code == 0


def test_created_test_is_not_a_modified_test_policy_violation(tmp_path: Path) -> None:
    diff = change(tmp_path, None, "assert 2 + 2 == 4\n", "tests/test_new.py")
    assert not any(v.rule_id == "PATH-002" for v in run_ci_gate_audit(diff, tmp_path).violations)


def test_invalid_python_is_an_error_not_a_silent_pass(tmp_path: Path) -> None:
    diff = change(tmp_path, "def f():\n    return 1\n", "def f(:\n    return 1\n")
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == "SYN-001" and v.line_number == 1 for v in report.violations)


@pytest.mark.parametrize("source", ["x = 1\n# \u200b\n", "x = 1\n \tx = 2\n", "K = 1\n"])
def test_zero_width_mixed_indent_and_normalized_unicode_identifier(tmp_path: Path, source: str) -> None:
    report = run_ci_gate_audit(change(tmp_path, "x = 1\n", source), tmp_path)
    assert report.exit_code == 1
    assert any(v.rule_id == "LEX-001" for v in report.violations)


def test_complexity_increase_cannot_hide_behind_other_function_reduction(tmp_path: Path) -> None:
    from tests.adversarial.test_adversarial_m15_ci_gate import complexity_source

    before = complexity_source(30, "a") + complexity_source(0, "b")
    after = complexity_source(2, "a") + complexity_source(13, "b")
    report = run_ci_gate_audit(change(tmp_path, before, after), tmp_path)
    assert report.file_metrics[0].cc_delta < 0
    assert any(v.rule_id == "CC-001" and "Function b" in v.message and v.line_number == 7 for v in report.violations)


def test_logging_handler_is_not_silent(tmp_path: Path) -> None:
    after = "def f():\n    try:\n        return 1\n    except Exception:\n        logger.exception('failed')\n        return None\n"
    report = run_ci_gate_audit(change(tmp_path, "def f():\n    return 1\n", after), tmp_path)
    assert not any(v.rule_id == "EXC-001" for v in report.violations)


def test_contained_assertion_discovery_excludes_virtual_environments(tmp_path: Path) -> None:
    diff = change(tmp_path, "def f():\n    return 1\n", "def f():\n    return 'vendor_literal'\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "test_vendor.py").write_bytes(b"\xff\x00")
    report = run_ci_gate_audit(diff, tmp_path)
    assert report.exit_code == 0


def test_shared_assertion_collector_accepts_optional_file_list(tmp_path: Path) -> None:
    from agentsentinel.verification.overfit_guard import extract_test_assertion_literals

    selected = tmp_path / "test_selected.py"
    selected.write_text("assert value == 'selected_literal'\n", encoding="utf-8", newline="\n")
    (tmp_path / "test_other.py").write_text("assert value == 'excluded_literal'\n", encoding="utf-8", newline="\n")
    assert extract_test_assertion_literals(tmp_path, test_paths=(selected,)) == frozenset({"selected_literal"})


def test_audit_does_not_construct_provider_or_container_or_spawn_process(tmp_path: Path, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("CI audit must remain offline and static")

    monkeypatch.setattr(cli_module, "_make_llm", forbidden)
    monkeypatch.setattr(cli_module, "HardenedContainerRunner", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert run_ci_gate_audit(change(tmp_path, "x = 1\n", "x = 2\n"), tmp_path).exit_code == 0


def test_representative_audit_sla_under_500ms(tmp_path: Path) -> None:
    from time import perf_counter

    before = "".join(f"def f_{i}(x):\n    return x + {i}\n" for i in range(40))
    after = before.replace("return x +", "return x -")
    diff = change(tmp_path, before, after)
    started = perf_counter()
    report = run_ci_gate_audit(diff, tmp_path)
    elapsed = (perf_counter() - started) * 1000
    assert report.exit_code == 0
    assert report.execution_time_ms < 500
    assert elapsed < 500


@pytest.mark.parametrize("kind", ["missing_workspace", "missing_diff", "corrupt_diff", "negative_limit"])
def test_cli_usage_errors_return_two_and_json(tmp_path: Path, capsys, kind: str) -> None:
    workspace = tmp_path / "workspace"
    diff = change(workspace, "x = 1\n", "x = 2\n")
    diff_path = tmp_path / "input.diff"
    diff_path.write_text(diff, encoding="utf-8", newline="\n")
    args = ["ci-gate", "--workspace", str(workspace), "--diff", str(diff_path)]
    if kind == "missing_workspace":
        args[2] = str(tmp_path / "missing")
    elif kind == "missing_diff":
        diff_path.unlink()
    elif kind == "corrupt_diff":
        diff_path.write_text("corrupt", encoding="utf-8", newline="\n")
    else:
        args += ["--max-cc-delta", "-1"]
    assert cli_module.main(args) == 2
    assert json.loads(capsys.readouterr().out)["exit_code"] == 2


def test_cli_reports_and_strict_warning_flag(tmp_path: Path, capsys) -> None:
    from tests.adversarial.test_adversarial_m15_ci_gate import complexity_source

    workspace = tmp_path / "workspace"
    diff_path = tmp_path / "input.diff"
    diff_path.write_text(change(workspace, complexity_source(2), complexity_source(14)), encoding="utf-8", newline="\n")
    disk = snapshot(workspace)
    json_out, md_out = tmp_path / "result.json", tmp_path / "summary.md"
    args = ["ci-gate", "--workspace", str(workspace), "--diff", str(diff_path), "--json-out", str(json_out), "--markdown-out", str(md_out)]
    assert cli_module.main(args) == 0
    normal = json.loads(capsys.readouterr().out)
    assert normal["status"] == "PASSED"
    assert json.loads(json_out.read_text(encoding="utf-8")) == normal
    assert md_out.read_bytes().startswith("## 🛡️ AgentSentinel CI Gatekeeper Summary".encode())
    assert cli_module.main(args + ["--strict-warnings"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAILED"
    assert snapshot(workspace) == disk


def test_cli_custom_complexity_budget_and_no_execution(tmp_path: Path, capsys, monkeypatch) -> None:
    from tests.adversarial.test_adversarial_m15_ci_gate import complexity_source

    workspace = tmp_path / "workspace"
    diff_path = tmp_path / "input.diff"
    diff_path.write_text(change(workspace, complexity_source(2), complexity_source(14)), encoding="utf-8", newline="\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("No host process allowed"))
    assert cli_module.main(["ci-gate", "--workspace", str(workspace), "--diff", str(diff_path), "--max-cc-delta", "12", "--strict-warnings"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["warning_count"] == 0


def test_cli_output_cannot_overwrite_workspace_or_diff(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "workspace"
    diff_path = tmp_path / "input.diff"
    original = change(workspace, "x = 1\n", "x = 2\n")
    diff_path.write_text(original, encoding="utf-8", newline="\n")
    disk = snapshot(workspace)
    for target in (workspace / "module.py", diff_path):
        assert cli_module.main(["ci-gate", "--workspace", str(workspace), "--diff", str(diff_path), "--json-out", str(target)]) == 2
        assert json.loads(capsys.readouterr().out)["exit_code"] == 2
    assert snapshot(workspace) == disk
    assert diff_path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("metadata,old,new", [("new file mode 100644\n", "tests/old.py", "module.py"), ("deleted file mode 100644\n", "module.py", "tests/new.py"), ("", "module.py", "module.py")])
def test_conflicting_git_metadata_cannot_hide_file_endpoints(tmp_path: Path, metadata: str, old: str, new: str) -> None:
    if metadata.startswith("new"):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "old.py").write_bytes(b"old\n")
    else:
        (tmp_path / "module.py").write_bytes(b"old\n")
    header = f"diff --git a/{old} b/{new}\n{metadata}"
    if metadata.startswith("new"):
        body = f"--- a/{old}\n+++ b/{new}\n@@ -0,0 +1 @@\n+new\n"
    elif metadata.startswith("deleted"):
        body = f"--- a/{old}\n+++ b/{new}\n@@ -1 +0,0 @@\n-old\n"
    else:
        header = "diff --git a/tests/hidden.py b/module.py\n"
        body = "--- a/module.py\n+++ b/module.py\n@@ -1 +1 @@\n-old\n+new\n"
    with pytest.raises(CIGateUsageError):
        reconstruct_in_memory_source_map(header + body, tmp_path)


@pytest.mark.parametrize("value", [None, b"GIT binary patch", 42])
def test_non_text_api_input_has_structured_usage_failure(tmp_path: Path, value) -> None:
    assert run_ci_gate_audit(value, tmp_path).exit_code == 2


@pytest.mark.parametrize("path", ["MODULE.PY", ".GITHUB/workflows/ci.yml"])
def test_windows_case_aliases_do_not_bypass_python_or_path_guards(tmp_path: Path, path: str) -> None:
    import os

    actual = "module.py" if path == "MODULE.PY" else ".github/workflows/ci.yml"
    before = "x = 1\n"
    after = "breakpoint()\nx = 1\n" if path == "MODULE.PY" else "x = 2\n"
    diff = change(tmp_path, before, after, actual).replace(f"a/{actual}", f"a/{path}").replace(f"b/{actual}", f"b/{path}")
    report = run_ci_gate_audit(diff, tmp_path, allowed_edit_paths=(actual,))
    if os.name == "nt":
        assert report.exit_code == 1
        assert any(v.rule_id == ("LEX-002" if path == "MODULE.PY" else "PATH-001") for v in report.violations)
        assert not any(v.rule_id == "PATH-003" for v in report.violations)
    else:
        assert report.exit_code == 2  # On case-sensitive systems the preimage is absent.


def test_duplicate_physical_endpoints_are_rejected(tmp_path: Path) -> None:
    diff = change(tmp_path, "x = 1\n", "x = 2\n")
    diff += diff.replace("a/module.py", "a/MODULE.PY").replace("b/module.py", "b/MODULE.PY")
    assert run_ci_gate_audit(diff, tmp_path).exit_code == 2


def _rename(old: str, new: str) -> str:
    return f"diff --git a/{old} b/{new}\nsimilarity index 100%\nrename from {old}\nrename to {new}\n"


def test_occupied_rename_destination_cannot_hide_public_api_loss(tmp_path: Path) -> None:
    (tmp_path / "old.py").write_bytes(b"x = 1\n")
    (tmp_path / "new.py").write_bytes(b"def public(): return 1\n")
    assert run_ci_gate_audit(_rename("old.py", "new.py"), tmp_path).exit_code == 2


def test_occupied_destination_is_allowed_when_another_section_vacates_it(tmp_path: Path) -> None:
    (tmp_path / "old.py").write_bytes(b"x = 1\n")
    (tmp_path / "new.py").write_bytes(b"def public(): return 1\n")
    disk = snapshot(tmp_path)
    report = run_ci_gate_audit(_rename("old.py", "new.py") + _rename("new.py", "moved.py"), tmp_path)
    assert report.exit_code == 0
    assert len(report.file_metrics) == 2
    assert snapshot(tmp_path) == disk


def test_case_only_rename_is_preserved(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_bytes(b"def public(): return 1\n")
    (entry,) = reconstruct_in_memory_source_map(_rename("module.py", "MODULE.PY"), tmp_path)
    assert entry.status is FileLifecycleStatus.RENAMED
    assert entry.post_buffer == entry.pre_buffer


@pytest.mark.parametrize("args", [["ci-gate"], ["ci-gate", "--workspace", "x", "--diff", "y", "--max-cc-delta", "bad"]])
def test_parser_level_ci_usage_errors_emit_json(args: list[str], capsys) -> None:
    assert cli_module.main(args) == 2
    assert json.loads(capsys.readouterr().out)["exit_code"] == 2


def test_ci_help_keeps_standard_successful_parser_behavior(capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        cli_module.main(["ci-gate", "--help"])
    assert caught.value.code == 0
    assert "--strict-warnings" in capsys.readouterr().out


def test_changed_api_header_reports_its_actual_post_line(tmp_path: Path) -> None:
    diff = change(tmp_path, "def f():\n    return 1\n", "async def f():\n    return 1\n")
    report = run_ci_gate_audit(diff, tmp_path)
    assert [v.line_number for v in report.violations if v.rule_id == "API-001"] == [1]


@pytest.mark.parametrize("alias", ["module.py.", "module.py ", "module.py:stream"])
def test_nonportable_windows_aliases_are_usage_errors(tmp_path: Path, alias: str) -> None:
    diff = change(tmp_path, "x = 1\n", "breakpoint()\nx = 1\n").replace("a/module.py", f"a/{alias}").replace("b/module.py", f"b/{alias}")
    assert run_ci_gate_audit(diff, tmp_path).exit_code == 2


@pytest.mark.parametrize("mode", ["120000", "160000", "040000", "invalid"])
@pytest.mark.parametrize("metadata", ["new file mode {mode}", "index 0000000..1111111 {mode}"])
def test_nonregular_git_modes_cannot_be_audited_as_plain_source(tmp_path: Path, mode: str, metadata: str) -> None:
    diff = (
        f"diff --git a/artifact b/artifact\n{metadata.format(mode=mode)}\n"
        "--- /dev/null\n+++ b/artifact\n@@ -0,0 +1 @@\n+../../outside\n"
    )
    assert run_ci_gate_audit(diff, tmp_path).exit_code == 2


def test_nonregular_preimage_is_rejected_before_reading(tmp_path: Path, monkeypatch) -> None:
    import stat
    from pathlib import Path
    from types import SimpleNamespace

    diff = change(tmp_path, "x = 1\n", "x = 2\n")
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path: SimpleNamespace(st_mode=stat.S_IFLNK) if path.name == "module.py" else original(path))
    assert run_ci_gate_audit(diff, tmp_path).exit_code == 2

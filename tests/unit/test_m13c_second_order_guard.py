"""Bounded symbolic folding and differential second-order policy contracts."""

from __future__ import annotations

import ast
import difflib
import time
from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.exceptions import OverfitPolicyError

if TYPE_CHECKING:
    from pathlib import Path


def guard(pre: str, post: str, literals: frozenset[str | int | float] = frozenset()):
    from agentsentinel.verification.second_order_guard import verify_second_order_evasion

    verify_second_order_evasion("app.py", pre, post, literals)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('"".join(chr(x) for x in [116, 101, 115, 116])', "test"),
        ('"".join([chr(x) for x in (116, 101, 115, 116)])', "test"),
        ('"".join(chr(x) for x in range(97, 100))', "abc"),
        ("bytes([116, 101, 115, 116]).decode()", "test"),
        ("bytearray([116, 101, 115, 116]).decode()", "test"),
        ('bytes.fromhex("74657374").decode()', "test"),
        ('bytearray.fromhex("74657374")', b"test"),
        ('binascii.unhexlify("74657374")', b"test"),
        ('base64.b64decode("dGVzdA==").decode()', "test"),
        ('base64.urlsafe_b64decode("dGVzdA==")', b"test"),
        ('base64.b32decode("ORSXG5A=")', b"test"),
        ('base64.b16decode("74657374")', b"test"),
        ('codecs.decode("grfg", "rot_13")', "test"),
        ('codecs.encode("grfg", "rot13")', "test"),
        ('codecs.decode(b"74657374", "hex")', b"test"),
        ('"test".encode("ascii").decode("utf-8")', "test"),
        ('"tset"[::-1]', "test"),
        ('base64.b64decode(bytes.fromhex("64484e6c64413d3d")).decode()[::-1]', "test"),
        ('" TEST ".strip().lower().replace("t", "T")', "TesT"),
        ('f"te{chr(115)}t"', "test"),
        ('"ab" * 3', "ababab"),
        ('ord("t")', 116),
        ('zlib.crc32(b"test")', 3632233996),
        ('hashlib.md5(b"test").hexdigest()', "098f6bcd4621d373cade4e832627b4f6"),
    ],
)
def test_symbolic_composition(expression: str, expected: object) -> None:
    from agentsentinel.verification import fold_symbolic_constant

    assert fold_symbolic_constant(ast.parse(expression, mode="eval").body) == expected


@pytest.mark.parametrize(
    "expression",
    [
        '"x" * 1000000000',
        "bytes(1000000000)",
        "list(range(1000000000))",
        '"".join(chr(x) for x in range(1000000000))',
        "chr(-1)",
        "chr(0x110000)",
        'bytes.fromhex("not hex")',
        'codecs.decode(b"x", "unknown_codec")',
        '"abc"[::0]',
        "arbitrary_function()",
        'hash("test")',
        '"".join(chr(x) for x in [116] if side_effect())',
    ],
)
def test_symbolic_unknown_or_excessive_inputs_do_not_execute(expression: str) -> None:
    from agentsentinel.verification import fold_symbolic_constant

    assert fold_symbolic_constant(ast.parse(expression, mode="eval").body) is None


@pytest.mark.parametrize(
    "post",
    [
        "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass Value:\n    x: int = 0\n",
        "from functools import lru_cache\n@lru_cache(maxsize=32)\ndef f(x=None):\n    return x\n",
        "class C:\n    @property\n    def value(self):\n        return 1\n    @staticmethod\n    def f(x: int | None = None):\n        return x\n",
        'class C:\n    def getattr(self, key):\n        return key\n    def f(self):\n        return self.getattr("k")\n',
        'class C:\n    def getattr(self, key):\n        return key\ndef f():\n    obj = C()\n    return obj.getattr("k")\n',
        'class C:\n    def getattr(self, key):\n        return key\ndef f(obj: C):\n    return obj.getattr("k")\n',
        "def f():\n    try:\n        work()\n    finally:\n        for item in items:\n            if item:\n                break\n",
        "def f():\n    try:\n        work()\n    finally:\n        def nested():\n            return True\n",
        'def f():\n    try:\n        work()\n    except ValueError as exc:\n        raise RuntimeError("failed") from exc\n',
        "import contextlib\ndef f():\n    with contextlib.suppress(FileNotFoundError):\n        remove()\n",
    ],
)
def test_positive_controls(post: str) -> None:
    guard("", post, frozenset({"  HELLO  "}))


def test_preexisting_hazards_are_exempt_by_scope_and_occurrence() -> None:
    pre = 'def f(x):\n    return getattr(x, "value")\n'
    guard(pre, pre.replace('"value"', '"value"') + "\n")
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_INDIRECT_REFLECTION"):
        guard(pre, pre + 'def g(x):\n    return getattr(x, "value")\n')
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_INDIRECT_REFLECTION"):
        guard(pre, pre.replace("    return", '    getattr(x, "value")\n    return'))


def test_alias_rebinding_and_unrelated_class_cannot_exempt_reflection() -> None:
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_INDIRECT_REFLECTION"):
        guard(
            "import safe as access\ndef f():\n    return access.lookup()\n",
            "import builtins as access\ndef f():\n    return access.lookup()\n",
        )
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_INDIRECT_REFLECTION"):
        guard(
            "",
            'class Safe:\n    def getattr(self, x): return x\ndef f(obj):\n    return obj.getattr("k")\n',
        )


def test_metrics_snapshot_reset_and_exact_feedback_code() -> None:
    from agentsentinel.orchestrator.failure_taxonomy import classify_attempt_failure
    from agentsentinel.verification import (
        get_second_order_evasion_metrics,
        reset_second_order_evasion_metrics,
    )

    reset_second_order_evasion_metrics()
    snapshot = get_second_order_evasion_metrics()
    with pytest.raises(OverfitPolicyError) as caught:
        guard("", 'def f(x):\n    return getattr(x, "value")\n')
    error = caught.value
    assert error.diagnostic_code == "ERR_M13C_INDIRECT_REFLECTION"
    category, directive = classify_attempt_failure(error, None)
    assert category.value == "OVERFIT_OR_HARDCODED_LITERAL"
    assert error.diagnostic_code in directive
    assert snapshot.ast_reflection_bypass_blocked_count == 0
    assert get_second_order_evasion_metrics().ast_reflection_bypass_blocked_count == 1
    reset_second_order_evasion_metrics()
    assert get_second_order_evasion_metrics() == snapshot


def test_ci_aggregates_second_order_findings_without_workspace_mutation(tmp_path: Path) -> None:
    from agentsentinel.verification import run_ci_gate_audit

    pre = "def f(x):\n    return x\n"
    post = 'def f(x):\n    try:\n        return getattr(x, "value")\n    finally:\n        return True\n'
    path = tmp_path / "app.py"
    path.write_text(pre, encoding="utf-8", newline="\n")
    diff = "".join(
        difflib.unified_diff(pre.splitlines(True), post.splitlines(True), "a/app.py", "b/app.py")
    )
    report = run_ci_gate_audit(diff, tmp_path)
    messages = "\n".join(item.message for item in report.violations)
    assert "ERR_M13C_INDIRECT_REFLECTION" in messages
    assert "ERR_M13C_ABRUPT_FINALLY_EXIT" in messages
    assert path.read_text(encoding="utf-8") == pre


def test_representative_positive_control_latency() -> None:
    pre = "def f(x):\n    return x\n"
    post = "def f(x):\n    return x.strip().lower()\n"
    guard(pre, post)  # Warm imports are excluded from traversal latency.
    start = time.perf_counter()
    for _ in range(100):
        guard(pre, post, frozenset({"test-input"}))
    assert (time.perf_counter() - start) / 100 < 0.015


@pytest.mark.parametrize(
    "source",
    [
        "def f(x=mutate_env()):\n    return x\n",
        "def f(x=(mutate_env(),)):\n    return x\n",
        "@dataclass(value=mutate_env())\nclass C:\n    value: int\n",
        'os.environ["X"] = "1"\n',
        "GLOBAL_CONFIG = False\n",
        "setup_hack()\n",
        "VALUE: int = setup_hack()\n",
    ],
)
def test_definition_and_module_side_effects(source: str) -> None:
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_TOPLEVEL_SIDEEFFECT"):
        guard("", source)


def test_existing_numeric_constant_compatibility_is_narrow_and_can_be_disabled(
    tmp_path: Path,
) -> None:
    from agentsentinel.verification.overfit_guard import verify_not_overfitted

    before, after = {"a.py": "x = 1\n"}, {"a.py": "x = 2\n"}
    verify_not_overfitted(tmp_path, before, after, frozenset())
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_TOPLEVEL_SIDEEFFECT"):
        verify_not_overfitted(
            tmp_path, before, after, frozenset(), allow_numeric_module_constants=False
        )
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_TOPLEVEL_SIDEEFFECT"):
        verify_not_overfitted(tmp_path, {}, {"a.py": "GLOBAL_CONFIG = False\n"}, frozenset())


@pytest.mark.parametrize(
    "source",
    [
        "import contextlib\ndef f(SomeError):\n    with contextlib.suppress(SomeError):\n        work()\n",
        "import contextlib as c\ndef f():\n    with c.suppress():\n        work()\n",
        "def f(x):\n    try:\n        work()\n    except* ValueError:\n        raise\n    finally:\n        return True\n",
    ],
)
def test_unknown_exception_variables_and_trystar_are_not_bypasses(source: str) -> None:
    with pytest.raises(
        OverfitPolicyError, match="ERR_M13C_(CONTEXT_SUPPRESSION|ABRUPT_FINALLY_EXIT)"
    ):
        guard("", source)


def test_unchanged_definition_expressions_and_preexisting_literal_exemption() -> None:
    pre = 'def f(x=existing_default()):\n    prior = "test"\n    return x\n'
    guard(pre, pre.replace("return x", 'return "tset"[::-1]'), frozenset({"test"}))


@pytest.mark.parametrize("expression", ['"a"[50]', 'b"a"[-50]', "(1,)[4]"])
def test_invalid_index_is_unknown(expression: str) -> None:
    from agentsentinel.verification import fold_symbolic_constant

    assert fold_symbolic_constant(ast.parse(expression, mode="eval").body) is None


def test_rejected_evasion_retries_without_docker_execution(tmp_path: Path) -> None:
    from unittest.mock import MagicMock

    from agentsentinel.domain.exit_codes import ExitCode
    from agentsentinel.domain.models import CaseSpec, ExecutionResult, PatchProposal
    from agentsentinel.llm.pricing import ModelUsage
    from agentsentinel.orchestrator.checkpoint import RunState
    from agentsentinel.orchestrator.state_machine import RepairStateMachine

    source = tmp_path / "source"
    source.mkdir()
    pre = "def f(s):\n    return s.lower()\n"
    (source / "app.py").write_text(pre, encoding="utf-8", newline="\n")
    bad = 'def f(s):\n    return getattr(s, "strip")().lower()\n'
    good = "def f(s):\n    return s.strip().lower()\n"
    diffs = [
        "".join(
            difflib.unified_diff(
                pre.splitlines(True), post.splitlines(True), "a/app.py", "b/app.py"
            )
        )
        for post in (bad, good)
    ]
    prompts: list[str] = []

    class LLM:
        def generate_patch(self, case_id: str, prompt: str, model_id: str):
            prompts.append(prompt)
            return PatchProposal(case_id, diffs[len(prompts) - 1], model_id, 1, 1), ModelUsage(
                model_id, 1, 1
            )

    runner = MagicMock()
    runner.run_in_container.side_effect = [
        ExecutionResult(
            "case", "baseline", ExitCode.TESTS_FAILED, "AssertionError: wrong", "", 0.01
        ),
        ExecutionResult(
            "case", "passing", ExitCode.OK, "tests/test_app.py::test_f PASSED", "", 0.01
        ),
    ]
    machine = RepairStateMachine(
        CaseSpec("case", "local", "a" * 40, "pytest", ("app.py",), ("tests/test_app.py::test_f",)),
        LLM(),
        runner,
        max_attempts=2,
        db_path=tmp_path / "state.db",
        source_workspace_override=source,
    )
    try:
        record = machine.run_to_terminal(machine.start_run())
        assert record.state is RunState.AWAITING_HUMAN_APPROVAL
        assert record.attempts_used == 2
        assert runner.run_in_container.call_count == 2
        assert "ERR_M13C_INDIRECT_REFLECTION" in prompts[1]
        assert (source / "app.py").read_text(encoding="utf-8") == pre
    finally:
        machine._store.close()


def test_diagnostics_never_interpolate_encoded_test_literals() -> None:
    from agentsentinel.orchestrator.failure_taxonomy import classify_attempt_failure
    from agentsentinel.orchestrator.state_machine import AttemptFeedback

    with pytest.raises(OverfitPolicyError) as caught:
        guard("", 'def f(s):\n    return "tset"[::-1]\n', frozenset({"test"}))
    category, directive = classify_attempt_failure(caught.value, None)
    text = AttemptFeedback(
        1,
        "policy",
        "OverfitPolicyError",
        str(caught.value),
        failure_category=category,
        remediation_directive=directive,
    ).to_prompt_block()
    assert '"tset"' not in text and '"test"' not in text
    assert "ERR_M13C_OBFUSCATED_LITERAL" in text


def test_import_alias_changes_cannot_hide_same_syntax_hazard() -> None:
    before = 'import safe as table\ndef f():\n    return table["key"]\n'
    after = 'import builtins as table\ndef f():\n    return table["key"]\n'
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_INDIRECT_REFLECTION"):
        guard(before, after)


def test_changed_definition_cannot_use_shadowed_decorator_allowlist_name() -> None:
    source = "def dataclass(**kw):\n    side_effect()\n    return lambda cls: cls\n@dataclass(frozen=True)\nclass C:\n    x: int\n"
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_TOPLEVEL_SIDEEFFECT"):
        guard("", source)


def test_digest_guard_does_not_need_available_test_literals(tmp_path: Path) -> None:
    from agentsentinel.verification.overfit_guard import verify_not_overfitted

    with pytest.raises(OverfitPolicyError, match="ERR_M13C_OBFUSCATED_LITERAL"):
        verify_not_overfitted(
            tmp_path, {}, {"a.py": "def f(s):\n    return hash(s) == 12345\n"}, frozenset()
        )


def test_class_receiver_exemption_does_not_survive_loop_rebinding() -> None:
    source = 'class C:\n    def getattr(self, key):\n        return key\ndef f(items):\n    obj = C()\n    for obj in items:\n        obj.getattr("k")\n'
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_INDIRECT_REFLECTION"):
        guard("", source)


@pytest.mark.parametrize(
    "source",
    [
        "class C:\n    setup_hack()\n",
        "class C:\n    value = setup_hack()\n",
        "class C(setup_hack()):\n    pass\n",
    ],
)
def test_definition_time_class_execution_is_not_a_purity_bypass(source: str) -> None:
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_TOPLEVEL_SIDEEFFECT"):
        guard("", source)


@pytest.mark.parametrize(
    "source",
    [
        "def f(x: mutate_env()):\n    return x\n",
        "def f() -> mutate_env():\n    return 1\n",
        "value: mutate_env()\n",
        "class C:\n    value: mutate_env()\n",
    ],
)
def test_eager_annotation_calls_are_definition_side_effects(source: str) -> None:
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_TOPLEVEL_SIDEEFFECT"):
        guard("", source)
    guard("", "from __future__ import annotations\n" + source)


def test_changed_digest_import_alias_is_a_new_hazard() -> None:
    pre = (
        "from zlib import crc32 as checksum\ndef f(s):\n    return checksum(s.encode()) == 12345\n"
    )
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_OBFUSCATED_LITERAL"):
        guard(pre, pre.replace("crc32", "adler32"))


@pytest.mark.parametrize("expression", ['"te" + "st"', '"".join(["te", "st"])', 'b"test".decode()'])
def test_legacy_folds_have_structured_codes_metrics_and_legacy_literal_property(
    tmp_path: Path, expression: str
) -> None:
    from agentsentinel.verification import (
        get_second_order_evasion_metrics,
        reset_second_order_evasion_metrics,
    )
    from agentsentinel.verification.overfit_guard import verify_not_overfitted

    reset_second_order_evasion_metrics()
    source = f"def f(s):\n    if s == {expression}:\n        return True\n    return False\n"
    with pytest.raises(OverfitPolicyError) as caught:
        verify_not_overfitted(tmp_path, {}, {"app.py": source}, frozenset({"test"}))
    assert caught.value.diagnostic_code == "ERR_M13C_OBFUSCATED_LITERAL"
    assert caught.value.leaked_literal == "test"
    assert get_second_order_evasion_metrics().ast_literal_obfuscation_folded_count == 1


def test_empty_specific_exception_handlers_are_reported() -> None:
    with pytest.raises(OverfitPolicyError, match="ERR_M13C_CONTEXT_SUPPRESSION"):
        guard("", "def f():\n    try:\n        work()\n    except ValueError:\n        pass\n")

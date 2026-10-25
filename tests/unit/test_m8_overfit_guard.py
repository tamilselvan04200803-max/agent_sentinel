from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.verification.overfit_guard import (
    check_forbidden_reflection,
    check_patch_hygiene,
    extract_test_assertion_literals,
    verify_not_overfitted,
)


def _ws() -> Path:
    return Path(tempfile.gettempdir())


def test_extract_ignores_short_and_trivial() -> None:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "test_foo.py").write_text(
            'def test_x():\n    assert x == "ab"\n    assert y == "  hi "\n'
            '    assert z == 1\n    assert w == 42\n',
            encoding="utf-8",
        )
        lits = extract_test_assertion_literals(root)
        assert "ab" not in lits
        assert "  hi " not in lits  # stripped len 2
        assert 1 not in lits
        assert 42 in lits


def test_extract_collects_parametrize_literals() -> None:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "test_param.py").write_text(
            'import pytest\n@pytest.mark.parametrize("v", ["  hello  ", "  world  "])\n'
            'def test_p(v):\n    assert v\n',
            encoding="utf-8",
        )
        lits = extract_test_assertion_literals(root)
        assert "  hello  " in lits
        assert "  world  " in lits


def test_extract_excludes_bool() -> None:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "test_bool.py").write_text(
            'def test_b():\n    assert x is True\n    assert y == False\n',
            encoding="utf-8",
        )
        lits = extract_test_assertion_literals(root)
        assert True not in lits  # type: ignore[operator]
        assert False not in lits  # type: ignore[operator]


def test_verify_eq_overfit_raises() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if s == "  HELLO  ":\n        return "hello"\n    return s\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert "  HELLO  " in ei.value.leaked_literal
    assert ei.value.file_path == "a.py"


def test_verify_in_overfit_raises() -> None:
    lits: frozenset[str | int | float] = frozenset({"  Alice  ", "\tBOB\n"})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if s in ("  Alice  ", "\tBOB\\n"):\n        return 1\n    return s\n'}
    with pytest.raises(OverfitPolicyError):
        verify_not_overfitted(_ws(), pre, post, lits)


def test_verify_obfuscated_concat_raises() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if s == "  HEL" + "LO  ":\n        return "hello"\n    return s\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert "  HELLO  " in ei.value.leaked_literal


def test_verify_byte_decode_raises() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if s == b"  HELLO  ".decode():\n        return "hello"\n    return s\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert "  HELLO  " in ei.value.leaked_literal


def test_verify_static_join_raises() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if s == "".join(["  HE", "LLO  "]):\n        return "hello"\n    return s\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert "  HELLO  " in ei.value.leaked_literal


def test_verify_dict_lookup_table_raises() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    table = {"  HELLO  ": "hello"}\n    return table.get(s, s)\n'}
    with pytest.raises(OverfitPolicyError) as ei:
        verify_not_overfitted(_ws(), pre, post, lits)
    assert "  HELLO  " in ei.value.leaked_literal


def test_verify_generic_fix_passes() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  ", "  Alice  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": "def f(s):\n    return s.strip().lower()\n"}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_verify_truthiness_guard_passes() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if not s:\n        return ""\n    return s\n'}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_verify_preexisting_literal_not_flagged() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": 'def f(s):\n    x = "  HELLO  "\n    return s\n'}
    post = {"a.py": 'def f(s):\n    x = "  HELLO  "\n    if s == "  HELLO  ":\n        return x\n    return s\n'}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_verify_no_false_positive_on_unrelated_eq() -> None:
    lits: frozenset[str | int | float] = frozenset({"  HELLO  "})
    pre = {"a.py": "def f(s):\n    return s\n"}
    post = {"a.py": 'def f(s):\n    if s == "other":\n        return 1\n    return s\n'}
    verify_not_overfitted(_ws(), pre, post, lits)


def test_reflection_inspect_stack_raises() -> None:
    pre = {"a.py": "def f():\n    return 1\n"}
    post = {"a.py": "import inspect\ndef f():\n    inspect.stack()\n    return 1\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_forbidden_reflection(pre, post)
    assert "Forbidden" in str(ei.value)


def test_reflection_sys_getframe_raises() -> None:
    pre = {"a.py": "def f():\n    return 1\n"}
    post = {"a.py": "from sys import _getframe\ndef f():\n    _getframe()\n    return 1\n"}
    with pytest.raises(OverfitPolicyError):
        check_forbidden_reflection(pre, post)


def test_reflection_pytest_import_raises() -> None:
    pre = {"a.py": "def f():\n    return 1\n"}
    post = {"a.py": "import pytest\ndef f():\n    return 1\n"}
    with pytest.raises(OverfitPolicyError):
        check_forbidden_reflection(pre, post)


def test_reflection_builtins_dict_raises() -> None:
    pre = {"a.py": "def f():\n    return 1\n"}
    post = {"a.py": "import builtins\ndef f():\n    return builtins.__dict__\n"}
    with pytest.raises(OverfitPolicyError):
        check_forbidden_reflection(pre, post)


def test_hygiene_bidi_character_raises() -> None:
    diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n def f():\n+    x = '\u202eadmin'\n"
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, {"a.py": "def f():\n    x = '\u202eadmin'\n"})
    assert "BiDi" in str(ei.value)


def test_hygiene_zero_width_space_raises() -> None:
    diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n def f():\n+    x = '\u200bsecret'\n"
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, {"a.py": "def f():\n    x = '\u200bsecret'\n"})
    assert "zero-width" in str(ei.value)


def test_hygiene_bare_carriage_return_raises() -> None:
    diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n def f():\n+    x = 1\r"
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, {"a.py": "def f():\n    x = 1\n"})
    assert "Bare carriage return" in str(ei.value)


def test_hygiene_mixed_indentation_raises() -> None:
    diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n def f():\n+\t  return 1\n"
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene(diff, {"a.py": "def f():\n\t  return 1\n"})
    assert "Mixed tab-and-space" in str(ei.value)


def test_hygiene_non_ascii_identifier_raises() -> None:
    # Cyrillic 'а' (\u0430) instead of ASCII 'a'
    pre = {"a.py": "def f():\n    return 1\n"}
    post = {"a.py": "def f():\n    \u0430lice = 1\n    return \u0430lice\n"}
    with pytest.raises(OverfitPolicyError) as ei:
        check_patch_hygiene("", post, pre)
    assert "non-ASCII identifier" in str(ei.value)

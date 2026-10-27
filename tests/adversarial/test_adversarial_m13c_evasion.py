"""ADV-01..12: fixtures are inspected as AST only, never executed."""

from __future__ import annotations

import pytest

from agentsentinel.domain.exceptions import OverfitPolicyError


@pytest.mark.parametrize(
    ("scenario", "source", "code"),
    [
        (
            "ADV-01",
            'import sys\ndef f(s):\n    return getattr(sys, "_get" + "frame")\n',
            "INDIRECT_REFLECTION",
        ),
        (
            "ADV-02",
            'import sys\ndef f(s):\n    return sys.modules["pytest"]\n',
            "INDIRECT_REFLECTION",
        ),
        ("ADV-03", 'def f(s):\n    return vars(__builtins__)["eval"]\n', "INDIRECT_REFLECTION"),
        (
            "ADV-04",
            'def f(s):\n    if s == "".join(chr(x) for x in [32,32,72,69,76,76,79,32,32]):\n        return True\n',
            "OBFUSCATED_LITERAL",
        ),
        (
            "ADV-05",
            'def f(s):\n    return bytes.fromhex("74657374").decode()\n',
            "OBFUSCATED_LITERAL",
        ),
        (
            "ADV-06",
            'def f(s):\n    if s == "  OLLEH  "[::-1]:\n        return True\n',
            "OBFUSCATED_LITERAL",
        ),
        (
            "ADV-07",
            "import zlib\ndef f(s):\n    return zlib.crc32(s.encode()) == 3629320252\n",
            "OBFUSCATED_LITERAL",
        ),
        (
            "ADV-08",
            "def f(s):\n    try:\n        work()\n    finally:\n        return True\n",
            "ABRUPT_FINALLY_EXIT",
        ),
        (
            "ADV-09",
            "def f(s):\n    for item in s:\n        try:\n            work()\n        finally:\n            break\n",
            "ABRUPT_FINALLY_EXIT",
        ),
        (
            "ADV-10",
            "import contextlib\ndef f(s):\n    with contextlib.suppress(Exception):\n        work()\n",
            "CONTEXT_SUPPRESSION",
        ),
        ("ADV-11", "GLOBAL_CONFIG = False\ndef f(s):\n    return s\n", "TOPLEVEL_SIDEEFFECT"),
        ("ADV-12", '@apply_side_effect("pwn")\ndef f(s):\n    return s\n', "TOPLEVEL_SIDEEFFECT"),
    ],
)
def test_twelve_evasion_scenarios(scenario: str, source: str, code: str) -> None:
    from agentsentinel.verification import verify_second_order_evasion

    with pytest.raises(OverfitPolicyError, match=f"ERR_M13C_{code}") as caught:
        verify_second_order_evasion("app.py", "", source, frozenset({"test", "  HELLO  "}))
    assert caught.value.file_path == "app.py", scenario


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ('return globals()["__builtins__"]', "INDIRECT_REFLECTION"),
        ('import sys as s\n    return s.modules.get("pytest")', "INDIRECT_REFLECTION"),
        (
            'from builtins import getattr as lookup\n    return lookup(x, "frame")',
            "INDIRECT_REFLECTION",
        ),
        (
            "from contextlib import suppress as quiet\n    with quiet(*errors):\n        work()",
            "CONTEXT_SUPPRESSION",
        ),
        ('import base64 as b\n    return b.b64decode("dGVzdA==").decode()', "OBFUSCATED_LITERAL"),
        (
            'match x:\n        case _ if getattr(x, "frame"):\n            return True',
            "INDIRECT_REFLECTION",
        ),
        (
            'match x:\n        case _ if x == "tset"[::-1]:\n            return True',
            "OBFUSCATED_LITERAL",
        ),
        (
            'import hashlib as h\n    return h.sha256(x.encode()).hexdigest() == "00"',
            "OBFUSCATED_LITERAL",
        ),
        ("return hash(x) == 12345", "OBFUSCATED_LITERAL"),
        (
            "try:\n        work()\n    finally:\n        if x:\n            return True",
            "ABRUPT_FINALLY_EXIT",
        ),
    ],
)
def test_composed_alias_and_compound_evasions(body: str, code: str) -> None:
    from agentsentinel.verification import verify_second_order_evasion

    with pytest.raises(OverfitPolicyError, match=f"ERR_M13C_{code}"):
        verify_second_order_evasion("app.py", "", f"def f(x):\n    {body}\n", frozenset({"test"}))

"""Public Python call contracts remain compatible across repair patches."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.exceptions import OverfitPolicyError
from agentsentinel.verification import overfit_guard

if TYPE_CHECKING:
    from pathlib import Path


def verify(pre: str, post: str) -> None:
    from agentsentinel.verification.contract_guard import verify_public_api_compatibility

    verify_public_api_compatibility("api.py", pre, post)


@pytest.mark.parametrize(
    ("pre", "post"),
    [
        ("def helper(x): return x", ""),
        ("class Public: ...", ""),
        ("def helper(x): return x", "def renamed(x): return x"),
        ("def f(x, y): return x", "def f(x): return x"),
        ("def f(x, y): return x", "def f(y, x): return x"),
        ("def f(timeout=30): return timeout", "def f(timeout): return timeout"),
        ("def f(x): return x", "async def f(x): return x"),
        ("async def f(x): return x", "def f(x): return x"),
        ("def f(x): return x", "def f(x, required): return x"),
        ("def f(x): return x", "def f(x, /): return x"),
        ("def f(x): return x", "def f(*, x): return x"),
        ("def f(*, timeout=30): return timeout", "def f(*, timeout): return timeout"),
        ("def f(*, x): return x", "def f(**kwargs): return kwargs"),
        ("def f(*args): return args", "def f(): return ()"),
        ("def f(**kwargs): return kwargs", "def f(): return {}"),
        ("def f(x, *args): return x", "def f(x, extra=None, *args): return x"),
        ("class A:\n    def method(self, x): return x", "class A: ..."),
        ("class A:\n    def __init__(self, x): self.x = x", "class A:\n    def __init__(self): ..."),
        ("class A:\n    def f(self, x): return x", "class A:\n    @staticmethod\n    def f(self, x): return x"),
        ("class A:\n    @classmethod\n    def f(cls, x): return x", "class A:\n    @staticmethod\n    def f(cls, x): return x"),
        ("class A:\n    @property\n    def value(self): return 1", "class A:\n    def value(self): return 1"),
        (
            "class A:\n    @property\n    def value(self): return 1\n    @value.setter\n    def value(self, x): ...",
            "class A:\n    @property\n    def value(self): return 2",
        ),
        ("def f(x): return x", "class f: ..."),
        ("class A: ...", "def A(): return None"),
    ],
)
def test_breaking_contracts_are_rejected(pre: str, post: str) -> None:
    with pytest.raises(OverfitPolicyError, match="API contract"):
        verify(pre, post)


@pytest.mark.parametrize(
    ("pre", "post"),
    [
        ("def f(x): return x", "def f(x, extra=None): return x"),
        ("def f(x): return x", "def f(x, *, extra=None): return x"),
        ("def f(x): return x", "def f(x, *args, **kwargs): return x"),
        ("def f(x, /): return x", "def f(x): return x"),
        ("def f(x, *args): return x", "def f(x, *args, extra=None): return x"),
        ("def f(*, x, y=2): return x", "def f(*, y=2, x, extra=None): return x"),
        ("def f(timeout=30): return timeout", "def f(timeout=60): return timeout"),
        ("def f(x): return x", "def f(x): return x\ndef _clean(): return 1"),
        ("def _private(x): return x", ""),
        ("class A:\n    def _private(self, x): return x", "class A: ..."),
        ("def f(x: int) -> int: return x", "def f(x): return x + 1"),
    ],
)
def test_compatible_additions_are_allowed(pre: str, post: str) -> None:
    verify(pre, post)


def test_contract_runs_with_empty_literals_and_missing_post_file(tmp_path: Path) -> None:
    with pytest.raises(OverfitPolicyError, match="API contract"):
        overfit_guard.verify_not_overfitted(
            tmp_path, {"api.py": "def public(x): return x\n"}, {},
            test_literals=frozenset(),
        )


def test_contract_can_be_explicitly_disabled(tmp_path: Path) -> None:
    overfit_guard.verify_not_overfitted(
        tmp_path, {"api.py": "def public(x): return x\n"}, {},
        test_literals=frozenset(), enforce_api_contract=False,
    )


def test_no_source_import_or_execution(tmp_path: Path) -> None:
    marker = tmp_path / "must_not_exist"
    source = f"raise RuntimeError('never execute')\nopen({str(marker)!r}, 'w')\ndef f(x): return x\n"
    verify(source, source.replace("return x", "return x + 1"))
    assert not marker.exists()


def test_new_optional_positional_only_parameter_is_compatible() -> None:
    verify("def f(x, /): return x", "def f(x, extra=None, /): return x")


def test_implicit_object_constructor_cannot_gain_required_arguments() -> None:
    with pytest.raises(OverfitPolicyError, match="API contract"):
        verify("class A: ...", "class A:\n    def __init__(self, required): ...")


def test_descriptor_import_alias_cannot_change_method_binding() -> None:
    pre = "class A:\n    def f(self, x): return x\n"
    post = "from builtins import staticmethod as static\nclass A:\n    @static\n    def f(self, x): return x\n"
    with pytest.raises(OverfitPolicyError, match="API contract"):
        verify(pre, post)


@pytest.mark.parametrize(
    ("pre", "post"),
    [
        ("def f(x): return x", "def f(x): return x\nf = None"),
        ("class A: ...", "class A: ...\nA = None"),
        ("class A: ...", "class A: ...\ndef A(): return None"),
        ("def f(x): return x", "def f(x): return x\nclass f: ..."),
        ("class A:\n    def f(self, x): return x", "class A:\n    def f(self, x): return x\n    f = None"),
        ("def f(x): return x", "def f(x): return x\ndel f"),
        ("def f(x): return x", "def f(x): return x\nfrom other import f"),
        (
            "class A:\n    @property\n    def value(self): return 1\n    @value.setter\n    def value(self, x): ...",
            "class A:\n    @property\n    def value(self): return 1\n    @value.setter\n    def value(self, x): ...\n    @property\n    def value(self): return 2",
        ),
    ],
)
def test_effective_public_bindings_cannot_be_removed(pre: str, post: str) -> None:
    with pytest.raises(OverfitPolicyError, match="API contract"):
        verify(pre, post)


def test_annotation_without_value_does_not_rebind_function() -> None:
    verify("def f(x): return x", "def f(x): return x\nf: object")


def test_property_getter_update_retains_existing_setter() -> None:
    pre = "class A:\n    @property\n    def value(self): return 1\n    @value.setter\n    def value(self, x): ...\n"
    verify(pre, pre + "    @value.getter\n    def value(self): return 2\n")

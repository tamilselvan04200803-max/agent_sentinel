"""The additive M10 API mutates only changed functions and respects its budget."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError

import pytest

from agentsentinel import verification


def generate(pre: str, post: str, cap: int = 3):
    return verification.generate_differential_patch_mutants("module.py", pre, post, cap)


def test_changed_function_only_and_deterministic_cap() -> None:
    pre = "GLOBAL = 1 + 2\ndef unchanged(x):\n    return x + 1\ndef changed(x):\n    return x\n"
    post = pre.replace("return x\n", "return (x + 1) * 2 if x > 0 and x < 5 else False\n")
    mutants = generate(pre, post)
    assert len(mutants) == 3
    assert mutants == generate(pre, post)
    for mutant in mutants:
        assert mutant.file_path == "module.py"
        assert mutant.function_name == "changed"
        assert "GLOBAL = 1 + 2" in mutant.mutated_source
        assert "return x + 1" in mutant.mutated_source
        compile(ast.parse(mutant.mutated_source), "module.py", "exec")
    with pytest.raises(FrozenInstanceError):
        mutants[0].file_path = "other.py"


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("x == y", "x != y"), ("x != y", "x == y"),
        ("x < y", "x >= y"), ("x >= y", "x < y"),
        ("x <= y", "x > y"), ("x > y", "x <= y"),
        ("x is y", "x is not y"), ("x is not y", "x is y"),
        ("x in y", "x not in y"), ("x not in y", "x in y"),
        ("x + y", "x - y"), ("x - y", "x + y"),
        ("x * y", "x // y"), ("x // y", "x * y"),
        ("x and y", "x or y"), ("x or y", "x and y"),
        ("True", "False"), ("False", "True"),
        ("x.strip().lower()", "x.strip()"),
    ],
)
def test_exact_first_order_rules(expression: str, expected: str) -> None:
    mutants = generate("def f(x, y):\n    return None\n", f"def f(x, y):\n    return {expression}\n")
    assert len(mutants) == 1
    assert ast.dump(ast.parse(mutants[0].mutated_source)) == ast.dump(
        ast.parse(f"def f(x, y):\n    return {expected}\n")
    )


def test_nested_edit_does_not_enable_enclosing_body_mutations() -> None:
    pre = "def outer(x):\n    def inner(y):\n        return y\n    return x + 1\n"
    post = pre.replace("return y\n", "return y * 2\n")
    mutants = generate(pre, post, 20)
    assert len(mutants) == 1
    assert mutants[0].function_name == "outer.inner"
    assert "return x + 1" in mutants[0].mutated_source


def test_class_method_async_and_duplicate_names_have_distinct_identity() -> None:
    pre = "class A:\n    async def f(self, x):\n        return x\nclass B:\n    def f(self, x):\n        return x + 1\n"
    post = pre.replace("return x\n", "return x - 2\n")
    mutants = generate(pre, post, 20)
    assert len(mutants) == 1
    assert mutants[0].function_name == "A.f"


def test_repeated_definitions_are_matched_by_occurrence() -> None:
    pre = "def f(x):\n    return x + 1\ndef f(x):\n    return x\n"
    post = pre[:-len("    return x\n")] + "    return x * 2\n"
    mutants = generate(pre, post, 20)
    assert len(mutants) == 1
    assert "return x + 1" in mutants[0].mutated_source
    assert "return x // 2" in mutants[0].mutated_source


def test_new_functions_are_eligible_but_defaults_and_decorators_are_not() -> None:
    post = "@decorate(1 + 2)\ndef f(x=3 + 4):\n    return x * 5\n"
    mutants = generate("", post, 20)
    assert len(mutants) == 1
    assert "@decorate(1 + 2)" in mutants[0].mutated_source
    assert "x=3 + 4" in mutants[0].mutated_source


def test_chained_comparison_mutates_one_operator_at_a_time() -> None:
    mutants = generate("", "def f(x, y, z):\n    return x < y <= z\n", 20)
    assert len(mutants) == 2
    assert "return x >= y <= z" in mutants[0].mutated_source
    assert "return x < y > z" in mutants[1].mutated_source


def test_no_mutations_for_unchanged_or_module_only_edits() -> None:
    source = "VALUE = 1 + 2\ndef f(x):\n    return x + 1\n"
    assert generate(source, source) == []
    assert generate(source, source.replace("1 + 2", "2 + 3")) == []


def test_budget_and_invalid_source_handling() -> None:
    assert generate("", "def f():\n    return True\n", 0) == []
    with pytest.raises(ValueError):
        generate("", "", -1)
    with pytest.raises(SyntaxError):
        generate("def broken(:", "")
    with pytest.raises(SyntaxError):
        generate("", "def broken(:")

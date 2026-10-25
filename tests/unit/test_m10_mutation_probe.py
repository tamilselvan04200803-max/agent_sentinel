"""Unit tests for M10 — AST Patch Mutation Adequacy Probe."""

from __future__ import annotations

import ast

import pytest

from agentsentinel.verification import PatchMutant, generate_patch_mutants

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_COMPARISON_SRC = (
    "def check(x, y):\n"
    "    if x == y:\n"
    "        return True\n"
    "    if x < y:\n"
    "        return True\n"
    "    if x is y:\n"
    "        return True\n"
    "    if x in y:\n"
    "        return True\n"
    "    return False\n"
)

_ARITHMETIC_SRC = (
    "def compute(a, b):\n"
    "    return (a + b) * (a - b) // 2\n"
)

_BOOLOP_SRC = (
    "def decide(a, b, c):\n"
    "    return (a and b) or c\n"
)

_CALL_SRC = (
    "def call_it(x):\n"
    "    return len(x, 0)\n"
)

_COMBINED_SRC = (
    "def complex_fn(a, b, lst):\n"
    "    if a > 0 and b < 10:\n"
    "        return a % b\n"
    "    return sum(lst)\n"
)


# ---------------------------------------------------------------------------
# PatchMutant dataclass tests
# ---------------------------------------------------------------------------


class TestPatchMutant:
    def test_dataclass_fields(self) -> None:
        mutant = PatchMutant(
            rule="comparison_flip",
            description="test description",
            mutant_id="comparison_flip:Compare:1:2:0",
            source="x != y\n",
        )
        assert mutant.rule == "comparison_flip"
        assert mutant.description == "test description"
        assert mutant.mutant_id == "comparison_flip:Compare:1:2:0"
        assert mutant.source == "x != y\n"

    def test_dataclass_frozen(self) -> None:
        mutant = PatchMutant(
            rule="arithmetic_flip",
            description="test",
            mutant_id="id",
            source="x\n",
        )
        with pytest.raises(AttributeError):
            mutant.rule = "other"  # type: ignore[misc]

    def test_source_field_not_in_repr(self) -> None:
        mutant = PatchMutant(
            rule="boolean_call_strip",
            description="strip args",
            mutant_id="boolean_call_strip:Call:1:2",
            source="len(x)\n",
        )
        repr_str = repr(mutant)
        assert "len(x)" not in repr_str
        assert "source" not in repr_str or "source=" not in repr_str


# ---------------------------------------------------------------------------
# Comparison Flip rule tests
# ---------------------------------------------------------------------------


class TestComparisonFlip:
    def test_flips_eq_to_neq(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        rules = [m.rule for m in mutants]
        assert "comparison_flip" in rules
        # At least one mutant should contain "!=" where "==" was.
        flipped = [m for m in mutants if m.rule == "comparison_flip"]
        assert any("!=" in m.source for m in flipped)

    def test_flips_lt_to_gte(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        flipped = [m for m in mutants if m.rule == "comparison_flip"]
        # The source originally has "x < y" → flipped to "x >= y".
        assert any(">=" in m.source for m in flipped)

    def test_flips_is_to_isnot(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        flipped = [m for m in mutants if m.rule == "comparison_flip"]
        assert any("is not" in m.source for m in flipped)

    def test_flips_in_to_notin(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        flipped = [m for m in mutants if m.rule == "comparison_flip"]
        assert any("not in" in m.source for m in flipped)

    def test_all_five_comparison_ops_yielded(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        flipped = [m for m in mutants if m.rule == "comparison_flip"]
        # 4 comparison operators in _COMPARISON_SRC (eq, lt, is, in).
        assert len(flipped) == 4

    def test_mutant_source_is_valid_python(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        for mutant in mutants:
            ast.parse(mutant.source)

    def test_mutant_id_contains_line_col(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        for mutant in mutants:
            if mutant.rule == "comparison_flip":
                parts = mutant.mutant_id.split(":")
                assert parts[0] == "comparison_flip"
                assert len(parts) >= 4


# ---------------------------------------------------------------------------
# Arithmetic Flip rule tests
# ---------------------------------------------------------------------------


class TestArithmeticFlip:
    def test_flips_add_to_sub(self) -> None:
        mutants = generate_patch_mutants(_ARITHMETIC_SRC, "arith.py")
        flipped = [m for m in mutants if m.rule == "arithmetic_flip"]
        # _ARITHMETIC_SRC = (a + b) * (a - b) // 2 has 4 BinOp nodes: +, -, *, //
        assert len(flipped) == 4
        # The + op should flip to -.
        assert any("Sub" in m.description or "-" in m.source for m in flipped)

    def test_flips_mult_to_div(self) -> None:
        mutants = generate_patch_mutants(_ARITHMETIC_SRC, "arith.py")
        flipped = [m for m in mutants if m.rule == "arithmetic_flip"]
        assert any("/" in m.source for m in flipped)

    def test_flips_mod_to_floordiv(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "combined.py")
        flipped = [m for m in mutants if m.rule == "arithmetic_flip"]
        assert any("//" in m.source for m in flipped)

    def test_mutant_source_is_valid_python(self) -> None:
        mutants = generate_patch_mutants(_ARITHMETIC_SRC, "arith.py")
        for mutant in mutants:
            ast.parse(mutant.source)

    def test_no_arithmetic_ops_returns_empty_for_rule(self) -> None:
        src = "def fn(a):\n    return a\n"
        mutants = generate_patch_mutants(src, "plain.py")
        arith = [m for m in mutants if m.rule == "arithmetic_flip"]
        assert len(arith) == 0


# ---------------------------------------------------------------------------
# Boolean/Call Strip rule tests
# ---------------------------------------------------------------------------


class TestBooleanCallStrip:
    def test_strips_one_boolop_operand(self) -> None:
        mutants = generate_patch_mutants(_BOOLOP_SRC, "boolop.py")
        bools = [m for m in mutants if m.rule == "boolean_call_strip"]
        assert len(bools) >= 1
        # Original: (a and b) or c → BoolOp(Or, [BoolOp(And, [a, b]), c])
        # Outer BoolOp has 2 values, inner has 2 values → 2 + 2 = 4 strips.
        assert len(bools) == 4

    def test_stripped_boolop_is_valid_python(self) -> None:
        mutants = generate_patch_mutants(_BOOLOP_SRC, "boolop.py")
        for mutant in mutants:
            ast.parse(mutant.source)

    def test_strips_call_arguments(self) -> None:
        mutants = generate_patch_mutants(_CALL_SRC, "call.py")
        call_strips = [
            m
            for m in mutants
            if m.rule == "boolean_call_strip" and "Call" in m.mutant_id
        ]
        assert len(call_strips) == 1
        # The call should be stripped to bare "len".
        assert "len()" in call_strips[0].source

    def test_call_strip_is_valid_python(self) -> None:
        mutants = generate_patch_mutants(_CALL_SRC, "call.py")
        for mutant in mutants:
            ast.parse(mutant.source)

    def test_no_boolop_or_call_returns_empty(self) -> None:
        src = "def fn(a):\n    return a\n"
        mutants = generate_patch_mutants(src, "plain.py")
        assert len(mutants) == 0


# ---------------------------------------------------------------------------
# Combined integration tests
# ---------------------------------------------------------------------------


class TestGeneratePatchMutants:
    def test_returns_list_of_patchmutant(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "combined.py")
        assert isinstance(mutants, list)
        assert all(isinstance(m, PatchMutant) for m in mutants)

    def test_all_three_rules_represented(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "combined.py")
        rules = {m.rule for m in mutants}
        assert rules == {"comparison_flip", "arithmetic_flip", "boolean_call_strip"}

    def test_source_path_in_description(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "my_file.py")
        assert all("my_file.py" in m.description for m in mutants)

    def test_source_always_ends_with_newline(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "combined.py")
        for mutant in mutants:
            assert mutant.source.endswith("\n")

    def test_invalid_syntax_returns_empty(self) -> None:
        mutants = generate_patch_mutants("def fn(:", "bad.py")
        assert mutants == []

    def test_mutant_id_uniqueness(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "combined.py")
        ids = [m.mutant_id for m in mutants]
        assert len(ids) == len(set(ids))

    def test_total_mutant_count(self) -> None:
        mutants = generate_patch_mutants(_COMBINED_SRC, "combined.py")
        # _COMBINED_SRC has:
        # - 2 comparison ops (>, <) → 2 comparison_flip mutants
        # - 1 arithmetic op (%) → 1 arithmetic_flip mutant
        # - 1 BoolOp (and, in if-condition) → 2 boolop strip
        # - 1 Call (sum) with 1 arg → 1 call strip
        rules = [m.rule for m in mutants]
        assert rules.count("comparison_flip") == 2
        assert rules.count("arithmetic_flip") == 1
        assert rules.count("boolean_call_strip") == 3  # 2 boolop + 1 call

    def test_empty_source_returns_empty(self) -> None:
        mutants = generate_patch_mutants("", "empty.py")
        assert mutants == []

    def test_description_mentions_line_and_col(self) -> None:
        mutants = generate_patch_mutants(_COMPARISON_SRC, "test.py")
        for mutant in mutants:
            if mutant.rule == "comparison_flip":
                assert "test.py:" in mutant.description

"""Unit tests for agentsentinel.domain.exit_codes."""

from __future__ import annotations

import pytest

from agentsentinel.domain.exit_codes import (
    ExitCode,
    HARNESS_BROKEN_CODES,
    VERDICT_CODES,
    classify,
    is_genuine_verdict,
    is_harness_broken,
)


# ---------------------------------------------------------------------------
# ExitCode enum correctness
# ---------------------------------------------------------------------------

class TestExitCodeValues:
    """Verify every exit code maps to the correct pytest integer."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("name", "expected_int"),
        [
            ("OK", 0),
            ("TESTS_FAILED", 1),
            ("INTERRUPTED", 2),
            ("INTERNAL_ERROR", 3),
            ("USAGE_ERROR", 4),
            ("NO_TESTS_COLLECTED", 5),
        ],
    )
    def test_integer_values(self, name: str, expected_int: int) -> None:
        assert ExitCode[name] == expected_int

    @pytest.mark.unit
    def test_no_tests_collected_is_not_ok(self) -> None:
        """NO_TESTS_COLLECTED must NOT equal OK — the reward-hacking guard."""
        assert ExitCode.NO_TESTS_COLLECTED != ExitCode.OK

    @pytest.mark.unit
    def test_all_codes_present(self) -> None:
        assert set(ExitCode) == {
            ExitCode.OK,
            ExitCode.TESTS_FAILED,
            ExitCode.INTERRUPTED,
            ExitCode.INTERNAL_ERROR,
            ExitCode.USAGE_ERROR,
            ExitCode.NO_TESTS_COLLECTED,
        }


# ---------------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------------

class TestClassify:
    @pytest.mark.unit
    @pytest.mark.parametrize("raw", [0, 1, 2, 3, 4, 5])
    def test_valid_codes(self, raw: int) -> None:
        result = classify(raw)
        assert isinstance(result, ExitCode)
        assert int(result) == raw

    @pytest.mark.unit
    @pytest.mark.parametrize("raw", [-1, 6, 100, 255])
    def test_invalid_codes_raise(self, raw: int) -> None:
        with pytest.raises(ValueError, match="Unrecognised pytest exit code"):
            classify(raw)


# ---------------------------------------------------------------------------
# is_harness_broken / is_genuine_verdict
# ---------------------------------------------------------------------------

class TestClassificationPredicates:
    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("code", "expected_broken"),
        [
            (ExitCode.OK, False),
            (ExitCode.TESTS_FAILED, False),
            (ExitCode.INTERRUPTED, True),
            (ExitCode.INTERNAL_ERROR, True),
            (ExitCode.USAGE_ERROR, True),
            (ExitCode.NO_TESTS_COLLECTED, True),  # <— critical reward-hacking guard
        ],
    )
    def test_is_harness_broken(self, code: ExitCode, expected_broken: bool) -> None:
        assert is_harness_broken(code) == expected_broken

    @pytest.mark.unit
    def test_is_genuine_verdict_inverse_of_is_harness_broken(self) -> None:
        for code in ExitCode:
            assert is_genuine_verdict(code) == (not is_harness_broken(code))

    @pytest.mark.unit
    def test_unknown_int_treated_as_broken(self) -> None:
        assert is_harness_broken(99) is True

    @pytest.mark.unit
    def test_sets_are_disjoint(self) -> None:
        assert HARNESS_BROKEN_CODES.isdisjoint(VERDICT_CODES)

    @pytest.mark.unit
    def test_sets_cover_all_codes(self) -> None:
        all_codes = frozenset(ExitCode)
        assert HARNESS_BROKEN_CODES | VERDICT_CODES == all_codes

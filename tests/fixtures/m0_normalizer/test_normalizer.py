"""Tests for M0 normalizer fixture in isolation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure direct importability even without package installation or root PYTHONPATH
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from normalizer import normalize_token


def test_basic_lowercase_and_strip():
    assert normalize_token("  HELLO WORLD  ") == "hello world"


def test_collapses_multiple_internal_whitespace():
    assert normalize_token("foo   \t\n  bar") == "foo bar"


def test_strips_ascii_control_characters():
    assert normalize_token("foo\x00\x08bar\x1f\x7f") == "foobar"


def test_empty_string():
    assert normalize_token("   \t\n  ") == ""


def test_type_error_on_non_string():
    with pytest.raises(TypeError, match="Expected str"):
        normalize_token(12345)  # type: ignore[arg-type]

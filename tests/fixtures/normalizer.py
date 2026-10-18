"""M0 normalizer target workload fixture.

Provides an intentional bug and fix scenario for testing reproduction harnesses,
sandbox containers, and patch application.

Bug scenario:
`normalize_token` trims leading/trailing whitespace and lowercases, but fails
to collapse multiple consecutive internal whitespace characters to single spaces,
and fails to strip non-printable/control characters.

Failing test cases verify:
- collapsing multiple internal whitespace sequences (`"foo   bar"` -> `"foo bar"`)
- stripping ASCII control characters (`"foo\x00\x08bar"` -> `"foobar"`)
"""

from __future__ import annotations

import re


def normalize_token_buggy(text: str) -> str:
    """Buggy implementation: only strips outer whitespace and lowercases."""
    return text.strip().lower()


def normalize_token_fixed(text: str) -> str:
    """Fixed implementation: strips outer whitespace, removes control chars,
    collapses multiple spaces, and lowercases.
    """
    # Remove control characters (ASCII 0-31 and 127)
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", text)
    # Collapse multiple whitespace characters into a single space
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned.lower()


NORMALIZER_BUGGY_SOURCE = '''"""Normalizer module."""

def normalize_token(text: str) -> str:
    return text.strip().lower()
'''

NORMALIZER_FIXED_SOURCE = '''"""Normalizer module."""
import re

def normalize_token(text: str) -> str:
    cleaned = re.sub(r"[\\x00-\\x1f\\x7f]", "", text)
    cleaned = re.sub(r"\\s+", " ", cleaned).strip()
    return cleaned.lower()
'''

NORMALIZER_TEST_SOURCE = '''"""Tests for normalizer module — requires pytest."""
import pytest
from normalizer import normalize_token

def test_basic_lowercase():
    assert normalize_token("  HELLO  ") == "hello"

def test_collapses_internal_whitespace():
    # FAILS on buggy version ("foo   bar" -> "foo   bar")
    assert normalize_token("foo   bar") == "foo bar"

def test_strips_control_characters():
    # FAILS on buggy version ("foo\\x00bar" -> "foo\\x00bar")
    assert normalize_token("foo\\x00\\x08bar") == "foobar"
'''

NORMALIZER_TEST_SOURCE_UNITTEST = '''"""Tests for normalizer module — stdlib unittest (no pytest required)."""
import unittest
from normalizer import normalize_token

class TestNormalizer(unittest.TestCase):
    def test_basic_lowercase(self):
        self.assertEqual(normalize_token("  HELLO  "), "hello")

    def test_collapses_internal_whitespace(self):
        # FAILS on buggy version ("foo   bar" -> "foo   bar")
        self.assertEqual(normalize_token("foo   bar"), "foo bar")

    def test_strips_control_characters(self):
        # FAILS on buggy version ("foo\\x00bar" -> "foo\\x00bar")
        self.assertEqual(normalize_token("foo\\x00\\x08bar"), "foobar")

if __name__ == "__main__":
    unittest.main()
'''

NORMALIZER_PATCH_DIFF = """--- a/normalizer.py
+++ b/normalizer.py
@@ -1,4 +1,6 @@
 \"\"\"Normalizer module.\"\"\"
+import re

 def normalize_token(text: str) -> str:
-    return text.strip().lower()
+    cleaned = re.sub(r"[\\x00-\\x1f\\x7f]", "", text)
+    cleaned = re.sub(r"\\s+", " ", cleaned).strip()
+    return cleaned.lower()
"""

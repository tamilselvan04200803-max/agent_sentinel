"""Unit tests for agentsentinel.policy.diff_parser."""

from __future__ import annotations

import pytest

from agentsentinel.domain.exceptions import MalformedDiffError
from agentsentinel.policy.diff_parser import UnifiedDiffParser

SAMPLE_DIFF = """diff --git a/src/normalizer.py b/src/normalizer.py
index e69de29..d95f3ad 100644
--- a/src/normalizer.py
+++ b/src/normalizer.py
@@ -1,3 +1,5 @@
+import re
+
 def normalize(s):
-    return s.lower()
+    return re.sub(r'\\s+', ' ', s.strip()).lower()
"""


class TestUnifiedDiffParser:
    @pytest.mark.unit
    def test_parse_valid_git_diff(self) -> None:
        parsed = UnifiedDiffParser.parse(SAMPLE_DIFF)
        assert len(parsed.files) == 1
        f = parsed.files[0]
        assert f.old_path == "src/normalizer.py"
        assert f.new_path == "src/normalizer.py"
        assert f.target_path == "src/normalizer.py"
        assert len(f.hunks) == 1

        h = f.hunks[0]
        assert h.old_start == 1
        assert h.old_count == 3
        assert h.new_start == 1
        assert h.new_count == 5

        # Check hunk lines
        origins = [line.origin for line in h.lines]
        assert "+" in origins
        assert "-" in origins
        assert " " in origins

    @pytest.mark.unit
    def test_parse_standard_diff_without_git_header(self) -> None:
        diff = """--- a/mod.py
+++ b/mod.py
@@ -1,1 +1,1 @@
-bad
+good
"""
        parsed = UnifiedDiffParser.parse(diff)
        assert len(parsed.files) == 1
        assert parsed.files[0].target_path == "mod.py"

    @pytest.mark.unit
    def test_parse_new_file_diff(self) -> None:
        diff = """--- /dev/null
+++ b/new_mod.py
@@ -0,0 +1,2 @@
+line 1
+line 2
"""
        parsed = UnifiedDiffParser.parse(diff)
        assert len(parsed.files) == 1
        f = parsed.files[0]
        assert f.is_new is True
        assert f.target_path == "new_mod.py"

    @pytest.mark.unit
    def test_parse_deleted_file_diff(self) -> None:
        diff = """--- a/old_mod.py
+++ /dev/null
@@ -1,2 +0,0 @@
-line 1
-line 2
"""
        parsed = UnifiedDiffParser.parse(diff)
        assert len(parsed.files) == 1
        f = parsed.files[0]
        assert f.is_delete is True
        assert f.target_path == "old_mod.py"

    @pytest.mark.unit
    def test_reject_empty_diff(self) -> None:
        with pytest.raises(MalformedDiffError, match="Diff text is empty"):
            UnifiedDiffParser.parse("   \n\t  ")

    @pytest.mark.unit
    def test_reject_binary_diff(self) -> None:
        binary_diff = """diff --git a/image.png b/image.png
index e69de29..d95f3ad 100644
GIT binary patch
literal 1234
zc$@#%^&*()
"""
        with pytest.raises(MalformedDiffError, match="Binary diffs are strictly forbidden"):
            UnifiedDiffParser.parse(binary_diff)

    @pytest.mark.unit
    def test_reject_malformed_hunk_header(self) -> None:
        bad_hunk = """--- a/f.py
+++ b/f.py
@@ not a valid range @@
-bad
+good
"""
        with pytest.raises(MalformedDiffError, match="Invalid hunk ranges"):
            UnifiedDiffParser.parse(bad_hunk)

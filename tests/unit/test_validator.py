"""Unit tests for agentsentinel.policy.validator."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agentsentinel.domain.exceptions import (
    AllowlistViolationError,
    PathTraversalError,
    SymlinkEscapeError,
    TestFileModificationError,
)
from agentsentinel.policy.validator import PatchPolicyValidator

if TYPE_CHECKING:
    from pathlib import Path

VALID_DIFF = """--- a/src/normalizer.py
+++ b/src/normalizer.py
@@ -1,1 +1,1 @@
-bad
+good
"""

TEST_DIFF = """--- a/tests/test_normalizer.py
+++ b/tests/test_normalizer.py
@@ -1,1 +1,1 @@
-assert False
+assert True
"""

INFRA_DIFF = """--- a/pyproject.toml
+++ b/pyproject.toml
@@ -1,1 +1,1 @@
-pytest
+pytest-fake
"""

TRAVERSAL_DIFF = """--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1,1 +1,1 @@
-root
+hacked
"""


class TestPatchPolicyValidator:
    @pytest.mark.unit
    def test_valid_allowed_patch(self) -> None:
        validator = PatchPolicyValidator(allowed_edit_paths=("src/normalizer.py",))
        result = validator.validate_diff(VALID_DIFF)
        assert result.is_valid is True
        assert result.target_files == ("src/normalizer.py",)

    @pytest.mark.unit
    def test_block_test_file_modification(self) -> None:
        validator = PatchPolicyValidator(allowed_edit_paths=("tests/test_normalizer.py",))
        with pytest.raises(TestFileModificationError, match="REWARD-HACKING BAN"):
            validator.validate_diff(TEST_DIFF)

    @pytest.mark.unit
    def test_block_infrastructure_tampering(self) -> None:
        validator = PatchPolicyValidator(allowed_edit_paths=("pyproject.toml",))
        with pytest.raises(AllowlistViolationError):
            validator.validate_diff(INFRA_DIFF)

    @pytest.mark.unit
    def test_block_unallowed_path(self) -> None:
        validator = PatchPolicyValidator(allowed_edit_paths=("src/other.py",))
        with pytest.raises(AllowlistViolationError):
            validator.validate_diff(VALID_DIFF)

    @pytest.mark.unit
    def test_block_path_traversal(self) -> None:
        validator = PatchPolicyValidator(allowed_edit_paths=("../../etc/passwd",))
        with pytest.raises(PathTraversalError):
            validator.validate_diff(TRAVERSAL_DIFF)

    @pytest.mark.unit
    def test_block_symlink_escape(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside_target = tmp_path / "outside_secret.txt"
        outside_target.write_text("secret", encoding="utf-8")

        # Create symlink inside workspace pointing outside
        link_path = workspace / "escaped_link.py"
        try:
            link_path.symlink_to(outside_target)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation not supported in this user environment")

        escape_diff = """--- a/escaped_link.py
+++ b/escaped_link.py
@@ -1,1 +1,1 @@
-secret
+pwned
"""
        validator = PatchPolicyValidator(allowed_edit_paths=("escaped_link.py",))
        with pytest.raises(SymlinkEscapeError, match="Symlink escape"):
            validator.validate_diff(escape_diff, workspace_root=workspace)

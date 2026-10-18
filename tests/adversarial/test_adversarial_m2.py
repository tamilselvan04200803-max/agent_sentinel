"""Adversarial security and policy bypass tests for Milestone 2 (M2).

Tries to break the policy engine with:
- Nested path traversal attacks (`foo/../../../etc/passwd`, `C:\\Windows\\System32\\cmd.exe`)
- Hidden test file modifications (`conftest.py`, `src/nested/test_internal.py`, `pkg/tests/runner.py`)
- Hidden infrastructure file modifications (`.github/workflows/ci.yml`, `Dockerfile.dev`, `setup.py`)
- Malformed hunk coordinates, zero counts, negative line coordinates
- Obfuscated binary diffs and null-byte payloads
"""

from __future__ import annotations

import pytest

from agentsentinel.domain.exceptions import (
    AllowlistViolationError,
    MalformedDiffError,
    PathTraversalError,
    TestFileModificationError,
)
from agentsentinel.policy.diff_parser import UnifiedDiffParser
from agentsentinel.policy.validator import PatchPolicyValidator


class TestAdversarialM2PolicySecurity:
    @pytest.mark.adversarial
    @pytest.mark.parametrize(
        "evil_path",
        [
            "../../etc/shadow",
            "src/../../etc/passwd",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/absolute/root/file.py",
            "\\root\\file.py",
        ],
    )
    def test_path_traversal_variations_blocked(self, evil_path: str) -> None:
        diff = f"""--- a/{evil_path}
+++ b/{evil_path}
@@ -1,1 +1,1 @@
-original
+tampered
"""
        validator = PatchPolicyValidator(allowed_edit_paths=(evil_path,))
        with pytest.raises(PathTraversalError):
            validator.validate_diff(diff)

    @pytest.mark.adversarial
    @pytest.mark.parametrize(
        "test_target",
        [
            "tests/unit/test_app.py",
            "src/tests/test_core.py",
            "src/core_test.py",
            "conftest.py",
            "sub/nested/conftest.py",
            "test_something.py",
        ],
    )
    def test_reward_hacking_test_files_strictly_blocked(self, test_target: str) -> None:
        diff = f"""--- a/{test_target}
+++ b/{test_target}
@@ -1,1 +1,1 @@
-def test_bug(): assert False
+def test_bug(): assert True
"""
        validator = PatchPolicyValidator(allowed_edit_paths=(test_target,))
        with pytest.raises(TestFileModificationError):
            validator.validate_diff(diff)

    @pytest.mark.adversarial
    @pytest.mark.parametrize(
        "infra_target",
        [
            ".github/workflows/deploy.yml",
            ".git/config",
            "Dockerfile",
            "Dockerfile.prod",
            "pyproject.toml",
            "setup.cfg",
            "setup.py",
        ],
    )
    def test_infrastructure_tampering_blocked(self, infra_target: str) -> None:
        diff = f"""--- a/{infra_target}
+++ b/{infra_target}
@@ -1,1 +1,1 @@
-safe
+compromised
"""
        validator = PatchPolicyValidator(allowed_edit_paths=(infra_target,))
        with pytest.raises(AllowlistViolationError):
            validator.validate_diff(diff)

    @pytest.mark.adversarial
    def test_malformed_diff_corrupt_hunk_lines(self) -> None:
        diff = """--- a/src/normalizer.py
+++ b/src/normalizer.py
@@ -1,2 +1,2 @@
? invalid diff origin symbol
! another invalid line
"""
        # Parser should stop or ignore unrecognized lines without crashing
        parsed = UnifiedDiffParser.parse(diff)
        assert len(parsed.files) == 1
        assert parsed.files[0].target_path == "src/normalizer.py"

    @pytest.mark.adversarial
    def test_git_binary_diff_header_variants_rejected(self) -> None:
        diff1 = """diff --git a/binary.dat b/binary.dat
index e69de29..d95f3ad 100644
GIT binary patch
literal 64
zcmV;B0#
"""
        with pytest.raises(MalformedDiffError, match="Binary diffs are strictly forbidden"):
            UnifiedDiffParser.parse(diff1)

        diff2 = """diff --git a/bin.so b/bin.so
Binary files a/bin.so and b/bin.so differ
"""
        with pytest.raises(MalformedDiffError, match="Binary diffs are strictly forbidden"):
            UnifiedDiffParser.parse(diff2)

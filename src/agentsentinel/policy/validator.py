"""Patch policy validator.

Enforces:
1. Allowlist enforcement: every modified file must be in `CaseSpec.allowed_edit_paths`.
2. Reward-Hacking Ban: patches targeting test files are strictly blocked.
3. Infrastructure Tampering Ban: patches targeting build/CI/environment files are blocked.
4. Symlink Escape Protection: paths resolving outside the workspace root trigger
   `SymlinkEscapeError`.
5. Path Traversal Protection: paths with traversal sequences trigger `PathTraversalError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentsentinel.domain.exceptions import (
    AllowlistViolationError,
    PathTraversalError,
    SymlinkEscapeError,
    TestFileModificationError,
)
from agentsentinel.policy.diff_parser import ParsedDiff, UnifiedDiffParser

if TYPE_CHECKING:
    from pathlib import Path

# Files and glob patterns strictly barred from model modifications
FORBIDDEN_INFRASTRUCTURE_PATTERNS: tuple[str, ...] = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "tox.ini",
    ".gitlab-ci.yml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
)


@dataclass(frozen=True)
class ValidationResult:
    """The result of validating a diff against policy rules."""

    is_valid: bool
    target_files: tuple[str, ...]
    violations: tuple[str, ...] = ()


class PatchPolicyValidator:
    """Validates unified diffs against safety, scope, and reward-hacking policies."""

    def __init__(self, allowed_edit_paths: tuple[str, ...]) -> None:
        self.allowed_edit_paths = allowed_edit_paths

    def is_test_file(self, path_str: str) -> bool:
        """Check if a path targets test files or conftest."""
        normalized = path_str.replace("\\", "/").strip("/")
        parts = normalized.split("/")
        filename = parts[-1]

        # Check directory membership
        if "tests" in parts or "test" in parts:
            return True

        # Check file naming conventions
        return bool(
            filename.startswith("test_")
            or filename.endswith("_test.py")
            or filename == "conftest.py"
        )

    def is_infrastructure_file(self, path_str: str) -> bool:
        """Check if a path targets infrastructure or build configurations."""
        normalized = path_str.replace("\\", "/").strip("/")
        parts = normalized.split("/")
        filename = parts[-1]

        if parts[0] in (".git", ".github", ".circleci"):
            return True

        for pat in FORBIDDEN_INFRASTRUCTURE_PATTERNS:
            if filename == pat or filename.startswith("Dockerfile"):
                return True

        return False

    def validate_diff(
        self,
        diff_text: str,
        workspace_root: Path | None = None,
    ) -> ValidationResult:
        """Validate a unified diff against all security and integrity policies.

        Parameters
        ----------
        diff_text:
            Raw unified diff content.
        workspace_root:
            Optional Path to the local workspace root to check for symlink escapes.

        Returns
        -------
        ValidationResult
            Validation verdict and target file list.

        Raises
        ------
        PathTraversalError
            If path traversal sequences are detected.
        TestFileModificationError
            If a test file is modified.
        AllowlistViolationError
            If a file outside the allowlist is modified.
        SymlinkEscapeError
            If a symlink resolves outside the workspace root.
        """
        parsed: ParsedDiff = UnifiedDiffParser.parse(diff_text)
        targets = parsed.target_paths

        for target in targets:
            # 1. Path traversal detection
            if ".." in target or target.startswith("/") or target.startswith("\\"):
                raise PathTraversalError(target)

            # 2. Reward-Hacking Ban: test modification forbidden
            if self.is_test_file(target):
                raise TestFileModificationError(target)

            # 3. Infrastructure files forbidden
            if self.is_infrastructure_file(target):
                raise AllowlistViolationError(target, self.allowed_edit_paths)

            # 4. Allowlist enforcement
            normalized_target = target.replace("\\", "/").strip("/")
            allowed_normalized = {p.replace("\\", "/").strip("/") for p in self.allowed_edit_paths}

            if normalized_target not in allowed_normalized:
                raise AllowlistViolationError(target, self.allowed_edit_paths)

            # 5. Symlink escape detection against physical workspace if provided
            if workspace_root:
                resolved_root = workspace_root.resolve()
                candidate_path = (workspace_root / target).resolve()

                # In Python 3.11+, use is_relative_to
                try:
                    if not candidate_path.is_relative_to(resolved_root):
                        raise SymlinkEscapeError(
                            link=target,
                            resolved=str(candidate_path),
                            root=str(resolved_root),
                        )
                except AttributeError:  # pragma: no cover
                    # Fallback for Python versions < 3.9
                    if (
                        resolved_root not in candidate_path.parents
                        and candidate_path != resolved_root
                    ):
                        raise SymlinkEscapeError(
                            link=target,
                            resolved=str(candidate_path),
                            root=str(resolved_root),
                        ) from None

        return ValidationResult(is_valid=True, target_files=targets)

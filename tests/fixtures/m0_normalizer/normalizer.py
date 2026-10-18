"""M0 Normalizer Module.

Provides deterministic string and token normalization:
- Strips leading and trailing whitespace
- Removes ASCII control characters (0x00-0x1F, 0x7F)
- Collapses multiple internal whitespace characters into a single space
- Lowercases output for canonical comparisons
"""

from __future__ import annotations

import re

# ASCII control characters pattern (0-31 and 127)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
WHITESPACE_RE = re.compile(r"\s+")


def normalize_token(text: str) -> str:
    """Normalize a string or token deterministically.

    Parameters
    ----------
    text:
        Raw input string.

    Returns
    -------
    str
        Canonical, normalized lowercase string.
    """
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")

    # Strip control characters
    cleaned = CONTROL_CHAR_RE.sub("", text)
    # Collapse multiple consecutive whitespace characters to a single space and strip outer
    cleaned = WHITESPACE_RE.sub(" ", cleaned).strip()
    return cleaned.lower()

"""Config loader — classic falsy-coalescing bug: `val or default`
treats legitimate 0/False/'' as missing.
"""


def get_timeout(value: int | None, default: int = 30) -> int:
    return value or default

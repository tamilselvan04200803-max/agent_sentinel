"""Paginator — buggy off-by-one: drops the last item on each page."""

from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


def paginate(items: Sequence[T], page_size: int) -> list[list[T]]:
    pages: list[list[T]] = []
    i = 0
    while i < len(items):
        pages.append(list(items[i : i + page_size - 1]))
        i += page_size - 1
    return pages

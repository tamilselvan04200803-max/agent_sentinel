"""Bounded interpretation of a closed set of constant AST expressions.

No inspected callable, import, descriptor or codec registry entry is executed.
Unknown expressions and resource-limit exhaustion produce no constant.
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import hashlib
import zlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

UNKNOWN = object()
MAX_MATERIALIZED = 65536
MAX_ITERATIONS = 256
_ENCODINGS = {"utf-8", "utf8", "ascii", "latin-1", "latin1"}


def qualified_name(node: ast.AST, aliases: Mapping[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{qualified_name(node.value, aliases)}.{node.attr}"
    return ""


class ConstantFolder:
    """Each evaluation has independent depth, operation and output bounds."""

    def __init__(self, aliases: Mapping[str, str] | None = None) -> None:
        self.aliases = aliases or {}
        self.remaining = 4096

    def fold(
        self, node: ast.AST, env: Mapping[str, object] | None = None, depth: int = 0
    ) -> object:
        self.remaining -= 1
        if self.remaining < 0 or depth > 48:
            return UNKNOWN
        try:
            value = self._fold(node, env or {}, depth)
            if isinstance(value, (str, bytes, tuple)) and len(value) > MAX_MATERIALIZED:
                return UNKNOWN
            if isinstance(value, int) and value.bit_length() > 4096:
                return UNKNOWN
            return value
        except (ValueError, TypeError, LookupError, OverflowError, ArithmeticError):
            return UNKNOWN

    def _fold(self, node: ast.AST, env: Mapping[str, object], depth: int) -> object:
        def child(item: ast.AST) -> object:
            return self.fold(item, env, depth + 1)

        if isinstance(node, ast.Constant):
            return (
                node.value
                if isinstance(node.value, (str, bytes, int, float, type(None)))
                else UNKNOWN
            )
        if isinstance(node, ast.Name):
            return env.get(node.id, UNKNOWN)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if len(node.elts) > MAX_ITERATIONS:
                return UNKNOWN
            values = tuple(child(item) for item in node.elts)
            if any(item is UNKNOWN for item in values):
                return UNKNOWN
            # Sets have no guaranteed iteration order; only singleton sets fold.
            return values if not isinstance(node, ast.Set) or len(values) <= 1 else UNKNOWN
        if isinstance(node, ast.UnaryOp):
            value = child(node.operand)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if isinstance(node.op, ast.USub):
                    return -value
                if isinstance(node.op, ast.UAdd):
                    return value
            return UNKNOWN
        if isinstance(node, ast.BinOp):
            left, right = child(node.left), child(node.right)
            if isinstance(node.op, ast.Add):
                if isinstance(left, str) and isinstance(right, str):
                    return left + right if len(left) + len(right) <= MAX_MATERIALIZED else UNKNOWN
                if isinstance(left, bytes) and isinstance(right, bytes):
                    return left + right if len(left) + len(right) <= MAX_MATERIALIZED else UNKNOWN
                if (
                    type(left) in {int, float}
                    and type(right) in {int, float}
                    and isinstance(left, (int, float))
                    and isinstance(right, (int, float))
                ):
                    return left + right
            if isinstance(node.op, ast.Mult):
                if isinstance(left, int) and isinstance(right, (str, bytes)):
                    left, right = right, left
                if (
                    isinstance(left, (str, bytes))
                    and type(right) is int
                    and 0 <= right <= 1024
                    and len(left) * right <= MAX_MATERIALIZED
                ):
                    return left * right
            return UNKNOWN
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for item in node.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    parts.append(item.value)
                elif isinstance(item, ast.FormattedValue) and item.format_spec is None:
                    value = child(item.value)
                    if not isinstance(value, (str, int, float, bytes)):
                        return UNKNOWN
                    if item.conversion == 114:
                        parts.append(repr(value))
                    elif item.conversion == 97:
                        parts.append(ascii(value))
                    elif item.conversion in {-1, 115}:
                        parts.append(str(value))
                    else:
                        return UNKNOWN
                else:
                    return UNKNOWN
            return "".join(parts) if sum(map(len, parts)) <= MAX_MATERIALIZED else UNKNOWN
        if isinstance(node, ast.Subscript):
            value = child(node.value)
            if not isinstance(value, (str, bytes, tuple)):
                return UNKNOWN
            if isinstance(node.slice, ast.Slice):
                bounds = [
                    child(item) if item is not None else None
                    for item in (
                        node.slice.lower,
                        node.slice.upper,
                        node.slice.step,
                    )
                ]
                if any(item is not None and type(item) is not int for item in bounds):
                    return UNKNOWN
                lower, upper, step = bounds
                if (
                    (lower is None or isinstance(lower, int))
                    and (upper is None or isinstance(upper, int))
                    and (step is None or isinstance(step, int))
                ):
                    return value[slice(lower, upper, step)]
            index = child(node.slice)
            if type(index) is int:
                return value[index]
            return UNKNOWN
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            if len(node.generators) != 1:
                return UNKNOWN
            generator = node.generators[0]
            if generator.is_async or generator.ifs or not isinstance(generator.target, ast.Name):
                return UNKNOWN
            iterable = child(generator.iter)
            if not isinstance(iterable, (tuple, str, bytes)) or len(iterable) > MAX_ITERATIONS:
                return UNKNOWN
            result: list[object] = []
            for element in iterable:
                value = self.fold(node.elt, {**env, generator.target.id: element}, depth + 1)
                if value is UNKNOWN:
                    return UNKNOWN
                result.append(value)
            return tuple(result)
        if isinstance(node, ast.Call):
            if any(isinstance(arg, ast.Starred) for arg in node.args) or node.keywords:
                return UNKNOWN
            args = tuple(child(arg) for arg in node.args)
            if any(arg is UNKNOWN for arg in args):
                return UNKNOWN
            name = qualified_name(node.func, self.aliases).removeprefix("builtins.")
            if name == "chr" and len(args) == 1 and type(args[0]) is int:
                return chr(args[0])
            if name == "ord" and len(args) == 1 and isinstance(args[0], (str, bytes)):
                return ord(args[0])
            if name == "range" and 1 <= len(args) <= 3 and all(type(arg) is int for arg in args):
                ints = [arg for arg in args if isinstance(arg, int)]
                range_values = range(*ints)
                return tuple(range_values) if len(range_values) <= MAX_ITERATIONS else UNKNOWN
            if name in {"bytes", "bytearray"} and len(args) == 1 and isinstance(args[0], tuple):
                return bytes(args[0]) if all(type(arg) is int for arg in args[0]) else UNKNOWN
            if (
                name in {"bytes.fromhex", "bytearray.fromhex", "binascii.unhexlify"}
                and len(args) == 1
            ):
                value = args[0]
                if name == "binascii.unhexlify" and isinstance(value, (str, bytes)):
                    return binascii.unhexlify(value)
                if isinstance(value, str):
                    return bytes.fromhex(value)
            if (
                name
                in {
                    "base64.b64decode",
                    "base64.urlsafe_b64decode",
                    "base64.b32decode",
                    "base64.b16decode",
                }
                and len(args) == 1
                and isinstance(args[0], (str, bytes))
            ):
                value = args[0]
                if name == "base64.b64decode":
                    return base64.b64decode(value)
                if name == "base64.urlsafe_b64decode":
                    return base64.urlsafe_b64decode(value)
                if name == "base64.b32decode":
                    return base64.b32decode(value)
                return base64.b16decode(value)
            if (
                name in {"codecs.decode", "codecs.encode"}
                and len(args) == 2
                and isinstance(args[1], str)
            ):
                value, encoding = args
                if encoding in {"rot_13", "rot13"} and isinstance(value, str):
                    return codecs.encode(value, "rot_13")
                if encoding == "hex":
                    if name.endswith("decode") and isinstance(value, (str, bytes)):
                        return binascii.unhexlify(value)
                    if name.endswith("encode") and isinstance(value, bytes):
                        return binascii.hexlify(value)
                if encoding in _ENCODINGS:
                    if name.endswith("decode") and isinstance(value, bytes):
                        return value.decode(encoding)
                    if name.endswith("encode") and isinstance(value, str):
                        return value.encode(encoding)
            if (
                name in {"zlib.crc32", "zlib.adler32"}
                and len(args) == 1
                and isinstance(args[0], bytes)
            ):
                return zlib.crc32(args[0]) if name.endswith("crc32") else zlib.adler32(args[0])
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
                receiver = child(node.func.value)
                if method in {"decode", "encode"} and len(args) <= 1:
                    encoding = args[0] if args else "utf-8"
                    if isinstance(encoding, str) and encoding in _ENCODINGS:
                        if method == "decode" and isinstance(receiver, bytes):
                            return receiver.decode(encoding)
                        if method == "encode" and isinstance(receiver, str):
                            return receiver.encode(encoding)
                if (
                    method == "join"
                    and isinstance(receiver, (str, bytes))
                    and len(args) == 1
                    and isinstance(args[0], tuple)
                ):
                    values = args[0]
                    if isinstance(receiver, str) and all(isinstance(part, str) for part in values):
                        strings = [part for part in values if isinstance(part, str)]
                        size = sum(map(len, strings)) + len(receiver) * max(0, len(strings) - 1)
                        return receiver.join(strings) if size <= MAX_MATERIALIZED else UNKNOWN
                    if isinstance(receiver, bytes) and all(
                        isinstance(part, bytes) for part in values
                    ):
                        byte_parts = [part for part in values if isinstance(part, bytes)]
                        size = sum(map(len, byte_parts)) + len(receiver) * max(
                            0, len(byte_parts) - 1
                        )
                        return receiver.join(byte_parts) if size <= MAX_MATERIALIZED else UNKNOWN
                if isinstance(receiver, str):
                    if not args and method in {"strip", "lstrip", "rstrip", "lower", "upper"}:
                        if method == "strip":
                            return receiver.strip()
                        if method == "lstrip":
                            return receiver.lstrip()
                        if method == "rstrip":
                            return receiver.rstrip()
                        return receiver.lower() if method == "lower" else receiver.upper()
                    if (
                        method == "replace"
                        and len(args) == 2
                        and all(isinstance(arg, str) for arg in args)
                    ):
                        old, new = args
                        if isinstance(old, str) and isinstance(new, str):
                            size = len(receiver) + (len(new) - len(old)) * receiver.count(old)
                            return (
                                receiver.replace(old, new) if size <= MAX_MATERIALIZED else UNKNOWN
                            )
                if (
                    method in {"hexdigest", "digest"}
                    and not args
                    and isinstance(node.func.value, ast.Call)
                ):
                    call = node.func.value
                    algorithm = qualified_name(call.func, self.aliases)
                    if (
                        algorithm in {"hashlib.md5", "hashlib.sha1", "hashlib.sha256"}
                        and len(call.args) == 1
                        and not call.keywords
                    ):
                        data = child(call.args[0])
                        if isinstance(data, bytes):
                            digest = hashlib.new(
                                algorithm.split(".")[1], data, usedforsecurity=False
                            )
                            return digest.hexdigest() if method == "hexdigest" else digest.digest()
        return UNKNOWN


def fold_symbolic_constant(node: ast.AST) -> str | int | float | bytes | tuple[object, ...] | None:
    """Fold supported constants; ``None`` also represents unknown expressions."""
    value = ConstantFolder().fold(node)
    return value if isinstance(value, (str, int, float, bytes, tuple)) else None

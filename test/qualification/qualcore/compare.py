import base64
import errno as errno_module
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Comparison:
    matched: bool
    kind: str
    mode: str
    detail: str


def errno_number(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        name = value.upper()
        if not name.startswith("E"):
            return None
        return int(getattr(errno_module, name, -1)) if hasattr(errno_module, name) else None
    return None


def decode_bytes(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError):
            return None
    return None


def _normalize_bytes(value: bytes, rules: Iterable[str]) -> bytes:
    normalized = value
    for rule in rules:
        if rule == "unicode-newlines":
            normalized = normalized.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        elif rule == "trim-trailing-whitespace":
            normalized = normalized.rstrip()
        else:
            raise ValueError(f"unknown byte normalization rule {rule!r}")
    return normalized


def _normalize_permission(value: Any, rules: Iterable[str]) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value
    for rule in rules:
        if rule == "case":
            normalized = normalized.lower()
        else:
            raise ValueError(f"unknown permission normalization rule {rule!r}")
    return normalized


def compare_value(kind: str, expected: Any, actual: Any, mode: str = "exact", normalization: Iterable[str] = ()) -> Comparison:
    rules = tuple(normalization)
    if kind == "errno":
        expected_errno = errno_number(expected)
        actual_errno = errno_number(actual)
        if mode == "invariant" and isinstance(expected, dict):
            if "one_of" in expected:
                matched = actual_errno in {errno_number(item) for item in expected["one_of"]}
                return Comparison(matched, kind, mode, f"actual errno {actual!r} against allowed set")
            if expected.get("nonzero") is True:
                return Comparison(actual_errno not in (None, 0), kind, mode, f"actual errno {actual!r} must be nonzero")
        matched = expected_errno is not None and expected_errno == actual_errno
        return Comparison(matched, kind, mode, f"expected errno {expected!r}, actual {actual!r}")

    if kind == "bytes":
        actual_bytes = decode_bytes(actual)
        if actual_bytes is None:
            return Comparison(False, kind, mode, "actual byte value is not valid base64 or bytes")
        if mode == "invariant" and isinstance(expected, dict):
            if "length" in expected:
                return Comparison(len(actual_bytes) == int(expected["length"]), kind, mode, f"byte length {len(actual_bytes)}")
            if "prefix_b64" in expected:
                prefix = decode_bytes(expected["prefix_b64"])
                return Comparison(prefix is not None and actual_bytes.startswith(prefix), kind, mode, "byte prefix invariant")
        expected_bytes = decode_bytes(expected)
        if expected_bytes is None:
            return Comparison(False, kind, mode, "expected byte value is not valid base64 or bytes")
        if mode == "normalized":
            expected_bytes = _normalize_bytes(expected_bytes, rules)
            actual_bytes = _normalize_bytes(actual_bytes, rules)
        matched = expected_bytes == actual_bytes
        return Comparison(matched, kind, mode, f"expected {len(expected_bytes)} bytes, actual {len(actual_bytes)} bytes")

    if kind == "permission":
        if mode == "invariant" and isinstance(expected, dict) and "one_of" in expected:
            matched = actual in expected["one_of"]
            return Comparison(matched, kind, mode, f"permission decision {actual!r} against allowed set")
        expected_text = expected
        actual_text = actual
        if mode == "normalized":
            expected_text = _normalize_permission(expected, rules or ("case",))
            actual_text = _normalize_permission(actual, rules or ("case",))
        matched = isinstance(expected_text, str) and expected_text == actual_text
        return Comparison(matched, kind, mode, f"expected permission {expected!r}, actual {actual!r}")

    return Comparison(False, kind, mode, f"unsupported comparison kind {kind!r}")


def verify_comparison_claim(kind: str, expected: Any, actual: Any, claimed_match: bool, mode: str = "exact", normalization: Iterable[str] = ()) -> bool:
    recomputed = compare_value(kind, expected, actual, mode, normalization)
    return recomputed.matched == claimed_match

import base64
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


LINUX_ERRNO_TABLE = {
    "EPERM": 1, "ENOENT": 2, "ESRCH": 3, "EINTR": 4, "EIO": 5,
    "ENXIO": 6, "E2BIG": 7, "ENOEXEC": 8, "EBADF": 9, "ECHILD": 10,
    "EAGAIN": 11, "ENOMEM": 12, "EACCES": 13, "EFAULT": 14, "ENOTBLK": 15,
    "EBUSY": 16, "EEXIST": 17, "EXDEV": 18, "ENODEV": 19, "ENOTDIR": 20,
    "EISDIR": 21, "EINVAL": 22, "ENFILE": 23, "EMFILE": 24, "ENOTTY": 25,
    "ETXTBSY": 26, "EFBIG": 27, "ENOSPC": 28, "ESPIPE": 29, "EROFS": 30,
    "EMLINK": 31, "EPIPE": 32, "EDOM": 33, "ERANGE": 34, "EDEADLK": 35,
    "ENAMETOOLONG": 36, "ENOLCK": 37, "ENOSYS": 38, "ENOTEMPTY": 39, "ELOOP": 40,
    "ENOMSG": 42, "EIDRM": 43, "ECHRNG": 44, "EL2NSYNC": 45, "EL3HLT": 46,
    "EL3RST": 47, "ELNRNG": 48, "EUNATCH": 49, "ENOCSI": 50, "EL2HLT": 51,
    "EBADE": 52, "EBADR": 53, "EXFULL": 54, "ENOANO": 55, "EBADRQC": 56,
    "EBADSLT": 57, "EBFONT": 59, "ENOSTR": 60, "ENODATA": 61, "ETIME": 62,
    "ENOSR": 63, "ENONET": 64, "ENOPKG": 65, "EREMOTE": 66, "ENOLINK": 67,
    "EADV": 68, "ESRMNT": 69, "ECOMM": 70, "EPROTO": 71, "EMULTIHOP": 72,
    "EDOTDOT": 73, "EBADMSG": 74, "EOVERFLOW": 75, "ENOTUNIQ": 76, "EBADFD": 77,
    "EREMCHG": 78, "ELIBACC": 79, "ELIBBAD": 80, "ELIBSCN": 81, "ELIBMAX": 82,
    "ELIBEXEC": 83, "EILSEQ": 84, "ERESTART": 85, "ESTRPIPE": 86, "EUSERS": 87,
    "ENOTSOCK": 88, "EDESTADDRREQ": 89, "EMSGSIZE": 90, "EPROTOTYPE": 91,
    "ENOPROTOOPT": 92, "EPROTONOSUPPORT": 93, "ESOCKTNOSUPPORT": 94, "EOPNOTSUPP": 95,
    "EPFNOSUPPORT": 96, "EAFNOSUPPORT": 97, "EADDRINUSE": 98, "EADDRNOTAVAIL": 99,
    "ENETDOWN": 100, "ENETUNREACH": 101, "ENETRESET": 102, "ECONNABORTED": 103,
    "ECONNRESET": 104, "ENOBUFS": 105, "EISCONN": 106, "ENOTCONN": 107,
    "ESHUTDOWN": 108, "ETOOMANYREFS": 109, "ETIMEDOUT": 110, "ECONNREFUSED": 111,
    "EHOSTDOWN": 112, "EHOSTUNREACH": 113, "EALREADY": 114, "EINPROGRESS": 115,
    "ESTALE": 116, "EUCLEAN": 117, "ENOTNAM": 118, "ENAVAIL": 119, "EISNAM": 120,
    "EREMOTEIO": 121, "EDQUOT": 122, "ENOMEDIUM": 123, "EMEDIUMTYPE": 124,
    "ECANCELED": 125, "ENOKEY": 126, "EKEYEXPIRED": 127, "EKEYREVOKED": 128,
    "EKEYREJECTED": 129, "EOWNERDEAD": 130, "ENOTRECOVERABLE": 131, "ERFKILL": 132,
    "EHWPOISON": 133,
    "EWOULDBLOCK": 11, "ENOTSUP": 95, "EDEADLOCK": 35,
}


@dataclass(frozen=True)
class Comparison:
    matched: bool
    kind: str
    mode: str
    detail: str


def errno_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return LINUX_ERRNO_TABLE.get(value.upper())
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
                choices = expected["one_of"]
                if not isinstance(choices, (list, tuple)):
                    return Comparison(False, kind, mode, "errno one_of invariant is not a list")
                allowed = {errno_number(item) for item in choices}
                matched = actual_errno is not None and actual_errno in allowed
                return Comparison(matched, kind, mode, f"actual errno {actual!r} against allowed set")
            if expected.get("nonzero") is True:
                return Comparison(actual_errno is not None and actual_errno != 0, kind, mode, f"actual errno {actual!r} must be nonzero")
        matched = expected_errno is not None and actual_errno is not None and expected_errno == actual_errno
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
            choices = expected["one_of"]
            if not isinstance(choices, (list, tuple)):
                return Comparison(False, kind, mode, "permission one_of invariant is not a list")
            matched = isinstance(actual, str) and actual in choices
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

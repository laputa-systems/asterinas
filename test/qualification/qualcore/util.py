import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_canonical(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant {value}")


def read_json_file(path: Path) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as error:
        raise ValueError(f"{path}: invalid JSON at line {error.lineno}: {error.msg}") from error
    except ValueError as error:
        raise ValueError(f"{path}: invalid JSON: {error}") from error

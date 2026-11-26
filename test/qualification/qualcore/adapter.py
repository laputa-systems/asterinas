import struct
from pathlib import Path


WRITE_LOG_MAGIC = 0x6A736677736872
WRITE_LOG_VERSION = 1
LOG_FLUSH_FLAG = 1 << 0
LOG_DISCARD_FLAG = 1 << 2


def validate_blklogwrites(path: Path) -> list[str]:
    if not path.is_file():
        return [f"blklogwrites log is missing: {path}"]
    data = path.read_bytes()
    if len(data) < 512:
        return [f"blklogwrites log is truncated: {len(data)} bytes"]
    magic, version, entries, sector_size = struct.unpack_from("<QQQI", data, 0)
    failures: list[str] = []
    if magic != WRITE_LOG_MAGIC:
        failures.append(f"blklogwrites magic mismatch: {magic:#x}")
    if version != WRITE_LOG_VERSION:
        failures.append(f"blklogwrites version mismatch: {version}")
    if sector_size < 512 or sector_size & (sector_size - 1):
        failures.append(f"blklogwrites sector size is invalid: {sector_size}")
    if entries == 0:
        failures.append("blklogwrites log records no writes")
    if failures:
        return failures

    data_writes = 0
    parsed = 0
    offset = sector_size
    while parsed < entries and offset + 32 <= len(data):
        _sector, sectors, flags, _data_length = struct.unpack_from("<QQQQ", data, offset)
        if not (flags & (LOG_DISCARD_FLAG | LOG_FLUSH_FLAG)) and sectors:
            data_writes += 1
        offset += sector_size
        if not (flags & LOG_DISCARD_FLAG):
            offset += sectors * sector_size
        parsed += 1
    if parsed != entries:
        failures.append(f"blklogwrites log ended after {parsed} of {entries} entries")
    if data_writes == 0:
        failures.append("blklogwrites log records no data writes")
    return failures

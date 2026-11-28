import struct
from pathlib import Path


WRITE_LOG_MAGIC = 0x6A736677736872
WRITE_LOG_VERSION = 1
LOG_FLUSH_FLAG = 1 << 0
LOG_FUA_FLAG = 1 << 1
LOG_DISCARD_FLAG = 1 << 2
LOG_MARK_FLAG = 1 << 3
LOG_FLAG_MASK = LOG_FLUSH_FLAG | LOG_FUA_FLAG | LOG_DISCARD_FLAG | LOG_MARK_FLAG

WRITE_LOG_SUPER_SIZE = struct.calcsize("<QQQI")
WRITE_LOG_ENTRY_SIZE = struct.calcsize("<QQQQ")
MAX_LOG_BYTES = 256 * 1024 * 1024
MAX_SECTOR_SIZE = 1 << 20
MAX_SECTOR_INDEX = 1 << 40
MAX_RECORD_SECTORS = 1 << 32
WRITE_LOG_SECTOR_SIZE = 512


def initialize_blklogwrites(path: Path) -> None:
    header = struct.pack("<QQQI", WRITE_LOG_MAGIC, WRITE_LOG_VERSION, 0, WRITE_LOG_SECTOR_SIZE)
    with path.open("xb") as log:
        log.write(header.ljust(WRITE_LOG_SECTOR_SIZE, b"\0"))


def validate_blklogwrites(path: Path, *, expect_writes: bool | None = True) -> list[str]:
    if not path.is_file():
        return [f"blklogwrites log is missing: {path}"]
    size = path.stat().st_size
    if size < 512:
        return [f"blklogwrites log is truncated: {size} bytes"]
    if size > MAX_LOG_BYTES:
        return [f"blklogwrites log exceeds the parsing bound: {size} bytes"]

    failures: list[str] = []
    with path.open("rb") as log:
        superblock = log.read(WRITE_LOG_SUPER_SIZE)
        if len(superblock) != WRITE_LOG_SUPER_SIZE:
            return [f"blklogwrites superblock is truncated: {len(superblock)} bytes"]
        magic, version, entries, sector_size = struct.unpack("<QQQI", superblock)
        if magic != WRITE_LOG_MAGIC:
            failures.append(f"blklogwrites magic mismatch: {magic:#x}")
        if version != WRITE_LOG_VERSION:
            failures.append(f"blklogwrites version mismatch: {version}")
        if sector_size < 512 or sector_size > MAX_SECTOR_SIZE or sector_size & (sector_size - 1):
            failures.append(f"blklogwrites sector size is invalid: {sector_size}")
        if failures:
            return failures
        if size < sector_size:
            return [f"blklogwrites superblock sector is truncated: {size} bytes"]

        max_entries = (size - sector_size) // sector_size
        if entries > max_entries:
            return [
                f"blklogwrites entry count {entries} exceeds {max_entries} possible in {size} bytes"
            ]

        data_writes = 0
        discards = 0
        offset = sector_size
        for index in range(entries):
            if offset + WRITE_LOG_ENTRY_SIZE > size:
                failures.append(f"blklogwrites record {index} header fields are truncated")
                break
            log.seek(offset)
            fields = log.read(WRITE_LOG_ENTRY_SIZE)
            sector, nr_sectors, flags, data_len = struct.unpack("<QQQQ", fields)
            if offset + sector_size > size:
                failures.append(f"blklogwrites record {index} header sector is truncated")
                break
            if flags & ~LOG_FLAG_MASK:
                failures.append(f"blklogwrites record {index} has unsupported flags: {flags:#x}")
                break
            if flags & LOG_MARK_FLAG:
                failures.append(f"blklogwrites record {index} contains an unsupported mark")
                break
            if flags & LOG_FLUSH_FLAG and (flags != LOG_FLUSH_FLAG or nr_sectors != 0):
                failures.append(f"blklogwrites record {index} has an invalid flush")
                break
            if data_len != 0:
                failures.append(f"blklogwrites record {index} has unsupported data length: {data_len}")
                break
            if sector > MAX_SECTOR_INDEX or nr_sectors > MAX_RECORD_SECTORS:
                failures.append(
                    f"blklogwrites record {index} has impossible geometry: sector {sector} nr_sectors {nr_sectors}"
                )
                break
            discard = bool(flags & LOG_DISCARD_FLAG)
            if discard:
                if nr_sectors == 0:
                    failures.append(f"blklogwrites record {index} discard has zero sectors")
                    break
                discards += 1
                offset += sector_size
            else:
                control_only = flags == LOG_FLUSH_FLAG
                if not control_only:
                    if nr_sectors == 0:
                        failures.append(f"blklogwrites record {index} data write has zero sectors")
                        break
                    payload = nr_sectors * sector_size
                    if offset + sector_size + payload > size:
                        failures.append(f"blklogwrites record {index} payload is truncated")
                        break
                    data_writes += 1
                    offset += sector_size + payload
                else:
                    offset += sector_size

    if failures:
        return failures
    if offset != size:
        return [f"blklogwrites has {size - offset} bytes after its declared records"]
    if expect_writes is True and data_writes == 0:
        failures.append("blklogwrites log records no data writes")
    elif expect_writes is False and (data_writes or discards):
        failures.append("read-only blklogwrites log records unexpected writes or discards")
    return failures

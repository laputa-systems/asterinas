# SPDX-License-Identifier: MPL-2.0
"""Crash-cut persistence model over bounded ``blklogwrites`` logs.

A write becomes durable only when a flush record follows it. Every flush
record therefore defines an admissible crash cut: a prefix of the log in
which all preceding data writes are durable and later writes are volatile.
The model is deliberately independent of any particular filesystem so that
the same cut enumeration can validate both kernels and the omitted-sync
control.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from .adapter import (
    LOG_DISCARD_FLAG,
    LOG_FLAG_MASK,
    LOG_FLUSH_FLAG,
    LOG_MARK_FLAG,
    MAX_LOG_BYTES,
    MAX_RECORD_SECTORS,
    MAX_SECTOR_INDEX,
    MAX_SECTOR_SIZE,
    WRITE_LOG_ENTRY_SIZE,
    WRITE_LOG_MAGIC,
    WRITE_LOG_SUPER_SIZE,
    WRITE_LOG_VERSION,
    validate_blklogwrites,
)


@dataclass(frozen=True)
class LogRecord:
    index: int
    sector: int
    nr_sectors: int
    flags: int


def parse_records(path: Path) -> list[LogRecord]:
    """Parses a validated log into bounded records."""
    failures = validate_blklogwrites(path)
    if failures:
        raise ValueError("; ".join(failures))
    size = path.stat().st_size
    with path.open("rb") as log:
        magic, version, entries, sector_size = struct.unpack(
            "<QQQI", log.read(WRITE_LOG_SUPER_SIZE)
        )
        if (
            magic != WRITE_LOG_MAGIC
            or version != WRITE_LOG_VERSION
            or sector_size < 512
            or sector_size > MAX_SECTOR_SIZE
            or sector_size & (sector_size - 1)
            or size > MAX_LOG_BYTES
        ):
            raise ValueError("invalid blklogwrites superblock")
        offset = sector_size
        records: list[LogRecord] = []
        for index in range(entries):
            if offset + WRITE_LOG_ENTRY_SIZE > size:
                raise ValueError("truncated blklogwrites record")
            log.seek(offset)
            sector, nr_sectors, flags, data_len = struct.unpack(
                "<QQQQ", log.read(WRITE_LOG_ENTRY_SIZE)
            )
            if flags & ~LOG_FLAG_MASK or data_len != 0:
                raise ValueError("unsupported blklogwrites record")
            if sector > MAX_SECTOR_INDEX or nr_sectors > MAX_RECORD_SECTORS:
                raise ValueError("impossible blklogwrites geometry")
            records.append(LogRecord(index, sector, nr_sectors, flags))
            if flags & LOG_DISCARD_FLAG or (
                flags & (LOG_FLUSH_FLAG | LOG_MARK_FLAG) and nr_sectors == 0
            ):
                offset += sector_size
            else:
                if nr_sectors == 0:
                    raise ValueError("data write with zero sectors")
                offset += sector_size + nr_sectors * sector_size
        return records


def is_flush(record: LogRecord) -> bool:
    return (
        bool(record.flags & LOG_FLUSH_FLAG)
        and not record.flags & LOG_MARK_FLAG
        and record.nr_sectors == 0
    )


def is_data_write(record: LogRecord) -> bool:
    return (
        not record.flags & LOG_DISCARD_FLAG
        and not is_flush(record)
        and record.nr_sectors > 0
    )


def enumerate_crash_cuts(records: list[LogRecord]) -> list[int]:
    """Returns admissible cut points: before any write and after each flush."""
    cuts = [0]
    for record in records:
        if is_flush(record):
            cuts.append(record.index + 1)
    return cuts


def durable_writes(records: list[LogRecord], cut: int) -> list[LogRecord]:
    """Returns the data writes that survived a crash at `cut`."""
    return [record for record in records[:cut] if is_data_write(record)]


def omitted_sync_detected(records: list[LogRecord]) -> bool:
    """True when a data write has no later flush and is volatile at every cut."""
    last_flush = max(
        (record.index for record in records if is_flush(record)), default=-1
    )
    return any(
        is_data_write(record) and record.index > last_flush for record in records
    )


def durable_sectors(records: list[LogRecord], cut: int) -> set[int]:
    """Returns the sectors whose data writes survived a crash at `cut`."""
    return {record.sector for record in durable_writes(records, cut)}


def missing_durable_sectors(
    synced: list[LogRecord], omitted: list[LogRecord]
) -> set[int]:
    """Returns sectors durable in the synced run but not in the omitted run."""
    synced_cuts = enumerate_crash_cuts(synced)
    omitted_cuts = enumerate_crash_cuts(omitted)
    synced_durable = durable_sectors(synced, synced_cuts[-1])
    omitted_durable = durable_sectors(omitted, omitted_cuts[-1])
    return synced_durable - omitted_durable

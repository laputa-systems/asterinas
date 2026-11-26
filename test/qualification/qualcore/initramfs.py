import stat
from dataclasses import dataclass
from pathlib import Path

from .util import atomic_write_bytes


@dataclass(frozen=True)
class CpioEntry:
    name: str
    mode: int
    data: bytes = b""
    device: tuple[int, int] | None = None


def _pad4(data: bytes) -> bytes:
    remainder = len(data) % 4
    if remainder == 0:
        return data
    return data + b"\0" * (4 - remainder)


def _entry_bytes(entry: CpioEntry, inode: int) -> bytes:
    encoded_name = entry.name.encode("ascii") + b"\0"
    device = entry.device or (0, 0)
    fields = (
        "070701",
        f"{inode:08x}",
        f"{entry.mode:08x}",
        f"{0:08x}",
        f"{0:08x}",
        f"{1:08x}",
        f"{0:08x}",
        f"{len(entry.data):08x}",
        f"{0:08x}",
        f"{0:08x}",
        f"{device[0]:08x}",
        f"{device[1]:08x}",
        f"{len(encoded_name):08x}",
        f"{0:08x}",
    )
    header = "".join(fields).encode("ascii")
    if len(header) != 110:
        raise ValueError("newc header length invariant failed")
    return _pad4(header + encoded_name) + _pad4(entry.data)


def newc_archive(entries: list[CpioEntry]) -> bytes:
    ordered = sorted(entries, key=lambda entry: entry.name)
    names = [entry.name for entry in ordered]
    if len(names) != len(set(names)):
        raise ValueError("duplicate initramfs entry")
    output = bytearray()
    inode = 1
    for entry in ordered:
        output.extend(_entry_bytes(entry, inode))
        inode += 1
    output.extend(_entry_bytes(CpioEntry("TRAILER!!!", 0), 0))
    while len(output) % 512:
        output.extend(b"\0")
    return bytes(output)


def selfcheck_archive(probe: bytes, payload: bytes) -> bytes:
    return newc_archive(
        [
            CpioEntry("dev", stat.S_IFDIR | 0o755),
            CpioEntry("dev/console", stat.S_IFCHR | 0o600, device=(5, 1)),
            CpioEntry("dev/null", stat.S_IFCHR | 0o666, device=(1, 3)),
            CpioEntry("dev/ttyS0", stat.S_IFCHR | 0o600, device=(4, 64)),
            CpioEntry("dev/ttyS1", stat.S_IFCHR | 0o600, device=(4, 65)),
            CpioEntry("init", stat.S_IFREG | 0o755, probe),
            CpioEntry("proc", stat.S_IFDIR | 0o755),
            CpioEntry("qual", stat.S_IFDIR | 0o755),
            CpioEntry("qual/input.txt", stat.S_IFREG | 0o444, payload),
        ]
    )


def write_selfcheck_initramfs(probe_path: Path, payload_path: Path, output_path: Path) -> None:
    archive = selfcheck_archive(probe_path.read_bytes(), payload_path.read_bytes())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(output_path, archive)

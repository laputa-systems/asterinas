import fcntl
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .supervisor import SupervisedResult, Supervisor


QEMU_ACCEL_ARGS = ("-accel", "tcg", "-machine", "q35", "-cpu", "max", "-smp", "2", "-m", "1024", "-no-reboot")
BASE_CMDLINE = "console=ttyS0 panic=-1"


class QemuError(Exception):
    pass


@dataclass(frozen=True)
class QemuExecution:
    label: str
    command: tuple[str, ...]
    result: SupervisedResult
    qual_log: Path
    console_log: Path
    duration_seconds: float


def qemu_version(qemu_path: Path) -> str:
    try:
        completed = subprocess.run([str(qemu_path), "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QemuError(f"qemu version probe failed: {error}") from error
    if completed.returncode != 0:
        raise QemuError(f"qemu version probe exited {completed.returncode}: {completed.stderr.strip()}")
    first = completed.stdout.splitlines()[0] if completed.stdout.splitlines() else ""
    match = re.search(r"version\s+([0-9]+(?:\.[0-9]+)+)", first)
    if not match:
        raise QemuError(f"qemu version output is unrecognized: {first!r}")
    return match.group(1)


def resolve_qemu_path(path: Path) -> Path:
    return Path(os.path.realpath(path))


def qemu_command(
    qemu_path: Path,
    kernel: Path,
    initramfs: Path,
    qual_log: Path,
    run_id: str,
    nonce: str,
    manifest_hash: str,
    payload_hash: str,
    control: str = "none",
) -> tuple[str, ...]:
    cmdline = (
        f"{BASE_CMDLINE} qual.run_id={run_id} qual.nonce={nonce} "
        f"qual.manifest_hash={manifest_hash} qual.payload_hash={payload_hash} qual.control={control}"
    )
    return tuple(
        str(item)
        for item in (
            qemu_path,
            *QEMU_ACCEL_ARGS,
            "-display",
            "none",
            "-monitor",
            "none",
            "-nic",
            "none",
            "-serial",
            "stdio",
            "-serial",
            f"file:{qual_log}",
            "-kernel",
            kernel,
            "-initrd",
            initramfs,
            "-append",
            cmdline,
        )
    )


class VmExclusion:
    def __init__(self, lock_path: Path) -> None:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = lock_path
        self.handle = None

    def __enter__(self) -> "VmExclusion":
        self.handle = open(self.lock_path, "a+b")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
        except BaseException:
            self.handle.close()
            self.handle = None
            raise
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"pid={os.getpid()} acquired_at={time.time()}\n".encode("ascii"))
        self.handle.flush()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is not None:
            try:
                self.handle.seek(0)
                self.handle.truncate()
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
                self.handle = None


def run_qemu(
    qemu_path: Path,
    kernel: Path,
    initramfs: Path,
    work_dir: Path,
    label: str,
    run_id: str,
    nonce: str,
    manifest_hash: str,
    payload_hash: str,
    deadline: float,
    output_budget: int,
    control: str = "none",
    silence_timeout: float | None = None,
) -> QemuExecution:
    vm_dir = work_dir / label
    vm_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    qual_log = vm_dir / "qual.log"
    console_log = vm_dir / "console.log"
    command = qemu_command(qemu_path, kernel, initramfs, qual_log, run_id, nonce, manifest_hash, payload_hash, control)
    started = time.monotonic()
    result = Supervisor().run(
        list(command),
        timeout=deadline,
        output_budget=output_budget,
        log_path=console_log,
        silence_timeout=silence_timeout,
    )
    return QemuExecution(
        label=label,
        command=command,
        result=result,
        qual_log=qual_log,
        console_log=console_log,
        duration_seconds=time.monotonic() - started,
    )

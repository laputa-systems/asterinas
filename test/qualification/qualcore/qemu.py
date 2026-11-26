import fcntl
import os
import re
import shutil
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
class AdapterDisk:
    image: Path
    write_log: Path
    blkdebug_config: Path
    serial: str


@dataclass(frozen=True)
class QemuExecution:
    label: str
    command: tuple[str, ...]
    result: SupervisedResult
    qual_log: Path
    console_log: Path
    duration_seconds: float
    adapter_disk: AdapterDisk | None = None


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
    case_id: str = "core.selfcheck",
    adapter_disk: AdapterDisk | None = None,
    isolated_network: bool = False,
) -> tuple[str, ...]:
    cmdline = (
        f"{BASE_CMDLINE} qual.run_id={run_id} qual.nonce={nonce} "
        f"qual.manifest_hash={manifest_hash} qual.payload_hash={payload_hash} "
        f"qual.control={control} qual.case_id={case_id}"
    )
    network_args: tuple[str, ...]
    if isolated_network:
        network_args = (
            "-netdev",
            "hubport,id=net0,hubid=0",
            "-device",
            "virtio-net-pci,netdev=net0,mac=52:54:00:6c:06:01",
        )
    else:
        network_args = ("-nic", "none")
    disk_args: tuple[str, ...] = ()
    if adapter_disk is not None:
        image = adapter_disk.image.resolve()
        write_log = adapter_disk.write_log.resolve()
        config = adapter_disk.blkdebug_config.resolve()
        disk_args = (
            "-blockdev",
            f"node-name=adapter-file,driver=file,filename={image},cache.direct=off,cache.no-flush=off",
            "-blockdev",
            "node-name=adapter-raw,driver=raw,file=adapter-file",
            "-blockdev",
            f"node-name=adapter-log-file,driver=file,filename={write_log},cache.direct=off,cache.no-flush=off",
            "-blockdev",
            "node-name=adapter-logged,driver=blklogwrites,file=adapter-raw,log=adapter-log-file,log-sector-size=512",
            "-blockdev",
            f"node-name=adapter-disk,driver=blkdebug,image=adapter-logged,config={config}",
            "-device",
            f"virtio-blk-pci,drive=adapter-disk,serial={adapter_disk.serial},write-cache=on",
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
            *network_args,
            "-serial",
            "stdio",
            "-serial",
            f"file:{qual_log}",
            *disk_args,
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
    case_id: str = "core.selfcheck",
    adapter_image: Path | None = None,
    adapter_serial: str = "qual-lc06-adapter",
    isolated_network: bool = False,
    inject_read_errors: bool = False,
) -> QemuExecution:
    vm_dir = work_dir / label
    vm_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    qual_log = vm_dir / "qual.log"
    console_log = vm_dir / "console.log"
    adapter_disk = None
    if adapter_image is not None:
        disk_image = vm_dir / "adapter-disk.img"
        shutil.copyfile(adapter_image, disk_image)
        write_log = vm_dir / "blklogwrites.log"
        write_log.touch(mode=0o600)
        blkdebug_config = vm_dir / "blkdebug.conf"
        if inject_read_errors:
            blkdebug_config.write_text('[inject-error]\nevent = "none"\niotype = "read"\nerrno = "5"\n', encoding="utf-8")
        else:
            blkdebug_config.write_text("", encoding="utf-8")
        adapter_disk = AdapterDisk(disk_image, write_log, blkdebug_config, adapter_serial)
    command = qemu_command(
        qemu_path,
        kernel,
        initramfs,
        qual_log,
        run_id,
        nonce,
        manifest_hash,
        payload_hash,
        control,
        case_id,
        adapter_disk,
        isolated_network,
    )
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
        adapter_disk=adapter_disk,
    )

import subprocess
from dataclasses import dataclass


class ProcessTreeError(Exception):
    pass


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    state: str

    @property
    def zombie(self) -> bool:
        return self.state.startswith("Z")


def snapshot_processes() -> dict[int, ProcessInfo]:
    command = ["ps", "-eo", "pid=", "-o", "ppid=", "-o", "stat="]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProcessTreeError(f"process snapshot failed: {error}") from error
    if completed.returncode != 0:
        raise ProcessTreeError(f"process snapshot exited {completed.returncode}: {completed.stderr.strip()}")
    processes: dict[int, ProcessInfo] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise ProcessTreeError(f"process snapshot line is malformed: {line!r}")
        try:
            pid, ppid = (int(fields[0]), int(fields[1]))
        except ValueError as error:
            raise ProcessTreeError(f"process snapshot line has non-numeric IDs: {line!r}") from error
        processes[pid] = ProcessInfo(pid, ppid, fields[2])
    return processes


class ProcessTreeTracker:
    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self.tracked_pids = {root_pid}
        self.snapshot: dict[int, ProcessInfo] = {}

    def update(self) -> dict[int, ProcessInfo]:
        snapshot = snapshot_processes()
        changed = True
        while changed:
            changed = False
            for pid, info in snapshot.items():
                if pid not in self.tracked_pids and info.ppid in self.tracked_pids:
                    self.tracked_pids.add(pid)
                    changed = True
        self.snapshot = snapshot
        return snapshot

    def survivors(self) -> list[int]:
        snapshot = self.update()
        return sorted(
            pid
            for pid in self.tracked_pids
            if pid != self.root_pid and pid in snapshot and not snapshot[pid].zombie
        )

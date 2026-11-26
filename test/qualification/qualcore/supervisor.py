import errno
import os
import select
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .proctree import ProcessTreeError, ProcessTreeTracker, terminate_processes


OutputHook = Callable[[str, bytes], str | None]
CleanupHook = Callable[[], None]
LogOpener = Callable[[], BinaryIO]
PipeCallback = Callable[[str, bytes, bytes], None]


@dataclass
class SupervisedResult:
    argv: tuple[str, ...]
    exit_code: int | None
    outcome: str
    stdout: bytes
    stderr: bytes
    stdout_bytes: int
    stderr_bytes: int
    output_truncated: bool
    orphaned: bool
    duration_seconds: float
    cleanup_errors: list[str] = field(default_factory=list)
    log_errors: list[OSError] = field(default_factory=list)
    hook_errors: list[str] = field(default_factory=list)
    reader_errors: list[str] = field(default_factory=list)
    tree_errors: list[str] = field(default_factory=list)
    orphan_pids: list[int] = field(default_factory=list)


class _LogSink:
    def __init__(self, writer: BinaryIO | None) -> None:
        self.writer = writer
        self.lock = threading.Lock()
        self.errors: list[OSError] = []
        self.write_failed = False

    def record_error(self, error: OSError) -> None:
        if len(self.errors) < 4:
            self.errors.append(error)

    def write(self, data: bytes) -> None:
        if self.writer is None or self.write_failed or not data:
            return
        try:
            with self.lock:
                self.writer.write(data)
        except OSError as error:
            self.write_failed = True
            self.record_error(error)

    def close(self) -> None:
        if self.writer is None:
            return
        try:
            self.writer.flush()
        except OSError as error:
            self.record_error(error)
        try:
            self.writer.close()
        except OSError as error:
            self.record_error(error)


class _PipeReader(threading.Thread):
    def __init__(self, name: str, pipe: BinaryIO, budget: int, callback: PipeCallback, stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.stream_name = name
        self.pipe = pipe
        self.budget = budget
        self.callback = callback
        self.stop_event = stop_event
        self.chunks: list[bytes] = []
        self.total_bytes = 0
        self.captured_bytes = 0
        self.truncated = False
        self.error: str | None = None

    def run(self) -> None:
        descriptor = self.pipe.fileno()
        try:
            while not self.stop_event.is_set():
                readable, _, _ = select.select([descriptor], [], [], 0.05)
                if not readable:
                    continue
                chunk = os.read(descriptor, 1024)
                if not chunk:
                    return
                self.total_bytes += len(chunk)
                remaining = self.budget - self.captured_bytes
                retained = chunk[:max(0, remaining)]
                if retained:
                    self.chunks.append(retained)
                    self.captured_bytes += len(retained)
                if len(chunk) > len(retained):
                    self.truncated = True
                self.callback(self.stream_name, chunk, retained)
        except Exception as error:
            self.error = f"{type(error).__name__}: {error}"

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_group(process: subprocess.Popen, pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        return


def _stop_group(process: subprocess.Popen, pgid: int) -> None:
    if process.poll() is None:
        _signal_group(process, pgid, signal.SIGTERM)
        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.01)
    if process.poll() is None or _group_exists(pgid):
        _signal_group(process, pgid, signal.SIGKILL)


class Supervisor:
    def __init__(self) -> None:
        if not hasattr(os, "killpg") or not hasattr(signal, "SIGKILL"):
            raise RuntimeError("Supervisor requires POSIX process groups")

    def run(
        self,
        argv: list[str] | tuple[str, ...],
        timeout: float,
        output_budget: int = 65536,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        panic_markers: tuple[bytes, ...] = (b"kernel panic", b"panic:"),
        event_hook: OutputHook | None = None,
        cleanup: CleanupHook | None = None,
        log_path: str | Path | None = None,
        log_opener: LogOpener | None = None,
        silence_timeout: float | None = None,
        process_tree_interval: float = 0.05,
    ) -> SupervisedResult:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if output_budget <= 0:
            raise ValueError("output_budget must be positive")
        if silence_timeout is not None and silence_timeout <= 0:
            raise ValueError("silence_timeout must be positive")
        if process_tree_interval <= 0:
            raise ValueError("process_tree_interval must be positive")
        started = time.monotonic()
        command = tuple(str(item) for item in argv)
        writer = None
        open_errors: list[OSError] = []
        if log_opener is not None:
            try:
                writer = log_opener()
            except OSError as error:
                open_errors.append(error)
        elif log_path is not None:
            try:
                writer = open(log_path, "wb")
            except OSError as error:
                open_errors.append(error)
        sink = _LogSink(writer)
        sink.errors.extend(open_errors)

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=env,
                start_new_session=True,
            )
        except OSError as error:
            if cleanup is not None:
                cleanup_errors = []
                try:
                    cleanup()
                except Exception as cleanup_error:
                    cleanup_errors.append(str(cleanup_error))
            else:
                cleanup_errors = []
            sink.close()
            return SupervisedResult(
                command,
                None,
                "spawn-error",
                b"",
                str(error).encode(),
                0,
                0,
                False,
                False,
                time.monotonic() - started,
                cleanup_errors,
                sink.errors,
            )

        pgid = os.getpgid(process.pid)
        tracker = ProcessTreeTracker(process.pid)
        tree_errors: list[str] = []
        orphan_pids: list[int] = []
        stop_reason: list[str] = []
        hook_errors: list[str] = []
        last_output = time.monotonic()
        scan_tails = {"stdout": b"", "stderr": b""}

        def observe(stream: str, chunk: bytes, retained: bytes) -> None:
            nonlocal last_output
            last_output = time.monotonic()
            sink.write(retained)
            scan = scan_tails[stream] + chunk
            lowered = scan.lower()
            if any(marker.lower() in lowered for marker in panic_markers):
                if not stop_reason:
                    stop_reason.append("panic")
            scan_tails[stream] = scan[-256:]
            if event_hook is not None:
                try:
                    event = event_hook(stream, chunk)
                except Exception as error:
                    if len(hook_errors) < 4:
                        hook_errors.append(f"{type(error).__name__}: {error}")
                    if not stop_reason:
                        stop_reason.append("harness-error")
                else:
                    if event in {"panic", "hang"} and not stop_reason:
                        stop_reason.append(event)

        stdout_pipe = process.stdout
        stderr_pipe = process.stderr
        if stdout_pipe is None or stderr_pipe is None:
            _stop_group(process, pgid)
            process.wait()
            sink.close()
            raise RuntimeError("supervised process pipes were not created")
        stop_readers = threading.Event()
        readers = [
            _PipeReader("stdout", stdout_pipe, output_budget, observe, stop_readers),
            _PipeReader("stderr", stderr_pipe, output_budget, observe, stop_readers),
        ]
        for reader in readers:
            reader.start()

        def update_tree() -> None:
            try:
                tracker.update()
            except ProcessTreeError as error:
                if len(tree_errors) < 4:
                    tree_errors.append(str(error))
                if not stop_reason:
                    stop_reason.append("harness-error")

        def terminate_tracked_survivors() -> None:
            nonlocal orphan_pids
            try:
                survivors = tracker.survivors()
            except ProcessTreeError as error:
                if len(tree_errors) < 4:
                    tree_errors.append(str(error))
                return
            orphan_pids = survivors
            if not survivors:
                return
            try:
                remaining = terminate_processes(survivors)
            except ProcessTreeError as error:
                if len(tree_errors) < 4:
                    tree_errors.append(str(error))
                return
            if remaining and len(tree_errors) < 4:
                tree_errors.append(f"surviving descendant processes could not be killed: {remaining}")

        outcome = "exit"
        orphaned = False
        reader_errors: list[str] = []
        try:
            update_tree()
            last_tree_update = time.monotonic()
            while True:
                if stop_reason:
                    outcome = stop_reason[0]
                    _stop_group(process, pgid)
                    break
                if time.monotonic() - started >= timeout:
                    outcome = "timeout"
                    _stop_group(process, pgid)
                    break
                if silence_timeout is not None and time.monotonic() - last_output >= silence_timeout and process.poll() is None:
                    outcome = "hang"
                    if not stop_reason:
                        stop_reason.append("hang")
                    _stop_group(process, pgid)
                    break
                if process.poll() is not None:
                    break
                if time.monotonic() - last_tree_update >= process_tree_interval:
                    update_tree()
                    last_tree_update = time.monotonic()
                time.sleep(0.01)

            deadline = time.monotonic() + 2.0
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if process.poll() is None:
                _stop_group(process, pgid)
            process.wait()

            group_orphaned = outcome == "exit" and _group_exists(pgid)
            if group_orphaned:
                _signal_group(process, pgid, signal.SIGKILL)
                deadline = time.monotonic() + 1.0
                while _group_exists(pgid) and time.monotonic() < deadline:
                    time.sleep(0.01)

            terminate_tracked_survivors()
            orphaned = group_orphaned or bool(orphan_pids)

            for reader in readers:
                reader.join(timeout=1.0)
            if any(reader.is_alive() for reader in readers):
                _signal_group(process, pgid, signal.SIGKILL)
                stop_readers.set()
                for reader in readers:
                    reader.join(timeout=1.0)
            reader_errors = [f"{reader.stream_name}: {reader.error}" for reader in readers if reader.error is not None]
            if outcome == "exit" and stop_reason:
                outcome = stop_reason[0]
            if outcome == "exit" and (reader_errors or tree_errors):
                outcome = "harness-error"
        except BaseException as primary_error:
            _stop_group(process, pgid)
            process.wait()
            try:
                terminate_tracked_survivors()
            except Exception as tree_error:
                primary_error.add_note(f"descendant cleanup failed: {tree_error}")
            raise
        finally:
            stop_readers.set()
            for reader in readers:
                reader.join(timeout=0.2)
            cleanup_errors: list[str] = []
            for pipe in (process.stdout, process.stderr):
                if pipe is None:
                    continue
                try:
                    pipe.close()
                except OSError as error:
                    cleanup_errors.append(f"pipe close failed: {error}")
            if cleanup is not None:
                try:
                    cleanup()
                except Exception as error:
                    cleanup_errors.append(str(error))
            sink.close()

        stdout_reader, stderr_reader = readers
        return SupervisedResult(
            argv=command,
            exit_code=process.returncode,
            outcome=outcome,
            stdout=stdout_reader.data,
            stderr=stderr_reader.data,
            stdout_bytes=stdout_reader.total_bytes,
            stderr_bytes=stderr_reader.total_bytes,
            output_truncated=stdout_reader.truncated or stderr_reader.truncated,
            orphaned=orphaned,
            duration_seconds=time.monotonic() - started,
            cleanup_errors=cleanup_errors,
            log_errors=sink.errors,
            hook_errors=hook_errors,
            reader_errors=reader_errors,
            tree_errors=tree_errors,
            orphan_pids=orphan_pids,
        )


def is_full_disk_error(errors: list[OSError]) -> bool:
    return any(error.errno == errno.ENOSPC for error in errors)

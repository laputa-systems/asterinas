import errno
import math
import os
import select
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .proctree import ProcessTreeError, ProcessTreeTracker


OutputHook = Callable[[str, bytes], str | None]
CleanupHook = Callable[[], None]
LogOpener = Callable[[], BinaryIO]
PipeCallback = Callable[[str, bytes, bytes], None]

_PROC_NOTE_FORK = 0x40000000
_EXEC_RELEASE_BYTE = b"1"
_EXEC_WRAPPER = "\n".join(
    (
        "import os, sys",
        "release_fd = int(sys.argv[1])",
        "error_fd = int(sys.argv[2])",
        "target = sys.argv[3:]",
        "release_byte = os.read(release_fd, 1)",
        "os.close(release_fd)",
        "if release_byte != " + repr(_EXEC_RELEASE_BYTE) + ":",
        "    os._exit(126)",
        "os.set_inheritable(error_fd, False)",
        "try:",
        "    os.execvp(target[0], target)",
        "except OSError as error:",
        "    message = str(error.errno or 0).encode() + b'\\n' + str(error).encode(errors='replace')",
        "    os.write(error_fd, message)",
        "    os._exit(127)",
    )
)


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
    teardown_state: str
    teardown_backend: str
    duration_seconds: float
    cleanup_errors: list[str] = field(default_factory=list)
    log_errors: list[OSError] = field(default_factory=list)
    hook_errors: list[str] = field(default_factory=list)
    reader_errors: list[str] = field(default_factory=list)
    tree_errors: list[str] = field(default_factory=list)
    teardown_details: list[str] = field(default_factory=list)
    observed_descendant_pids: list[int] = field(default_factory=list)


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


def _signal_group(pgid: int, sig: int) -> bool:
    try:
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _stop_group(process: subprocess.Popen, pgid: int) -> None:
    if process.poll() is None:
        _signal_group(pgid, signal.SIGTERM)
        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.01)
    if process.poll() is None or _group_exists(pgid):
        _signal_group(pgid, signal.SIGKILL)


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _proc_fork_backend() -> str | None:
    required = ("kqueue", "kevent", "KQ_FILTER_PROC", "KQ_EV_ADD", "KQ_EV_ENABLE", "KQ_EV_ERROR")
    if not all(hasattr(select, name) for name in required):
        return None
    if sys.platform == "darwin":
        return "macos-kqueue-proc-fork"
    if sys.platform.startswith("freebsd"):
        return "freebsd-kqueue-proc-fork"
    return None


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
        panic_markers: tuple[bytes, ...] = (b"kernel panic", b"panic:", b"[panic]", b"non-resettable panic!"),
        event_hook: OutputHook | None = None,
        cleanup: CleanupHook | None = None,
        log_path: str | Path | None = None,
        log_opener: LogOpener | None = None,
        silence_timeout: float | None = None,
        process_tree_interval: float = 0.05,
    ) -> SupervisedResult:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if output_budget <= 0:
            raise ValueError("output_budget must be positive")
        if silence_timeout is not None and (not math.isfinite(silence_timeout) or silence_timeout <= 0):
            raise ValueError("silence_timeout must be a finite positive number")
        if not math.isfinite(process_tree_interval) or process_tree_interval <= 0:
            raise ValueError("process_tree_interval must be a finite positive number")
        started = time.monotonic()
        command = tuple(str(item) for item in argv)
        if not command:
            raise ValueError("argv must not be empty")
        if any("\x00" in item for item in command):
            raise ValueError("argv items must not contain NUL")
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

        backend = _proc_fork_backend()
        use_exec_wrapper = backend is not None
        release_read = None
        release_write = None
        exec_error_read = None
        exec_error_write = None
        pipe_fds: list[int] = []
        popen_command = command
        pass_fds: tuple[int, ...] = ()

        try:
            if use_exec_wrapper:
                release_read, release_write = os.pipe()
                pipe_fds.extend((release_read, release_write))
                exec_error_read, exec_error_write = os.pipe()
                pipe_fds.extend((exec_error_read, exec_error_write))
                popen_command = tuple(
                    [sys.executable, "-c", _EXEC_WRAPPER, str(release_read), str(exec_error_write), *command]
                )
                pass_fds = (release_read, exec_error_write)
            process = subprocess.Popen(
                popen_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=env,
                start_new_session=True,
                pass_fds=pass_fds,
            )
        except OSError as error:
            for fd in pipe_fds:
                _close_fd(fd)
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
                argv=command,
                exit_code=None,
                outcome="spawn-error",
                stdout=b"",
                stderr=str(error).encode(),
                stdout_bytes=0,
                stderr_bytes=0,
                output_truncated=False,
                teardown_state="verified-empty",
                teardown_backend=backend or "unsupported",
                duration_seconds=time.monotonic() - started,
                cleanup_errors=cleanup_errors,
                log_errors=sink.errors,
            )

        _close_fd(release_read)
        _close_fd(exec_error_write)
        release_read = None
        exec_error_write = None

        pgid = process.pid
        tree_errors: list[str] = []
        observed_descendant_pids: list[int] = []
        stop_reason: list[str] = []
        hook_errors: list[str] = []
        watcher_errors: list[str] = []
        teardown_details: list[str] = []
        cleanup_errors: list[str] = []
        reader_errors: list[str] = []
        fork_event_seen = False
        fork_watcher = None
        readers: list[_PipeReader] = []
        stop_readers = threading.Event()
        outcome = "exit"
        exec_error = b""
        group_teardown_failed = False
        last_output = time.monotonic()
        scan_tails = {"stdout": b"", "stderr": b""}
        if backend is None:
            teardown_details.append("strict teardown proof backend unavailable")

        try:
            try:
                pgid = os.getpgid(process.pid)
            except OSError:
                pgid = process.pid
            tracker = ProcessTreeTracker(process.pid)

            def record_watcher_error(message: str) -> None:
                if len(watcher_errors) < 4:
                    watcher_errors.append(message)

            if use_exec_wrapper:
                try:
                    fork_watcher = select.kqueue()
                    fork_event = select.kevent(
                        process.pid,
                        filter=select.KQ_FILTER_PROC,
                        flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE,
                        fflags=_PROC_NOTE_FORK,
                    )
                    fork_watcher.control([fork_event], 0, 0)
                except (OSError, ValueError, OverflowError) as error:
                    record_watcher_error(f"process fork watcher registration failed: {error}")
                    if fork_watcher is not None:
                        try:
                            fork_watcher.close()
                        except OSError:
                            pass
                        fork_watcher = None
                try:
                    if release_write is not None:
                        os.write(release_write, _EXEC_RELEASE_BYTE)
                except OSError as error:
                    record_watcher_error(f"controlled exec release failed: {error}")
                    if not stop_reason:
                        stop_reason.append("harness-error")
                finally:
                    _close_fd(release_write)
                    release_write = None

            def drain_fork_events() -> None:
                nonlocal fork_event_seen
                if fork_watcher is None:
                    return
                try:
                    events = fork_watcher.control(None, 16, 0)
                except OSError as error:
                    record_watcher_error(f"process fork watcher read failed: {error}")
                    return
                for event in events:
                    if event.flags & select.KQ_EV_ERROR:
                        record_watcher_error(f"process fork watcher event error: {event.data}")
                    if event.fflags & _PROC_NOTE_FORK:
                        fork_event_seen = True

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
                raise RuntimeError("supervised process pipes were not created")
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

            def observe_survivors() -> None:
                nonlocal observed_descendant_pids
                try:
                    observed_descendant_pids = tracker.survivors()
                except ProcessTreeError as error:
                    if len(tree_errors) < 4:
                        tree_errors.append(str(error))

            def read_exec_error() -> bytes:
                if exec_error_read is None:
                    return b""
                chunks: list[bytes] = []
                while True:
                    try:
                        chunk = os.read(exec_error_read, 4096)
                    except OSError as error:
                        record_watcher_error(f"target exec error pipe read failed: {error}")
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)

            update_tree()
            last_tree_update = time.monotonic()
            while True:
                drain_fork_events()
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
                drain_fork_events()
                time.sleep(0.01)
            if process.poll() is None:
                _stop_group(process, pgid)
            process.wait()
            drain_fork_events()

            if _group_exists(pgid):
                _signal_group(pgid, signal.SIGKILL)
                deadline = time.monotonic() + 1.0
                while _group_exists(pgid) and time.monotonic() < deadline:
                    time.sleep(0.01)
                if _group_exists(pgid):
                    group_teardown_failed = True
                    teardown_details.append("original process group still exists after SIGKILL")

            observe_survivors()
            exec_error = read_exec_error()
            if exec_error:
                outcome = "spawn-error"
                teardown_details.append("target exec failed: " + exec_error.decode(errors="replace").strip())

            for reader in readers:
                reader.join(timeout=1.0)
            if any(reader.is_alive() for reader in readers):
                _signal_group(pgid, signal.SIGKILL)
                stop_readers.set()
                for reader in readers:
                    reader.join(timeout=1.0)
            reader_errors = [f"{reader.stream_name}: {reader.error}" for reader in readers if reader.error is not None]
            if outcome == "exit" and stop_reason:
                outcome = stop_reason[0]
        except BaseException:
            _stop_group(process, pgid)
            process.wait()
            raise
        finally:
            _close_fd(release_write)
            release_write = None
            stop_readers.set()
            for reader in readers:
                reader.join(timeout=0.2)
            if fork_watcher is not None:
                try:
                    fork_watcher.close()
                except OSError:
                    pass
            _close_fd(exec_error_read)
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

        if fork_event_seen:
            teardown_details.append("supervised root process forked; recursive teardown is unproven")
        teardown_details.extend(f"fork watcher: {item}" for item in watcher_errors)
        teardown_details.extend(f"process scan: {item}" for item in tree_errors)
        if observed_descendant_pids:
            teardown_details.append(f"observed descendant processes still running: {observed_descendant_pids}")

        if group_teardown_failed or observed_descendant_pids:
            teardown_state = "failed"
        elif backend is None or fork_event_seen or watcher_errors or tree_errors:
            teardown_state = "fork-tainted-unproven"
        else:
            teardown_state = "verified-empty"
        if teardown_state != "verified-empty" or sink.errors or cleanup_errors or hook_errors or reader_errors:
            if outcome != "harness-error":
                teardown_details.append(f"runtime outcome before harness-error escalation: {outcome}")
            outcome = "harness-error"

        stdout_reader, stderr_reader = readers
        stderr = stderr_reader.data
        result_exit_code = process.returncode
        if exec_error:
            message = exec_error.split(b"\n", 1)[1] if b"\n" in exec_error else exec_error
            stderr = stderr + (b"\n" if stderr else b"") + message
            result_exit_code = None
        return SupervisedResult(
            argv=command,
            exit_code=result_exit_code,
            outcome=outcome,
            stdout=stdout_reader.data,
            stderr=stderr,
            stdout_bytes=stdout_reader.total_bytes,
            stderr_bytes=stderr_reader.total_bytes,
            output_truncated=stdout_reader.truncated or stderr_reader.truncated,
            teardown_state=teardown_state,
            teardown_backend=backend or "unsupported",
            duration_seconds=time.monotonic() - started,
            cleanup_errors=cleanup_errors,
            log_errors=sink.errors,
            hook_errors=hook_errors,
            reader_errors=reader_errors,
            tree_errors=tree_errors,
            teardown_details=teardown_details,
            observed_descendant_pids=observed_descendant_pids,
        )


def is_full_disk_error(errors: list[OSError]) -> bool:
    return any(error.errno == errno.ENOSPC for error in errors)

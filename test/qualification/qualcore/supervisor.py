import errno
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


OutputHook = Callable[[str, bytes], str | None]
CleanupHook = Callable[[], None]
LogOpener = Callable[[], BinaryIO]


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
    log_errors: list[str] = field(default_factory=list)
    hook_errors: list[str] = field(default_factory=list)


class _LogSink:
    def __init__(self, writer: BinaryIO | None) -> None:
        self.writer = writer
        self.lock = threading.Lock()
        self.errors: list[str] = []
        self.write_failed = False

    def record_error(self, error: OSError) -> None:
        if len(self.errors) < 4:
            self.errors.append(f"errno={error.errno} {error.strerror or error}")

    def write(self, data: bytes) -> None:
        if self.writer is None or self.write_failed:
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
    def __init__(self, name: str, pipe: BinaryIO, budget: int, callback: Callable[[str, bytes], None]) -> None:
        super().__init__(daemon=True)
        self.stream_name = name
        self.pipe = pipe
        self.budget = budget
        self.callback = callback
        self.chunks: list[bytes] = []
        self.total_bytes = 0
        self.captured_bytes = 0
        self.truncated = False

    def run(self) -> None:
        while True:
            chunk = self.pipe.read1(1024)
            if not chunk:
                return
            self.total_bytes += len(chunk)
            self.callback(self.stream_name, chunk)
            remaining = self.budget - self.captured_bytes
            if remaining > 0:
                retained = chunk[:remaining]
                self.chunks.append(retained)
                self.captured_bytes += len(retained)
            if len(chunk) > max(0, remaining):
                self.truncated = True

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


def _format_open_error(error: OSError) -> str:
    return f"errno={error.errno} {error.strerror or error}"


class Supervisor:
    def run(
        self,
        argv: list[str] | tuple[str, ...],
        timeout: float,
        output_budget: int = 65536,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        panic_markers: tuple[bytes, ...] = (b"panic",),
        event_hook: OutputHook | None = None,
        cleanup: CleanupHook | None = None,
        log_path: str | Path | None = None,
        log_opener: LogOpener | None = None,
        silence_timeout: float | None = None,
    ) -> SupervisedResult:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if output_budget <= 0:
            raise ValueError("output_budget must be positive")
        if silence_timeout is not None and silence_timeout <= 0:
            raise ValueError("silence_timeout must be positive")
        started = time.monotonic()
        command = tuple(str(item) for item in argv)
        writer = None
        open_errors: list[str] = []
        if log_opener is not None:
            try:
                writer = log_opener()
            except OSError as error:
                open_errors.append(_format_open_error(error))
        elif log_path is not None:
            try:
                writer = open(log_path, "wb")
            except OSError as error:
                open_errors.append(_format_open_error(error))
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
        stop_reason: list[str] = []
        hook_errors: list[str] = []
        last_output = time.monotonic()
        scan_tails = {"stdout": b"", "stderr": b""}

        def observe(stream: str, chunk: bytes) -> None:
            nonlocal last_output
            last_output = time.monotonic()
            sink.write(chunk)
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

        readers = [
            _PipeReader("stdout", process.stdout, output_budget, observe),
            _PipeReader("stderr", process.stderr, output_budget, observe),
        ]
        for reader in readers:
            reader.start()

        outcome = "exit"
        try:
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
                time.sleep(0.01)

            deadline = time.monotonic() + 2.0
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if process.poll() is None:
                _stop_group(process, pgid)
            process.wait()

            orphaned = outcome == "exit" and _group_exists(pgid)
            if orphaned:
                _signal_group(process, pgid, signal.SIGKILL)
                deadline = time.monotonic() + 1.0
                while _group_exists(pgid) and time.monotonic() < deadline:
                    time.sleep(0.01)

            for reader in readers:
                reader.join(timeout=1.0)
            if any(reader.is_alive() for reader in readers):
                _signal_group(process, pgid, signal.SIGKILL)
                for reader in readers:
                    reader.join(timeout=1.0)
            if outcome == "exit" and stop_reason:
                outcome = stop_reason[0]
        except BaseException:
            _stop_group(process, pgid)
            process.wait()
            raise
        finally:
            cleanup_errors: list[str] = []
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
        )


def is_full_disk_error(errors: list[str]) -> bool:
    needle = f"errno={errno.ENOSPC}"
    return any(item.startswith(needle) for item in errors)

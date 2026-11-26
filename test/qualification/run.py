#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import FrameType

from qualcore.selftest import selftest_main


def run_selftest() -> int:
    terminating_signals: list[int] = []

    def termination_handler(signum: int, frame: FrameType | None) -> None:
        terminating_signals.append(signum)
        raise KeyboardInterrupt

    graceful_signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
    previous_handlers = {signum: signal.signal(signum, termination_handler) for signum in graceful_signals}
    try:
        return selftest_main()
    except KeyboardInterrupt:
        signum = terminating_signals[0] if terminating_signals else signal.SIGINT
        print("interrupted; partial evidence remains under target/qualification and rerunning starts a fresh run", file=sys.stderr, flush=True)
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
        return 128 + signum
    finally:
        for handled_signum, previous_handler in previous_handlers.items():
            signal.signal(handled_signum, previous_handler)


def run_inventory_check() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    inventory = Path(__file__).resolve().parent / "inventory" / "inventory.py"
    completed = subprocess.run(
        [sys.executable, str(inventory), "check", "--repo-root", str(repo_root)],
        check=False,
    )
    return completed.returncode


def main(argv: list[str]) -> int:
    if argv == ["selftest"]:
        return run_selftest()
    if argv == ["inventory", "--check"]:
        return run_inventory_check()
    print("usage: python3 test/qualification/run.py selftest | inventory --check", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

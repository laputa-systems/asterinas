#!/usr/bin/env python3
import os
import signal
import sys
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


def main(argv: list[str]) -> int:
    if argv == ["selftest"]:
        return run_selftest()
    print("usage: python3 test/qualification/run.py selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

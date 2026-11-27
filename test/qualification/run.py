#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import FrameType

from qualcore.lock import LockError, verify_lock, write_lock
from qualcore.runner import run_controls, run_selfcheck
from qualcore.selftest import selftest_main


def run_with_interrupt_policy(operation: Callable[[], int]) -> int:
    terminating_signals: list[int] = []

    def termination_handler(signum: int, frame: FrameType | None) -> None:
        terminating_signals.append(signum)
        raise KeyboardInterrupt

    graceful_signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
    previous_handlers = {signum: signal.signal(signum, termination_handler) for signum in graceful_signals}
    try:
        return operation()
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


def run_lock(arguments: argparse.Namespace, repo: Path) -> int:
    try:
        if arguments.update:
            path = write_lock(repo)
            print(f"input lock updated: {path}")
            return 0
        verification = verify_lock(repo)
    except LockError as error:
        print(f"LOCK ERROR {error}", file=sys.stderr)
        return 1
    print(f"input lock verified: sha256 {verification.lock_hash}")
    print("checked: " + ", ".join(verification.checked))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asterinas qualification runner",
        epilog=(
            "examples:\n"
            "  python3 test/qualification/run.py selftest\n"
            "  python3 test/qualification/run.py inventory --check\n"
            "  python3 test/qualification/run.py lock --verify\n"
            "  python3 test/qualification/run.py run --profile selfcheck --candidate linux\n"
            "  python3 test/qualification/run.py run --profile selfcheck --controls\n"
            "  python3 test/qualification/run.py run --profile pilot-ext2 --baseline\n"
            "Ctrl-C, SIGTERM, SIGHUP, or SIGQUIT stops the current supervised operation, keeps partial evidence, "
            "and terminates this process by that signal."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("selftest", help="run the LC-02 synthetic control suite")

    inventory = subparsers.add_parser("inventory", help="inventory commands")
    inventory.add_argument("--check", action="store_true", help="verify the generated inventory")

    lock = subparsers.add_parser("lock", help="input lock commands")
    lock_group = lock.add_mutually_exclusive_group(required=True)
    lock_group.add_argument("--verify", action="store_true", help="verify all locked inputs")
    lock_group.add_argument("--update", action="store_true", help="rebuild artifacts and regenerate the input lock")

    fixtures = subparsers.add_parser("fixtures", help="build and verify qualification fixtures")
    fixtures.add_argument("--build", choices=["ext4"], help="build fixtures for the given filesystem")
    fixtures.add_argument("--check", action="store_true", help="rebuild and verify fixture hashes and feature masks")

    run = subparsers.add_parser("run", help="run a qualification profile")
    run.add_argument("--profile", required=True, help="profile name")
    run.add_argument("--candidate", default=None, help="candidate backend")
    run.add_argument("--baseline", action="store_true", help="capture the paired failing baseline with the Asterinas candidate")
    run.add_argument("--controls", action="store_true", help="run integration negative controls")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0
    arguments = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    if arguments.command == "selftest":
        return run_with_interrupt_policy(selftest_main)
    if arguments.command == "inventory":
        if arguments.check:
            return run_inventory_check()
        parser.error("inventory requires --check")
    if arguments.command == "lock":
        return run_with_interrupt_policy(lambda: run_lock(arguments, repo))
    if arguments.command == "fixtures":
        from fixtures import ext4 as ext4_fixtures
        from fixtures.ext4 import build, check

        if arguments.check:
            ok, failures = check(repo)
            for failure in failures:
                print(f"check failed: {failure}")
            print("fixture check passed" if ok else "fixture check failed")
            return 0 if ok else 1
        if arguments.build == "ext4":
            manifest = build(repo)
            path = repo / ext4_fixtures.MANIFEST_PATH
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            print(f"fixture manifest written: {path}")
            return 0
        parser.error("fixtures requires --build ext4 or --check")
    if arguments.command == "run":
        if arguments.controls:
            return run_with_interrupt_policy(lambda: run_controls(repo, arguments.profile))
        candidate = "asterinas" if arguments.baseline else arguments.candidate
        if candidate is None:
            parser.error("run requires --candidate unless --controls or --baseline is selected")
        return run_with_interrupt_policy(lambda: run_selfcheck(repo, arguments.profile, candidate, arguments.baseline))
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

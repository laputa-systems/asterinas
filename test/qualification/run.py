#!/usr/bin/env python3
import sys

from qualcore.selftest import selftest_main


def main(argv: list[str]) -> int:
    if argv == ["selftest"]:
        return selftest_main()
    print("usage: python3 test/qualification/run.py selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

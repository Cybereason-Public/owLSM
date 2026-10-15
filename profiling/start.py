#!/usr/bin/env python3
"""Run one profiling test. This is the only program you start."""

import argparse
import os
import sys
from pathlib import Path

PROFILING_DIR = Path(__file__).resolve().parent
if str(PROFILING_DIR) not in sys.path:
    sys.path.insert(0, str(PROFILING_DIR))

from paths import DEFAULT_OWLSM_BIN
from session import Session
from tests import TESTS


def main():
    parser = argparse.ArgumentParser(description="Run an owLSM profiling test")
    parser.add_argument("test", nargs="?", choices=[test.name for test in TESTS])
    parser.add_argument("--list", action="store_true", help="print the test names and exit")
    parser.add_argument("--owlsm", type=Path, default=DEFAULT_OWLSM_BIN, help="path to the owlsm binary")
    args = parser.parse_args()

    if args.list or args.test is None:
        for test in TESTS:
            print(test.name)
        if args.test is None and not args.list:
            parser.error("choose a test")
        return

    if os.geteuid() != 0:
        sys.exit("start.py must run as root")

    selected = next(test for test in TESTS if test.name == args.test)
    selected.run(Session(args.owlsm))


if __name__ == "__main__":
    main()

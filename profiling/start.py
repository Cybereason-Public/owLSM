#!/usr/bin/env python3

import argparse
import os
import sys
from pathlib import Path

PROFILING_DIR = Path(__file__).resolve().parent
if str(PROFILING_DIR) not in sys.path:
    sys.path.insert(0, str(PROFILING_DIR))

from test_factory import ProfilingTestFactory


def main():
    parser = argparse.ArgumentParser(description="Run one owLSM profiling test")
    parser.add_argument("test", nargs="?")
    parser.add_argument("--list", action="store_true", help="print the test names and exit")
    args = parser.parse_args()

    if args.list or args.test is None:
        for name in ProfilingTestFactory.names():
            print(name)
        if args.test is None and not args.list:
            parser.error("choose a test")
        return

    if os.geteuid() != 0:
        sys.exit("start.py must run as root")

    ProfilingTestFactory.create(args.test).execute()


if __name__ == "__main__":
    main()

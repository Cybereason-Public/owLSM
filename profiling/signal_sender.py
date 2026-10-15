#!/usr/bin/env python3
"""Send SIGUSR1 to owLSM ten times a second until the finish file appears."""

import argparse
import os
import signal
import time
from pathlib import Path


def send_until_finish(owlsm_pid, finish_file):
    interval = 0.1
    while not finish_file.exists():
        started = time.monotonic()
        try:
            os.kill(owlsm_pid, signal.SIGUSR1)
        except ProcessLookupError:
            return
        except PermissionError:
            # BLOCK_EVENT denies the signal. owLSM keeps running, and the event is still emitted.
            pass
        remaining = interval - (time.monotonic() - started)
        if remaining > 0 and not finish_file.exists():
            time.sleep(remaining)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--finish", type=Path, required=True)
    args = parser.parse_args()
    send_until_finish(args.pid, args.finish)


if __name__ == "__main__":
    main()

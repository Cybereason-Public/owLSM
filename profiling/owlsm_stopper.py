"""Child whose only job is to signal owLSM.

start.py passes this process's pid as `-p`. The pid has to be a process that
does not fork the pressure: after the probes attach, a protected parent marks
every new child protected too.
"""

import os
import select
import signal
import subprocess
import sys
from pathlib import Path


READY_TIMEOUT_SECONDS = 5


class OwlsmStopper:
    def __init__(self):
        self._closed = False
        self._process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            text=True,
        )
        try:
            self._wait_until_ready()
        except Exception:
            self.close()
            raise

    @property
    def pid(self):
        return self._process.pid

    def signal_owlsm(self, owlsm_pid, sig):
        if self._closed or self._process.poll() is not None:
            raise RuntimeError("owLSM stopper is not running")
        if sig == signal.SIGINT:
            command = "INT"
        elif sig == signal.SIGKILL:
            command = "KILL"
        else:
            raise RuntimeError(f"stopper cannot send signal {sig}")
        self._process.stdin.write(f"{command} {owlsm_pid}\n")
        self._process.stdin.flush()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._process.poll() is not None:
            return
        try:
            self._process.stdin.write("QUIT\n")
            self._process.stdin.flush()
            self._process.stdin.close()
            self._process.wait(timeout=READY_TIMEOUT_SECONDS)
        except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
            self._process.kill()
            self._process.wait(timeout=READY_TIMEOUT_SECONDS)

    def _wait_until_ready(self):
        readable, _, _ = select.select([self._process.stdout], [], [], READY_TIMEOUT_SECONDS)
        if not readable:
            raise RuntimeError("owLSM stopper did not start")
        ready = self._process.stdout.readline().strip()
        self._process.stdout.close()
        if ready != "ready":
            raise RuntimeError("owLSM stopper did not start")


def _serve():
    print("ready", flush=True)
    for line in sys.stdin:
        parts = line.split()
        if not parts or parts[0] == "QUIT":
            return
        if len(parts) != 2:
            continue
        command, pid_text = parts
        if command == "INT":
            requested = signal.SIGINT
        elif command == "KILL":
            requested = signal.SIGKILL
        else:
            continue
        try:
            os.kill(int(pid_text), requested)
        except ProcessLookupError:
            pass


if __name__ == "__main__":
    _serve()

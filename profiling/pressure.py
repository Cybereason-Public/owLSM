"""Start the pressure workers and remove their files after they exit."""

import os
import shutil
import signal
import subprocess
import sys
import time

from globals import Strings, log
from workload import cleanup_namespace, setup_notrack, teardown_notrack, worker_count


class Pressure:
    def __init__(self):
        self._processes = []
        self._count = 0
        self._stopped = False

    def run(self):
        self._count = worker_count()
        log(f"starting {self._count} workers")
        setup_notrack()
        self._reset_work_root()
        for index in range(self._count):
            cleanup_namespace(index)
            self._spawn(index)
        self._wait()
        self._remove_work_root()
        teardown_notrack()
        log("pressure cleanup finished")

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        for process in self._processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        for index in range(self._count):
            cleanup_namespace(index)
        teardown_notrack()
        self._remove_work_root()

    def _reset_work_root(self):
        self._remove_work_root()
        Strings.WORK_ROOT.mkdir(parents=True)

    def _remove_work_root(self):
        if Strings.WORK_ROOT.exists():
            shutil.rmtree(Strings.WORK_ROOT, ignore_errors=True)

    def _spawn(self, index):
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        process = subprocess.Popen(
            [sys.executable, str(Strings.WORKLOAD_SCRIPT), "--index", str(index)],
            start_new_session=True,
            env=environment,
        )
        self._processes.append(process)

    def _wait(self):
        pending = set(self._processes)
        while pending:
            finished = [process for process in pending if process.poll() is not None]
            if not finished:
                time.sleep(0.2)
                continue
            for process in finished:
                pending.remove(process)
                if process.returncode != 0:
                    self.stop()
                    raise RuntimeError(f"worker pid {process.pid} exited with status {process.returncode}")

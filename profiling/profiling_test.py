"""Template shared by every profiling test. A test only replaces run()."""

import subprocess
import sys
import time

from globals import Numbers, Strings, log
from pressure import Pressure


class ProfilingTest:
    name = ""
    config_name = ""
    capture_events_log = False

    def __init__(self):
        self.output_dir = None
        self._owlsm = None
        self._killer = None
        self._pressure = None
        self._profiler = None
        self._events_log_file = None
        self._log_offset = 0
        self._started = 0.0

    def execute(self):
        self._started = time.monotonic()
        log(f"step 1: start {self.name}")
        stamp = time.strftime("%d%m%Y_%H%M%S")
        self.output_dir = Strings.RESULTS_DIR / self.name / stamp
        self.output_dir.mkdir(parents=True)
        log(f"results {self.output_dir}")
        try:
            self._delete_finish()
            self._start_killer()
            self._start_owlsm()
            self._wait_until_attached()
            log("step 6: run")
            self.run()
            self._stop_owlsm()
            self._finish_children()
            log("step 9: create the results")
            self.create_results()
        finally:
            self._last_cleanup()
            log(f"finished in {time.monotonic() - self._started:.0f}s")

    def run(self):
        raise NotImplementedError

    def profile_start(self):
        raise NotImplementedError

    def pressure(self):
        log("pressure")
        self._pressure = Pressure()
        self._pressure.run()

    def profile_stop(self):
        raise NotImplementedError

    def create_results(self):
        raise NotImplementedError

    def _delete_finish(self):
        log("step 2: delete finish file")
        if Strings.FINISH_FILE.exists():
            Strings.FINISH_FILE.unlink()
        if Strings.OWLSM_PID_FILE.exists():
            Strings.OWLSM_PID_FILE.unlink()

    def _start_killer(self):
        log("step 3: start owlsm_killer")
        self._killer = subprocess.Popen(
            [sys.executable, str(Strings.KILLER_SCRIPT)],
            start_new_session=True,
        )
        time.sleep(0.2)
        if self._killer.poll() is not None:
            raise RuntimeError(f"owlsm_killer exited with status {self._killer.returncode}")

    def _start_owlsm(self):
        log("step 4: start owlsm")
        if not Strings.OWLSM_BIN.is_file():
            raise RuntimeError(
                f"owLSM binary was not found at {Strings.OWLSM_BIN}. Copy build/owlsm to profiling/owlsm."
            )
        config_path = Strings.CONFIG_DIR / self.config_name
        if not config_path.is_file():
            raise RuntimeError(f"config was not found at {config_path}")
        existing = subprocess.run(
            ["pidof", Strings.OWLSM_BIN.name],
            stdout=subprocess.PIPE,
            text=True,
        )
        if existing.returncode == 0 and existing.stdout.strip():
            raise RuntimeError(f"owlsm is already running: {existing.stdout.strip()}")
        if Strings.OWLSM_LOG.exists():
            self._log_offset = Strings.OWLSM_LOG.stat().st_size
        stdout_target = subprocess.DEVNULL
        if self.capture_events_log:
            self._events_log_file = (self.output_dir / Strings.OWLSM_EVENTS_LOG).open("wb")
            stdout_target = self._events_log_file
        self._owlsm = subprocess.Popen(
            [
                str(Strings.OWLSM_BIN),
                "-c", str(config_path),
                "-p", str(self._killer.pid),
                "-e", str(self._killer.pid),
            ],
            stdout=stdout_target,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        Strings.OWLSM_PID_FILE.write_text(str(self._owlsm.pid), encoding="utf-8")
        log(f"owlsm pid {self._owlsm.pid}")

    def _wait_until_attached(self):
        log("step 5: wait for probes")
        deadline = time.monotonic() + Numbers.ATTACH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self._owlsm.poll() is not None:
                raise RuntimeError(
                    f"owLSM exited with status {self._owlsm.returncode} before the probes were attached.\n"
                    + self._log_tail()
                )
            if Strings.ATTACHED_LINE in self._new_log_text():
                log("probes attached")
                return
            time.sleep(Numbers.ATTACH_POLL_SECONDS)
        raise RuntimeError(
            f"owLSM did not log '{Strings.ATTACHED_LINE}' within {Numbers.ATTACH_TIMEOUT_SECONDS}s.\n"
            + self._log_tail()
        )

    def _stop_owlsm(self):
        log("step 7: stop owlsm")
        Strings.FINISH_FILE.touch()
        if self._owlsm is None:
            return
        try:
            self._owlsm.wait(timeout=Numbers.OWLSM_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            log(f"error: owlsm did not exit within {Numbers.OWLSM_STOP_TIMEOUT_SECONDS}s, only owlsm_killer may kill it")

    def _finish_children(self):
        log("step 8: finish children")
        if self._owlsm is not None and self._owlsm.poll() is None:
            log("error: owlsm is still running, only owlsm_killer may kill it")
        if self._events_log_file is not None:
            self._events_log_file.close()
        if self._killer is not None:
            try:
                self._killer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._killer.kill()
                self._killer.wait(timeout=5)
        if self._pressure is not None:
            self._pressure.stop()

    def _last_cleanup(self):
        log("step 10: last cleanups")
        if self._events_log_file is not None and not self._events_log_file.closed:
            self._events_log_file.close()
        if self._profiler is not None:
            try:
                self._profiler.stop()
            except Exception as error:
                log(f"profiler cleanup failed: {error}")
        if self._pressure is not None:
            try:
                self._pressure.stop()
            except Exception as error:
                log(f"pressure cleanup failed: {error}")
        if self._owlsm is not None and self._owlsm.poll() is None:
            Strings.FINISH_FILE.touch()
            try:
                self._owlsm.wait(timeout=Numbers.OWLSM_STOP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                log("error: owlsm still running during cleanup, only owlsm_killer may kill it")
        if self._killer is not None and self._killer.poll() is None:
            Strings.FINISH_FILE.touch()
            try:
                self._killer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._killer.kill()
                self._killer.wait(timeout=5)
        for path in (Strings.FINISH_FILE, Strings.OWLSM_PID_FILE):
            if path.exists():
                path.unlink()

    def _new_log_text(self):
        if not Strings.OWLSM_LOG.exists():
            return ""
        with Strings.OWLSM_LOG.open(encoding="utf-8", errors="replace") as handle:
            handle.seek(self._log_offset)
            return handle.read()

    def _log_tail(self):
        lines = self._new_log_text().splitlines()
        return "\n".join(lines[-Numbers.LOG_TAIL_LINES:])

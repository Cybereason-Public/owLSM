import signal
import subprocess
import threading
import time
from pathlib import Path

from owlsm_stopper import OwlsmStopper
from paths import CONFIGS_DIR


ATTACHED_LINE = "Attached all probes"
ATTACH_TIMEOUT_SECONDS = 180
STOP_TIMEOUT_SECONDS = 20


class OwlsmProcess:
    def __init__(self, process, log_path, stderr_path, stopper):
        self.pid = process.pid
        self._process = process
        self._log_path = Path(log_path)
        self._stderr_path = Path(stderr_path)
        self._stopper = stopper

    def wait_until_attached(self):
        deadline = time.monotonic() + ATTACH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError(
                    "owLSM exited before the probes were attached.\n" + self._diagnostics()
                )
            if self._log_path.exists() and ATTACHED_LINE in self._log_path.read_text(encoding="utf-8", errors="replace"):
                return
            time.sleep(0.2)
        raise RuntimeError(
            f"owLSM did not log '{ATTACHED_LINE}' within {ATTACH_TIMEOUT_SECONDS}s.\n" + self._diagnostics()
        )

    def ensure_running(self):
        if self._process.poll() is not None:
            raise RuntimeError(f"owLSM exited with status {self._process.returncode}.\n" + self._diagnostics())

    def stop(self):
        try:
            if self._process.poll() is None:
                self._stopper.signal_owlsm(self.pid, signal.SIGINT)
                try:
                    self._process.wait(timeout=STOP_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    self._stopper.signal_owlsm(self.pid, signal.SIGKILL)
                    self._process.wait(timeout=STOP_TIMEOUT_SECONDS)
        finally:
            self._stopper.close()

    def _diagnostics(self):
        return f"stderr:\n{_tail(self._stderr_path)}\nlog:\n{_tail(self._log_path)}"


def start_owlsm(owlsm_bin, config_name, output_dir):
    config_path = CONFIGS_DIR / config_name
    if not config_path.is_file():
        raise RuntimeError(f"missing {config_path}")
    owlsm_bin = Path(owlsm_bin)
    if not owlsm_bin.is_file():
        raise RuntimeError(f"owLSM binary not found at {owlsm_bin}. Build it with: make profiler -j$(nproc)")

    output_dir = Path(output_dir)
    log_path = output_dir / "owlsm.log"
    stderr_path = output_dir / "owlsm_stderr.log"
    stopper = OwlsmStopper()
    stderr_file = stderr_path.open("w", encoding="utf-8")
    try:
        # -p is only the stopper. Protecting start.py would mark every child it
        # forks after attach as protected, including the workloads and the signal sender.
        # cwd makes the config's relative log_location, "owlsm.log", resolve in this directory.
        # Events go to /dev/null. Profiling does not read them, and storing the
        # stream writes several GB under pressure.
        process = subprocess.Popen(
            [str(owlsm_bin), "-c", str(config_path), "-p", str(stopper.pid)],
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
            cwd=output_dir,
            start_new_session=True,
        )
    except Exception:
        stderr_file.close()
        stopper.close()
        raise
    stderr_file.close()
    owlsm = OwlsmProcess(process, log_path, stderr_path, stopper)
    try:
        owlsm.wait_until_attached()
    except Exception:
        owlsm.stop()
        raise
    return owlsm


def _tail(path, limit=40):
    if not path.exists():
        return "(missing)"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-limit:])

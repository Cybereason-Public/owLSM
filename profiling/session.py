import time
from pathlib import Path

from owlsm_process import start_owlsm
from paths import RESULTS_DIR
from pressure import Pressure, cleanup_network, remove_work_dir


class Session:
    def __init__(self, owlsm_bin, results_root=RESULTS_DIR):
        self._owlsm_bin = Path(owlsm_bin)
        self._results_root = Path(results_root)
        self.output_dir = None
        self._owlsm = None
        self._pressure = None
        self._closed = False

    def begin(self, test_name):
        cleanup_network()
        remove_work_dir()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.output_dir = self._results_root / test_name / stamp
        self.output_dir.mkdir(parents=True)
        self._pressure = Pressure(self.output_dir)
        print(f"[profiling] {test_name}", flush=True)
        print(f"[profiling] output {self.output_dir}", flush=True)

    def start_owlsm(self, config_name):
        print(f"[profiling] starting owLSM with {config_name}", flush=True)
        self._owlsm = start_owlsm(self._owlsm_bin, config_name, self.output_dir)
        print(f"[profiling] probes attached, pid {self._owlsm.pid}", flush=True)
        return self._owlsm

    def start_workloads_and_shell(self):
        print("[profiling] starting workloads and bash", flush=True)
        self._pressure.start_workloads_and_shell()

    def start_signal_sender(self):
        if self._owlsm is None:
            raise RuntimeError("signal sender starts after owLSM is attached")
        print("[profiling] starting signal sender", flush=True)
        self._pressure.start_signal_sender(self._owlsm.pid)

    def signal_finish(self):
        print("[profiling] writing finish", flush=True)
        self._pressure.signal_finish()

    def wait_for_pressure_to_exit(self):
        self._pressure.wait_until_stopped()

    def ensure_owlsm_running(self):
        if self._owlsm is not None:
            self._owlsm.ensure_running()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._pressure is not None:
            try:
                self._pressure.force_cleanup()
            except Exception as error:
                print(f"[profiling] cleanup failed: {error}", flush=True)
        if self._owlsm is not None:
            self._owlsm.stop()
            self._owlsm = None
        if self.output_dir is not None:
            print(f"[profiling] done {self.output_dir}", flush=True)

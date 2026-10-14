import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from paths import FINISH_FILE, SHELL_LOOP, SIGNAL_SENDER_SCRIPT, WORK_DIR, WORKER_COUNT, WORKLOAD_SCRIPT


CLEANUP_TIMEOUT_SECONDS = 30


class Pressure:
    def __init__(self, output_dir):
        self._output_dir = Path(output_dir)
        self._processes = []
        self._logs = []
        self._started = False

    def start_workloads_and_shell(self):
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        cleanup_network()
        for index in range(WORKER_COUNT):
            self._spawn(
                [
                    sys.executable,
                    str(WORKLOAD_SCRIPT),
                    "--index", str(index),
                    "--work-root", str(WORK_DIR),
                    "--finish", str(FINISH_FILE),
                ],
                self._output_dir / f"workload-{index}.log",
            )
        self._spawn(
            ["bash", str(SHELL_LOOP), str(FINISH_FILE)],
            self._output_dir / "shell_loop.log",
        )
        self._started = True

    def start_signal_sender(self, owlsm_pid):
        self._spawn(
            [
                sys.executable,
                str(SIGNAL_SENDER_SCRIPT),
                "--pid", str(owlsm_pid),
                "--finish", str(FINISH_FILE),
            ],
            self._output_dir / "signal_sender.log",
        )
        self._started = True

    def signal_finish(self):
        if not self._started:
            return
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        FINISH_FILE.touch()

    def wait_until_stopped(self):
        if not self._started:
            return
        deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        for process in self._processes:
            remaining = max(0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                _kill_process(process)
                raise RuntimeError("pressure process did not exit after the finish file appeared")
        failed = [process for process in self._processes if process.returncode != 0]
        self._close_logs()
        if failed:
            details = ", ".join(f"pid {process.pid} status {process.returncode}" for process in failed)
            raise RuntimeError(f"pressure process failed: {details}")

    def force_cleanup(self):
        self.signal_finish()
        for process in self._processes:
            _kill_process(process)
        self._close_logs()
        cleanup_network()
        remove_work_dir()

    def _spawn(self, command, log_path):
        log_file = log_path.open("w", encoding="utf-8")
        self._logs.append(log_file)
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        process = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=environment,
        )
        self._processes.append(process)

    def _close_logs(self):
        for log_file in self._logs:
            log_file.close()
        self._logs.clear()


def remove_work_dir():
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)


def cleanup_network():
    for index in range(WORKER_COUNT):
        namespace = f"owlsm-w{index}"
        if _namespace_exists(namespace):
            _kill_namespace(namespace)
        _run_quiet(["ip", "link", "delete", f"owl{index}h"])
        _delete_namespace(namespace)


def _kill_process(process):
    if process.poll() is not None:
        return
    process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _namespace_exists(namespace):
    return Path("/run/netns", namespace).exists()


def _kill_namespace(namespace):
    result = subprocess.run(
        ["ip", "netns", "pids", namespace],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return
    for pid_text in result.stdout.split():
        try:
            os.kill(int(pid_text), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, ValueError):
            continue


def _delete_namespace(namespace):
    if not _namespace_exists(namespace):
        return
    for _attempt in range(10):
        _run_quiet(["ip", "netns", "delete", namespace])
        if not _namespace_exists(namespace):
            return
        time.sleep(0.1)


def _run_quiet(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

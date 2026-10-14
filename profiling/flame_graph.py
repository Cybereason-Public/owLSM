"""Record a process-wide cpu-clock profile and write one flame graph per thread, plus an overall graph."""

import shutil
import signal
import subprocess
import threading
from pathlib import Path


class FlameGraphProfiler:
    def __init__(self, seconds):
        self._seconds = seconds

    def record(self, pid, output_dir):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        perf_data = output_dir / "perf.data"
        names = {}
        stop = threading.Event()

        def snapshot():
            while not stop.is_set():
                _collect_thread_names(pid, names)
                stop.wait(1)

        _collect_thread_names(pid, names)
        watcher = threading.Thread(target=snapshot, name="thread-names")
        watcher.start()
        try:
            self._record_perf(pid, perf_data)
        finally:
            stop.set()
            watcher.join()
            _collect_thread_names(pid, names)

        self._render_all(perf_data, names, output_dir)

    def _record_perf(self, pid, perf_data):
        perf = _require_tool("perf")
        command = [
            perf, "record",
            "-e", "cpu-clock",
            "--call-graph", "dwarf",
            "-p", str(pid),
            "-o", str(perf_data),
            "--", "sleep", str(self._seconds),
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stderr = process.communicate()[1]
        except KeyboardInterrupt:
            process.send_signal(signal.SIGINT)
            try:
                process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise
        if process.returncode != 0:
            raise RuntimeError(f"perf record failed:\n{stderr}")

    def _render_all(self, perf_data, names, output_dir):
        stackcollapse = _require_tool("stackcollapse-perf.pl")
        flamegraph = _require_tool("flamegraph.pl")
        script = _perf_script(perf_data, None)
        _render_svg(script, "owLSM overall", output_dir / "overall.svg", stackcollapse, flamegraph)
        for tid, comm in sorted(names.items()):
            thread_script = _perf_script(perf_data, tid)
            if not thread_script.strip():
                continue
            filename = f"{_safe_name(comm)}-{tid}.svg"
            _render_svg(
                thread_script,
                f"owLSM {comm} tid {tid}",
                output_dir / filename,
                stackcollapse,
                flamegraph,
            )


def _collect_thread_names(pid, names):
    task_dir = Path(f"/proc/{pid}/task")
    if not task_dir.is_dir():
        return
    for entry in task_dir.iterdir():
        try:
            names[int(entry.name)] = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue


def _perf_script(perf_data, tid):
    command = ["perf", "script", "-i", str(perf_data)]
    if tid is not None:
        command.extend(["--tid", str(tid)])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"perf script failed:\n{result.stderr}")
    return result.stdout


def _render_svg(script_text, title, svg_path, stackcollapse, flamegraph):
    collapsed = subprocess.run(
        [stackcollapse],
        input=script_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if collapsed.returncode != 0:
        raise RuntimeError(f"stackcollapse-perf.pl failed:\n{collapsed.stderr}")
    graph = subprocess.run(
        [flamegraph, "--title", title, "--countname", "samples"],
        input=collapsed.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if graph.returncode != 0 or not graph.stdout.strip():
        raise RuntimeError(f"flamegraph.pl failed:\n{graph.stderr}")
    svg_path.write_text(graph.stdout, encoding="utf-8")


def _require_tool(name):
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(
            f"{name} was not found. Run scripts/oci_testing_machines_setup/ubuntu_24_profiling.sh on the profiling machine."
        )
    return path


def _safe_name(comm):
    cleaned = "".join(character if character.isalnum() or character in "-_" else "_" for character in comm)
    return cleaned or "thread"

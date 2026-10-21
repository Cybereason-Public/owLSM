"""Record a cpu-clock flame graph per owLSM thread, plus one overall graph."""

import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from globals import Numbers, Strings, log
from profiling_test import ProfilingTest


class FlameGraphTest(ProfilingTest):
    def profile_start(self):
        log("profile_start")
        self._profiler = FlameGraphProfiler()
        self._profiler.start(self._owlsm.pid, self.output_dir)

    def profile_stop(self):
        log("profile_stop")
        if self._profiler is not None:
            self._profiler.stop()

    def create_results(self):
        if self._profiler is None:
            raise RuntimeError("flame graph profiler was not started")
        self._profiler.render()
        svg = self.output_dir / Strings.OVERALL_SVG
        if not svg.is_file() or svg.stat().st_size == 0:
            raise RuntimeError("overall flame graph was not written")
        log(f"wrote {svg}")
        perf_data = self.output_dir / Strings.PERF_DATA
        if perf_data.exists():
            perf_data.unlink()


class FlameGraphProfiler:
    def __init__(self):
        self._process = None
        self._perf_data = None
        self._names = {}
        self._pid = None
        self._output_dir = None
        self._stopped = False

    def start(self, pid, output_dir):
        self._pid = pid
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._perf_data = self._output_dir / Strings.PERF_DATA
        _collect_thread_names(pid, self._names)
        perf = _require_tool(Strings.PERF)
        self._process = subprocess.Popen(
            [
                perf, "record",
                "-e", "cpu-clock",
                "--call-graph", "dwarf",
                "-p", str(pid),
                "-o", str(self._perf_data),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(0.3)
        if self._process.poll() is not None:
            _stdout, stderr = self._process.communicate()
            self._stopped = True
            raise RuntimeError(f"perf record exited immediately:\n{stderr}")

    def stop(self):
        if self._stopped or self._process is None:
            return
        self._stopped = True
        if self._pid is not None:
            _collect_thread_names(self._pid, self._names)
        if self._process.poll() is None:
            self._process.send_signal(signal.SIGINT)
        try:
            _stdout, stderr = self._process.communicate(timeout=Numbers.PERF_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            _stdout, stderr = self._process.communicate()
            raise RuntimeError("perf record did not stop after SIGINT")
        if self._process.returncode not in (0, -signal.SIGINT, 128 + signal.SIGINT):
            raise RuntimeError(f"perf record failed:\n{stderr}")

    def render(self):
        if self._perf_data is None or not self._perf_data.exists():
            raise RuntimeError("perf record did not write a data file")
        stackcollapse = _require_tool(Strings.STACKCOLLAPSE)
        flamegraph = _require_tool(Strings.FLAMEGRAPH)
        folded_text = _fold_once(self._perf_data, stackcollapse)
        (self._output_dir / Strings.STACKS_FOLDED).write_text(folded_text, encoding="utf-8")
        overall, by_tid = _split_folded(folded_text)
        if not overall:
            raise RuntimeError("perf record produced no stacks")
        _write_svg(_format_folded(overall), "owLSM overall", self._output_dir / Strings.OVERALL_SVG, flamegraph)
        for tid, comm in sorted(self._names.items()):
            stacks = by_tid.get(tid)
            if not stacks:
                continue
            filename = f"{_safe_name(comm)}-{tid}.svg"
            _write_svg(
                _format_folded(stacks),
                f"owLSM {comm} tid {tid}",
                self._output_dir / filename,
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


def _fold_once(perf_data, stackcollapse):
    script = subprocess.Popen(
        [Strings.PERF, "script", "-i", str(perf_data)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    folded = subprocess.Popen(
        [stackcollapse, "--tid"],
        stdin=script.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    script.stdout.close()
    script_error = []
    script_error_reader = threading.Thread(
        target=_read_stream,
        args=(script.stderr, script_error),
        name="perf-script-error",
    )
    script_error_reader.start()
    folded_text, folded_error = folded.communicate()
    script_error_reader.join()
    script.wait()
    if script.returncode != 0:
        raise RuntimeError(f"perf script failed:\n{''.join(script_error)}")
    if folded.returncode != 0:
        raise RuntimeError(f"stackcollapse-perf.pl failed:\n{folded_error}")
    return folded_text


def _read_stream(stream, chunks):
    chunks.append(stream.read())


_THREAD_PREFIX = re.compile(r"^(.+)-(\?|\d+)/(\d+)$")


def _split_folded(folded_text):
    overall = {}
    by_tid = {}
    for line in folded_text.splitlines():
        if not line.strip():
            continue
        stack, count_text = line.rsplit(" ", 1)
        count = int(count_text)
        frames = stack.split(";")
        comm, tid = _thread_prefix(frames[0])
        frames[0] = comm
        key = ";".join(frames)
        overall[key] = overall.get(key, 0) + count
        thread_stacks = by_tid.setdefault(tid, {})
        thread_stacks[key] = thread_stacks.get(key, 0) + count
    return overall, by_tid


def _thread_prefix(frame):
    match = _THREAD_PREFIX.fullmatch(frame)
    if match is None:
        raise RuntimeError(f"folded stack is missing its thread id: {frame}")
    return match.group(1), int(match.group(3))


def _format_folded(stacks):
    return "".join(f"{stack} {count}\n" for stack, count in stacks.items())


def _write_svg(folded_text, title, svg_path, flamegraph):
    graph = subprocess.run(
        [flamegraph, "--title", title, "--countname", "samples"],
        input=folded_text,
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
        raise RuntimeError(f"{name} was not found")
    return path


def _safe_name(comm):
    cleaned = "".join(character if character.isalnum() or character in "-_" else "_" for character in comm)
    return cleaned or "thread"

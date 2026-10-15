"""Record a process-wide cpu-clock profile and write one flame graph per thread, plus an overall graph."""

import re
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
        # Unwind the recording once. A second perf script per thread repeats
        # that unwind. --tid leaves the thread id on the first frame.
        folded_text = _fold_once(perf_data, stackcollapse)
        (output_dir / "stacks.folded").write_text(folded_text, encoding="utf-8")
        overall, by_tid = _split_folded(folded_text)
        _write_svg(_format_folded(overall), "owLSM overall", output_dir / "overall.svg", flamegraph)
        for tid, comm in sorted(names.items()):
            stacks = by_tid.get(tid)
            if not stacks:
                continue
            filename = f"{_safe_name(comm)}-{tid}.svg"
            _write_svg(
                _format_folded(stacks),
                f"owLSM {comm} tid {tid}",
                output_dir / filename,
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
        ["perf", "script", "-i", str(perf_data)],
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
    script_error_reader = threading.Thread(target=_read_stream, args=(script.stderr, script_error), name="perf-script-error")
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
        # The SVGs use the thread name as the root frame. --tid appends "-pid/tid".
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
        raise RuntimeError(
            f"{name} was not found. Run scripts/oci_testing_machines_setup/ubuntu_24_profiling.sh on the profiling machine."
        )
    return path


def _safe_name(comm):
    cleaned = "".join(character if character.isalnum() or character in "-_" else "_" for character in comm)
    return cleaned or "thread"

"""Run bpftop --export during a profiling test and plot owLSM eBPF program CPU."""

import datetime
import json
import os
import signal
import subprocess
import time
from collections import defaultdict
from pathlib import Path

import plotly.graph_objects as go

from globals import Numbers, Strings, log
from profiling_test import ProfilingTest


class BpfProgramsCpuGraphTest(ProfilingTest):
    def profile_start(self):
        log("profile_start")

    def profile_stop(self):
        log("profile_stop")
        if self._profiler is not None:
            self._profiler.stop()

    def mark_pressure_start(self):
        if self._profiler is not None:
            self._profiler.mark_pressure_start()

    def mark_pressure_end(self):
        if self._profiler is not None:
            self._profiler.mark_pressure_end()

    def create_results(self):
        if self._profiler is None or self._owlsm is None:
            raise RuntimeError("bpftop profiler was not started")
        self._profiler.render(self._owlsm.pid)
        html = self.output_dir / Strings.BPF_PROGRAMS_CPU_GRAPH_HTML
        if not html.is_file() or html.stat().st_size == 0:
            raise RuntimeError("bpf programs cpu graph was not written")
        log(f"wrote {html}")

    def _before_start_owlsm(self):
        log("start bpftop before owlsm")
        self._profiler = BpfTopExportProfiler()
        self._profiler.start(self.output_dir)

    def exclude_pids(self):
        pids = super().exclude_pids()
        if self._profiler is not None:
            pids.extend(self._profiler.exclude_pids())
        return pids


class BpfTopExportProfiler:
    def __init__(self):
        self._process = None
        self._export_path = None
        self._pressure_start = None
        self._pressure_end = None

    def start(self, output_dir):
        if not Strings.BPFTOP_BIN.is_file():
            raise RuntimeError(
                f"bpftop was not found at {Strings.BPFTOP_BIN}. "
                "Run: git submodule update --init profiling/bpftop && "
                "cd profiling/bpftop && cargo build --release -j$(nproc)"
            )
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        self._export_path = output_dir / Strings.BPFTOP_EXPORT_JSONL
        if self._export_path.exists():
            self._export_path.unlink()
        self._process = subprocess.Popen(
            [
                str(Strings.BPFTOP_BIN),
                "--export",
                str(self._export_path),
                "-d",
                str(Numbers.BPFTOP_SAMPLE_DELAY_SECONDS),
            ],
            start_new_session=True,
        )
        time.sleep(Numbers.BPFTOP_STARTUP_SECONDS)
        if self._process.poll() is not None:
            raise RuntimeError(f"bpftop exited with status {self._process.returncode}")
        log(f"bpftop pid {self._process.pid}, export {self._export_path}")

    def exclude_pids(self):
        if self._process is None:
            return []
        return _task_pids(self._process.pid)

    def mark_pressure_start(self):
        self._pressure_start = time.time()

    def mark_pressure_end(self):
        self._pressure_end = time.time()

    def stop(self):
        if self._process is None or self._process.poll() is not None:
            return
        try:
            os.killpg(self._process.pid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            self._process.wait(timeout=Numbers.BPFTOP_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(self._process.pid, signal.SIGKILL)
            self._process.wait(timeout=Numbers.BPFTOP_STOP_TIMEOUT_SECONDS)

    def render(self, owlsm_pid):
        if self._export_path is None or not self._export_path.is_file():
            raise RuntimeError("bpftop export file was not written")
        if self._export_path.stat().st_size == 0:
            raise RuntimeError("bpftop export file is empty")
        write_graph(
            self._export_path,
            owlsm_pid,
            self._export_path.parent / Strings.BPF_PROGRAMS_CPU_GRAPH_HTML,
            self._pressure_start,
            self._pressure_end,
        )


def _task_pids(main_pid):
    task_dir = Path(f"/proc/{main_pid}/task")
    if not task_dir.is_dir():
        return [main_pid]
    pids = sorted(int(entry.name) for entry in task_dir.iterdir() if entry.name.isdigit())
    return pids if pids else [main_pid]


def write_graph(input_path, owlsm_pid, output_path, pressure_start=None, pressure_end=None):
    records = _load_records(input_path, owlsm_pid)
    series = _series_by_program(records)
    _render(series, output_path, pressure_start, pressure_end)


def _load_records(input_path, owlsm_pid):
    records = []
    with Path(input_path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            pids = [int(value) for value in row.get("pids", [])]
            if owlsm_pid not in pids:
                continue
            records.append(row)
    if not records:
        raise RuntimeError(f"no programs referenced pid {owlsm_pid} in {input_path}")
    return records


def _series_by_program(records):
    series = defaultdict(lambda: {"name": "", "times": [], "cpu": []})
    for row in records:
        program_id = str(row["id"])
        entry = series[program_id]
        entry["name"] = row["name"]
        entry["times"].append(datetime.datetime.fromtimestamp(float(row["timestamp"])))
        entry["cpu"].append(_parse_cpu_percent(row["cpu_percent"]))
    return series


def _parse_cpu_percent(value):
    if isinstance(value, (int, float)):
        return float(value)
    return float(str(value).strip().rstrip("%"))


def _render(series, output_path, pressure_start, pressure_end):
    figure = go.Figure()
    for program_id, entry in sorted(series.items(), key=lambda item: (item[1]["name"], item[0])):
        hook_name = f"{entry['name']} ({program_id})"
        figure.add_trace(
            go.Scatter(
                x=entry["times"],
                y=entry["cpu"],
                name=hook_name,
                mode="lines",
                line=dict(width=2, simplify=False),
                hovertemplate=f"{hook_name}<br>%{{x|%H:%M:%S}}<br>CPU: %{{y}}%<extra></extra>",
                hoverlabel=dict(namelength=-1),
            )
        )
    for mark_time, label in (
        (pressure_start, Strings.PRESSURE_START_LABEL),
        (pressure_end, Strings.PRESSURE_END_LABEL),
    ):
        if mark_time is not None:
            figure.add_vline(
                x=datetime.datetime.fromtimestamp(mark_time),
                line_dash="dash",
                line_color="gray",
                annotation_text=label,
            )
    figure.update_layout(
        title="owLSM eBPF program CPU",
        hovermode="closest",
        hoverdistance=40,
        hoverlabel=dict(namelength=-1),
        legend=dict(font=dict(size=12)),
        margin=dict(r=320),
        xaxis=dict(title="time", tickformat="%H:%M:%S", hoverformat="%H:%M:%S"),
        yaxis=dict(title="Total CPU %", rangemode="tozero"),
    )
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.write_html(output_path, post_script=_HOVER_BOLD_SCRIPT)


_HOVER_BOLD_SCRIPT = """
var graph = document.getElementById('{plot_id}');
var current = null;
var restyling = false;

function set_width(trace, width) {
    restyling = true;
    return Plotly.restyle(graph, {'line.width': width}, [trace]).then(function() {
        restyling = false;
    });
}

graph.on('plotly_hover', function(event_data) {
    if (restyling || !event_data || !event_data.points.length) {
        return;
    }
    var hovered = event_data.points[0].curveNumber;
    if (hovered === current) {
        return;
    }
    var previous = current;
    current = hovered;
    var pending = Promise.resolve();
    if (previous !== null) {
        pending = set_width(previous, 2);
    }
    pending.then(function() {
        return set_width(hovered, 5);
    });
});
graph.on('plotly_unhover', function() {
    if (restyling || current === null) {
        return;
    }
    var previous = current;
    current = null;
    set_width(previous, 2);
});
"""

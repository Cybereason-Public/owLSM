"""Sample owLSM CPU%, RSS and virtual memory once a second and plot them."""

import datetime
import hashlib
import os
import threading
import time
from pathlib import Path

import plotly.graph_objects as go

from globals import Numbers, Strings, log
from profiling_test import ProfilingTest


class ResourceGraphTest(ProfilingTest):
    def profile_start(self):
        log("profile_start")
        self._profiler = ResourceGraphProfiler()
        self._profiler.start(self._owlsm.pid, self.output_dir)

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
        if self._profiler is None:
            raise RuntimeError("resource graph profiler was not started")
        self._profiler.render()
        html = self.output_dir / Strings.RESOURCE_GRAPH_HTML
        if not html.is_file() or html.stat().st_size == 0:
            raise RuntimeError("resource graph was not written")
        log(f"wrote {html}")


class ResourceGraphProfiler:
    def __init__(self):
        self._pid = None
        self._output_dir = None
        self._thread = None
        self._stop_event = threading.Event()
        self._samples = []
        self._pressure_start = None
        self._pressure_end = None
        self._owlsm_sha256 = None
        self._clock_ticks = os.sysconf("SC_CLK_TCK")
        self._cpu_count = os.cpu_count()

    def start(self, pid, output_dir):
        self._pid = pid
        self._owlsm_sha256 = _sha256(Path(f"/proc/{pid}/exe"))
        log(f"owlsm sha256 {self._owlsm_sha256}")
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._sample_loop, name="resource-sampler", daemon=True)
        self._thread.start()

    def mark_pressure_start(self):
        self._pressure_start = time.time()

    def mark_pressure_end(self):
        self._pressure_end = time.time()

    def stop(self):
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=Numbers.RESOURCE_SAMPLER_STOP_TIMEOUT_SECONDS)

    def render(self):
        if not self._samples:
            raise RuntimeError("resource sampler collected no samples")
        times = [datetime.datetime.fromtimestamp(sample[0]) for sample in self._samples]
        rss_mb = [sample[1] for sample in self._samples]
        vsz_mb = [sample[2] for sample in self._samples]
        cpu_percent = [sample[3] for sample in self._samples]

        figure = go.Figure()
        figure.add_trace(go.Scatter(x=times, y=rss_mb, name="RSS (MB)", mode="lines", line=dict(width=2, color="#2a78d6")))
        figure.add_trace(go.Scatter(x=times, y=vsz_mb, name="Virtual memory (MB)", mode="lines", line=dict(width=2, color="#eb6834")))
        figure.add_trace(go.Scatter(x=times, y=cpu_percent, name="CPU % of machine", mode="lines", line=dict(width=2, color="#1baf7a"), yaxis="y2"))
        for mark_time, label in ((self._pressure_start, Strings.PRESSURE_START_LABEL), (self._pressure_end, Strings.PRESSURE_END_LABEL)):
            if mark_time is not None:
                figure.add_vline(
                    x=datetime.datetime.fromtimestamp(mark_time),
                    line_dash="dash",
                    line_color="gray",
                    annotation_text=label,
                )
        figure.update_layout(
            title="owLSM resource usage",
            hovermode="x unified",
            xaxis=dict(title="time", tickformat="%H:%M:%S", hoverformat="%H:%M:%S"),
            yaxis=dict(title="MB", rangemode="tozero"),
            yaxis2=dict(title="CPU % of machine", overlaying="y", side="right", rangemode="tozero"),
        )
        self._write_html(figure)

    def _write_html(self, figure):
        if not self._owlsm_sha256:
            raise RuntimeError("owlsm sha256 was not recorded")
        html = figure.to_html(full_html=True, include_plotlyjs=True)
        banner = (
            '<div style="font-family:sans-serif;padding:8px 16px;font-size:14px;'
            'background:#f4f4f4;border-bottom:1px solid #ccc;">'
            f"owlsm sha256: {self._owlsm_sha256}</div>\n"
        )
        plot_div = '<div style="height:100%; width:100%;">'
        if plot_div not in html:
            raise RuntimeError("resource graph HTML has no plot container")
        html = html.replace(plot_div, banner + '<div style="height:calc(100% - 36px); width:100%;">', 1)
        (self._output_dir / Strings.RESOURCE_GRAPH_HTML).write_text(html, encoding="utf-8")

    def _sample_loop(self):
        start = time.monotonic()
        previous = None
        index = 0
        while not self._stop_event.is_set():
            target = start + index * Numbers.RESOURCE_SAMPLE_INTERVAL_SECONDS
            remaining = target - time.monotonic()
            if remaining > 0 and self._stop_event.wait(remaining):
                break
            sample = _read_sample(self._pid)
            if sample is None:
                log("error: owlsm process disappeared, stopping resource sampling")
                break
            wall_time = time.time()
            rss_kb, vsz_kb, cpu_ticks = sample
            cpu_percent = None
            if previous is not None:
                previous_ticks, previous_wall = previous
                elapsed_seconds = wall_time - previous_wall
                cpu_seconds = (cpu_ticks - previous_ticks) / self._clock_ticks
                cpu_percent = cpu_seconds / (elapsed_seconds * self._cpu_count) * 100
            previous = (cpu_ticks, wall_time)
            self._samples.append((wall_time, rss_kb / 1024, vsz_kb / 1024, cpu_percent))
            index += 1


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as binary:
        while True:
            chunk = binary.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _read_sample(pid):
    status = _read_status(pid)
    cpu_ticks = _read_stat(pid)
    if status is None or cpu_ticks is None:
        return None
    rss_kb, vsz_kb = status
    return rss_kb, vsz_kb, cpu_ticks


def _read_status(pid):
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    values = {}
    for line in lines:
        if line.startswith("VmRSS:") or line.startswith("VmSize:"):
            key, rest = line.split(":", 1)
            values[key] = int(rest.split()[0])
    if "VmRSS" not in values or "VmSize" not in values:
        return None
    return values["VmRSS"], values["VmSize"]


def _read_stat(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    fields = text.rsplit(")", 1)[-1].split()
    if len(fields) < 13:
        return None
    utime = int(fields[11])
    stime = int(fields[12])
    return utime + stime

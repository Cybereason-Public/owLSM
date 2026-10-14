"""Sample owLSM RSS, virtual memory, and CPU, then write one HTML chart with plotly."""

import datetime
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path


KILOBYTE = 1024


@dataclass
class Sample:
    wall_time: float
    rss_mb: float
    virtual_mb: float
    cpu_percent: float | None


def process_cpu_ticks(stat_text):
    comm_end = stat_text.rfind(")")
    if comm_end < 0:
        raise RuntimeError("unrecognized /proc stat line")
    fields = stat_text[comm_end + 2 :].split()
    # Field 14 is utime and field 15 is stime. Field 3 is the first field after comm.
    if len(fields) < 13:
        raise RuntimeError("unrecognized /proc stat line")
    return int(fields[11]), int(fields[12])


def status_kilobytes(status_text, key):
    prefix = key + ":"
    for line in status_text.splitlines():
        if line.startswith(prefix):
            return int(line.split()[1])
    raise RuntimeError(f"{key} missing from /proc status")


def cpu_percent_of_machine(delta_ticks, clk_tck, delta_wall, cpu_count):
    if delta_wall <= 0 or cpu_count <= 0:
        return 0.0
    process_seconds = delta_ticks / clk_tck
    return 100.0 * process_seconds / (delta_wall * cpu_count)


def _read_proc(pid):
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    return status, stat


class ResourcesGraphSampler:
    def __init__(self, pid):
        self._pid = pid
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._samples = []
        self._pressure_start = None
        self._pressure_end = None
        self._thread = None
        self._error = None
        self._cpu_count = os.sysconf("SC_NPROCESSORS_ONLN")
        self._clk_tck = os.sysconf("SC_CLK_TCK")
        self._written = False

    def start(self):
        self._thread = threading.Thread(target=self._loop, name="resource-sample")
        self._thread.start()

    def mark_pressure_start(self):
        with self._lock:
            self._pressure_start = time.time()

    def mark_pressure_end(self):
        with self._lock:
            self._pressure_end = time.time()

    def raise_if_failed(self):
        with self._lock:
            error = self._error
        if error is not None:
            raise error

    def stop(self, output_path):
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        if not self._written:
            with self._lock:
                samples = list(self._samples)
                pressure_start = self._pressure_start
                pressure_end = self._pressure_end
            write_resources_graph(
                samples, pressure_start, pressure_end, self._cpu_count, Path(output_path)
            )
            self._written = True
        if self._error is not None:
            error = self._error
            self._error = None
            raise error

    def _loop(self):
        previous_ticks = None
        previous_mono = None
        started = time.monotonic()
        index = 0
        while not self._stop.is_set():
            delay = (started + index) - time.monotonic()
            if delay > 0 and self._stop.wait(delay):
                return
            try:
                sample, ticks, mono = self._take_sample(previous_ticks, previous_mono)
            except (FileNotFoundError, ProcessLookupError):
                self._fail(RuntimeError("owLSM exited while the resources graph was sampling"))
                return
            except Exception as error:
                self._fail(error)
                return
            with self._lock:
                self._samples.append(sample)
            previous_ticks = ticks
            previous_mono = mono
            index += 1

    def _fail(self, error):
        with self._lock:
            self._error = error if isinstance(error, RuntimeError) else RuntimeError(str(error))

    def _take_sample(self, previous_ticks, previous_mono):
        status_text, stat_text = _read_proc(self._pid)
        wall_time = time.time()
        mono = time.monotonic()
        rss_mb = status_kilobytes(status_text, "VmRSS") / KILOBYTE
        virtual_mb = status_kilobytes(status_text, "VmSize") / KILOBYTE
        utime, stime = process_cpu_ticks(stat_text)
        ticks = utime + stime
        cpu_percent = None
        if previous_ticks is not None:
            cpu_percent = cpu_percent_of_machine(
                ticks - previous_ticks,
                self._clk_tck,
                mono - previous_mono,
                self._cpu_count,
            )
        return Sample(wall_time, rss_mb, virtual_mb, cpu_percent), ticks, mono


def require_plotly():
    try:
        import plotly.graph_objects
        from plotly.subplots import make_subplots
    except ImportError as error:
        raise RuntimeError(
            "python3-plotly is not installed. Install it with: apt-get install -y python3-plotly"
        ) from error
    return plotly.graph_objects, make_subplots


def write_resources_graph(samples, pressure_start, pressure_end, cpu_count, output_path):
    graph_objects, make_subplots = require_plotly()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    times = [datetime.datetime.fromtimestamp(sample.wall_time) for sample in samples]
    figure = make_subplots(specs=[[{"secondary_y": True}]])
    figure.add_trace(
        graph_objects.Scatter(
            x=times,
            y=[sample.rss_mb for sample in samples],
            name="RSS MB",
            line={"color": "#0b6e4f"},
        ),
        secondary_y=False,
    )
    figure.add_trace(
        graph_objects.Scatter(
            x=times,
            y=[sample.virtual_mb for sample in samples],
            name="Virtual memory MB",
            line={"color": "#1d4e89"},
        ),
        secondary_y=False,
    )
    figure.add_trace(
        graph_objects.Scatter(
            x=times,
            y=[sample.cpu_percent for sample in samples],
            name="CPU % of machine",
            line={"color": "#c44900"},
            connectgaps=False,
        ),
        secondary_y=True,
    )
    figure.update_yaxes(title_text="MB", rangemode="tozero", secondary_y=False)
    figure.update_yaxes(title_text="CPU % of machine", rangemode="tozero", secondary_y=True)
    figure.update_xaxes(tickformat="%H:%M:%S", hoverformat="%H:%M:%S")
    figure.update_layout(
        title=f"owLSM resources ({cpu_count} CPUs)",
        hovermode="x unified",
        template="plotly_white",
    )
    for wall_time, name in ((pressure_start, "pressure start"), (pressure_end, "pressure end")):
        if wall_time is None:
            continue
        figure.add_vline(
            x=datetime.datetime.fromtimestamp(wall_time).isoformat(),
            line_dash="dash",
            line_color="#222",
            annotation_text=name,
        )
    figure.write_html(str(output_path), include_plotlyjs=True, full_html=True)



def self_check():
    stat_line = "1 (owlsm) R 0 1 1 0 -1 0 1 2 3 4 10 20 0 0"
    if process_cpu_ticks(stat_line) != (10, 20):
        raise AssertionError("utime/stime parse")
    status = "VmSize:\t   2048 kB\nVmRSS:\t   1024 kB\n"
    if status_kilobytes(status, "VmRSS") != 1024:
        raise AssertionError("VmRSS parse")
    percent = cpu_percent_of_machine(100, 100, 1.0, 8)
    if abs(percent - 12.5) > 0.001:
        raise AssertionError(percent)
    start = 1_700_000_000.0
    samples = [
        Sample(start, 10.0, 40.0, None),
        Sample(start + 1, 12.0, 41.0, 12.5),
        Sample(start + 2, 11.0, 41.0, 6.25),
    ]
    with tempfile.TemporaryDirectory() as directory:
        output_path = Path(directory) / "resources_graph.html"
        write_resources_graph(samples, start + 1, start + 2, 8, output_path)
        html = output_path.read_text(encoding="utf-8")
    for text in ("pressure start", "pressure end", "CPU % of machine", "RSS MB", "Virtual memory MB"):
        if text not in html:
            raise AssertionError(text)


if __name__ == "__main__":
    self_check()
    print("resources graph self-check passed")

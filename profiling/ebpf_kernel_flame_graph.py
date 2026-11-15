"""Record kernel perf samples and build a flame graph per bpf hook."""

import re
import shutil
import signal
import subprocess
import threading
from pathlib import Path

from globals import Numbers, Strings, log
from profiling_test import ProfilingTest


BPF_HOOKS = ("write", "rename", "chmod")
# JIT name: bpf_prog_<tag>_<hook>_hook or bpf_prog_<tag>_<hook>_hook_2
BPF_HOOK_PROG_FRAME = re.compile(
    r"^bpf_prog_[0-9a-f]+_(" + "|".join(BPF_HOOKS) + r")_hook(_2)?$"
)


class EbpfKernelFlameGraphTest(ProfilingTest):
    def profile_start(self):
        log("bpf hook kernel profile_start")
        self._profiler = BpfHookKernelFlameGraphProfiler()
        self._profiler.start(self.output_dir)

    def profile_stop(self):
        log("bpf hook kernel profile_stop")
        if self._profiler is not None:
            self._profiler.stop()

    def create_results(self):
        if self._profiler is None:
            raise RuntimeError("bpf hook kernel flame graph profiler was not started")
        self._profiler.render()
        for hook in BPF_HOOKS:
            svg = self.output_dir / Strings.BPF_HOOK_KERNEL_SVG.format(hook=hook)
            if not svg.is_file() or svg.stat().st_size == 0:
                raise RuntimeError(f"{hook} kernel flame graph was not written")
            _verify_svg(svg, hook)
            log(f"wrote {svg}")
        perf_data = self.output_dir / Strings.PERF_DATA
        if perf_data.exists():
            perf_data.unlink()


class BpfHookKernelFlameGraphProfiler:
    def __init__(self):
        self._process = None
        self._perf_data = None
        self._output_dir = None
        self._stopped = False

    def start(self, output_dir):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._perf_data = self._output_dir / Strings.PERF_DATA
        perf = _require_tool(Strings.PERF)
        self._process = subprocess.Popen(
            [
                perf, "record",
                "-a",
                "-g",
                "--call-graph", "fp",
                "-e", "cpu-clock:k",
                "-F", str(Numbers.EBPF_KERNEL_SAMPLE_FREQ),
                "--sample-cpu",
                "-o", str(self._perf_data),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        if self._process.poll() is not None:
            _stdout, stderr = self._process.communicate()
            self._stopped = True
            raise RuntimeError(f"perf record exited immediately:\n{stderr}")

    def stop(self):
        if self._stopped or self._process is None:
            return
        self._stopped = True
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
        trimmed_by_hook = _trim_to_bpf_hook_roots(folded_text)
        missing = [hook for hook in BPF_HOOKS if not trimmed_by_hook[hook]]
        if missing:
            names = ", ".join(f"bpf_prog_*{hook}_hook*" for hook in missing)
            raise RuntimeError(
                f"no kernel stacks contained {names}; "
                "check net.core.bpf_jit_kallsyms and that pressure ran during recording"
            )
        for hook in BPF_HOOKS:
            trimmed_text = _format_folded(trimmed_by_hook[hook])
            stacks_path = self._output_dir / Strings.BPF_HOOK_KERNEL_STACKS_FOLDED.format(hook=hook)
            stacks_path.write_text(trimmed_text, encoding="utf-8")
            _write_svg(
                trimmed_text,
                f"owLSM {hook}_hook / {hook}_hook_2 (kernel, aggregated)",
                self._output_dir / Strings.BPF_HOOK_KERNEL_SVG.format(hook=hook),
                flamegraph,
            )


def _trim_to_bpf_hook_roots(folded_text):
    aggregated = {hook: {} for hook in BPF_HOOKS}
    for line in folded_text.splitlines():
        if not line.strip():
            continue
        stack, count_text = line.rsplit(" ", 1)
        count = int(count_text)
        frames = stack.split(";")
        root_index = None
        hook = None
        for index, frame in enumerate(frames):
            match = BPF_HOOK_PROG_FRAME.match(frame)
            if match:
                root_index = index
                hook = match.group(1)
                break
        if root_index is None:
            continue
        key = ";".join(frames[root_index:])
        hook_stacks = aggregated[hook]
        hook_stacks[key] = hook_stacks.get(key, 0) + count
    return aggregated


def _fold_once(perf_data, stackcollapse):
    script = subprocess.Popen(
        [Strings.PERF, "script", "-i", str(perf_data)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    folded = subprocess.Popen(
        [stackcollapse],
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


def _verify_svg(svg_path, hook):
    text = svg_path.read_text(encoding="utf-8", errors="replace")
    if "<svg" not in text or "</svg>" not in text:
        raise RuntimeError(f"{svg_path} is not a valid SVG document")
    if f"{hook}_hook" not in text:
        raise RuntimeError(f"{svg_path} does not contain {hook}_hook stacks")


def _read_stream(stream, chunks):
    chunks.append(stream.read())


def _require_tool(name):
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"{name} was not found")
    return path

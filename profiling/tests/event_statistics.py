import json

from globals import Strings, log
from profiling_test import ProfilingTest


class EventStatistics(ProfilingTest):
    name = "EventStatistics"
    config_name = Strings.CONFIG_NO_RULE_MATCHES

    def run(self):
        log("run")
        self.pressure()
        if self._owlsm.poll() is not None:
            raise RuntimeError(f"owLSM exited during the run with status {self._owlsm.returncode}")

    def create_results(self):
        stats = self._read_profiler_stats()
        results_path = self.output_dir / Strings.EVENT_STATISTICS_JSON
        results_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        log(f"wrote {results_path}")

    def _read_profiler_stats(self):
        for path in self._profiler_log_paths():
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            label_index = text.rfind(Strings.PROFILER_STATS_LABEL)
            if label_index < 0:
                continue
            line_end = text.find("\n", label_index)
            if line_end < 0:
                line_end = len(text)
            json_text = text[label_index + len(Strings.PROFILER_STATS_LABEL):line_end]
            return json.loads(json_text)
        raise RuntimeError(
            f"owlsm logs have no '{Strings.PROFILER_STATS_LABEL.strip()}' line. Was owlsm built with make profiler?\n"
            + self._log_tail()
        )

    def _profiler_log_paths(self):
        paths = [Strings.OWLSM_LOG]
        for index in range(1, 6):
            paths.append(Strings.OWLSM_LOG.with_name(f"{Strings.OWLSM_LOG.name}.{index}"))
        return paths

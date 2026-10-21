from flame_graph import FlameGraphTest
from globals import Strings, log


class FlameGraphPressureYesMatches(FlameGraphTest):
    name = "FlameGraphPressureYesMatches"
    config_name = Strings.CONFIG_YES_RULE_MATCHES
    capture_events_log = False

    def run(self):
        log("run")
        self.profile_start()
        self.pressure()
        if self._owlsm.poll() is not None:
            raise RuntimeError(f"owLSM exited during the run with status {self._owlsm.returncode}")
        self.profile_stop()

    def create_results(self):
        super().create_results()
        if self.capture_events_log:
            self._verify_rule_matched()

    def _verify_rule_matched(self):
        log("verify rule matches")
        events_log = self.output_dir / Strings.OWLSM_EVENTS_LOG
        text = events_log.read_text(encoding="utf-8", errors="replace")
        matches = text.count(Strings.MATCHED_RULE_FIELD)
        if matches == 0:
            raise RuntimeError(f"no event in {events_log} matched the rule")
        log(f"{matches} events matched the rule")

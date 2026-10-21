import time

from flame_graph import FlameGraphTest
from globals import Numbers, Strings, log


class FlameGraphIdle(FlameGraphTest):
    name = "FlameGraphIdle"
    config_name = Strings.CONFIG_NO_RULE_MATCHES

    def run(self):
        log("run")
        self.profile_start()
        log(f"idle for {Numbers.IDLE_PROFILE_SECONDS}s")
        time.sleep(Numbers.IDLE_PROFILE_SECONDS)
        if self._owlsm.poll() is not None:
            raise RuntimeError(f"owLSM exited during the run with status {self._owlsm.returncode}")
        self.profile_stop()

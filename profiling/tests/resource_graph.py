import time

from globals import Numbers, Strings, log
from resource_graph import ResourceGraphTest


class ResourceGraph(ResourceGraphTest):
    name = "ResourceGraph"
    config_name = Strings.CONFIG_NO_RULE_MATCHES

    def run(self):
        log("run")
        self.profile_start()
        log(f"idle for {Numbers.RESOURCE_GRAPH_IDLE_SECONDS}s")
        time.sleep(Numbers.RESOURCE_GRAPH_IDLE_SECONDS)
        self.mark_pressure_start()
        self.pressure()
        self.mark_pressure_end()
        log(f"idle for {Numbers.RESOURCE_GRAPH_IDLE_SECONDS}s")
        time.sleep(Numbers.RESOURCE_GRAPH_IDLE_SECONDS)
        if self._owlsm.poll() is not None:
            raise RuntimeError(f"owLSM exited during the run with status {self._owlsm.returncode}")
        self.profile_stop()

from flame_graph import FlameGraphProfiler


FLAME_GRAPH_SECONDS = 120


class FlameGraphIdle:
    name = "Flame_Graph_Idle"

    def run(self, session):
        session.begin(self.name)
        try:
            owlsm = session.start_owlsm("no_rule_matches_config.json")
            FlameGraphProfiler(FLAME_GRAPH_SECONDS).record(owlsm.pid, session.output_dir)
            session.ensure_owlsm_running()
        finally:
            session.close()

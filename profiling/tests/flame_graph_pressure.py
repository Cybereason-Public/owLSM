from flame_graph import FlameGraphProfiler


FLAME_GRAPH_SECONDS = 120


class FlameGraphPressure:
    name = ""
    config_name = ""

    def run(self, session):
        session.begin(self.name)
        try:
            session.start_workloads_and_shell()
            owlsm = session.start_owlsm(self.config_name)
            session.start_signal_sender()
            FlameGraphProfiler(FLAME_GRAPH_SECONDS).record(owlsm.pid, session.output_dir)
            session.ensure_owlsm_running()
            session.signal_finish()
            session.wait_for_pressure_to_exit()
        finally:
            session.close()

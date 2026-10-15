import time

from resources_graph import ResourcesGraphSampler, require_plotly


IDLE_BEFORE_SECONDS = 60
PRESSURE_SECONDS = 120
IDLE_AFTER_SECONDS = 60


def _sleep_while_sampling(sampler, seconds):
    deadline = time.monotonic() + seconds
    while True:
        sampler.raise_if_failed()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


class ResourcesGraphRun:
    name = "resources_graph"

    def run(self, session):
        require_plotly()
        session.begin(self.name)
        sampler = None
        output_path = None
        try:
            owlsm = session.start_owlsm("rule_matches_config.json")
            output_path = session.output_dir / "resources_graph.html"
            sampler = ResourcesGraphSampler(owlsm.pid)
            sampler.start()
            _sleep_while_sampling(sampler, IDLE_BEFORE_SECONDS)
            session.start_workloads_and_shell()
            session.start_signal_sender()
            sampler.mark_pressure_start()
            _sleep_while_sampling(sampler, PRESSURE_SECONDS)
            sampler.mark_pressure_end()
            session.signal_finish()
            session.wait_for_pressure_to_exit()
            _sleep_while_sampling(sampler, IDLE_AFTER_SECONDS)
            session.ensure_owlsm_running()
            sampler.stop(output_path)
            sampler = None
        finally:
            if sampler is not None and output_path is not None:
                try:
                    sampler.stop(output_path)
                except RuntimeError as error:
                    print(f"[profiling] {error}", flush=True)
            session.close()

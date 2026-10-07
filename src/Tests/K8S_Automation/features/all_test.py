from pytest_bdd import scenario

from steps.event_steps import *
from steps.file_steps import *
from steps.log_steps import *
from steps.owlsm_steps import *
from steps.pod_steps import *


@scenario("owlsm_lifecycle.feature", "deploy_and_remove_owlsm_twice")
def test_deploy_and_remove_owlsm_twice():
    pass


@scenario("owlsm_host_events.feature", "host_chmod_event")
def test_host_chmod_event():
    pass


@scenario("owlsm_container_events.feature", "chmod in container that runs after owlsm is deployed")
def test_chmod_in_container_that_runs_after_owlsm_is_deployed():
    pass


@scenario("owlsm_container_events.feature", "chmod in container that runs before owlsm is deployed")
def test_chmod_in_container_that_runs_before_owlsm_is_deployed():
    pass


@scenario("owlsm_container_events.feature", "chmod event uses updated pod labels")
def test_chmod_event_uses_updated_pod_labels():
    pass


@scenario("owlsm_config.feature", "chmod event stops after helm disables chmod")
def test_chmod_event_stops_after_helm_disables_chmod():
    pass


_STRESS_RUNS = 10

_STRESS_SCENARIOS = (
    (
        "six pods start and exit without kubernetes mapping misses",
        "test_six_pods_start_and_exit_without_kubernetes_mapping_misses",
    ),
    (
        "chmod on one hundred pods that existed before owlsm started",
        "test_chmod_on_one_hundred_pods_that_existed_before_owlsm_started",
    ),
    (
        "container restart keeps the pod uid and updates the container id",
        "test_container_restart_keeps_the_pod_uid_and_updates_the_container_id",
    ),
)


def _repeat_stress_scenario(scenario_name: str, test_name: str, run_index: int):
    @scenario("owlsm_container_stress.feature", scenario_name)
    def stress_test():
        pass

    stress_test.__name__ = f"{test_name}_{run_index}"
    stress_test.__qualname__ = stress_test.__name__
    return stress_test


for _scenario_name, _test_name in _STRESS_SCENARIOS:
    for _run_index in range(1, _STRESS_RUNS + 1):
        _test_func = _repeat_stress_scenario(_scenario_name, _test_name, _run_index)
        globals()[_test_func.__name__] = _test_func

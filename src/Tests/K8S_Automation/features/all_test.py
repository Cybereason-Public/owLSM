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


@scenario("ignore_events.feature", "owlsm ignores kube-system events by default")
def test_owlsm_ignores_kube_system_events_by_default():
    pass


@scenario(
    "ignore_events.feature",
    "owlsm always ignores owlsm pod events that are not part of the owlsm process tree",
)
def test_owlsm_always_ignores_owlsm_pod_events_that_are_not_part_of_the_owlsm_process_tree():
    pass


@scenario("ignore_events.feature", "owlsm ignores host events")
def test_owlsm_ignores_host_events():
    pass


@scenario("ignore_events.feature", "owlsm ignores preexisting kube-system pods and host events")
def test_owlsm_ignores_preexisting_kube_system_pods_and_host_events():
    pass


@scenario(
    "owlsm_container_stress.feature",
    "six pods start and exit without kubernetes mapping misses",
)
def test_six_pods_start_and_exit_without_kubernetes_mapping_misses():
    pass


@scenario(
    "owlsm_container_stress.feature",
    "chmod on one hundred pods that existed before owlsm started",
)
def test_chmod_on_one_hundred_pods_that_existed_before_owlsm_started():
    pass


@scenario(
    "owlsm_container_stress.feature",
    "container restart keeps the pod uid and updates the container id",
)
def test_container_restart_keeps_the_pod_uid_and_updates_the_container_id():
    pass

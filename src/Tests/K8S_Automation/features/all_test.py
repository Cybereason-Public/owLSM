from pytest_bdd import scenario

from steps.event_steps import *
from steps.file_steps import *
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

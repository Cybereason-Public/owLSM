import time

from pytest_bdd import given, parsers, then, when

from Utils.cluster_utils import (
    delete_manifest,
    deploy_manifest,
    deploy_test_pod,
    ensure_pod_uid_unchanged_and_container_id_changed,
    get_pod,
    patch_test_pod_labels,
    remove_test_pod,
    restart_pod,
)
from Utils.logger_utils import logger


@given("I deploy the test_pod")
@when("I deploy the test_pod")
@then("I deploy the test_pod")
def i_deploy_the_test_pod():
    logger.log_info("Deploying the test_pod")
    deploy_test_pod()


@given("I remove the test_pod")
@when("I remove the test_pod")
@then("I remove the test_pod")
def i_remove_the_test_pod():
    logger.log_info("Removing the test_pod")
    remove_test_pod()


@given("I change the test_pod labels:")
@when("I change the test_pod labels:")
@then("I change the test_pod labels:")
def i_change_the_test_pod_labels(datatable):
    labels = {row[0].strip(): row[1].strip() for row in datatable}
    logger.log_info(f"Changing the test_pod labels: {labels}")
    patch_test_pod_labels(labels)


@given(parsers.parse('I sleep for "{seconds}" seconds'))
@when(parsers.parse('I sleep for "{seconds}" seconds'))
@then(parsers.parse('I sleep for "{seconds}" seconds'))
def i_sleep_for_seconds(seconds):
    logger.log_info(f"Sleeping for {seconds} seconds")
    time.sleep(int(seconds))


@given(parsers.parse('I deploy the manifest "{name}"'))
@when(parsers.parse('I deploy the manifest "{name}"'))
@then(parsers.parse('I deploy the manifest "{name}"'))
def i_deploy_the_manifest(name):
    logger.log_info(f"Deploying manifest {name}")
    deploy_manifest(name)


@given(parsers.parse('I delete the manifest "{name}"'))
@when(parsers.parse('I delete the manifest "{name}"'))
@then(parsers.parse('I delete the manifest "{name}"'))
def i_delete_the_manifest(name):
    logger.log_info(f"Deleting manifest {name}")
    delete_manifest(name)


@given(parsers.parse('I restart pod "{alias}" by killing its init pid and its uid stays the same while its container id changes'))
@when(parsers.parse('I restart pod "{alias}" by killing its init pid and its uid stays the same while its container id changes'))
@then(parsers.parse('I restart pod "{alias}" by killing its init pid and its uid stays the same while its container id changes'))
def i_restart_pod_by_killing_its_init_pid_and_its_uid_stays_the_same_while_its_container_id_changes(alias):
    pod = get_pod(alias)
    previous_uid = pod.uid
    previous_container_id = pod.container_id
    restart_pod(alias)
    ensure_pod_uid_unchanged_and_container_id_changed(alias, previous_uid, previous_container_id)

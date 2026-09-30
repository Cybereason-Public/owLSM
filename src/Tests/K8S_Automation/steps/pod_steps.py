import time

from pytest_bdd import given, parsers, then, when

from Utils.cluster_utils import deploy_test_pod, patch_test_pod_labels, remove_test_pod
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

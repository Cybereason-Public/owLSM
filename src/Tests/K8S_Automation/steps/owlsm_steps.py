from pytest_bdd import given, when, then

from Utils.logger_utils import logger
from Utils.owlsm_utils import (
    deploy_owlsm_and_ensure_running,
    is_owlsm_deployed_cluster_wide,
    is_owlsm_process_absent_on_all_nodes,
    remove_owlsm,
    upgrade_owlsm_values_and_ensure_running,
    wait_until_owlsm_process_running_on_all_nodes,
)
from globals.global_strings import global_strings


@given("owlsm is deployed cluster wide")
@when("owlsm is deployed cluster wide")
@then("owlsm is deployed cluster wide")
def owlsm_is_deployed_cluster_wide():
    if is_owlsm_deployed_cluster_wide() and wait_until_owlsm_process_running_on_all_nodes():
        return
    logger.log_info("Deploying owlsm cluster wide")
    deploy_owlsm_and_ensure_running(
        global_strings.OWLSM_IMAGE_REPOSITORY,
        global_strings.OWLSM_IMAGE_TAG,
    )


@given("I remove owlsm from the cluster")
@when("I remove owlsm from the cluster")
@then("I remove owlsm from the cluster")
def i_remove_owlsm_from_the_cluster():
    if is_owlsm_deployed_cluster_wide() or not is_owlsm_process_absent_on_all_nodes():
        logger.log_info("Removing owlsm from the cluster")
        remove_owlsm()
    still_present = is_owlsm_deployed_cluster_wide() or not is_owlsm_process_absent_on_all_nodes()
    assert not still_present, "owlsm is still deployed or still running on a node"


@given("I change owlsm helm values:")
@when("I change owlsm helm values:")
@then("I change owlsm helm values:")
def i_change_owlsm_helm_values(datatable):
    values = {row[0].strip(): row[1].strip() for row in datatable}
    logger.log_info(f"Changing owlsm helm values: {values}")
    upgrade_owlsm_values_and_ensure_running(values)

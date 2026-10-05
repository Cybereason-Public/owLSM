import os

import pytest

from Utils.cluster_utils import (
    cleanup_cluster_objects,
    close_cluster_ssh,
    create_kind_cluster,
    delete_kind_cluster,
    deploy_test_pod,
    forget_manifest_pods,
    ensure_connection_to_cluster,
    init_global_cluster_object,
    load_owlsm_runtime_local_image_into_kind,
    should_load_owlsm_runtime_local_image_into_kind,
)
from Utils.log_utils import clear_owlsm_log_and_output, remove_old_log_directories, save_log_files
from Utils.logger_utils import logger
from Utils.owlsm_utils import (
    deploy_owlsm_and_ensure_running,
    is_owlsm_deployed_cluster_wide,
    remove_leftover_cluster_objects,
    start_owlsm_stdout_reader,
)
from globals.global_objects import global_objects
from globals.global_strings import global_strings


@pytest.fixture(scope="function")
def scenario_context():
    return {}


def pytest_configure(config):
    logger.log_info("pytest_configure")


def pytest_sessionstart(session):
    if session.config.option.collectonly:
        logger.log_info("pytest_sessionstart skipped (collect-only)")
        return
    logger.log_info("pytest_sessionstart")
    global_objects.PYTEST_SESSION_PID = os.getpid()
    if global_strings.CLUSTER_TYPE == global_strings.KIND:
        create_kind_cluster()
        if should_load_owlsm_runtime_local_image_into_kind():
            load_owlsm_runtime_local_image_into_kind()
        else:
            logger.log_info(
                f"OWLSM image is GHCR; skipping {global_strings.KIND} load, {global_strings.KIND} nodes will pull it"
            )
    elif global_strings.CLUSTER_TYPE == global_strings.OCI:
        logger.log_info(
            f"CLUSTER_TYPE={global_strings.OCI}; skipping {global_strings.KIND} create and {global_strings.KIND} load"
        )
    else:
        raise RuntimeError(
            f"unsupported OWLSM_CLUSTER_TYPE={global_strings.CLUSTER_TYPE}"
        )
    ensure_connection_to_cluster()
    init_global_cluster_object()
    remove_leftover_cluster_objects()
    deploy_test_pod()
    deploy_owlsm_and_ensure_running(
        global_strings.OWLSM_IMAGE_REPOSITORY,
        global_strings.OWLSM_IMAGE_TAG,
    )


def pytest_sessionfinish(session, exitstatus):
    if session.config.option.collectonly:
        return
    if (
        global_objects.PYTEST_SESSION_PID is not None
        and os.getpid() != global_objects.PYTEST_SESSION_PID
    ):
        os._exit(0)
    logger.log_info("pytest_sessionfinish")
    _run_cleanup_step("remove_leftover_cluster_objects", remove_leftover_cluster_objects)
    _run_cleanup_step("remove_old_log_directories", remove_old_log_directories)
    if global_strings.CLUSTER_TYPE == global_strings.KIND:
        _run_cleanup_step("delete_kind_cluster", delete_kind_cluster)
    elif global_strings.CLUSTER_TYPE == global_strings.OCI:
        logger.log_info(f"CLUSTER_TYPE={global_strings.OCI}; skipping {global_strings.KIND} delete")
        _run_cleanup_step("close_cluster_ssh", close_cluster_ssh)
    else:
        _run_cleanup_step("close_cluster_ssh", close_cluster_ssh)


def pytest_bdd_before_scenario(request, feature, scenario):
    try:
        clear_owlsm_log_and_output()
        if is_owlsm_deployed_cluster_wide():
            start_owlsm_stdout_reader()
        logger.log_info(f"BEFORE scenario: '{scenario.name}' in feature: '{feature.name}'")
    except Exception as e:
        logger.log_error(f"Failed to clear scenario logs: {e}")
        assert False, f"Failed to clear scenario logs: {e}"


def pytest_bdd_after_scenario(request, feature, scenario):
    logger.log_info(f"AFTER scenario: '{scenario.name}' in feature: '{feature.name}'")
    save_log_files(scenario.name)
    cleanup_cluster_objects()
    forget_manifest_pods()


def pytest_bdd_before_step(request, feature, scenario, step, step_func):
    logger.log_info(f"BEFORE step: '{step.name}' in scenario: '{scenario.name}'")


def pytest_bdd_after_step(request, feature, scenario, step, step_func, step_func_args):
    logger.log_info(f"AFTER step: '{step.name}' in scenario: '{scenario.name}'")


def _run_cleanup_step(name: str, func) -> None:
    try:
        func()
    except Exception as e:
        logger.log_error(f"{name} failed during session finish: {e}")

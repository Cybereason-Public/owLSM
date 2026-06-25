import pytest
from pytest_bdd import given, when, then
from Utils.logger_utils import logger
from Utils.process_utils import *
from Utils.user_utils import *
from globals.system_related_globals import system_globals
from state_db.file_db import file_db
from state_db.process_db import process_db
from Utils.distro_utils import get_distro_type, DistroType
from common_steps.bdd_conftest_extentions import *

@pytest.fixture(scope="function")
def scenario_context():
    """Fresh dict for each scenario (test)."""
    return {}

def pytest_configure(config):
    logger.log_info("pytest_configure")


def pytest_collection_modifyitems(config, items):
    distro = get_distro_type()
    if distro == DistroType.DEB:
        return

    dash_suffix = "dash-dash]"
    remaining = []
    for item in items:
        if item.nodeid.endswith(dash_suffix):
            logger.log_info(f"Deselecting DASH test (not .deb distro): {item.nodeid}")
        else:
            remaining.append(item)

    items[:] = remaining

def pytest_sessionstart(session):
    logger.log_info("pytest_sessionstart")
    system_globals.PYTEST_SESSION_PID = os.getpid()
    ensure_automation_running_as_root()
    assert create_local_user(system_globals.USER_NAME, system_globals.PASSWORD), f"Failed to create {system_globals.USER_NAME} user"
    assert create_local_user(system_globals.NO_SUDO_USER_NAME, system_globals.NO_SUDO_PASSWORD), f"Failed to create {system_globals.NO_SUDO_USER_NAME} user"
    add_user_to_group(system_globals.USER_NAME, "sudo")
    start_owlsm_process(f"{system_globals.OWLSM_PATH} -c {system_globals.RESOURCES_PATH / 'config.json'}")


def pytest_sessionfinish(session, exitstatus):
    if system_globals.PYTEST_SESSION_PID is not None and os.getpid() != system_globals.PYTEST_SESSION_PID:
        os._exit(0)
    logger.log_info("pytest_sessionfinish")
    stop_owlsm_process()
    delete_user(system_globals.USER_NAME)
    delete_user(system_globals.NO_SUDO_USER_NAME)
    session_cleanup()
    remove_old_log_directories()


def pytest_bdd_before_scenario(request, feature, scenario):
    try:
        if system_globals.LOG_PATH.exists():
            with open(system_globals.LOG_PATH, 'w') as f:
                f.truncate(0)
        logger.log_info(f"BEFORE scenario: '{scenario.name}' in feature: '{feature.name}'")

        if system_globals.OWLSM_OUTPUT_LOG.exists():
            fd = system_globals.OWLSM_OUTPUT_LOG_FD.fileno()
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            logger.log_info(f"Cleared content of OWLSM output log: {system_globals.OWLSM_OUTPUT_LOG}")
        run_command_sync("echo 'first event'")
            
    except Exception as e:
        logger.log_error(f"Failed to clear OWLSM output log content: {e}")
        assert False, f"Failed to clear OWLSM output log content: {e}"


def pytest_bdd_after_scenario(request, feature, scenario):
    logger.log_info(f"AFTER scenario: '{scenario.name}' in feature: '{feature.name}'")
    file_paths = file_db.get_all()
    for path in file_paths:
        try:
            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
        except Exception as e:
            logger.log_error(f"Failed to cleanup file/dir '{path}': {e}")
    
    process_entries = process_db.get_all()
    for pid, start_time in process_entries:
        try:
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                if abs(process.create_time() - start_time) < 3.0:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                else:
                    logger.log_warning(f"PID {pid} exists but start time mismatch - skipping cleanup")
        except Exception as e:
            logger.log_error(f"Failed to cleanup process PID {pid}: {e}")
    
    file_db.remove_all()
    process_db.remove_all()

    save_log_files(scenario.name)



def pytest_bdd_before_step(request, feature, scenario, step, step_func):
    logger.log_info(f"BEFORE step: '{step.name}' in scenario: '{scenario.name}'")


def pytest_bdd_after_step(request, feature, scenario, step, step_func, step_func_args):
    logger.log_info(f"AFTER step: '{step.name}' in scenario: '{scenario.name}'")
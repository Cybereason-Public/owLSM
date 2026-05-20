from pytest_bdd import given, when, then, parsers, scenarios
import subprocess
from globals.system_related_globals import system_globals
from Utils.process_utils import *
from Utils.logger_utils import logger
import psutil
import os
import pwd
import json
from globals.global_strings import global_strings
from state_db.file_db import file_db

@given(parsers.parse('I run the command "{command}" sync'))
@when(parsers.parse('I run the command "{command}" sync'))
@then(parsers.parse('I run the command "{command}" sync'))
def I_run_the_command_sync(command):
    assert run_command_sync(command), f"Failed to run command: {command}"


@given(parsers.parse('I run the command "{command}" async'))
@when(parsers.parse('I run the command "{command}" async'))
@then(parsers.parse('I run the command "{command}" async'))
def I_run_the_command_async(command):
    assert run_command_async(command), f"Failed to run command: {command}"


@given(parsers.parse('I run the command "{command}" and ensure it runs for at least "{duration}" seconds'))
@when(parsers.parse('I run the command "{command}" and ensure it runs for at least "{duration}" seconds'))
@then(parsers.parse('I run the command "{command}" and ensure it runs for at least "{duration}" seconds'))
def I_run_the_command_and_ensure_it_runs_for_at_least_duration_seconds(command, duration):
    assert ensure_async_command_runs_for_at_least_seconds(command, duration), f"Failed to run command: {command}"


@given(parsers.parse('I run the command "{command}" sync as grandchild'))
@when(parsers.parse('I run the command "{command}" sync as grandchild'))
@then(parsers.parse('I run the command "{command}" sync as grandchild'))
def I_run_the_command_sync_as_grandchild(command):
    run_command_sync_as_grandchild(command)


@given(parsers.parse('I run the command "{command}" sync as grandchild as user "{user}"'))
@when(parsers.parse('I run the command "{command}" sync as grandchild as user "{user}"'))
@then(parsers.parse('I run the command "{command}" sync as grandchild as user "{user}"'))
def I_run_the_command_sync_as_grandchild_as_user(command, user):
    try:
        pwd.getpwnam(user)
    except KeyError:
        assert False, f"User '{user}' does not exist"
    run_command_sync_as_grandchild(command, user=user)


@given("The owLSM process is running")
@when("The owLSM process is running")
@then("The owLSM process is running")
def the_owlsm_process_is_running():
    assert system_globals.OWLSM_PROCESS_OBJECT is not None, "OWLSM process is None"
    assert is_subprocess_running(system_globals.OWLSM_PROCESS_OBJECT), "OWLSM process is not running"


@given("The owLSM process is not running")
@when("The owLSM process is not running")
@then("The owLSM process is not running")
def the_owlsm_process_is_not_running():
    proc = system_globals.OWLSM_PROCESS_OBJECT
    if proc is None:
        return
    if not is_subprocess_running(proc):
        system_globals.OWLSM_PROCESS_OBJECT = None
        return
    assert False, "OWLSM process is still running"

@given(parsers.parse('I fork and child exits with code "{code}"'))
@when(parsers.parse('I fork and child exits with code "{code}"'))
@then(parsers.parse('I fork and child exits with code "{code}"'))
def I_fork_and_child_exits_with_code(code):
    code = int(code)
    pid = fork_current_process()
    if pid == 0:
        os._exit(code)
    else:
        _, status = os.waitpid(pid, 0)
        exit_code = os.WEXITSTATUS(status)
        logger.log_info(f"Child exited with code {exit_code}, expected {code}")
        assert exit_code == code, f"Child exited with code {exit_code}, expected {code}"


@given(parsers.parse('I run sudo and succeed "{success}"'))
@when(parsers.parse('I run sudo and succeed "{success}"'))
@then(parsers.parse('I run sudo and succeed "{success}"'))
def I_run_sudo_and_succeed(success):
    if success.lower() == "true":
        success = True
    elif success.lower() == "false":
        success = False
    else:
        assert False, f"Invalid success value: {success}"

    proc = None
    try:
        stdout = None
        stderr = None
        proc = subprocess.Popen(['/usr/bin/sudo', '-k', '-S', '-p', '', 'whoami'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, user=system_globals.USER_NAME)
        if success == True:
            stdout, stderr = proc.communicate(input=system_globals.PASSWORD, timeout=3) # TODO: user needs to be specified in sudoers file. The %sudo group alone didn't work.
        else:
            stdout, stderr = proc.communicate(input='wrong_password\n', timeout=3)
        logger.log_info(f"command: '/usr/bin/sudo -k -S -p \"\" whoami'\nstdout: {stdout}\nstderr: {stderr}, exit code: {proc.returncode}")
        
        if success == True:
            assert proc.returncode == 0, f"Expected sudo to succeed but got exit code {proc.returncode}"
        else:
            assert proc.returncode != 0, f"Expected sudo to fail but got exit code {proc.returncode}"
    except Exception as e:
        if success:
            logger.log_error(f"Failed to run sudo and succeed: {e}")
            assert False, f"Failed to run sudo and succeed: {e}"
    finally:
        if proc:
            proc.terminate()
            

@given(parsers.parse('I run the resource "{resource}" with arguments "{arguments}" sync'))
@when(parsers.parse('I run the resource "{resource}" with arguments "{arguments}" sync'))
@then(parsers.parse('I run the resource "{resource}" with arguments "{arguments}" sync'))
def I_run_the_resource_with_arguments_sync(resource, arguments):
    resource_path = system_globals.RESOURCES_PATH / resource
    full_command = f"{resource_path} {arguments}"
    assert run_command_sync(full_command), f"Failed to run resource: {resource} with arguments: {arguments}"


@given(parsers.re(r'I run the resource "(?P<resource>[^"]*)" with arguments "(?P<arguments>[^"]*)" async and save pid'))
@when(parsers.re(r'I run the resource "(?P<resource>[^"]*)" with arguments "(?P<arguments>[^"]*)" async and save pid'))
@then(parsers.re(r'I run the resource "(?P<resource>[^"]*)" with arguments "(?P<arguments>[^"]*)" async and save pid'))
def I_run_the_resource_with_arguments_async_and_save_pid(resource, arguments, scenario_context):
    resource_path = system_globals.RESOURCES_PATH / resource
    full_command = f"{resource_path} {arguments}"
    proc = run_command_async(full_command)
    if proc is None:
        assert False, f"Failed to run resource: {resource} with arguments: {arguments}"
    scenario_context[global_strings.RESOURCE_PID] = proc.pid
    scenario_context[f"resource_proc_{resource}"] = proc
    logger.log_info(f"Saved scenario_context[{global_strings.RESOURCE_PID}] is {scenario_context[global_strings.RESOURCE_PID]}")


@given(parsers.parse('I run flatbuffer_reader async for "{stream}" stream and save pid'))
@when(parsers.parse('I run flatbuffer_reader async for "{stream}" stream and save pid'))
@then(parsers.parse('I run flatbuffer_reader async for "{stream}" stream and save pid'))
def I_run_flatbuffer_reader_async_for_stream_and_save_pid(stream, scenario_context):
    stream_lower = stream.strip().lower()
    if stream_lower == "events":
        bin_path = system_globals.AUTOMATION_ROOT_DIR / "owLSM_output_events.bin"
    elif stream_lower == "errors":
        bin_path = system_globals.AUTOMATION_ROOT_DIR / "owLSM_output_errors.bin"
    else:
        assert False, f"Unknown flatbuffer stream '{stream}', expected events or errors"

    log_path = system_globals.OWLSM_OUTPUT_LOG
    arguments = f"{bin_path} {log_path}"
    I_run_the_resource_with_arguments_async_and_save_pid("flatbuffer_reader/flatbuffer_reader", arguments, scenario_context)


@given("I start the owLSM process with flatbuffers output")
@when("I start the owLSM process with flatbuffers output")
@then("I start the owLSM process with flatbuffers output")
def I_start_the_owlsm_process_with_flatbuffers_output():
    config_path = system_globals.RESOURCES_PATH / "flatbuffers_config.json"
    command = f"{system_globals.OWLSM_PATH} -c {config_path}"
    start_owlsm_with_flatbuffer_binary_streams(command)


@given("I check that the async resource process is still running")
@when("I check that the async resource process is still running")
@then("I check that the async resource process is still running")
def I_check_that_the_async_resource_process_is_still_running(scenario_context):
    pid = scenario_context.get(global_strings.RESOURCE_PID)
    assert pid is not None, "No resource PID saved in scenario context"
    if not psutil.pid_exists(pid):
        assert False, f"Resource process {pid} is not running"
    proc = psutil.Process(pid)
    stored_start = process_db.get(pid)
    if stored_start is not None and abs(proc.create_time() - stored_start) > 3.0:
        assert False, f"PID {pid} was reused (start time mismatch)"
    assert proc.is_running(), f"Resource process {pid} is not running"


@given("I stop the owLSM process")
@when("I stop the owLSM process")
@then("I stop the owLSM process")
def I_stop_the_owlsm_process():
    stop_owlsm_process()


@given("I start the owLSM process")
@when("I start the owLSM process")
@then("I start the owLSM process")
def I_start_the_owlsm_process():
    start_owlsm_process(f"{system_globals.OWLSM_PATH} -c {system_globals.RESOURCES_PATH / 'config.json'}")


@given("I start the owLSM process with config via stdin")
@when("I start the owLSM process with config via stdin")
@then("I start the owLSM process with config via stdin")
def I_start_the_owlsm_process_with_config_via_stdin():
    start_owlsm_process_with_stdin(str(system_globals.RESOURCES_PATH / 'config.json'))


@given(parsers.parse('I start the owLSM process with config file "{config_file}"'))
@when(parsers.parse('I start the owLSM process with config file "{config_file}"'))
@then(parsers.parse('I start the owLSM process with config file "{config_file}"'))
def I_start_the_owlsm_process_with_config_file(config_file):
    config_path = system_globals.RESOURCES_PATH / config_file
    custom_log_path = None
    try:
        with open(config_path) as f:
            custom_log_path = json.load(f).get("userspace", {}).get("log_location")
    except Exception:
        pass
    start_owlsm_process(f"{system_globals.OWLSM_PATH} -c {config_path}", custom_log_path=custom_log_path)


@given(parsers.parse('I start owLSM and ignore the resource pid'))
@when(parsers.parse('I start owLSM and ignore the resource pid'))
@then(parsers.parse('I start owLSM and ignore the resource pid'))
def I_start_owlsm_and_ignore_the_resource_pid(scenario_context):
    resource_pid = scenario_context[global_strings.RESOURCE_PID]
    logger.log_info(f"from scenario_context[{global_strings.RESOURCE_PID}] we got {resource_pid}")
    start_owlsm_process(f"{system_globals.OWLSM_PATH} -c {system_globals.RESOURCES_PATH / 'config.json'} -e {resource_pid}")


@given(parsers.parse('I run shell command "{command}" with shell "{shell_path}" and timeout "{timeout}" and save shell pid'))
@when(parsers.parse('I run shell command "{command}" with shell "{shell_path}" and timeout "{timeout}" and save shell pid'))
@then(parsers.parse('I run shell command "{command}" with shell "{shell_path}" and timeout "{timeout}" and save shell pid'))
def I_run_shell_command_with_shell_timeout_and_save_shell_pid(command, shell_path, timeout, scenario_context):
    success, shell_pid = run_shell_commands_sync(shell_path, command, timeout=int(timeout))
    assert success, f"Failed to run shell command: {command} with shell: {shell_path} (timeout: {timeout}s)"
    scenario_context[global_strings.SHELL_PID] = shell_pid
    logger.log_info(f"Saved scenario_context[{global_strings.SHELL_PID}] is {scenario_context[global_strings.SHELL_PID]}")

@given(parsers.parse('I run shell command "{command}" with shell "{shell_path}" and save shell pid'))
@when(parsers.parse('I run shell command "{command}" with shell "{shell_path}" and save shell pid'))
@then(parsers.parse('I run shell command "{command}" with shell "{shell_path}" and save shell pid'))
def I_run_shell_command_with_shell_and_save_shell_pid(command, shell_path, scenario_context):
    success, shell_pid = run_shell_commands_sync(shell_path, command)
    assert success, f"Failed to run shell command: {command} with shell: {shell_path}"
    scenario_context[global_strings.SHELL_PID] = shell_pid
    logger.log_info(f"Saved scenario_context[{global_strings.SHELL_PID}] is {scenario_context[global_strings.SHELL_PID]}")


@given(parsers.parse('I run shell commands with shell "{shell_path}" and save shell pid:'))
@when(parsers.parse('I run shell commands with shell "{shell_path}" and save shell pid:'))
@then(parsers.parse('I run shell commands with shell "{shell_path}" and save shell pid:'))
def I_run_shell_commands_with_shell_and_save_shell_pid(shell_path, datatable, scenario_context):
    commands = [row[0].strip() for row in datatable]
    success, shell_pid = run_shell_commands_sync(shell_path, commands)
    assert success, f"Failed to run shell commands: {commands} with shell: {shell_path}"
    scenario_context[global_strings.SHELL_PID] = shell_pid
    logger.log_info(f"Saved scenario_context[{global_strings.SHELL_PID}] is {scenario_context[global_strings.SHELL_PID]}")


@given(parsers.parse('I spawn a persistent shell "{shell_path}" and save it'))
@when(parsers.parse('I spawn a persistent shell "{shell_path}" and save it'))
@then(parsers.parse('I spawn a persistent shell "{shell_path}" and save it'))
def I_spawn_persistent_shell_and_save_it(shell_path, scenario_context):
    child, shell_pid = spawn_persistent_shell(shell_path)
    assert child is not None, f"Failed to spawn persistent shell: {shell_path}"
    scenario_context[global_strings.PERSISTENT_SHELL] = child
    scenario_context[global_strings.SHELL_PID] = shell_pid
    logger.log_info(f"Spawned persistent shell: {shell_path}, saved to scenario_context[{global_strings.PERSISTENT_SHELL}], pid={shell_pid}")


@given(parsers.parse('I send command "{command}" to the persistent shell'))
@when(parsers.parse('I send command "{command}" to the persistent shell'))
@then(parsers.parse('I send command "{command}" to the persistent shell'))
def I_send_command_to_persistent_shell(command, scenario_context):
    child = scenario_context.get(global_strings.PERSISTENT_SHELL)
    assert child is not None, "No persistent shell found in scenario_context"
    success = send_command_to_shell(child, command)
    assert success, f"Failed to send command to persistent shell: {command}"


@given(parsers.parse('I sleep for "{seconds}" seconds'))
@when(parsers.parse('I sleep for "{seconds}" seconds'))
@then(parsers.parse('I sleep for "{seconds}" seconds'))
def I_sleep_for_seconds(seconds):
    time.sleep(int(seconds))
    logger.log_info(f"Slept for {seconds} seconds")


def _build_anti_tampering_command(name1, name2, config_filename, scenario_context):
    pids = [os.getpid()]  # always protect the automation process so it can stop owLSM
    for name in [name1, name2]:
        if name and name.lower() != "none":
            res_proc = scenario_context.get(f"resource_proc_{name}")
            assert res_proc is not None, f"No proc saved for named resource '{name}'"
            pids.append(res_proc.pid)
    p_flags = " ".join(f"-p {pid}" for pid in pids)
    config = system_globals.RESOURCES_PATH / config_filename
    return f"{system_globals.OWLSM_PATH} -c {config} {p_flags}".strip()


@given(parsers.parse('I start owLSM with anti_tampering config and protect the programs "{name1}" and "{name2}"'))
@when(parsers.parse('I start owLSM with anti_tampering config and protect the programs "{name1}" and "{name2}"'))
@then(parsers.parse('I start owLSM with anti_tampering config and protect the programs "{name1}" and "{name2}"'))
def I_start_owlsm_with_anti_tampering_config(name1, name2, scenario_context):
    command = _build_anti_tampering_command(name1, name2, "anti_tampering_config.json", scenario_context)
    start_owlsm_process(command)


@given(parsers.parse('I start owLSM with anti_tampering flatbuffers config and protect the programs "{name1}" and "{name2}"'))
@when(parsers.parse('I start owLSM with anti_tampering flatbuffers config and protect the programs "{name1}" and "{name2}"'))
@then(parsers.parse('I start owLSM with anti_tampering flatbuffers config and protect the programs "{name1}" and "{name2}"'))
def I_start_owlsm_with_anti_tampering_flatbuffers_config(name1, name2, scenario_context):
    command = _build_anti_tampering_command(name1, name2, "anti_tampering_flatbuffers_config.json", scenario_context)
    start_owlsm_with_flatbuffer_binary_streams(command)


@given(parsers.parse('I write "{data}" to the resource "{resource}" process stdin'))
@when(parsers.parse('I write "{data}" to the resource "{resource}" process stdin'))
@then(parsers.parse('I write "{data}" to the resource "{resource}" process stdin'))
def I_write_to_resource_stdin(data, resource, scenario_context):
    proc = scenario_context.get(f"resource_proc_{resource}")
    assert proc is not None, f"No proc saved for resource '{resource}' in scenario_context"
    proc.stdin.write(data + "\n")
    proc.stdin.flush()
    logger.log_info(f"Wrote '{data}' to resource '{resource}' (pid={proc.pid}) stdin")


@given(parsers.parse('I ensure the resource "{resource}" subprocess has exited'))
@when(parsers.parse('I ensure the resource "{resource}" subprocess has exited'))
@then(parsers.parse('I ensure the resource "{resource}" subprocess has exited'))
def I_ensure_the_resource_subprocess_has_exited(resource, scenario_context):
    proc = scenario_context.get(f"resource_proc_{resource}")
    assert proc is not None, f"No subprocess saved for resource '{resource}'"
    assert not is_subprocess_running(proc), \
        f"Subprocess for resource '{resource}' (pid={proc.pid}) is still running"


@given(parsers.parse('I wait until resource "{resource}" is not running with a timeout of "{seconds}" seconds'))
@when(parsers.parse('I wait until resource "{resource}" is not running with a timeout of "{seconds}" seconds'))
@then(parsers.parse('I wait until resource "{resource}" is not running with a timeout of "{seconds}" seconds'))
def I_wait_until_resource_is_not_running_with_timeout(resource, seconds, scenario_context):
    proc = scenario_context.get(f"resource_proc_{resource}")
    assert proc is not None, f"No subprocess saved for resource '{resource}'"
    wait_until_subprocess_exited(proc, float(seconds))
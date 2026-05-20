import signal
import subprocess
import time

from pytest_bdd import given, when, then

from globals.global_strings import global_strings
from globals.system_related_globals import system_globals
from Utils.logger_utils import logger
from Utils.process_utils import get_pid_start_time, is_process_alive, read_line_from_process
from Utils.file_utils import create_directory
from state_db.process_db import process_db


def _write_line_stdin(proc, line: str) -> None:
    proc.stdin.write(line if line.endswith("\n") else line + "\n")
    proc.stdin.flush()


def _signal_sender_send(signal_sender_proc, pid: int, signum: int) -> None:
    _write_line_stdin(signal_sender_proc, f"{pid} {signum}")


def _read_pid_from_stdout(protected_proc, description: str, timeout: int = 3) -> int:
    line = read_line_from_process(protected_proc, timeout=timeout)
    assert line is not None, f"Failed to read {description} pid from protected_process stdout"
    return int(line)


@given("I send SIGKILL to owLSM")
@when("I send SIGKILL to owLSM")
@then("I send SIGKILL to owLSM")
def I_send_sigkill_to_owlsm():
    proc = system_globals.OWLSM_PROCESS_OBJECT
    assert proc is not None, "OWLSM process is None"
    proc.send_signal(signal.SIGKILL)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        logger.log_error("OWLSM process did not die within 5s after SIGKILL")
        assert False, "OWLSM process did not die within 5s after SIGKILL"
    system_globals.OWLSM_PROCESS_OBJECT = None
    logger.log_info("Sent SIGKILL to owLSM and cleared process object")


def _fork_descendant_via_stdin_message_then_block_signals(
    protected_proc,
    signal_sender_proc,
    message: str,
    process_name: str,
    signums_to_send: list,
) -> int:
    _write_line_stdin(protected_proc, message)
    pid = _read_pid_from_stdout(protected_proc, process_name)
    start_time = get_pid_start_time(pid)
    process_db.add(pid, start_time)
    for signum in signums_to_send:
        _signal_sender_send(signal_sender_proc, pid, signum)
    time.sleep(2)
    assert is_process_alive(pid, start_time), f"{process_name} (pid={pid}) was killed but should still be alive"
    return pid


@given("signal_sender sends signal to protected_process")
@when("signal_sender sends signal to protected_process")
@then("signal_sender sends signal to protected_process")
def signal_sender_sends_signal_to_protected_process(scenario_context):
    signal_sender_proc = scenario_context.get("resource_proc_signal_sender")
    protected_proc = scenario_context.get("resource_proc_protected_process")

    assert signal_sender_proc is not None, "No proc saved for 'signal_sender'"
    assert protected_proc is not None, "No proc object saved for 'protected_process'"
    protected_proc_pid = protected_proc.pid

    _signal_sender_send(signal_sender_proc, protected_proc_pid, signal.SIGKILL)
    time.sleep(2)

    start_time = process_db.get(protected_proc_pid)
    if not is_process_alive(protected_proc_pid, start_time):
        signal_sender_proc.stdin.close()
        logger.log_info(f"protected_process (pid={protected_proc_pid}) isn't alive")
        return

    child_pid = _fork_descendant_via_stdin_message_then_block_signals(
        protected_proc,
        signal_sender_proc,
        "1",
        "child",
        [signal.SIGKILL, signal.SIGSEGV],
    )

    grandchild_pid = _fork_descendant_via_stdin_message_then_block_signals(
        protected_proc,
        signal_sender_proc,
        "2",
        "grandchild",
        [signal.SIGABRT],
    )

    signal_sender_proc.stdin.close()

    logger.log_info(
        f"Signal protection test passed: protected_process={protected_proc_pid}, "
        f"child={child_pid}, grandchild={grandchild_pid}"
    )


@given("I set up the OOM cgroup for the saved resource process")
@when("I set up the OOM cgroup for the saved resource process")
@then("I set up the OOM cgroup for the saved resource process")
def I_set_up_oom_cgroup(scenario_context):
    pid = scenario_context.get(global_strings.RESOURCE_PID)
    assert pid is not None, "No resource PID saved in scenario_context"

    cgroup_path = "/sys/fs/cgroup/owlsm_oom_test"
    assert create_directory(cgroup_path), f"Failed to create cgroup directory: {cgroup_path}"

    with open(f"{cgroup_path}/memory.max", "w") as f:
        f.write("5M")

    with open(f"{cgroup_path}/cgroup.procs", "w") as f:
        f.write(str(pid))
    logger.log_info(f"Moved process {pid} into cgroup: {cgroup_path} with memory limit to 5M")

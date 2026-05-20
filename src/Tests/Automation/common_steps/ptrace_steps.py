from pytest_bdd import when, then

from globals.system_related_globals import system_globals
from Utils.logger_utils import logger


@when('I write the running owLSM PID to the resource "ptrace_attacher" process stdin')
@then('I write the running owLSM PID to the resource "ptrace_attacher" process stdin')
def I_write_running_owlsm_pid_to_ptrace_attacher_stdin(scenario_context):
    proc = scenario_context.get("resource_proc_ptrace_attacher")
    assert proc is not None, "No proc saved for resource 'ptrace_attacher' in scenario_context"

    owlsm = system_globals.OWLSM_PROCESS_OBJECT
    assert owlsm is not None, "OWLSM process is not running"
    pid = owlsm.pid
    assert pid > 0, "Invalid owLSM pid"

    proc.stdin.write(f"{pid}\n")
    proc.stdin.flush()
    logger.log_info(f"Wrote owLSM pid {pid} to ptrace_attacher stdin")

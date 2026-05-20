import subprocess
import os
import signal
import select
import psutil
import pexpect
import time
from typing import List, Optional, Union
from Utils.logger_utils import logger
from state_db.process_db import process_db
from state_db.file_db import file_db
from globals.system_related_globals import system_globals
from globals.global_strings import global_strings

def spawn_persistent_shell(shell_path: str) -> tuple:
    try:
        child = pexpect.spawn(shell_path, timeout=10, encoding='utf-8')
        shell_pid = child.pid
        if shell_pid is not None:
            process_db.add(shell_pid, get_pid_start_time(shell_pid))
        
        logger.log_info(f"Spawned persistent shell: {shell_path}, shell_pid={shell_pid}")
        return child, shell_pid
        
    except Exception as e:
        logger.log_error(f"Failed to spawn persistent shell: {shell_path}. Error: {e}")
        return None, None


def send_command_to_shell(child, command: str, timeout: float = 0.5) -> bool:
    try:
        logger.log_info(f"Sending command to persistent shell (pid={child.pid}): '{command}'")
        child.sendline(command)
        time.sleep(timeout)
        return True
        
    except pexpect.TIMEOUT as e:
        logger.log_error(f"Timeout sending command to shell: '{command}'. Error: {e}")
        return False
        
    except Exception as e:
        logger.log_error(f"Failed to send command to shell: '{command}'. Error: {e}")
        return False


def close_persistent_shell(child) -> bool:
    try:
        logger.log_info(f"Closing persistent shell (pid={child.pid})")
        child.sendline('exit')
        child.expect(pexpect.EOF, timeout=3)
        child.wait()
        return True
        
    except Exception as e:
        logger.log_error(f"Failed to close persistent shell: {e}")
        if child:
            child.terminate(force=True)
        return False


def run_shell_commands_sync(shell_path: str, commands: Union[str, List[str]], timeout: float = 0.5) -> tuple:
    if isinstance(commands, str):
        commands = [commands]
    
    child, shell_pid = spawn_persistent_shell(shell_path)
    if child is None:
        return False, None
    
    try:
        for cmd in commands:
            if not send_command_to_shell(child, cmd, timeout=timeout):
                return False, shell_pid
        
        close_persistent_shell(child)
        
        logger.log_info(
            f"Shell session completed: shell={shell_path}, shell_pid={shell_pid}, "
            f"commands={commands}, exit_code={child.exitstatus}"
        )
        return True, shell_pid
        
    except Exception as e:
        logger.log_error(f"Failed to run shell commands: shell={shell_path}, commands={commands}. Error: {e}")
        if child:
            child.terminate(force=True)
        return False, shell_pid

def run_command_sync(command: str, timeout: int = None, stdout_out: list = None, stderr_out: list = None, stdin_data=None, expect_exit_code=None, user: str = None) -> bool:
    return_value = False
    try:
        result = subprocess.run(
            command.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin_data,
            text=True,
            timeout=timeout,
            user=user,
        )

        if stdout_out is not None:
            stdout_out.append(result.stdout)
        if stderr_out is not None:
            stderr_out.append(result.stderr)

        user_info = f" (as user: {user})" if user else ""
        logger.log_info(f"Command completed{user_info}: {command}, exit code: {result.returncode}")

        if expect_exit_code is not None:
            return_value = (result.returncode == expect_exit_code)
        else:
            return_value = True

    except subprocess.TimeoutExpired as e:
        message = f"Command timed out after {timeout}s: {command}"
        if e.stdout:
            message += f"\nSTDOUT: {e.stdout.strip()}"
        if e.stderr:
            message += f"\nSTDERR: {e.stderr.strip()}"
        logger.log_error(message)
        return_value = False

    except Exception as e:
        logger.log_error(f"Failed to run command: {command}. Error: {e}")
        return_value = False

    return return_value



def run_command_async(command: str, stdout_fd=None, stderr_fd=None, user: str = None):
    try:
        stdout_target = stdout_fd if stdout_fd is not None else subprocess.PIPE
        stderr_target = stderr_fd if stderr_fd is not None else subprocess.PIPE
        
        proc = subprocess.Popen(
            command.split(),
            stdout=stdout_target,
            stderr=stderr_target,
            stdin=subprocess.PIPE,
            text=True,
            user=user,
        )
        
        process_db.add(proc.pid, get_pid_start_time(proc.pid))
        user_info = f" (as user: {user})" if user else ""
        if stdout_fd is None and stderr_fd is None:
            logger.log_info(f"Started async command{user_info}: {command} (PID: {proc.pid}) with output captured to pipes")
        else:
            logger.log_info(f"Started async command{user_info}: {command} (PID: {proc.pid}) with output redirected to provided file descriptors")
        return proc
        
    except Exception as e:
        logger.log_error(f"Failed to start async command: {command}. Error: {e}")
        return None

def ensure_async_command_runs_for_at_least_seconds(command: str, seconds: int, stdout_fd=None, stderr_fd=None):
    proc = run_command_async(command, stdout_fd, stderr_fd)
    if proc is None:
        assert False, f"Failed to start async command: {command}"
    
    try:
        proc.wait(timeout=seconds)
        logger.log_error(f"Async command {command} ran for less than {seconds} seconds")
        assert False, f"Async command {command} ran for less than {seconds} seconds"
    except subprocess.TimeoutExpired:
        return proc
    except Exception as e:
        logger.log_error(f"Failed to ensure async command runs for at least {seconds} seconds: {command}. Error: {e}")
        assert False, f"Failed to ensure async command runs for at least {seconds} seconds: {command}. Error: {e}"


def run_command_sync_as_grandchild(command: str, timeout: int = None, user: str = None) -> bool:
        logger.log_info(f"running command as grandchild: {command}")
        child_pid = fork_current_process()
        if child_pid == 0:
            run_command_sync(command, timeout, user=user)
        else:
            os.waitpid(child_pid, 0)
            return True
    
def fork_current_process():
    child_pid = None
    try:
        child_pid = os.fork()
    except Exception as e:
        logger.log_error(f"Failed to fork current process. Error: {e}")
        assert False, f"Failed to fork current process. Error: {e}"

    if child_pid != 0:
        process_db.add(child_pid, get_pid_start_time(child_pid))

    return child_pid


def get_pid_start_time(pid: int):
    return psutil.Process(pid).create_time()


def is_subprocess_running(proc: Optional[subprocess.Popen]) -> bool:
    if proc is None:
        return False
    return proc.poll() is None


def wait_until_subprocess_exited(proc: Optional[subprocess.Popen], timeout_seconds: float) -> None:
    if proc is None:
        return
    deadline = time.time() + float(timeout_seconds)
    poll_interval = 0.5
    while time.time() < deadline:
        if not is_subprocess_running(proc):
            logger.log_info(f"Subprocess pid={proc.pid} exited within timeout")
            return
        time.sleep(poll_interval)
    assert not is_subprocess_running(proc), \
        f"Subprocess (pid={proc.pid}) still running after {timeout_seconds}s timeout"


def is_process_alive(pid, start_time=None):
    if not psutil.pid_exists(pid):
        return False
    try:
        proc = psutil.Process(pid)
        if start_time is not None and abs(proc.create_time() - start_time) > 3.0:
            return False
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False

def stop_owlsm_process():
    if system_globals.OWLSM_PROCESS_OBJECT:
        try:
            system_globals.OWLSM_PROCESS_OBJECT.send_signal(signal.SIGINT)
            try:
                system_globals.OWLSM_PROCESS_OBJECT.wait(timeout=10)
                logger.log_info(f"OWLSM process stopped successfully, pid: {system_globals.OWLSM_PROCESS_OBJECT.pid}")
            except subprocess.TimeoutExpired:
                system_globals.OWLSM_PROCESS_OBJECT.kill()
                logger.log_error(f"OWLSM process did not stop within 10 seconds after SIGINT, pid: {system_globals.OWLSM_PROCESS_OBJECT.pid}. Killing process.")
                assert False, f"OWLSM process did not stop within 10 seconds after SIGINT, pid: {system_globals.OWLSM_PROCESS_OBJECT.pid}. Killing process."
        except Exception as e:
            logger.log_error(f"Failed to kill OWLSM process: {e}")
            assert False, f"Failed to kill OWLSM process: {e}"
            
    system_globals.OWLSM_PROCESS_OBJECT = None

def wait_for_owlsm_initialization(proc, custom_log_path=None):
    from pathlib import Path
    log_paths = [system_globals.OWLSM_LOGGER_LOG]
    if custom_log_path:
        log_paths.append(Path(custom_log_path))
    timeout = system_globals.OWLSM_SETUP_TIME_IN_SECONDS
    start_time = time.time()

    while time.time() - start_time < timeout:
        if not is_subprocess_running(proc):
            logger.log_error(f"owLSM process exited prematurely with code {proc.returncode}")
            assert False, f"owLSM process exited prematurely with code {proc.returncode}"

        for log_path in log_paths:
            try:
                if log_path.exists():
                    with open(log_path, 'r') as f:
                        if global_strings.OWLSM_INIT_COMPLETE_MESSAGE in f.read():
                            elapsed = time.time() - start_time
                            logger.log_info(f"owLSM initialization confirmed after {elapsed:.1f}s")
                            return
            except Exception as e:
                logger.log_error(f"Failed to read owLSM log at {log_path}: {e}")

        time.sleep(1)

    logger.log_error(f"owLSM failed to initialize within {timeout}s")
    proc.kill()
    assert False, f"owLSM failed to initialize within {timeout}s"

def start_owlsm_process(command: str, stdin_data: str = None, stdout_fd=None, stderr_fd=None, custom_log_path=None):
    if system_globals.OWLSM_LOGGER_LOG.exists():
        open(system_globals.OWLSM_LOGGER_LOG, 'w').close()

    system_globals.OWLSM_OUTPUT_LOG_FD = open(system_globals.OWLSM_OUTPUT_LOG, 'w')
    stdout_fd = stdout_fd if stdout_fd is not None else system_globals.OWLSM_OUTPUT_LOG_FD
    stderr_fd = stderr_fd if stderr_fd is not None else system_globals.OWLSM_OUTPUT_LOG_FD

    proc = run_command_async(command, stdout_fd, stderr_fd)
    if proc is None:
        assert False, f"Failed to start owLSM process: {command}"

    if stdin_data is not None:
        proc.stdin.write(stdin_data)
        proc.stdin.close()

    wait_for_owlsm_initialization(proc, custom_log_path=custom_log_path)

    system_globals.OWLSM_PROCESS_OBJECT = proc
    process_db.remove(proc.pid)
    logger.log_info("owLSM startup completed successfully")


def start_owlsm_process_with_stdin(config_path: str):
    with open(config_path, 'r') as f:
        config_data = f.read()
    start_owlsm_process(f"{system_globals.OWLSM_PATH} --stdin", stdin_data=config_data)


def read_line_from_process(proc, timeout=5):
    try:
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if ready:
            line = proc.stdout.readline().strip()
            logger.log_info(f"Read '{line}' from process PID {proc.pid} stdout")
            return line
        logger.log_error(f"Timeout ({timeout}s) reading from process PID {proc.pid} stdout")
        return None
    except Exception as e:
        logger.log_error(f"Failed to read from process PID {proc.pid} stdout: {e}")
        return None


def start_owlsm_with_flatbuffer_binary_streams(command: str) -> None:
    events_bin = system_globals.AUTOMATION_ROOT_DIR / "owLSM_output_events.bin"
    errors_bin = system_globals.AUTOMATION_ROOT_DIR / "owLSM_output_errors.bin"
    for path in (events_bin, errors_bin):
        if path.exists():
            os.remove(path)
    events_fd = open(events_bin, "wb")
    errors_fd = open(errors_bin, "wb")
    file_db.add(events_bin)
    file_db.add(errors_bin)
    start_owlsm_process(command, stdout_fd=events_fd, stderr_fd=errors_fd)
    events_fd.close()
    errors_fd.close()
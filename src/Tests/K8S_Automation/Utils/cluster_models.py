from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from enum import Enum
from threading import Event, Thread
from typing import Optional

import paramiko

from Utils.logger_utils import logger
from globals.global_strings import global_strings


class ClusterType(Enum):
    KIND = global_strings.KIND
    OCI = global_strings.OCI
    MINIKUBE = "minikube"


@dataclass
class Pod:
    name: str
    namespace: str
    uid: str
    node_name: str
    labels: dict[str, str] = field(default_factory=dict)
    container_name: str = ""
    container_id: str = ""


class StdoutReader:
    def __init__(self, node_name: str):
        self.node_name = node_name
        self._thread: Optional[Thread] = None
        self._process: Optional[subprocess.Popen] = None
        self._stop_event = Event()

    def start(self) -> None:
        if self.is_running():
            self.stop()
        self._truncate_output_log()
        self._stop_event.clear()
        self._thread = Thread(
            target=self._run,
            name=f"stdout-reader-{self.node_name}",
            daemon=True,
        )
        self._thread.start()
        logger.log_info(f"Started owlsm stdout reader on {self.node_name}")

    def stop(self) -> None:
        self._stop_event.set()
        self._terminate_process()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.log_info(f"Stopped owlsm stdout reader on {self.node_name}")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _truncate_output_log(self) -> None:
        log_path = global_strings.OWLSM_OUTPUT_LOG
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w", encoding="utf-8"):
            pass

    def _run(self) -> None:
        pod_name = self._owlsm_pod_name()
        if not pod_name:
            logger.log_error(f"no owlsm pod on {self.node_name}; stdout reader exiting")
            return
        self._follow_logs(pod_name)

    def _follow_logs(self, pod_name: str) -> None:
        from Utils.cluster_utils import kubectl_command

        command = kubectl_command(
            [
                "logs",
                "-n",
                global_strings.OWLSM_NAMESPACE,
                pod_name,
                "-c",
                global_strings.OWLSM_CONTAINER_NAME,
                "-f",
                "--tail=0",
            ]
        )
        logger.log_info(f"Following owlsm logs: {' '.join(command)}")
        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        stderr_thread = Thread(
            target=self._drain_stderr,
            args=(self._process,),
            name=f"stdout-reader-stderr-{self.node_name}",
            daemon=True,
        )
        stderr_thread.start()
        try:
            stdout = self._process.stdout
            if stdout is None:
                return
            with open(
                global_strings.OWLSM_OUTPUT_LOG,
                "a",
                encoding="utf-8",
                buffering=1,
            ) as log_file:
                for line in stdout:
                    if self._stop_event.is_set():
                        break
                    log_file.write(line)
        finally:
            self._terminate_process()
            stderr_thread.join(timeout=1)

    def _drain_stderr(self, process: subprocess.Popen) -> None:
        stderr = process.stderr
        if stderr is None:
            return
        for line in stderr:
            text = line.strip()
            if text:
                logger.log_info(f"kubectl logs stderr on {self.node_name}: {text}")

    def _owlsm_pod_name(self) -> str:
        from Utils.cluster_utils import owlsm_pod_name_on_node

        return owlsm_pod_name_on_node(self.node_name)

    def _terminate_process(self) -> None:
        process = self._process
        self._process = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()


@dataclass
class Node:
    name: str
    ip: str
    live_ssh_connection_to_node: Optional[paramiko.SSHClient] = None
    stdout_reader_thread: Optional[StdoutReader] = None
    pod_uid_to_pod_info: dict[str, Pod] = field(default_factory=dict)
    test_pod_uid: str = ""

    def run_ssh_command(self, command: str, check: bool = True) -> str:
        if self.live_ssh_connection_to_node is None:
            raise RuntimeError(f"no SSH connection to node {self.name}")
        _stdin, stdout, stderr = self.live_ssh_connection_to_node.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()
        logger.log_info(
            f"SSH on {self.name}: command={command!r} exit_status={exit_status} "
            f"stdout={output!r} stderr={error_output!r}"
        )
        if check and exit_status != 0:
            raise RuntimeError(
                f"SSH command failed on {self.name}: {command} "
                f"(exit {exit_status}): {error_output or output}"
            )
        return output


@dataclass
class Cluster:
    type: ClusterType
    main_node: Node
    second_node: Node

    def nodes(self) -> list[Node]:
        return [self.main_node, self.second_node]

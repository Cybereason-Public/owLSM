from __future__ import annotations

import shlex
from dataclasses import dataclass

from Utils.cluster_models import Node, Pod
from Utils.cluster_utils import run_kubectl
from Utils.logger_utils import logger


@dataclass
class File:
    path: str
    permissions: int = 0
    target: Pod | Node | None = None


def create_file(file: File) -> None:
    command = f"touch {shlex.quote(file.path)}"
    if file.permissions != 0:
        command = f"{command} && {_chmod_command(file)}"
    logger.log_info(f"Creating file {file.path} on {_target_name(file)}")
    _run_on_target(file, command)


def delete_file(file: File) -> None:
    command = f"rm -f {shlex.quote(file.path)}"
    logger.log_info(f"Deleting file {file.path} on {_target_name(file)}")
    _run_on_target(file, command)


def chmod_file(file: File) -> None:
    command = _chmod_command(file)
    logger.log_info(
        f"chmod {file.permissions:o} {file.path} on {_target_name(file)}"
    )
    _run_on_target(file, command)


def create_dir(file: File) -> None:
    command = f"mkdir {shlex.quote(file.path)}"
    if file.permissions != 0:
        command = f"{command} && {_chmod_command(file)}"
    logger.log_info(f"Creating dir {file.path} on {_target_name(file)}")
    _run_on_target(file, command)


def delete_dir(file: File) -> None:
    command = f"rm -rf {shlex.quote(file.path)}"
    logger.log_info(f"Deleting dir {file.path} on {_target_name(file)}")
    _run_on_target(file, command)


def _run_on_target(file: File, command: str) -> None:
    target = file.target
    if isinstance(target, Node):
        target.run_ssh_command(command)
        return
    if isinstance(target, Pod):
        _run_on_pod(target, command)
        return
    raise RuntimeError("File.target must be a Pod or Node")


def _run_on_pod(pod: Pod, command: str) -> None:
    args = ["exec", "-n", pod.namespace, pod.name]
    if pod.container_name:
        args.extend(["-c", pod.container_name])
    args.extend(["--", "sh", "-c", command])
    run_kubectl(args)


def _chmod_command(file: File) -> str:
    return f"chmod {file.permissions:o} {shlex.quote(file.path)}"


def _target_name(file: File) -> str:
    target = file.target
    if isinstance(target, Node):
        return f"node {target.name}"
    if isinstance(target, Pod):
        return f"pod {target.namespace}/{target.name}"
    return "unknown"

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


def assert_file_mode(file: File, mode: str) -> None:
    command = f"stat -c %a {shlex.quote(file.path)}"
    logger.log_info(f"Checking mode of {file.path} on {_target_name(file)}")
    actual = _run_on_target(file, command)
    if actual != mode:
        raise RuntimeError(
            f"{file.path} on {_target_name(file)} has mode {actual}, expected {mode}"
        )


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


def _run_on_target(file: File, command: str) -> str:
    target = file.target
    if isinstance(target, Node):
        return target.run_ssh_command(command)
    if isinstance(target, Pod):
        return _run_on_pod(target, command)
    raise RuntimeError("File.target must be a Pod or Node")


def _run_on_pod(pod: Pod, command: str) -> str:
    args = ["exec", "-n", pod.namespace, pod.name]
    if pod.container_name:
        args.extend(["-c", pod.container_name])
    args.extend(["--", "sh", "-c", command])
    result = run_kubectl(args)
    return (result.stdout or "").strip()


def _chmod_command(file: File) -> str:
    return f"chmod {file.permissions:o} {shlex.quote(file.path)}"


def _target_name(file: File) -> str:
    target = file.target
    if isinstance(target, Node):
        return f"node {target.name}"
    if isinstance(target, Pod):
        return f"pod {target.namespace}/{target.name}"
    return "unknown"

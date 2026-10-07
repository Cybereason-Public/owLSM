from __future__ import annotations

import json

from Utils.cluster_utils import get_cluster
from Utils.logger_utils import logger


def log_container_snapshot(stage: str) -> None:
    try:
        for node in get_cluster().nodes():
            _log_node_runtime_snapshot(node, stage)
    except Exception as error:
        logger.log_error(f"container snapshot stage={stage} failed: {error}")


def _log_node_runtime_snapshot(node, stage: str) -> None:
    node_name = node.name
    containers = _runtime_records(node, "crictl ps -a -o json", "containers")
    sandboxes = _runtime_records(node, "crictl pods -a -o json", "items")
    logger.log_info(
        f"container snapshot stage={stage} node={node_name} "
        f"containers={len(containers)} sandboxes={len(sandboxes)}"
    )
    for container in containers:
        logger.log_info(_container_line(stage, node_name, container))
    for sandbox in sandboxes:
        logger.log_info(_sandbox_line(stage, node_name, sandbox))


def _runtime_records(node, command: str, list_key: str) -> list[dict]:
    output = node.run_ssh_command(command, check=False, log_output=False)
    if not output:
        return []
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        logger.log_error(f"container snapshot could not parse {command!r}")
        return []
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        for key in (list_key, "containers", "items"):
            records = parsed.get(key)
            if isinstance(records, list):
                return [item for item in records if isinstance(item, dict)]
    return []


def _container_line(stage: str, node_name: str, container: dict) -> str:
    metadata = container.get("metadata") or {}
    labels = container.get("labels") or {}
    container_id = str(container.get("id") or "")
    sandbox_id = str(container.get("podSandboxId") or "")
    pod_namespace = labels.get("io.kubernetes.pod.namespace", "")
    pod_name = labels.get("io.kubernetes.pod.name", "")
    pod_uid = labels.get("io.kubernetes.pod.uid", "")
    return (
        f"container snapshot stage={stage} node={node_name} kind=container "
        f"truncated={_truncated_id(container_id)} id={container_id} "
        f"state={container.get('state', '')} name={metadata.get('name', '')} "
        f"pod={pod_namespace}/{pod_name} uid={pod_uid} "
        f"sandbox_truncated={_truncated_id(sandbox_id)} image={_image_name(container)}"
    )


def _sandbox_line(stage: str, node_name: str, sandbox: dict) -> str:
    metadata = sandbox.get("metadata") or {}
    labels = sandbox.get("labels") or {}
    sandbox_id = str(sandbox.get("id") or "")
    pod_namespace = metadata.get("namespace") or labels.get("io.kubernetes.pod.namespace", "")
    pod_name = metadata.get("name") or labels.get("io.kubernetes.pod.name", "")
    pod_uid = metadata.get("uid") or labels.get("io.kubernetes.pod.uid", "")
    return (
        f"container snapshot stage={stage} node={node_name} kind=sandbox "
        f"truncated={_truncated_id(sandbox_id)} id={sandbox_id} "
        f"state={sandbox.get('state', '')} pod={pod_namespace}/{pod_name} uid={pod_uid}"
    )


def _image_name(container: dict) -> str:
    image = container.get("image") or container.get("imageRef") or ""
    if isinstance(image, dict):
        image = image.get("image") or image.get("imageRef") or ""
    return _one_line(str(image))


def _truncated_id(container_id: str) -> str:
    stripped = container_id.split("://", 1)[-1]
    if len(stripped) < 16:
        return ""
    try:
        return str(int(stripped[:16], 16))
    except ValueError:
        return ""


def _one_line(value: str) -> str:
    return value.replace("\n", " ").replace("\r", " ")

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import paramiko

from Utils.cluster_models import Cluster, ClusterType, Node, Pod, StdoutReader
from Utils.logger_utils import logger
from globals.global_numbers import global_numbers
from globals.global_objects import global_objects
from globals.global_strings import global_strings


def create_kind_cluster() -> None:
    _require_kind_cluster_type()
    script = global_strings.REPO_K8S_DIR / "kind" / "create.sh"
    logger.log_info(f"Creating kind cluster with {script}")
    _run_kind_script(script)


def delete_kind_cluster() -> None:
    _require_kind_cluster_type()
    close_cluster_ssh()
    script = global_strings.REPO_K8S_DIR / "kind" / "delete.sh"
    logger.log_info(f"Deleting kind cluster with {script}")
    _run_kind_script(script)
    global_objects.CLUSTER = None


def load_owlsm_runtime_local_image_into_kind() -> None:
    _require_kind_cluster_type()
    image = f"{global_strings.OWLSM_IMAGE_REPOSITORY}:{global_strings.OWLSM_IMAGE_TAG}"
    logger.log_info(
        f"Loading host Docker image {image} into kind cluster {global_strings.KIND_CLUSTER_NAME}"
    )
    result = subprocess.run(
        ["kind", "load", "docker-image", image, "--name", global_strings.KIND_CLUSTER_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        logger.log_info(result.stdout.strip())
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout).strip()
        logger.log_error(error_text)
        raise RuntimeError(f"kind load failed for {image}: {error_text}")


def should_load_owlsm_runtime_local_image_into_kind() -> bool:
    return not _is_ghcr_image_repository(global_strings.OWLSM_IMAGE_REPOSITORY)


def _is_ghcr_image_repository(repository: str) -> bool:
    return repository.startswith("ghcr.io/")


def ensure_connection_to_cluster() -> None:
    kubeconfig = global_strings.KUBECONF_PATH
    if not kubeconfig.is_file():
        raise RuntimeError(f"kubeconfig not found: {kubeconfig}")
    result = run_kubectl(["get", "nodes"])
    logger.log_info(f"kubectl can reach the cluster:\n{result.stdout.strip()}")


def init_global_cluster_object() -> None:
    cluster_type = ClusterType(global_strings.CLUSTER_TYPE)
    discovered = _discover_nodes()
    min_nodes = global_numbers.MIN_NUMBER_OF_NODES_IN_TEST_CLUSTER
    if len(discovered) < min_nodes:
        raise RuntimeError(f"need {min_nodes} nodes, found {len(discovered)}")
    main_node, second_node = _select_main_and_second(discovered)
    _open_ssh(main_node)
    _open_ssh(second_node)
    hostname = main_node.run_ssh_command("hostname")
    logger.log_info(f"SSH to main_node {main_node.name} ({main_node.ip}) hostname={hostname}")
    hostname = second_node.run_ssh_command("hostname")
    logger.log_info(f"SSH to second_node {second_node.name} ({second_node.ip}) hostname={hostname}")
    main_node.stdout_reader_thread = StdoutReader(main_node.name)
    global_objects.CLUSTER = Cluster(
        type=cluster_type,
        main_node=main_node,
        second_node=second_node,
    )
    logger.log_info(
        f"Cluster type={cluster_type.value} main_node={main_node.name} "
        f"second_node={second_node.name}"
    )


def deploy_test_pod() -> None:
    cluster = get_cluster()
    remove_test_pod()
    node = cluster.main_node
    namespace = global_strings.TEST_POD_NAMESPACE
    name = global_strings.TEST_POD_NAME
    timeout = f"{global_numbers.TEST_POD_READY_TIMEOUT_SECONDS}s"
    logger.log_info(f"Deploying '{name}' in namespace '{namespace}' on node '{node.name}'")
    run_kubectl(["apply", "-f", "-"], stdin=json.dumps(_test_pod_namespace_manifest()))
    run_kubectl(["apply", "-f", "-"], stdin=json.dumps(_test_pod_manifest(node.name)))
    run_kubectl(
        [
            "wait",
            "--for=condition=Ready",
            f"pod/{name}",
            "-n",
            namespace,
            f"--timeout={timeout}",
        ]
    )
    pod = _pod_from_kubectl(name, namespace)
    if pod.node_name != node.name:
        raise RuntimeError(f"test_pod landed on {pod.node_name}, expected {node.name}")
    node.pod_uid_to_pod_info[pod.uid] = pod
    node.test_pod_uid = pod.uid
    logger.log_info(
        f"test_pod uid={pod.uid} node={pod.node_name} "
        f"container={pod.container_name} id={pod.container_id}"
    )


def remove_test_pod() -> None:
    namespace = global_strings.TEST_POD_NAMESPACE
    name = global_strings.TEST_POD_NAME
    timeout = f"{global_numbers.TEST_POD_READY_TIMEOUT_SECONDS}s"
    logger.log_info(f"Removing test_pod {name} from namespace {namespace}")
    result = run_kubectl(
        [
            "delete",
            "pod",
            name,
            "-n",
            namespace,
            "--ignore-not-found",
            "--wait=true",
            f"--timeout={timeout}",
        ],
        check=False,
    )
    if result.returncode != 0:
        run_kubectl(
            [
                "delete",
                "pod",
                name,
                "-n",
                namespace,
                "--ignore-not-found",
                "--force",
                "--grace-period=0",
            ],
            check=False,
        )
    cluster = global_objects.CLUSTER
    if cluster is None:
        return
    for node in cluster.nodes():
        uid = node.test_pod_uid
        if uid:
            node.pod_uid_to_pod_info.pop(uid, None)
            node.test_pod_uid = ""


def remove_test_namespace() -> None:
    namespace = global_strings.TEST_POD_NAMESPACE
    timeout = f"{global_numbers.TEST_NAMESPACE_DELETE_TIMEOUT_SECONDS}s"
    logger.log_info(f"Removing test namespace {namespace}")
    run_kubectl(
        [
            "delete",
            "namespace",
            namespace,
            "--ignore-not-found",
            "--wait=true",
            f"--timeout={timeout}",
        ]
    )


def get_cluster() -> Cluster:
    cluster = global_objects.CLUSTER
    if cluster is None:
        raise RuntimeError("CLUSTER is not initialized")
    return cluster


def get_test_pod() -> Pod:
    cluster = get_cluster()
    uid = cluster.main_node.test_pod_uid
    pod = cluster.main_node.pod_uid_to_pod_info.get(uid)
    if not uid or pod is None:
        raise RuntimeError("test_pod is not deployed")
    return pod


def patch_test_pod_labels(labels: dict[str, str]) -> None:
    pod = get_test_pod()
    logger.log_info(f"Patching labels on {pod.namespace}/{pod.name}: {labels}")
    run_kubectl(
        [
            "patch",
            "pod",
            pod.name,
            "-n",
            pod.namespace,
            "--type=merge",
            "-p",
            json.dumps({"metadata": {"labels": labels}}),
        ]
    )
    refreshed = _pod_from_kubectl(pod.name, pod.namespace)
    for key, value in labels.items():
        if refreshed.labels.get(key) != value:
            raise RuntimeError(
                f"test_pod label {key} is {refreshed.labels.get(key)!r}, expected {value!r}"
            )
    node = get_cluster().main_node
    node.pod_uid_to_pod_info[refreshed.uid] = refreshed
    node.test_pod_uid = refreshed.uid
    logger.log_info(f"test_pod labels are now {refreshed.labels}")


def run_kubectl(
    args: list[str],
    check: bool = True,
    stdin: str | None = None,
) -> subprocess.CompletedProcess:
    command = kubectl_command(args)
    logger.log_info(f"Running: {' '.join(command)}")
    result = subprocess.run(
        command,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout).strip()
        if check:
            logger.log_error(error_text)
            raise RuntimeError(f"kubectl failed: {' '.join(args)}: {error_text}")
        logger.log_info(error_text)
    return result


def kubectl_command(args: list[str]) -> list[str]:
    command = [_kubectl_bin(), f"--kubeconfig={global_strings.KUBECONF_PATH}"]
    if global_strings.KUBE_CONTEXT:
        command.extend(["--context", global_strings.KUBE_CONTEXT])
    command.extend(args)
    return command


def owlsm_pod_name_on_node(node_name: str) -> str:
    result = run_kubectl(
        [
            "get",
            "pods",
            "-n",
            global_strings.OWLSM_NAMESPACE,
            "-l",
            f"app.kubernetes.io/name={global_strings.OWLSM_APP_NAME}",
            "--field-selector",
            f"spec.nodeName={node_name}",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
        check=False,
    )
    return (result.stdout or "").strip()


def _require_kind_cluster_type() -> None:
    if global_strings.CLUSTER_TYPE != global_strings.KIND:
        raise RuntimeError(
            f"kind helper called with CLUSTER_TYPE={global_strings.CLUSTER_TYPE}"
        )


def _run_kind_script(script: Path) -> None:
    if not script.is_file():
        raise RuntimeError(f"kind script not found: {script}")
    env = os.environ.copy()
    env["KUBECONFIG"] = str(global_strings.KUBECONF_PATH)
    result = subprocess.run(
        [str(script), "--cluster", global_strings.KIND_CLUSTER_NAME],
        cwd=global_strings.REPO_ROOT,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{script.name} failed with exit {result.returncode}")


def _kubectl_bin() -> str:
    found = shutil.which("kubectl")
    if found:
        return found
    raise RuntimeError("kubectl not found in PATH")


def _discover_nodes() -> list[tuple[Node, bool]]:
    result = run_kubectl(["get", "nodes", "-o", "json"])
    payload = json.loads(result.stdout)
    discovered: list[tuple[Node, bool]] = []
    for item in payload.get("items", []):
        name = item["metadata"]["name"]
        ip = _node_ssh_ip(item)
        if not ip:
            raise RuntimeError(f"node {name} has no SSH address")
        labels = item.get("metadata", {}).get("labels", {})
        is_control_plane = "node-role.kubernetes.io/control-plane" in labels
        discovered.append((Node(name=name, ip=ip), is_control_plane))
        logger.log_info(f"Found node {name} ip={ip} control_plane={is_control_plane}")
    return discovered


def _node_ssh_ip(node_item: dict) -> str:
    if global_strings.CLUSTER_TYPE == global_strings.OCI:
        external_ip = _address_of_type(node_item, "ExternalIP")
        if external_ip:
            return external_ip
    return _address_of_type(node_item, "InternalIP")


def _address_of_type(node_item: dict, address_type: str) -> str:
    for address in node_item.get("status", {}).get("addresses", []):
        if address.get("type") == address_type:
            return address.get("address", "")
    return ""


# Kind control-plane nodes are like workers and can be used as workers as well. We can deploy owlsm on them.
def _select_main_and_second(discovered: list[tuple[Node, bool]]) -> tuple[Node, Node]:
    min_nodes = global_numbers.MIN_NUMBER_OF_NODES_IN_TEST_CLUSTER
    workers = [node for node, is_control_plane in discovered if not is_control_plane]
    control_planes = [node for node, is_control_plane in discovered if is_control_plane]
    if len(workers) >= min_nodes:
        return workers[0], workers[1]
    if workers and control_planes:
        return workers[0], control_planes[0]
    if len(control_planes) >= min_nodes:
        return control_planes[0], control_planes[1]
    raise RuntimeError(
        f"need {min_nodes} nodes to deploy owlsm, "
        f"found {len(workers)} worker(s) and {len(control_planes)} control-plane(s)"
    )


def _test_pod_namespace_manifest() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": global_strings.TEST_POD_NAMESPACE},
    }


def _test_pod_manifest(node_name: str) -> dict:
    name = global_strings.TEST_POD_NAME
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": global_strings.TEST_POD_NAMESPACE,
            "labels": {"app": name},
        },
        "spec": {
            "nodeName": node_name,
            "restartPolicy": "Always",
            "terminationGracePeriodSeconds": 1,
            "tolerations": [
                {
                    "key": "node-role.kubernetes.io/control-plane",
                    "operator": "Exists",
                    "effect": "NoSchedule",
                }
            ],
            "containers": [
                {
                    "name": name,
                    "image": global_strings.TEST_POD_IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["sleep", "infinity"],
                }
            ],
        },
    }


def _pod_from_kubectl(name: str, namespace: str) -> Pod:
    result = run_kubectl(["get", "pod", name, "-n", namespace, "-o", "json"])
    item = json.loads(result.stdout)
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    container_name = ""
    container_id = ""
    container_statuses = status.get("containerStatuses") or []
    if container_statuses:
        container_name = container_statuses[0].get("name", "")
        container_id = container_statuses[0].get("containerID", "")
    return Pod(
        name=metadata.get("name", name),
        namespace=metadata.get("namespace", namespace),
        uid=metadata.get("uid", ""),
        node_name=spec.get("nodeName", ""),
        labels=dict(metadata.get("labels") or {}),
        container_name=container_name,
        container_id=container_id,
    )


def _open_ssh(node: Node) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": node.ip,
        "username": global_strings.SSH_USER,
        "timeout": 10,
        "look_for_keys": False,
        "allow_agent": False,
    }
    key_path = _ssh_key_path()
    if key_path:
        logger.log_info(
            f"Opening SSH to {node.name} ({node.ip}) as {global_strings.SSH_USER} "
            f"with key {key_path}"
        )
        connect_kwargs["key_filename"] = key_path
    elif global_strings.CLUSTER_TYPE == global_strings.OCI:
        raise RuntimeError(
            "CLUSTER_TYPE=oci requires OWLSM_OKE_SSH_KEY to be a readable private key file"
        )
    else:
        logger.log_info(
            f"Opening SSH to {node.name} ({node.ip}) as {global_strings.SSH_USER} "
            "with password"
        )
        connect_kwargs["password"] = global_strings.SSH_PASSWORD
    client.connect(**connect_kwargs)
    transport = client.get_transport()
    if transport is not None:
        transport.set_keepalive(30)
    node.live_ssh_connection_to_node = client


def _ssh_key_path() -> str:
    raw = global_strings.SSH_KEY_PATH.strip()
    if not raw:
        return ""
    path = Path(raw).expanduser()
    if not path.is_file():
        raise RuntimeError(f"OWLSM_OKE_SSH_KEY is not a readable file: {raw}")
    return str(path)


def close_cluster_ssh() -> None:
    cluster = global_objects.CLUSTER
    if cluster is None:
        return
    for node in cluster.nodes():
        if node.live_ssh_connection_to_node is not None:
            logger.log_info(f"Closing SSH to {node.name}")
            node.live_ssh_connection_to_node.close()
            node.live_ssh_connection_to_node = None
        if node.stdout_reader_thread is not None:
            node.stdout_reader_thread.stop()
            node.stdout_reader_thread = None

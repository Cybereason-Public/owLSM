from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
import paramiko

from Utils.cluster_models import Cluster, ClusterType, Node, Pod, StdoutReader
from Utils.logger_utils import logger
from globals.global_numbers import global_numbers
from state_db.cluster_object_db import cluster_object_db
from globals.global_objects import global_objects
from globals.global_strings import global_strings


def create_kind_cluster() -> None:
    _require_kind_cluster_type()
    script = global_strings.REPO_K8S_DIR / global_strings.KIND / "create.sh"
    logger.log_info(f"Creating {global_strings.KIND} cluster with {script}")
    _run_kind_script(script)


def delete_kind_cluster() -> None:
    _require_kind_cluster_type()
    close_cluster_ssh()
    script = global_strings.REPO_K8S_DIR / global_strings.KIND / "delete.sh"
    logger.log_info(f"Deleting {global_strings.KIND} cluster with {script}")
    _run_kind_script(script)
    global_objects.CLUSTER = None


def load_owlsm_runtime_local_image_into_kind() -> None:
    _require_kind_cluster_type()
    image = f"{global_strings.OWLSM_IMAGE_REPOSITORY}:{global_strings.OWLSM_IMAGE_TAG}"
    logger.log_info(
        f"Loading host Docker image {image} into {global_strings.KIND} cluster {global_strings.KIND_CLUSTER_NAME}"
    )
    result = subprocess.run(
        [global_strings.KIND, "load", "docker-image", image, "--name", global_strings.KIND_CLUSTER_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        logger.log_info(result.stdout.strip())
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout).strip()
        logger.log_error(error_text)
        raise RuntimeError(f"{global_strings.KIND} load failed for {image}: {error_text}")


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
    pod = _wait_for_pod_identity(name, namespace)
    _remember_pod(global_strings.TEST_POD_ALIAS, pod)
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
        node.pods_by_alias.pop(global_strings.TEST_POD_ALIAS, None)


_POD_ALIAS_ANNOTATION = "owlsm/alias"
_MAX_PINNED_DEPLOYMENT_REPLICAS = 100
_manifest_aliases: dict[str, list[str]] = {}


def deploy_manifest(name: str) -> None:
    rendered = _render_manifest(name)
    cluster_object_db.add(name)
    delete_manifest(name, check=False)
    rendered = _fit_pinned_deployments(rendered)
    node_name = get_cluster().main_node.name
    logger.log_info(f"Applying manifest {name} on node {node_name}")
    run_kubectl(["apply", "-f", "-"], stdin=rendered)
    items = _manifest_items(rendered)
    refs = _pod_refs(items)
    _wait_for_named_pods(refs)
    refs.extend(_deployment_pod_refs(items))
    if not refs:
        raise RuntimeError(f"manifest {name} has no pods")
    _remember_manifest_pods(name, refs)


def delete_manifest(name: str, check: bool = True) -> None:
    rendered = _render_manifest(name)
    timeout = f"{global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS}s"
    logger.log_info(f"Deleting manifest {name}")
    run_kubectl(
        [
            "delete",
            "-f",
            "-",
            "--ignore-not-found",
            "--wait=true",
            f"--timeout={timeout}",
        ],
        check=check,
        stdin=rendered,
    )


def cleanup_cluster_objects() -> None:
    for name in cluster_object_db.get_all():
        try:
            delete_manifest(name, check=False)
        except Exception as error:
            logger.log_error(f"Failed to cleanup manifest {name}: {error}")
    cluster_object_db.remove_all()


def delete_manifests(check: bool = False) -> None:
    manifests_dir = global_strings.MANIFESTS_DIR
    if not manifests_dir.is_dir():
        return
    for path in sorted(manifests_dir.glob("*.yaml")):
        delete_manifest(path.name, check=check)
    forget_manifest_pods()


def pods_in_manifest(name: str) -> list[Pod]:
    aliases = _manifest_aliases.get(name)
    if not aliases:
        raise RuntimeError(f"manifest {name} has no recorded pods")
    seen: set[tuple[str, str]] = set()
    pods: list[Pod] = []
    for alias in aliases:
        pod = get_pod(alias)
        key = (pod.namespace, pod.name)
        if key in seen:
            continue
        seen.add(key)
        pods.append(pod)
    return pods


def get_pod(alias: str) -> Pod:
    if alias == global_strings.TEST_POD_ALIAS:
        return get_test_pod()
    pod = get_cluster().main_node.pods_by_alias.get(alias)
    if pod is None:
        raise RuntimeError(f"pod {alias} is not deployed")
    return pod


def restart_pod(alias: str) -> None:
    pod = get_pod(alias)
    node = get_cluster().main_node
    container_hex = shlex.quote(pod.container_id.split("://", 1)[-1])
    logger.log_info(f"Killing pid 1 of {pod.namespace}/{pod.name} from {node.name}")
    host_pid = node.run_ssh_command(
        "set -e; "
        f"pid=$(crictl inspect {container_hex} "
        "| sed -n 's/.*\"pid\": *\\([0-9][0-9]*\\).*/\\1/p' "
        "| awk '$1 > 1 { print; exit }'); "
        'test -n "$pid"; '
        'kill -9 "$pid"; '
        'echo "$pid"'
    )
    logger.log_info(f"Killed host pid {host_pid} for pod {alias}")


def ensure_pod_uid_unchanged_and_container_id_changed(
    alias: str,
    previous_uid: str,
    previous_container_id: str,
) -> None:
    pod = get_pod(alias)
    deadline = time.time() + global_numbers.TEST_POD_READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        refreshed = _pod_after_container_restart(
            pod.name,
            pod.namespace,
            previous_uid,
            previous_container_id,
        )
        if refreshed is not None:
            _remember_pod(alias, refreshed)
            logger.log_info(
                f"pod {alias} uid={refreshed.uid} container id {previous_container_id} -> {refreshed.container_id}"
            )
            return
        time.sleep(0.2)
    raise RuntimeError(
        f"pod {pod.namespace}/{pod.name} kept uid {previous_uid} but did not get a new container id"
    )


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
    _remember_pod(global_strings.TEST_POD_ALIAS, refreshed)
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
            f"{global_strings.KIND} helper called with CLUSTER_TYPE={global_strings.CLUSTER_TYPE}"
        )


def _run_kind_script(script: Path) -> None:
    if not script.is_file():
        raise RuntimeError(f"{global_strings.KIND} script not found: {script}")
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


def _remember_pod(alias: str, pod: Pod) -> None:
    node = get_cluster().main_node
    if pod.node_name != node.name:
        raise RuntimeError(f"pod {pod.name} landed on {pod.node_name}, expected {node.name}")
    previous = node.pods_by_alias.get(alias)
    if previous is not None and previous.uid != pod.uid and node.test_pod_uid != previous.uid:
        node.pod_uid_to_pod_info.pop(previous.uid, None)
    node.pods_by_alias[alias] = pod
    node.pod_uid_to_pod_info[pod.uid] = pod
    if alias == global_strings.TEST_POD_ALIAS:
        node.test_pod_uid = pod.uid


def _manifest_path(name: str) -> Path:
    if Path(name).name != name or not name.endswith(".yaml"):
        raise RuntimeError(f"manifest name must be a yaml file name, got {name!r}")
    path = global_strings.MANIFESTS_DIR / name
    if not path.is_file():
        raise RuntimeError(f"manifest not found: {path}")
    return path


def _render_manifest(name: str) -> str:
    text = _manifest_path(name).read_text(encoding="utf-8")
    node_name = get_cluster().main_node.name
    if "<main_node_name>" not in text:
        raise RuntimeError(f"manifest {name} has no <main_node_name> placeholder")
    return text.replace("<main_node_name>", node_name)


def _fit_pinned_deployments(rendered: str) -> str:
    documents = re.split(r"\n---\n", rendered)
    return "\n---\n".join(_fit_pinned_deployment_document(document) for document in documents)


def _fit_pinned_deployment_document(document: str) -> str:
    if not re.search(r"(?m)^kind:\s*Deployment\s*$", document):
        return document
    replicas_match = re.search(r"(?m)^(\s*)replicas:\s*(\d+)\s*$", document)
    node_match = re.search(r"(?m)^\s*nodeName:\s*(\S+)\s*$", document)
    if replicas_match is None or node_match is None:
        return document
    requested = int(replicas_match.group(2))
    node_name = node_match.group(1)
    free_slots = _free_pod_slots(node_name)
    allowed = max(free_slots - _owlsm_slot_reserve(node_name), 0)
    fitted = min(requested, allowed, _MAX_PINNED_DEPLOYMENT_REPLICAS)
    if fitted < 1:
        raise RuntimeError(
            f"node {node_name} has {free_slots} free pod slots, "
            f"not enough for a deployment that requests {requested}"
        )
    if fitted == requested:
        return document
    logger.log_info(
        f"node {node_name} has {free_slots} free pod slots; "
        f"deployment replicas {requested} -> {fitted}"
    )
    return document[: replicas_match.start(2)] + str(fitted) + document[replicas_match.end(2) :]


def _free_pod_slots(node_name: str) -> int:
    node = json.loads(run_kubectl(["get", "node", node_name, "-o", "json"]).stdout)
    allocatable = int(node["status"]["allocatable"]["pods"])
    listed = json.loads(
        run_kubectl(
            ["get", "pods", "-A", "--field-selector", f"spec.nodeName={node_name}", "-o", "json"]
        ).stdout
    )
    used = 0
    for item in listed.get("items") or []:
        phase = (item.get("status") or {}).get("phase", "")
        if phase in ("Succeeded", "Failed"):
            continue
        used += 1
    return max(allocatable - used, 0)


def _owlsm_slot_reserve(node_name: str) -> int:
    if owlsm_pod_name_on_node(node_name):
        return 0
    return 1


def _pod_refs(items: list[dict]) -> list[tuple[str, str, str]]:
    pods: list[tuple[str, str, str]] = []
    for item in items:
        if item.get("kind") != "Pod":
            continue
        metadata = item.get("metadata") or {}
        pod_name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        alias = (metadata.get("annotations") or {}).get(_POD_ALIAS_ANNOTATION, "")
        if not pod_name or not namespace or not alias:
            raise RuntimeError(
                f"pod {namespace}/{pod_name} needs a name, namespace, and {_POD_ALIAS_ANNOTATION} annotation"
            )
        pods.append((namespace, pod_name, alias))
    aliases = [alias for _namespace, _pod_name, alias in pods]
    if len(aliases) != len(set(aliases)):
        raise RuntimeError(f"duplicate {_POD_ALIAS_ANNOTATION} in manifest: {aliases}")
    return pods


def _wait_for_named_pods(pods: list[tuple[str, str, str]]) -> None:
    if not pods:
        return
    timeout = f"{global_numbers.TEST_POD_READY_TIMEOUT_SECONDS}s"
    by_namespace: dict[str, list[str]] = {}
    for namespace, pod_name, _alias in pods:
        by_namespace.setdefault(namespace, []).append(pod_name)
    for namespace, pod_names in by_namespace.items():
        run_kubectl(
            [
                "wait",
                "--for=condition=Ready",
                *[f"pod/{pod_name}" for pod_name in pod_names],
                "-n",
                namespace,
                f"--timeout={timeout}",
            ]
        )


def _deployment_pod_refs(items: list[dict]) -> list[tuple[str, str, str]]:
    pods: list[tuple[str, str, str]] = []
    timeout = f"{global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS}s"
    for item in items:
        if item.get("kind") != "Deployment":
            continue
        metadata = item.get("metadata") or {}
        name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        if not name or not namespace:
            raise RuntimeError("deployment needs a name and namespace")
        run_kubectl(
            [
                "rollout",
                "status",
                f"deployment/{name}",
                "-n",
                namespace,
                f"--timeout={timeout}",
            ]
        )
        spec = item.get("spec") or {}
        replicas = int(spec.get("replicas", 1))
        labels = ((spec.get("selector") or {}).get("matchLabels")) or {}
        if not labels:
            raise RuntimeError(f"deployment {namespace}/{name} has no selector")
        selector = ",".join(f"{key}={value}" for key, value in labels.items())
        result = run_kubectl(["get", "pods", "-n", namespace, "-l", selector, "-o", "json"])
        pod_items = json.loads(result.stdout).get("items") or []
        if len(pod_items) != replicas:
            raise RuntimeError(
                f"deployment {namespace}/{name} has {len(pod_items)} pods, expected {replicas}"
            )
        template_alias = (
            ((spec.get("template") or {}).get("metadata") or {}).get("annotations") or {}
        ).get(_POD_ALIAS_ANNOTATION, "")
        pod_items.sort(key=lambda pod_item: (pod_item.get("metadata") or {}).get("name", ""))
        for index, pod_item in enumerate(pod_items):
            pod_name = (pod_item.get("metadata") or {}).get("name", "")
            if not pod_name:
                raise RuntimeError(f"deployment {namespace}/{name} has a pod with no name")
            pods.append((namespace, pod_name, pod_name))
            if index == 0 and template_alias and template_alias != pod_name:
                pods.append((namespace, pod_name, template_alias))
    return pods


def _remember_manifest_pods(manifest_name: str, refs: list[tuple[str, str, str]]) -> None:
    loaded = _pods_in_namespaces({namespace for namespace, _pod_name, _alias in refs})
    aliases: list[str] = []
    recorded: set[tuple[str, str]] = set()
    for namespace, pod_name, alias in refs:
        pod = loaded.get((namespace, pod_name))
        if pod is None or not pod.uid or not pod.container_id or not pod.node_name:
            pod = _wait_for_pod_identity(pod_name, namespace)
        _remember_pod(alias, pod)
        aliases.append(alias)
        recorded.add((namespace, pod_name))
    _manifest_aliases[manifest_name] = aliases
    logger.log_info(f"manifest {manifest_name} recorded {len(recorded)} pods")


def _pods_in_namespaces(namespaces: set[str]) -> dict[tuple[str, str], Pod]:
    found: dict[tuple[str, str], Pod] = {}
    for namespace in sorted(namespaces):
        result = run_kubectl(["get", "pods", "-n", namespace, "-o", "json"])
        for item in json.loads(result.stdout).get("items") or []:
            pod = _pod_from_item(item)
            found[(pod.namespace, pod.name)] = pod
    return found


def _manifest_items(rendered: str) -> list[dict]:
    result = run_kubectl(["get", "-f", "-", "-o", "json"], stdin=rendered)
    parsed = json.loads(result.stdout)
    if parsed.get("kind") == "List":
        return parsed.get("items") or []
    return [parsed]


def forget_manifest_pods() -> None:
    _manifest_aliases.clear()
    cluster = global_objects.CLUSTER
    if cluster is None:
        return
    keep = global_strings.TEST_POD_ALIAS
    for node in cluster.nodes():
        for alias in list(node.pods_by_alias):
            if alias != keep:
                _drop_pod_alias(node, alias)


def _drop_pod_alias(node: Node, alias: str) -> None:
    pod = node.pods_by_alias.pop(alias, None)
    if pod is not None and node.test_pod_uid != pod.uid:
        node.pod_uid_to_pod_info.pop(pod.uid, None)


def _wait_for_pod_identity(name: str, namespace: str) -> Pod:
    deadline = time.time() + 10
    pod = _pod_from_kubectl(name, namespace)
    while time.time() < deadline:
        if pod.uid and pod.container_id and pod.node_name:
            return pod
        time.sleep(0.2)
        pod = _pod_from_kubectl(name, namespace)
    raise RuntimeError(f"pod {namespace}/{name} has no uid or container id")


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


def _pod_after_container_restart(
    name: str,
    namespace: str,
    previous_uid: str,
    previous_container_id: str,
) -> Pod | None:
    result = run_kubectl(["get", "pod", name, "-n", namespace, "-o", "json"], check=False)
    if result.returncode != 0:
        return None
    item = json.loads(result.stdout)
    statuses = (item.get("status") or {}).get("containerStatuses") or []
    if not statuses or not statuses[0].get("ready"):
        return None
    pod = _pod_from_item(item)
    if pod.uid != previous_uid:
        raise RuntimeError(f"pod {namespace}/{name} uid changed from {previous_uid} to {pod.uid}")
    if not pod.container_id or pod.container_id == previous_container_id:
        return None
    return pod


def _pod_from_kubectl(name: str, namespace: str) -> Pod:
    result = run_kubectl(["get", "pod", name, "-n", namespace, "-o", "json"])
    return _pod_from_item(json.loads(result.stdout))


def _pod_from_item(item: dict) -> Pod:
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
        name=metadata.get("name", ""),
        namespace=metadata.get("namespace", ""),
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

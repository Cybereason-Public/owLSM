from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from Utils.cluster_models import StdoutReader
from Utils.cluster_utils import (
    delete_manifests,
    get_cluster,
    owlsm_pod_name_on_node,
    remove_test_namespace,
    remove_test_pod,
    run_kubectl,
)
from Utils.logger_utils import logger
from globals.global_numbers import global_numbers
from globals.global_objects import global_objects
from globals.global_strings import global_strings


def deploy_owlsm(image_repository: str, image_tag: str) -> None:
    chart = global_strings.HELM_CHART_PATH
    if not chart.is_dir():
        raise RuntimeError(f"Helm chart not found: {chart}")
    release = global_strings.OWLSM_HELM_RELEASE
    namespace = global_strings.OWLSM_NAMESPACE
    logger.log_info(
        f"Helm installing {release} from {chart} into {namespace} "
        f"image={image_repository}:{image_tag}"
    )
    _run_helm(
        [
            "upgrade",
            "--install",
            release,
            str(chart),
            "--namespace",
            namespace,
            "--reset-values",
            "--set",
            f"image.repository={image_repository}",
            "--set",
            f"image.tag={image_tag}",
            *_test_rollout_helm_args(),
        ]
    )
    _wait_for_owlsm_rollout()


def is_owlsm_deployed_cluster_wide() -> bool:
    result = run_kubectl(
        [
            "get",
            "daemonset",
            global_strings.OWLSM_DAEMONSET,
            "-n",
            global_strings.OWLSM_NAMESPACE,
            "-o",
            "json",
        ],
        check=False,
    )
    if result.returncode != 0:
        logger.log_info("owlsm DaemonSet is not present")
        return False
    status = json.loads(result.stdout).get("status", {})
    desired = status.get("desiredNumberScheduled", 0)
    current = status.get("currentNumberScheduled", 0)
    ready = status.get("numberReady", 0)
    node_count = _cluster_node_count()
    logger.log_info(
        f"owlsm DaemonSet desired={desired} current={current} "
        f"ready={ready} node_count={node_count}"
    )
    return desired > 0 and desired == current == ready == node_count


def is_owlsm_process_running_on_all_nodes() -> bool:
    return count_nodes_with_owlsm_process() == len(get_cluster().nodes())


def is_owlsm_process_absent_on_all_nodes() -> bool:
    return count_nodes_with_owlsm_process() == 0


def wait_until_owlsm_process_running_on_all_nodes() -> bool:
    deadline = time.time() + global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS
    while time.time() < deadline:
        if is_owlsm_process_running_on_all_nodes():
            return True
        time.sleep(0.5)
    return False


def count_nodes_with_owlsm_process() -> int:
    count = 0
    for node in get_cluster().nodes():
        output = node.run_ssh_command("pgrep -l owlsm", check=False)
        if "owlsm" in output:
            logger.log_info(f"owlsm process found on {node.name}: {output}")
            count += 1
        else:
            logger.log_info(f"owlsm process not found on {node.name}")
    return count


def deploy_owlsm_and_ensure_running(image_repository: str, image_tag: str) -> None:
    deploy_owlsm(image_repository, image_tag)
    _ensure_owlsm_running_and_reading_logs()


def upgrade_owlsm_values_and_ensure_running(values: dict[str, str]) -> None:
    stop_owlsm_stdout_reader()
    upgrade_owlsm_values(values)
    _ensure_owlsm_running_and_reading_logs()


def upgrade_owlsm_values(values: dict[str, str]) -> None:
    if not values:
        raise RuntimeError("no helm values to change")
    chart = global_strings.HELM_CHART_PATH
    if not chart.is_dir():
        raise RuntimeError(f"Helm chart not found: {chart}")
    release = global_strings.OWLSM_HELM_RELEASE
    namespace = global_strings.OWLSM_NAMESPACE
    args = [
        "upgrade",
        release,
        str(chart),
        "--namespace",
        namespace,
        "--reuse-values",
        *_test_rollout_helm_args(),
    ]
    for key, value in values.items():
        args.extend(["--set", f"{key}={value}"])
    logger.log_info(f"Helm upgrading {release} values={values}")
    _run_helm(args)
    _wait_for_owlsm_rollout()


def _ensure_owlsm_running_and_reading_logs() -> None:
    assert is_owlsm_deployed_cluster_wide(), "owlsm is not deployed cluster-wide"
    assert wait_until_owlsm_process_running_on_all_nodes(), (
        "owlsm process is not running on all nodes"
    )
    start_owlsm_stdout_reader()


def _wait_for_owlsm_rollout() -> None:
    timeout = f"{global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS}s"
    run_kubectl(
        [
            "rollout",
            "status",
            f"daemonset/{global_strings.OWLSM_DAEMONSET}",
            "-n",
            global_strings.OWLSM_NAMESPACE,
            f"--timeout={timeout}",
        ]
    )


def start_owlsm_stdout_reader() -> None:
    cluster = get_cluster()
    reader = cluster.main_node.stdout_reader_thread
    if reader is None:
        reader = StdoutReader(cluster.main_node.name)
        cluster.main_node.stdout_reader_thread = reader
    assert wait_until_owlsm_pod_log_has_json_event(), (
        "owlsm pod log is not emitting JSON events yet"
    )
    reader.start()
    assert wait_until_owlsm_stdout_has_json_event(), (
        "owlsm is not emitting JSON events yet"
    )


def wait_until_owlsm_pod_log_has_json_event() -> bool:
    deadline = time.time() + global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS
    node_name = get_cluster().main_node.name
    while time.time() < deadline:
        pod_name = owlsm_pod_name_on_node(node_name)
        if pod_name:
            result = run_kubectl(
                [
                    "logs",
                    "-n",
                    global_strings.OWLSM_NAMESPACE,
                    pod_name,
                    "-c",
                    global_strings.OWLSM_CONTAINER_NAME,
                    "--tail=20",
                ],
                check=False,
            )
            if result.returncode == 0:
                for line in (result.stdout or "").splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(event, dict) and event.get("type"):
                        logger.log_info("owlsm pod log has JSON events")
                        return True
        time.sleep(0.5)
    return False


def wait_until_owlsm_stdout_has_json_event() -> bool:
    deadline = time.time() + global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS
    log_path = global_strings.OWLSM_OUTPUT_LOG
    follow_alive_since = None
    while time.time() < deadline:
        if _output_log_has_json_event(log_path):
            logger.log_info("owlsm stdout is emitting JSON events")
            return True
        reader = get_cluster().main_node.stdout_reader_thread
        if reader is not None and reader.follow_is_alive():
            if follow_alive_since is None:
                follow_alive_since = time.time()
            elif time.time() - follow_alive_since >= 3:
                logger.log_info("owlsm log follow stayed up and the pod log already has JSON events")
                return True
        else:
            follow_alive_since = None
        time.sleep(0.2)
    last_line = ""
    if log_path.is_file():
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        last_line = lines[-1] if lines else ""
    logger.log_error(f"owlsm stdout has no JSON event; last line: {last_line!r}")
    return False


def _output_log_has_json_event(log_path) -> bool:
    if not log_path.is_file():
        return False
    with log_path.open("r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("type"):
                return True
    return False


def stop_owlsm_stdout_reader() -> None:
    cluster = global_objects.CLUSTER
    if cluster is None:
        return
    for node in cluster.nodes():
        if node.stdout_reader_thread is not None:
            logger.log_info(f"Stopping stdout reader on {node.name}")
            node.stdout_reader_thread.stop()


def copy_owlsm_logger_log() -> None:
    cluster = get_cluster()
    for node in cluster.nodes():
        if node.name == cluster.main_node.name:
            dest_path = global_strings.OWLSM_LOGGER_LOG
        else:
            dest_path = global_strings.AUTOMATION_ROOT_DIR / f"owlsm.{node.name}.log"
        pod_name = owlsm_pod_name_on_node(node.name)
        if not pod_name:
            raise RuntimeError(f"no owlsm pod on {node.name}")
        if dest_path.exists():
            dest_path.unlink()
        logger.log_info(f"Copying owlsm logger from {pod_name} on {node.name} to {dest_path}")
        run_kubectl(
            [
                "cp",
                f"{global_strings.OWLSM_NAMESPACE}/{pod_name}:{global_strings.OWLSM_CONTAINER_LOG_PATH}",
                str(dest_path),
                "-c",
                global_strings.OWLSM_CONTAINER_NAME,
            ]
        )


def remove_leftover_cluster_objects() -> None:
    logger.log_info("Removing leftover owlsm Helm release and test-pod namespace")
    remove_owlsm()
    remove_test_pod()
    delete_manifests(check=False)
    remove_test_namespace()


def remove_owlsm() -> None:
    stop_owlsm_stdout_reader()
    release = global_strings.OWLSM_HELM_RELEASE
    namespace = global_strings.OWLSM_NAMESPACE
    status = _run_helm(["status", release, "-n", namespace], check=False)
    if status.returncode != 0:
        logger.log_info(f"Helm release {release} is not installed")
        return
    logger.log_info(f"Helm uninstalling {release} from {namespace}")
    _run_helm(["uninstall", release, "-n", namespace, "--wait"])
    run_kubectl(
        [
            "wait",
            "--for=delete",
            "pod",
            "-l",
            f"app.kubernetes.io/name={global_strings.OWLSM_APP_NAME}",
            "-n",
            namespace,
            f"--timeout={global_numbers.OWLSM_ROLLOUT_TIMEOUT_SECONDS}s",
        ],
        check=False,
    )


def _test_rollout_helm_args() -> list[str]:
    return [
        "--set-string",
        "updateStrategy.rollingUpdate.maxUnavailable=100%",
    ]


def _run_helm(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    command = [_helm_bin(), f"--kubeconfig={global_strings.KUBECONF_PATH}"]
    if global_strings.KUBE_CONTEXT:
        command.extend(["--kube-context", global_strings.KUBE_CONTEXT])
    command.extend(args)
    logger.log_info(f"Running: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.stdout:
        logger.log_info(result.stdout.strip())
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout).strip()
        if check:
            logger.log_error(error_text)
            raise RuntimeError(f"helm failed: {' '.join(args)}: {error_text}")
        logger.log_info(error_text)
    elif result.stderr:
        logger.log_info(result.stderr.strip())
    return result


def _helm_bin() -> str:
    found = shutil.which("helm")
    if found:
        return found
    raise RuntimeError("helm not found in PATH")


def _cluster_node_count() -> int:
    result = run_kubectl(["get", "nodes", "-o", "json"])
    return len(json.loads(result.stdout).get("items", []))

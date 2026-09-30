#!/usr/bin/env bash
# Create a fresh 2-node OKE pool (same settings + cloud-init as Phase 5),
# wait until its nodes are Ready, then cordon and delete every older pool.
# Intended to run once per GitHub workflow / run_oke.sh invocation.
set -euo pipefail

export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

if [[ -z "${OKE_CLUSTER_OCID:-}" || -z "${OKE_COMPARTMENT_OCID:-}" ]]; then
    echo "error: OKE_CLUSTER_OCID and OKE_COMPARTMENT_OCID must be set" >&2
    exit 1
fi

CLUSTER_ID="${OKE_CLUSTER_OCID}"
COMPARTMENT_ID="${OKE_COMPARTMENT_OCID}"
KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
SSH_KEY_PATH="${OWLSM_OKE_SSH_KEY:-}"
EXPECTED_NODES="${OKE_NODE_POOL_SIZE:-2}"
NEW_NAME="${OKE_NODE_POOL_NAME:-pool-owlsm-$(date -u +%Y%m%d%H%M%S)}"
NODE_LABEL="owlsm.io/node-pool=${NEW_NAME}"
READY_TIMEOUT_SECONDS="${OKE_NODE_READY_TIMEOUT_SECONDS:-600}"
SSH_TIMEOUT_SECONDS="${OKE_SSH_READY_TIMEOUT_SECONDS:-180}"

if [[ -z "${OKE_SSH_PUBLIC_KEY:-}" ]]; then
    echo "error: OKE_SSH_PUBLIC_KEY is unset" >&2
    exit 1
fi

if [[ -z "${SSH_KEY_PATH}" || ! -f "${SSH_KEY_PATH}" ]]; then
    echo "error: OWLSM_OKE_SSH_KEY must be a readable private key path" >&2
    exit 1
fi

if ! command -v oci >/dev/null 2>&1; then
    echo "error: oci is required but not in PATH" >&2
    exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "error: kubectl is required but not in PATH" >&2
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "error: ssh is required but not in PATH" >&2
    exit 1
fi

kubectl_cmd() {
    kubectl --kubeconfig "${KUBECONFIG_FILE}" "$@"
}

list_pool_ids() {
    CLUSTER_ID="${CLUSTER_ID}" COMPARTMENT_ID="${COMPARTMENT_ID}" python3 -c '
import json, os, subprocess
result = subprocess.run(
    [
        "oci", "ce", "node-pool", "list",
        "--cluster-id", os.environ["CLUSTER_ID"],
        "--compartment-id", os.environ["COMPARTMENT_ID"],
        "--all",
        "--output", "json",
    ],
    check=True,
    capture_output=True,
    text=True,
)
for pool in json.loads(result.stdout)["data"]:
    if pool.get("lifecycle-state") in ("ACTIVE", "CREATING", "UPDATING"):
        print(pool["id"])
'
}

node_names() {
    kubectl_cmd get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
}

wait_for_new_nodes() {
    local deadline=$((SECONDS + READY_TIMEOUT_SECONDS))
    local count
    while (( SECONDS < deadline )); do
        count="$(kubectl_cmd get nodes -l "${NODE_LABEL}" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
        echo "Waiting for ${EXPECTED_NODES} nodes with ${NODE_LABEL} (have ${count})"
        if (( count >= EXPECTED_NODES )); then
            kubectl_cmd wait --for=condition=Ready node -l "${NODE_LABEL}" --timeout="${READY_TIMEOUT_SECONDS}s"
            return 0
        fi
        sleep 10
    done
    echo "error: timed out waiting for ${EXPECTED_NODES} Ready nodes with ${NODE_LABEL}" >&2
    kubectl_cmd get nodes -o wide >&2 || true
    return 1
}

new_node_external_ips() {
    kubectl_cmd get nodes -l "${NODE_LABEL}" -o json | python3 -c '
import json, sys
for node in json.load(sys.stdin).get("items", []):
    for address in node.get("status", {}).get("addresses", []):
        if address.get("type") == "ExternalIP" and address.get("address"):
            print(address["address"])
            break
'
}

wait_for_ssh() {
    local ip="$1"
    local user="$2"
    local deadline=$((SECONDS + SSH_TIMEOUT_SECONDS))
    local ssh_opts=(
        -i "${SSH_KEY_PATH}"
        -o StrictHostKeyChecking=accept-new
        -o ConnectTimeout=10
        -o BatchMode=yes
        -o IdentitiesOnly=yes
    )
    while (( SECONDS < deadline )); do
        if ssh "${ssh_opts[@]}" "${user}@${ip}" "echo OK_${user}"; then
            return 0
        fi
        sleep 5
    done
    echo "error: SSH as ${user} to ${ip} failed" >&2
    return 1
}

mapfile -t old_pool_ids < <(list_pool_ids)
mapfile -t old_node_names < <(node_names)

echo "Recycling OKE node pools; creating ${NEW_NAME}"
if ((${#old_pool_ids[@]})); then
    echo "Existing pools: ${old_pool_ids[*]}"
fi
if ((${#old_node_names[@]})); then
    echo "Existing nodes: ${old_node_names[*]}"
fi

OKE_NODE_POOL_NAME="${NEW_NAME}" "${SCRIPT_DIR}/create_oke_test_node_pool.sh"
wait_for_new_nodes

for node_name in "${old_node_names[@]}"; do
    if [[ -n "${node_name}" ]]; then
        echo "Cordoning ${node_name}"
        kubectl_cmd cordon "${node_name}" || true
    fi
done

for pool_id in "${old_pool_ids[@]}"; do
    if [[ -z "${pool_id}" ]]; then
        continue
    fi
    echo "Deleting old node pool ${pool_id}"
    oci ce node-pool delete \
        --node-pool-id "${pool_id}" \
        --force \
        --wait-for-state SUCCEEDED \
        --wait-for-state FAILED
done

for node_name in "${old_node_names[@]}"; do
    if [[ -n "${node_name}" ]]; then
        echo "Waiting for old node ${node_name} to go away"
        kubectl_cmd wait --for=delete "node/${node_name}" --timeout="${READY_TIMEOUT_SECONDS}s" || true
    fi
done

echo "Remaining nodes:"
kubectl_cmd get nodes -o wide

mapfile -t new_ips < <(new_node_external_ips)
if ((${#new_ips[@]} < EXPECTED_NODES)); then
    echo "error: expected ${EXPECTED_NODES} ExternalIPs for ${NODE_LABEL}, found ${#new_ips[@]}" >&2
    exit 1
fi

chmod 600 "${SSH_KEY_PATH}"
for ip in "${new_ips[@]}"; do
    echo "Checking SSH on ${ip}"
    wait_for_ssh "${ip}" root
    wait_for_ssh "${ip}" opc
done

echo "Node-pool recycle finished: ${NEW_NAME}"

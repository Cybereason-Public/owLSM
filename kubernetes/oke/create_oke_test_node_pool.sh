#!/usr/bin/env bash
# Create a 2-node OKE pool with the same shape/image/subnet as the existing
# test cluster, plus cloud-init that enables root SSH with OKE_SSH_PUBLIC_KEY.
# The same public key is also passed as --ssh-public-key for the opc user.
set -euo pipefail

export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

required_vars=(
    OKE_CLUSTER_OCID
    OKE_COMPARTMENT_OCID
    OKE_NODE_IMAGE_ID
    OKE_NODE_SUBNET_ID
    OKE_AVAILABILITY_DOMAIN_1
    OKE_AVAILABILITY_DOMAIN_2
    OKE_SSH_PUBLIC_KEY
)
for var_name in "${required_vars[@]}"; do
    if [[ -z "${!var_name:-}" ]]; then
        echo "error: ${var_name} is unset" >&2
        exit 1
    fi
done

CLUSTER_ID="${OKE_CLUSTER_OCID}"
COMPARTMENT_ID="${OKE_COMPARTMENT_OCID}"
REGION="${OKE_REGION:-us-ashburn-1}"
POOL_NAME="${OKE_NODE_POOL_NAME:-pool-owlsm}"
IMAGE_ID="${OKE_NODE_IMAGE_ID}"
SUBNET_ID="${OKE_NODE_SUBNET_ID}"
K8S_VERSION="${OKE_K8S_VERSION:-v1.36.1}"
NODE_SHAPE="${OKE_NODE_SHAPE:-VM.Standard.E3.Flex}"

if ! command -v oci >/dev/null 2>&1; then
    echo "error: oci is required but not in PATH" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required but not in PATH" >&2
    exit 1
fi

cloud_init="$("${SCRIPT_DIR}/oke_worker_cloud_init.sh")"
metadata_file="$(mktemp)"
trap 'rm -f "${metadata_file}"' EXIT
CLOUD_INIT="${cloud_init}" METADATA_FILE="${metadata_file}" python3 -c '
import base64, json, os
script = os.environ["CLOUD_INIT"].encode()
with open(os.environ["METADATA_FILE"], "w", encoding="utf-8") as out:
    json.dump({"user_data": base64.b64encode(script).decode("ascii")}, out)
'

placement_configs='[
  {"availabilityDomain":"'"${OKE_AVAILABILITY_DOMAIN_1}"'","subnetId":"'"${SUBNET_ID}"'"},
  {"availabilityDomain":"'"${OKE_AVAILABILITY_DOMAIN_2}"'","subnetId":"'"${SUBNET_ID}"'"}
]'
shape_config='{"ocpus":1.0,"memoryInGBs":16.0}'
pod_subnet_ids='["'"${SUBNET_ID}"'"]'
initial_node_labels='[{"key":"owlsm.io/node-pool","value":"'"${POOL_NAME}"'"}]'

echo "Creating node pool ${POOL_NAME} (2 nodes, ${NODE_SHAPE}, ${K8S_VERSION})"
oci ce node-pool create \
    --region "${REGION}" \
    --cluster-id "${CLUSTER_ID}" \
    --compartment-id "${COMPARTMENT_ID}" \
    --name "${POOL_NAME}" \
    --kubernetes-version "${K8S_VERSION}" \
    --node-shape "${NODE_SHAPE}" \
    --node-shape-config "${shape_config}" \
    --node-image-id "${IMAGE_ID}" \
    --node-boot-volume-size-in-gbs 50 \
    --size 2 \
    --placement-configs "${placement_configs}" \
    --initial-node-labels "${initial_node_labels}" \
    --ssh-public-key "${OKE_SSH_PUBLIC_KEY}" \
    --node-metadata "file://${metadata_file}" \
    --cni-type OCI_VCN_IP_NATIVE \
    --pod-subnet-ids "${pod_subnet_ids}" \
    --wait-for-state SUCCEEDED \
    --wait-for-state FAILED

pool_id="$(
    CLUSTER_ID="${CLUSTER_ID}" COMPARTMENT_ID="${COMPARTMENT_ID}" POOL_NAME="${POOL_NAME}" python3 -c '
import json, os, subprocess
name = os.environ["POOL_NAME"]
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
matches = [pool["id"] for pool in json.loads(result.stdout)["data"] if pool.get("name") == name]
if not matches:
    raise SystemExit(f"created pool {name} not found")
print(matches[0])
'
)"
echo "NODE_POOL_NAME=${POOL_NAME}"
echo "NODE_POOL_ID=${pool_id}"

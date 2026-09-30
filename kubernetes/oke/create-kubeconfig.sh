#!/usr/bin/env bash
# From repo root: ./kubernetes/oke/create-kubeconfig.sh
# Refresh kubeconfig for the existing OKE cluster. Does not create or delete the cluster.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

if [[ -z "${OKE_CLUSTER_OCID:-}" ]]; then
    echo "error: OKE_CLUSTER_OCID is unset" >&2
    exit 1
fi

CLUSTER_ID="${OKE_CLUSTER_OCID}"
REGION="${OKE_REGION:-us-ashburn-1}"
KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"

usage() {
    echo "usage: $0" >&2
    echo "  refresh kubeconfig for the existing OKE cluster (PUBLIC_ENDPOINT)" >&2
    echo "  env: OKE_CLUSTER_OCID OKE_REGION KUBECONFIG" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if ! command -v oci >/dev/null 2>&1; then
    echo "error: oci is required but not in PATH" >&2
    exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "error: kubectl is required but not in PATH" >&2
    exit 1
fi

export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True

echo "Refreshing kubeconfig at $KUBECONFIG_FILE"
oci ce cluster create-kubeconfig \
    --cluster-id "$CLUSTER_ID" \
    --file "$KUBECONFIG_FILE" \
    --region "$REGION" \
    --token-version 2.0.0 \
    --kube-endpoint PUBLIC_ENDPOINT

echo "Nodes:"
kubectl --kubeconfig "$KUBECONFIG_FILE" get nodes -o wide

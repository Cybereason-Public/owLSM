#!/usr/bin/env bash
# Recycle the OKE node pool once. Call from the K8s CI workflow (k8s-oci), not from pytest. After this, pytest uses OWLSM_OKE_SKIP_NODE_POOL_RECYCLE=1.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

export OWLSM_OKE_SSH_KEY="$("${SCRIPT_DIR}/write_oke_ssh_key.sh")"

if [[ -z "${OKE_SSH_PUBLIC_KEY:-}" ]]; then
    if [[ -f "${OWLSM_OKE_SSH_KEY}.pub" ]]; then
        OKE_SSH_PUBLIC_KEY="$(tr -d '\r' < "${OWLSM_OKE_SSH_KEY}.pub")"
    else
        OKE_SSH_PUBLIC_KEY="$(ssh-keygen -y -f "${OWLSM_OKE_SSH_KEY}")"
    fi
    export OKE_SSH_PUBLIC_KEY
fi

echo "Refreshing OKE kubeconfig"
"${SCRIPT_DIR}/create-kubeconfig.sh"

echo "Recycling OKE node pool once"
"${SCRIPT_DIR}/recycle_oke_node_pool.sh"

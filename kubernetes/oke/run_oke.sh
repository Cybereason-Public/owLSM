#!/usr/bin/env bash
# Local stand-in for the future GitHub OKE workflow.
# Stable env names (1e should only wrap this script):
#   OWLSM_CLUSTER_TYPE
#   KUBECONFIG
#   OWLSM_KUBE_CONTEXT
#   OWLSM_IMAGE_REPOSITORY
#   OWLSM_IMAGE_TAG
#   OWLSM_OKE_SSH_KEY
# Optional:
#   OWLSM_OKE_SKIP_NODE_POOL_RECYCLE=1   # when Terraform already recycled
#   OKE_SSH_PUBLIC_KEY                   # contents; default is KEY.pub
# Extra args are passed to pytest.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
AUTOMATION_DIR="${REPO_ROOT}/src/Tests/K8S_Automation"

if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

export OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True
export OWLSM_CLUSTER_TYPE="${OWLSM_CLUSTER_TYPE:-oci}"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
export OWLSM_IMAGE_REPOSITORY="${OWLSM_IMAGE_REPOSITORY:-ttl.sh/test-image-owlsm-20260924090037}"
export OWLSM_IMAGE_TAG="${OWLSM_IMAGE_TAG:-24h}"

if [[ "${OWLSM_CLUSTER_TYPE}" != "oci" ]]; then
    echo "error: run_oke.sh requires OWLSM_CLUSTER_TYPE=oci" >&2
    exit 1
fi

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

export OWLSM_KUBE_CONTEXT="${OWLSM_KUBE_CONTEXT:-$(kubectl --kubeconfig "${KUBECONFIG}" config current-context)}"
echo "Using kube context ${OWLSM_KUBE_CONTEXT}"

if [[ "${OWLSM_OKE_SKIP_NODE_POOL_RECYCLE:-0}" == "1" ]]; then
    echo "Skipping node-pool recycle (OWLSM_OKE_SKIP_NODE_POOL_RECYCLE=1)"
else
    echo "Recycling OKE node pool"
    "${SCRIPT_DIR}/recycle_oke_node_pool.sh"
fi

if [[ -f "${AUTOMATION_DIR}/venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "${AUTOMATION_DIR}/venv/bin/activate"
fi

if ! command -v pytest >/dev/null 2>&1; then
    echo "error: pytest not found; create the venv in ${AUTOMATION_DIR} first" >&2
    exit 1
fi

echo "Running pytest CLUSTER_TYPE=${OWLSM_CLUSTER_TYPE} image=${OWLSM_IMAGE_REPOSITORY}:${OWLSM_IMAGE_TAG}"
cd "${AUTOMATION_DIR}"
export PYTHONPATH=.
pytest "$@"

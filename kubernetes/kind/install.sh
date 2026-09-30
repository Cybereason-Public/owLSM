#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/install.sh
# Optional:      ./kubernetes/kind/install.sh --cluster NAME
# Optional:      ./kubernetes/kind/install.sh --image REPO:TAG
# Helm-install kubernetes/chart into kube-system. Chart is always from disk.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

CLUSTER_NAME="kind"
RELEASE="owlsm"
NAMESPACE="kube-system"
CHART="$REPO_ROOT/kubernetes/chart"
IMAGE=""
PULL_POLICY=""

usage() {
    echo "usage: $0 [--cluster NAME] [--image REPO:TAG] [--pull-policy POLICY]" >&2
    echo "  helm upgrade --install owlsm from kubernetes/chart into kube-system" >&2
    echo "  default image is chart values (owlsm:local)" >&2
}

while [[ $# -ge 1 ]]; do
    case "$1" in
        --cluster)
            CLUSTER_NAME="${2:?--cluster requires a name}"
            shift 2
            ;;
        --image)
            IMAGE="${2:?--image requires REPO:TAG}"
            shift 2
            ;;
        --pull-policy)
            PULL_POLICY="${2:?--pull-policy requires a policy}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

KUBE_CONTEXT="kind-${CLUSTER_NAME}"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: $1 is required but not in PATH" >&2
        exit 1
    fi
}

need_cmd helm

if command -v kubectl >/dev/null 2>&1; then
    KUBECTL="$(command -v kubectl)"
elif [[ -x "$REPO_ROOT/kubectl" ]]; then
    KUBECTL="$REPO_ROOT/kubectl"
else
    echo "error: kubectl not found in PATH or at $REPO_ROOT/kubectl" >&2
    exit 1
fi

helm_args=(
    upgrade --install "$RELEASE" "$CHART"
    --namespace "$NAMESPACE"
    --kube-context "$KUBE_CONTEXT"
    --reset-values
)

if [[ -n "$IMAGE" ]]; then
    if [[ "$IMAGE" != *:* ]]; then
        echo "error: --image must be REPO:TAG (got '$IMAGE')" >&2
        exit 1
    fi
    image_tag="${IMAGE##*:}"
    image_repo="${IMAGE%:*}"
    if [[ -z "$image_repo" || -z "$image_tag" || "$image_repo" == "$IMAGE" ]]; then
        echo "error: --image must be REPO:TAG (got '$IMAGE')" >&2
        exit 1
    fi
    helm_args+=(--set "image.repository=${image_repo}" --set "image.tag=${image_tag}")
    echo "Installing Helm release '$RELEASE' into $NAMESPACE with image ${image_repo}:${image_tag}"
else
    echo "Installing Helm release '$RELEASE' into $NAMESPACE with chart default image"
fi

if [[ -n "$PULL_POLICY" ]]; then
    helm_args+=(--set "image.pullPolicy=${PULL_POLICY}")
fi

helm "${helm_args[@]}"

echo "Waiting for DaemonSet owlsm"
if ! "$KUBECTL" --context "$KUBE_CONTEXT" rollout status "daemonset/${RELEASE}" -n "$NAMESPACE" --timeout=3m; then
    echo "error: DaemonSet owlsm not Ready" >&2
    "$KUBECTL" --context "$KUBE_CONTEXT" get ds,pods -n "$NAMESPACE" -l app.kubernetes.io/name=owlsm >&2 || true
    "$KUBECTL" --context "$KUBE_CONTEXT" describe ds/owlsm -n "$NAMESPACE" >&2 || true
    exit 1
fi

"$KUBECTL" --context "$KUBE_CONTEXT" get ds,pods -n "$NAMESPACE" -l app.kubernetes.io/name=owlsm -o wide
echo "Helm install succeeded"

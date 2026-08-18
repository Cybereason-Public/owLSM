#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/setup.sh
# Optional:      ./kubernetes/kind/setup.sh --cluster NAME
# create cluster (if missing) → build/load owlsm:local → helm install → smoke check
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

CLUSTER_NAME="kind"
IMAGE="owlsm:local"
RELEASE="owlsm"
NAMESPACE="kube-system"
CHART="$REPO_ROOT/kubernetes/chart"

usage() {
    echo "usage: $0 [--cluster NAME]" >&2
    echo "  create/reuse a kind cluster, build owlsm:local, helm install, smoke check" >&2
}

while [[ $# -ge 1 ]]; do
    case "$1" in
        --cluster)
            CLUSTER_NAME="${2:?--cluster requires a name}"
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

need_cmd kind
need_cmd docker
need_cmd helm

if command -v kubectl >/dev/null 2>&1; then
    KUBECTL="$(command -v kubectl)"
elif [[ -x "$REPO_ROOT/kubectl" ]]; then
    KUBECTL="$REPO_ROOT/kubectl"
else
    echo "error: kubectl not found in PATH or at $REPO_ROOT/kubectl" >&2
    exit 1
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "Reusing existing kind cluster '$CLUSTER_NAME'"
else
    echo "Creating kind cluster '$CLUSTER_NAME'"
    kind create cluster --name "$CLUSTER_NAME"
fi

if [[ ! -d "$REPO_ROOT/build/owlsm" ]]; then
    echo "error: $REPO_ROOT/build/owlsm not found. Build first with: make -j\$(nproc) (from repo root)" >&2
    exit 1
fi

echo "Building $IMAGE"
docker build -f "$REPO_ROOT/kubernetes/Dockerfile" -t "$IMAGE" "$REPO_ROOT/build/owlsm"

echo "Loading $IMAGE into kind cluster '$CLUSTER_NAME'"
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

echo "Installing Helm release '$RELEASE' into $NAMESPACE"
helm upgrade --install "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --kube-context "$KUBE_CONTEXT"

echo "Waiting for DaemonSet owlsm"
if ! "$KUBECTL" --context "$KUBE_CONTEXT" rollout status "daemonset/${RELEASE}" -n "$NAMESPACE" --timeout=3m; then
    echo "error: DaemonSet owlsm not Ready" >&2
    "$KUBECTL" --context "$KUBE_CONTEXT" get ds,pods -n "$NAMESPACE" -l app.kubernetes.io/name=owlsm >&2 || true
    exit 1
fi

"$KUBECTL" --context "$KUBE_CONTEXT" get ds,pods -n "$NAMESPACE" -l app.kubernetes.io/name=owlsm
echo "kind setup succeeded"

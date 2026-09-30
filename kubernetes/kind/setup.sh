#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/setup.sh
# Optional:      ./kubernetes/kind/setup.sh --cluster NAME
# create cluster → build/load owlsm:local from build/owlsm-k8s → helm install → smoke check
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

CLUSTER_NAME="kind"
IMAGE="owlsm:local"
PACKAGE_DIR="$REPO_ROOT/build/owlsm-k8s"

usage() {
    echo "usage: $0 [--cluster NAME]" >&2
    echo "  create/reuse kind, build owlsm:local from build/owlsm-k8s, helm install, smoke check" >&2
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

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: $1 is required but not in PATH" >&2
        exit 1
    fi
}

need_cmd kind
need_cmd docker
need_cmd helm

"$SCRIPT_DIR/create.sh" --cluster "$CLUSTER_NAME"

if [[ ! -d "$PACKAGE_DIR" ]]; then
    echo "error: $PACKAGE_DIR not found. Build first with: make K8S=1 -j\$(nproc)" >&2
    exit 1
fi

echo "Building $IMAGE from $PACKAGE_DIR"
docker build -f "$REPO_ROOT/kubernetes/Dockerfile" -t "$IMAGE" "$PACKAGE_DIR"

echo "Loading $IMAGE into kind cluster '$CLUSTER_NAME'"
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

"$SCRIPT_DIR/install.sh" --cluster "$CLUSTER_NAME"

echo "kind setup succeeded"

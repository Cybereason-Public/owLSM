#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/delete.sh
# Optional:      ./kubernetes/kind/delete.sh --cluster NAME
set -euo pipefail

CLUSTER_NAME="kind"

usage() {
    echo "usage: $0 [--cluster NAME]" >&2
    echo "  delete the kind cluster" >&2
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

if ! command -v kind >/dev/null 2>&1; then
    echo "error: kind is required but not in PATH" >&2
    exit 1
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "Deleting kind cluster '$CLUSTER_NAME'"
    kind delete cluster --name "$CLUSTER_NAME"
else
    echo "Kind cluster '$CLUSTER_NAME' does not exist"
fi

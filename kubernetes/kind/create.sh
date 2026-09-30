#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/create.sh
# Optional:      ./kubernetes/kind/create.sh --cluster NAME
# Create (or reuse) a 2-node kind cluster with NRI, then enable SSH on the nodes.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

CLUSTER_NAME="kind"
CONFIG="$SCRIPT_DIR/cluster.yaml"
EXPECTED_NODE_COUNT=2

usage() {
    echo "usage: $0 [--cluster NAME]" >&2
    echo "  create/reuse a 2-node kind cluster (NRI on) and enable SSH on the nodes" >&2
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
    actual_node_count="$(kind get nodes --name "$CLUSTER_NAME" | wc -l)"
    if [[ "$actual_node_count" -ne "$EXPECTED_NODE_COUNT" ]]; then
        echo "error: cluster '$CLUSTER_NAME' has $actual_node_count node(s), expected $EXPECTED_NODE_COUNT" >&2
        echo "error: delete it first: $SCRIPT_DIR/delete.sh --cluster $CLUSTER_NAME" >&2
        exit 1
    fi
else
    echo "Creating kind cluster '$CLUSTER_NAME'"
    kind create cluster --name "$CLUSTER_NAME" --config "$CONFIG"
fi

echo "Waiting for $EXPECTED_NODE_COUNT nodes to be Ready"
"$KUBECTL" --context "$KUBE_CONTEXT" wait --for=condition=Ready nodes --all --timeout=180s
"$KUBECTL" --context "$KUBE_CONTEXT" get nodes -o wide

echo "Checking NRI socket and bpffs on each node"
while IFS= read -r node; do
    if ! docker exec "$node" test -S /var/run/nri/nri.sock; then
        echo "error: NRI socket /var/run/nri/nri.sock missing on $node" >&2
        exit 1
    fi
    echo "  $node: /var/run/nri/nri.sock ok"
    if ! docker exec "$node" mountpoint -q /sys/fs/bpf; then
        echo "  $node: mounting bpffs on /sys/fs/bpf"
        docker exec "$node" mount -t bpf bpf /sys/fs/bpf
    fi
    if ! docker exec "$node" mountpoint -q /sys/fs/bpf; then
        echo "error: /sys/fs/bpf is not a bpf filesystem on $node" >&2
        exit 1
    fi
    echo "  $node: /sys/fs/bpf ok"
done < <(kind get nodes --name "$CLUSTER_NAME")

"$SCRIPT_DIR/enable_ssh.sh" --cluster "$CLUSTER_NAME"

echo "kind cluster '$CLUSTER_NAME' is ready"

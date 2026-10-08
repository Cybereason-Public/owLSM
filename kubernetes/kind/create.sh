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

# fs.inotify is a host kernel limit. Kind nodes share it, and cluster.yaml cannot set it.
# inotify_init returns EMFILE ("too many open files") once max_user_instances is hit.
# The runner is not root, and sysctl -w still exits 0 after "permission denied, ignoring".
echo "Raising host inotify limits"
raise_inotify_limit() {
    local key="$1"
    local minimum="$2"
    local current
    current="$(sysctl -n "$key")"
    if [[ "$current" -lt "$minimum" ]]; then
        if [[ "$(id -u)" -eq 0 ]]; then
            sysctl -w "${key}=${minimum}"
        else
            sudo sysctl -w "${key}=${minimum}"
        fi
        current="$(sysctl -n "$key")"
    fi
    if [[ "$current" -lt "$minimum" ]]; then
        echo "error: $key is $current, need at least $minimum" >&2
        exit 1
    fi
    echo "  $key=$current"
}
raise_inotify_limit fs.inotify.max_user_instances 65536
raise_inotify_limit fs.inotify.max_user_watches 1048576
raise_inotify_limit fs.inotify.max_queued_events 65536

# Kind nodes share the host kernel. A new bpffs mount in each node's mount namespace is a
# separate filesystem, so pinned maps under /sys/fs/bpf/owLSM stay on that node.
# BPF_FS_MAGIC from linux/magic.h.
BPF_FS_MAGIC="cafe4a11"

mount_private_bpffs() {
    local node="$1"
    echo "  $node: mounting a private bpffs on /sys/fs/bpf"
    docker exec "$node" mkdir -p /sys/fs/bpf
    if docker exec "$node" mountpoint -q /sys/fs/bpf; then
        docker exec "$node" mount --make-rprivate /sys/fs/bpf
    fi
    docker exec "$node" mount -t bpf bpf /sys/fs/bpf
    local fstype
    fstype="$(docker exec "$node" stat -f -c %t /sys/fs/bpf)"
    fstype="${fstype,,}"
    if [[ "$fstype" != "$BPF_FS_MAGIC" ]]; then
        echo "error: /sys/fs/bpf on $node is not a bpf filesystem (type $fstype)" >&2
        exit 1
    fi
}

echo "Checking NRI socket and bpffs on each node"
kind_nodes=()
while IFS= read -r node; do
    if ! docker exec "$node" test -S /var/run/nri/nri.sock; then
        echo "error: NRI socket /var/run/nri/nri.sock missing on $node" >&2
        exit 1
    fi
    echo "  $node: /var/run/nri/nri.sock ok"
    mount_private_bpffs "$node"
    kind_nodes+=("$node")
done < <(kind get nodes --name "$CLUSTER_NAME")

if [[ "${#kind_nodes[@]}" -ge 2 ]]; then
    # bpffs accepts directories, which is how maps are pinned. It rejects regular files.
    docker exec "${kind_nodes[0]}" mkdir /sys/fs/bpf/owlsm-kind-bpffs-marker
    if docker exec "${kind_nodes[1]}" test -d /sys/fs/bpf/owlsm-kind-bpffs-marker; then
        echo "error: kind nodes share /sys/fs/bpf" >&2
        exit 1
    fi
    docker exec "${kind_nodes[0]}" rmdir /sys/fs/bpf/owlsm-kind-bpffs-marker
    echo "  bpffs is private on each node"
fi

"$SCRIPT_DIR/enable_ssh.sh" --cluster "$CLUSTER_NAME"

echo "kind cluster '$CLUSTER_NAME' is ready"

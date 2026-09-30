#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/enable_ssh.sh
# Optional:      ./kubernetes/kind/enable_ssh.sh --cluster NAME
# Install sshd on each kind node. Login: root / Password1
set -euo pipefail

CLUSTER_NAME="kind"
SSH_USER="root"
SSH_PASSWORD="Password1"

usage() {
    echo "usage: $0 [--cluster NAME]" >&2
    echo "  install and start sshd on kind nodes (root / Password1)" >&2
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
need_cmd ssh

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "error: kind cluster '$CLUSTER_NAME' does not exist" >&2
    exit 1
fi

enable_ssh_on_node() {
    local node="$1"
    echo "Enabling SSH on $node"
    docker exec -i "$node" bash -s <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v sshd >/dev/null 2>&1; then
    apt-get update
    apt-get install -y --no-install-recommends openssh-server
fi
install -d -m 755 /var/run/sshd
cat >/etc/ssh/sshd_config.d/99-owlsm-test.conf <<'SSHD'
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
SSHD
echo "root:Password1" | chpasswd
ssh-keygen -A
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable ssh
    systemctl start ssh
else
    mkdir -p /var/run/sshd
    /usr/sbin/sshd
fi
EOF
}

node_ip() {
    local node="$1"
    docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$node"
}

while IFS= read -r node; do
    enable_ssh_on_node "$node"
done < <(kind get nodes --name "$CLUSTER_NAME")

if ! command -v sshpass >/dev/null 2>&1; then
    echo "Installing sshpass on the host (needed to test password SSH)"
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sshpass
fi

echo "Testing SSH on each node"
while IFS= read -r node; do
    ip="$(node_ip "$node")"
    if [[ -z "$ip" ]]; then
        echo "error: no kind-network IP for $node" >&2
        exit 1
    fi
    hostname="$(sshpass -p "$SSH_PASSWORD" ssh -n \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=10 \
        "${SSH_USER}@${ip}" hostname)"
    echo "  $node ($ip) hostname=$hostname"
done < <(kind get nodes --name "$CLUSTER_NAME")

echo "SSH login: ${SSH_USER} / ${SSH_PASSWORD}  (kind-network IP, port 22)"

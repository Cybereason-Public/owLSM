#!/bin/bash

# Debian 13.1 (Trixie) Complete Setup Script
# Run as root

set -e  # Exit on error

echo "=========================================="
echo "Starting Debian 13.1 (Trixie) System Setup"
echo "=========================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (uid 0)."
    exit 1
fi

# Update system
echo "[1/8] Updating system packages..."
apt-get update
apt-get upgrade -y

# Disable needrestart and unattended-upgrades to prevent them from
# killing CI runner processes during ephemeral job execution
apt-get remove -y needrestart unattended-upgrades 2>/dev/null || true
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# Install base utilities
echo "[2/8] Installing sudo and base utilities..."
apt-get install -y sudo iptables grep

# Configure users
echo "[3/8] Configuring users..."
# Set root password
echo "root:Password1" | chpasswd

# Create admin user if doesn't exist
if ! id -u admin >/dev/null 2>&1; then
    # Check if group 'admin' already exists
    if getent group admin >/dev/null 2>&1; then
        echo "Group 'admin' exists. Creating user 'admin' assigned to existing group."
        useradd -m -s /bin/bash -g admin admin
    else
        echo "Creating user 'admin' and group 'admin'."
        useradd -m -s /bin/bash admin
    fi
else
    echo "User 'admin' already exists."
fi

# Set admin password
echo "admin:Password1" | chpasswd

# Add admin to sudo group
usermod -aG sudo admin

# Make sure sudo group line exists in sudoers
if ! grep -q "^%sudo" /etc/sudoers 2>/dev/null; then
    echo "%sudo   ALL=(ALL:ALL) ALL" >> /etc/sudoers
fi

# Configure SSH
echo "[4/8] Configuring SSH..."
# Install openssh-server if not present
if ! command -v sshd >/dev/null 2>&1; then
    apt-get install -y openssh-server
fi

# Backup original sshd_config
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true
fi

# Enable root login with password
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

rm -fRd /etc/ssh/sshd_config.d/*

# Restart SSH service
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

# Configure firewall
echo "[5/8] Configuring firewall services..."
# Disable firewalld if installed
if systemctl list-unit-files 2>/dev/null | grep -q firewalld; then
    systemctl stop firewalld 2>/dev/null || true
    systemctl disable firewalld 2>/dev/null || true
fi

# Flush all iptables rules (handles cloud provider pre-configured rules)
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Set default policies to ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Flush ip6tables as well
ip6tables -F
ip6tables -X
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT

# Save rules (optional - makes it persistent across reboots on some systems)
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

# Install required packages
echo "[6/8] Installing required packages..."
apt-get install -y \
    ncdu \
    netcat-openbsd \
    git \
    wget \
    jq \
    bind9-dnsutils \
    htop \
    tcpdump \
    tree \
    zip \
    strace \
    nmap \
    lsof \
    curl \
    gnupg \
    ca-certificates \
    apt-transport-https \
    bash \
    zsh \
    fish \
    dash

curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Python
echo "[7/8] Installing Python (system default: 3.13)..."
# Debian 13 (Trixie) ships Python 3.13 as the system Python.
apt-get install -y python3 python3-venv python3-dev python3-pip

# Set python to point to python3
update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# Install Docker
echo "[8/8] Installing Docker..."
# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker packages
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Add admin user to docker group
usermod -aG docker admin

# Test Docker
echo "Testing Docker installation..."
if docker run hello-world; then
    echo "Docker test successful"
else
    echo "Docker test failed"
fi

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="

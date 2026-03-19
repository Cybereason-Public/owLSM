#!/bin/bash

# Ubuntu 24.04 LTS Complete Setup Script
# Run as root

set -e  # Exit on error

echo "=========================================="
echo "Starting Ubuntu 24.04 LTS System Setup"
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
apt-get remove -y needrestart unattended-upgrades
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# Install sudo first if not present
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
# Disable UFW (Ubuntu's firewall)
ufw disable 2>/dev/null || true

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

# Install Python 3.12
echo "Installing Python 3.12..."
apt-get install -y python3.12 python3.12-venv python3.12-dev python3-pip

# Set Python 3.12 as default
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
update-alternatives --set python3 /usr/bin/python3.12
update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1

# Install pip 24.0
echo "Installing pip 24.0..."
python3 -m pip install --upgrade pip==24.0 --break-system-packages

# Install Docker
echo "[7/8] Installing Docker..."
# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
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
    echo "✓ Docker test successful"
else
    echo "✗ Docker test failed"
fi

# Configure BPF LSM support
echo "[8/8] Configuring BPF LSM support..."

# 1) Check if BPF LSM is already enabled at runtime
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM already enabled."
else
    # 2) Check if config file already exists
    if [ -f /etc/default/grub.d/99-enable-bpf.cfg ]; then
        echo "Error: /etc/default/grub.d/99-enable-bpf.cfg already exists but BPF LSM is not enabled."
        echo "Please reboot or investigate the issue."
        exit 1
    fi
    
    # 3) Create the drop-in config
    echo 'GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} lsm=lockdown,yama,integrity,apparmor,bpf"' > /etc/default/grub.d/99-enable-bpf.cfg
    
    # Update grub
    update-grub
    
    # 4) Inform user
    echo "BPF LSM configured. A reboot is required for changes to take effect."
fi


echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
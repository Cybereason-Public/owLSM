#!/bin/bash


set -e  # Exit on error

echo "=========================================="
echo "Starting Fedora 35 (Cloud Edition) Setup"
echo "=========================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (uid 0)."
    exit 1
fi

# Python version installed via uv as a prebuilt build (F35 repo only has an alpha).
PYTHON_VERSION="3.12"

# Update system
echo "[1/8] Updating system packages (kernel pinned)..."
# Pin the kernel permanently so neither this upgrade nor any future manual
# `dnf upgrade` ever replaces the running 5.14 kernel.
if ! grep -q '^exclude=' /etc/dnf/dnf.conf; then
    echo 'exclude=kernel kernel-core kernel-modules kernel-modules-extra' >> /etc/dnf/dnf.conf
fi
dnf upgrade -y --exclude=kernel*

# Disable auto updates / upgrades. F35 Cloud has no dnf-automatic installed;
# dnf-makecache.timer only refreshes metadata but we disable it too. These
# timers, if present, would refresh/stage updates during ephemeral CI jobs.
echo "Disabling automatic updates..."
systemctl disable --now dnf-makecache.timer 2>/dev/null || true
for t in dnf-automatic.timer dnf-automatic-install.timer \
         dnf-automatic-notifyonly.timer dnf-automatic-download.timer packagekit; do
    systemctl disable --now "$t" 2>/dev/null || true
done

# Install base utilities
echo "[2/8] Installing base utilities..."
# dnf-plugins-core provides `dnf config-manager` (needed for the Docker repo).
# iptables-services + iptables-legacy give us the classic `iptables` tooling
# (F35 defaults to nftables).
dnf install -y dnf-plugins-core sudo iptables-services iptables-legacy grep

# Configure users
echo "[3/8] Configuring users..."
# Set root password
echo "root:Password1" | chpasswd

# Create admin user if doesn't exist
if ! id -u admin >/dev/null 2>&1; then
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

# Add admin to wheel group (sudo equivalent in Fedora/RHEL family)
usermod -aG wheel admin

# Ensure wheel group has sudo access
if ! grep -q "^%wheel" /etc/sudoers 2>/dev/null; then
    echo "%wheel  ALL=(ALL)       ALL" >> /etc/sudoers
fi

# Configure SSH
echo "[4/8] Configuring SSH..."
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true
fi

# Enable root login with password
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Install our drop-in. sshd reads /etc/ssh/sshd_config.d/*.conf in lexical order
# with "first value wins", and the Include sits at the TOP of sshd_config, so
# 00- wins over the vendor 50-redhat.conf AND over any 50-cloud-init.conf the
# image regenerates on first boot. We deliberately KEEP 50-redhat.conf (it does
# not set PermitRootLogin/PasswordAuthentication anyway) so that UsePAM yes, the
# crypto-policy include, GSSAPI and locale AcceptEnv stay in effect.
cat > /etc/ssh/sshd_config.d/00-owlsm-ssh.conf << 'EOF'
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
EOF

systemctl restart sshd 2>/dev/null || true

# Configure firewall (disable firewalld, clear iptables) and SELinux
echo "[5/8] Configuring firewall services..."
# firewalld is not installed on F35 Cloud, but guard anyway.
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true

# Flush all iptables rules (handles any cloud provider pre-configured rules)
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

# Save the clean rules and make sure nftables/iptables services won't reload
# blocking rules on boot. (Docker later re-adds its own container-networking
# chains; those do not block host ingress/egress.)
iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
systemctl disable --now nftables 2>/dev/null || true
systemctl disable --now iptables 2>/dev/null || true

# Set SELinux to permissive (matches the rest of the suite; keeps the bpf LSM
# in the active list while preventing SELinux denials for ssh/docker).
echo "Setting SELinux to permissive..."
setenforce 0 2>/dev/null || true
sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true
sed -i 's/^SELINUX=disabled/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || true

# Install required packages
echo "[6/8] Installing required packages..."
dnf install -y \
    ncdu \
    netcat \
    nmap-ncat \
    git \
    wget \
    jq \
    bind-utils \
    htop \
    tcpdump \
    tree \
    zip \
    unzip \
    strace \
    nmap \
    lsof \
    curl \
    gnupg2 \
    ca-certificates \
    bash \
    zsh \
    fish \
    dash \
    libicu \
    openssl-libs \

curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Python 3.12 (prebuilt standalone CPython via uv -- no toolchain)
echo "[7/8] Installing Python ${PYTHON_VERSION} via uv..."
# uv was installed just above to ~/.local/bin; make sure it is on PATH.
export PATH="$HOME/.local/bin:$PATH"
# Install into a shared, world-readable dir so the 'admin' user can use it too.
export UV_PYTHON_INSTALL_DIR=/opt/python
uv python install "${PYTHON_VERSION}"
PYBIN="$(uv python find "${PYTHON_VERSION}")"   # /opt/python/.../bin/python3.12
PYDIR="$(dirname "$PYBIN")"
chmod -R a+rX /opt/python

# Make 3.12 the default for shells WITHOUT touching /usr/bin/python3.
# /usr/local/bin precedes /usr/bin in PATH, so `python`/`python3` resolve to
# 3.12 for users, while dnf/yum/cloud-init keep using /usr/bin/python3 (3.10).
ln -sf "$PYBIN" /usr/local/bin/python3.12
ln -sf "$PYBIN" /usr/local/bin/python3
ln -sf "$PYBIN" /usr/local/bin/python
ln -sf "$PYDIR/pip3.12" /usr/local/bin/pip3
ln -sf "$PYDIR/pip3.12" /usr/local/bin/pip

# Install pip 24.0 (optional per requirements; best-effort). The standalone
# build is PEP-668 marked, hence --break-system-packages (same as the other
# suite scripts).
echo "Installing pip 24.0..."
"$PYBIN" -m pip install --upgrade pip==24.0 --break-system-packages || true
chmod -R a+rX /opt/python

# Install Docker
echo "[8/8] Installing Docker..."
# Remove old versions / podman if present
dnf remove -y docker docker-client docker-client-latest docker-common docker-latest \
    docker-latest-logrotate docker-logrotate docker-engine podman runc 2>/dev/null || true

# Add Docker's official Fedora repository
dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo

# Install Docker packages.
# NOTE: docker-buildx-plugin is NOT published for Fedora 35 in the docker-ce
# repo, so it is omitted (the other distros in the suite include it).
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
systemctl enable --now docker

# Add admin user to docker group
usermod -aG docker admin

# Test Docker
echo "Testing Docker installation..."
if docker run --rm hello-world; then
    echo "Docker test successful"
else
    echo "Docker test failed"
fi

# Cloud-init SSH defaults - belt-and-suspenders with the sshd drop-in above so
# instances created from this template keep root + password SSH after
# cloud-init runs on first boot. Cloud-init must stay enabled (OCI uses it).
# Ref: https://cloudinit.readthedocs.io/en/latest/reference/modules.html#mod-cc-ssh
echo "Configuring cloud-init SSH defaults..."
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-owlsm-ssh.cfg << 'EOF'
ssh_pwauth: true
disable_root: false
EOF

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="

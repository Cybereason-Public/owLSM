#!/bin/bash
set -e

# =============================================================================
# GitHub Actions Runner Setup Script
# Bootstraps an OCI instance as a self-hosted GitHub Actions runner.
# Runs via cloud-init on first boot.
# =============================================================================

# === CONFIGURATION (injected by Terraform templatefile) ===
RUNNER_USER="${runner_user}"
RUNNER_VERSION="${runner_version}"
RUNNER_URL="${github_repo_url}"

# GitHub PAT with 'repo' scope for repository runners
# Can be set via environment variable or hardcoded here
GITHUB_PAT="${github_pat}"

RUNNER_NAME="${runner_name}"
RUNNER_LABELS="${runner_labels}"
RUNNER_GROUP="${runner_group}"
RUNNER_WORK_DIR="_work"
EPHEMERAL_RUNNER="${ephemeral_runner}"

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "$${GREEN}[INFO]$${NC} $1" >&2; }
log_warn()  { echo -e "$${YELLOW}[WARN]$${NC} $1" >&2; }
log_error() { echo -e "$${RED}[ERROR]$${NC} $1" >&2; }

# === VALIDATE ===
if [ -z "$RUNNER_URL" ]; then
    log_error "Please set RUNNER_URL to your GitHub repository URL (e.g., https://github.com/owner/repo)"
    exit 1
fi

if [ -z "$GITHUB_PAT" ]; then
    log_error "Please set GITHUB_PAT environment variable or configure it in the script"
    log_error "PAT needs 'repo' scope for repository runners"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

# =============================================================================
# FUNCTION: Get Runner Registration Token (Repository only)
# =============================================================================
get_runner_token() {
    local url="$1"
    local pat="$2"
    
    # Extract owner/repo from URL (e.g., https://github.com/owner/repo)
    local repo_path="$${url#https://github.com/}"
    repo_path="$${repo_path%/}"  # Remove trailing slash if present
    
    # Validate repo URL format
    if [[ ! "$repo_path" == *"/"* ]]; then
        log_error "Invalid repository URL. Expected format: https://github.com/owner/repo"
        exit 1
    fi
    
    local api_url="https://api.github.com/repos/$${repo_path}/actions/runners/registration-token"
    log_info "Requesting runner token for repository: $repo_path"
    log_info "API URL: $api_url"
    
    local response
    local curl_exit_code
    
    # Make API request (-s for silent, --connect-timeout and --max-time for timeouts)
    # Use || true to prevent set -e from exiting on curl failure
    log_info "Making API request..."
    response=$(curl -s --connect-timeout 10 --max-time 30 -X POST \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $${pat}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$api_url" 2>&1) || curl_exit_code=$?
    
    # Check if curl failed
    if [ -n "$curl_exit_code" ] && [ "$curl_exit_code" -ne 0 ]; then
        log_error "curl failed with exit code: $curl_exit_code"
        log_error "Response/Error: $response"
        return 1
    fi
    
    # Debug: print response to stderr so it's visible
    log_info "API Response: $response"
    
    # Extract token
    local token
    token=$(echo "$response" | jq -r '.token' 2>/dev/null)
    
    if [ -z "$token" ] || [ "$token" == "null" ]; then
        log_error "Failed to extract runner token from response"
        return 1
    fi
    
    # Return only the token to stdout
    echo "$token"
}

# Get runner registration token dynamically
log_info "Retrieving runner registration token from GitHub API..."
RUNNER_TOKEN=$(get_runner_token "$RUNNER_URL" "$GITHUB_PAT") || {
    log_error "Failed to get runner token. Exiting."
    exit 1
}
log_info "Runner token retrieved successfully (expires in 1 hour)"

# Release apt locks before installing packages (cloud-init may race with unattended-upgrades)
release_apt_locks() {
    if command -v apt-get &> /dev/null; then
        log_info "Releasing apt locks if held..."
        for proc in apt-get apt dpkg unattended-upgrade; do
            pkill -9 "$proc" 2>/dev/null || true
        done
        sleep 2
        rm -f /var/lib/apt/lists/lock \
              /var/lib/dpkg/lock \
              /var/lib/dpkg/lock-frontend \
              /var/cache/apt/archives/lock
        dpkg --configure -a 2>/dev/null || true
        log_info "apt locks released."
    fi
}

# Optional: Docker
if ! command -v docker &> /dev/null; then
    release_apt_locks
    log_info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
fi

# =============================================================================
# STEP 2: Create Runner User
# =============================================================================
log_info "Creating user: $RUNNER_USER"

if id "$RUNNER_USER" &>/dev/null; then
    log_warn "User $RUNNER_USER already exists"
else
    useradd -m -s /bin/bash "$RUNNER_USER"
    log_info "User $RUNNER_USER created"
fi

if getent group docker &>/dev/null; then
    usermod -aG docker "$RUNNER_USER"
    log_info "Added $RUNNER_USER to docker group"
fi

# Configure passwordless sudo
log_info "Configuring passwordless sudo for $RUNNER_USER"
echo "$RUNNER_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$RUNNER_USER
chmod 440 /etc/sudoers.d/$RUNNER_USER
log_info "Passwordless sudo configured"

# =============================================================================
# STEP 3: Setup Runner Directory
# =============================================================================
RUNNER_HOME="/home/$RUNNER_USER"
RUNNER_DIR="$RUNNER_HOME/actions-runner"

log_info "Setting up runner directory: $RUNNER_DIR"

mkdir -p "$RUNNER_DIR"
chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"

# =============================================================================
# STEP 4: Download and Extract Runner
# =============================================================================
log_info "Downloading GitHub Actions Runner v$RUNNER_VERSION..."

cd "$RUNNER_DIR"
RUNNER_TAR="actions-runner-linux-x64-$${RUNNER_VERSION}.tar.gz"

if [ ! -f "$RUNNER_TAR" ]; then
    sudo -u "$RUNNER_USER" curl -sL -o "$RUNNER_TAR" \
        "https://github.com/actions/runner/releases/download/v$${RUNNER_VERSION}/$${RUNNER_TAR}"
fi

log_info "Extracting runner..."
sudo -u "$RUNNER_USER" tar xzf "$RUNNER_TAR"

# =============================================================================
# STEP 5: Install Runner Dependencies
# =============================================================================
release_apt_locks

# installdependencies.sh doesn't know about newer distros (e.g. Debian 13 ships
# libicu76 and libssl3, but the script only tries libicu52-72 and libssl1.x).
# Pre-install the correct packages so config.sh finds a working .NET runtime.
if command -v apt-get &> /dev/null; then
    log_info "Pre-installing libicu and libssl for .NET runtime..."
    apt-get update
    apt-get install -y libicu-dev libssl-dev
fi

log_info "Installing runner dependencies..."
"$RUNNER_DIR/bin/installdependencies.sh" || log_warn "installdependencies.sh exited with errors (non-fatal, continuing)"

# =============================================================================
# STEP 6: Configure Runner
# =============================================================================
log_info "Configuring runner..."

EPHEMERAL_FLAG=""
if [ "$EPHEMERAL_RUNNER" = "true" ]; then
    EPHEMERAL_FLAG="--ephemeral"
    log_info "Runner will be ephemeral (single job)"
else
    log_info "Runner will be persistent (multi job)"
fi

sudo -u "$RUNNER_USER" bash -c "
    cd '$RUNNER_DIR'
    ./config.sh \
        --url '$RUNNER_URL' \
        --token '$RUNNER_TOKEN' \
        --name '$RUNNER_NAME' \
        --labels '$RUNNER_LABELS' \
        --work '$RUNNER_WORK_DIR' \
        --unattended \
        --replace \
        --disableupdate \
        $EPHEMERAL_FLAG
"

# =============================================================================
# STEP 6b: Prevent needrestart from killing runner mid-job
# =============================================================================
# unattended-upgrades + needrestart can restart services (including the runner)
# after library updates. Configure needrestart to only LIST services needing
# restart, not auto-restart them. Prevents runner disconnect during tests.
if [ -d /etc/needrestart/conf.d ]; then
    log_info "Configuring needrestart to avoid auto-restarting runner service..."
    cat > /etc/needrestart/conf.d/disable-auto-restart.conf << 'NEEDRESTART_EOF'
$$nrconf{restart} = 'l';
NEEDRESTART_EOF
fi

# =============================================================================
# STEP 7: Install and Start Service
# =============================================================================
log_info "Installing runner service..."
cd "$RUNNER_DIR"
./svc.sh install "$RUNNER_USER"

log_info "Starting runner service..."
./svc.sh start

# =============================================================================
# STEP 8: Verify
# =============================================================================
log_info "Verifying installation..."
sleep 3
./svc.sh status

# =============================================================================
# DONE
# =============================================================================
echo ""
log_info "Setup complete!"
echo ""
echo "Runner: $RUNNER_NAME"
echo "User:   $RUNNER_USER"
echo "Labels: $RUNNER_LABELS"
echo ""
echo "Commands:"
echo "  Status: sudo $RUNNER_DIR/svc.sh status"
echo "  Logs:   journalctl -u actions.runner.* -f"

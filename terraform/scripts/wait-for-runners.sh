#!/bin/bash
set -euo pipefail

# =============================================================================
# Wait for GitHub Actions self-hosted runners to come online.
#
# Usage:
#   ./wait-for-runners.sh <repo> <run_label> <expected_count> <tfvars_path> [max_wait] [poll_interval]
#
# Arguments:
#   repo             - GitHub repository (owner/repo)
#   run_label        - Runner label to filter by (e.g., run-12345678)
#   expected_count   - Number of runners expected to come online
#   tfvars_path      - Path to runners.auto.tfvars.json (maps display names to TF keys)
#   max_wait         - Max wait time in seconds (default: 300)
#   poll_interval    - Polling interval in seconds (default: 30)
#
# Exit codes:
#   0 - All runners online
#   1 - Total failure (no runners came online, or missing arguments)
#   2 - Partial failure (some runners online, some failed)
#       Writes failed_runners (JSON array of TF keys) to $GITHUB_OUTPUT if set
#
# Environment:
#   GH_TOKEN         - GitHub PAT with repo admin / self-hosted runners read access
#   GITHUB_OUTPUT    - (optional) GitHub Actions output file for failed_runners
# =============================================================================

REPO="${1:?Usage: $0 <repo> <run_label> <expected_count> <tfvars_path> [max_wait] [poll_interval]}"
RUN_LABEL="${2:?Usage: $0 <repo> <run_label> <expected_count> <tfvars_path> [max_wait] [poll_interval]}"
EXPECTED_RUNNERS="${3:?Usage: $0 <repo> <run_label> <expected_count> <tfvars_path> [max_wait] [poll_interval]}"
TFVARS_PATH="${4:?Usage: $0 <repo> <run_label> <expected_count> <tfvars_path> [max_wait] [poll_interval]}"
MAX_WAIT="${5:-300}"
POLL_INTERVAL="${6:-30}"

if [ -z "${GH_TOKEN:-}" ]; then
    echo "::error::GH_TOKEN environment variable is not set"
    exit 1
fi

if [ ! -f "$TFVARS_PATH" ]; then
    echo "::error::tfvars file not found: $TFVARS_PATH"
    exit 1
fi

echo "Waiting for runners to register with GitHub..."
echo "  Repository:       $REPO"
echo "  Run label:        $RUN_LABEL"
echo "  Expected runners: $EXPECTED_RUNNERS"
echo "  Max wait:         ${MAX_WAIT}s"
echo "  Poll interval:    ${POLL_INTERVAL}s"
echo "  TFVars:           $TFVARS_PATH"

ELAPSED=0
ONLINE_COUNT=0
SEEN_ONLINE=""

while [ $ELAPSED -lt $MAX_WAIT ]; do
    RUNNERS_JSON=$(gh api "repos/${REPO}/actions/runners" --paginate --jq '.runners' 2>&1) || true
    MERGED=$(echo "$RUNNERS_JSON" | jq -s 'add // []' 2>/dev/null) || MERGED="[]"

    if [ $ELAPSED -eq 0 ]; then
        echo "  Debug: All runners:"
        echo "$MERGED" | jq -r '.[] | "    \(.name) | status=\(.status) | labels=\([.labels[].name] | join(","))"'
    fi

    ONLINE_NAMES=$(echo "$MERGED" | jq -r \
        "[.[] | select(.status == \"online\") | select(any(.labels[]; .name == \"$RUN_LABEL\"))] | .[].name" \
        2>/dev/null) || ONLINE_NAMES=""

    if [ -z "$ONLINE_NAMES" ]; then
        ONLINE_COUNT=0
    else
        ONLINE_COUNT=$(echo "$ONLINE_NAMES" | wc -l | tr -d ' ')
    fi

    if [ -n "$ONLINE_NAMES" ]; then
        while IFS= read -r runner_name; do
            if ! echo "$SEEN_ONLINE" | grep -qF "$runner_name"; then
                echo "  ✓ Runner online: $runner_name (at ${ELAPSED}s)"
                SEEN_ONLINE="${SEEN_ONLINE}${runner_name}"$'\n'
            fi
        done <<< "$ONLINE_NAMES"
    fi

    echo "  Online runners with label '$RUN_LABEL': $ONLINE_COUNT / $EXPECTED_RUNNERS (elapsed: ${ELAPSED}s)"

    if [ "$ONLINE_COUNT" -ge "$EXPECTED_RUNNERS" ]; then
        echo "All expected runners are online!"
        exit 0
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

# ---- Timeout: identify which runners failed ----
echo "::error::Timed out waiting for runners. Only $ONLINE_COUNT / $EXPECTED_RUNNERS are online after ${MAX_WAIT}s."
echo "  Final runner state:"
echo "$MERGED" | jq -r '.[] | "    \(.name) | status=\(.status) | labels=\([.labels[].name] | join(","))"' 2>/dev/null || true

# Build the list of expected runner display names from tfvars
# TF keys match display_name, so: automation-owlsm-<key>-<run_id>
RUN_ID="${RUN_LABEL#run-}"
EXPECTED_NAMES=$(jq -r --arg rid "$RUN_ID" \
    '.runners | keys[] | "automation-owlsm-\(.)-\($rid)"' \
    "$TFVARS_PATH")

# Find which expected runners are NOT in the online list
FAILED_KEYS="[]"
while IFS= read -r expected_name; do
    if [ -z "$expected_name" ]; then continue; fi
    if ! echo "$ONLINE_NAMES" | grep -qF "$expected_name"; then
        TF_KEY=$(echo "$expected_name" | sed "s/^automation-owlsm-//;s/-${RUN_ID}$//")
        FAILED_KEYS=$(echo "$FAILED_KEYS" | jq --arg k "$TF_KEY" '. + [$k]')
    fi
done <<< "$EXPECTED_NAMES"

FAILED_KEYS_COMPACT=$(echo "$FAILED_KEYS" | jq -c '.')
echo "  Failed runner TF keys: $FAILED_KEYS_COMPACT"

# Write to GITHUB_OUTPUT if available (must be single-line JSON)
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "failed_runners=$FAILED_KEYS_COMPACT" >> "$GITHUB_OUTPUT"
fi

if [ "$ONLINE_COUNT" -gt 0 ]; then
    exit 2
else
    exit 1
fi

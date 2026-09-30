#!/usr/bin/env bash
# From repo root: ./kubernetes/oke/write_oke_ssh_key.sh
# Print a private-key path for OWLSM_OKE_SSH_KEY.
# Prefer an existing OWLSM_OKE_SSH_KEY file. Otherwise write OKE_SSH_PRIVATE_KEY
# (PEM contents, as in the GitHub secret) to a file. stdout is the path only.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

usage() {
    echo "usage: $0" >&2
    echo "  print a readable private-key path for OWLSM_OKE_SSH_KEY" >&2
    echo "  env: OWLSM_OKE_SSH_KEY (existing file) or OKE_SSH_PRIVATE_KEY (PEM)" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

KEY_PATH="${OWLSM_OKE_SSH_KEY:-${TMPDIR:-/tmp}/owlsm-oke-ssh-key}"

if [[ -n "${OWLSM_OKE_SSH_KEY:-}" && -f "${OWLSM_OKE_SSH_KEY}" ]]; then
    chmod 600 "${OWLSM_OKE_SSH_KEY}"
    echo "Using existing SSH key ${OWLSM_OKE_SSH_KEY}" >&2
    printf '%s\n' "${OWLSM_OKE_SSH_KEY}"
    exit 0
fi

if [[ -z "${OKE_SSH_PRIVATE_KEY:-}" ]]; then
    echo "error: set OWLSM_OKE_SSH_KEY to a key file, or OKE_SSH_PRIVATE_KEY to PEM contents" >&2
    exit 1
fi

umask 077
mkdir -p "$(dirname -- "${KEY_PATH}")"
printf '%s\n' "${OKE_SSH_PRIVATE_KEY}" | tr -d '\r' > "${KEY_PATH}"
chmod 600 "${KEY_PATH}"
echo "Wrote SSH key to ${KEY_PATH}" >&2
printf '%s\n' "${KEY_PATH}"

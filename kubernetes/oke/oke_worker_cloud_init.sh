#!/usr/bin/env bash
# Emit an OKE worker cloud-init script on stdout.
# Requires OKE_SSH_PUBLIC_KEY (OpenSSH public key, same key used for opc).
#
# The generated script keeps the OKE bootstrap (do not edit those two lines)
# and then allows root SSH with that key only.
# See: https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengusingcustomcloudinitscripts.htm
set -euo pipefail

if [[ -z "${OKE_SSH_PUBLIC_KEY:-}" ]]; then
    echo "error: OKE_SSH_PUBLIC_KEY is unset" >&2
    exit 1
fi

pubkey="$(printf '%s\n' "${OKE_SSH_PUBLIC_KEY}" | tr -d '\r' | sed '/^$/d' | head -n1)"
if [[ ! "${pubkey}" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)[[:space:]] ]]; then
    echo "error: OKE_SSH_PUBLIC_KEY does not look like an OpenSSH public key" >&2
    exit 1
fi

cat <<EOF
#!/bin/bash
set -euo pipefail

curl --fail -H "Authorization: Bearer Oracle" -L0 http://169.254.169.254/opc/v2/instance/metadata/oke_init_script | base64 --decode >/var/run/oke-init.sh
bash /var/run/oke-init.sh

# Oracle Linux writes the metadata SSH key to root with a command=
# wrapper that prints "Please login as the user opc" and exits.
# SSH matches the first copy of a key, so overwrite that file with
# the raw key. opc still gets the same key via --ssh-public-key.
install -d -m 700 /root/.ssh
printf '%s\\n' '${pubkey}' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chown root:root /root/.ssh /root/.ssh/authorized_keys

cat > /etc/ssh/sshd_config.d/99-owlsm-root-key.conf <<'SSHD'
PermitRootLogin prohibit-password
PubkeyAuthentication yes
SSHD

systemctl reload sshd || systemctl restart sshd
EOF

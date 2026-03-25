#!/bin/bash
#
# Checks if this machine meets the requirements to run owLSM.

REQUIRED_KERNEL_MAJOR=5
REQUIRED_KERNEL_MINOR=14
REQUIRED_GLIBC_MAJOR=2
REQUIRED_GLIBC_MINOR=31

PASS=0
FAIL=0

pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

echo "=== owLSM Compatibility Check ==="
echo ""

# --- Kernel version ---
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt "$REQUIRED_KERNEL_MAJOR" ] 2>/dev/null || \
   { [ "$KERNEL_MAJOR" -eq "$REQUIRED_KERNEL_MAJOR" ] && [ "$KERNEL_MINOR" -ge "$REQUIRED_KERNEL_MINOR" ]; }; then
    pass "Kernel version: $KERNEL_VERSION (>= ${REQUIRED_KERNEL_MAJOR}.${REQUIRED_KERNEL_MINOR})"
else
    fail "Kernel version: $KERNEL_VERSION (requires >= ${REQUIRED_KERNEL_MAJOR}.${REQUIRED_KERNEL_MINOR})"
fi

# --- glibc version ---
GLIBC_VERSION=$(ldd --version 2>&1 | head -n1 | grep -oP '[0-9]+\.[0-9]+$')
if [ -n "$GLIBC_VERSION" ]; then
    GLIBC_MAJOR=$(echo "$GLIBC_VERSION" | cut -d. -f1)
    GLIBC_MINOR=$(echo "$GLIBC_VERSION" | cut -d. -f2)
    if [ "$GLIBC_MAJOR" -gt "$REQUIRED_GLIBC_MAJOR" ] 2>/dev/null || \
       { [ "$GLIBC_MAJOR" -eq "$REQUIRED_GLIBC_MAJOR" ] && [ "$GLIBC_MINOR" -ge "$REQUIRED_GLIBC_MINOR" ]; }; then
        pass "glibc version: $GLIBC_VERSION (>= ${REQUIRED_GLIBC_MAJOR}.${REQUIRED_GLIBC_MINOR})"
    else
        fail "glibc version: $GLIBC_VERSION (requires >= ${REQUIRED_GLIBC_MAJOR}.${REQUIRED_GLIBC_MINOR})"
    fi
else
    fail "glibc version: could not detect"
fi

# --- BTF support ---
if [ -f /sys/kernel/btf/vmlinux ]; then
    pass "BTF support: /sys/kernel/btf/vmlinux exists"
else
    fail "BTF support: /sys/kernel/btf/vmlinux not found"
fi

# --- eBPF LSM support ---
LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null)
if echo "$LSM_LIST" | grep -q "bpf"; then
    pass "eBPF LSM: enabled (lsm list: $LSM_LIST)"
else
    fail "eBPF LSM: not enabled (lsm list: ${LSM_LIST:-not readable}). Add 'bpf' to your kernel boot parameter lsm="
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    echo "owLSM may not work correctly on this system."
    exit 1
else
    echo "This system meets all owLSM requirements."
    exit 0
fi

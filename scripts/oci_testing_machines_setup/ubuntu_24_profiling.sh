#!/bin/bash

# Ubuntu 24.04 profiling-machine setup.
# Runs the base owLSM image setup, then installs the userspace profiling tools.
# Run as root. Reboot after it finishes.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/ubuntu_24.sh"

echo "=========================================="
echo "Installing profiling tools"
echo "=========================================="

# perf: flame graphs and lock samples. heaptrack: heap snapshots.
# python3-plotly: resources graph HTML. perl: FlameGraph scripts. binutils: addr2line for perf stacks.
apt-get install -y \
    linux-tools-common \
    linux-tools-generic \
    heaptrack \
    python3-plotly \
    binutils \
    perl

kernel_release="$(uname -r)"
kernel_tools="linux-tools-${kernel_release}"
if apt-cache show "${kernel_tools}" >/dev/null 2>&1; then
    apt-get install -y "${kernel_tools}"
else
    echo "No ${kernel_tools} package for this kernel. Using linux-tools-generic."
fi

# Ubuntu's linux-oracle-*-tools packages do not ship the perf binary.
# Install the generic tools for the same kernel series and point the perf
# wrapper at that binary. cpu-clock sampling works with it on the Oracle kernel.
if ! perf --version >/dev/null 2>&1; then
    kernel_base="${kernel_release%%-*}"
    kernel_series="${kernel_base%.*}"
    generic_tools="linux-tools-generic-${kernel_series}"
    if ! apt-cache show "${generic_tools}" >/dev/null 2>&1; then
        echo "perf is missing and ${generic_tools} is not available."
        exit 1
    fi
    apt-get install -y "${generic_tools}"
    generic_perf="$(find /usr/lib -type f -name perf -path "*${kernel_series}*" | sort | tail -n 1)"
    if [ -z "${generic_perf}" ]; then
        echo "Installed ${generic_tools} but found no perf binary."
        exit 1
    fi
    tools_dir="/usr/lib/linux-tools/${kernel_release}"
    if [ ! -d "${tools_dir}" ]; then
        mkdir -p "${tools_dir}"
    fi
    ln -sfn "${generic_perf}" "${tools_dir}/perf"
fi

flamegraph_dir="/opt/FlameGraph"
if [ ! -f "${flamegraph_dir}/flamegraph.pl" ]; then
    rm -rf "${flamegraph_dir}"
    git clone --depth 1 https://github.com/brendangregg/FlameGraph.git "${flamegraph_dir}"
fi

ln -sfn "${flamegraph_dir}/flamegraph.pl" /usr/local/bin/flamegraph.pl
ln -sfn "${flamegraph_dir}/stackcollapse-perf.pl" /usr/local/bin/stackcollapse-perf.pl

if ! perf --version >/dev/null 2>&1; then
    echo "perf is installed but did not run. Check that linux-tools matches $(uname -r)."
    exit 1
fi

if ! command -v heaptrack >/dev/null 2>&1; then
    echo "heaptrack was not installed."
    exit 1
fi

if ! python3 -c "import plotly" >/dev/null 2>&1; then
    echo "python3-plotly was not installed."
    exit 1
fi

echo "=========================================="
echo "Profiling setup complete. Reboot before use."
echo "=========================================="

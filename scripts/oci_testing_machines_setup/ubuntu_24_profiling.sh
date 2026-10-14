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

kernel_tools="linux-tools-$(uname -r)"
if apt-cache show "${kernel_tools}" >/dev/null 2>&1; then
    apt-get install -y "${kernel_tools}"
else
    echo "No ${kernel_tools} package for this kernel. Using linux-tools-generic."
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

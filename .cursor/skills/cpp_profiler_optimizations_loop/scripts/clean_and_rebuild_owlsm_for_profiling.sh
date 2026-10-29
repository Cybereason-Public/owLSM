#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$script_dir"
while [[ ! -f "$repo_root/Makefile" || ! -f "$repo_root/profiling/README.md" ]]; do
    repo_root="$(dirname "$repo_root")"
    if [[ "$repo_root" == "/" ]]; then
        echo "could not find the owLSM repo root" >&2
        exit 1
    fi
done

cd "$repo_root"
echo "Cleaning and rebuilding owlsm for profiling in $repo_root"

docker pull ghcr.io/cybereason-public/owlsm-ci:latest
docker run --rm \
    -v "$repo_root":/workspace \
    -w /workspace \
    ghcr.io/cybereason-public/owlsm-ci:latest \
    bash -lc 'make clean && make profiler -j$(nproc)'

rm -rf profiling/owlsm
cp -a build/owlsm profiling/owlsm

if [[ ! -x profiling/owlsm/bin/owlsm ]]; then
    echo "profiler binary was not created at profiling/owlsm/bin/owlsm" >&2
    exit 1
fi

echo "profiler binary is at profiling/owlsm/bin/owlsm"

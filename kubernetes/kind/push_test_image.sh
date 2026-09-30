#!/usr/bin/env bash
# From repo root: ./kubernetes/kind/push_test_image.sh
# Tag owlsm:local and push the throwaway GHCR test image (not owlsm-runtime).
set -euo pipefail

SRC_IMAGE="owlsm:local"
DST_IMAGE="ghcr.io/cybereason-public/test-owlsm-runtime:local"

usage() {
    echo "usage: $0 [--from IMAGE] [--to IMAGE]" >&2
    echo "  docker tag and push the test-owlsm-runtime image (not the official owlsm-runtime)" >&2
}

while [[ $# -ge 1 ]]; do
    case "$1" in
        --from)
            SRC_IMAGE="${2:?--from requires an image}"
            shift 2
            ;;
        --to)
            DST_IMAGE="${2:?--to requires an image}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: $1 is required but not in PATH" >&2
        exit 1
    fi
}

need_cmd docker

if ! docker image inspect "$SRC_IMAGE" >/dev/null 2>&1; then
    echo "error: source image '$SRC_IMAGE' not found. Run ./kubernetes/kind/setup.sh first" >&2
    exit 1
fi

echo "Tagging $SRC_IMAGE -> $DST_IMAGE"
docker tag "$SRC_IMAGE" "$DST_IMAGE"

echo "Pushing $DST_IMAGE"
docker push "$DST_IMAGE"

echo "Pushed $DST_IMAGE"

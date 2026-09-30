#!/usr/bin/env bash
# From repo root: ./kubernetes/chart/package.sh X.Y.Z
# Optional:      ./kubernetes/chart/package.sh X.Y.Z --destination DIR
# Copy the in-repo chart, stamp official version + owlsm-runtime image, lint, template, package.
# Default output: build/helm-chart/owlsm-X.Y.Z.tgz. The chart on disk stays owlsm:local.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

CHART_SRC="$SCRIPT_DIR"
IMAGE_REPOSITORY="ghcr.io/cybereason-public/owlsm-runtime"
DESTINATION="$REPO_ROOT/build/helm-chart"
VERSION=""

usage() {
    echo "usage: $0 VERSION [--destination DIR]" >&2
    echo "  copy kubernetes/chart, stamp Chart.yaml and official owlsm-runtime image, then" >&2
    echo "  helm lint, helm template, helm package" >&2
    echo "  VERSION is X.Y.Z; packaged image is ${IMAGE_REPOSITORY}:vX.Y.Z" >&2
    echo "  default destination is build/helm-chart/" >&2
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: $1 is required but not in PATH" >&2
        exit 1
    fi
}

is_xyz_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

stamp_chart() {
    local chart_dir="$1"
    local image_tag="v${VERSION}"

    sed -i -E \
        -e "s/^version:[[:space:]].*/version: ${VERSION}/" \
        -e "s/^appVersion:[[:space:]].*/appVersion: \"${VERSION}\"/" \
        "$chart_dir/Chart.yaml"

    sed -i -E \
        -e "s|^([[:space:]]+)repository:[[:space:]].*|\\1repository: ${IMAGE_REPOSITORY}|" \
        -e "s|^([[:space:]]+)tag:[[:space:]].*|\\1tag: ${image_tag}|" \
        "$chart_dir/values.yaml"

    if ! grep -qE "^version:[[:space:]]+${VERSION}$" "$chart_dir/Chart.yaml"; then
        echo "error: failed to stamp Chart.yaml version" >&2
        exit 1
    fi
    if ! grep -qE "^appVersion:[[:space:]]+\"${VERSION}\"$" "$chart_dir/Chart.yaml"; then
        echo "error: failed to stamp Chart.yaml appVersion" >&2
        exit 1
    fi
    if ! grep -qE "^[[:space:]]+repository:[[:space:]]+${IMAGE_REPOSITORY}$" "$chart_dir/values.yaml"; then
        echo "error: failed to stamp values.yaml image.repository" >&2
        exit 1
    fi
    if ! grep -qE "^[[:space:]]+tag:[[:space:]]+${image_tag}$" "$chart_dir/values.yaml"; then
        echo "error: failed to stamp values.yaml image.tag" >&2
        exit 1
    fi
}

while [[ $# -ge 1 ]]; do
    case "$1" in
        --destination)
            DESTINATION="${2:?--destination requires a directory}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            echo "error: unknown option $1" >&2
            usage
            exit 1
            ;;
        *)
            if [[ -n "$VERSION" ]]; then
                echo "error: unexpected argument $1" >&2
                usage
                exit 1
            fi
            VERSION="$1"
            shift
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "error: VERSION is required" >&2
    usage
    exit 1
fi

if ! is_xyz_version "$VERSION"; then
    echo "error: VERSION must be X.Y.Z (got '$VERSION')" >&2
    exit 1
fi

need_cmd helm

if [[ ! -f "$CHART_SRC/Chart.yaml" || ! -f "$CHART_SRC/values.yaml" ]]; then
    echo "error: chart files not found in $CHART_SRC" >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

chart_copy="$tmp_dir/owlsm"
mkdir -p "$chart_copy"
cp -a "$CHART_SRC/." "$chart_copy/"
rm -f "$chart_copy/package.sh"

stamp_chart "$chart_copy"

mkdir -p "$DESTINATION"
DESTINATION="$(cd -- "$DESTINATION" && pwd)"

echo "Linting stamped chart ${VERSION}"
helm lint "$chart_copy"

echo "Rendering stamped chart ${VERSION}"
rendered="$tmp_dir/rendered.yaml"
helm template owlsm "$chart_copy" > "$rendered"
if ! grep -q "image: \"${IMAGE_REPOSITORY}:v${VERSION}\"" "$rendered"; then
    echo "error: helm template did not render image ${IMAGE_REPOSITORY}:v${VERSION}" >&2
    exit 1
fi
echo "Rendered image ${IMAGE_REPOSITORY}:v${VERSION}"

echo "Packaging stamped chart ${VERSION} to $DESTINATION"
helm package "$chart_copy" --destination "$DESTINATION"

package_path="$DESTINATION/owlsm-${VERSION}.tgz"
if [[ ! -f "$package_path" ]]; then
    echo "error: expected package not found: $package_path" >&2
    exit 1
fi

echo "Packaged $package_path"
echo "In-repo chart left unchanged (owlsm:local)"

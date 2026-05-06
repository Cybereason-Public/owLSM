#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BUILD_TMP="${PROJECT_ROOT}/build/.rules_generator_build"
VENV_DIR="${BUILD_TMP}/.venv"
PYI_WORK_DIR="${BUILD_TMP}/.pyinstaller"

ENTRYPOINT="${SCRIPT_DIR}/create_config.py"
SCHEMA_FILE="${PROJECT_ROOT}/src/Userspace/configuration/schema.json"
CONSTANTS_FILE="${PROJECT_ROOT}/src/Shared/constants.json"
MEMORY_SCHEMA_FILE="${SCRIPT_DIR}/memory_json_schema.json"
BASE_CONFIG_FILE="${SCRIPT_DIR}/base_config.json"
BINARY_NAME="rules_generator"
BINARY_PATH="${SCRIPT_DIR}/${BINARY_NAME}"

for f in "${ENTRYPOINT}" "${SCHEMA_FILE}" "${CONSTANTS_FILE}" "${MEMORY_SCHEMA_FILE}" "${BASE_CONFIG_FILE}"; do
    if [[ ! -f "${f}" ]]; then
        echo "Required file not found: ${f}" >&2
        exit 1
    fi
done

mkdir -p "${BUILD_TMP}"

rm -rf "${VENV_DIR}"
uv venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"
uv pip install -r "${SCRIPT_DIR}/requirements.txt"

rm -rf "${PYI_WORK_DIR}"
rm -f "${BINARY_PATH}"

python -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --strip \
    --name "${BINARY_NAME}" \
    --distpath "${SCRIPT_DIR}" \
    --workpath "${PYI_WORK_DIR}/work" \
    --specpath "${PYI_WORK_DIR}/spec" \
    --add-data "${SCHEMA_FILE}:." \
    --add-data "${CONSTANTS_FILE}:." \
    --add-data "${MEMORY_SCHEMA_FILE}:." \
    --add-data "${BASE_CONFIG_FILE}:." \
    --exclude-module pytest \
    --exclude-module _pytest \
    --exclude-module pytest_bdd \
    "${ENTRYPOINT}"

patchelf --set-rpath '$ORIGIN/../lib' "${BINARY_PATH}"

rm -rf "${BUILD_TMP}"

echo "Binary: ${BINARY_PATH}"

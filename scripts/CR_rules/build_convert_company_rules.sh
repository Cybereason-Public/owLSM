#!/usr/bin/env bash
set -euo pipefail

# Builds the Cybereason-specific `convert_company_rules` tool into a standalone
# --onefile binary. Modeled on Rules/RulesGenerator/build_py_to_bin.sh, but kept
# separate so the community build script stays untouched.
#
# Usage: build_convert_company_rules.sh
# Output: scripts/CR_rules/convert_company_rules
#
# Note: convert_company_rules imports `field_mapping` at runtime, which in turn
# imports `constants`. Both live in Rules/RulesGenerator and are reached via a
# __file__-relative sys.path hack that does not exist inside a --onefile bundle,
# so we make them importable at build time (--paths) and bundle them as hidden
# imports. constants.py reads constants.json from sys._MEIPASS when frozen,
# hence --add-data for it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RULES_GENERATOR_DIR="${PROJECT_ROOT}/Rules/RulesGenerator"
CONSTANTS_FILE="${PROJECT_ROOT}/src/Shared/constants.json"

ENTRYPOINT="${SCRIPT_DIR}/convert_company_rules.py"
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"
BINARY_NAME="convert_company_rules"
BINARY_PATH="${SCRIPT_DIR}/${BINARY_NAME}"

BUILD_TMP="${PROJECT_ROOT}/build/.${BINARY_NAME}_build"
VENV_DIR="${BUILD_TMP}/.venv"
PYI_WORK_DIR="${BUILD_TMP}/.pyinstaller"

for f in \
    "${ENTRYPOINT}" \
    "${REQUIREMENTS}" \
    "${CONSTANTS_FILE}" \
    "${RULES_GENERATOR_DIR}/field_mapping.py" \
    "${RULES_GENERATOR_DIR}/constants.py"; do
    if [[ ! -f "${f}" ]]; then
        echo "Required file not found: ${f}" >&2
        exit 1
    fi
done

mkdir -p "${BUILD_TMP}"

rm -rf "${VENV_DIR}"
uv venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"
uv pip install -r "${REQUIREMENTS}"

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
    --paths "${RULES_GENERATOR_DIR}" \
    --hidden-import field_mapping \
    --hidden-import constants \
    --add-data "${CONSTANTS_FILE}:." \
    --exclude-module pytest \
    --exclude-module _pytest \
    --exclude-module pytest_bdd \
    "${ENTRYPOINT}"

patchelf --set-rpath '$ORIGIN/../lib' "${BINARY_PATH}"

rm -rf "${BUILD_TMP}"

echo "Binary: ${BINARY_PATH}"

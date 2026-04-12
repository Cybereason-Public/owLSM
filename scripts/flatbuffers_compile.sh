#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

SCHEMA_DIR="$PROJECT_ROOT/src/Userspace/events/flatbuffers/schema"
CPP_OUT_DIR="$PROJECT_ROOT/src/Userspace/events/flatbuffers/include"

SCHEMA_FILE="$SCHEMA_DIR/owlsm_events.fbs"

if ! command -v flatc &>/dev/null; then
    echo "ERROR: flatc not found in PATH. Install FlatBuffers v25.12.19." >&2
    exit 1
fi

echo "==> Compiling FlatBuffers schema: $SCHEMA_FILE"

rm -f "$CPP_OUT_DIR"/*.h
flatc --cpp \
      --scoped-enums \
      --gen-name-strings \
      --filename-suffix "_generated" \
      -o "$CPP_OUT_DIR" \
      "$SCHEMA_FILE"
echo "    C++ header generated in $CPP_OUT_DIR"

echo "==> FlatBuffers compilation complete."

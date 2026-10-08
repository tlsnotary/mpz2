#!/usr/bin/env bash
set -euo pipefail

if [ -z "${WASM_HARNESS_ENV_RAYON_NUM_THREADS:-}" ]; then
    if command -v nproc >/dev/null 2>&1; then
        cores=$(nproc)
    elif command -v sysctl >/dev/null 2>&1; then
        cores=$(sysctl -n hw.ncpu)
    else
        cores=1
    fi
    export WASM_HARNESS_ENV_RAYON_NUM_THREADS=$cores
fi

exec wasm-harness "$@"

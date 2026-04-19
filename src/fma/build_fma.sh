#!/usr/bin/env bash
# Compile fma_hook.cpp into fma_hook.so.
# Called by install.sh; requires g++ and CUDA headers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-/etc/cmppatcher/fma_hook.so}"

# Locate CUDA include directory
CUDA_INCLUDE=""
for dir in /usr/local/cuda/include /usr/local/cuda-*/include; do
    [[ -f "$dir/cuda.h" ]] && { CUDA_INCLUDE="$dir"; break; }
done
if [[ -z "$CUDA_INCLUDE" ]]; then
    # Try system cuda-dev headers (nvidia-cuda-dev package on Ubuntu)
    for dir in /usr/include/cuda /usr/include; do
        [[ -f "$dir/cuda.h" ]] && { CUDA_INCLUDE="$dir"; break; }
    done
fi
if [[ -z "$CUDA_INCLUDE" ]]; then
    echo "ERROR: cuda.h not found. Install CUDA toolkit or nvidia-cuda-dev." >&2
    exit 1
fi

echo "  Compiling fma_hook.so (CUDA include: $CUDA_INCLUDE) ..."
g++ -shared -fPIC -O2 -std=c++17 \
    -I"$SCRIPT_DIR" \
    -I"$CUDA_INCLUDE" \
    -o "$OUT" \
    "$SCRIPT_DIR/fma_hook.cpp" \
    -ldl

echo "  Written: $OUT"

#!/usr/bin/env bash
# cmppatcher — one-shot NVIDIA mining GPU driver patcher
#
# Usage: sudo bash install.sh [--dry-run] [--force] [--restore] [--status] [--uninstall]
#
# Supported hardware:
#   CMP 170HX / 90HX / 70HX / 50HX / 40HX / 30HX  (Ampere)
#   CMP variant IDs confirmed in dartraiden/NVIDIA-patcher
#   P102-100 / P104-100 / P106-100 / P106-090 / P104-101  (Pascal)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/etc/cmppatcher"
MANIFEST="$INSTALL_DIR/patch_manifest.json"
CONFIG="$INSTALL_DIR/config"
BACKUP_DIR="$INSTALL_DIR/backups"
LOG="$INSTALL_DIR/install.log"

DRY_RUN=0
FORCE=0
RESTORE=0
STATUS=0
UNINSTALL=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

for arg in "$@"; do
    case "$arg" in
        --dry-run)   DRY_RUN=1   ;;
        --force)     FORCE=1     ;;
        --restore)   RESTORE=1   ;;
        --status)    STATUS=1    ;;
        --uninstall) UNINSTALL=1 ;;
        --help|-h)
            sed -n '2,12p' "$0" | sed 's/^# //'
            exit 0
            ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: cmppatcher must be run as root (sudo bash install.sh)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
exec > >(tee -a "$LOG") 2>&1

echo ""
echo "========================================================"
echo "  cmppatcher  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================================"

# ---------------------------------------------------------------------------
# Prerequisite check / install
# ---------------------------------------------------------------------------

install_if_missing() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if ! command -v "$cmd" &>/dev/null; then
        echo "  Installing prerequisite: $pkg ..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y --no-install-recommends "$pkg" >/dev/null
        elif command -v dnf &>/dev/null; then
            dnf install -y "$pkg" >/dev/null
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm "$pkg" >/dev/null
        else
            echo "  WARNING: cannot install $pkg automatically; please install it manually." >&2
        fi
    fi
}

echo ""
echo "  Checking prerequisites ..."
install_if_missing python3
install_if_missing zstd
install_if_missing patchelf

if ! python3 -c "import struct, json, hashlib, glob" 2>/dev/null; then
    echo "ERROR: Python 3 stdlib modules not available." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# GPU and driver detection
# ---------------------------------------------------------------------------

echo ""
echo "  Detecting GPU and driver ..."
DETECTION="$(python3 "$REPO_DIR/src/detector.py")"

DRIVER_VER="$(echo "$DETECTION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['driver_version'] or '')")"
HAS_170HX="$(echo "$DETECTION"  | python3 -c "import sys,json; d=json.load(sys.stdin); print('1' if d['has_170hx'] else '0')")"
GPU_COUNT="$(echo "$DETECTION"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['gpus']))")"
GPU_NAMES="$(echo "$DETECTION"  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for g in d['gpus']:
    print(f\"    {g['name']}  ({g['device_id']})  @ {g['pci_addr']}\")
")"

echo ""
echo "  Detected driver:  ${DRIVER_VER:-UNKNOWN}"
echo "  Supported GPUs:   $GPU_COUNT"
echo "$GPU_NAMES"

if [[ "$DRIVER_VER" == "" ]]; then
    echo ""
    echo "ERROR: NVIDIA driver not detected. Install the driver first." >&2
    exit 1
fi

if [[ "$GPU_COUNT" == "0" && "$FORCE" == "0" ]]; then
    echo ""
    echo "ERROR: No supported CMP/Pascal mining GPU detected." >&2
    echo "  Use --force to patch anyway." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# --status
# ---------------------------------------------------------------------------

if [[ "$STATUS" == "1" ]]; then
    python3 "$REPO_DIR/src/patcher.py" \
        --status \
        --manifest "$MANIFEST" \
        --driver   "$DRIVER_VER"
    exit 0
fi

# ---------------------------------------------------------------------------
# --restore / --uninstall
# ---------------------------------------------------------------------------

if [[ "$RESTORE" == "1" || "$UNINSTALL" == "1" ]]; then
    echo ""
    echo "  Restoring patched files from backups ..."
    python3 "$REPO_DIR/src/patcher.py" \
        --restore \
        --manifest "$MANIFEST" \
        --driver   "$DRIVER_VER"

    if [[ "$UNINSTALL" == "1" ]]; then
        echo "  Removing /etc/cmppatcher hooks ..."
        rm -f /etc/apt/apt.conf.d/99cmppatcher
        rm -f /etc/dnf/plugins/cmppatcher.py
        rm -f /etc/pacman.d/hooks/cmppatcher.hook
        if systemctl is-enabled cmppatcher-rewriter &>/dev/null; then
            systemctl disable --now cmppatcher-rewriter 2>/dev/null || true
            rm -f /etc/systemd/system/cmppatcher-rewriter.service
            systemctl daemon-reload
        fi
        rm -rf "$INSTALL_DIR"
        echo "  cmppatcher uninstalled."
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# SecureBoot / sig_enforce check (abort if module signature enforcement is on)
# ---------------------------------------------------------------------------

SIG_ENFORCE="$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo N)"
if mokutil --sb-state 2>/dev/null | grep -q 'SecureBoot enabled'; then
    SECUREBOOT="1"
else
    SECUREBOOT="0"
fi

if [[ "$SIG_ENFORCE" == "1" || "$SIG_ENFORCE" == "Y" || "$SECUREBOOT" != "0" ]]; then
    echo ""
    echo "ERROR: Kernel module signature enforcement is active." >&2
    echo "  The nvidia.ko.zst patch will invalidate the module signature." >&2
    echo "  Disable SecureBoot in your UEFI firmware, then re-run cmppatcher." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Install files to /etc/cmppatcher/
# ---------------------------------------------------------------------------

echo ""
echo "  Installing cmppatcher files to $INSTALL_DIR ..."

mkdir -p "$INSTALL_DIR/src/fma" "$BACKUP_DIR"

cp -r "$REPO_DIR/src/"* "$INSTALL_DIR/src/"
cp "$REPO_DIR/repatch.sh" "$INSTALL_DIR/repatch.sh"
chmod +x "$INSTALL_DIR/repatch.sh"

cat > "$CONFIG" <<EOF
DRIVER_VER=$DRIVER_VER
HAS_170HX=$HAS_170HX
INSTALL_DIR=$INSTALL_DIR
REPO_DIR=$REPO_DIR
EOF

# ---------------------------------------------------------------------------
# Run the Python patcher
# ---------------------------------------------------------------------------

PATCHER_FLAGS=""
[[ "$DRY_RUN" == "1" ]] && PATCHER_FLAGS="$PATCHER_FLAGS --dry-run"
[[ "$FORCE"   == "1" ]] && PATCHER_FLAGS="$PATCHER_FLAGS --force"

echo ""
echo "  Applying patches ..."
python3 "$INSTALL_DIR/src/patcher.py" \
    --manifest  "$MANIFEST" \
    --backup-dir "$BACKUP_DIR" \
    --driver    "$DRIVER_VER" \
    $PATCHER_FLAGS

# ---------------------------------------------------------------------------
# Package manager hooks
# ---------------------------------------------------------------------------

if [[ "$DRY_RUN" == "0" ]]; then
    echo "  Installing package manager hooks ..."

    # APT (Debian / Ubuntu)
    if command -v apt-get &>/dev/null; then
        cp "$REPO_DIR/templates/apt_hook.conf" \
           /etc/apt/apt.conf.d/99cmppatcher
        echo "    APT hook → /etc/apt/apt.conf.d/99cmppatcher"
    fi

    # DNF (Fedora / RHEL)
    if command -v dnf &>/dev/null && [[ -d /etc/dnf/plugins ]]; then
        cp "$REPO_DIR/templates/dnf_plugin.py" \
           /etc/dnf/plugins/cmppatcher.py
        echo "    DNF plugin → /etc/dnf/plugins/cmppatcher.py"
    fi

    # Pacman (Arch)
    if command -v pacman &>/dev/null && [[ -d /etc/pacman.d/hooks ]]; then
        cp "$REPO_DIR/templates/pacman_hook.hook" \
           /etc/pacman.d/hooks/cmppatcher.hook
        echo "    Pacman hook → /etc/pacman.d/hooks/cmppatcher.hook"
    fi
fi

# ---------------------------------------------------------------------------
# FMA bypass — CMP 170HX only
# ---------------------------------------------------------------------------

if [[ "$HAS_170HX" == "1" && "$DRY_RUN" == "0" ]]; then
    echo ""
    echo "  CMP 170HX detected — setting up FMA bypass ..."

    # Check prerequisites
    NVDISASM=""
    for p in "$(command -v nvdisasm 2>/dev/null)" /usr/local/cuda*/bin/nvdisasm; do
        [[ -x "$p" ]] && { NVDISASM="$p"; break; }
    done

    GPP="$(command -v g++ 2>/dev/null || true)"

    if [[ -z "$NVDISASM" ]]; then
        echo "  WARNING: nvdisasm not found — FMA bypass requires the CUDA toolkit." >&2
        echo "  Install CUDA toolkit and re-run install.sh to enable FMA bypass." >&2
    elif [[ -z "$GPP" ]]; then
        echo "  WARNING: g++ not found — cannot compile fma_hook.so." >&2
        echo "  Install build-essential and re-run install.sh to enable FMA bypass." >&2
    else
        LIBCUDA="/usr/lib/x86_64-linux-gnu/libcuda.so.$DRIVER_VER"

        if [[ ! -f "$LIBCUDA" ]]; then
            echo "  WARNING: $LIBCUDA not found — skipping FMA hook injection." >&2
        else
            # Copy FMA sources
            cp "$REPO_DIR/src/fma/fma_hook.cpp"       "$INSTALL_DIR/fma_hook.cpp"
            cp "$REPO_DIR/src/fma/sha256.h"            "$INSTALL_DIR/sha256.h"
            cp "$REPO_DIR/src/fma/rewriter_daemon.py"  "$INSTALL_DIR/rewriter_daemon.py"
            cp -r "$REPO_DIR/src/fma/CuAssembler" "$INSTALL_DIR/CuAssembler"

            # Compile hook
            echo "  Compiling fma_hook.so ..."
            bash "$REPO_DIR/src/fma/build_fma.sh" "$INSTALL_DIR/fma_hook.so"

            # Remove any stale patchelf DT_NEEDED injection from previous installs
            if patchelf --print-needed "$LIBCUDA" 2>/dev/null | grep -qF "fma_hook.so"; then
                echo "  Removing old DT_NEEDED injection from $LIBCUDA ..."
                patchelf --remove-needed "$INSTALL_DIR/fma_hook.so" "$LIBCUDA" || true
            fi

            # Register via /etc/ld.so.preload so the hook wins symbol resolution
            # regardless of whether CUDA is dlopen'd or linked directly.
            echo "  Registering fma_hook.so in /etc/ld.so.preload ..."
            touch /etc/ld.so.preload
            if ! grep -qF "$INSTALL_DIR/fma_hook.so" /etc/ld.so.preload; then
                echo "$INSTALL_DIR/fma_hook.so" >> /etc/ld.so.preload
            fi

            # Update manifest with FMA state
            python3 - <<PYEOF
import json, os
manifest_path = "$MANIFEST"
try:
    m = json.load(open(manifest_path))
except Exception:
    m = {}
m['fma_enabled']      = True
m['fma_hook_path']    = "$INSTALL_DIR/fma_hook.so"
with open(manifest_path, 'w') as f:
    json.dump(m, f, indent=2)
PYEOF

            # Install and start systemd service
            sed "s|__INSTALL_DIR__|$INSTALL_DIR|g" \
                "$REPO_DIR/templates/cmppatcher-rewriter.service.tmpl" \
                > /etc/systemd/system/cmppatcher-rewriter.service

            systemctl daemon-reload
            systemctl enable --now cmppatcher-rewriter
            echo "  cmppatcher-rewriter.service enabled and started."
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "========================================================"
echo "  cmppatcher — DONE"
if [[ "$DRY_RUN" == "1" ]]; then
    echo "  (dry run — no files were modified)"
fi
echo ""
echo "  Run 'sudo bash install.sh --status' to verify."
echo "========================================================"
echo ""

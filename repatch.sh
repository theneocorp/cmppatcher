#!/usr/bin/env bash
# cmppatcher — idempotent re-patcher.
#
# Called automatically by APT/DNF/Pacman hooks after NVIDIA driver updates.
# Also installed to /etc/cmppatcher/repatch.sh.
#
# Usage: repatch.sh [--auto] [--force]
#   --auto   suppress interactive output; always exits 0 (for hook use)
#   --force  re-apply even if files appear already patched

set -euo pipefail

INSTALL_DIR="/etc/cmppatcher"
MANIFEST="$INSTALL_DIR/patch_manifest.json"
CONFIG="$INSTALL_DIR/config"

AUTO=0
FORCE_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --auto)  AUTO=1              ;;
        --force) FORCE_FLAG="--force" ;;
    esac
done

# Not installed — nothing to do
if [[ ! -f "$MANIFEST" ]]; then
    exit 0
fi

# Escalate to root if needed
if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

# Source config for DRIVER_VER
if [[ -f "$CONFIG" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG"
else
    DRIVER_VER=""
fi

# Detect driver version if not in config
if [[ -z "${DRIVER_VER:-}" ]]; then
    DRIVER_VER="$(python3 -c "
import glob
for p in sorted(glob.glob('/usr/lib/x86_64-linux-gnu/libcuda.so.*.*.*')):
    s = p.split('libcuda.so.')[-1]
    parts = s.split('.')
    if len(parts) == 3 and all(x.isdigit() for x in parts):
        print(s)
        break
" 2>/dev/null || true)"
fi

if [[ -z "${DRIVER_VER:-}" ]]; then
    [[ "$AUTO" == "1" ]] && exit 0
    echo "ERROR: could not detect NVIDIA driver version" >&2
    exit 1
fi

# Check whether any target file has changed (needs repatch)
NEEDS_REPATCH="$(python3 - <<'PYEOF'
import json, hashlib, sys, os

manifest_path = "/etc/cmppatcher/patch_manifest.json"

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1<<20), b''):
            h.update(chunk)
    return h.hexdigest()

try:
    m = json.load(open(manifest_path))
except Exception:
    print("yes")
    sys.exit(0)

for entry in m.get("patches", []):
    path = entry.get("file_path", "")
    post = entry.get("file_sha256_post", "")
    if not os.path.isfile(path):
        continue
    if sha256_file(path) != post:
        print("yes")
        sys.exit(0)

print("no")
PYEOF
)"

if [[ "$NEEDS_REPATCH" == "no" && -z "$FORCE_FLAG" ]]; then
    [[ "$AUTO" == "0" ]] && echo "cmppatcher: all patches current — nothing to do."
    exit 0
fi

[[ "$AUTO" == "0" ]] && echo "cmppatcher: repatching (driver may have been updated) ..."

python3 "$INSTALL_DIR/src/patcher.py" \
    --manifest   "$MANIFEST" \
    --backup-dir "$INSTALL_DIR/backups" \
    --driver     "$DRIVER_VER" \
    $FORCE_FLAG \
    2>&1 | (
        if [[ "$AUTO" == "1" ]]; then
            logger -t cmppatcher
        else
            cat
        fi
    )

# Restart FMA daemon if running
if systemctl is-active cmppatcher-rewriter &>/dev/null; then
    systemctl restart cmppatcher-rewriter
fi

exit 0

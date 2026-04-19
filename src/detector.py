#!/usr/bin/env python3
"""
Detect installed NVIDIA CMP/Pascal mining GPUs and the active driver version.
Reads /sys/bus/pci/devices — no lspci dependency.
Outputs a single JSON object to stdout.
"""

import glob
import json
import os
import sys

NVIDIA_VENDOR = 0x10DE

# CMP Ampere series
CMP_IDS = {
    0x1E09: "CMP 30HX",
    0x1E49: "CMP 40HX",
    0x1EBC: "CMP 50HX",
    0x1EFC: "CMP 70HX",
    0x1F0B: "CMP 90HX",
    0x2081: "CMP 170HX",
    0x2082: "CMP (0x2082)",
    0x2083: "CMP (0x2083)",
    0x2089: "CMP (0x2089)",
    0x20C2: "CMP (0x20C2)",
    0x20C3: "CMP (0x20C3)",
    0x220D: "CMP (0x220D)",
    0x224D: "CMP (0x224D)",
    0x248A: "CMP (0x248A)",
    0x248D: "CMP (0x248D)",
}

# Pascal mining series
PASCAL_IDS = {
    0x1B07: "P102-100",
    0x1B87: "P104-100",
    0x1BC7: "P106-100",
    0x1C07: "P106-090",
    0x1C09: "P104-101",
}

SUPPORTED_IDS: dict[int, str] = {**CMP_IDS, **PASCAL_IDS}

# Only 0x2081 (GA100-105F) is confirmed to have the 16:1 OTP FFMA throttle.
FMA_IDS = {0x2081}


def _read_hex(path: str) -> int | None:
    try:
        return int(open(path).read().strip(), 16)
    except Exception:
        return None


def detect_gpus() -> list[dict]:
    found = []
    pci_root = "/sys/bus/pci/devices"
    if not os.path.isdir(pci_root):
        return found

    for dev in sorted(os.listdir(pci_root)):
        vendor = _read_hex(f"{pci_root}/{dev}/vendor")
        device = _read_hex(f"{pci_root}/{dev}/device")
        if vendor != NVIDIA_VENDOR:
            continue
        if device not in SUPPORTED_IDS:
            continue
        found.append({
            "pci_addr": dev,
            "device_id": hex(device),
            "name": SUPPORTED_IDS[device],
            "is_cmp": device in CMP_IDS,
            "is_pascal": device in PASCAL_IDS,
            "has_fma_throttle": device in FMA_IDS,
        })
    return found


def detect_driver_version() -> str | None:
    """
    Parse driver version from installed libcuda.so.X.Y.Z filename.
    Falls back to /proc/driver/nvidia/version.
    """
    # Prefer libcuda.so version — most reliable
    for path in glob.glob("/usr/lib/x86_64-linux-gnu/libcuda.so.*.*.*"):
        basename = os.path.basename(path)
        suffix = basename[len("libcuda.so."):]
        parts = suffix.split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            return suffix

    # Fallback: /proc/driver/nvidia/version
    try:
        line = open("/proc/driver/nvidia/version").readline()
        # "NVRM version: NVIDIA UNIX x86_64 Kernel Module  595.58.03  ..."
        for token in line.split():
            parts = token.split(".")
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                return token
    except Exception:
        pass

    return None


def get_patch_targets(driver_ver: str) -> dict[str, list[str]]:
    """
    Return lists of file paths that exist on this system, grouped by patch type.
    Handles multiple installed kernels.
    """
    lib_dir = "/usr/lib/x86_64-linux-gnu"

    so_targets = []
    for name in [
        f"libcuda.so.{driver_ver}",
        f"libnvidia-glcore.so.{driver_ver}",
        f"libGLX_nvidia.so.{driver_ver}",
    ]:
        p = os.path.join(lib_dir, name)
        if os.path.isfile(p):
            so_targets.append(p)

    nvenc_targets = []
    for name in [f"libnvidia-encode.so.{driver_ver}"]:
        p = os.path.join(lib_dir, name)
        if os.path.isfile(p):
            nvenc_targets.append(p)

    fbc_targets = []
    for name in [f"libnvidia-fbc.so.{driver_ver}"]:
        p = os.path.join(lib_dir, name)
        if os.path.isfile(p):
            fbc_targets.append(p)

    ko_targets = sorted(glob.glob("/lib/modules/*/updates/dkms/nvidia.ko.zst"))

    return {
        "3d_unlock": so_targets,
        "nvenc": nvenc_targets,
        "fbc": fbc_targets,
        "ko_3d_unlock": ko_targets,
    }


def main():
    gpus = detect_gpus()
    driver_ver = detect_driver_version()
    has_170hx = any(g["has_fma_throttle"] for g in gpus)

    result = {
        "gpus": gpus,
        "driver_version": driver_ver,
        "has_170hx": has_170hx,
        "patch_targets": get_patch_targets(driver_ver) if driver_ver else {},
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
cmppatcher — main patch engine.

Three patch types:
  1. 3D unlock   — replace mining GPU device IDs with 0xFFFF wildcards
                   in ELF .rodata/.data sections of .so files and nvidia.ko.zst
  2. NVENC/FBC   — version-specific byte patches to libnvidia-encode.so
                   and libnvidia-fbc.so (keylase patterns)
  3. FMA bypass  — handled by install.sh (patchelf + fma_hook.so); this
                   module only records the pre/post sha256 in the manifest

CLI:
  patcher.py [--dry-run] [--force] [--restore] [--status] [--auto-repatch]
             [--manifest PATH] [--config PATH] [--driver VER]
"""

import argparse
import datetime
import json
import os
import struct
import subprocess
import sys
import tempfile

# Allow running from the repo root or from /etc/cmppatcher/src/
sys.path.insert(0, os.path.dirname(__file__))
import manifest as mf
from elf_utils import ELF64

# ---------------------------------------------------------------------------
# Device IDs
# ---------------------------------------------------------------------------

CMP_IDS = [
    0x1E09, 0x1E49, 0x1EBC, 0x1EFC, 0x1F0B,
    0x2081, 0x2082, 0x2083, 0x2089, 0x20C2, 0x20C3,
    0x220D, 0x224D, 0x248A, 0x248D,
]
PASCAL_IDS = [0x1B07, 0x1B87, 0x1BC7, 0x1C07, 0x1C09]
ALL_DEVICE_IDS = CMP_IDS + PASCAL_IDS

# ---------------------------------------------------------------------------
# NVENC / FBC version-specific patterns (from keylase/nvidia-patch)
# ---------------------------------------------------------------------------

# Each entry: (search_bytes, replace_bytes)
NVENC_PATTERNS: dict[str, tuple[bytes, bytes]] = {
    "595.58.03": (
        b"\xe8\x51\x21\xfe\xff\x41\x89\xc6\x85\xc0",
        b"\xe8\x51\x21\xfe\xff\x29\xc0\x41\x89\xc6",
    ),
}

FBC_PATTERNS: dict[str, tuple[bytes, bytes]] = {
    "595.58.03": (
        b"\x85\xc0\x0f\x85\xd4\x00\x00\x00\x48",
        b"\x85\xc0\x90\x90\x90\x90\x90\x90\x48",
    ),
}


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _atomic_write(path: str, data: bytes) -> None:
    dir_ = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(dir=dir_, delete=False, suffix=".tmp") as f:
        f.write(data)
        tmp = f.name
    os.replace(tmp, path)


def _patch_bytes_in_data(
    data: bytearray,
    search: bytes,
    replace: bytes,
) -> list[int]:
    """Replace all non-overlapping occurrences of `search` with `replace`.
    Returns list of offsets where replacements were made."""
    assert len(search) == len(replace), "search and replace must be same length"
    offsets = []
    start = 0
    while True:
        pos = data.find(search, start)
        if pos < 0:
            break
        data[pos : pos + len(replace)] = replace
        offsets.append(pos)
        start = pos + len(replace)
    return offsets


# ---------------------------------------------------------------------------
# Patch 1: 3D unlock — ELF-aware device-ID replacement
# ---------------------------------------------------------------------------

def patch_3d_unlock_data(data: bytearray, device_ids: list[int]) -> list[dict]:
    """
    Scan the ELF data sections of `data` for each device ID stored as a
    4-byte little-endian struct [did_lo, did_hi, 0x00, 0x00] at 4-byte
    alignment, and replace the 16-bit ID with 0xFFFF.

    Returns a list of PatchRecord dicts.
    """
    elf = ELF64(bytes(data))
    sections = elf.get_data_sections()
    records = []

    for did in device_ids:
        needle      = struct.pack("<HH", did,    0x0000)
        replacement = struct.pack("<HH", 0xFFFF, 0x0000)

        for sec_off, sec_size in sections:
            pos = sec_off
            end = sec_off + sec_size
            while True:
                p = data.find(needle, pos, end)
                if p < 0:
                    break
                if p % 4 != 0:
                    pos = p + 2
                    continue
                records.append({
                    "offset": p,
                    "original_bytes": data[p : p + 4].hex(),
                    "patched_bytes":  replacement.hex(),
                })
                data[p : p + 4] = replacement
                pos = p + 4

    return records


def patch_3d_unlock_file(path: str, dry_run: bool) -> tuple[list[dict], bytes]:
    """
    Patch `path` in memory.  Returns (records, patched_bytes).
    File is NOT written here; caller decides.
    """
    raw = open(path, "rb").read()
    data = bytearray(raw)
    records = patch_3d_unlock_data(data, ALL_DEVICE_IDS)
    return records, bytes(data)


# ---------------------------------------------------------------------------
# Patch 1b: kernel module (.ko.zst)
# ---------------------------------------------------------------------------

def patch_ko_zst(path: str, dry_run: bool) -> tuple[list[dict], str | None]:
    """
    Decompress, patch device IDs, strip module signature, recompress.
    Returns (records, error_message).  error_message is None on success.
    """
    # Decompress
    result = subprocess.run(
        ["zstd", "-d", "--stdout", path],
        capture_output=True,
    )
    if result.returncode != 0:
        return [], f"zstd -d failed: {result.stderr.decode(errors='replace')}"

    data = bytearray(result.stdout)

    # Parse ELF and strip module signature
    try:
        elf = ELF64(bytes(data))
        elf_end = elf.get_elf_end()
        data = data[:elf_end]
    except ValueError as e:
        return [], f"ELF parse failed: {e}"

    # Apply device ID patches
    records = patch_3d_unlock_data(data, ALL_DEVICE_IDS)

    if not dry_run and records:
        # Recompress with zstd -3 (fast, ~0.2 s vs 29 s for -19)
        result = subprocess.run(
            ["zstd", "-3", "--no-progress", "-f", "-", "-o", path],
            input=bytes(data),
            capture_output=True,
        )
        if result.returncode != 0:
            return records, f"zstd -3 failed: {result.stderr.decode(errors='replace')}"

    return records, None


# ---------------------------------------------------------------------------
# Patch 2: NVENC / FBC unlock — full-file byte pattern replacement
# ---------------------------------------------------------------------------

def patch_pattern_file(
    path: str,
    search: bytes,
    replace: bytes,
    dry_run: bool,
) -> tuple[list[dict], bytes]:
    """
    Scan entire file for `search`, replace with `replace`.
    Returns (records, patched_bytes).
    """
    data = bytearray(open(path, "rb").read())
    offsets = _patch_bytes_in_data(data, search, replace)
    records = [
        {
            "offset": off,
            "original_bytes": search.hex(),
            "patched_bytes":  replace.hex(),
        }
        for off in offsets
    ]
    return records, bytes(data)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Patcher:
    def __init__(
        self,
        driver_ver: str,
        patch_targets: dict,
        manifest_path: str,
        backup_dir: str,
        dry_run: bool = False,
        force: bool = False,
    ):
        self.driver_ver    = driver_ver
        self.targets       = patch_targets
        self.manifest_path = manifest_path
        self.backup_dir    = backup_dir
        self.dry_run       = dry_run
        self.force         = force

        if os.path.isfile(manifest_path):
            self.manifest = mf.load(manifest_path)
        else:
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.manifest = mf.make_empty_manifest(driver_ver, ts)

        self.summary: list[str] = []

    # ------------------------------------------------------------------

    def run(self) -> int:
        """Apply all applicable patches. Returns exit code (0 = success)."""
        errors = 0

        errors += self._run_3d_unlock()
        errors += self._run_nvenc()
        errors += self._run_fbc()
        errors += self._run_ko()

        if not self.dry_run:
            os.makedirs(os.path.dirname(self.manifest_path), exist_ok=True)
            mf.save(self.manifest, self.manifest_path)

        self._print_summary()
        return errors

    # ------------------------------------------------------------------

    def _should_patch(self, path: str, patch_type: str) -> bool:
        if not os.path.isfile(path):
            self.summary.append(f"  SKIP  {os.path.basename(path)} — file not found")
            return False

        state = mf.needs_patch(path, self.manifest)
        if state is False:
            self.summary.append(f"  SKIP  {os.path.basename(path)} — already patched")
            return False
        if state is None and not self.force:
            self.summary.append(
                f"  WARN  {os.path.basename(path)} — unknown sha256 state; "
                "use --force to override"
            )
            return False
        return True

    def _record_patch(
        self,
        path: str,
        patch_type: str,
        sha_pre: str,
        patched_bytes: bytes,
        records: list[dict],
    ) -> None:
        if self.dry_run:
            return
        backup = mf.backup_file(path, self.backup_dir)
        _atomic_write(path, patched_bytes)
        sha_post = mf.sha256_bytes(patched_bytes)
        entry = mf.make_entry(path, patch_type, sha_pre, sha_post, backup, records)
        mf.upsert_entry(self.manifest, entry)

    # ------------------------------------------------------------------

    def _run_3d_unlock(self) -> int:
        errors = 0
        for path in self.targets.get("3d_unlock", []):
            if not self._should_patch(path, "3d_unlock"):
                continue
            sha_pre = mf.sha256_file(path)
            records, patched = patch_3d_unlock_file(path, self.dry_run)
            if not records:
                self.summary.append(
                    f"  WARN  {os.path.basename(path)} — 3D unlock: no device IDs found"
                )
                continue
            verb = "DRY-RUN" if self.dry_run else "PATCHED"
            self.summary.append(
                f"  {verb}  {os.path.basename(path)} — 3D unlock: "
                f"{len(records)} device ID(s) replaced"
            )
            self._record_patch(path, "3d_unlock", sha_pre, patched, records)
        return errors

    def _run_nvenc(self) -> int:
        errors = 0
        pat = NVENC_PATTERNS.get(self.driver_ver)
        if pat is None:
            self.summary.append(
                f"  SKIP  NVENC — no pattern for driver {self.driver_ver}"
            )
            return 0
        search, replace = pat
        for path in self.targets.get("nvenc", []):
            if not self._should_patch(path, "nvenc"):
                continue
            sha_pre = mf.sha256_file(path)
            records, patched = patch_pattern_file(path, search, replace, self.dry_run)
            if not records:
                self.summary.append(
                    f"  WARN  {os.path.basename(path)} — NVENC: pattern not found"
                )
                continue
            verb = "DRY-RUN" if self.dry_run else "PATCHED"
            self.summary.append(
                f"  {verb}  {os.path.basename(path)} — NVENC unlock: "
                f"{len(records)} occurrence(s)"
            )
            self._record_patch(path, "nvenc", sha_pre, patched, records)
        return errors

    def _run_fbc(self) -> int:
        errors = 0
        pat = FBC_PATTERNS.get(self.driver_ver)
        if pat is None:
            self.summary.append(
                f"  SKIP  FBC — no pattern for driver {self.driver_ver}"
            )
            return 0
        search, replace = pat
        for path in self.targets.get("fbc", []):
            if not self._should_patch(path, "fbc"):
                continue
            sha_pre = mf.sha256_file(path)
            records, patched = patch_pattern_file(path, search, replace, self.dry_run)
            if not records:
                self.summary.append(
                    f"  WARN  {os.path.basename(path)} — FBC: pattern not found"
                )
                continue
            verb = "DRY-RUN" if self.dry_run else "PATCHED"
            self.summary.append(
                f"  {verb}  {os.path.basename(path)} — FBC unlock: "
                f"{len(records)} occurrence(s)"
            )
            self._record_patch(path, "fbc", sha_pre, patched, records)
        return errors

    def _run_ko(self) -> int:
        errors = 0
        for path in self.targets.get("ko_3d_unlock", []):
            if not self._should_patch(path, "ko_3d_unlock"):
                continue
            sha_pre = mf.sha256_file(path)
            # Backup first (before decompression/recompression changes the file)
            if not self.dry_run:
                mf.backup_file(path, self.backup_dir)
            records, err = patch_ko_zst(path, self.dry_run)
            if err:
                self.summary.append(
                    f"  ERROR {os.path.basename(path)} — ko patch: {err}"
                )
                errors += 1
                continue
            if not records:
                self.summary.append(
                    f"  WARN  {os.path.basename(path)} — ko 3D unlock: no device IDs found"
                )
                continue
            verb = "DRY-RUN" if self.dry_run else "PATCHED"
            # Include kernel version in display: e.g. nvidia.ko [6.8.0-107-generic]
            kver = _ko_kernel_ver(path)
            label = f"nvidia.ko [{kver}]" if kver else os.path.basename(path)
            self.summary.append(
                f"  {verb}  {label} — ko 3D unlock: "
                f"{len(records)} device ID(s) replaced"
            )
            if not self.dry_run:
                sha_post = mf.sha256_file(path)
                backup = os.path.join(self.backup_dir, _ko_backup_name(path))
                entry = mf.make_entry(
                    path, "ko_3d_unlock", sha_pre, sha_post, backup, records
                )
                mf.upsert_entry(self.manifest, entry)
        return errors

    # ------------------------------------------------------------------

    def _print_summary(self) -> None:
        print()
        print("cmppatcher — patch summary")
        print("=" * 60)
        for line in self.summary:
            print(line)
        print("=" * 60)
        if self.dry_run:
            print("(dry run — no files were modified)")
        print()

    # ------------------------------------------------------------------

    def restore(self) -> int:
        errors = 0
        for entry in self.manifest.get("patches", []):
            path = entry["file_path"]
            ok = mf.restore_file(path, self.manifest)
            if ok:
                print(f"  RESTORED  {path}")
            else:
                print(f"  FAILED    {path} — backup not found")
                errors += 1
        # Remove FMA DT_NEEDED injection if present
        if self.manifest.get("fma_enabled"):
            libcuda = _find_libcuda(self.driver_ver)
            if libcuda:
                subprocess.run(
                    ["patchelf", "--remove-needed",
                     "/etc/cmppatcher/fma_hook.so", libcuda],
                    capture_output=True,
                )
                print(f"  REMOVED   fma_hook.so DT_NEEDED from {libcuda}")
        return errors

    def status(self) -> None:
        print()
        print("cmppatcher — status")
        print("=" * 60)
        print(f"  Driver: {self.manifest.get('driver_version', 'unknown')}")
        print(f"  FMA enabled: {self.manifest.get('fma_enabled', False)}")
        print()
        for entry in self.manifest.get("patches", []):
            path = entry["file_path"]
            state = mf.needs_patch(path, self.manifest)
            if state is False:
                status_str = "OK (patched)"
            elif state is True:
                status_str = "NEEDS REPATCH"
            else:
                status_str = "UNKNOWN STATE"
            print(f"  {status_str:<20} {path}")
        print("=" * 60)
        print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ko_kernel_ver(path: str) -> str | None:
    parts = path.split(os.sep)
    try:
        return parts[parts.index("modules") + 1]
    except (ValueError, IndexError):
        return None


def _ko_backup_name(path: str) -> str:
    parts = path.split(os.sep)
    try:
        kver = parts[parts.index("modules") + 1]
        return f"nvidia.ko.{kver}.zst.bak"
    except (ValueError, IndexError):
        return os.path.basename(path) + ".bak"


def _find_libcuda(driver_ver: str) -> str | None:
    path = f"/usr/lib/x86_64-linux-gnu/libcuda.so.{driver_ver}"
    return path if os.path.isfile(path) else None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="cmppatcher — NVIDIA driver binary patcher")
    ap.add_argument("--dry-run",      action="store_true")
    ap.add_argument("--force",        action="store_true")
    ap.add_argument("--restore",      action="store_true")
    ap.add_argument("--status",       action="store_true")
    ap.add_argument("--auto-repatch", action="store_true")
    ap.add_argument("--manifest",     default="/etc/cmppatcher/patch_manifest.json")
    ap.add_argument("--config",       default="/etc/cmppatcher/config")
    ap.add_argument("--driver",       default=None)
    ap.add_argument("--backup-dir",   default="/etc/cmppatcher/backups")
    args = ap.parse_args()

    # Detect driver version
    driver_ver = args.driver
    if driver_ver is None:
        import glob as _glob
        matches = sorted(_glob.glob("/usr/lib/x86_64-linux-gnu/libcuda.so.*.*.*"))
        for m in matches:
            suffix = os.path.basename(m)[len("libcuda.so."):]
            parts = suffix.split(".")
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                driver_ver = suffix
                break
    if driver_ver is None:
        print("ERROR: could not detect NVIDIA driver version", file=sys.stderr)
        return 1

    # Build patch targets from installed files
    import glob as _glob
    lib = "/usr/lib/x86_64-linux-gnu"
    targets = {
        "3d_unlock": [
            p for p in [
                f"{lib}/libcuda.so.{driver_ver}",
                f"{lib}/libnvidia-glcore.so.{driver_ver}",
                f"{lib}/libGLX_nvidia.so.{driver_ver}",
            ] if os.path.isfile(p)
        ],
        "nvenc": [p for p in [f"{lib}/libnvidia-encode.so.{driver_ver}"] if os.path.isfile(p)],
        "fbc":   [p for p in [f"{lib}/libnvidia-fbc.so.{driver_ver}"]    if os.path.isfile(p)],
        "ko_3d_unlock": sorted(_glob.glob("/lib/modules/*/updates/dkms/nvidia.ko.zst")),
    }

    patcher = Patcher(
        driver_ver=driver_ver,
        patch_targets=targets,
        manifest_path=args.manifest,
        backup_dir=args.backup_dir,
        dry_run=args.dry_run,
        force=args.force,
    )

    if args.restore:
        return patcher.restore()

    if args.status:
        patcher.status()
        return 0

    return patcher.run()


if __name__ == "__main__":
    sys.exit(main())

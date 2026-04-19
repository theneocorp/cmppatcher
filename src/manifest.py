"""
Patch manifest: records every byte changed, SHA-256 state before/after,
and backup file paths.  Provides idempotency logic for repatch.sh.

Backups live as separate files (not inline base64) because each NVIDIA
.so can be 88–91 MB — inline base64 would OOM on 2 GB systems.
"""

import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from typing import Optional


BACKUP_DIR = "/etc/cmppatcher/backups"
MANIFEST_SCHEMA_VERSION = 1


@dataclass
class PatchRecord:
    offset: int
    original_bytes: str   # hex string
    patched_bytes: str    # hex string


@dataclass
class FileEntry:
    file_path: str
    patch_type: str       # "3d_unlock" | "nvenc" | "fbc" | "ko_3d_unlock"
    backup_path: str
    file_sha256_pre: str
    file_sha256_post: str
    records: list[PatchRecord] = field(default_factory=list)


@dataclass
class Manifest:
    schema_version: int
    driver_version: str
    install_timestamp: str
    fma_enabled: bool
    fma_libcuda_sha256_pre: Optional[str]
    fma_libcuda_sha256_post: Optional[str]
    patches: list[FileEntry] = field(default_factory=list)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def save(manifest: dict, path: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp, path)


def needs_patch(file_path: str, manifest: dict) -> Optional[bool]:
    """
    True  → file needs to be patched (never patched, or driver update restored it)
    False → already patched, skip
    None  → unknown state (sha256 matches neither pre nor post) — warn, require --force
    """
    entry = _find_entry(file_path, manifest)
    if entry is None:
        return True

    try:
        current = sha256_file(file_path)
    except FileNotFoundError:
        return True

    if current == entry["file_sha256_post"]:
        return False
    if current == entry["file_sha256_pre"]:
        return True
    return None


def backup_file(src: str, backup_dir: str = BACKUP_DIR) -> str:
    """Copy src to backup_dir, return the backup path."""
    os.makedirs(backup_dir, exist_ok=True)
    basename = os.path.basename(src)
    dst = os.path.join(backup_dir, basename + ".bak")
    # For nvidia.ko.zst, include the kernel version to avoid collisions
    if "nvidia.ko" in basename:
        # path looks like /lib/modules/6.8.0-107-generic/updates/dkms/nvidia.ko.zst
        parts = src.split(os.sep)
        try:
            kver = parts[parts.index("modules") + 1]
            dst = os.path.join(backup_dir, f"nvidia.ko.{kver}.zst.bak")
        except (ValueError, IndexError):
            pass
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
    return dst


def restore_file(file_path: str, manifest: dict) -> bool:
    """Restore file from its backup. Returns True on success."""
    entry = _find_entry(file_path, manifest)
    if entry is None:
        return False
    backup = entry.get("backup_path")
    if not backup or not os.path.isfile(backup):
        return False
    shutil.copy2(backup, file_path)
    return True


def make_entry(
    file_path: str,
    patch_type: str,
    sha_pre: str,
    sha_post: str,
    backup_path: str,
    records: list[dict],
) -> dict:
    return {
        "file_path": file_path,
        "patch_type": patch_type,
        "backup_path": backup_path,
        "file_sha256_pre": sha_pre,
        "file_sha256_post": sha_post,
        "records": records,
    }


def upsert_entry(manifest: dict, entry: dict) -> None:
    """Insert or replace the entry for entry['file_path']."""
    patches = manifest.setdefault("patches", [])
    for i, e in enumerate(patches):
        if e["file_path"] == entry["file_path"]:
            patches[i] = entry
            return
    patches.append(entry)


def make_empty_manifest(driver_ver: str, timestamp: str) -> dict:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "driver_version": driver_ver,
        "install_timestamp": timestamp,
        "fma_enabled": False,
        "fma_libcuda_sha256_pre": None,
        "fma_libcuda_sha256_post": None,
        "patches": [],
    }


def _find_entry(file_path: str, manifest: dict) -> Optional[dict]:
    for e in manifest.get("patches", []):
        if e["file_path"] == file_path:
            return e
    return None

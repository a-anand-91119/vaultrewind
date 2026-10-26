"""Versioned, content-addressed full-instance manifests (never public view models)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath

from .errors import VaultRewindError

SCHEMA_VERSION = 1
SECTIONS = ("data", "deployment", "images")


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_hash(manifest: dict) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def logical_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\x00" in value or "\\" in value:
        raise VaultRewindError("UNSAFE_PATH", "A path escapes the approved instance boundary.")
    return path


def _inside(root: Path, candidate: Path) -> bool:
    return candidate.resolve().is_relative_to(root.resolve())


def inventory(root: Path) -> list[dict]:
    """Fail on unreadable files, special files, external links or unsupported metadata."""
    root = root.resolve(strict=True)
    result, inodes = [], {}

    def visit(path: Path):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        kind = ("symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode)
                else "file" if stat.S_ISREG(info.st_mode) else "unsupported")
        if kind == "unsupported":
            raise VaultRewindError("UNSUPPORTED_FILE", "The instance contains an unsupported special file.")
        entry = {"path": relative, "type": kind, "size": info.st_size if kind == "file" else 0,
                 "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
                 "mtime_ns": info.st_mtime_ns, "xattrs": {}}
        if kind == "symlink":
            target = os.readlink(path)
            if os.path.isabs(target) or not _inside(root, path.parent / target):
                raise VaultRewindError("UNSAFE_SYMLINK", "A link points outside the instance boundary.")
            entry["link_target"] = target
        if kind == "file":
            entry["sha256"] = sha256_file(path)
            inode = (info.st_dev, info.st_ino)
            if info.st_nlink > 1:
                if inode in inodes:
                    entry["hardlink_to"] = inodes[inode]
                else:
                    inodes[inode] = relative
        for name in os.listxattr(path, follow_symlinks=False):
            entry["xattrs"][name] = base64.b64encode(os.getxattr(path, name, follow_symlinks=False)).decode()
        result.append(entry)
        if kind == "directory":
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                visit(child)

    try:
        for child in sorted(root.iterdir(), key=lambda item: item.name):
            visit(child)
    except OSError as exc:
        raise VaultRewindError("REQUIRED_FILE_UNREADABLE", "A required file or its metadata could not be read.") from exc
    return result


def verify_inventory(root: Path, entries: list[dict]) -> dict:
    seen = set()
    for entry in entries:
        relative = logical_path(entry["path"])
        if str(relative) in seen:
            raise VaultRewindError("SNAPSHOT_INCOMPLETE", "The inventory contains duplicate paths.")
        seen.add(str(relative))
        path = root / str(relative)
        if not _inside(root, path.parent):
            raise VaultRewindError("UNSAFE_PATH", "An inventory member escapes the staging boundary.")
        try:
            info = path.lstat()
            expected = entry["type"]
            if expected == "file":
                valid = (stat.S_ISREG(info.st_mode) and not path.is_symlink() and
                         info.st_size == entry["size"] and sha256_file(path) == entry["sha256"])
                if entry.get("hardlink_to"):
                    other = root / str(logical_path(entry["hardlink_to"]))
                    valid = valid and os.path.samefile(path, other)
            elif expected == "directory":
                valid = stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            elif expected == "symlink":
                valid = (stat.S_ISLNK(info.st_mode) and os.readlink(path) == entry["link_target"]
                         and _inside(root, path))
            else:
                valid = False
            if not valid:
                raise VaultRewindError("SNAPSHOT_INCOMPLETE", "A required member failed content or link verification.")
        except OSError as exc:
            raise VaultRewindError("SNAPSHOT_INCOMPLETE", "A required inventory member is unavailable.") from exc
    return {"inventory_verified": True, "members": len(entries),
            "logical_bytes": sum(item["size"] for item in entries if item["type"] == "file")}


def atomic_json(path: Path, value: dict | list):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def create_manifest(root: Path, metadata: dict) -> dict:
    for section in SECTIONS:
        if not (root / section).is_dir() or (root / section).is_symlink():
            raise VaultRewindError("SNAPSHOT_INCOMPLETE", "The canonical snapshot tree is incomplete.")
    required = {"snapshot_uuid", "instance_uuid", "capture_started_at", "captured_at", "source_state",
                "image_id", "image_archive_hash", "platform", "deployment_fingerprint"}
    if not required.issubset(metadata):
        raise VaultRewindError("MANIFEST_INVALID", "Required recovery metadata is missing.")
    entries = [entry for entry in inventory(root) if entry["path"].split("/")[0] in SECTIONS]
    manifest = {"schema_version": SCHEMA_VERSION, "app_version": "0.1.0", "helper_version": "1",
                "consistency_mode": "controlled_stop", "database_engine": "sqlite",
                "registry_digest": None, "vaultwarden_version": "unknown", "database_schema_evidence": {},
                "declared_exclusions": ["normalized db.sqlite3-wal", "normalized db.sqlite3-shm"],
                "dependency_inventory": [], "verification": {}, **metadata, "inventory": entries}
    atomic_json(root / "manifest" / "inventory.json", entries)
    atomic_json(root / "manifest" / "manifest.json", manifest)
    return manifest


def verify_snapshot(root: Path, expected_manifest_hash: str | None = None) -> dict:
    try:
        manifest = json.loads((root / "manifest" / "manifest.json").read_bytes())
    except (OSError, ValueError) as exc:
        raise VaultRewindError("MANIFEST_INVALID", "The stored manifest is unreadable.") from exc
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise VaultRewindError("MANIFEST_VERSION_UNSUPPORTED", "This manifest needs a compatible controller/helper.")
    digest = manifest_hash(manifest)
    if expected_manifest_hash and digest != expected_manifest_hash:
        raise VaultRewindError("MANIFEST_HASH_MISMATCH", "The manifest differs from the committed catalog identity.")
    evidence = verify_inventory(root, manifest["inventory"])
    actual = {entry["path"] for entry in inventory(root) if entry["path"].split("/")[0] in SECTIONS}
    if actual != {entry["path"] for entry in manifest["inventory"]}:
        raise VaultRewindError("SNAPSHOT_INCOMPLETE", "Snapshot content differs from its complete inventory.")
    from .sqlite import validate_sqlite
    evidence.update(validate_sqlite(root / "data"))
    return {**evidence, "manifest_hash": digest, "snapshot_uuid": manifest["snapshot_uuid"],
            "instance_uuid": manifest["instance_uuid"], "manifest": manifest}

"""Controller-backup operations over standard encrypted restic repositories.

This adapter deliberately does not use the Vaultwarden manifest/tree validator. Controller metadata
has its own schema, tags, inventory and exact restore/readback checks while restic still owns repository
format, encryption, chunking and locking.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import ensure_private_directory
from vaultrewind.storage.restic import EXIT_OK, ResticRepository, parse_utc

_FORMAT = "vaultrewind-controller-backup"
_SCHEMA = 1
_HASH = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def file_inventory(root: Path) -> list[dict]:
    """Inventory regular files and directories without following symlinks."""
    entries: list[dict] = []
    for path in sorted(Path(root).rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.relative_to(root).as_posix() in {"controller-manifest.json", "controller-inventory.json"}:
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_UNSUPPORTED_FILE", "Controller backup staging contains a symlink."
            )
        if stat.S_ISDIR(info.st_mode):
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "type": "directory",
                    "mode": stat.S_IMODE(info.st_mode),
                }
            )
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "type": "file",
                    "size": info.st_size,
                    "sha256": digest.hexdigest(),
                    "mode": stat.S_IMODE(info.st_mode),
                }
            )
        else:
            raise VaultRewindError(
                "CONTROLLER_BACKUP_UNSUPPORTED_FILE", "Controller backup staging contains a special file."
            )
    return entries


def verify_inventory(root: Path, inventory: list[dict]) -> dict:
    expected = {entry["path"]: entry for entry in inventory}
    actual = {entry["path"]: entry for entry in file_inventory(root)}
    if expected.keys() != actual.keys():
        raise VaultRewindError(
            "CONTROLLER_BACKUP_READBACK_FAILED",
            "Restored controller files differ from the committed inventory.",
        )
    for path, item in expected.items():
        current = actual[path]
        if (
            item["type"] != current["type"]
            or item.get("mode") != current.get("mode")
            or (
                item["type"] == "file"
                and (item["size"] != current["size"] or item["sha256"] != current["sha256"])
            )
        ):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED", "A restored controller file failed its hash check."
            )
    return {
        "files": sum(item["type"] == "file" for item in inventory),
        "directories": sum(item["type"] == "directory" for item in inventory),
        "bytes": sum(item.get("size", 0) for item in inventory if item["type"] == "file"),
    }


@contextlib.contextmanager
def repository_lock(
    lock_root: Path, physical_identity: str, timeout_seconds: float = 120.0
) -> Iterator[None]:
    """Process-safe controller lock layered over the standard restic repository lock."""
    if not _HASH.fullmatch(physical_identity or ""):
        raise VaultRewindError(
            "REPOSITORY_IDENTITY_MISMATCH", "The controller repository identity is invalid."
        )
    directory = ensure_private_directory(Path(lock_root) / "controller-locks")
    path = directory / f"{physical_identity}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        import time

        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise VaultRewindError(
                        "REPOSITORY_LOCKED", "Another controller backup owns this repository.", True
                    ) from None
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _snapshot_records(repository: ResticRepository) -> list[dict]:
    result = repository._execute(["snapshots", "--json"], "list", max_stdout=16 * 1024 * 1024)
    if result.exit_code != EXIT_OK or result.error_messages or result.warnings:
        raise VaultRewindError(
            "CONTROLLER_REPOSITORY_READ_FAILED",
            "The controller repository snapshot list could not be verified.",
        )
    try:
        records = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise VaultRewindError(
            "CONTROLLER_REPOSITORY_READ_FAILED", "The controller repository returned malformed metadata."
        ) from exc
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise VaultRewindError(
            "CONTROLLER_REPOSITORY_READ_FAILED", "The controller repository returned malformed metadata."
        )
    return records


def _exact_snapshot(
    repository: ResticRepository,
    snapshot_uuid: str,
    manifest_hash: str,
    controller_id: str,
    destination_id: str,
) -> dict | None:
    tag_uuid, tag_manifest = (
        f"vaultrewind:controller-snapshot={snapshot_uuid}",
        f"vaultrewind:controller-manifest={manifest_hash}",
    )
    matches = [row for row in _snapshot_records(repository) if tag_uuid in (row.get("tags") or [])]
    if len(matches) > 1:
        raise VaultRewindError(
            "SNAPSHOT_IDENTITY_CONFLICT", "The repository has duplicate controller snapshot identities."
        )
    if not matches:
        return None
    row = matches[0]
    required = {
        tag_uuid,
        tag_manifest,
        f"vaultrewind:controller={controller_id}",
        f"vaultrewind:destination={destination_id}",
        "vaultrewind:controller-schema=1",
    }
    if not required.issubset(set(row.get("tags") or [])):
        raise VaultRewindError(
            "SNAPSHOT_IDENTITY_CONFLICT",
            "The controller snapshot identity does not match its catalog record.",
        )
    return row


def find_controller_snapshot(
    repository: ResticRepository, *, controller_id: str, destination_id: str, snapshot_uuid: str
) -> dict | None:
    """Find one committed snapshot after a lost worker response, without inventing a new identity."""
    tag_uuid = f"vaultrewind:controller-snapshot={snapshot_uuid}"
    matches = [row for row in _snapshot_records(repository) if tag_uuid in (row.get("tags") or [])]
    if len(matches) > 1:
        raise VaultRewindError(
            "SNAPSHOT_IDENTITY_CONFLICT", "The repository has duplicate controller snapshot identities."
        )
    if not matches:
        return None
    row = matches[0]
    tags = set(row.get("tags") or [])
    required = {
        tag_uuid,
        f"vaultrewind:controller={controller_id}",
        f"vaultrewind:destination={destination_id}",
        "vaultrewind:controller-schema=1",
    }
    if not required.issubset(tags):
        raise VaultRewindError(
            "SNAPSHOT_IDENTITY_CONFLICT",
            "The controller snapshot identity does not match its catalog record.",
        )
    manifest_tags = [tag for tag in tags if tag.startswith("vaultrewind:controller-manifest=")]
    if len(manifest_tags) != 1:
        raise VaultRewindError(
            "SNAPSHOT_IDENTITY_CONFLICT", "The controller snapshot manifest tag is malformed."
        )
    digest = manifest_tags[0].split("=", 1)[1]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise VaultRewindError(
            "SNAPSHOT_IDENTITY_CONFLICT", "The controller snapshot manifest tag is malformed."
        )
    return {**row, "manifest_hash": digest}


def list_controller_snapshots(repository: ResticRepository, *, controller_id: str, destination_id: str) -> list[dict]:
    """List exact controller identities for offline selection without exposing credentials."""
    result = []
    for row in _snapshot_records(repository):
        tags = set(row.get("tags") or [])
        if f"vaultrewind:controller={controller_id}" not in tags:
            continue
        identities = [tag.split("=", 1)[1] for tag in tags if tag.startswith("vaultrewind:controller-snapshot=")]
        if len(identities) != 1:
            raise VaultRewindError("SNAPSHOT_IDENTITY_CONFLICT", "Controller snapshot tags are ambiguous.")
        exact = find_controller_snapshot(repository, controller_id=controller_id,
                                         destination_id=destination_id, snapshot_uuid=identities[0])
        result.append({"snapshot_uuid": identities[0], "restic_snapshot_id": exact["id"],
                       "manifest_hash": exact["manifest_hash"], "captured_at": exact.get("time")})
    return result


def commit_controller_snapshot(
    repository: ResticRepository,
    root: Path,
    *,
    controller_id: str,
    destination_id: str,
    snapshot_uuid: str,
    captured_at: str,
    manifest_hash: str,
    verify_callback: Callable[[Path, dict, dict], None] | None = None,
) -> dict:
    """Commit to standard restic then restore and hash every member before returning success."""
    repository.initialize()
    existing = _exact_snapshot(repository, snapshot_uuid, manifest_hash, controller_id, destination_id)
    summary: dict = {}
    tags = [
        f"vaultrewind:controller={controller_id}",
        f"vaultrewind:destination={destination_id}",
        f"vaultrewind:controller-snapshot={snapshot_uuid}",
        f"vaultrewind:controller-manifest={manifest_hash}",
        "vaultrewind:controller-schema=1",
    ]
    if existing is None:

        def collect(message: dict):
            if message.get("message_type") == "summary":
                summary.update(message)

        args = [
            "backup",
            "--host",
            "vaultrewind-controller",
            "--time",
            parse_utc(captured_at).strftime("%Y-%m-%d %H:%M:%S"),
        ]
        for tag in tags:
            args += ["--tag", tag]
        args += ["--", "."]
        result = repository._execute(args, "commit", cwd=Path(root), stdout_line=collect)
        if (
            result.exit_code != EXIT_OK
            or result.error_messages
            or result.warnings
            or not summary.get("snapshot_id")
        ):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_COMMIT_FAILED", "Restic did not confirm a complete controller snapshot."
            )
        existing = _exact_snapshot(repository, snapshot_uuid, manifest_hash, controller_id, destination_id)
        if not existing or existing.get("id") != summary.get("snapshot_id"):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED",
                "The controller snapshot was not rediscovered with its exact identity.",
            )
    target_parent = Path(root).parent / f"readback-{snapshot_uuid}"
    if target_parent.exists():
        shutil.rmtree(target_parent)
    target_parent.mkdir(mode=0o700)
    result = repository._execute(
        ["restore", "--target", str(target_parent), "--verify", "--", existing["id"]],
        "restore",
        stdout_line=lambda _message: None,
    )
    if result.exit_code != EXIT_OK or result.error_messages or result.warnings:
        shutil.rmtree(target_parent, ignore_errors=True)
        raise VaultRewindError(
            "CONTROLLER_BACKUP_READBACK_FAILED", "The committed controller snapshot failed restic readback."
        )
    restored = target_parent
    try:
        manifest = json.loads((restored / "controller-manifest.json").read_bytes())
        inventory = json.loads((restored / "controller-inventory.json").read_bytes())
        if (
            manifest.get("manifest_hash") != manifest_hash
            or manifest.get("snapshot_uuid") != snapshot_uuid
            or manifest.get("captured_at") != captured_at
        ):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED", "The stored controller manifest identity did not match."
            )
        if (
            hashlib.sha256(
                canonical_json({k: v for k, v in manifest.items() if k != "manifest_hash"})
            ).hexdigest()
            != manifest_hash
        ):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED",
                "The stored controller manifest failed its canonical hash check.",
            )
        if (
            manifest.get("format") != _FORMAT
            or manifest.get("schema_version") != _SCHEMA
            or manifest.get("controller_uuid") != controller_id
            or manifest.get("destination_id") != destination_id
        ):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED", "The stored controller manifest ownership did not match."
            )
        if (
            not isinstance(inventory, dict)
            or inventory.get("format") != _FORMAT
            or inventory.get("schema_version") != _SCHEMA
        ):
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED", "The stored controller inventory schema is unsupported."
            )
        evidence = verify_inventory(restored, inventory["files"])
        if manifest.get("inventory_sha256") != hashlib.sha256(canonical_json(inventory)).hexdigest():
            raise VaultRewindError(
                "CONTROLLER_BACKUP_READBACK_FAILED", "The stored controller inventory failed its hash check."
            )
        if verify_callback:
            verify_callback(restored, manifest, inventory)
        return {
            "restic_snapshot_id": existing["id"],
            "manifest_hash": manifest_hash,
            "repository_id": repository.repository_id,
            "reconciled": not bool(summary),
            **evidence,
        }
    finally:
        shutil.rmtree(target_parent, ignore_errors=True)


def restore_controller_snapshot(
    repository: ResticRepository,
    restic_snapshot_id: str,
    target: Path,
    *,
    expected_manifest_hash: str | None = None,
) -> dict:
    """Restore only into a fresh private directory and validate the controller-specific format."""
    target = Path(target)
    if target.is_symlink() or target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise VaultRewindError(
            "RESTORE_TARGET_NOT_EMPTY", "Controller recovery requires an empty staging directory."
        )
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target, 0o700)
    result = repository._execute(
        ["restore", "--target", str(target), "--verify", "--", restic_snapshot_id],
        "restore",
        stdout_line=lambda _message: None,
    )
    if result.exit_code != EXIT_OK or result.error_messages or result.warnings:
        raise VaultRewindError(
            "CONTROLLER_RESTORE_FAILED", "The controller repository restore could not be verified."
        )
    # The controller snapshot was backed up from cwd with path ".", so restic restores
    # its contents directly into the requested target.
    root = target
    try:
        manifest = json.loads((root / "controller-manifest.json").read_bytes())
        inventory = json.loads((root / "controller-inventory.json").read_bytes())
    except (OSError, ValueError) as exc:
        raise VaultRewindError(
            "CONTROLLER_BACKUP_FORMAT_INVALID", "The controller manifest or inventory is unreadable."
        ) from exc
    if manifest.get("format") != _FORMAT or manifest.get("schema_version") != _SCHEMA:
        raise VaultRewindError(
            "CONTROLLER_BACKUP_VERSION_UNSUPPORTED", "The controller backup schema is not supported."
        )
    if expected_manifest_hash and manifest.get("manifest_hash") != expected_manifest_hash:
        raise VaultRewindError(
            "MANIFEST_HASH_MISMATCH", "The controller backup manifest does not match the catalog record."
        )
    calculated = hashlib.sha256(
        canonical_json({k: v for k, v in manifest.items() if k != "manifest_hash"})
    ).hexdigest()
    if calculated != manifest.get("manifest_hash"):
        raise VaultRewindError(
            "MANIFEST_HASH_MISMATCH", "The controller backup manifest failed its integrity check."
        )
    if (
        not isinstance(inventory, dict)
        or inventory.get("format") != _FORMAT
        or inventory.get("schema_version") != _SCHEMA
        or inventory.get("controller_uuid") != manifest.get("controller_uuid")
        or inventory.get("snapshot_uuid") != manifest.get("snapshot_uuid")
        or not isinstance(inventory.get("files"), list)
    ):
        raise VaultRewindError(
            "CONTROLLER_BACKUP_FORMAT_INVALID", "The controller inventory does not match its manifest."
        )
    if hashlib.sha256(canonical_json(inventory)).hexdigest() != manifest.get("inventory_sha256"):
        raise VaultRewindError(
            "MANIFEST_HASH_MISMATCH", "The controller backup inventory failed its integrity check."
        )
    evidence = verify_inventory(root, inventory["files"])
    return {"root": root, "manifest": manifest, "inventory": inventory, "verified": True, **evidence}

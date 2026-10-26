"""Local persistent controller storage (spec 14.2).

"Local" is a directory mounted from the controller host into the controller
(default ``/var/lib/vaultrewind/backups``), never the container's writable layer.
A missing mount must fail instead of silently writing into the empty underlying
directory, so every destination carries an identity marker created only by the
explicit setup action; validation fails closed when it is absent or different.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import write_private_file

from . import layout

MARKER_NAME = ".vaultrewind-destination.json"
DEFAULT_PATH = "/var/lib/vaultrewind/backups"
DEFAULT_MIN_FREE = 5 * 1024 ** 3

SUPPORTED_FILESYSTEMS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "bcachefs",
                                   "reiserfs", "nfs", "nfs4"})
NETWORK_FILESYSTEMS = frozenset({"nfs", "nfs4"})
REJECTED_FILESYSTEMS = {
    "tmpfs": "a RAM-backed tmpfs does not survive restarts", "ramfs": "RAM-backed storage is not persistent",
    "overlay": "the container's writable layer is discarded when the container is recreated",
    "aufs": "the container's writable layer is discarded when the container is recreated",
    "devtmpfs": "device filesystems are not storage", "proc": "proc is not storage", "sysfs": "sysfs is not storage",
    "squashfs": "read-only image filesystem", "iso9660": "read-only media", "cifs": "restic advises against SMB/CIFS",
    "smb3": "restic advises against SMB/CIFS", "smbfs": "restic advises against SMB/CIFS",
}
SYSTEM_DIRECTORIES = frozenset({"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/opt",
                                "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
                                "/var/lib", "/var/tmp", "/var/run", "/mnt", "/media", "/var/lib/vaultrewind"})


@dataclass
class LocalDestination:
    destination_id: str
    path: Path = Path(DEFAULT_PATH)
    host_path: str | None = None
    min_free_bytes: int = DEFAULT_MIN_FREE
    require_dedicated_mount: bool = True
    allow_unlisted_filesystems: bool = False

    @classmethod
    def from_config(cls, configuration: dict, destination_id: str) -> LocalDestination:
        unknown = set(configuration) - {"path", "host_path", "min_free_bytes", "require_dedicated_mount",
                                        "allow_unlisted_filesystems"}
        if unknown:
            raise VaultRewindError("STORAGE_CONFIGURATION", "Unknown local destination settings were supplied.")
        min_free = configuration.get("min_free_bytes", DEFAULT_MIN_FREE)
        if not isinstance(min_free, int) or isinstance(min_free, bool) or min_free < 0:
            raise VaultRewindError("STORAGE_CONFIGURATION", "The minimum free space must be a byte count.")
        host_path = configuration.get("host_path")
        if host_path is not None and (not isinstance(host_path, str) or len(host_path) > 1024
                                      or any(ord(c) < 32 for c in host_path)):
            raise VaultRewindError("STORAGE_CONFIGURATION", "The displayed host path is malformed.")
        return cls(destination_id=layout.canonical_uuid(destination_id, "destination ID"),
                   path=Path(configuration.get("path", DEFAULT_PATH)), host_path=host_path, min_free_bytes=min_free,
                   require_dedicated_mount=bool(configuration.get("require_dedicated_mount", True)),
                   allow_unlisted_filesystems=bool(configuration.get("allow_unlisted_filesystems", False)))


@dataclass
class LocalRecoveryDestination(LocalDestination):
    """Explicit capability to read an old mounted directory; never usable for new backups."""

    @classmethod
    def from_path(cls, path: Path | str, destination_id: str) -> LocalRecoveryDestination:
        return cls(layout.canonical_uuid(destination_id, "destination ID"), Path(path))


def require_writable(destination: LocalDestination) -> None:
    if isinstance(destination, LocalRecoveryDestination):
        raise VaultRewindError("STORAGE_READ_ONLY", "An offline recovery destination cannot accept repository writes.")


def _unescape(field: str) -> str:
    """mountinfo escapes space, tab, newline and backslash as octal sequences."""
    out, index = [], 0
    while index < len(field):
        if field[index] == "\\" and index + 3 < len(field) and field[index + 1:index + 4].isdigit():
            out.append(chr(int(field[index + 1:index + 4], 8)))
            index += 4
        else:
            out.append(field[index])
            index += 1
    return "".join(out)


def parse_mountinfo(text: str) -> list[dict]:
    mounts = []
    for line in text.splitlines():
        parts = line.split()
        if "-" not in parts:
            continue
        separator = parts.index("-")
        if separator < 6 or len(parts) < separator + 3:
            continue
        mounts.append({"mount_id": int(parts[0]), "parent_id": int(parts[1]), "device": parts[2],
                       "root": _unescape(parts[3]), "mount_point": _unescape(parts[4]),
                       "options": parts[5].split(","), "fs_type": parts[separator + 1],
                       "source": _unescape(parts[separator + 2])})
    return mounts


def mount_for(path: Path, mounts: list[dict]) -> dict:
    """The topmost mount whose mount point contains ``path`` (component-wise)."""
    target = PurePosixPath(path)
    best, best_len = None, -1
    for mount in mounts:  # later entries are mounted on top of earlier ones
        point = PurePosixPath(mount["mount_point"])
        if target == point or point in target.parents:
            length = len(point.parts)
            if length >= best_len:
                best, best_len = mount, length
    if best is None:
        raise VaultRewindError("LOCAL_MOUNT_MISSING", "The storage mount could not be identified.")
    return best


def _check_path_shape(path: Path) -> Path:
    text = str(path)
    if not path.is_absolute() or ".." in path.parts or str(PurePosixPath(text)) != text or any(ord(c) < 32 for c in text):
        raise VaultRewindError("LOCAL_PATH_UNSAFE", "Local storage needs a normalized absolute path.")
    if text in SYSTEM_DIRECTORIES:
        raise VaultRewindError("LOCAL_PATH_UNSAFE", "A root or system directory cannot hold backups.")
    return path


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def read_marker(path: Path) -> dict | None:
    marker = path / MARKER_NAME
    try:
        info = marker.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise VaultRewindError("LOCAL_PATH_UNSAFE", "The destination identity marker is not a regular file.")
    try:
        data = json.loads(marker.read_text())
    except (OSError, ValueError) as exc:
        raise VaultRewindError("LOCAL_MARKER_INVALID", "The destination identity marker is unreadable.") from exc
    if not isinstance(data, dict) or data.get("format") != "vaultrewind-destination":
        raise VaultRewindError("LOCAL_MARKER_INVALID", "The destination identity marker is malformed.")
    return data


def inspect_local_destination(destination: LocalDestination, *, protected_paths=(), required_bytes: int = 0,
                              require_marker: bool = True, mountinfo_text: str | None = None) -> dict:
    """Validate without writing anything. Raises on every blocking condition."""
    path = _check_path_shape(Path(destination.path))
    warnings = ["Local copies alone do not survive loss of the controller disk; add an off-host destination."]
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise VaultRewindError("LOCAL_MOUNT_MISSING", "The local storage mount point does not exist.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise VaultRewindError("LOCAL_PATH_UNSAFE", "The local storage path must be a real directory, not a link.")
    if os.path.realpath(path) != str(path):
        raise VaultRewindError("LOCAL_PATH_UNSAFE", "The local storage path traverses a symbolic link.")
    for protected in protected_paths:
        protected_path = Path(os.path.realpath(protected))
        if _overlaps(path, protected_path):
            raise VaultRewindError("LOCAL_PATH_OVERLAP",
                                   "Backups cannot overlap application, staging, database, key or cache directories.")
    if mountinfo_text is None:
        try:
            mountinfo_text = Path("/proc/self/mountinfo").read_text()
        except OSError as exc:
            raise VaultRewindError("LOCAL_MOUNT_UNKNOWN", "Mount information is unavailable on this controller.") from exc
    mount = mount_for(path, parse_mountinfo(mountinfo_text))
    fs_type = mount["fs_type"]
    if isinstance(destination, LocalRecoveryDestination):
        return _recovery_evidence(destination, path, mount)
    if fs_type in REJECTED_FILESYSTEMS:
        raise VaultRewindError("LOCAL_FILESYSTEM_UNSUPPORTED",
                               f"Unsupported filesystem for backups: {REJECTED_FILESYSTEMS[fs_type]}.",
                               fs_type=fs_type)
    if fs_type.startswith("fuse") and not destination.allow_unlisted_filesystems:
        raise VaultRewindError("LOCAL_FILESYSTEM_UNSUPPORTED", "FUSE filesystems are not supported for backups.",
                               fs_type=fs_type)
    if fs_type not in SUPPORTED_FILESYSTEMS and not destination.allow_unlisted_filesystems:
        raise VaultRewindError("LOCAL_FILESYSTEM_UNSUPPORTED", "This filesystem type has not been validated.",
                               fs_type=fs_type)
    if fs_type in NETWORK_FILESYSTEMS:
        warnings.append("Network filesystem: confirm the export is persistent and not shared with other writers.")
    if destination.require_dedicated_mount and mount["mount_point"] == "/":
        raise VaultRewindError("LOCAL_MOUNT_MISSING",
                               "No dedicated persistent mount was found at the storage path; refusing to write to "
                               "the controller's own root filesystem.")
    if "ro" in mount["options"]:
        raise VaultRewindError("STORAGE_READ_ONLY", "The local storage mount is read-only.")
    if info.st_uid != os.geteuid():
        raise VaultRewindError("LOCAL_PERMISSIONS_UNSAFE",
                               "The storage directory must be owned by the VaultRewind service account.")
    marker = read_marker(path)
    if require_marker:
        if marker is None:
            raise VaultRewindError("LOCAL_MOUNT_MISSING",
                                   "The destination identity marker is missing; the storage mount may be absent. "
                                   "Nothing was written.")
        if info.st_mode & 0o077:
            raise VaultRewindError("LOCAL_PERMISSIONS_UNSAFE",
                                   "The storage directory must be accessible only by the VaultRewind service account.")
    if marker is not None and marker.get("destination_id") != destination.destination_id:
        raise VaultRewindError("LOCAL_DESTINATION_MISMATCH",
                               "This directory belongs to a different VaultRewind destination.")
    usage = os.statvfs(path)
    free, total = usage.f_bavail * usage.f_frsize, usage.f_blocks * usage.f_frsize
    needed = destination.min_free_bytes + max(0, int(required_bytes))
    if free < needed:
        raise VaultRewindError("INSUFFICIENT_SPACE", "The local storage mount lacks the required free space.",
                               free_bytes=free, required_bytes=needed)
    return {"backend": "local", "path": str(path), "host_path": destination.host_path,
            "mount": {"mount_point": mount["mount_point"], "fs_type": fs_type, "mount_id": mount["mount_id"],
                      "device": mount["device"], "fsid": int(getattr(usage, "f_fsid", 0))},
            "free_bytes": free, "total_bytes": total, "min_free_bytes": destination.min_free_bytes,
            "marker_present": marker is not None, "warnings": warnings}


def _recovery_evidence(destination: LocalDestination, path: Path, mount: dict) -> dict:
    """Offline recovery of an existing disk: identity must match if present; nothing is created."""
    marker = read_marker(path)
    if marker is not None and marker.get("destination_id") != destination.destination_id:
        raise VaultRewindError("LOCAL_DESTINATION_MISMATCH",
                               "This directory belongs to a different VaultRewind destination.")
    warnings = ["Recovery mode: persistence, ownership and free-space checks for new backups are skipped."]
    if marker is None:
        warnings.append("No destination identity marker was found; confirm this is the intended backup copy.")
    return {"backend": "local", "path": str(path), "host_path": None, "recovery_mode": True,
            "backup_ready": False, "retention_ready": False, "durable_for_safety": False, "read_only": True,
            "mount": {"mount_point": mount["mount_point"], "fs_type": mount["fs_type"], "mount_id": mount["mount_id"],
                      "device": mount["device"]}, "marker_present": marker is not None, "warnings": warnings}


def initialize_local_destination(destination: LocalDestination, *, protected_paths=(),
                                 mountinfo_text: str | None = None) -> dict:
    """Explicit setup/test action: restrict permissions and write the identity marker once."""
    require_writable(destination)
    evidence = inspect_local_destination(destination, protected_paths=protected_paths, require_marker=False,
                                         mountinfo_text=mountinfo_text)
    path = Path(destination.path)
    os.chmod(path, 0o700)  # our dedicated backup directory, never live instance data
    if not evidence["marker_present"]:
        marker = {"format": "vaultrewind-destination", "version": 1, "destination_id": destination.destination_id,
                  "marker_id": str(uuid.uuid4()), "created_at": datetime.now(UTC).isoformat()}
        try:
            write_private_file(path / MARKER_NAME, json.dumps(marker, sort_keys=True) + "\n")
        except FileExistsError:
            pass
    return inspect_local_destination(destination, protected_paths=protected_paths, mountinfo_text=mountinfo_text)


def local_repository_location(destination: LocalDestination, instance_id: str) -> str:
    return str(Path(destination.path) / layout.repository_prefix(instance_id, destination.destination_id))


def probe_local(destination: LocalDestination, **inspect_kwargs) -> dict:
    """Write, read back and delete a uniquely named probe inside the destination namespace."""
    require_writable(destination)
    evidence = inspect_local_destination(destination, **inspect_kwargs)
    probe_dir = Path(destination.path) / layout.LAYOUT_ROOT / ".probe"
    probe_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    probe = probe_dir / f"{uuid.uuid4()}.probe"
    payload = os.urandom(32)
    write_private_file(probe, payload)
    try:
        if probe.read_bytes() != payload:
            raise VaultRewindError("STORAGE_PROBE_FAILED", "The storage probe did not read back correctly.")
    finally:
        probe.unlink(missing_ok=True)
    return {**evidence, "probe": {"write": True, "read": True, "delete": not probe.exists()}}


def list_local_repositories(destination: LocalDestination) -> list[dict]:
    """Discover ``vaultrewind/<instance>/<destination>`` repositories (offline recovery)."""
    root = Path(destination.path) / layout.LAYOUT_ROOT
    found = []
    if not root.is_dir() or root.is_symlink():
        return found
    for instance_dir in sorted(root.iterdir()):
        if not instance_dir.is_dir() or instance_dir.is_symlink():
            continue
        for repo_dir in sorted(instance_dir.iterdir()):
            parsed = layout.parse_repository_prefix(f"{layout.LAYOUT_ROOT}/{instance_dir.name}/{repo_dir.name}")
            if parsed and repo_dir.is_dir() and not repo_dir.is_symlink() and (repo_dir / "config").is_file():
                found.append({"instance_id": parsed[0], "destination_id": parsed[1], "location": str(repo_dir)})
    return found

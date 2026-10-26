"""Revisioned encrypted credential persistence and per-destination credential locks."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import stat
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import atomic_private_write, ensure_private_directory
from vaultrewind.security.secrets import SecretBox, load_master_key_file, write_master_key_file

_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


def _safe_id(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise VaultRewindError("IDENTIFIER_INVALID", "Invalid destination identifier.")
    return value


@dataclass(frozen=True)
class StoredCredential:
    envelope: str
    revision: int
    generation: str | None = None


class CredentialStore(Protocol):
    def load(self, destination_id: str) -> StoredCredential | None: ...

    def compare_and_swap(self, destination_id: str, envelope: str, expected_revision: int | None,
                         *, expected_generation: str | None = None) -> int: ...


def credential_context(destination_id: str) -> str:
    return f"destination:{destination_id}:credential"


@contextlib.contextmanager
def credential_lock(lock_dir: Path, destination_id: str, timeout: float = 120.0) -> Iterator[None]:
    """Exclusive inter-process (flock) and inter-thread lock for one destination's credential."""
    directory = ensure_private_directory(Path(lock_dir))
    path = directory / f"{_safe_id(destination_id)}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise VaultRewindError("CREDENTIAL_LOCK_TIMEOUT",
                                           "Another job is updating this destination's credential.", True) from None
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class FileCredentialStore:
    """Single-host store for the CLI/offline tools: one 0600 JSON file per destination."""

    def __init__(self, directory: Path):
        self.directory = ensure_private_directory(Path(directory))
        self.state_directory = self.directory
        self._mutex = threading.Lock()

    def _path(self, destination_id: str) -> Path:
        return self.directory / f"{_safe_id(destination_id)}.credential.json"

    def load(self, destination_id: str) -> StoredCredential | None:
        try:
            data = json.loads(_read_private(self._path(destination_id)))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise VaultRewindError("CREDENTIAL_UNREADABLE", "The stored credential is unreadable.") from exc
        # Legacy files use a stable generation until their next atomic replacement.
        return StoredCredential(str(data["envelope"]), int(data["revision"]), data.get("generation", "legacy"))

    def compare_and_swap(self, destination_id: str, envelope: str, expected_revision: int | None,
                         *, expected_generation: str | None = None) -> int:
        with self._mutex, credential_lock(self.directory / "locks", destination_id):
            current = self.load(destination_id)
            current_revision = current.revision if current else None
            if current_revision != expected_revision or (expected_generation is not None and
                    (current is None or current.generation != expected_generation)):
                raise VaultRewindError("CREDENTIAL_STALE", "A newer credential was stored concurrently.")
            revision = (current_revision or 0) + 1
            generation = current.generation if current else str(uuid.uuid4())
            atomic_private_write(self._path(destination_id),
                                 json.dumps({"envelope": envelope, "revision": revision, "generation": generation}))
            return revision


class MemoryCredentialStore:
    """In-process store used by tests and by the offline recovery CLI when nothing is persisted."""

    def __init__(self):
        self._mutex = threading.Lock()
        self._items: dict[str, StoredCredential] = {}

    def load(self, destination_id: str) -> StoredCredential | None:
        with self._mutex:
            return self._items.get(destination_id)

    def compare_and_swap(self, destination_id: str, envelope: str, expected_revision: int | None,
                         *, expected_generation: str | None = None) -> int:
        with self._mutex:
            current = self._items.get(destination_id)
            if (current.revision if current else None) != expected_revision or (expected_generation is not None and
                    (current is None or current.generation != expected_generation)):
                raise VaultRewindError("CREDENTIAL_STALE", "A newer credential was stored concurrently.")
            revision = (current.revision if current else 0) + 1
            self._items[destination_id] = StoredCredential(envelope, revision,
                                                          current.generation if current else str(uuid.uuid4()))
            return revision


def _read_private_bytes(path: Path) -> bytes:
    """Read bounded private state without following links or accepting permissive modes."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise VaultRewindError("CREDENTIAL_STATE_UNSAFE", "Credential recovery state must be private and owner-only.")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            text = handle.read(1024 * 1024 + 1)
        if len(text) > 1024 * 1024:
            raise VaultRewindError("CREDENTIAL_STATE_UNSAFE", "Credential recovery state exceeds the size limit.")
        return text
    finally:
        os.close(fd)


def _read_private(path: Path) -> str:
    try:
        return _read_private_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VaultRewindError("CREDENTIAL_STATE_UNSAFE", "Credential recovery state is malformed.") from exc


def _private_state_directory(path: Path) -> Path:
    path = Path(path).absolute()
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise VaultRewindError("CREDENTIAL_STATE_UNSAFE", "Credential recovery directories cannot traverse links.")
    if path.exists():
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise VaultRewindError("CREDENTIAL_STATE_UNSAFE", "Credential recovery directories must be owner-only.")
    else:
        path.mkdir(mode=0o700, parents=True)
        _fsync_directory(path.parent)
    return path


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def open_recovery_credentials(work_dir: Path) -> tuple[SecretBox, FileCredentialStore]:
    """Restart-safe offline credential state; keep this directory until all refreshes are reconciled.

    The random encryption key is a private key file, never an OAuth token. The store and
    pending journal contain only authenticated encrypted envelopes, independently of kit export.
    """
    root = _private_state_directory(Path(work_dir))
    directory = _private_state_directory(root / "recovery-credentials")
    key_path = directory / "master.key"
    with credential_lock(directory / "locks", "recovery-key"):
        if not key_path.exists() and not key_path.is_symlink():
            if (any((directory / "store").rglob("*.json")) or has_pending_credentials(directory) or
                    has_unrecovered_drive_sessions(directory)):
                raise VaultRewindError("SECRET_KEY_UNAVAILABLE",
                                       "Restore the recovery credential key before opening encrypted updates.")
            write_master_key_file(key_path)
            _fsync_directory(directory)
        _read_private_bytes(key_path)
        box = SecretBox(load_master_key_file(key_path))
    return box, FileCredentialStore(_private_state_directory(directory / "store"))


class PendingCredentialUpdates:
    """Fsynced encrypted outbox, separate from disposable rclone scratch."""

    def __init__(self, state_directory: Path, box: SecretBox, destination_id: str):
        self.directory = _private_state_directory(_private_state_directory(state_directory) / "pending")
        self.box, self.destination_id = box, _safe_id(destination_id)

    def _context(self, path: Path) -> str:
        return f"destination:{self.destination_id}:pending:{path.name}"

    def save(self, update: dict) -> Path:
        path = self.directory / f"{self.destination_id}.{uuid.uuid4()}.pending-credential"
        atomic_private_write(path, self.box.encrypt(update, context=self._context(path)))
        return path

    def load(self):
        for path in sorted(self.directory.glob(f"{self.destination_id}.*.pending-credential")):
            payload = self.box.decrypt(_read_private(path), context=self._context(path))
            if not isinstance(payload, dict) or payload.get("version") != 1:
                raise VaultRewindError("CREDENTIAL_STATE_UNSAFE", "A pending credential update is malformed.")
            yield path, payload

    def remove(self, path: Path) -> None:
        path.unlink()
        _fsync_directory(self.directory)


def has_pending_credentials(root: Path) -> bool:
    """Cleanup guard: never discard a tree containing an unreconciled encrypted update."""
    return any(Path(root).rglob("*.pending-credential"))


MAX_DRIVE_SESSIONS = 128
MAX_SESSION_FILES = 16
MAX_RCLONE_CONFIG = 64 * 1024


@dataclass
class DriveSessionRecord:
    path: Path
    value: dict
    lease_fd: int

    def close(self) -> None:
        if self.lease_fd >= 0:
            os.close(self.lease_fd)
            self.lease_fd = -1


class DriveSessionJournal:
    """Encrypted provenance for rclone configs, durable before a provider process can use them.

    The config may be rewritten atomically by rclone, so its parent directory identity and
    immutable configuration settings are bound instead of pinning the config's original inode.
    A lease held for the context lifetime prevents recovery from treating a live session as orphaned.
    """

    def __init__(self, state_directory: Path, box: SecretBox, destination_id: str):
        self.directory = _private_state_directory(_private_state_directory(state_directory) / "sessions")
        self.box, self.destination_id = box, _safe_id(destination_id)

    def _context(self, path: Path) -> str:
        return f"destination:{self.destination_id}:session:{path.name}"

    def register(self, workspace: Path, update: dict, configuration_fingerprint: str) -> DriveSessionRecord:
        workspace = Path(workspace).absolute()
        _private_state_directory(workspace)
        info = workspace.stat()
        _fsync_directory(workspace)
        _fsync_directory(workspace.parent)
        session_id = str(uuid.uuid4())
        path = self.directory / f"{self.destination_id}.{session_id}.drive-session"
        lease = path.with_suffix(".lease")
        fd = os.open(lease, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(fd, 0o600)
        record = DriveSessionRecord(path, {
            "version": 1, "session_id": session_id, "phase": "prepared", "created_ns": time.time_ns(),
            "workspace": str(workspace), "workspace_device": info.st_dev, "workspace_inode": info.st_ino,
            "owner_uid": os.geteuid(), "configuration_fingerprint": configuration_fingerprint,
            "update": update}, fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(fd)
            self.save(record)
        except BaseException:
            record.close()
            raise
        return record

    def save(self, record: DriveSessionRecord, *, phase: str | None = None) -> None:
        if phase is not None:
            record.value["phase"] = phase
        if phase == "ready":
            _fsync_directory(Path(record.value["workspace"]))
        atomic_private_write(record.path, self.box.encrypt(record.value, context=self._context(record.path)))

    def paths(self) -> list[Path]:
        paths = []
        scanned = 0
        with os.scandir(self.directory) as entries:
            for entry in entries:
                scanned += 1
                if scanned > 4096:
                    raise VaultRewindError("CREDENTIAL_SESSION_LIMIT", "Too much credential recovery state needs review.")
                if entry.name.startswith(self.destination_id + ".") and entry.name.endswith(".drive-session"):
                    paths.append(Path(entry.path))
                    if len(paths) > MAX_DRIVE_SESSIONS:
                        raise VaultRewindError("CREDENTIAL_SESSION_LIMIT", "Too many Drive sessions need recovery.")
        return sorted(paths)

    def acquire_orphan(self, path: Path) -> DriveSessionRecord | None:
        # Never recreate a missing lease: replacing one could bypass a still-live owner's lock.
        fd = os.open(path.with_suffix(".lease"), os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "A Drive session lease is unsafe.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                return None
            value = self.box.decrypt(_read_private(path), context=self._context(path))
            if (not isinstance(value, dict) or value.get("version") != 1 or
                    path.name != f"{self.destination_id}.{value.get('session_id')}.drive-session" or
                    value.get("phase") not in {"prepared", "ready", "finalized"} or
                    not isinstance(value.get("update"), dict)):
                raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "Drive session recovery metadata is malformed.")
            return DriveSessionRecord(path, value, fd)
        except BaseException:
            os.close(fd)
            raise

    def remove(self, record: DriveSessionRecord) -> None:
        record.path.unlink(missing_ok=True)
        _fsync_directory(self.directory)
        record.path.with_suffix(".lease").unlink(missing_ok=True)
        _fsync_directory(self.directory)


@contextlib.contextmanager
def registered_workspace(record: DriveSessionRecord) -> Iterator[int]:
    """Walk the sealed absolute path without following any component's symlink; pin its identity."""
    value = record.value
    text = value.get("workspace")
    if not isinstance(text, str) or len(text) > 4096:
        raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "The registered Drive workspace is invalid.")
    path = Path(text)
    if (not path.is_absolute() or ".." in path.parts or len(path.parts) > 128 or str(path) != text or
            not path.name.startswith("vaultrewind-rclone-")):
        raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "The registered Drive workspace is invalid.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if (info.st_uid != os.geteuid() or info.st_uid != value.get("owner_uid") or
                stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != value.get("workspace_device") or
                info.st_ino != value.get("workspace_inode")):
            raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "The registered Drive workspace identity changed.")
        yield fd
    finally:
        os.close(fd)


def read_registered_config(record: DriveSessionRecord) -> str:
    with registered_workspace(record) as directory:
        fd = os.open("rclone.conf", os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > MAX_RCLONE_CONFIG):
                raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "The registered Drive config is unsafe.")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read(MAX_RCLONE_CONFIG + 1)
            if len(data) > MAX_RCLONE_CONFIG:
                raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "The registered Drive config is too large.")
            return data.decode("utf-8")
        finally:
            os.close(fd)


def scrub_registered_workspace(record: DriveSessionRecord) -> None:
    """Scrub only bounded regular config files in the exact registered private directory."""
    with registered_workspace(record) as directory:
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                names.append(entry.name)
                if (len(names) > MAX_SESSION_FILES or
                        not re.fullmatch(r"rclone\.conf[A-Za-z0-9._-]{0,100}", entry.name)):
                    raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "Unexpected files in a registered Drive workspace.")
        for name in names:
            fd = os.open(name, os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > MAX_RCLONE_CONFIG):
                    raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "An orphaned Drive config cannot be scrubbed safely.")
                data = memoryview(b"\0" * info.st_size)
                while data:
                    written = os.write(fd, data)
                    if written <= 0:
                        raise OSError("credential scrub made no progress")
                    data = data[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    workspace = Path(record.value["workspace"])
    os.rmdir(workspace)
    _fsync_directory(workspace.parent)


def registered_config_in_use(record: DriveSessionRecord) -> bool:
    """A killed owner can leave a restic/rclone child alive; do not recover while it can still rewrite.

    Every producer gives provider subprocesses RCLONE_CONFIG. Only compare this exact sealed path,
    never log environments. Limit process count and each read; uncertain process visibility fails closed.
    """
    needle = b"RCLONE_CONFIG=" + os.fsencode(str(Path(record.value["workspace"]) / "rclone.conf"))
    scanned = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            scanned += 1
            if scanned > 4096:
                raise VaultRewindError("CREDENTIAL_SESSION_LIMIT", "Process visibility is too large for safe Drive recovery.")
            try:
                if entry.stat(follow_symlinks=False).st_uid != os.geteuid():
                    continue
                with open(Path(entry.path) / "environ", "rb") as handle:
                    environment = handle.read(128 * 1024 + 1)
                if len(environment) > 128 * 1024:
                    raise VaultRewindError("CREDENTIAL_SESSION_BUSY", "A provider process needs review before token recovery.", True)
                if needle in environment.split(b"\0"):
                    return True
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as exc:
                raise VaultRewindError("CREDENTIAL_SESSION_BUSY", "Provider process visibility is uncertain; retry recovery.", True) from exc
    return False


def has_unrecovered_drive_sessions(root: Path) -> bool:
    """Protect encrypted session metadata as well as pending updates during state maintenance."""
    return any(Path(root).rglob("*.drive-session"))

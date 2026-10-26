"""Owner-only temporary credential files for restic/rclone and atomic private writes."""
from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def ensure_private_directory(path: Path, *, create: bool = True) -> Path:
    """Require an existing owner-only (0700) directory that is not a symlink."""
    path = Path(path)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = path.lstat()
    except OSError as exc:
        raise VaultRewindError("PRIVATE_DIRECTORY_UNAVAILABLE", "A private working directory is unavailable.") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise VaultRewindError("PRIVATE_DIRECTORY_UNSAFE", "A private working directory is not a real directory.")
    if info.st_uid != os.geteuid():
        raise VaultRewindError("PRIVATE_DIRECTORY_UNSAFE", "A private working directory belongs to another account.")
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)
    return path


def write_private_file(path: Path, data: bytes | str, *, mode: int = 0o600, exclusive: bool = True) -> Path:
    """Write a file readable only by the controller account; refuses to follow symlinks."""
    path = Path(path)
    payload = data.encode() if isinstance(data, str) else data
    flags = os.O_WRONLY | os.O_CREAT | _NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def atomic_private_write(path: Path, data: bytes | str, *, mode: int = 0o600) -> None:
    """Replace ``path`` atomically (temp file + fsync + rename + directory fsync)."""
    path = Path(path)
    payload = data.encode() if isinstance(data, str) else data
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def scrub_file(path: Path) -> None:
    """Best-effort overwrite then unlink. Copy-on-write filesystems may keep old blocks."""
    try:
        fd = os.open(path, os.O_WRONLY | _NOFOLLOW)
    except (FileNotFoundError, OSError):
        with contextlib.suppress(FileNotFoundError, IsADirectoryError, PermissionError):
            os.unlink(path)
        return
    try:
        size = os.fstat(fd).st_size
        if size:
            os.pwrite(fd, b"\0" * min(size, 16 * 1024 * 1024), 0)
            os.fsync(fd)
    finally:
        os.close(fd)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def scrub_tree(root: Path) -> None:
    root = Path(root)
    if not root.exists():
        return
    for directory, _, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            scrub_file(Path(directory) / name)
    shutil.rmtree(root, ignore_errors=True)


def default_runtime_root() -> Path:
    """Prefer a RAM-backed per-user runtime directory for short-lived credential files."""
    for candidate in (os.environ.get("VAULTREWIND_RUNTIME_DIR"), os.environ.get("XDG_RUNTIME_DIR")):
        if candidate and Path(candidate).is_absolute() and Path(candidate).is_dir():
            return Path(candidate)
    return Path(tempfile.gettempdir())


@contextlib.contextmanager
def private_workspace(root: Path | None = None, prefix: str = "vaultrewind-") -> Iterator[Path]:
    """A fresh 0700 directory that is scrubbed on exit, even after errors."""
    base = Path(root) if root else default_runtime_root()
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=base))
    os.chmod(directory, 0o700)
    try:
        yield directory
    finally:
        scrub_tree(directory)

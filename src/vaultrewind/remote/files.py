"""Lossless private staging and conservative filesystem capability checks."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tarfile
from pathlib import Path, PurePosixPath

from .journal import fsync_directory
from .policy import no_symlink, relative
from .protocol import fail


def file_hash(path: Path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def walk_checked(root: Path):
    no_symlink(root)
    device = root.stat().st_dev
    entries = []
    links = {}

    def visit(path, expected=None):
        if len(entries) >= 1_000_000:
            fail("INVENTORY_LIMIT", "Persistent tree exceeds the supported member count.")
        st = expected or path.lstat()
        if st.st_dev != device:
            fail("UNSUPPORTED_MOUNT", "An unenrolled nested filesystem crosses the persistent boundary.")
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
            fail("UNSUPPORTED_METADATA", "Persistent tree contains a device, socket, or FIFO.")
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            fail("UNSUPPORTED_METADATA", "Setuid/setgid persistent files require explicit unsupported metadata support.")
        try:
            attrs = os.listxattr(path, follow_symlinks=False)
            if "security.capability" in attrs:
                fail("UNSUPPORTED_METADATA", "Executable file capabilities are unsupported.")
            for attr in attrs:
                os.getxattr(path, attr, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(path)
                if os.path.isabs(target):
                    fail("PATH_UNSAFE", "Only internal relative symbolic links are supported.")
                resolved = (path.parent / target).resolve(strict=True)
                if root != resolved and root not in resolved.parents:
                    fail("PATH_UNSAFE", "Symbolic link escapes the enrolled persistent boundary.")
            if stat.S_ISREG(st.st_mode):
                links.setdefault((st.st_dev, st.st_ino), []).append(st.st_nlink)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                os.close(fd)
            entries.append((path, st))
            if stat.S_ISDIR(st.st_mode):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    opened = os.fstat(fd)
                    if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                        fail("SOURCE_CHANGED", "A persistent directory changed during inventory.")
                    with os.scandir(fd) as children:
                        for child in sorted(children, key=lambda c: c.name):
                            visit(path / child.name, child.stat(follow_symlinks=False))
                finally:
                    os.close(fd)
        except OSError:
            fail("REQUIRED_FILE_UNREADABLE", "A required file or its metadata cannot be read completely.")
    visit(root)
    if any(len(counts) != counts[0] for counts in links.values()):
        fail("PATH_UNSAFE", "Hard links cross the enrolled persistent boundary.")
    return entries


def copy_tree(source: Path, destination: Path, check=lambda: None):
    entries = walk_checked(source)
    hardlinks = {}
    metadata = {}
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path, old in entries:
        check()
        rel = path.relative_to(source)
        target = destination / rel if rel.parts else destination
        now = path.lstat()
        if (now.st_dev, now.st_ino, now.st_mode, now.st_size, now.st_mtime_ns) != (
                old.st_dev, old.st_ino, old.st_mode, old.st_size, old.st_mtime_ns):
            fail("SOURCE_CHANGED", "Persistent content changed while capture was in progress.")
        if stat.S_ISLNK(old.st_mode):
            metadata[path] = {name: os.getxattr(path, name, follow_symlinks=False)
                              for name in os.listxattr(path, follow_symlinks=False)}
        else:
            metadata_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(metadata_fd)
                if (opened.st_dev, opened.st_ino) != (old.st_dev, old.st_ino):
                    fail("SOURCE_CHANGED", "A persistent entry changed before metadata capture.")
                metadata[path] = {name: os.getxattr(metadata_fd, name) for name in os.listxattr(metadata_fd)}
            finally:
                os.close(metadata_fd)
        if stat.S_ISDIR(old.st_mode):
            if target == destination and target.exists():
                if not target.is_dir() or any(target.iterdir()):
                    fail("TARGET_NOT_EMPTY", "Generation destination is not empty.")
            else:
                target.mkdir(mode=0o700)
        elif stat.S_ISLNK(old.st_mode):
            target.symlink_to(os.readlink(path))
        else:
            key = (old.st_dev, old.st_ino)
            if key in hardlinks:
                os.link(hardlinks[key], target)
            else:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as src, target.open("xb") as dst:
                    opened = os.fstat(src.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (old.st_dev, old.st_ino, old.st_size, old.st_mtime_ns):
                        fail("SOURCE_CHANGED", "A persistent file changed before content capture.")
                    while block := src.read(1024 * 1024):
                        check()
                        dst.write(block)
                    dst.flush()
                    os.fsync(dst.fileno())
                hardlinks[key] = target
                if path.stat().st_mtime_ns != old.st_mtime_ns:
                    fail("SOURCE_CHANGED", "Persistent content changed during capture.")
    for path, old in reversed(entries):
        rel = path.relative_to(source)
        target = destination / rel if rel.parts else destination
        os.chown(target, old.st_uid, old.st_gid, follow_symlinks=False)
        if not stat.S_ISLNK(old.st_mode):
            os.chmod(target, stat.S_IMODE(old.st_mode))
        os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns), follow_symlinks=False)
        for attr, value in metadata[path].items():
            os.setxattr(target, attr, value, follow_symlinks=False)
            if os.getxattr(target, attr, follow_symlinks=False) != value:
                fail("UNSUPPORTED_METADATA", "Filesystem could not preserve required extended metadata.")
        if stat.S_ISDIR(old.st_mode):
            fsync_directory(target)
        elif stat.S_ISREG(old.st_mode):
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    fsync_directory(destination.parent)


def build_archive(root: Path, archive: Path, max_bytes: int):
    # Core inventory verifies hashes and metadata; validate links once more before export.
    walk_checked(root)
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT, dereference=False) as tar:
        for child in sorted(root.iterdir()):
            tar.add(child, arcname=child.name, recursive=True)
            if archive.stat().st_size > max_bytes:
                fail("TRANSFER_LIMIT", "Snapshot archive exceeds the enrolled transfer quota.")
    if archive.stat().st_size > max_bytes:
        archive.unlink()
        fail("TRANSFER_LIMIT", "Snapshot archive exceeds the enrolled transfer quota.")
    with archive.open("rb") as f:
        os.fsync(f.fileno())
    return {"bytes": archive.stat().st_size, "sha256": file_hash(archive)}


def extract_archive(archive: Path, target: Path, max_bytes: int, max_members: int):
    """Validate the *whole* archive before writing; links materialized only after files.

    Ownership/xattrs are reapplied separately from the verified manifest, never tar headers.
    """
    if target.exists():
        fail("TARGET_NOT_EMPTY", "Archive extraction requires a new private directory.")
    entries = {}
    total = 0
    with tarfile.open(archive, "r:") as tar:
        for member in tar:
            name = relative(member.name.rstrip("/"))
            if name.split("/")[0] not in ("data", "deployment", "images", "manifest"):
                fail("ARCHIVE_UNSAFE", "Archive member is outside the snapshot layout.")
            if name in entries or len(entries) >= max_members:
                fail("ARCHIVE_UNSAFE", "Archive contains duplicate or excessive members.")
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                fail("ARCHIVE_UNSAFE", "Archive contains unsupported special entries.")
            if member.mode & 0o6000 or member.size < 0 or member.sparse:
                fail("ARCHIVE_UNSAFE", "Archive contains unsupported metadata.")
            if set(member.pax_headers) - {"path", "linkpath", "mtime", "atime", "ctime", "size", "uid", "gid", "uname", "gname"}:
                fail("ARCHIVE_UNSAFE", "Unsupported archive extended headers.")
            total += member.size
            if total > max_bytes:
                fail("TRANSFER_LIMIT", "Expanded archive exceeds the enrolled quota.")
            entries[name] = member
        for name, member in entries.items():
            p = PurePosixPath(name)
            for parent in p.parents:
                if str(parent) != "." and (str(parent) not in entries or not entries[str(parent)].isdir()):
                    fail("ARCHIVE_UNSAFE", "Archive parent is missing or is a link.")
            if member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or "\\" in member.linkname:
                    fail("ARCHIVE_UNSAFE", "Absolute symbolic links are unsupported.")
                # resolve lexically, disallowing traversal above this mount's snapshot boundary
                parts = list(p.parent.parts)
                for part in link.parts:
                    if part == "..":
                        if len(parts) <= 1:
                            fail("ARCHIVE_UNSAFE", "Symbolic link escapes its snapshot boundary.")
                        parts.pop()
                    elif part != ".":
                        parts.append(part)
                linked = "/".join(parts)
                if linked not in entries or entries[linked].issym() or entries[linked].islnk():
                    fail("ARCHIVE_UNSAFE", "Dangling or chained archive links are unsupported.")
            if member.islnk():
                linked = relative(member.linkname)
                if linked not in entries or not entries[linked].isfile():
                    fail("ARCHIVE_UNSAFE", "Hard link must target an included regular file.")
        target.mkdir(mode=0o700)
        for name, member in sorted(entries.items(), key=lambda pair: len(PurePosixPath(pair[0]).parts)):
            path = target / name
            if member.isdir():
                path.mkdir(mode=0o700)
            elif member.isfile():
                with tar.extractfile(member) as src, path.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())
        for name, member in entries.items():
            if member.issym():
                (target / name).symlink_to(member.linkname)
            elif member.islnk():
                os.link(target / member.linkname, target / name)
        # Archive modes are safe (no setuid) and necessary for core content verification.
        for name, member in reversed(list(entries.items())):
            if not member.issym():
                os.chmod(target / name, member.mode & 0o777)
                os.utime(target / name, (member.mtime, member.mtime))
        fsync_directory(target)

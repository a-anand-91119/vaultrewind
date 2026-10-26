"""Bounded, non-privileged archive transfer; target metadata is applied by the helper."""
from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path

from .errors import VaultRewindError
from .manifest import logical_path


def _validate_link_graph(members):
    """Resolve the complete archive link graph before creating any filesystem links."""
    links = {m.name: m.linkname for m in members if m.issym()}
    for name, target in links.items():
        if not target or os.path.isabs(target) or "\x00" in target:
            raise VaultRewindError("UNSAFE_ARCHIVE", "Archive symlink has an unsafe destination.")
        pending = [*name.split("/")[:-1], *target.split("/")]
        resolved, expansions = [], 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved:
                    raise VaultRewindError("UNSAFE_ARCHIVE", "Archive symlink escapes the staging boundary.")
                resolved.pop()
                continue
            resolved.append(part)
            destination = links.get("/".join(resolved))
            if destination is not None:
                expansions += 1
                if expansions > 40 or os.path.isabs(destination):
                    raise VaultRewindError("UNSAFE_ARCHIVE", "Archive symlink graph is cyclic or unsafe.")
                resolved.pop()
                pending = [*destination.split("/"), *pending]


def safe_extract(archive: Path, target: Path, max_bytes: int = 50 * 1024**3, max_members: int = 250_000):
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink() or any(target.iterdir()):
        raise VaultRewindError("UNSAFE_STAGING", "Archive extraction requires an empty private directory.")
    root = target.resolve()
    try:
        with tarfile.open(archive, "r:*") as stream:
            members, seen, total = [], set(), 0
            for member in stream:
                if member.name in (".", "./") and member.isdir():
                    continue
                name = str(logical_path(member.name))
                if name in seen or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise VaultRewindError("UNSAFE_ARCHIVE", "Archive contains duplicate or unsupported members.")
                seen.add(name)
                total += member.size
                if total > max_bytes or len(seen) > max_members:
                    raise VaultRewindError("STAGING_QUOTA_EXCEEDED", "Archive exceeds the reserved staging quota.")
                member.name = name
                if member.islnk():
                    logical_path(member.linkname)
                members.append(member)
            _validate_link_graph(members)
            links = {m.name for m in members if m.issym() or m.islnk()}
            for member in members:
                path = root / member.name
                if any(str(parent.relative_to(root)) in links for parent in path.parents if parent != root and parent.is_relative_to(root)):
                    raise VaultRewindError("UNSAFE_ARCHIVE", "Archive attempts to write through a link.")
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True, mode=0o700)
                elif member.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with stream.extractfile(member) as source, path.open("xb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    os.chmod(path, member.mode & 0o777)
                    os.utime(path, (member.mtime, member.mtime))
            for member in members:
                path = root / member.name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if member.issym():
                    os.symlink(member.linkname, path)
                elif member.islnk():
                    destination = root / str(logical_path(member.linkname))
                    if not destination.is_file() or destination.is_symlink():
                        raise VaultRewindError("UNSAFE_ARCHIVE", "Archive hardlink target is unavailable or unsafe.")
                    os.link(destination, path)
            for member in reversed(members):
                if member.isdir():
                    os.chmod(root / member.name, member.mode & 0o777)
    except (OSError, tarfile.TarError) as exc:
        raise VaultRewindError("TRANSFER_INVALID", "The transferred archive failed safe extraction.") from exc


def create_archive(root: Path, archive: Path):
    from .manifest import inventory
    inventory(root)  # rejects unsupported special files and external links first
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
        for child in sorted(root.iterdir()):
            output.add(child, arcname=child.name, recursive=True)

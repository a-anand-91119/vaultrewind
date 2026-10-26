"""Root-owned enrollment is the authority for every privileged action."""
from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .protocol import HEX, VERBS, decode, fail, identifier

POLICY_PATH = Path("/etc/vaultrewind/helper-policy.json")
STATE_ROOT = Path("/var/lib/vaultrewind-helper")


def clean_absolute(value: str, *, container=False) -> Path:
    if not isinstance(value, str) or "\x00" in value:
        fail("POLICY_INVALID", "An absolute policy path is required.")
    p = PurePosixPath(value)
    if not p.is_absolute() or ".." in p.parts or str(p) != value or len(p.parts) < (2 if container else 3):
        fail("POLICY_INVALID", "Policy paths must be canonical non-root absolute paths.")
    return Path(value)


def no_symlink(path: Path, missing_leaf=False):
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            st = current.lstat()
        except FileNotFoundError:
            if missing_leaf and current == path:
                return path
            fail("REQUIRED_FILE_UNREADABLE", "An enrolled path is unavailable.")
        if stat.S_ISLNK(st.st_mode):
            fail("PATH_UNSAFE", "Policy path contains a symbolic link.")
    return path


def root_trusted(path: Path, directory=False):
    no_symlink(path)
    for current in (path, *path.parents):
        st = current.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            fail("POLICY_UNTRUSTED", "Helper policy and its ancestors must be root-owned and not writable by others.")
    st = path.stat()
    if directory and not stat.S_ISDIR(st.st_mode):
        fail("POLICY_INVALID", "Expected a private state directory.")
    if not directory and not stat.S_ISREG(st.st_mode):
        fail("POLICY_INVALID", "Expected a regular policy file.")


def relative(value):
    if not isinstance(value, str) or "\x00" in value or "\\" in value:
        fail("PATH_UNSAFE", "Invalid logical path.")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or value in ("", ".") or str(p) != value:
        fail("PATH_UNSAFE", "Logical path escapes its snapshot boundary.")
    return value


@dataclass(frozen=True)
class InstancePolicy:
    instance_id: str
    value: dict

    @property
    def mounts(self):
        return self.value["mounts"]

    @property
    def container_id(self):
        return self.value.get("container_id")

    @property
    def operations(self):
        return self.value["allowed_operations"]

    def limit(self, name, default):
        return self.value.get(name, default)

    def mount_source(self, mount):
        return no_symlink(clean_absolute(mount["source"]), missing_leaf=not self.container_id)


class Policy:
    def __init__(self, value: dict, state_root: Path = STATE_ROOT):
        self.value = value
        self.state_root = state_root
        if value.get("schema_version") != 1:
            fail("POLICY_INVALID", "Unsupported policy schema.")
        if not re.fullmatch(r"[A-Za-z0-9:._-]{8,128}", value.get("daemon_id", "")):
            fail("POLICY_INVALID", "Enroll the exact Docker daemon identity.")
        if not re.fullmatch(r"[0-9a-f]{32}", value.get("machine_id", "")):
            fail("POLICY_INVALID", "Enroll the Linux machine identity.")
        if type(value.get("max_staging_bytes", 100 * 1024**3)) is not int or value.get("max_staging_bytes", 100 * 1024**3) < 1024:
            fail("POLICY_INVALID", "A positive host staging quota is required.")
        if not isinstance(value.get("instances"), dict) or not value["instances"]:
            fail("POLICY_INVALID", "Enroll at least one instance.")
        for key, item in value["instances"].items():
            self._validate_instance(identifier(key), item)

    @classmethod
    def load(cls):
        root_trusted(POLICY_PATH)
        root_trusted(STATE_ROOT, directory=True)
        if STATE_ROOT.stat().st_mode & 0o077:
            fail("POLICY_UNTRUSTED", "Helper state directory must have mode 0700.")
        with POLICY_PATH.open("rb") as f:
            return cls(decode(f.read(1024 * 1024 + 1)))

    def instance(self, instance_id):
        item = self.value["instances"].get(instance_id)
        if item is None:
            fail("INSTANCE_NOT_ENROLLED", "Instance is not enrolled in the host policy.")
        return InstancePolicy(instance_id, item)

    def _validate_instance(self, key, item):
        if not isinstance(item, dict):
            fail("POLICY_INVALID", "Invalid instance policy.")
        cid = item.get("container_id")
        if cid is not None and not HEX.fullmatch(cid):
            fail("POLICY_INVALID", "A complete immutable container ID is required.")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", item.get("container_name", "")):
            fail("POLICY_INVALID", "Enroll a valid target container name.")
        ops = item.get("allowed_operations", [])
        if not isinstance(ops, list) or not ops or set(ops) - VERBS:
            fail("POLICY_INVALID", "Invalid allowed operations.")
        mounts = item.get("mounts", [])
        if not isinstance(mounts, list) or not mounts or len(mounts) > 32:
            fail("POLICY_INVALID", "Enroll every persistent mount.")
        sources, targets, names = [], [], []
        for m in mounts:
            if set(m) - {"type", "source", "target", "read_only", "snapshot_path", "volume_name"}:
                fail("POLICY_INVALID", "Unknown mount policy setting.")
            if m.get("type") not in ("bind", "volume") or type(m.get("read_only")) is not bool:
                fail("POLICY_INVALID", "Only bind and local named-volume mounts are supported.")
            source = clean_absolute(m.get("source"))
            target = clean_absolute(m.get("target"), container=True)
            name = relative(m.get("snapshot_path"))
            if name != "data" and not re.fullmatch(r"deployment/mounts/[a-zA-Z0-9_-]{1,64}", name):
                fail("POLICY_INVALID", "Mount snapshot paths must be data or deployment/mounts/<id>.")
            if target == Path("/data") and (name != "data" or m["read_only"]):
                fail("POLICY_INVALID", "The writable /data mount must map to snapshot data/.")
            if source == self.state_root or source in self.state_root.parents or self.state_root in source.parents:
                fail("POLICY_INVALID", "Protected data and helper staging must not overlap.")
            if m["type"] == "volume" and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", m.get("volume_name", "")):
                fail("POLICY_INVALID", "A local named-volume identity is required.")
            if any(source == s or source in s.parents or s in source.parents for s in sources):
                fail("POLICY_INVALID", "Overlapping data mounts are unsupported.")
            if any(target == t or target in t.parents or t in target.parents for t in targets) or name in names:
                fail("UNSUPPORTED_MOUNT", "Overlapping container mount targets require an unsupported layered mount adapter.")
            sources.append(source)
            targets.append(target)
            names.append(name)
        if targets.count(Path("/data")) != 1:
            fail("UNSUPPORTED_INSTALLATION", "Exactly one writable /data mount is required.")
        for name, path in item.get("additional_files", {}).items():
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name) or name in (".", ".."):
                fail("POLICY_INVALID", "Invalid enrolled deployment file name.")
            clean_absolute(path)
        for name, low, high in (("capture_budget", 10, 3600), ("restore_budget", 30, 7200),
                                ("rollback_grace_seconds", 60, 31536000), ("validation_window", 1, 600), ("max_archive_bytes", 1024, 2**50),
                                ("max_members", 1, 10_000_000), ("free_space_reserve", 0, 2**50)):
            if name in item and (type(item[name]) is not int or not low <= item[name] <= high):
                fail("POLICY_INVALID", "Policy limit is out of range.")
        if item.get("ownership") not in ("exclusive", "vaultrewind"):
            fail("SOURCE_RESTART_CONFLICT", "Enrollment must establish exclusive deployment and writer ownership.")
        if item.get("external_dependencies_ready") is not True:
            fail("DEPENDENCY_UNREADY", "Approve external recovery prerequisites before activation.")

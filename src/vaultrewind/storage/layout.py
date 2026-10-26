"""Stable repository naming, snapshot tags and repository secrets.

One restic repository exists per instance per destination at::

    <destination base>/vaultrewind/<instance_uuid>/<destination_uuid>

Display names, hostnames and staging paths never take part in the path, so
renaming anything never moves a repository.  Inside each restic snapshot the
canonical tree is always rooted at ``/`` with ``/data``, ``/deployment``,
``/images`` and ``/manifest`` regardless of the controller staging directory.
"""
from __future__ import annotations

import base64
import re
import secrets
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vaultrewind.core.errors import VaultRewindError

LAYOUT_ROOT = "vaultrewind"
SNAPSHOT_HOST = "vaultrewind"
MANIFEST_PATH = "/manifest/manifest.json"
INVENTORY_PATH = "/manifest/inventory.json"
CANONICAL_SECTIONS = ("data", "deployment", "images", "manifest")

TAG_SNAPSHOT = "vaultrewind:snapshot="
TAG_INSTANCE = "vaultrewind:instance="
TAG_MANIFEST = "vaultrewind:manifest="
TAG_KIND = "vaultrewind:kind="
TAG_SCHEMA = "vaultrewind:schema="
SNAPSHOT_KINDS = ("backup", "safety")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_uuid(value: str, what: str = "identifier") -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise VaultRewindError("IDENTIFIER_INVALID", f"The {what} must be a UUID.") from exc
    text = str(parsed)
    if text != str(value).lower():
        raise VaultRewindError("IDENTIFIER_INVALID", f"The {what} must be a canonical UUID.")
    return text


def repository_prefix(instance_id: str, destination_id: str) -> str:
    return (f"{LAYOUT_ROOT}/{canonical_uuid(instance_id, 'instance ID')}/"
            f"{canonical_uuid(destination_id, 'destination ID')}")


def parse_repository_prefix(relative: str) -> tuple[str, str] | None:
    parts = relative.strip("/").split("/")
    if len(parts) != 3 or parts[0] != LAYOUT_ROOT:
        return None
    try:
        return canonical_uuid(parts[1]), canonical_uuid(parts[2])
    except VaultRewindError:
        return None


def snapshot_tags(snapshot_uuid: str, instance_uuid: str, manifest_hash: str, kind: str) -> list[str]:
    if kind not in SNAPSHOT_KINDS:
        raise VaultRewindError("SNAPSHOT_KIND_INVALID", "Unsupported snapshot kind.")
    if not _HEX64.fullmatch(manifest_hash or ""):
        raise VaultRewindError("MANIFEST_INVALID", "The manifest hash is malformed.")
    return [TAG_SNAPSHOT + canonical_uuid(snapshot_uuid, "snapshot UUID"),
            TAG_INSTANCE + canonical_uuid(instance_uuid, "instance UUID"),
            TAG_MANIFEST + manifest_hash, TAG_KIND + kind, TAG_SCHEMA + "1"]


def parse_tags(tags: list[str] | None) -> dict:
    """Extract VaultRewind identity tags; malformed values are ignored, never trusted."""
    result = {"snapshot_uuid": None, "instance_uuid": None, "manifest_hash": None, "kind": None, "schema": None}
    for tag in tags or []:
        try:
            if tag.startswith(TAG_SNAPSHOT):
                result["snapshot_uuid"] = canonical_uuid(tag[len(TAG_SNAPSHOT):])
            elif tag.startswith(TAG_INSTANCE):
                result["instance_uuid"] = canonical_uuid(tag[len(TAG_INSTANCE):])
            elif tag.startswith(TAG_MANIFEST) and _HEX64.fullmatch(tag[len(TAG_MANIFEST):]):
                result["manifest_hash"] = tag[len(TAG_MANIFEST):]
            elif tag.startswith(TAG_KIND) and tag[len(TAG_KIND):] in SNAPSHOT_KINDS:
                result["kind"] = tag[len(TAG_KIND):]
            elif tag.startswith(TAG_SCHEMA) and tag[len(TAG_SCHEMA):].isdigit():
                result["schema"] = int(tag[len(TAG_SCHEMA):])
        except VaultRewindError:
            continue
    return result


def new_repository_password() -> str:
    """A unique random repository secret (384 bits)."""
    return secrets.token_urlsafe(48)


def new_recovery_root_secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def derive_repository_password(recovery_root_secret: str, instance_id: str, destination_id: str) -> str:
    """Deterministic, unique per instance/destination secret derived with HKDF-SHA256.

    Lets a recovery kit exported at first run open repositories created later.
    A repository whose password was later rotated is no longer derivable; the
    controller then flags that a new recovery kit export is required.
    """
    try:
        root = base64.urlsafe_b64decode(recovery_root_secret + "=" * (-len(recovery_root_secret) % 4))
    except (ValueError, TypeError) as exc:
        raise VaultRewindError("RECOVERY_ROOT_INVALID", "The recovery root secret is malformed.") from exc
    if len(root) != 32:
        raise VaultRewindError("RECOVERY_ROOT_INVALID", "The recovery root secret is malformed.")
    info = f"repository-password|{canonical_uuid(instance_id)}|{canonical_uuid(destination_id)}".encode()
    derived = HKDF(algorithm=hashes.SHA256(), length=36, salt=b"vaultrewind-repository-v1", info=info).derive(root)
    return base64.urlsafe_b64encode(derived).decode()


def validate_restic_id(value: str, *, full: bool = True) -> str:
    """Exact restic object IDs only, so no argument can be interpreted as an option or pattern."""
    if not isinstance(value, str):
        raise VaultRewindError("SNAPSHOT_ID_INVALID", "A restic snapshot ID is malformed.")
    text = value.strip().lower()
    if not (_HEX64.fullmatch(text) if full else re.fullmatch(r"[0-9a-f]{8,64}", text)):
        raise VaultRewindError("SNAPSHOT_ID_INVALID", "A restic snapshot ID is malformed.")
    return text

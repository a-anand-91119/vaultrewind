"""Independently passphrase-encrypted recovery kit (spec section 16).

The kit unlocks every repository without the controller database or master key.
Encryption: Argon2id (argon2-cffi) derives a 256-bit key from the owner-held
passphrase; AES-256-GCM (cryptography) encrypts the JSON contents; the complete
plaintext header (format, version, KDF parameters, salt, nonce) is authenticated
as associated data, so tampering with parameters fails decryption.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import write_private_file
from vaultrewind.security.redaction import register_secret
from vaultrewind.storage import layout, providers
from vaultrewind.storage.restic import RepositoryConfig

KIT_FORMAT = "vaultrewind-recovery-kit"
KIT_VERSION = 1
KIT_SCHEMA = 1
DEFAULT_KDF = {"time_cost": 4, "memory_cost": 262144, "parallelism": 4}  # 256 MiB, ~1 s on a modern CPU
KDF_BOUNDS = {"time_cost": (1, 32), "memory_cost": (8192, 4 * 1024 * 1024), "parallelism": (1, 16)}
MIN_PASSPHRASE = 12
MAX_KIT_BYTES = 32 * 1024 * 1024
NOTICE = ("Encrypted VaultRewind recovery kit. Keep this file and its passphrase outside Vaultwarden and outside "
          "VaultRewind. Inspect it offline with: python -m vaultrewind.recovery inspect --kit <file>")

MANIFEST_SCHEMA = {
    "schema_version": 1,
    "canonical_tree": ["/data", "/deployment", "/images", "/manifest"],
    "manifest_path": layout.MANIFEST_PATH, "inventory_path": layout.INVENTORY_PATH,
    "deployment_descriptor": "/deployment/recovery.json", "image_archive": "/images/vaultwarden.tar",
    "manifest_hash": "sha256 of canonical JSON (sorted keys, compact separators, UTF-8)",
    "restic_tags": [layout.TAG_SNAPSHOT + "<uuid>", layout.TAG_INSTANCE + "<uuid>",
                    layout.TAG_MANIFEST + "<sha256>", layout.TAG_KIND + "backup|safety", layout.TAG_SCHEMA + "1"],
    "repository_layout": "<destination base>/vaultrewind/<instance_uuid>/<destination_uuid>",
}

GENERAL_INSTRUCTIONS = [
    ("Install VaultRewind (or only Python 3.13 with the vaultrewind package) plus the pinned restic 0.19.1 and "
    "rclone 1.75.2 binaries on a clean Linux machine."),
    ("Run 'python -m vaultrewind.recovery discover --kit <file> --work-dir <private dir>' to list snapshots. "
    "The passphrase is prompted for, or read from --passphrase-file; never pass it as an argument."),
    ("Restore a snapshot to an empty local directory with 'python -m vaultrewind.recovery restore'; it is verified "
    "against its manifest and the repository before success is reported."),
    ("Generate the supported target deployment plan with 'python -m vaultrewind.recovery plan'. Apply it only through "
    "VaultRewind's enrolled helper ('Restore to another server'), never by overwriting a live instance by hand."),
    ("On a fresh controller, use Recovery > Import with this kit: repositories are imported in protected mode with "
    "automatic retention disabled until you review policies and pins."),
    ("Repositories created after this kit was exported can still be opened when the kit contains the recovery root "
    "secret and their passwords were not rotated; otherwise export a new kit after adding destinations."),
]

PROVIDER_INSTRUCTIONS = {
    "local": [
        "Attach the disk that held the controller's local backup directory to the recovery machine and mount it.",
        ("The directory contains '.vaultrewind-destination.json' and 'vaultrewind/<instance>/<destination>'. "
        "Pass its new location with --local-path <destination_id>=<mount path> when it differs."),
    ],
    "s3": [
        "The kit holds the endpoint, bucket, prefix and the access key that was valid at export time.",
        ("If that key was rotated or revoked, create a key limited to the bucket prefix (list/read/write; delete only "
        "for retention) and supply it with --credentials-file, a 0600 JSON file "
        "{\"<destination_id>\": {\"access_key_id\": \"...\", \"secret_access_key\": \"...\"}}."),
        "A custom CA bundle, if one was used, is included in the kit.",
    ],
    "drive": [
        ("The repository folder was created by your OAuth client with the drive.file scope, so recovery must use an "
        "OAuth client from the same Google Cloud project; the kit stores its client ID and secret."),
        ("If the stored refresh token was revoked or expired (Testing-mode consent lasts 7 days), run "
        "'rclone authorize drive' as described in docs/RECOVERY.md and supply the token JSON with --credentials-file "
        "{\"<destination_id>\": {\"token\": {...}}}."),
        ("If the Cloud project itself is lost, a new client cannot see the old folder under drive.file; download the "
        "folder through Google Drive's web interface and use it as a local destination copy."),
    ],
}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def check_passphrase(passphrase: str) -> str:
    if not isinstance(passphrase, str) or len(passphrase) > 1024 or "\x00" in passphrase:
        raise VaultRewindError("RECOVERY_PASSPHRASE_WEAK", "The recovery passphrase is invalid.")
    if len(passphrase) < MIN_PASSPHRASE or len(set(passphrase)) < 6:
        raise VaultRewindError("RECOVERY_PASSPHRASE_WEAK",
                               f"Use a recovery passphrase of at least {MIN_PASSPHRASE} varied characters.")
    register_secret(passphrase)
    return passphrase


def _derive(passphrase: str, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(passphrase.encode("utf-8"), salt, time_cost=params["time_cost"],
                           memory_cost=params["memory_cost"], parallelism=params["parallelism"], hash_len=32,
                           type=Type.ID, version=19)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def build_recovery_kit(*, controller_id: str, destinations: list[dict], repositories: list[dict],
                       instances: list[dict] | None = None, recovery_root_secret: str | None = None,
                       app_version: str = "0.1.0", tool_versions: dict | None = None,
                       controller_recovery_roots: dict[str, str] | None = None) -> dict:
    """Validate and assemble plaintext kit contents (never persisted unencrypted)."""
    by_destination = {}
    for item in destinations:
        destination_id = layout.canonical_uuid(item.get("destination_id", ""), "destination ID")
        backend = item.get("backend")
        providers.validate_destination(backend, item.get("configuration") or {}, item.get("credential"),
                                       destination_id)
        by_destination[destination_id] = {"destination_id": destination_id, "backend": backend,
                                          "name": str(item.get("name") or "")[:120],
                                          "configuration": dict(item.get("configuration") or {}),
                                          "credential": item.get("credential")}
    clean_repositories = []
    for item in repositories:
        destination_id = layout.canonical_uuid(item.get("destination_id", ""), "destination ID")
        instance_id = layout.canonical_uuid(item.get("instance_id", ""), "instance ID")
        purpose = item.get("purpose", "instance")
        if purpose not in {"instance", "controller"}:
            raise VaultRewindError("RECOVERY_KIT_INVALID", "A repository has an invalid recovery purpose or identity.")
        if destination_id not in by_destination:
            raise VaultRewindError("RECOVERY_KIT_INVALID", "Every repository needs its destination in the kit.")
        location, password = item.get("location"), item.get("password")
        destination = by_destination[destination_id]
        RepositoryConfig(location=location, password=password,
                         rclone_config=Path("/nonexistent") if destination["backend"] == "drive" else None,
                         allow_insecure_http=bool(destination["configuration"].get("development_http")))
        restic_id = item.get("restic_repository_id")
        if restic_id is not None and not (isinstance(restic_id, str) and len(restic_id) == 64):
            raise VaultRewindError("RECOVERY_KIT_INVALID", "A restic repository ID is malformed.")
        clean_repositories.append({"repository_id": str(item.get("repository_id") or ""),
                                   "purpose": purpose,
                                   "restic_repository_id": restic_id, "instance_id": instance_id,
                                   "destination_id": destination_id, "location": location, "password": password})
    if recovery_root_secret is not None:
        layout.derive_repository_password(recovery_root_secret, str(uuid.UUID(int=1)), str(uuid.UUID(int=2)))
    historical_roots = {}
    for identity, root in (controller_recovery_roots or {}).items():
        identity = layout.canonical_uuid(identity, "controller ID")
        layout.derive_repository_password(root, identity, str(uuid.UUID(int=2)))
        historical_roots[identity] = root
    used = {d["backend"] for d in by_destination.values()}
    return {
        "kit_schema": KIT_SCHEMA, "kit_id": str(uuid.uuid4()),
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "app_version": app_version, "controller_id": str(controller_id),
        "recovery_root_secret": recovery_root_secret,
        "controller_recovery_roots": historical_roots,
        "destinations": list(by_destination.values()), "repositories": clean_repositories,
        "instances": [{"instance_id": layout.canonical_uuid(i["instance_id"], "instance ID"),
                       "name": str(i.get("name") or "")[:120]} for i in (instances or [])],
        "manifest_schema": MANIFEST_SCHEMA,
        "tool_versions": tool_versions or {"restic": "0.19.1", "rclone": "1.75.2"},
        "recovery_instructions": {"general": GENERAL_INSTRUCTIONS,
                                  **{backend: PROVIDER_INSTRUCTIONS[backend] for backend in sorted(used)}},
    }


def seal_recovery_kit(contents: dict, passphrase: str, *, kdf: dict | None = None) -> bytes:
    check_passphrase(passphrase)
    if not isinstance(contents, dict) or contents.get("kit_schema") != KIT_SCHEMA:
        raise VaultRewindError("RECOVERY_KIT_INVALID", "Recovery kit contents are malformed.")
    params = {**DEFAULT_KDF, **(kdf or {})}
    for key, (low, high) in KDF_BOUNDS.items():
        if not isinstance(params[key], int) or not low <= params[key] <= high:
            raise VaultRewindError("RECOVERY_KIT_INVALID", "Recovery kit key-derivation parameters are out of range.")
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"format": KIT_FORMAT, "version": KIT_VERSION, "notice": NOTICE, "kit_id": contents["kit_id"],
              "created_at": contents["created_at"],
              "kdf": {"name": "argon2id", "version": 19, "salt": _b64e(salt), "hash_len": 32, **params},
              "cipher": {"name": "AES-256-GCM", "nonce": _b64e(nonce)}}
    key = _derive(passphrase, salt, params)
    ciphertext = AESGCM(key).encrypt(nonce, _canonical(contents), _canonical(header))
    return json.dumps({**header, "ciphertext": _b64e(ciphertext)}, indent=1).encode() + b"\n"


def read_kit_header(blob: bytes) -> dict:
    if not isinstance(blob, bytes | bytearray) or len(blob) > MAX_KIT_BYTES:
        raise VaultRewindError("RECOVERY_KIT_INVALID", "This is not a VaultRewind recovery kit.")
    try:
        envelope = json.loads(blob)
    except ValueError as exc:
        raise VaultRewindError("RECOVERY_KIT_INVALID", "This is not a VaultRewind recovery kit.") from exc
    if not isinstance(envelope, dict) or envelope.get("format") != KIT_FORMAT:
        raise VaultRewindError("RECOVERY_KIT_INVALID", "This is not a VaultRewind recovery kit.")
    if envelope.get("version") != KIT_VERSION:
        raise VaultRewindError("RECOVERY_KIT_VERSION_UNSUPPORTED", "This recovery kit needs a newer VaultRewind.")
    return envelope


def open_recovery_kit(blob: bytes, passphrase: str) -> dict:
    envelope = read_kit_header(blob)
    header = {key: value for key, value in envelope.items() if key != "ciphertext"}
    try:
        kdf, cipher = header["kdf"], header["cipher"]
        if kdf.get("name") != "argon2id" or kdf.get("version") != 19 or kdf.get("hash_len") != 32:
            raise ValueError("kdf")
        params = {key: kdf[key] for key in KDF_BOUNDS}
        for key, (low, high) in KDF_BOUNDS.items():
            if not isinstance(params[key], int) or not low <= params[key] <= high:
                raise ValueError("bounds")
        if cipher.get("name") != "AES-256-GCM":
            raise ValueError("cipher")
        salt, nonce, ciphertext = _b64d(kdf["salt"]), _b64d(cipher["nonce"]), _b64d(envelope["ciphertext"])
        if len(salt) < 16 or len(nonce) != 12:
            raise ValueError("lengths")
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultRewindError("RECOVERY_KIT_INVALID", "The recovery kit header is malformed.") from exc
    if not isinstance(passphrase, str) or not passphrase:
        raise VaultRewindError("RECOVERY_KIT_PASSPHRASE_INVALID", "The recovery passphrase is required.")
    try:
        plaintext = AESGCM(_derive(passphrase, salt, params)).decrypt(nonce, ciphertext, _canonical(header))
    except InvalidTag as exc:
        raise VaultRewindError("RECOVERY_KIT_PASSPHRASE_INVALID",
                               "The passphrase is wrong or the recovery kit was modified.") from exc
    contents = json.loads(plaintext)
    if contents.get("kit_schema") != KIT_SCHEMA or contents.get("kit_id") != header.get("kit_id"):
        raise VaultRewindError("RECOVERY_KIT_INVALID", "The recovery kit contents are inconsistent.")
    register_secret(passphrase)
    for repository in contents.get("repositories", []):
        register_secret(repository.get("password"))
    if contents.get("recovery_root_secret"):
        register_secret(contents["recovery_root_secret"])
    for root in (contents.get("controller_recovery_roots") or {}).values():
        register_secret(root)
    return contents


def write_recovery_kit(path: Path, blob: bytes) -> Path:
    """Create a new owner-only kit file; never overwrites an existing file."""
    return write_private_file(Path(path), blob)


def kit_summary(contents: dict) -> dict:
    """A secret-free description for display (`inspect`)."""
    return {
        "kit_id": contents.get("kit_id"), "created_at": contents.get("created_at"),
        "app_version": contents.get("app_version"), "controller_id": contents.get("controller_id"),
        "has_recovery_root_secret": bool(contents.get("recovery_root_secret")),
        "controller_recovery_identities": sorted((contents.get("controller_recovery_roots") or {}).keys()),
        "instances": contents.get("instances", []),
        "destinations": [{"destination_id": d["destination_id"], "backend": d["backend"], "name": d.get("name"),
                          "configuration": providers.validate_destination(d["backend"], d["configuration"], None,
                                                                          d["destination_id"]),
                          "credential_included": d.get("credential") is not None}
                         for d in contents.get("destinations", [])],
        "repositories": [{"instance_id": r["instance_id"], "destination_id": r["destination_id"], "purpose": r.get("purpose", "instance"),
                          "location": r["location"], "restic_repository_id": r.get("restic_repository_id")}
                         for r in contents.get("repositories", [])],
        "tool_versions": contents.get("tool_versions"),
        "recovery_instructions": contents.get("recovery_instructions"),
    }

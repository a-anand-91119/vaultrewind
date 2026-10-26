"""Private destination rotation and configuration editing; no provider I/O.

The caller owns authorization and the transaction. Both entry points return only
explicitly selected public fields; credential and configuration envelopes stay private.
"""
from pathlib import Path, PurePosixPath

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.storage import drive, local, providers, s3

from .db import now, uid
from .models import ControllerState, OAuthState, Repository, ResourceLease, StorageDestination
from .queue import audit, ensure_resource

_FIELDS = {
    "local": {"path", "host_path", "min_free_bytes", "require_dedicated_mount", "allow_unlisted_filesystems"},
    "s3": {"endpoint", "bucket", "prefix", "region", "bucket_lookup", "ca_cert_pem", "development_http"},
    "drive": {"folder_id", "folder_name", "scope"},
}
_ALIASES = {"local": {"root": "path"}, "s3": {"addressing_mode": "bucket_lookup",
            "allow_insecure_local": "development_http"}, "drive": {"root_folder_id": "folder_id"}}


def _invalid():
    raise VaultRewindError("VALIDATION_ERROR", "The destination contains invalid or unsupported settings.")


def _destination(db, ident, *, locked=False):
    query = select(StorageDestination).where(StorageDestination.id == ident,
                                             StorageDestination.archived.is_(False))
    row = db.scalar(query.with_for_update() if locked else query)
    if row is None:
        raise VaultRewindError("NOT_FOUND", "The storage destination does not exist.")
    return row


def _configuration(backend, config, ident):
    """Strict types before provider validators (some older validators coerce booleans)."""
    if not isinstance(config, dict) or set(config) - _FIELDS[backend]:
        _invalid()
    for key, value in config.items():
        if key in {"require_dedicated_mount", "allow_unlisted_filesystems", "development_http"}:
            if type(value) is not bool:
                _invalid()
        elif key == "min_free_bytes":
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                _invalid()
        elif value is not None and (not isinstance(value, str) or any(ord(c) < 32 for c in value)
                                    and key != "ca_cert_pem") or value is None and key not in {"host_path", "ca_cert_pem", "folder_id", "folder_name"}:
            _invalid()
    providers.validate_destination(backend, config, None, ident)
    if backend == "local":
        destination = local.LocalDestination.from_config(config, ident)
        path = str(destination.path)
        if (not destination.path.is_absolute() or ".." in PurePosixPath(path).parts
                or path in local.SYSTEM_DIRECTORIES or len(path) > 1024):
            raise VaultRewindError("STORAGE_PATH_UNSAFE", "Select a dedicated persistent backup directory.")
        return {"path": path, "host_path": destination.host_path,
                "min_free_bytes": destination.min_free_bytes,
                "require_dedicated_mount": destination.require_dedicated_mount,
                "allow_unlisted_filesystems": destination.allow_unlisted_filesystems}
    if backend == "s3":
        destination = s3.S3Destination.from_config(config, ident)
        return {key: getattr(destination, key) for key in _FIELDS[backend]}
    if config.get("folder_name") is not None:
        drive._folder_name(config["folder_name"], ident)
    return {**config, "scope": drive.SCOPE_NAME}


def _public(db, store, destination):
    # upgrade=False also makes inspection of legacy envelopes a genuinely read-only operation.
    private = store.get(db, destination.configuration_secret_id, upgrade=False)
    selected = {key: value for key, value in private.items() if key in _FIELDS[destination.backend]}
    config = _configuration(destination.backend, selected, destination.id)
    if destination.backend == "s3":
        config["custom_ca"] = bool(config.pop("ca_cert_pem"))
    credential = (store.get(db, destination.credential_id, upgrade=False)
                  if destination.credential_id else {})
    keys = {"local": (), "s3": ("access_key_id", "secret_access_key", "session_token"),
            "drive": ("client_id", "client_secret")}[destination.backend]
    flags = {key: bool(credential.get(key)) for key in keys}
    if destination.backend == "drive":
        flags["authorized"] = bool(credential.get("token")) and not bool(
            credential.get("revoked") or credential.get("revoked_at"))
    count = len(list(db.scalars(select(Repository.id).where(Repository.destination_id == destination.id))))
    return {"id": destination.id, "name": destination.name, "backend": destination.backend,
            "health": destination.health, "revision": destination.revision,
            "last_test_at": destination.last_test_at.isoformat() if destination.last_test_at else None,
            "quota_bytes": destination.quota_bytes, "configuration": config,
            "credentials_configured": bool(destination.credential_id), "credential_flags": flags,
            "repository_count": count, "physical_identity_locked": count > 0,
            "recovery_kit_reminder": "Export a current encrypted recovery kit after changing storage access."}


def destination_view(db, store, ident):
    """Administrator detail view. Never tests storage or refreshes OAuth credentials."""
    return _public(db, store, _destination(db, ident))


def _credentials(backend, supplied, config):
    if not isinstance(supplied, dict):
        _invalid()
    allowed = {"local": set(), "s3": {"access_key_id", "secret_access_key", "session_token"},
               "drive": {"client_id", "client_secret"}}[backend]
    if set(supplied) - allowed:
        _invalid()
    # Empty fields always keep the existing pair. A replacement requires a full pair.
    values = {key: value for key, value in supplied.items() if value != "" and value is not None}
    if not values:
        return None
    if backend == "s3":
        s3.S3Credentials.from_dict(values)
        return values  # absent session_token clears the old session token with this new pair
    if backend == "drive":
        client = drive.GoogleClient(values.get("client_id"), values.get("client_secret"))
        return {"type": "google_drive_client", "version": 1, **client.as_dict(), "scope": drive.SCOPE_NAME,
                "folder_id": config.get("folder_id"), "grant_id": uid(), "token": {},
                "revoked": True, "revoked_at": now().isoformat()}
    _invalid()


def _preserve_repositories(db, store, destination, old, proposed, repositories):
    if not repositories:
        return
    identity_fields = {"local": {"path"}, "s3": {"endpoint", "bucket", "prefix"},
                       "drive": {"folder_id", "scope"}}[destination.backend]
    if any(old.get(key) != proposed.get(key) for key in identity_fields):
        raise VaultRewindError("DESTINATION_IDENTITY_CHANGED",
                               "Create a new destination to change physical storage; keep existing copies available.")
    for repo in repositories:
        private = store.get(db, repo.configuration_secret_id, upgrade=False)
        state = db.get(ControllerState, 1) if repo.instance_id is None else None
        owner = repo.instance_id or private.get("controller_id") or (state.controller_id if state else None)
        if not owner:
            raise VaultRewindError("REPOSITORY_IDENTITY_MISMATCH", "The repository owner cannot be verified.")
        before = providers.repository_location(destination.backend, old, owner, destination.id)
        after = providers.repository_location(destination.backend, proposed, owner, destination.id)
        identity = providers.physical_identity(destination.backend, proposed, owner, destination.id)
        if (before != after or identity != repo.physical_identity or private.get("location") != after
                or providers.physical_identity(destination.backend, old, owner, destination.id) != identity):
            raise VaultRewindError("DESTINATION_IDENTITY_CHANGED",
                                   "The existing repository identity must remain unchanged. Create a new destination.")


def update_destination(db, store, settings, ident, changes, revision, actor_id):
    """Validate and atomically edit a destination in the caller's transaction.

    Credential lease precedes destination row locking, matching queue ownership.
    An expired owned lease still requires reconciliation; it is never stolen here.
    """
    if not isinstance(changes, dict) or not changes or set(changes) - {"name", "configuration", "credentials"}:
        _invalid()
    key = f"credential:{ident}"
    ensure_resource(db, key)
    lease = db.scalar(select(ResourceLease).where(ResourceLease.resource_key == key).with_for_update())
    destination = _destination(db, ident, locked=True)
    if type(revision) is not int or revision != destination.revision:
        raise VaultRewindError("REVISION_CONFLICT", "Reload the destination before saving.")
    if lease.owner_job_id is not None:
        raise VaultRewindError("RESOURCE_BUSY", "Reconcile or finish the destination's active operation first.")
    name = changes.get("name", destination.name)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120 or any(ord(c) < 32 for c in name):
        _invalid()
    old_private = store.get(db, destination.configuration_secret_id, upgrade=False)
    old = _configuration(destination.backend, old_private, ident)
    delta = changes.get("configuration", {})
    if not isinstance(delta, dict):
        _invalid()
    delta = dict(delta)
    for alias, canonical in _ALIASES[destination.backend].items():
        if alias in delta:
            if canonical in delta:
                _invalid()
            delta[canonical] = delta.pop(alias)
    proposed = _configuration(destination.backend, {**old, **delta}, ident)
    if destination.backend == "local" and proposed["path"] != old["path"]:
        path = Path(proposed["path"])
        if not path.is_relative_to(settings.local_storage_root):
            raise VaultRewindError("STORAGE_PATH_UNSAFE", "Select the configured persistent backup mount.")
    repositories = list(db.scalars(select(Repository).where(Repository.destination_id == ident).with_for_update()))
    _preserve_repositories(db, store, destination, old, proposed, repositories)
    replacement = _credentials(destination.backend, changes["credentials"], proposed) if "credentials" in changes else None
    config_changed = proposed != old
    if config_changed:
        destination.configuration_secret_id = store.put(db, "destination_configuration", ident, proposed)
    if replacement is not None:
        # A new row ID is the generation fence for stale refreshes and durable pending updates.
        destination.credential_id = store.put(db, "provider_credentials", ident, replacement)
        if destination.backend == "drive":
            # Browser states made for the previous client must not exchange under the new client.
            for pending in db.scalars(select(OAuthState).where(OAuthState.destination_id == ident,
                                                              OAuthState.consumed_at.is_(None))):
                pending.consumed_at = now()
    if config_changed or replacement is not None:
        destination.health = "reauthorization_required" if destination.backend == "drive" and replacement else "untested"
        destination.last_test_at = None
    destination.name = name.strip()
    destination.revision += 1
    fields = (["name"] if "name" in changes else []) + [f"configuration.{key}" for key in sorted(delta)]
    if replacement is not None:
        fields += [f"credentials.{key}" for key in sorted(changes["credentials"])]
    audit(db, actor_id, "storage.update", ident, changes={"fields": fields, "revision": destination.revision})
    db.flush()
    return _public(db, store, destination)

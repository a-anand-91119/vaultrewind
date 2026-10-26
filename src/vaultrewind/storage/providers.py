"""Single entry point used by the worker, API and offline recovery for every backend."""
from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import ensure_private_directory
from vaultrewind.security.secrets import SecretBox

from . import drive, layout, local, s3
from .credentials import CredentialStore
from .restic import RepositoryConfig, ResticRepository

BACKENDS = ("local", "s3", "drive")


def _backend(backend: str) -> str:
    if backend not in BACKENDS:
        raise VaultRewindError("REPOSITORY_BACKEND_UNSUPPORTED", "Unsupported storage destination type.")
    return backend


def _drive_configuration(configuration: dict, *, require_folder: bool = True) -> dict:
    unknown = set(configuration) - {"folder_id", "folder_name", "scope"}
    if unknown:
        raise VaultRewindError("STORAGE_CONFIGURATION", "Unknown Google Drive destination settings were supplied.")
    if configuration.get("scope", drive.SCOPE_NAME) != drive.SCOPE_NAME:
        raise VaultRewindError("STORAGE_CONFIGURATION", "Only the drive.file scope is supported.")
    if not configuration.get("folder_id"):
        if require_folder:
            raise VaultRewindError("STORAGE_AUTHORIZATION_REQUIRED", "Authorize this Google Drive destination first.",
                                   credential_state="authorization_required")
        return configuration
    drive._safe_value(configuration.get("folder_id"), drive._FOLDER_ID, "folder ID")
    return configuration


_UI_ALIASES = {"local": {"root": "path"},
               "s3": {"addressing_mode": "bucket_lookup", "allow_insecure_local": "development_http"},
               "drive": {"root_folder_id": "folder_id"}}


def normalize_destination_input(backend: str, configuration: dict | None, credentials: dict | None
                                ) -> tuple[dict, dict | None]:
    """Canonicalize form input (accepting the UI's legacy field names) into stored configuration/credential."""
    backend = _backend(backend)
    if backend == "local" and configuration is not None and "recovery_mode" in configuration:
        raise VaultRewindError("STORAGE_CONFIGURATION", "Recovery mode is not an operational destination setting.")
    configuration = {k: v for k, v in dict(configuration or {}).items() if v not in (None, "")}
    for alias, canonical in _UI_ALIASES[backend].items():
        if alias in configuration:
            value = configuration.pop(alias)
            configuration.setdefault(canonical, value)
    credential = {k: v for k, v in dict(credentials or {}).items() if v not in (None, "")} or None
    if backend == "drive":
        client_id = configuration.pop("client_id", None)
        if client_id:
            credential = {**(credential or {}), "client_id": client_id}
        if credential and credential.get("type") != "google_drive_oauth":
            client = drive.GoogleClient(credential.get("client_id"), credential.get("client_secret"))
            credential = {"type": "google_drive_client", **client.as_dict()}
    if backend == "local":
        credential = None
    return configuration, credential


def validate_destination(backend: str, configuration: dict, credential: dict | None = None,
                         destination_id: str = "00000000-0000-4000-8000-000000000000") -> dict:
    """Pure validation of the stored configuration (and credential shape); performs no writes."""
    backend = _backend(backend)
    if not isinstance(configuration, dict):
        raise VaultRewindError("STORAGE_CONFIGURATION", "Destination settings are missing.")
    if backend == "local":
        destination = local.LocalDestination.from_config(configuration, destination_id)
        return {"backend": "local", "path": str(destination.path), "host_path": destination.host_path,
                "min_free_bytes": destination.min_free_bytes}
    if backend == "s3":
        destination = s3.S3Destination.from_config(configuration, destination_id)
        if credential is not None:
            s3.S3Credentials.from_dict(credential)
        return {"backend": "s3", **destination.public_view()}
    configuration = _drive_configuration(configuration, require_folder=False)
    if credential is not None:
        drive.GoogleClient(credential.get("client_id"), credential.get("client_secret"))
        if credential.get("type") == "google_drive_oauth":
            drive.validate_token(credential.get("token"))
    return {"backend": "drive", "folder_id": configuration.get("folder_id"),
            "folder_name": configuration.get("folder_name"), "scope": drive.SCOPE_NAME,
            "authorization_required": not configuration.get("folder_id")}


def repository_location(backend: str, configuration: dict, instance_id: str, destination_id: str) -> str:
    backend = _backend(backend)
    if backend == "local":
        return local.local_repository_location(local.LocalDestination.from_config(configuration, destination_id),
                                               instance_id)
    if backend == "s3":
        return s3.S3Destination.from_config(configuration, destination_id).repository_location(instance_id)
    _drive_configuration(configuration)
    return drive.drive_location(instance_id, destination_id)


def physical_identity(backend: str, configuration: dict, instance_id: str, destination_id: str) -> str:
    """Stable identity of the physical repository; Drive includes the folder ID since the path is relative."""
    identity = {"backend": backend, "location": repository_location(backend, configuration, instance_id,
                                                                     destination_id)}
    if backend == "drive":
        identity["folder_id"] = configuration["folder_id"]
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def _inside(location: str | None, prefix: str, default: str) -> str:
    if location is None:
        return default
    if not isinstance(location, str) or not location.startswith(prefix) or ".." in location.split("/"):
        raise VaultRewindError("REPOSITORY_LOCATION_INVALID",
                               "The recorded repository location is outside its destination.")
    return location


@contextlib.contextmanager
def open_repository(backend: str, configuration: dict, credential: dict | None, *, instance_id: str,
                    destination_id: str, password: str, work_dir: Path, repository_id: str | None = None,
                    credential_store: CredentialStore | None = None, box: SecretBox | None = None,
                    cancel_event=None, protected_paths=(), required_bytes: int = 0,
                    mountinfo_text: str | None = None, location: str | None = None) -> Iterator[ResticRepository]:
    """Yield a ready ``ResticRepository``; provider sessions (Drive tokens) are finalized on exit.

    ``location`` opens an exact recorded repository location (recovery/import); it must lie inside the
    destination (local base path, S3 bucket/prefix, or the Drive remote) or it is rejected.
    """
    backend = _backend(backend)
    instance_id = layout.canonical_uuid(instance_id, "instance ID")
    destination_id = layout.canonical_uuid(destination_id, "destination ID")
    work_dir = ensure_private_directory(Path(work_dir))
    cache = work_dir / "cache" / "restic"
    runtime = work_dir / "runtime"
    if backend == "local":
        destination = local.LocalDestination.from_config(configuration, destination_id)
        local.inspect_local_destination(destination, protected_paths=(*protected_paths, work_dir),
                                        required_bytes=required_bytes, mountinfo_text=mountinfo_text)
        config = RepositoryConfig(location=_inside(location, str(destination.path) + "/",
                                                   local.local_repository_location(destination, instance_id)),
                                  password=password, cache_dir=cache, instance_uuid=instance_id,
                                  expected_repository_id=repository_id, runtime_dir=runtime)
        yield ResticRepository(config, cancel_event=cancel_event)
    elif backend == "s3":
        destination = s3.S3Destination.from_config(configuration, destination_id)
        credentials = s3.S3Credentials.from_dict(credential)
        prefix = f"s3:{destination.endpoint}/{destination.bucket}/" + (destination.prefix + "/" if destination.prefix
                                                                         else "")
        config = RepositoryConfig(location=_inside(location, prefix, destination.repository_location(instance_id)),
                                  password=password,
                                  environment=credentials.environment(destination.region), cache_dir=cache,
                                  instance_uuid=instance_id, expected_repository_id=repository_id,
                                  ca_cert_pem=destination.ca_cert_pem, options=destination.restic_options(),
                                  runtime_dir=runtime, allow_insecure_http=destination.development_http)
        yield ResticRepository(config, cancel_event=cancel_event)
    else:
        if credential_store is None or box is None:
            raise VaultRewindError("STORAGE_CONFIGURATION", "Drive repositories need the credential store and key.")
        with drive.drive_repository(destination_id, _drive_configuration(configuration), instance_id=instance_id,
                                    password=password, store=credential_store, box=box, work_dir=work_dir,
                                    repository_id=repository_id, cancel_event=cancel_event,
                                    location=_inside(location, f"rclone:{drive.REMOTE}:",
                                                     drive.drive_location(instance_id, destination_id))) as repository:
            yield repository


def test_destination(backend: str, configuration: dict, credential: dict | None, *, destination_id: str,
                     work_dir: Path, credential_store: CredentialStore | None = None, box: SecretBox | None = None,
                     protected_paths=(), mountinfo_text: str | None = None) -> dict:
    """User-requested connection test. WRITES one probe object and, for Drive, may refresh and save tokens."""
    backend = _backend(backend)
    destination_id = layout.canonical_uuid(destination_id, "destination ID")
    work_dir = ensure_private_directory(Path(work_dir))
    if backend == "local":
        destination = local.LocalDestination.from_config(configuration, destination_id)
        local.initialize_local_destination(destination, protected_paths=(*protected_paths, work_dir),
                                           mountinfo_text=mountinfo_text)
        result = local.probe_local(destination, protected_paths=(*protected_paths, work_dir),
                                   mountinfo_text=mountinfo_text)
        result.update(backup_ready=all(result["probe"].values()), retention_ready=result["probe"]["delete"])
    elif backend == "s3":
        result = s3.probe_s3(s3.S3Destination.from_config(configuration, destination_id),
                             s3.S3Credentials.from_dict(credential), runtime_dir=work_dir / "runtime")
    else:
        if credential_store is None or box is None:
            raise VaultRewindError("STORAGE_CONFIGURATION", "Drive tests need the credential store and key.")
        configuration = _drive_configuration(configuration)
        with drive.DriveCredentialSession(destination_id, credential_store, box,
                                          folder_id=configuration["folder_id"], lock_dir=work_dir / "locks",
                                          runtime_dir=work_dir / "runtime") as session:
            result = drive.probe_drive(session)
        result["token_refresh"] = dict(session.outcome)
    result["destination_id"] = destination_id
    return result


def list_repositories(backend: str, configuration: dict, credential: dict | None, *, destination_id: str,
                      work_dir: Path, credential_store: CredentialStore | None = None,
                      box: SecretBox | None = None) -> list[dict]:
    """Enumerate repositories present at a destination (offline recovery / import)."""
    backend = _backend(backend)
    work_dir = ensure_private_directory(Path(work_dir))
    if backend == "local":
        return local.list_local_repositories(local.LocalDestination.from_config(configuration, destination_id))
    if backend == "s3":
        return s3.list_s3_repositories(s3.S3Destination.from_config(configuration, destination_id),
                                       s3.S3Credentials.from_dict(credential), runtime_dir=work_dir / "runtime")
    configuration = _drive_configuration(configuration)
    with drive.DriveCredentialSession(destination_id, credential_store, box, folder_id=configuration["folder_id"],
                                      lock_dir=work_dir / "locks", runtime_dir=work_dir / "runtime") as session:
        return drive.list_drive_repositories(session)


@contextlib.contextmanager
def open_recovery_repository(backend: str, configuration: dict, credential: dict | None, *, instance_id: str,
                             destination_id: str, password: str, work_dir: Path,
                             repository_id: str | None = None, credential_store: CredentialStore | None = None,
                             box: SecretBox | None = None, location: str | None = None,
                             mountinfo_text: str | None = None, **kwargs) -> Iterator[ResticRepository]:
    """Offline read-only recovery. Local old copies need no new-backup durability evidence.

    Reads use restic's --no-lock so a read-only old disk is supported. Credential refreshes for
    cloud providers are still durably persisted. This capability can never commit a safety copy.
    """
    backend = _backend(backend)
    if backend != "local":
        with open_repository(backend, configuration, credential, instance_id=instance_id,
                             destination_id=destination_id, password=password, work_dir=work_dir,
                             repository_id=repository_id, credential_store=credential_store, box=box,
                             location=location, **kwargs) as repo:
            repo.config.read_only = True
            yield repo
        return
    parsed = local.LocalDestination.from_config(configuration, destination_id)
    destination = local.LocalRecoveryDestination.from_path(parsed.path, destination_id)
    instance_id = layout.canonical_uuid(instance_id, "instance ID")
    work_dir = ensure_private_directory(Path(work_dir))
    local.inspect_local_destination(destination, protected_paths=(work_dir, *kwargs.get("protected_paths", ())),
                                    mountinfo_text=mountinfo_text)
    config = RepositoryConfig(location=_inside(location, str(destination.path) + "/",
                                               local.local_repository_location(destination, instance_id)),
                              password=password, instance_uuid=instance_id, expected_repository_id=repository_id,
                              cache_dir=work_dir / "cache" / "restic", runtime_dir=work_dir / "runtime", read_only=True)
    yield ResticRepository(config, cancel_event=kwargs.get("cancel_event"))


def list_recovery_repositories(backend: str, configuration: dict, credential: dict | None, *, destination_id: str,
                               work_dir: Path, credential_store: CredentialStore | None = None,
                               box: SecretBox | None = None, mountinfo_text: str | None = None) -> list[dict]:
    """Explicit offline discovery, preserving identity checks on re-mounted local copies."""
    if _backend(backend) == "local":
        parsed = local.LocalDestination.from_config(configuration, destination_id)
        destination = local.LocalRecoveryDestination.from_path(parsed.path, destination_id)
        local.inspect_local_destination(destination, protected_paths=(work_dir,), mountinfo_text=mountinfo_text)
        return local.list_local_repositories(destination)
    return list_repositories(backend, configuration, credential, destination_id=destination_id, work_dir=work_dir,
                             credential_store=credential_store, box=box)

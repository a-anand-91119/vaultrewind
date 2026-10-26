"""Offline disaster recovery: works with only the recovery kit, storage access and restic/rclone.

No controller database, master key or running controller is used.  Discovery is
read-only apart from restic's own lock files; imports are planned in protected
mode (automatic retention disabled, every snapshot pinned for review); restores
go to an empty local directory and are verified against manifest and repository;
the target plan is advisory and is applied only through the helper protocol.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.core.manifest import canonical_json, manifest_hash, sha256_file, verify_snapshot
from vaultrewind.security.privatefiles import ensure_private_directory
from vaultrewind.storage import layout, providers
from vaultrewind.storage.credentials import credential_context, open_recovery_credentials
from vaultrewind.storage.restic import parse_utc, utc_iso

FUTURE_TOLERANCE = timedelta(minutes=5)
BACKEND_PREFERENCE = {"local": 0, "s3": 1, "drive": 2}
_SENSITIVE_ENV = re.compile(r"TOKEN|SECRET|PASSW|PRIVATE|CREDENTIAL|(^|_)S?KEY$|DATABASE_URL|_AUTH$|SMTP_USERNAME",
                            re.IGNORECASE)


@dataclass
class OfflineSession:
    kit: dict
    work_dir: Path
    credential_overrides: dict = field(default_factory=dict)
    local_paths: dict = field(default_factory=dict)

    def __post_init__(self):
        self.work_dir = ensure_private_directory(Path(self.work_dir))
        self.box, self.store = open_recovery_credentials(self.work_dir)
        self.destinations = {d["destination_id"]: d for d in self.kit.get("destinations", [])}
        for destination_id, destination in self.destinations.items():
            credential = self.credential(destination)
            if destination["backend"] == "drive" and credential:
                stored = self.store.load(destination_id)
                override = destination_id in self.credential_overrides
                fingerprint = hashlib.sha256(canonical_json(credential)).hexdigest()
                # Reopening the same kit must retain refreshed tokens, rather than overwriting
                # them with the older token embedded in the kit. An explicit new grant may replace it.
                if stored is not None:
                    previous = self.box.decrypt(stored.envelope, context=credential_context(destination_id))
                    if override and previous.get("_recovery_override_fingerprint") == fingerprint:
                        continue
                    # The work directory is authoritative after its first seed.
                    # Grant IDs cannot order tokens; replacement must be explicit.
                    if not override:
                        continue
                credential = {**credential, "grant_id": str(uuid.uuid4()) if override else credential.get("grant_id") or str(uuid.uuid4())}
                if override:
                    credential["_recovery_override_fingerprint"] = fingerprint
                self.store.compare_and_swap(destination_id, self.box.encrypt(
                    credential, context=credential_context(destination_id)), stored.revision if stored else None,
                    expected_generation=stored.generation if stored else None)

    def credential(self, destination: dict) -> dict | None:
        override = self.credential_overrides.get(destination["destination_id"])
        base = destination.get("credential")
        if override is None:
            return base
        if not isinstance(override, dict):
            raise VaultRewindError("RECOVERY_OVERRIDE_INVALID", "Credential overrides must be JSON objects.")
        return {**(base or {}), **override}

    def configuration(self, destination: dict) -> dict:
        configuration = dict(destination.get("configuration") or {})
        if destination["backend"] == "local":
            override = self.local_paths.get(destination["destination_id"])
            if override:
                configuration["path"] = str(override)
            configuration.pop("host_path", None)
            configuration.pop("recovery_mode", None)  # legacy kits never enable an operational bypass
        return configuration

    def open(self, destination: dict, candidate: dict):
        return providers.open_recovery_repository(
            destination["backend"], self.configuration(destination), self.credential(destination),
            instance_id=candidate["instance_id"], destination_id=destination["destination_id"],
            password=candidate["password"], work_dir=self.work_dir,
            repository_id=candidate.get("restic_repository_id"), credential_store=self.store, box=self.box,
            location=candidate["location"])


def _candidates(session: OfflineSession, destination: dict) -> tuple[list[dict], str | None]:
    destination_id = destination["destination_id"]
    original = str((destination.get("configuration") or {}).get("path") or "")
    current = str(session.configuration(destination).get("path") or "")

    def relocated(location: str) -> str:
        if destination["backend"] == "local" and original and current != original and \
                location.startswith(original.rstrip("/") + "/"):
            return current.rstrip("/") + location[len(original.rstrip("/")):]
        return location

    known = {}
    for repository in session.kit.get("repositories", []):
        if repository["destination_id"] == destination_id:
            location = relocated(repository["location"])
            known[location] = {**repository, "location": location, "password_source": "kit"}
    error = None
    try:
        found = providers.list_recovery_repositories(destination["backend"], session.configuration(destination),
                                            session.credential(destination), destination_id=destination_id,
                                            work_dir=session.work_dir, credential_store=session.store,
                                            box=session.box)
    except VaultRewindError as exc:
        found, error = [], exc.code
    root = session.kit.get("recovery_root_secret")
    for item in found:
        if item["location"] in known or item["destination_id"] != destination_id:
            continue
        candidate = {"instance_id": item["instance_id"], "destination_id": destination_id,
                     "purpose": "controller" if item["instance_id"] == session.kit.get("controller_id") else "instance",
                     "location": item["location"], "restic_repository_id": None, "password": None,
                     "password_source": "unavailable"}
        if root:
            candidate["password"] = layout.derive_repository_password(root, item["instance_id"], destination_id)
            candidate["password_source"] = "derived"
        known[item["location"]] = candidate
    return list(known.values()), error


def _snapshot_view(entry: dict, manifest: dict | None, now: datetime) -> dict:
    view = {"restic_snapshot_id": entry["restic_snapshot_id"], "managed": entry["managed"],
            "snapshot_uuid": entry["snapshot_uuid"], "instance_uuid": entry["instance_uuid"],
            "kind": entry["kind"] or "backup", "time": entry["time"], "manifest_hash": entry["manifest_hash"],
            "manifest_verified": False}
    if manifest is not None:
        digest = manifest_hash(manifest)
        consistent = (digest == entry["manifest_hash"] and manifest.get("snapshot_uuid") == entry["snapshot_uuid"]
                      and manifest.get("instance_uuid") == entry["instance_uuid"])
        view.update(manifest_hash=digest, manifest_verified=consistent,
                    captured_at=manifest.get("captured_at"), capture_started_at=manifest.get("capture_started_at"),
                    vaultwarden_version=manifest.get("vaultwarden_version"), image_id=manifest.get("image_id"),
                    platform=manifest.get("platform"), source_state=manifest.get("source_state"),
                    logical_bytes=sum(int(i.get("size") or 0) for i in manifest.get("inventory", [])
                                      if i.get("type") == "file"))
    reference = view.get("captured_at") or entry["time"]
    try:
        view["future_dated"] = parse_utc(reference) > now + FUTURE_TOLERANCE
    except VaultRewindError:
        view["future_dated"] = True  # unknown capture time is protected for review
    return view


def discover(kit: dict, *, work_dir: Path, credential_overrides: dict | None = None, local_paths: dict | None = None,
             read_manifests: bool = True, now: datetime | None = None) -> dict:
    """List repositories and snapshots reachable with the kit. Never deletes or modifies snapshots."""
    now = now or datetime.now(UTC)
    session = OfflineSession(kit, Path(work_dir), credential_overrides or {}, local_paths or {})
    destinations = []
    for destination in session.destinations.values():
        candidates, listing_error = _candidates(session, destination)
        repositories = []
        for candidate in candidates:
            record = {"instance_id": candidate["instance_id"], "location": candidate["location"],
                      "purpose": candidate.get("purpose", "instance"),
                      "restic_repository_id": candidate.get("restic_repository_id"),
                      "password_source": candidate["password_source"], "status": "ok", "error_code": None,
                      "snapshots": []}
            if not candidate.get("password"):
                record.update(status="locked", error_code="REPOSITORY_SECRET_UNAVAILABLE")
                repositories.append(record)
                continue
            try:
                with session.open(destination, candidate) as repository:
                    record["restic_repository_id"] = repository.describe()["repository_id"]
                    if record["purpose"] == "controller":
                        from vaultrewind.storage.controller import list_controller_snapshots
                        record["controller_snapshots"] = list_controller_snapshots(repository,
                            controller_id=candidate["instance_id"], destination_id=destination["destination_id"])
                        repositories.append(record)
                        continue
                    for entry in repository.list_snapshots():
                        manifest = None
                        if read_manifests and entry["managed"]:
                            try:
                                manifest = repository.read_manifest(entry["restic_snapshot_id"])
                            except VaultRewindError:
                                manifest = None
                        record["snapshots"].append(_snapshot_view(entry, manifest, now))
            except VaultRewindError as exc:
                record.update(status="error", error_code=exc.code)
            repositories.append(record)
        destinations.append({"destination_id": destination["destination_id"], "backend": destination["backend"],
                             "name": destination.get("name"), "listing_error_code": listing_error,
                             "repositories": repositories})
    return {"kit_id": kit.get("kit_id"), "discovered_at": utc_iso(now), "destinations": destinations}


def import_plan(discovery: dict, kit: dict) -> dict:
    """Protected-mode import plan for a fresh controller. Contains no secrets."""
    names = {i["instance_id"]: i.get("name") for i in kit.get("instances", [])}
    by_uuid: dict[str, dict] = {}
    conflicts, repositories, errors = [], [], []
    for destination in discovery["destinations"]:
        if destination.get("listing_error_code"):
            errors.append({"destination_id": destination["destination_id"],
                           "error_code": destination["listing_error_code"]})
        for repository in destination["repositories"]:
            if repository["status"] != "ok":
                errors.append({"destination_id": destination["destination_id"], "location": repository["location"],
                               "error_code": repository["error_code"]})
                continue
            repositories.append({"destination_id": destination["destination_id"], "backend": destination["backend"],
                                 "purpose": repository.get("purpose", "instance"),
                                 "instance_id": repository["instance_id"], "location": repository["location"],
                                 "restic_repository_id": repository["restic_repository_id"],
                                 "password_source": repository["password_source"]})
            for snapshot in repository["snapshots"]:
                if not snapshot["managed"] or snapshot["instance_uuid"] != repository["instance_id"]:
                    continue
                copy = {"destination_id": destination["destination_id"], "backend": destination["backend"],
                        "location": repository["location"], "restic_snapshot_id": snapshot["restic_snapshot_id"],
                        "manifest_verified": snapshot["manifest_verified"]}
                existing = by_uuid.get(snapshot["snapshot_uuid"])
                if existing is None:
                    protections = ["imported_review"] + (["safety"] if snapshot["kind"] == "safety" else [])
                    if snapshot.get("future_dated"):
                        protections.append("future_dated_review")
                    by_uuid[snapshot["snapshot_uuid"]] = {
                        "snapshot_uuid": snapshot["snapshot_uuid"], "instance_id": snapshot["instance_uuid"],
                        "kind": snapshot["kind"], "captured_at": snapshot.get("captured_at") or snapshot["time"],
                        "manifest_hash": snapshot["manifest_hash"], "logical_bytes": snapshot.get("logical_bytes"),
                        "future_dated": snapshot.get("future_dated", False), "protections": protections,
                        "copies": [copy], "conflict": False}
                elif existing["manifest_hash"] != snapshot["manifest_hash"]:
                    existing["conflict"] = True
                    conflicts.append({"snapshot_uuid": snapshot["snapshot_uuid"], "copies": [*existing["copies"], copy],
                                      "reason": "same snapshot UUID with different manifest hashes"})
                    existing["copies"].append(copy)
                else:
                    existing["copies"].append(copy)
    instances = sorted({r["instance_id"] for r in repositories if r.get("purpose") != "controller"} | set(names))
    return {
        "plan_version": 1, "mode": "protected", "kit_id": kit.get("kit_id"),
        "retention": {"automatic_deletion_enabled": False,
                      "reason": "Imported repositories stay frozen until the owner reviews policies and pins."},
        "deletions": [], "instances": [{"instance_id": i, "name": names.get(i)} for i in instances],
        "destinations": [{"destination_id": d["destination_id"], "backend": d["backend"], "name": d.get("name"),
                          "configuration": providers.validate_destination(d["backend"], d["configuration"], None,
                                                                          d["destination_id"]),
                          "credential_included": d.get("credential") is not None}
                         for d in kit.get("destinations", [])],
        "repositories": repositories,
        "snapshots": sorted(by_uuid.values(), key=lambda s: (s["instance_id"], s["captured_at"] or "")),
        "conflicts": conflicts, "errors": errors,
        "notes": ["Missing catalog rows never imply deletion of repository snapshots.",
                  "Future-dated snapshots are protected and do not advance retention cutoffs."],
    }


def restore_snapshot(kit: dict, snapshot_uuid: str, target: Path, *, work_dir: Path,
                     credential_overrides: dict | None = None, local_paths: dict | None = None,
                     destination_id: str | None = None) -> dict:
    """Restore one logical snapshot to an empty directory, falling back only to equivalent copies."""
    snapshot_uuid = layout.canonical_uuid(snapshot_uuid, "snapshot UUID")
    target = Path(target)
    if target.exists() and (not target.is_dir() or target.is_symlink() or any(target.iterdir())):
        raise VaultRewindError("RESTORE_TARGET_NOT_EMPTY", "Restore into a new or empty directory.")
    session = OfflineSession(kit, Path(work_dir), credential_overrides or {}, local_paths or {})
    destinations = sorted(session.destinations.values(), key=lambda d: BACKEND_PREFERENCE.get(d["backend"], 9))
    if destination_id:
        destinations = [d for d in destinations if d["destination_id"] == destination_id]
    attempts, expected_hash = [], None
    for destination in destinations:
        candidates, _ = _candidates(session, destination)
        for candidate in candidates:
            if not candidate.get("password"):
                continue
            try:
                with session.open(destination, candidate) as repository:
                    matches = repository.find_snapshots(snapshot_uuid)
                    for entry in matches:
                        if expected_hash and entry["manifest_hash"] != expected_hash:
                            attempts.append({"destination_id": destination["destination_id"],
                                             "error_code": "SNAPSHOT_COPY_NOT_EQUIVALENT"})
                            continue
                        try:
                            evidence = repository.restore(entry["restic_snapshot_id"], target,
                                                          expected_manifest_hash=entry["manifest_hash"])
                        except VaultRewindError as exc:
                            attempts.append({"destination_id": destination["destination_id"], "error_code": exc.code})
                            expected_hash = expected_hash or entry["manifest_hash"]
                            _empty(target)
                            continue
                        manifest = json.loads((target / "manifest" / "manifest.json").read_bytes())
                        return {"snapshot_uuid": snapshot_uuid, "instance_uuid": evidence["instance_uuid"],
                                "manifest_hash": evidence["manifest_hash"], "captured_at": manifest.get("captured_at"),
                                "kind": entry["kind"] or "backup",
                                "source": {"destination_id": destination["destination_id"],
                                           "backend": destination["backend"],
                                           "restic_snapshot_id": entry["restic_snapshot_id"]},
                                "verification": evidence, "attempts": attempts}
            except VaultRewindError as exc:
                attempts.append({"destination_id": destination["destination_id"], "error_code": exc.code})
    raise VaultRewindError("SNAPSHOT_COPY_UNAVAILABLE", "No verified copy of this snapshot could be restored.",
                           attempts=attempts)


def _empty(target: Path) -> None:
    """Remove a failed attempt's partial files from our own private staging directory."""
    if target.is_dir() and not target.is_symlink():
        for child in target.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()


def _environment_view(descriptor: dict) -> tuple[list[dict], dict]:
    values, view = {}, []
    for entry in (descriptor.get("config") or {}).get("Env") or []:
        if not isinstance(entry, str) or "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        values[key] = value
        sensitive = bool(_SENSITIVE_ENV.search(key))
        view.append({"name": key, "value": "[REDACTED]" if sensitive else value, "sensitive": sensitive})
    return sorted(view, key=lambda item: item["name"]), values


def build_target_plan(restored_root: Path, *, target_profile: dict | None = None, kit: dict | None = None,
                      same_instance: bool = False) -> dict:
    """Validate a restored snapshot and describe the supported recovery deployment. Never executes anything."""
    root = Path(restored_root)
    evidence = verify_snapshot(root)
    manifest = evidence["manifest"]
    blocking, notes = [], []
    descriptor_path = root / "deployment" / "recovery.json"
    try:
        descriptor = json.loads(descriptor_path.read_bytes())
    except (OSError, ValueError):
        descriptor = None
        blocking.append({"code": "DEPLOYMENT_DESCRIPTOR_MISSING",
                         "message": "The snapshot has no normalized recovery descriptor."})
    fingerprint_ok = bool(descriptor) and (hashlib.sha256(canonical_json(descriptor)).hexdigest()
                                          == manifest.get("deployment_fingerprint"))
    if descriptor and not fingerprint_ok:
        blocking.append({"code": "DEPLOYMENT_UNSAFE",
                         "message": "The recovery descriptor differs from the manifest's deployment fingerprint."})
    image_path = root / "images" / "vaultwarden.tar"
    image_hash_ok = image_path.is_file() and sha256_file(image_path) == manifest.get("image_archive_hash")
    if not image_hash_ok:
        blocking.append({"code": "IMAGE_MISMATCH", "message": "The saved image archive is missing or differs from the manifest."})
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    recorded_platform = manifest.get("platform") or (descriptor or {}).get("platform")
    descriptor = descriptor or {}
    environment, env_values = _environment_view(descriptor)
    host = descriptor.get("host_config") or {}
    profile = target_profile or {}
    unknown = set(profile) - {"public_url", "network", "port_bindings", "target_name"}
    if unknown:
        raise VaultRewindError("TARGET_PROFILE_INVALID", "Unsupported target profile settings.")
    substitutions = []
    source_domain = env_values.get("DOMAIN")
    if profile.get("public_url"):
        substitutions.append({"setting": "DOMAIN", "from": source_domain, "to": profile["public_url"]})
    elif not same_instance:
        blocking.append({"code": "TARGET_PROFILE_REQUIRED",
                         "message": "Restoring to another server requires an explicit public URL for the target."})
    if profile.get("network"):
        substitutions.append({"setting": "network", "from": host.get("NetworkMode"), "to": profile["network"]})
    if profile.get("port_bindings") is not None:
        substitutions.append({"setting": "port_bindings", "from": host.get("PortBindings"),
                              "to": profile["port_bindings"]})
    dependencies = descriptor.get("dependencies") or manifest.get("dependency_inventory") or []
    if dependencies:
        notes.append("External prerequisites must be ready on the target before activation (see external_dependencies).")
    plan = {
        "plan_version": 1, "generated_at": utc_iso(), "executes_nothing": True,
        "snapshot": {key: manifest.get(key) for key in ("snapshot_uuid", "instance_uuid", "captured_at",
                                                          "capture_started_at", "source_state", "vaultwarden_version",
                                                          "image_id", "registry_digest", "image_archive_hash",
                                                          "platform", "app_version", "helper_version")},
        "validation": {"inventory_verified": evidence["inventory_verified"], "members": evidence["members"],
                       "logical_bytes": evidence["logical_bytes"], "manifest_hash": evidence["manifest_hash"],
                       "descriptor_fingerprint_matches": fingerprint_ok, "image_archive_hash_matches": image_hash_ok,
                       "database": {k: v for k, v in evidence.items() if k.startswith(("sqlite", "integrity",
                                                                                         "database"))}},
        "image": {"archive": "images/vaultwarden.tar", "image_id": manifest.get("image_id"),
                  "registry_digest": manifest.get("registry_digest"), "platform": recorded_platform,
                  "recovery_machine_architecture": f"linux/{machine}",
                  "note": "Load and verify this exact image ID on the target; do not pull a newer tag."},
        "deployment": {"environment": environment, "network_mode": host.get("NetworkMode"),
                       "port_bindings": host.get("PortBindings"), "restart_policy": host.get("RestartPolicy"),
                       "mounts": descriptor.get("mounts", []),
                       "user": (descriptor.get("config") or {}).get("User"),
                       "healthcheck_defined": bool((descriptor.get("config") or {}).get("Healthcheck"))},
        "substitutions": substitutions, "external_dependencies": dependencies,
        "blocking_issues": blocking, "ready": not blocking, "notes": notes,
        "preconditions": [
            f"The target host runs Linux with Docker and systemd on {recorded_platform}.",
            ("The target is enrolled in VaultRewind with the helper activated, its fingerprint verified and its "
            "recovery profile (public URL, network, ports, data paths) approved."),
            "Alternate targets must be proven empty; replacing an existing instance creates a pinned safety snapshot.",
            "Reverse proxy, TLS certificates, DNS and SMTP prerequisites listed above are available.",
        ],
        "apply_procedure": [
            "Install a fresh VaultRewind controller and import this recovery kit (protected mode).",
            "Enroll or select the prepared target host and complete helper activation.",
            ("Choose the snapshot and run 'Restore to another server' (or restore to the original instance); the "
            "helper stages, validates the candidate in isolation and activates only after validation."),
            "Update DNS or proxy routes yourself after the restored instance is verified; VaultRewind never does so.",
        ],
        "refused_actions": [
            "Overwriting live instance files outside the helper's journaled generation switch.",
            "Starting the captured container with public ports before isolated validation.",
            "Pulling or upgrading the Vaultwarden image during recovery.",
        ],
    }
    if kit:
        backends = {d["backend"] for d in kit.get("destinations", [])}
        plan["provider_recovery"] = {b: (kit.get("recovery_instructions") or {}).get(b, []) for b in sorted(backends)}
    return plan

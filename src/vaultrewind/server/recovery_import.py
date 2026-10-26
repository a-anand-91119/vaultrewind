"""Protected-mode import of recovered repositories into a (possibly fresh) controller catalog (spec section 21).

The ``recovery_import`` job opens the owner-held kit, discovers repositories/snapshots with the independent
offline tooling and stores two private records: the secret-free *plan* and the *materials* the import needs
(destination configuration/credentials, repository passwords, recovery root). ``apply_import_plan`` turns them
into catalog rows and never deletes, restores or schedules anything:

* destinations keep their kit UUIDs; credentials are stored encrypted; health is ``imported``;
* repositories are created ``imported=True`` with health ``imported`` (a retention freeze reason);
* unknown instances become placeholder registrations (no host, readiness ``imported``, policy disabled,
  retention forever). Enrolling the same remote instance UUID later binds the placeholder to its host;
* each snapshot/copy receives an ``import_review`` protection, plus ``safety`` or ``future_dated_review``.

Same-UUID/different-manifest conflicts, listing errors and unverifiable copies are reported, not resolved.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .db import now, uid, utc
from .models import (
    BackupPolicy,
    Instance,
    Repository,
    Snapshot,
    SnapshotCopy,
    SnapshotProtection,
    StorageDestination,
)
from .queue import audit, digest

PLACEHOLDER_READINESS = "imported"


def discover_and_plan(kit: dict, work_dir: Path) -> tuple[dict, dict]:
    """Run offline discovery, build the protected plan and keep per-snapshot manifest facts for the catalog."""
    from vaultrewind.recovery.offline import discover, import_plan
    discovery = discover(kit, work_dir=Path(work_dir), read_manifests=True)
    plan = import_plan(discovery, kit)
    facts: dict[str, dict] = {}
    for destination in discovery.get("destinations", []):
        for repository in destination.get("repositories", []):
            for snapshot in repository.get("snapshots", []):
                if not snapshot.get("managed") or not snapshot.get("manifest_verified"):
                    continue
                facts.setdefault(snapshot["snapshot_uuid"], {
                    key: snapshot.get(key) for key in ("image_id", "vaultwarden_version", "source_state",
                                                       "capture_started_at", "captured_at", "logical_bytes")})
    plan["manifest_facts"] = facts
    return discovery, plan


def private_materials(kit: dict, *, work_dir: Path | None = None) -> dict:
    # Discovery can rotate a Drive refresh token. Transfer the final encrypted file-store
    # value into durable SQL import material before the import job's workspace is cleaned.
    refreshed = {}
    if work_dir is not None:
        from vaultrewind.recovery.offline import OfflineSession
        from vaultrewind.storage.credentials import credential_context
        session = OfflineSession(kit, work_dir)
        for destination in session.destinations.values():
            if destination["backend"] == "drive":
                stored = session.store.load(destination["destination_id"])
                if stored:
                    refreshed[destination["destination_id"]] = session.box.decrypt(
                        stored.envelope, context=credential_context(destination["destination_id"]))
    return {"destinations": [{"destination_id": d["destination_id"], "backend": d["backend"],
                              "name": d.get("name") or d["backend"], "configuration": d.get("configuration") or {},
                              "credential": refreshed.get(d["destination_id"], d.get("credential"))} for d in kit.get("destinations", [])],
            "repositories": [{key: r.get(key) for key in ("repository_id", "restic_repository_id", "instance_id",
                                                           "destination_id", "location", "password", "purpose")}
                             for r in kit.get("repositories", [])],
            "recovery_root_secret": kit.get("recovery_root_secret"),
            "controller_id": kit.get("controller_id"),
            "controller_recovery_roots": kit.get("controller_recovery_roots") or {},
            "instances": [{"instance_id": i["instance_id"], "name": i.get("name")} for i in kit.get("instances", [])]}


def summarize_plan(plan: dict) -> dict:
    """Sanitized summary for job results and the review endpoint: counts, identities and codes only."""
    snapshots = plan.get("snapshots", [])
    return {"mode": plan.get("mode", "protected"), "plan_version": plan.get("plan_version"),
            "automatic_deletion_enabled": bool(plan.get("retention", {}).get("automatic_deletion_enabled")),
            "destinations": [{"destination_id": d["destination_id"], "backend": d["backend"], "name": d.get("name"),
                              "credential_included": bool(d.get("credential_included"))}
                             for d in plan.get("destinations", [])],
            "instances": [{"instance_id": i["instance_id"], "name": i.get("name")} for i in plan.get("instances", [])],
            "repositories": len(plan.get("repositories", [])), "snapshots": len(snapshots),
            "verified_copies": sum(1 for s in snapshots for c in s.get("copies", []) if c.get("manifest_verified")),
            "unverified_copies": sum(1 for s in snapshots for c in s.get("copies", []) if not c.get("manifest_verified")),
            "future_dated": sum(1 for s in snapshots if s.get("future_dated")),
            "conflicts": len(plan.get("conflicts", [])),
            "errors": [{"destination_id": e.get("destination_id"), "error_code": e.get("error_code")}
                       for e in plan.get("errors", [])],
            "notes": list(plan.get("notes", []))}


def _parse(value, fallback=None) -> datetime:
    if not value:
        if fallback is None:
            raise VaultRewindError("IMPORT_PLAN_INVALID", "An imported snapshot has no capture time.")
        return fallback
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise VaultRewindError("IMPORT_PLAN_INVALID", "An imported snapshot has an invalid capture time.") from exc
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _ensure_destination(db, store, entry: dict, summary: dict) -> StorageDestination:
    from vaultrewind.storage import providers
    existing = db.get(StorageDestination, entry["destination_id"])
    if existing:
        summary["destinations_existing"] += 1
        return existing
    providers.validate_destination(entry["backend"], entry["configuration"], entry.get("credential"),
                                   entry["destination_id"])
    ident = entry["destination_id"]
    config_id = store.put(db, "destination_configuration", ident, dict(entry["configuration"]))
    credential_id = store.put(db, "provider_credentials", ident, entry["credential"]) if entry.get("credential") else None
    destination = StorageDestination(id=ident, name=str(entry.get("name") or entry["backend"])[:120],
                                     backend=entry["backend"], configuration_secret_id=config_id,
                                     credential_id=credential_id, health="imported")
    db.add(destination)
    db.flush()
    summary["destinations_created"] += 1
    return destination


def _ensure_placeholder(db, store, instance_id: str, name: str | None, summary: dict) -> Instance:
    instance = db.get(Instance, instance_id)
    if instance:
        summary["instances_existing"] += 1
        return instance
    configuration = store.put(db, "instance_configuration", instance_id, {
        "remote_instance_id": instance_id, "imported": True, "restore_enabled": False, "resource_keys": [],
        "recovery_profile": {}})
    instance = Instance(id=instance_id, host_id=None, name=(name or f"Imported {instance_id[:8]}")[:120],
                        container_id="", physical_identity=digest({"imported_instance": instance_id}),
                        physical_keys=[], configuration_secret_id=configuration, fingerprint="",
                        readiness=PLACEHOLDER_READINESS, source_health="unknown", backup_health="unprotected")
    db.add(instance)
    db.flush()
    protected_policy = BackupPolicy(instance_id=instance_id, enabled=False, next_run_at=None)
    db.add(protected_policy)
    db.flush()
    # SQLAlchemy applies the ordinary 30-day INSERT default to a Python None. Persist
    # the explicit forever value after insertion before any import can be committed.
    protected_policy.retention_days = None
    db.flush()
    summary["instances_created"] += 1
    return instance


def _ensure_repository(db, store, entry: dict, destination: StorageDestination, materials: dict,
                       destination_config: dict, summary: dict) -> Repository | None:
    from vaultrewind.storage import providers
    from vaultrewind.storage.layout import derive_repository_password
    instance_id, destination_id = entry["instance_id"], destination.id
    controller = entry.get("purpose") == "controller"
    existing = db.scalar(select(Repository).where(Repository.instance_id == (None if controller else instance_id),
                                                  Repository.purpose == ("controller" if controller else "instance"),
                                                  Repository.destination_id == destination_id))
    if existing:
        private = store.get(db, existing.configuration_secret_id)
        known = private.get("restic_repository_id")
        if known and entry.get("restic_repository_id") and known != entry["restic_repository_id"]:
            summary["repositories_conflicting"] += 1
            summary["conflict_details"].append({"instance_id": instance_id, "destination_id": destination_id,
                                                "reason": "restic repository identity differs"})
            return None
        summary["repositories_existing"] += 1
        return existing
    kit_entry = next((r for r in materials.get("repositories", []) if r.get("instance_id") == instance_id
                      and r.get("destination_id") == destination_id), None)
    password = kit_entry.get("password") if kit_entry else None
    if not password:
        root = materials.get("recovery_root_secret")
        if not root:
            summary["repositories_locked"] += 1
            return None
        password = derive_repository_password(root, instance_id, destination_id)
    location = entry.get("location") or providers.repository_location(destination.backend, destination_config,
                                                                      instance_id, destination_id)
    expected = providers.repository_location(destination.backend, destination_config, instance_id, destination_id)
    if location != expected:
        # A relocated local path is tolerated only when it is inside the (possibly relocated) destination.
        providers._inside(location, str(destination_config.get("path", "")).rstrip("/") + "/", expected)
    repo_id = kit_entry.get("repository_id") if kit_entry and kit_entry.get("repository_id") else uid()
    if db.get(Repository, repo_id):
        repo_id = uid()
    private = {"location": location, "backend": destination.backend, "destination_id": destination_id,
               "destination_configuration": destination_config, "restic_repository_id": entry.get("restic_repository_id"),
               "imported": True}
    if controller:
        private["controller_id"] = instance_id
    repository = Repository(id=repo_id, instance_id=None if controller else instance_id, destination_id=destination_id,
                            purpose="controller" if controller else "instance",
                            configuration_secret_id=store.put(db, "repository_configuration", repo_id, private),
                            key_id=store.put(db, "repository_key", repo_id, password),
                            physical_identity=providers.physical_identity(destination.backend, destination_config,
                                                                          instance_id, destination_id),
                            health="imported", imported=True)
    db.add(repository)
    db.flush()
    summary["repositories_created"] += 1
    return repository


def _protect(db, snapshot_id: str, reason: str, job_id: str) -> None:
    if not db.scalar(select(SnapshotProtection.id).where(SnapshotProtection.snapshot_id == snapshot_id,
                                                        SnapshotProtection.reason == reason)):
        db.add(SnapshotProtection(snapshot_id=snapshot_id, reason=reason, job_id=job_id))


def apply_import_plan(db, store, plan: dict, materials: dict, *, actor_id: str | None, job_id: str) -> dict:
    """Create protected catalog rows for a reviewed import plan. Idempotent for identical plans."""
    if plan.get("mode") != "protected" or plan.get("plan_version") != 1:
        raise VaultRewindError("IMPORT_PLAN_INVALID", "Only protected-mode version 1 import plans can be applied.")
    summary = {"destinations_created": 0, "destinations_existing": 0, "instances_created": 0, "instances_existing": 0,
               "repositories_created": 0, "repositories_existing": 0, "repositories_conflicting": 0,
               "repositories_locked": 0, "snapshots_created": 0, "snapshots_existing": 0, "snapshots_conflicting": 0,
               "copies_created": 0, "copies_existing": 0, "copies_unverified": 0, "copies_skipped": 0,
               "conflict_details": [], "automatic_deletion_enabled": False}
    # A genuinely fresh catalog can adopt the recovered controller identity/root. Importing
    # into an existing catalog never rotates its current identity or existing repository derivation.
    from uuid import UUID

    from .models import ControllerState, Secret
    state = db.scalar(select(ControllerState).where(ControllerState.id == 1).with_for_update())
    recovered_id = materials.get("controller_id")
    try:
        recovered_id = str(UUID(recovered_id))
    except (ValueError, TypeError, AttributeError):
        recovered_id = None  # Older kits used an informational non-UUID controller label.
    own_root = db.scalar(select(Secret).where(Secret.kind == "recovery_root", Secret.owner_scope == "controller"))
    if state and not state.controller_id:
        # Older initialized catalogs may already derive application repository
        # keys from a local root without recording their controller identity.
        # Preserve that root under a fresh local identity; import foreign roots
        # independently instead of attaching a foreign identity to our own root.
        state.controller_id = uid() if own_root else recovered_id
    if materials.get("recovery_root_secret") and not own_root:
        store.put(db, "recovery_root", "controller", materials["recovery_root_secret"])
    roots = dict(materials.get("controller_recovery_roots") or {})
    if recovered_id and materials.get("recovery_root_secret"):
        roots.setdefault(recovered_id, materials["recovery_root_secret"])
    from vaultrewind.storage.layout import canonical_uuid, derive_repository_password
    for identity, root in roots.items():
        canonical_uuid(identity, "controller ID")
        derive_repository_password(root, identity, identity)
        if state and identity == state.controller_id and own_root and store.get(db, own_root.id) != root:
            raise VaultRewindError("CONTROLLER_RECOVERY_ROOT_CONFLICT", "The current controller identity already has different recovery material; preserve both kits for review.")
        prior = db.scalar(select(Secret).where(Secret.kind == "controller_recovery_root", Secret.owner_scope == identity))
        if prior and store.get(db, prior.id) != root:
            raise VaultRewindError("CONTROLLER_RECOVERY_ROOT_CONFLICT", "A recovered controller identity has conflicting recovery material; preserve both kits for review.")
        if not prior:
            store.put(db, "controller_recovery_root", identity, root)
    names = {i["instance_id"]: i.get("name") for i in plan.get("instances", [])}
    for item in materials.get("instances", []):
        names.setdefault(item["instance_id"], item.get("name"))
    materials_by_destination = {d["destination_id"]: d for d in materials.get("destinations", [])}
    destinations: dict[str, StorageDestination] = {}
    configs: dict[str, dict] = {}
    for entry in plan.get("destinations", []):
        material = materials_by_destination.get(entry["destination_id"])
        if material is None:
            raise VaultRewindError("IMPORT_PLAN_INVALID", "The import plan references a destination absent from the kit.")
        destination = _ensure_destination(db, store, material, summary)
        destinations[destination.id] = destination
        configs[destination.id] = store.get(db, destination.configuration_secret_id)
    repositories: dict[tuple[str, str], Repository] = {}
    for entry in plan.get("repositories", []):
        destination = destinations.get(entry["destination_id"])
        if destination is None:
            continue
        if entry.get("purpose") != "controller":
            _ensure_placeholder(db, store, entry["instance_id"], names.get(entry["instance_id"]), summary)
        repository = _ensure_repository(db, store, entry, destination, materials, configs[destination.id], summary)
        if repository is not None and entry.get("purpose") != "controller":
            repositories[(entry["instance_id"], destination.id)] = repository
    facts = plan.get("manifest_facts", {})
    current = now()
    for item in plan.get("snapshots", []):
        if item.get("conflict"):
            summary["snapshots_conflicting"] += 1
            continue
        snapshot_id, instance_id = item["snapshot_uuid"], item["instance_id"]
        if instance_id not in {key[0] for key in repositories}:
            summary["copies_skipped"] += len(item.get("copies", []))
            continue
        fact = facts.get(snapshot_id, {})
        verified_copies = [c for c in item.get("copies", []) if c.get("manifest_verified")]
        snapshot = db.get(Snapshot, snapshot_id)
        if snapshot is None:
            captured = _parse(item.get("captured_at") or fact.get("captured_at"))
            snapshot = Snapshot(id=snapshot_id, instance_id=instance_id, captured_at=captured,
                                capture_started_at=_parse(fact.get("capture_started_at"), captured),
                                trigger="safety" if item.get("kind") == "safety" else "imported",
                                manifest_hash=item["manifest_hash"],
                                completeness="complete" if verified_copies else "unverified",
                                logical_bytes=int(item.get("logical_bytes") or fact.get("logical_bytes") or 0),
                                image_id=str(fact.get("image_id") or "unknown")[:100],
                                vaultwarden_version=str(fact.get("vaultwarden_version") or "unknown")[:100],
                                source_state=str(fact.get("source_state") or "unknown")[:30],
                                verification={"capture_validated": False, "stored_copy_verified": bool(verified_copies)},
                                imported=True)
            db.add(snapshot)
            db.flush()
            summary["snapshots_created"] += 1
        elif snapshot.manifest_hash != item["manifest_hash"]:
            summary["snapshots_conflicting"] += 1
            summary["conflict_details"].append({"snapshot_id": snapshot_id, "reason": "catalog manifest hash differs"})
            continue
        else:
            summary["snapshots_existing"] += 1
        for copy in item.get("copies", []):
            repository = repositories.get((instance_id, copy["destination_id"]))
            if repository is None:
                summary["copies_skipped"] += 1
                continue
            existing = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot_id,
                                                            SnapshotCopy.repository_id == repository.id))
            if existing:
                summary["copies_existing"] += 1
                continue
            verified = bool(copy.get("manifest_verified"))
            db.add(SnapshotCopy(id=uid(), snapshot_id=snapshot_id, repository_id=repository.id,
                                restic_snapshot_id=copy.get("restic_snapshot_id"),
                                state="complete" if verified else "unverified",
                                manifest_hash=item["manifest_hash"] if verified else None,
                                verified_at=current if verified else None,
                                error_code=None if verified else "MANIFEST_UNVERIFIED"))
            summary["copies_created"] += 1
            if not verified:
                summary["copies_unverified"] += 1
        _protect(db, snapshot_id, "import_review", job_id)
        if item.get("kind") == "safety":
            _protect(db, snapshot_id, "safety", job_id)
        if item.get("future_dated") or utc(snapshot.captured_at) > current:
            _protect(db, snapshot_id, "future_dated_review", job_id)
    db.flush()
    audit(db, actor_id, "recovery.import_apply", job_id, "succeeded",
          changes={k: v for k, v in summary.items() if k != "conflict_details"})
    return summary

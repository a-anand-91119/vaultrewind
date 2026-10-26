"""Domain services shared by HTTP and the normal authenticated CLI."""
import hmac
import secrets
from datetime import timedelta

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .auth import hash_token
from .db import now, uid, utc
from .models import (
    ActivationPlan,
    BackupPolicy,
    DeletionPlan,
    Host,
    Instance,
    InstanceDependency,
    Job,
    PolicyDestination,
    Repository,
    RestorePlan,
    Snapshot,
    SnapshotCopy,
    SnapshotProtection,
    StorageDestination,
)
from .policy import ACTIVE, next_run, retention_preview, validate_schedule
from .queue import audit, digest, enqueue, resources_for_instance
from .schemas import CopyView, JobAccepted, SnapshotView


def get(db, cls, ident):
    obj = db.get(cls, ident)
    if obj is None:
        raise VaultRewindError("NOT_FOUND", "The requested object does not exist.")
    return obj


def iso(value):
    return utc(value).isoformat() if value else None


def accepted(job):
    return JobAccepted(job_id=job.id, state=job.state, status_url=f"/api/v1/jobs/{job.id}",
                       events_url=f"/api/v1/jobs/{job.id}/events").model_dump()


# Policy budget field -> root helper policy limit enforced on the host.
BUDGET_FIELDS = {"outage_seconds": "capture_budget", "maintenance_seconds": "restore_budget",
                 "validation_seconds": "validation_window"}


def approved_budgets(db, store, host_id, remote_id, configuration=None):
    """Budgets the host's root helper policy enforces for one enrolled instance (empty when unknown).

    The helper's capture payload carries no budget: the root policy installed at activation is authoritative.
    The controller therefore records the approved values at enrollment and refuses policy values above them.
    """
    budgets = dict((configuration or {}).get("approved_budgets") or {})
    if budgets or not host_id:
        return budgets
    activations = db.scalars(select(Job).where(Job.kind == "activate", Job.state == "succeeded")
                             .order_by(Job.finished_at.desc()).limit(50))
    for job in activations:
        if job.request.get("host_id") != host_id:
            continue
        plan = db.get(ActivationPlan, job.request.get("plan_id", ""))
        if not plan:
            continue
        item = ((store.get(db, plan.secret_id) or {}).get("policy") or {}).get("instances", {}).get(remote_id) or {}
        budgets = {field: item[key] for field, key in BUDGET_FIELDS.items() if type(item.get(key)) is int}
        if budgets:
            return budgets
    return budgets


def policy_view(db, policy, store=None):
    destinations = db.execute(select(PolicyDestination, Repository, StorageDestination)
        .join(Repository, Repository.id == PolicyDestination.repository_id)
        .join(StorageDestination, StorageDestination.id == Repository.destination_id)
        .where(PolicyDestination.policy_id == policy.id)).all()
    budgets = {}
    if store is not None:
        instance = db.get(Instance, policy.instance_id)
        if instance is not None and instance.configuration_secret_id:
            try:
                configuration = store.get(db, instance.configuration_secret_id)
            except VaultRewindError:
                configuration = {}
            budgets = approved_budgets(db, store, instance.host_id, configuration.get("remote_instance_id", instance.id),
                                       configuration)
    effective = {field: min(getattr(policy, field), budgets[field]) if budgets.get(field) is not None
                 else getattr(policy, field) for field in BUDGET_FIELDS}
    return {k: getattr(policy, k) for k in ("id", "instance_id", "revision", "enabled", "schedule_kind", "timezone",
                "daily_time", "interval_hours", "retention_days", "outage_seconds", "maintenance_seconds",
                "validation_seconds", "runner_id")} | {
        "next_run_at": iso(policy.next_run_at), "next_verify_at": iso(policy.next_verify_at),
        "next_test_at": iso(policy.next_test_at),
        "host_budgets": {field: budgets.get(field) for field in BUDGET_FIELDS},
        "effective_outage_seconds": effective["outage_seconds"],
        "effective_maintenance_seconds": effective["maintenance_seconds"],
        "effective_validation_seconds": effective["validation_seconds"],
        "destinations": [
        {"destination_id": r.destination_id, "destination_name": d.name, "backend": d.backend,
         "repository_id": r.id, "required": p.required} for p, r, d in destinations]}


def destination_view(db, store, settings, destination):
    """Sanitized destination status: identifiers, host path, free space and provider folder; never credentials."""
    import shutil
    from pathlib import Path
    from urllib.parse import urlsplit
    base = {k: getattr(destination, k) for k in ("id", "name", "backend", "health", "revision", "quota_bytes")} | {
        "last_test_at": iso(destination.last_test_at), "credentials_configured": bool(destination.credential_id)}
    details = {}
    try:
        config = store.get(db, destination.configuration_secret_id)
    except VaultRewindError as exc:
        return base | {"details": details, "configuration_error": exc.code}
    if destination.backend == "local":
        path = Path(str(config.get("path") or settings.local_storage_root))
        details = {"host_path": config.get("host_path"), "mount_path": str(path),
                   "require_dedicated_mount": bool(config.get("require_dedicated_mount", True)),
                   "min_free_bytes": config.get("min_free_bytes"), "free_bytes": None, "total_bytes": None,
                   "marker_present": False}
        try:
            usage = shutil.disk_usage(path)
            details.update(free_bytes=usage.free, total_bytes=usage.total,
                           marker_present=(path / ".vaultrewind-destination.json").is_file())
        except OSError:
            pass
    elif destination.backend == "s3":
        details = {"endpoint_host": urlsplit(str(config.get("endpoint") or "")).hostname, "bucket": config.get("bucket"),
                   "prefix": config.get("prefix"), "region": config.get("region"),
                   "bucket_lookup": config.get("bucket_lookup", "auto"), "custom_ca": bool(config.get("ca_cert_pem")),
                   "development_http": bool(config.get("development_http"))}
    else:
        details = {"folder_id": config.get("folder_id"), "folder_name": config.get("folder_name"),
                   "scope": config.get("scope", "drive.file"), "authorized": False, "authorized_at": None,
                   "token_expiry": None}
        if destination.credential_id:
            try:
                credential = store.get(db, destination.credential_id)
                token = credential.get("token") or {}
                details.update(authorized=bool(token.get("refresh_token")), authorized_at=credential.get("authorized_at"),
                               token_expiry=token.get("expiry"))
            except VaultRewindError:
                details["authorized"] = False
    return base | {"details": details}


def prepare_local_destination(settings, destination_id, configuration):
    """Validate a local destination against the configured persistent mount and create its identity marker.

    Saving a destination is the user action that permits the first write (the marker), per the storage contract.
    """
    from pathlib import Path

    from vaultrewind.storage.local import LocalDestination, initialize_local_destination
    path = Path(str(configuration.get("path") or settings.local_storage_root))
    if not path.is_absolute() or not path.resolve(strict=False).is_relative_to(settings.local_storage_root.resolve(strict=False)):
        raise VaultRewindError("STORAGE_PATH_UNSAFE", "Select a directory inside the configured persistent storage mount.")
    config = {**configuration, "path": str(path)}
    config.setdefault("require_dedicated_mount", settings.local_require_dedicated_mount)
    config.setdefault("min_free_bytes", settings.min_free_bytes)
    evidence = initialize_local_destination(LocalDestination.from_config(config, destination_id),
        protected_paths=[settings.staging_dir, settings.master_key_file, settings.bootstrap_secret_file])
    return config, {"free_bytes": evidence.get("free_bytes"), "marker_present": bool(evidence.get("marker_present")),
                    "warnings": list(evidence.get("warnings", []))}


def controller_id(db):
    """Stable controller identity, created once and persisted in controller_state."""
    from .models import ControllerState
    state = db.scalar(select(ControllerState).where(ControllerState.id == 1).with_for_update())
    if state is None:
        state = ControllerState(id=1, bootstrap_used=False)
        db.add(state)
        db.flush()
    if not state.controller_id:
        state.controller_id = uid()
        db.flush()
    return state.controller_id


def instance_view(db, instance, store=None):
    issue = []
    if instance.readiness != "ready":
        issue.append("instance_not_ready")
    if instance.backup_health != "healthy":
        issue.append("backup_" + instance.backup_health)
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance.id))
    if not policy or not policy.runner_id:
        issue.append("restore_testing_not_configured")
    from .policy import is_overdue
    if policy and is_overdue(db, policy):
        issue.append("backup_overdue")
    readiness = {}
    if store is not None:
        private = store.get(db, instance.configuration_secret_id, upgrade=False)
        readiness = {"restore_ready": bool(private.get("restore_enabled")),
                     "restore_error_code": private.get("restore_error_code"),
                     "source_public_ports_ready": private.get("source_public_ports_ready")}
        if readiness["source_public_ports_ready"] is False:
            issue.append("source_public_endpoint_unready")
    if db.scalar(select(Job.id).where(Job.instance_id == instance.id, Job.state.in_(["needs_attention", "rollback_failed"])).limit(1)):
        issue.append("operation_needs_attention")
    return {k: getattr(instance, k) for k in ("id", "host_id", "name", "revision", "readiness", "source_health",
             "backup_health", "archived", "is_runner")} | {"last_complete_at": iso(instance.last_complete_at),
             "capture_age_seconds": int((now() - utc(instance.last_complete_at)).total_seconds())
             if instance.last_complete_at else None, "last_test_at": iso(instance.last_test_at),
             "protection_issues": issue, **readiness}


def snapshot_view(db, snapshot):
    from .models import VerificationRun
    annotations = dict(snapshot.verification)
    for run in db.scalars(select(VerificationRun).where(VerificationRun.snapshot_id == snapshot.id,
                                                      VerificationRun.result == "succeeded")):
        for key, value in run.evidence.items():
            if value is True:
                annotations[key] = True
    copies = list(db.scalars(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot.id)))
    labels = {}
    for repo, dest in db.execute(select(Repository, StorageDestination)
                                 .join(StorageDestination, StorageDestination.id == Repository.destination_id)
                                 .where(Repository.id.in_([c.repository_id for c in copies]))).all():
        labels[repo.id] = (dest.id, dest.name, dest.backend)
    pinned = db.scalar(select(SnapshotProtection.id).where(SnapshotProtection.snapshot_id == snapshot.id,
                            SnapshotProtection.reason.in_(["pin", "safety"]),
                            (SnapshotProtection.expires_at.is_(None)) | (SnapshotProtection.expires_at > now())))
    bool_keys = {"capture_validated", "stored_copy_verified", "full_data_verified", "restored_bytes_verified",
                 "application_started", "user_login_tested", "inventory_verified", "sqlite_integrity"}
    return SnapshotView(id=snapshot.id, instance_id=snapshot.instance_id,
        captured_at=iso(snapshot.captured_at), capture_started_at=iso(snapshot.capture_started_at),
        trigger=snapshot.trigger, completeness=snapshot.completeness, logical_bytes=snapshot.logical_bytes,
        vaultwarden_version=snapshot.vaultwarden_version, image_id=snapshot.image_id, source_state=snapshot.source_state,
        pinned=bool(pinned), safety=bool(snapshot.safety_for_job_id),
        verification={k: v for k, v in annotations.items() if k in bool_keys and isinstance(v, bool)},
        copies=[CopyView(id=c.id, repository_id=c.repository_id, destination_id=labels.get(c.repository_id, (None,))[0],
                  destination_name=labels.get(c.repository_id, (None, None))[1],
                  backend=labels.get(c.repository_id, (None, None, None))[2], state=c.state, logical_bytes=c.logical_bytes,
                  stored_bytes=c.stored_bytes, verified_at=iso(c.verified_at), data_verified_at=iso(c.data_verified_at),
                  error_code=c.error_code) for c in copies]).model_dump()


def job_view(job):
    from .errors import error_body
    allowed = {"snapshot_id", "safety_snapshot_id", "verification_id", "plan_id", "plan_hash", "expires_at",
               "destination_id", "active_generation", "retained_copies", "deleted_copies", "artifact_ready",
               "source_state", "candidate_validated", "application_started", "user_login_tested",
               "full_data_verified", "restored_bytes_verified", "activation_started", "empty_target",
               "readiness", "cleanup_result", "discovered_instances", "changes", "prerequisites",
               "failure_code", "failure_phase", "remote_phase", "source_recovery", "original_source_state",
               "reconciliation_error", "remote_fence_adopted", "artifact_expires_at", "import_summary",
               "apply_summary", "controller_backup_id", "repository_id", "destination_name", "pg_dump_included",
               "tables", "rows", "bytes"}
    allowed |= {"failure_operation_category", "failure_transport_kind"}
    allowed |= {"remote_storage", "historical_job_id", "cleanup_kind"}
    allowed |= {"public_ports_verified", "public_endpoint_verified"}
    return {k: getattr(job, k) for k in ("id", "kind", "instance_id", "state", "phase", "attempts", "error_code",
            "content_commit", "required_copy_outcome", "source_service_outcome", "target_activation_outcome")} | {
            "created_at": iso(job.created_at), "started_at": iso(job.started_at), "finished_at": iso(job.finished_at),
            "result": {k: v for k, v in job.result.items() if k in allowed},
            "artifact_url": f"/api/v1/jobs/{job.id}/artifact" if job.result.get("artifact_ready") else None,
            "artifact_ready": bool(job.result.get("artifact_ready")),
            "error": error_body(job.error_code, phase=job.phase, job_id=job.id)["error"] if job.error_code else None}


def backup_request(db, instance_id, label=None, trigger="manual"):
    instance = get(db, Instance, instance_id)
    if instance.host_id is None:
        raise VaultRewindError("INSTANCE_NOT_READY", "Enroll the recovered registration on a prepared host first.")
    host = get(db, Host, instance.host_id)
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance_id))
    if instance.archived or instance.readiness != "ready" or host.readiness != "ready" or not policy:
        raise VaultRewindError("INSTANCE_NOT_READY", "Complete instance activation before backup.")
    destinations = list(db.scalars(select(PolicyDestination).where(PolicyDestination.policy_id == policy.id)))
    if not destinations or not any(d.required for d in destinations):
        raise VaultRewindError("STORAGE_NOT_CONFIGURED", "At least one required storage destination is needed.")
    return {"instance_id": instance.id, "configuration_revision": instance.revision,
            "fingerprint": instance.fingerprint, "policy_revision": policy.revision,
            "repositories": [{"repository_id": d.repository_id, "required": d.required} for d in destinations],
            "label": label, "trigger": trigger, "outage_seconds": policy.outage_seconds}


def select_copy(db, snapshot_id, copy_id=None):
    snapshot = get(db, Snapshot, snapshot_id)
    query = select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot.id, SnapshotCopy.state == "complete")
    if copy_id:
        query = query.where(SnapshotCopy.id == copy_id)
    copy = db.scalar(query.order_by(SnapshotCopy.verified_at.desc(), SnapshotCopy.id))
    if snapshot.completeness != "complete" or not copy or copy.manifest_hash != snapshot.manifest_hash:
        raise VaultRewindError("SNAPSHOT_INCOMPLETE", "A verified complete copy is required.")
    return snapshot, copy


def new_restore_plan(db, secrets_store, snapshot_id, actor_id, body):
    snapshot, copy = select_copy(db, snapshot_id, body.copy_id)
    target = get(db, Instance, body.target_id or snapshot.instance_id)
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == target.id))
    if target.host_id is None:
        raise VaultRewindError("TARGET_NOT_READY", "Choose a prepared target; the recovered source is not enrolled on a host.")
    host = get(db, Host, target.host_id)
    if target.readiness != "ready" or host.readiness != "ready" or not policy or target.is_runner:
        raise VaultRewindError("TARGET_NOT_READY", "Enroll and validate a recovery target first.")
    dependencies = list(db.scalars(select(InstanceDependency).where(InstanceDependency.instance_id == target.id,
                                      InstanceDependency.required.is_(True), InstanceDependency.state != "ready")))
    if dependencies:
        raise VaultRewindError("DEPENDENCY_UNREADY", "Required target dependencies must be enrolled.")
    configuration = secrets_store.get(db, target.configuration_secret_id)
    if not configuration.get("restore_enabled", False):
        raise VaultRewindError("RESTORE_NOT_ENABLED", "The target is enrolled for backup only.")
    from vaultrewind.remote.overlays import approved_environment
    profile = configuration.get("recovery_profile") or {}
    environment = approved_environment(profile)
    substitutions = {"profile_revision": profile.get("revision", 1)}
    if environment.get("DOMAIN"):
        substitutions["public_url"] = environment["DOMAIN"]
    if profile.get("network"):
        substitutions["network"] = profile["network"]
    if "port_bindings" in profile:
        substitutions["published_ports"] = "; ".join(
            f"{binding.get('HostIp') or '0.0.0.0'}:{binding['HostPort']} → {port}"
            for port, bindings in profile["port_bindings"].items() for binding in bindings
        ) or "None (data-only recovery)"
    token = secrets.token_urlsafe(32)
    mapping_id = secrets_store.put(db, "restore_mapping", target.id, {
        "recovery_profile": configuration.get("recovery_profile", {}), "start_on_completion": body.start_on_completion})
    plan = RestorePlan(id=uid(), snapshot_id=snapshot.id, copy_id=copy.id, target_id=target.id,
        actor_id=actor_id, target_revision=target.revision, policy_revision=policy.revision,
        target_fingerprint=target.fingerprint, manifest_hash=snapshot.manifest_hash,
        mappings_secret_id=mapping_id, token_hash=hash_token(token), expires_at=now() + timedelta(minutes=10))
    db.add(plan)
    audit(db, actor_id, "restore.plan", plan.id)
    return {"id": plan.id, "snapshot_id": snapshot.id, "copy_id": copy.id, "target_id": target.id,
            "target_name": target.name, "captured_at": iso(snapshot.captured_at),
            "vaultwarden_version": snapshot.vaultwarden_version, "image_id": snapshot.image_id, "target_revision": target.revision,
            "policy_revision": policy.revision, "confirmation_token": token, "expires_at": iso(plan.expires_at),
            "maintenance_budget_seconds": policy.maintenance_seconds, "safety_snapshot_required": True,
            "substitutions": substitutions,
            "start_on_completion": body.start_on_completion,
            "consequence": "Changes after this capture point will be replaced on the selected target."}


def execute_restore(db, plan_id, token, actor_id, key):
    plan = db.scalar(select(RestorePlan).where(RestorePlan.id == plan_id).with_for_update())
    if not plan or plan.actor_id != actor_id or not hmac.compare_digest(plan.token_hash, hash_token(token)):
        raise VaultRewindError("PLAN_INVALID", "The restore confirmation is invalid.")
    request = {"plan_id": plan.id, "snapshot_id": plan.snapshot_id, "copy_id": plan.copy_id,
               "target_id": plan.target_id, "target_revision": plan.target_revision,
               "policy_revision": plan.policy_revision, "fingerprint": plan.target_fingerprint,
               "manifest_hash": plan.manifest_hash, "mappings_secret_id": plan.mappings_secret_id}
    # Consumed-token retries are allowed only for the identical originating request/key.
    if plan.consumed_at:
        existing = get(db, Job, plan.job_id)
        if existing.idempotency_key == key and existing.request_hash == digest(request):
            return existing
        raise VaultRewindError("PLAN_INVALID", "This restore confirmation was already consumed.")
    if utc(plan.expires_at) <= now():
        raise VaultRewindError("PLAN_INVALID", "The restore confirmation expired.")
    target = db.scalar(select(Instance).where(Instance.id == plan.target_id).with_for_update())
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == target.id).with_for_update())
    snapshot, copy = select_copy(db, plan.snapshot_id, plan.copy_id)
    if (target.revision != plan.target_revision or target.fingerprint != plan.target_fingerprint or
            policy.revision != plan.policy_revision or snapshot.manifest_hash != plan.manifest_hash):
        raise VaultRewindError("TARGET_CHANGED", "The restore target or source changed.")
    keys = sorted(set(resources_for_instance(db, target.id) + resources_for_instance(db, snapshot.instance_id, [copy.repository_id])))
    job = enqueue(db, kind="restore", request=request, key=key, actor_id=actor_id,
                  instance_id=target.id, resources=keys)
    plan.consumed_at, plan.job_id = now(), job.id
    db.add(SnapshotProtection(snapshot_id=snapshot.id, reason="active_restore", actor_id=actor_id, job_id=job.id))
    return job


def patch_policy(db, secrets_store, settings, instance_id, body, revision, actor_id):
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance_id).with_for_update())
    if not policy:
        raise VaultRewindError("NOT_FOUND", "The policy does not exist.")
    if revision != policy.revision:
        raise VaultRewindError("REVISION_CONFLICT", "The policy revision changed.")
    instance = get(db, Instance, instance_id)
    if db.scalar(select(Job.id).where(Job.instance_id == instance_id, Job.state.in_(ACTIVE))):
        raise VaultRewindError("RESOURCE_BUSY", "Wait for active work before changing policy.")
    changes = body.model_dump(exclude_unset=True)
    for budget in ("outage_seconds", "maintenance_seconds", "validation_seconds"):
        if budget in changes and changes[budget] != getattr(policy, budget):
            raise VaultRewindError("REMOTE_POLICY_UPDATE_REQUIRED", "Review and activate the corresponding helper policy budget before changing the controller budget.")
    for field, value in changes.items():
        if field != "destinations":
            if value is None and field not in {"retention_days", "runner_id"}:
                raise VaultRewindError("VALIDATION_ERROR", "A required policy value cannot be null.")
            setattr(policy, field, value)
    validate_schedule(policy.schedule_kind, policy.timezone, policy.daily_time, policy.interval_hours)
    if {"outage_seconds", "maintenance_seconds", "validation_seconds"} & changes.keys():
        configuration = secrets_store.get(db, instance.configuration_secret_id) if instance.configuration_secret_id else {}
        budgets = approved_budgets(db, secrets_store, instance.host_id,
                                   configuration.get("remote_instance_id", instance.id), configuration)
        for field in BUDGET_FIELDS:
            limit = budgets.get(field)
            if limit is not None and getattr(policy, field) > limit:
                raise VaultRewindError("BUDGET_EXCEEDS_HOST_POLICY",
                                       "The host helper policy enforces a smaller budget; re-activate the host with a larger budget first.",
                                       field=field, host_limit_seconds=limit)
    if policy.runner_id:
        runner = get(db, Instance, policy.runner_id)
        if not runner.is_runner or runner.host_id == instance.host_id or runner.physical_identity == instance.physical_identity:
            raise VaultRewindError("RUNNER_UNSAFE", "Use a dedicated isolated runner on a separate host.")
    if "destinations" in changes:
        selected = body.destinations
        if not selected or not any(d.required for d in selected) or len({d.destination_id for d in selected}) != len(selected):
            raise VaultRewindError("VALIDATION_ERROR", "Select at least one required destination without duplicates.")
        for old in db.scalars(select(PolicyDestination).where(PolicyDestination.policy_id == policy.id)):
            db.delete(old)
        db.flush()
        for chosen in selected:
            destination = get(db, StorageDestination, chosen.destination_id)
            if destination.archived:
                raise VaultRewindError("STORAGE_NOT_CONFIGURED", "The selected destination is archived.")
            repo = db.scalar(select(Repository).where(Repository.instance_id == instance_id,
                                                      Repository.destination_id == destination.id))
            if not repo:
                repo = create_repository(db, secrets_store, settings, instance_id, destination)
            db.add(PolicyDestination(policy_id=policy.id, repository_id=repo.id, required=chosen.required))
    if {"schedule_kind", "timezone", "daily_time", "interval_hours", "enabled"} & changes.keys():
        policy.next_run_at = next_run(policy, now()) if policy.enabled else None
    policy.revision += 1
    audit(db, actor_id, "policy.change", policy.id, changes={"fields": sorted(changes), "revision": policy.revision})
    return policy


def create_repository(db, store, settings, instance_id, destination):
    config = store.get(db, destination.configuration_secret_id)
    repo_id = uid()
    from pathlib import Path

    from vaultrewind.storage import providers
    if destination.backend == "local" and not Path(config.get("path", "")).is_relative_to(settings.local_storage_root):
        raise VaultRewindError("STORAGE_PATH_UNSAFE", "Select the configured persistent storage mount.")
    backend = destination.backend
    location = providers.repository_location(backend, config, instance_id, destination.id)
    private = {"location": location, "backend": backend, "destination_id": destination.id,
               "destination_configuration": config}
    cfg_id = store.put(db, "repository_configuration", repo_id, private)
    from vaultrewind.storage.layout import derive_repository_password
    password = derive_repository_password(recovery_root(db, store), instance_id, destination.id)
    key_id = store.put(db, "repository_key", repo_id, password)
    repo = Repository(id=repo_id, instance_id=instance_id, destination_id=destination.id,
                      configuration_secret_id=cfg_id, key_id=key_id,
                      physical_identity=providers.physical_identity(backend, config, instance_id, destination.id))
    db.add(repo)
    db.flush()
    return repo


def deletion_plan(db, snapshot_id, actor_id):
    snapshot = get(db, Snapshot, snapshot_id)
    preview = retention_preview(db, snapshot.instance_id)
    ids = sorted(set(preview["copy_ids"]) & set(db.scalars(select(SnapshotCopy.id)
                        .where(SnapshotCopy.snapshot_id == snapshot_id))))
    if not ids:
        raise VaultRewindError("RETENTION_PROTECTED", "This recovery point is protected from deletion.")
    token = secrets.token_urlsafe(32)
    plan = DeletionPlan(id=uid(), instance_id=snapshot.instance_id, actor_id=actor_id,
             policy_revision=preview["policy_revision"], copy_ids=ids, token_hash=hash_token(token),
             expires_at=now() + timedelta(minutes=10))
    db.add(plan)
    audit(db, actor_id, "delete.plan", plan.id)
    return {"id": plan.id, "copy_ids": ids, "confirmation_token": token, "expires_at": iso(plan.expires_at)}


def execute_deletion(db, plan_id, token, actor_id, key):
    plan = db.scalar(select(DeletionPlan).where(DeletionPlan.id == plan_id).with_for_update())
    if not plan or plan.actor_id != actor_id or not hmac.compare_digest(plan.token_hash, hash_token(token)):
        raise VaultRewindError("PLAN_INVALID", "The deletion confirmation is invalid.")
    if plan.consumed_at:
        existing = get(db, Job, plan.job_id)
        if existing.idempotency_key == key:
            return existing
        raise VaultRewindError("PLAN_INVALID", "The deletion confirmation was consumed.")
    if utc(plan.expires_at) <= now():
        raise VaultRewindError("PLAN_INVALID", "The deletion confirmation expired.")
    preview = retention_preview(db, plan.instance_id)
    if preview["policy_revision"] != plan.policy_revision or not set(plan.copy_ids) <= set(preview["copy_ids"]):
        raise VaultRewindError("RETENTION_PROTECTED", "Deletion eligibility changed.")
    job = enqueue(db, kind="delete", request={"plan_id": plan.id, "copy_ids": plan.copy_ids,
        "policy_revision": plan.policy_revision}, key=key, actor_id=actor_id, instance_id=plan.instance_id)
    plan.consumed_at, plan.job_id = now(), job.id
    return job


def recovery_root(db, store):
    from vaultrewind.storage.layout import new_recovery_root_secret

    from .models import ResourceLease, Secret
    from .queue import ensure_resource
    # A root and its controller identity must be established together, before any
    # repository derives an unlock key from that root.
    controller_id(db)
    ensure_resource(db, "controller:recovery_root")
    db.scalar(select(ResourceLease).where(ResourceLease.resource_key == "controller:recovery_root").with_for_update())
    row = db.scalar(select(Secret).where(Secret.kind == "recovery_root", Secret.owner_scope == "controller"))
    if row:
        return store.get(db, row.id)
    value = new_recovery_root_secret()
    store.put(db, "recovery_root", "controller", value)
    return value


def enqueue_controller_backup(db, store, settings, destination_id, *, key, actor_id=None, scheduled_at=None):
    from .controller_backup import _controller_identity, _repository
    from .models import ControllerBackupPolicy
    if destination_id is None:
        configured = db.get(ControllerBackupPolicy, 1)
        destination_id = configured.destination_id if configured else None
    if destination_id is None:
        raise VaultRewindError("CONTROLLER_BACKUP_NOT_CONFIGURED", "Select a controller backup destination first.")
    controller_id = _controller_identity(db)
    destination, repo, *_ = _repository(db, store, settings, controller_id, destination_id)
    request = {"destination_id": destination.id}
    if scheduled_at:
        request["scheduled_at"] = scheduled_at
    return enqueue(db, kind="controller_backup", request=request, key=key, actor_id=actor_id,
                   resources=["controller:metadata-backup", "controller:catalog",
                              f"repository:{repo.physical_identity}", f"credential:{destination.id}"])


def ensure_safety_repository(db, store, settings, instance_id, actor_id=None):
    """Every enrolled target has local encrypted safety capacity, independently of its cloud policy."""
    existing = db.scalar(select(Repository).join(StorageDestination).where(
        Repository.instance_id == instance_id, StorageDestination.backend == "local", StorageDestination.archived.is_(False)))
    if existing:
        return existing
    candidates = list(db.scalars(select(StorageDestination).where(StorageDestination.backend == "local",
                                                                 StorageDestination.archived.is_(False))))
    destination = next((d for d in candidates if store.get(db, d.configuration_secret_id).get("path") == str(settings.local_storage_root)), None)
    if destination is None:
        ident = uid()
        config = {"path": str(settings.local_storage_root), "min_free_bytes": settings.min_free_bytes,
                  "require_dedicated_mount": settings.local_require_dedicated_mount}
        destination = StorageDestination(id=ident, name="Local controller disk", backend="local",
            configuration_secret_id=store.put(db, "destination_configuration", ident, config))
        db.add(destination)
        db.flush()
        enqueue(db, kind="storage_test", request={"destination_id": ident}, key=f"initial-local:{ident}",
                actor_id=actor_id, resources=[f"credential:{ident}"])
    return create_repository(db, store, settings, instance_id, destination)

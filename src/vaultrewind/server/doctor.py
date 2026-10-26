"""Read-only catalog readiness. No probes, no credential refresh, no remote access."""
from datetime import timedelta

from sqlalchemy import func, select

from .db import now, utc
from .models import BackupPolicy, ControllerBackup, Host, Instance, Job, Repository, Secret, StagingAllocation


def inspect_catalog(db, settings=None):
    checks = []
    for host in db.scalars(select(Host).where(Host.archived.is_(False))):
        if host.helper_protocol != 1 or host.readiness != "ready":
            checks.append({"code": "HELPER_NOT_READY", "object_id": host.id})
    for job in db.scalars(select(Job).where(Job.state.in_(["running", "cancel_requested"]))):
        if not job.lease_expires_at or utc(job.lease_expires_at) <= now():
            checks.append({"code": "STALE_JOB_RECONCILIATION_REQUIRED", "object_id": job.id})
    for job in db.scalars(select(Job).where(Job.state.in_(["needs_attention", "rollback_failed"]))):
        checks.append({"code": "MANUAL_RECOVERY_REQUIRED", "object_id": job.id})
    for allocation in db.scalars(select(StagingAllocation).where(StagingAllocation.state == "cleanup_failed")):
        checks.append({"code": "CLEANUP_FAILED", "object_id": allocation.job_id})
    for repo in db.scalars(select(Repository)):
        if repo.health != "healthy" or repo.imported:
            checks.append({"code": "REPOSITORY_REVIEW_REQUIRED", "object_id": repo.id})
    for instance in db.scalars(select(Instance).where(Instance.readiness == "imported", Instance.archived.is_(False))):
        checks.append({"code": "IMPORTED_INSTANCE_UNBOUND", "object_id": instance.id})
    for policy in db.scalars(select(BackupPolicy).join(Instance, Instance.id == BackupPolicy.instance_id)
                             .where(Instance.readiness == "ready", Instance.is_runner.is_(False))):
        if not policy.runner_id:
            checks.append({"code": "RESTORE_TESTING_NOT_CONFIGURED", "object_id": policy.instance_id})
    if not db.scalar(select(Job.id).where(Job.kind == "recovery_export", Job.state == "succeeded")):
        checks.append({"code": "RECOVERY_KIT_NOT_EXPORTED", "object_id": "controller"})
    unverified = int(db.scalar(select(func.count()).select_from(Secret).where(Secret.binding == "unverified")) or 0)
    if unverified:
        # Rows written before row binding (or by an older process). Resolve with the explicit binding migration.
        checks.append({"code": "SECRET_BINDING_UNVERIFIED", "object_id": "secrets", "count": unverified})
    max_age = timedelta(days=getattr(settings, "controller_backup_max_age_days", 7))
    latest = db.scalar(select(ControllerBackup).where(ControllerBackup.state == "complete")
                       .order_by(ControllerBackup.captured_at.desc()).limit(1))
    if latest is None:
        checks.append({"code": "CONTROLLER_BACKUP_MISSING", "object_id": "controller"})
    elif utc(latest.captured_at) < now() - max_age:
        checks.append({"code": "CONTROLLER_BACKUP_STALE", "object_id": latest.id})
    provider_state = None
    if settings is not None:
        from vaultrewind.storage.credentials import has_pending_credentials, has_unrecovered_drive_sessions
        directory = settings.provider_credential_state_dir or settings.staging_dir.parent / "provider-credentials"
        provider_state = {"pending_updates_present": has_pending_credentials(directory),
                          "registered_sessions_present": has_unrecovered_drive_sessions(directory),
                          "persistent_state_required": True}
    return {"status": "attention" if checks else "healthy", "checks": checks,
            "provider_credential_state": provider_state,
            "read_only": True, "credentials_refreshed": False, "probe_writes": False}

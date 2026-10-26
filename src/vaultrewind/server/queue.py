"""Transactional claims. Lease expiry permits reconciliation, never overlapping ownership."""
import hashlib
import json
from datetime import timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from vaultrewind.core.errors import VaultRewindError

from .db import now, uid, utc
from .models import (
    AuditEvent,
    BackupPolicy,
    Host,
    IdempotencyRecord,
    Instance,
    Job,
    JobEvent,
    JobResource,
    Repository,
    ResourceLease,
)
from .policy import ACTIVE


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def audit(db, actor_id, action, object_id, outcome="accepted", changes=None):
    db.add(AuditEvent(actor_id=actor_id, action=action, object_id=object_id,
                      outcome=outcome, changes=changes or {}))


def ensure_resource(db, key: str):
    dialect = db.bind.dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    db.execute(insert(ResourceLease).values(resource_key=key, generation=0).on_conflict_do_nothing())


def resources_for_instance(db, instance_id, repository_ids=None):
    instance = db.get(Instance, instance_id)
    if not instance:
        raise VaultRewindError("NOT_FOUND", "The instance does not exist.")
    host = db.get(Host, instance.host_id) if instance.host_id else None
    # Imported placeholder registrations have no host yet; their lock key is still unique per instance.
    keys = {f"host:{host.physical_identity or host.id}" if host else f"host:unbound:{instance.id}",
            f"instance:{instance.physical_identity}"}
    keys.update(f"mount:{key}" for key in instance.physical_keys)
    if repository_ids is None:
        repository_ids = list(db.scalars(select(Repository.id).where(Repository.instance_id == instance_id)))
    for rid in repository_ids:
        repo = db.get(Repository, rid)
        if repo:
            keys.add(f"repository:{repo.physical_identity}")
            keys.add(f"credential:{repo.destination_id}")
    return sorted(keys)


def enqueue(db, *, kind, request, key, actor_id=None, instance_id=None, resources=None, deduplicate=True):
    if not key or len(key) > 160:
        raise VaultRewindError("IDEMPOTENCY_KEY_REQUIRED", "Supply an Idempotency-Key of at most 160 characters.")
    scope = f"{actor_id or 'scheduler'}:{kind}"
    fingerprint = digest({k: v for k, v in request.items() if k != "secret_id"}) if request.get("input_hash") else digest(request)
    alias = db.get(IdempotencyRecord, (scope, key))
    if alias:
        if alias.request_hash != fingerprint:
            raise VaultRewindError("IDEMPOTENCY_CONFLICT", "This key was already used with different inputs.")
        return db.get(Job, alias.job_id)
    previous = db.scalar(select(Job).where(Job.idempotency_scope == scope, Job.idempotency_key == key))
    if previous:
        if previous.request_hash != fingerprint:
            raise VaultRewindError("IDEMPOTENCY_CONFLICT", "This idempotency key was already used with different inputs.")
        return previous
    if instance_id and deduplicate and kind in {"backup", "restore"}:
        # Serialize enqueue on the physical identity; duplicate registrations share this row.
        inst = db.get(Instance, instance_id)
        physical = f"instance:{inst.physical_identity}"
        ensure_resource(db, physical)
        db.scalar(select(ResourceLease).where(ResourceLease.resource_key == physical).with_for_update())
        other = db.scalar(select(Job).join(JobResource).where(JobResource.resource_key == physical,
                                                             Job.state.in_(ACTIVE),
                                                             Job.kind.in_(["backup", "restore"])))
        if other:
            if other.request_hash == fingerprint and other.kind == kind:
                db.add(IdempotencyRecord(scope=scope, key=key, request_hash=fingerprint, job_id=other.id))
                return other
            raise VaultRewindError("RESOURCE_BUSY", "Another operation owns this physical instance.")
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance_id)) if instance_id else None
    job = Job(id=uid(), kind=kind, instance_id=instance_id, actor_id=actor_id,
              idempotency_scope=scope, idempotency_key=key, request_hash=fingerprint,
              request=request, policy_revision=policy.revision if policy else None)
    try:
        with db.begin_nested():
            db.add(job)
            db.flush()
    except IntegrityError:
        previous = db.scalar(select(Job).where(Job.idempotency_scope == scope, Job.idempotency_key == key))
        if previous and previous.request_hash == fingerprint:
            return previous
        raise VaultRewindError("IDEMPOTENCY_CONFLICT", "This idempotency key was already used with different inputs.") from None
    keys = resources if resources is not None else resources_for_instance(db, instance_id) if instance_id else []
    for resource in sorted(set(keys)):
        ensure_resource(db, resource)
        db.add(JobResource(job_id=job.id, resource_key=resource))
    db.add(IdempotencyRecord(scope=scope, key=key, request_hash=fingerprint, job_id=job.id))
    event(db, job, "QUEUED")
    audit(db, actor_id, f"{kind}.enqueue", job.id)
    return job


def event(db, job, code, progress=None):
    sequence = (db.scalar(select(func.max(JobEvent.sequence)).where(JobEvent.job_id == job.id)) or 0) + 1
    # Caller holds the job row when workers/events can contend.
    db.add(JobEvent(job_id=job.id, sequence=sequence, phase=job.phase, code=code,
                    progress={k: v for k, v in (progress or {}).items()
                              if k in {"bytes", "elapsed_seconds", "attempt", "snapshot_id", "copy_id"}}))


def claim(db, owner, lease_seconds=60, global_concurrency=2):
    current = now()
    ensure_resource(db, "controller:claim")
    db.scalar(select(ResourceLease).where(ResourceLease.resource_key == "controller:claim").with_for_update())
    running = db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(["running", "cancel_requested"]),
                         Job.lease_expires_at > current))
    if running >= global_concurrency:
        return None
    candidates = db.scalars(select(Job).where(
        or_(Job.state == "queued",
            (Job.state == "waiting_retry") & (Job.next_attempt_at <= current),
            Job.state.in_(["running", "cancel_requested"]) &
            or_(Job.lease_expires_at <= current, Job.lease_expires_at.is_(None))))
        .order_by(Job.created_at).with_for_update(skip_locked=True).limit(100)).all()
    for job in candidates:
        keys = list(db.scalars(select(JobResource.resource_key).where(JobResource.job_id == job.id)
                               .order_by(JobResource.resource_key)))
        leases = list(db.scalars(select(ResourceLease).where(ResourceLease.resource_key.in_(keys))
                                 .order_by(ResourceLease.resource_key).with_for_update()))
        if any(l.owner_job_id and l.owner_job_id != job.id for l in leases):
            continue
        stale = job.lease_owner is not None
        token = max([job.fencing_token] + [l.generation for l in leases]) + 1
        if token > 2**63 - 1:
            raise VaultRewindError("FENCE_EXHAUSTED", "A physical resource fencing generation cannot be advanced safely.")
        for lease in leases:
            lease.owner_job_id, lease.generation = job.id, token
            lease.expires_at = current + timedelta(seconds=lease_seconds)
        job.reconcile_required = job.reconcile_required or stale
        job.lease_owner, job.fencing_token = owner, token
        job.lease_expires_at = current + timedelta(seconds=lease_seconds)
        job.attempts += 1
        if job.state != "cancel_requested":
            job.state = "running"
        job.started_at = job.started_at or current
        event(db, job, "RECONCILING" if stale else "CLAIMED", {"attempt": job.attempts})
        db.flush()
        return job
    return None


def assert_fence(db, job_id, owner, token):
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
    if (job is None or job.lease_owner != owner or job.fencing_token != token or
            not job.lease_expires_at or utc(job.lease_expires_at) <= now() or
            job.state not in {"running", "cancel_requested"}):
        raise VaultRewindError("LEASE_LOST", "The worker lease expired; reconciliation is required.")
    leases = list(db.scalars(select(ResourceLease).join(JobResource,
                         JobResource.resource_key == ResourceLease.resource_key).where(JobResource.job_id == job_id)))
    if any(l.owner_job_id != job_id or l.generation != token for l in leases):
        raise VaultRewindError("LEASE_LOST", "The worker no longer owns its physical resources.")
    return job


def heartbeat(db, job_id, owner, token, seconds):
    job = assert_fence(db, job_id, owner, token)
    deadline = now() + timedelta(seconds=seconds)
    job.lease_expires_at = deadline
    for lease in db.scalars(select(ResourceLease).where(ResourceLease.owner_job_id == job_id)):
        lease.expires_at = deadline


def finish(db, job, state):
    job.state, job.finished_at = state, now()
    event(db, job, state.upper())
    audit(db, job.actor_id, f"{job.kind}.complete", job.id, state)
    if state not in {"needs_attention", "rollback_failed"}:
        for lease in db.scalars(select(ResourceLease).where(ResourceLease.owner_job_id == job.id).with_for_update()):
            lease.owner_job_id, lease.expires_at = None, None
    job.lease_expires_at = None

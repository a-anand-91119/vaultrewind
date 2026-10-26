"""Relational catalog. Recovery content is never cascade deleted with registrations."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, now, uid


def fk(table):
    return ForeignKey(f"{table}.id", ondelete="RESTRICT")


class Row:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Row, Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    timezone: Mapped[str] = mapped_column(String(80), default="UTC")
    __table_args__ = (CheckConstraint("role IN ('administrator','viewer')", name="user_role"),)


class Session(Row, Base):
    __tablename__ = "sessions"
    user_id: Mapped[str] = mapped_column(fk("users"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ControllerState(Base):
    __tablename__ = "controller_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    bootstrap_used: Mapped[bool] = mapped_column(default=False)
    local_storage_root: Mapped[str | None] = mapped_column(Text)
    # Stable controller identity for recovery kits and controller metadata backups.
    controller_id: Mapped[str | None] = mapped_column(String(36))


class Secret(Row, Base):
    __tablename__ = "secrets"
    kind: Mapped[str] = mapped_column(String(40))
    owner_scope: Mapped[str] = mapped_column(String(100))
    envelope: Mapped[str] = mapped_column(Text, deferred=True)
    key_version: Mapped[int] = mapped_column(default=1)
    revision: Mapped[int] = mapped_column(default=1)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Envelope binding version. "row": AAD binds kind/scope/id (current). "unverified": written by a
    # process that may predate row binding; resolved explicitly by the binding migration (see secrets.py).
    # The database default is "unverified" so rows inserted by an older process during a rolling
    # upgrade are never mistaken for row-bound envelopes.
    binding: Mapped[str] = mapped_column(String(20), default="row", server_default="unverified")
    __table_args__ = (CheckConstraint("binding IN ('row','unverified')", name="secret_binding"),)


class Host(Row, Base):
    __tablename__ = "hosts"
    name: Mapped[str] = mapped_column(String(120))
    endpoint: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(default=22)
    username: Mapped[str] = mapped_column(String(80))
    host_public_key: Mapped[str] = mapped_column(Text)
    credential_id: Mapped[str] = mapped_column(fk("secrets"))
    activation_credential_id: Mapped[str | None] = mapped_column(fk("secrets"))
    physical_identity: Mapped[str | None] = mapped_column(String(64), index=True)
    helper_protocol: Mapped[int | None] = mapped_column()
    readiness: Mapped[str] = mapped_column(String(30), default="not_activated")
    archived: Mapped[bool] = mapped_column(default=False)
    revision: Mapped[int] = mapped_column(default=1)


class ActivationPlan(Row, Base):
    __tablename__ = "activation_plans"
    host_id: Mapped[str] = mapped_column(fk("hosts"))
    host_revision: Mapped[int] = mapped_column()
    plan_hash: Mapped[str] = mapped_column(String(64))
    # Encrypted plan can include private enrolled paths; only safe changes are returned.
    secret_id: Mapped[str] = mapped_column(fk("secrets"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Instance(Row, Base):
    __tablename__ = "instances"
    # NULL only for protected placeholder registrations created by a recovery import; enrolling the
    # same remote instance UUID later binds the placeholder to its verified host.
    host_id: Mapped[str | None] = mapped_column(fk("hosts"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    container_id: Mapped[str] = mapped_column(String(128))
    physical_identity: Mapped[str] = mapped_column(String(64), index=True)
    physical_keys: Mapped[list] = mapped_column(JSON, default=list)
    database_engine: Mapped[str] = mapped_column(String(20), default="sqlite")
    configuration_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    revision: Mapped[int] = mapped_column(default=1)
    fingerprint: Mapped[str] = mapped_column(String(64))
    active_generation: Mapped[str | None] = mapped_column(String(100))
    readiness: Mapped[str] = mapped_column(String(30), default="blocked")
    source_health: Mapped[str] = mapped_column(String(30), default="unknown")
    backup_health: Mapped[str] = mapped_column(String(30), default="unprotected")
    last_complete_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archived: Mapped[bool] = mapped_column(default=False)
    is_runner: Mapped[bool] = mapped_column(default=False)
    __table_args__ = (CheckConstraint("database_engine = 'sqlite'", name="instance_sqlite"),)


class InstanceDependency(Row, Base):
    __tablename__ = "instance_dependencies"
    instance_id: Mapped[str] = mapped_column(fk("instances"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    reference_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    required: Mapped[bool] = mapped_column(default=True)
    state: Mapped[str] = mapped_column(String(30), default="unenrolled")


class StorageDestination(Row, Base):
    __tablename__ = "storage_destinations"
    name: Mapped[str] = mapped_column(String(120))
    backend: Mapped[str] = mapped_column(String(20))
    configuration_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    credential_id: Mapped[str | None] = mapped_column(fk("secrets"))
    revision: Mapped[int] = mapped_column(default=1)
    health: Mapped[str] = mapped_column(String(30), default="untested")
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger)
    archived: Mapped[bool] = mapped_column(default=False)
    __table_args__ = (CheckConstraint("backend IN ('local','s3','drive')", name="destination_backend"),)


class Repository(Row, Base):
    __tablename__ = "repositories"
    # NULL instance only for purpose="controller" (controller metadata backups under a fixed namespace).
    instance_id: Mapped[str | None] = mapped_column(fk("instances"), index=True)
    destination_id: Mapped[str] = mapped_column(fk("storage_destinations"))
    configuration_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    key_id: Mapped[str] = mapped_column(fk("secrets"))
    physical_identity: Mapped[str] = mapped_column(String(64), unique=True)
    storage_format: Mapped[str] = mapped_column(String(20), default="restic-v2")
    purpose: Mapped[str] = mapped_column(String(20), default="instance", server_default="instance")
    health: Mapped[str] = mapped_column(String(30), default="uninitialized")
    imported: Mapped[bool] = mapped_column(default=False)
    last_full_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        UniqueConstraint("instance_id", "destination_id", name="repository_pair"),
        CheckConstraint("purpose IN ('instance','controller')", name="repository_purpose"),
        CheckConstraint(
            "(purpose = 'controller') = (instance_id IS NULL)", name="repository_instance_purpose"
        ),
        Index(
            "controller_repository_destination",
            "destination_id",
            unique=True,
            postgresql_where=text("purpose = 'controller'"),
            sqlite_where=text("purpose = 'controller'"),
        ),
    )


class BackupPolicy(Row, Base):
    __tablename__ = "backup_policies"
    instance_id: Mapped[str] = mapped_column(fk("instances"), unique=True)
    revision: Mapped[int] = mapped_column(default=1)
    enabled: Mapped[bool] = mapped_column(default=True)
    schedule_kind: Mapped[str] = mapped_column(String(20), default="daily")
    timezone: Mapped[str] = mapped_column(String(80), default="UTC")
    daily_time: Mapped[str] = mapped_column(String(5), default="02:00")
    interval_hours: Mapped[int] = mapped_column(default=1)
    retention_days: Mapped[int | None] = mapped_column(default=30)
    outage_seconds: Mapped[int] = mapped_column(default=300)
    maintenance_seconds: Mapped[int] = mapped_column(default=900)
    validation_seconds: Mapped[int] = mapped_column(default=180)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    runner_id: Mapped[str | None] = mapped_column(fk("instances"))
    next_verify_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("retention_days IS NULL OR retention_days BETWEEN 1 AND 3650", name="retention_days"),
        CheckConstraint("schedule_kind IN ('daily','hourly')", name="schedule_kind"),
    )


class PolicyDestination(Base):
    __tablename__ = "policy_destinations"
    policy_id: Mapped[str] = mapped_column(fk("backup_policies"), primary_key=True)
    repository_id: Mapped[str] = mapped_column(fk("repositories"), primary_key=True)
    required: Mapped[bool] = mapped_column(default=True)


class Snapshot(Row, Base):
    __tablename__ = "snapshots"
    instance_id: Mapped[str] = mapped_column(fk("instances"), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    capture_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    trigger: Mapped[str] = mapped_column(String(20))
    manifest_hash: Mapped[str] = mapped_column(String(64))
    completeness: Mapped[str] = mapped_column(String(30))
    logical_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    image_id: Mapped[str] = mapped_column(String(100))
    vaultwarden_version: Mapped[str] = mapped_column(String(100))
    source_state: Mapped[str] = mapped_column(String(30))
    verification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    safety_for_job_id: Mapped[str | None] = mapped_column(fk("jobs"), use_existing_column=True)
    imported: Mapped[bool] = mapped_column(default=False)


class SnapshotCopy(Row, Base):
    __tablename__ = "snapshot_copies"
    snapshot_id: Mapped[str] = mapped_column(fk("snapshots"), index=True)
    repository_id: Mapped[str] = mapped_column(fk("repositories"), index=True)
    restic_snapshot_id: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(30), default="pending")
    manifest_hash: Mapped[str | None] = mapped_column(String(64))
    logical_bytes: Mapped[int | None] = mapped_column(BigInteger)
    stored_bytes: Mapped[int | None] = mapped_column(BigInteger)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    data_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(80))
    __table_args__ = (UniqueConstraint("snapshot_id", "repository_id", name="snapshot_repository"),)


class Job(Row, Base):
    __tablename__ = "jobs"
    kind: Mapped[str] = mapped_column(String(40), index=True)
    instance_id: Mapped[str | None] = mapped_column(fk("instances"), index=True)
    actor_id: Mapped[str | None] = mapped_column(fk("users"))
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(40), default="queued")
    idempotency_scope: Mapped[str] = mapped_column(String(100))
    idempotency_key: Mapped[str] = mapped_column(String(160))
    request_hash: Mapped[str] = mapped_column(String(64))
    request: Mapped[dict] = mapped_column(JSON)
    policy_revision: Mapped[int | None] = mapped_column()
    lease_owner: Mapped[str | None] = mapped_column(String(100))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fencing_token: Mapped[int] = mapped_column(BigInteger, default=0)
    attempts: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reconcile_required: Mapped[bool] = mapped_column(default=False)
    content_commit: Mapped[str] = mapped_column(String(30), default="unknown")
    required_copy_outcome: Mapped[str] = mapped_column(String(30), default="unknown")
    source_service_outcome: Mapped[str] = mapped_column(String(30), default="unknown")
    target_activation_outcome: Mapped[str] = mapped_column(String(30), default="not_started")
    error_code: Mapped[str | None] = mapped_column(String(80))
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    __table_args__ = (UniqueConstraint("idempotency_scope", "idempotency_key", name="job_idempotency"),)


class JobResource(Base):
    __tablename__ = "job_resources"
    job_id: Mapped[str] = mapped_column(fk("jobs"), primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(180), primary_key=True)


class ResourceLease(Base):
    __tablename__ = "resource_leases"
    resource_key: Mapped[str] = mapped_column(String(180), primary_key=True)
    owner_job_id: Mapped[str | None] = mapped_column(fk("jobs"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    generation: Mapped[int] = mapped_column(BigInteger, default=0)


class JobStep(Row, Base):
    __tablename__ = "job_steps"
    job_id: Mapped[str] = mapped_column(fk("jobs"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    sequence: Mapped[int] = mapped_column()
    state: Mapped[str] = mapped_column(String(20), default="started")
    attempt: Mapped[int] = mapped_column(default=1)
    fencing_token: Mapped[int] = mapped_column(BigInteger)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("job_id", "name", name="job_step_name"),)


class JobEvent(Row, Base):
    __tablename__ = "job_events"
    job_id: Mapped[str] = mapped_column(fk("jobs"), index=True)
    sequence: Mapped[int] = mapped_column()
    phase: Mapped[str] = mapped_column(String(40))
    code: Mapped[str] = mapped_column(String(80))
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    __table_args__ = (UniqueConstraint("job_id", "sequence", name="job_event_sequence"),)


class SnapshotProtection(Row, Base):
    __tablename__ = "snapshot_protections"
    snapshot_id: Mapped[str] = mapped_column(fk("snapshots"), index=True)
    copy_id: Mapped[str | None] = mapped_column(fk("snapshot_copies"))
    reason: Mapped[str] = mapped_column(String(40))
    actor_id: Mapped[str | None] = mapped_column(fk("users"))
    job_id: Mapped[str | None] = mapped_column(fk("jobs"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RestorePlan(Row, Base):
    __tablename__ = "restore_plans"
    snapshot_id: Mapped[str] = mapped_column(fk("snapshots"))
    copy_id: Mapped[str] = mapped_column(fk("snapshot_copies"))
    target_id: Mapped[str] = mapped_column(fk("instances"))
    actor_id: Mapped[str] = mapped_column(fk("users"))
    target_revision: Mapped[int] = mapped_column()
    policy_revision: Mapped[int] = mapped_column()
    target_fingerprint: Mapped[str] = mapped_column(String(64))
    manifest_hash: Mapped[str] = mapped_column(String(64))
    mappings_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    job_id: Mapped[str | None] = mapped_column(fk("jobs"))


class DeletionPlan(Row, Base):
    __tablename__ = "deletion_plans"
    instance_id: Mapped[str] = mapped_column(fk("instances"))
    actor_id: Mapped[str] = mapped_column(fk("users"))
    policy_revision: Mapped[int] = mapped_column()
    copy_ids: Mapped[list] = mapped_column(JSON)
    token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    job_id: Mapped[str | None] = mapped_column(fk("jobs"))


class VerificationRun(Row, Base):
    __tablename__ = "verification_runs"
    snapshot_id: Mapped[str] = mapped_column(fk("snapshots"))
    copy_id: Mapped[str] = mapped_column(fk("snapshot_copies"))
    job_id: Mapped[str] = mapped_column(fk("jobs"))
    runner_id: Mapped[str | None] = mapped_column(fk("instances"))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[str] = mapped_column(String(30), default="pending")
    cleanup_result: Mapped[str] = mapped_column(String(30), default="pending")
    duration_seconds: Mapped[int | None] = mapped_column()


class ScheduleOccurrence(Row, Base):
    __tablename__ = "schedule_occurrences"
    policy_id: Mapped[str] = mapped_column(fk("backup_policies"))
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    kind: Mapped[str] = mapped_column(String(30), default="backup")
    job_id: Mapped[str | None] = mapped_column(fk("jobs"))
    catch_up: Mapped[bool] = mapped_column(default=False)
    coalesced: Mapped[int] = mapped_column(default=0)
    __table_args__ = (UniqueConstraint("policy_id", "scheduled_at", "kind", name="schedule_occurrence"),)


class AuditEvent(Row, Base):
    __tablename__ = "audit_events"
    actor_id: Mapped[str | None] = mapped_column(fk("users"))
    action: Mapped[str] = mapped_column(String(60))
    object_id: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(40))
    changes: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Row, Base):
    __tablename__ = "alerts"
    dedupe_key: Mapped[str] = mapped_column(String(180), unique=True)
    instance_id: Mapped[str | None] = mapped_column(fk("instances"))
    code: Mapped[str] = mapped_column(String(80))
    active: Mapped[bool] = mapped_column(default=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NotificationChannel(Row, Base):
    __tablename__ = "notification_channels"
    kind: Mapped[str] = mapped_column(String(20))
    configuration_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    enabled: Mapped[bool] = mapped_column(default=True)


class NotificationDelivery(Row, Base):
    __tablename__ = "notification_deliveries"
    event_id: Mapped[str] = mapped_column(fk("alerts"))
    channel_id: Mapped[str] = mapped_column(fk("notification_channels"))
    recovery: Mapped[bool] = mapped_column(default=False)
    attempt: Mapped[int] = mapped_column(default=0)
    state: Mapped[str] = mapped_column(String(30), default="pending")
    error_code: Mapped[str | None] = mapped_column(String(80))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("event_id", "channel_id", "recovery", name="notification_once"),)


class OAuthState(Row, Base):
    __tablename__ = "oauth_states"
    destination_id: Mapped[str] = mapped_column(fk("storage_destinations"))
    session_id: Mapped[str] = mapped_column(fk("sessions"))
    state_hash: Mapped[str] = mapped_column(String(64), unique=True)
    verifier_secret_id: Mapped[str] = mapped_column(fk("secrets"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class StagingAllocation(Row, Base):
    __tablename__ = "staging_allocations"
    job_id: Mapped[str] = mapped_column(fk("jobs"), unique=True)
    reserved_bytes: Mapped[int] = mapped_column(BigInteger)
    actual_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    state: Mapped[str] = mapped_column(String(30), default="reserved")
    retry_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(80))


Index("job_claim", Job.state, Job.next_attempt_at, Job.created_at)


class ControllerBackup(Row, Base):
    """Durable record of a sealed controller metadata backup committed to a destination repository."""

    __tablename__ = "controller_backups"
    job_id: Mapped[str] = mapped_column(fk("jobs"), unique=True)
    destination_id: Mapped[str] = mapped_column(fk("storage_destinations"))
    repository_id: Mapped[str] = mapped_column(fk("repositories"))
    snapshot_uuid: Mapped[str] = mapped_column(String(36), unique=True)
    restic_snapshot_id: Mapped[str | None] = mapped_column(String(64))
    manifest_hash: Mapped[str | None] = mapped_column(String(64))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(30), default="pending")
    alembic_version: Mapped[str | None] = mapped_column(String(64))
    tables: Mapped[int] = mapped_column(default=0)
    rows: Mapped[int] = mapped_column(default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    pg_dump_included: Mapped[bool] = mapped_column(default=False)
    error_code: Mapped[str | None] = mapped_column(String(80))


class ControllerBackupPolicy(Base):
    """Singleton durable policy for backing up this controller's own PostgreSQL catalog."""

    __tablename__ = "controller_backup_policies"
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    destination_id: Mapped[str] = mapped_column(fk("storage_destinations"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    schedule_kind: Mapped[str] = mapped_column(String(20), default="daily")
    timezone: Mapped[str] = mapped_column(String(80), default="UTC")
    daily_time: Mapped[str] = mapped_column(String(5), default="02:00")
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    revision: Mapped[int] = mapped_column(default=1)
    __table_args__ = (
        UniqueConstraint("destination_id", name="controller_backup_policy_destination"),
        CheckConstraint("id = 1", name="controller_backup_policy_singleton"),
        CheckConstraint("schedule_kind = 'daily'", name="controller_backup_policy_schedule"),
    )


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    scope: Mapped[str] = mapped_column(String(100), primary_key=True)
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    job_id: Mapped[str] = mapped_column(fk("jobs"))


# Identity/content fields and the application audit are append-only through the ORM.
# Migration triggers also enforce this boundary for ordinary SQL clients.
from sqlalchemy import event as orm_event
from sqlalchemy import inspect as orm_inspect

from vaultrewind.core.errors import VaultRewindError


@orm_event.listens_for(Snapshot, "before_update")
def immutable_snapshot(mapper, connection, target):
    if any(attr.history.has_changes() for attr in orm_inspect(target).attrs):
        raise VaultRewindError("IMMUTABLE_SNAPSHOT", "Snapshot identity and captured content are immutable.")


@orm_event.listens_for(AuditEvent, "before_update")
@orm_event.listens_for(AuditEvent, "before_delete")
def append_only_audit(mapper, connection, target):
    raise VaultRewindError("IMMUTABLE_AUDIT", "The application audit trail is append-only.")

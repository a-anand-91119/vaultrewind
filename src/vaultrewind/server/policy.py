"""Wall-clock retention and civil-time scheduling. All cutoffs are controller UTC."""
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .db import now, utc
from .models import (
    BackupPolicy,
    Instance,
    Job,
    Repository,
    Snapshot,
    SnapshotCopy,
    SnapshotProtection,
    VerificationRun,
)

ACTIVE = {"queued", "running", "waiting_retry", "cancel_requested", "needs_attention", "rollback_failed"}
TERMINAL = {"succeeded", "partial", "failed", "cancelled", "rolled_back", "rollback_failed", "needs_attention"}


def validate_schedule(kind: str, zone: str, daily_time: str, interval_hours: int):
    try:
        ZoneInfo(zone)
        parsed = time.fromisoformat(daily_time)
        if len(daily_time) != 5 or parsed.tzinfo or kind not in {"daily", "hourly"} or not 1 <= interval_hours <= 24:
            raise ValueError()
    except (ValueError, ZoneInfoNotFoundError):
        raise VaultRewindError("SCHEDULE_INVALID", "Select a valid timezone, HH:MM time and hourly interval.") from None


def first_valid(local: datetime, zone: ZoneInfo) -> datetime:
    # fold=0 chooses the first occurrence on fall-back. Spring gaps advance minute by minute.
    for _ in range(24 * 60 + 1):
        candidate = local.replace(tzinfo=zone, fold=0)
        instant = candidate.astimezone(UTC)
        if instant.astimezone(zone).replace(tzinfo=None) == local:
            return instant
        local += timedelta(minutes=1)
    raise VaultRewindError("SCHEDULE_INVALID", "The selected civil date cannot be resolved.")


def next_run(policy: BackupPolicy, after: datetime) -> datetime:
    after = utc(after)
    validate_schedule(policy.schedule_kind, policy.timezone, policy.daily_time, policy.interval_hours)
    if policy.schedule_kind == "hourly":
        return after + timedelta(hours=policy.interval_hours)
    zone = ZoneInfo(policy.timezone)
    day = after.astimezone(zone).date()
    for offset in range(3):
        local = datetime.combine(day + timedelta(days=offset), time.fromisoformat(policy.daily_time))
        candidate = first_valid(local, zone)
        if candidate > after:
            return candidate
    raise VaultRewindError("SCHEDULE_INVALID", "Cannot calculate the next occurrence.")


def advance_missed(policy: BackupPolicy, due: datetime, current: datetime) -> tuple[datetime, int]:
    due, current = utc(due), utc(current)
    if policy.schedule_kind == "hourly":
        count = int((current - due).total_seconds() // (policy.interval_hours * 3600)) + 1
        return due + timedelta(hours=max(1, count) * policy.interval_hours), max(0, count - 1)
    candidate = next_run(policy, current)
    zone = ZoneInfo(policy.timezone)
    day = current.astimezone(zone).date()
    today = first_valid(datetime.combine(day, time.fromisoformat(policy.daily_time)), zone)
    latest_day = day if today <= current else day - timedelta(days=1)
    missed = max(0, (latest_day - due.astimezone(zone).date()).days)
    return candidate, missed


def is_overdue(db, policy, current=None):
    from .models import ScheduleOccurrence
    if not policy.enabled:
        return False
    current = utc(current or now())
    if policy.next_run_at and utc(policy.next_run_at) < current:
        return True
    occurrence = db.scalar(select(ScheduleOccurrence).where(ScheduleOccurrence.policy_id == policy.id,
        ScheduleOccurrence.kind == "backup", ScheduleOccurrence.scheduled_at <= current)
        .order_by(ScheduleOccurrence.scheduled_at.desc()).limit(1))
    if not occurrence:
        return False
    expected = utc(occurrence.scheduled_at)
    if occurrence.coalesced:
        if policy.schedule_kind == "hourly":
            expected += timedelta(hours=policy.interval_hours * occurrence.coalesced)
        else:
            zone = ZoneInfo(policy.timezone)
            day = expected.astimezone(zone).date() + timedelta(days=occurrence.coalesced)
            expected = first_valid(datetime.combine(day, time.fromisoformat(policy.daily_time)), zone)
    instance = db.get(Instance, policy.instance_id)
    return not instance.last_complete_at or utc(instance.last_complete_at) < expected


_STORED = object()


def retention_preview(db, instance_id: str, current: datetime | None = None, *, retention_days=_STORED) -> dict:
    """Exact UTC retention preview. ``retention_days`` previews a hypothetical value (None = keep forever)
    without writing the policy; the freeze reasons and protections are evaluated identically."""
    current = utc(current or now())
    instance = db.get(Instance, instance_id)
    policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance_id))
    if instance is None or policy is None:
        raise VaultRewindError("NOT_FOUND", "The instance or its policy does not exist.")
    hypothetical = retention_days is not _STORED
    days = policy.retention_days if not hypothetical else retention_days
    if days is not None and (type(days) is not int or not 1 <= days <= 3650):
        raise VaultRewindError("VALIDATION_ERROR", "Retention days must be between 1 and 3650 or null.")
    reasons = []
    if instance.backup_health not in {"healthy"}:
        reasons.append("backup_policy_degraded")
    if is_overdue(db, policy, current):
        reasons.append("backup_overdue")
    latest = db.scalar(select(Job).where(Job.instance_id == instance_id,
                                        Job.kind.in_(["backup", "restore", "verify", "retention", "delete", "retry_copy"]), Job.state.in_(TERMINAL))
                       .order_by(Job.created_at.desc()).limit(1))
    if latest and latest.state in {"failed", "partial", "needs_attention", "rollback_failed", "rolled_back"}:
        reasons.append("latest_operation_failed")
    repos = list(db.scalars(select(Repository).where(Repository.instance_id == instance_id)))
    if any(r.imported or r.health not in {"healthy"} for r in repos):
        reasons.append("repository_uncertain_or_imported")
    pairs = db.execute(select(SnapshotCopy, Snapshot).join(Snapshot, Snapshot.id == SnapshotCopy.snapshot_id)
                       .where(Snapshot.instance_id == instance_id, SnapshotCopy.state == "complete")
                       .order_by(Snapshot.captured_at.desc(), Snapshot.id.desc())).all()
    newest = {}
    newest_tested = {}
    tested = {r.snapshot_id for r in db.scalars(select(VerificationRun).where(VerificationRun.result == "succeeded"))
              if r.evidence.get("application_started") is True}
    for copy, snapshot in pairs:
        if snapshot.completeness == "complete":
            newest.setdefault(copy.repository_id, snapshot.id)
            if snapshot.id in tested:
                newest_tested.setdefault(copy.repository_id, snapshot.id)
    protections = list(db.scalars(select(SnapshotProtection).join(Snapshot)
                                 .where(Snapshot.instance_id == instance_id)))
    active_inputs = set()
    for job in db.scalars(select(Job).where(Job.state.in_(ACTIVE), Job.kind.in_(["restore", "verify", "retry_copy"]))):
        if job.request.get("snapshot_id"):
            active_inputs.add(job.request["snapshot_id"])
    cutoff = current - timedelta(days=days) if days is not None else None
    candidates, entries = [], []
    for copy, snapshot in pairs:
        protected = []
        if snapshot.id == newest.get(copy.repository_id):
            protected.append("newest_complete")
        if snapshot.id == newest_tested.get(copy.repository_id):
            protected.append("newest_restore_tested")
        if snapshot.imported or utc(snapshot.captured_at) > current:
            protected.append("import_review")
        if snapshot.id in active_inputs:
            protected.append("active_restore_input")
        for p in protections:
            if (p.snapshot_id == snapshot.id and (not p.copy_id or p.copy_id == copy.id)
                    and (not p.expires_at or utc(p.expires_at) > current)):
                protected.append(p.reason)
        expired = cutoff is not None and utc(snapshot.captured_at) < cutoff
        eligible = bool(expired and not protected and not reasons)
        if eligible:
            candidates.append(copy.id)
        entries.append({"snapshot_id": snapshot.id, "copy_id": copy.id, "repository_id": copy.repository_id,
                        "captured_at": utc(snapshot.captured_at).isoformat(), "eligible": eligible,
                        "protections": sorted(set(protected)),
                        "expires_at": (utc(snapshot.captured_at) + timedelta(days=days)).isoformat()
                        if days is not None else None})
    return {"instance_id": instance_id, "policy_revision": policy.revision, "as_of": current.isoformat(),
            "retention_days": days, "hypothetical": hypothetical,
            "cutoff": cutoff.isoformat() if cutoff else None, "frozen": bool(reasons),
            "freeze_reasons": sorted(set(reasons)), "copy_ids": sorted(candidates), "entries": entries}

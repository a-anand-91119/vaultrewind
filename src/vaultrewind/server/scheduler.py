"""Durable occurrence keys and one catch-up per policy; no production restore schedules."""
from datetime import timedelta

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .db import now, utc
from .models import BackupPolicy, ScheduleOccurrence, Snapshot, SnapshotCopy
from .policy import advance_missed
from .queue import enqueue, resources_for_instance
from .services import backup_request


def tick(db, current=None, *, settings=None, store=None):
    current = utc(current or now())
    policies = list(db.scalars(select(BackupPolicy).where(BackupPolicy.enabled.is_(True))
                              .order_by(BackupPolicy.id).with_for_update(skip_locked=True)))
    result = []
    for policy in policies:
        if policy.next_run_at and utc(policy.next_run_at) <= current:
            due = utc(policy.next_run_at)
            upcoming, coalesced = advance_missed(policy, due, current)
            key = f"schedule:{policy.id}:{due.isoformat()}"
            previous = db.scalar(select(ScheduleOccurrence).where(ScheduleOccurrence.policy_id == policy.id,
                                 ScheduleOccurrence.scheduled_at == due, ScheduleOccurrence.kind == "backup"))
            if not previous:
                occurrence = ScheduleOccurrence(policy_id=policy.id, scheduled_at=due,
                    catch_up=coalesced > 0, coalesced=coalesced, kind="backup")
                try:
                    req = backup_request(db, policy.instance_id, trigger="scheduled")
                    req["scheduled_occurrence"] = due.isoformat()
                    job = enqueue(db, kind="backup", request=req, key=key, instance_id=policy.instance_id)
                    occurrence.job_id = job.id
                    result.append(job.id)
                except VaultRewindError as exc:
                    # Persist skipped occurrence rather than flood after restart or overlap live work.
                    from .notifications import raise_alert
                    raise_alert(db, policy.instance_id, exc.code)
                db.add(occurrence)
            policy.next_run_at = upcoming
        for field, kind in (("next_verify_at", "full_data"), ("next_test_at", "application")):
            due = getattr(policy, field)
            if not due or utc(due) > current:
                continue
            if kind == "application" and not policy.runner_id:
                from .notifications import raise_alert
                raise_alert(db, policy.instance_id, "RESTORE_TESTING_NOT_CONFIGURED")
                setattr(policy, field, current + timedelta(days=7))
                continue
            pairs = db.execute(select(SnapshotCopy, Snapshot).join(Snapshot).where(
                Snapshot.instance_id == policy.instance_id, Snapshot.completeness == "complete",
                SnapshotCopy.state == "complete").order_by(Snapshot.captured_at.desc())).all()
            # Full checks cover each repository; application test needs one equivalent copy.
            seen = set()
            for copy, snapshot in pairs:
                if copy.repository_id in seen:
                    continue
                seen.add(copy.repository_id)
                keys = resources_for_instance(db, policy.instance_id, [copy.repository_id])
                if kind == "application":
                    keys += resources_for_instance(db, policy.runner_id, [])
                job = enqueue(db, kind="verify", request={"snapshot_id": snapshot.id, "copy_id": copy.id,
                        "level": kind, "runner_id": policy.runner_id}, instance_id=policy.instance_id,
                        key=f"verify:{policy.id}:{kind}:{utc(due).isoformat()}:{copy.repository_id}", resources=keys)
                result.append(job.id)
                if kind == "application":
                    break
            db.add(ScheduleOccurrence(policy_id=policy.id, scheduled_at=due, kind=kind,
                                     job_id=result[-1] if pairs and result else None, catch_up=True, coalesced=0))
            setattr(policy, field, current + timedelta(days=7))
    if settings is not None and store is not None:
        from .controller_backup import schedule_due
        from .services import enqueue_controller_backup
        occurrence = schedule_due(db, current)
        if occurrence:
            result.append(enqueue_controller_backup(db, store, settings, occurrence["destination_id"],
                key=f"controller-backup:{occurrence['policy_id']}:{occurrence['scheduled_at']}",
                scheduled_at=occurrence["scheduled_at"]).id)
    return result

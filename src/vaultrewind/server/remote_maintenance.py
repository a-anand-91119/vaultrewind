"""Job-bound remote accounting and explicit cleanup; never accepts a host path."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .db import now
from .models import Host, Instance, Job, JobResource
from .queue import enqueue, resources_for_instance

CLEANUP_KINDS = {"generations", "discard_candidate", "staging"}
SAFE_STATES = {"succeeded", "partial", "failed", "cancelled", "rolled_back"}
SAFE_PHASES = {"complete", "data_restored_service_stopped", "captured", "cleaned",
               "failed_safe", "cancelled", "rolled_back"}
COMPLETE_PHASES = {"complete", "data_restored_service_stopped"}
UNCERTAIN_ACTIVATION = {"activation_started", "activated", "needs_attention", "unknown", "uncertain"}
MAX_OPERATIONS = 500


def _error(code, message):
    raise VaultRewindError(code, message)


def _instance(db, instance_id):
    instance = db.get(Instance, instance_id)
    if instance is None:
        _error("NOT_FOUND", "The instance does not exist.")
    host = db.get(Host, instance.host_id) if instance.host_id else None
    if instance.archived or host is None or host.archived or host.readiness != "ready" or host.helper_protocol != 1:
        _error("HELPER_NOT_READY", "A ready enrolled host with helper protocol 1 is required.")
    return instance


def _historical(db, job_id, instance_id=None):
    job = db.get(Job, job_id)
    if job is None or job.kind not in {"backup", "restore"} or not job.instance_id:
        _error("NOT_FOUND", "A historical backup or restore job is required.")
    if instance_id is not None and job.instance_id != instance_id:
        _error("TARGET_CHANGED", "The historical job belongs to another instance.")
    _instance(db, job.instance_id)
    if job.kind == "restore" and job.request.get("target_id") != job.instance_id:
        _error("TARGET_CHANGED", "The historical restore target does not match its instance.")
    # Instance/inode identities change during a successful restore. The canonical mount-path
    # lease and host identity survive it; include both old and new keys in maintenance leases.
    current = set(resources_for_instance(db, job.instance_id, []))
    previous = set(db.scalars(select(JobResource.resource_key).where(JobResource.job_id == job.id)))
    if (not {k for k in current if k.startswith("host:")} <= previous
            or not {k for k in current & previous if k.startswith("mount:")}):
        _error("TARGET_CHANGED", "Historical host and physical data ownership cannot be verified.")
    return job, current | {k for k in previous if k.startswith(("host:", "instance:", "mount:"))}


def validate_cleanup(job, kind, status=None, *, current=None):
    """Controller gate; the root-owned helper performs final identity and grace checks."""
    if kind not in CLEANUP_KINDS:
        _error("VALIDATION_ERROR", "Select staging, generations or discard_candidate cleanup.")
    if job.state not in SAFE_STATES or job.target_activation_outcome in UNCERTAIN_ACTIVATION:
        _error("CLEANUP_UNSAFE", "Active or unresolved jobs must be reconciled before cleanup.")
    if kind == "generations" and (job.kind != "restore" or job.state != "succeeded"
                                  or job.target_activation_outcome not in COMPLETE_PHASES):
        _error("CLEANUP_UNSAFE", "Generation cleanup requires a completed activated restore.")
    if kind == "discard_candidate" and (job.kind != "restore" or job.target_activation_outcome not in {"not_started", "candidate_validated"}):
        _error("CLEANUP_UNSAFE", "Only a never-activated restored candidate may be discarded.")
    if status is None:
        return
    if status.get("exists") is not True or status.get("phase") not in SAFE_PHASES:
        _error("CLEANUP_UNSAFE", "The remote journal is missing, active or unresolved.")
    if status.get("activation_started") is True and status.get("phase") not in COMPLETE_PHASES:
        _error("RESTORE_ACTIVATION_UNCERTAIN", "Activation may have occurred; preserve all generations.")
    if kind == "generations":
        if status.get("kind") != "restore" or status.get("phase") not in COMPLETE_PHASES:
            _error("CLEANUP_UNSAFE", "Only a completed restored generation may be retired.")
        deadline = status.get("rollback_cleanup_after")
        if type(deadline) not in (int, float) or not 0 < deadline < 253402300800:
            _error("REMOTE_ACCOUNTING_UNAVAILABLE", "The helper did not report a valid rollback grace deadline.")
        if (current or now()).timestamp() < deadline:
            _error("CLEANUP_GRACE_PERIOD", "The root-owned rollback preservation grace period has not elapsed.")
    # Protocol 1 journals historically omitted this flag until activation. These three
    # helper-verified phases are reachable only through pre-activation recovery. An
    # explicit null is malformed evidence, not the historical absence convention.
    never_activated = "activation_started" not in status or status["activation_started"] is False
    if kind == "discard_candidate" and (status.get("kind") != "restore"
            or status.get("phase") not in {"rolled_back", "failed_safe", "cancelled"}
            or not never_activated):
        _error("CLEANUP_UNSAFE", "Candidate disposal requires positive evidence that activation never began.")


def queue_inventory(db, instance_id, *, key, actor_id=None):
    _instance(db, instance_id)
    return enqueue(db, kind="remote_inventory", request={}, key=key, actor_id=actor_id,
                   instance_id=instance_id, resources=resources_for_instance(db, instance_id, []))


def queue_cleanup(db, historical_job_id, kind, *, key, actor_id=None):
    job, resources = _historical(db, historical_job_id)
    validate_cleanup(job, kind)
    return enqueue(db, kind="remote_cleanup", request={"historical_job_id": job.id, "kind": kind},
                   key=key, actor_id=actor_id, instance_id=job.instance_id, resources=sorted(resources))


def _count(value):
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None


def _accounting(preflight):
    if preflight.get("protocol_version") != 1:
        _error("HELPER_NOT_READY", "A compatible helper protocol is required.")
    mapping = {"source_staging_bytes": "source_staging_bytes", "image_cache_bytes": "image_cache_bytes",
               "staging_bytes": "staging_bytes", "quota_bytes": "staging_quota_bytes"}
    result = {key: _count(preflight.get(source)) for key, source in mapping.items()}
    if any(v is None for v in result.values()):
        _error("REMOTE_ACCOUNTING_UNAVAILABLE", "Upgrade the helper to report source staging and image cache accounting.")
    if result["source_staging_bytes"] + result["image_cache_bytes"] != result["staging_bytes"]:
        _error("REMOTE_ACCOUNTING_INVALID", "Remote staging counters are inconsistent.")
    return result


def _status_identity(status, job_id, remote_id):
    if status.get("exists") is True and (status.get("operation_id") != job_id or status.get("instance_id") != remote_id):
        _error("TARGET_CHANGED", "The remote journal does not belong to this historical job and instance.")


def _operation(job, status):
    phase = status.get("phase")
    known_phases = SAFE_PHASES | {"activation_started", "activated", "needs_attention", "rollback_failed",
                               "source_recovery_failed", "preparing", "validating", "switching", "staging"}
    result = {"job_id": job.id, "kind": job.kind, "state": job.state,
              "remote_phase": phase if phase in known_phases else "unknown",
              "generation_bytes": _count(status.get("generation_logical_bytes")),
              "retained_generation_bytes": _count(status.get("retained_generation_logical_bytes")),
              "staging_cleaned": status.get("staging_cleaned") is True,
              "generations_cleaned": status.get("generations_cleaned") is True,
              "candidate_cleanup_outcome": status.get("candidate_cleanup_outcome")
                  if status.get("candidate_cleanup_outcome") in {"complete", "pending", "failed", "partial", "incomplete"} else "unknown",
              "cleanup_after": None, "eligible_cleanup": [], "cleanup_blocked": {}}
    deadline = status.get("rollback_cleanup_after")
    if type(deadline) in (int, float) and 0 < deadline < 253402300800:
        result["cleanup_after"] = datetime.fromtimestamp(deadline, UTC).isoformat()
    if status.get("exists") is not True:
        result["accounting_error"] = "REMOTE_JOURNAL_MISSING"
    elif job.kind == "restore" and (result["generation_bytes"] is None
            or (phase in COMPLETE_PHASES and not status.get("empty_target") and result["retained_generation_bytes"] is None)):
        result["accounting_error"] = "REMOTE_ACCOUNTING_UNAVAILABLE"
    for kind in sorted(CLEANUP_KINDS):
        if ((kind == "staging" and result["staging_cleaned"])
                or (kind == "generations" and result["generations_cleaned"])
                or (kind == "discard_candidate" and result["candidate_cleanup_outcome"] == "complete")):
            continue
        try:
            validate_cleanup(job, kind, status)
            result["eligible_cleanup"].append(kind)
        except VaultRewindError as exc:
            result["cleanup_blocked"][kind] = exc.code
    return result


def storage_view(db, instance_id):
    """GET is cached only: never SSH, probes, credential refresh or remote mutations."""
    if db.get(Instance, instance_id) is None:
        _error("NOT_FOUND", "The instance does not exist.")
    latest = db.scalar(select(Job).where(Job.instance_id == instance_id,
        Job.kind.in_(["remote_inventory", "remote_cleanup"]), Job.state.in_(["succeeded", "partial"]))
        .order_by(Job.finished_at.desc(), Job.created_at.desc()).limit(1))
    inventory = latest.result.get("remote_storage") if latest else None
    if not isinstance(inventory, dict):
        return {"as_of": None, "source_staging_bytes": None, "image_cache_bytes": None,
                "staging_bytes": None, "quota_bytes": None, "operations": []}
    # The only writer is _inventory(), which builds its nested contents from primitive allowlists.
    return inventory


def _inventory(ctx, remote, rid):
    ctx.guard()
    accounting_error = None
    try:
        preflight = asyncio.run(remote.request("preflight", rid, ctx.id, ctx.token,
                                             {"controller_time": now().isoformat()}))
        counts = _accounting(preflight)
    except VaultRewindError as exc:
        if exc.code not in {"STAGING_QUOTA_EXCEEDED", "INSUFFICIENT_SPACE"}:
            raise
        # A full disk must not hide the actions needed to reclaim space. The helper's
        # preflight enforces capacity before it returns counters, so keep usage unknown
        # and inspect historical journals to expose only independently verified cleanup.
        accounting_error = exc.code
        preflight = None
        counts = {name: None for name in ("source_staging_bytes", "image_cache_bytes", "staging_bytes", "quota_bytes")}
    with ctx.sessions() as db:
        instance = _instance(db, ctx.instance_id)
        if preflight is not None and set(preflight.get("resource_keys", [])) != set(instance.physical_keys):
            _error("TARGET_CHANGED", "The enrolled physical data roots changed.")
        jobs = list(db.scalars(select(Job).where(Job.instance_id == ctx.instance_id,
            Job.kind.in_(["backup", "restore"])).order_by(Job.created_at.desc()).limit(MAX_OPERATIONS + 1)))
    operations = []
    for job in jobs[:MAX_OPERATIONS]:
        ctx.guard()
        status = asyncio.run(remote.request("status", rid, job.id, ctx.token))
        _status_identity(status, job.id, rid)
        operations.append(_operation(job, status))
    return {"as_of": now().isoformat(), **counts, "accounting_error": accounting_error, "scope": "shared_host_staging",
            "operations": operations, "operations_truncated": len(jobs) > MAX_OPERATIONS}


def run_inventory(worker, ctx):
    ctx.phase("remote_inventory")
    remote, rid = ctx.remote()
    inventory = _inventory(ctx, remote, rid)
    ctx.update(result={"remote_storage": inventory})
    ctx.finish("partial" if inventory["accounting_error"] else "succeeded")


def run_cleanup(worker, ctx):
    ctx.phase("remote_cleanup")
    with ctx.sessions() as db:
        job, resources = _historical(db, ctx.request["historical_job_id"], ctx.instance_id)
        owned = set(db.scalars(select(JobResource.resource_key).where(JobResource.job_id == ctx.id)))
        if not resources <= owned:
            _error("TARGET_CHANGED", "The cleanup job does not hold every historical and current data lease.")
        validate_cleanup(job, ctx.request["kind"])
    remote, rid = ctx.remote()
    ctx.guard()
    status = asyncio.run(remote.request("status", rid, job.id, ctx.token))
    _status_identity(status, job.id, rid)
    validate_cleanup(job, ctx.request["kind"], status)
    # Use the old operation UUID with the NEW lease's fence. Context.request_remote would
    # incorrectly address ctx.id. Helper cleanup is journaled/idempotent and rechecks ownership.
    ctx.guard()
    outcome = asyncio.run(remote.request("cleanup", rid, job.id, ctx.token, {"kind": ctx.request["kind"]}))
    _status_identity(outcome, job.id, rid)
    expected = {"staging": outcome.get("staging_cleaned") is True,
                "generations": outcome.get("generations_cleaned") is True,
                "discard_candidate": outcome.get("candidate_cleanup_outcome") == "complete"}
    if not expected[ctx.request["kind"]]:
        _error("REMOTE_CLEANUP_UNCONFIRMED", "Cleanup did not return durable completion evidence; retry this job.")
    ctx.update(result={"cleanup_result": "complete", "historical_job_id": job.id,
                       "cleanup_kind": ctx.request["kind"]})
    # Space counters are sampled after cleanup rather than subtracting estimates.
    inventory = _inventory(ctx, remote, rid)
    ctx.update(result={"remote_storage": inventory})
    ctx.finish("partial" if inventory["accounting_error"] else "succeeded")

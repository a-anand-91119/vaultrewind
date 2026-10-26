"""Synthetic SQLite/remote-wire proof. No SSH, Docker or live hosts are contacted."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from tests.unit.test_server import env, seed  # noqa: F401
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.db import now, uid
from vaultrewind.server.models import Job, JobResource
from vaultrewind.server.queue import claim, enqueue, finish, resources_for_instance
from vaultrewind.server.remote_maintenance import (
    queue_cleanup,
    queue_inventory,
    run_cleanup,
    run_inventory,
    storage_view,
    validate_cleanup,
)
from vaultrewind.server.worker import Context, Worker


def history(db, instance_id, *, kind="restore", state="succeeded", activation="complete"):
    job = enqueue(db, kind=kind, request={"target_id": instance_id} if kind == "restore" else {},
                  key=uid(), instance_id=instance_id, resources=resources_for_instance(db, instance_id, []))
    finish(db, job, state)
    job.target_activation_outcome = activation
    db.flush()
    return job


def status(job_id, remote_id, **overrides):
    return {"exists": True, "operation_id": job_id, "instance_id": remote_id, "kind": "restore",
            "phase": "complete", "activation_started": True, "generation_logical_bytes": 120,
            "retained_generation_logical_bytes": 90, "rollback_cleanup_after": (now() - timedelta(days=1)).timestamp(),
            "staging_cleaned": False, "generations_cleaned": False, "candidate_cleanup_outcome": "pending",
            "private_path": "/secret/source/tree", **overrides}


class Remote:
    def __init__(self, operation_status, *, accounting=True):
        self.operation_status = operation_status
        self.calls = []
        self.accounting = accounting

    async def request(self, verb, instance, operation, fence, payload=None):
        self.calls.append((verb, instance, operation, fence, payload))
        if verb == "preflight":
            result = {"protocol_version": 1, "staging_bytes": 600, "staging_quota_bytes": 10000,
                      "resource_keys": ["b" * 64]}
            if self.accounting:
                result.update(source_staging_bytes=400, image_cache_bytes=200)
            return result
        if verb == "status":
            return self.operation_status
        if verb == "cleanup":
            key = {"generations": "generations_cleaned", "staging": "staging_cleaned"}[payload["kind"]]
            self.operation_status = {**self.operation_status, key: True}
            return self.operation_status
        raise AssertionError(f"Unexpected verb {verb}")


def context(environment, remote, kind="inventory", cleanup_kind="generations", overrides=None):
    settings, engine, factory, store, _ = environment
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        original = history(db, instance.id)
        for key, value in (overrides or {}).items():
            setattr(original, key, value)
        remote.operation_status = status(original.id, instance.id)
        if kind == "inventory":
            maintenance = queue_inventory(db, instance.id, key="inventory")
        else:
            maintenance = queue_cleanup(db, original.id, cleanup_kind, key="cleanup")
        instance_id, original_id, maintenance_id = instance.id, original.id, maintenance.id
    worker = Worker(settings, engine=engine, owner="remote-maintenance-test")
    with factory.begin() as db:
        claimed = claim(db, worker.owner)
        assert claimed.id == maintenance_id
    ctx = Context(worker, claimed)
    ctx.remote = lambda: (remote, instance_id)
    return worker, ctx, original_id, instance_id


@pytest.mark.parametrize("state", ["queued", "running", "waiting_retry", "cancel_requested", "needs_attention", "rollback_failed"])
def test_rejects_active_or_uncertain_historical_jobs(env, state):  # noqa: F811
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        job = history(db, instance.id, state=state)
        with pytest.raises(VaultRewindError, match="Active or unresolved") as error:
            queue_cleanup(db, job.id, "staging", key="unsafe")
        assert error.value.code == "CLEANUP_UNSAFE"


@pytest.mark.parametrize("activation", ["activation_started", "activated", "uncertain", "unknown", "needs_attention"])
def test_activation_uncertainty_is_rejected_even_with_terminal_state(env, activation):  # noqa: F811
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        job = history(db, instance.id, activation=activation)
        with pytest.raises(VaultRewindError) as error:
            queue_cleanup(db, job.id, "staging", key="uncertain")
        assert error.value.code == "CLEANUP_UNSAFE"


def test_cleanup_is_bound_to_historical_host_and_target(env):  # noqa: F811
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        job = history(db, instance.id)
        job.request = {"target_id": uid()}
        with pytest.raises(VaultRewindError) as error:
            queue_cleanup(db, job.id, "generations", key="wrong-target")
        assert error.value.code == "TARGET_CHANGED"
        job.request = {"target_id": instance.id}
        db.get(JobResource, (job.id, next(k for k in resources_for_instance(db, instance.id, []) if k.startswith("host:")))).resource_key = "host:other"
        db.flush()
        with pytest.raises(VaultRewindError) as error:
            queue_cleanup(db, job.id, "generations", key="wrong-host")
        assert error.value.code == "TARGET_CHANGED"


def test_generation_grace_and_positive_candidate_evidence(env):  # noqa: F811
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        job = history(db, instance.id)
        journal = status(job.id, instance.id, rollback_cleanup_after=(now() + timedelta(days=7)).timestamp())
        with pytest.raises(VaultRewindError) as error:
            validate_cleanup(job, "generations", journal)
        assert error.value.code == "CLEANUP_GRACE_PERIOD"
        job.state, job.target_activation_outcome = "rolled_back", "not_started"
        journal.update(phase="rolled_back", activation_started=False)
        validate_cleanup(job, "discard_candidate", journal)
        journal.pop("activation_started")
        validate_cleanup(job, "discard_candidate", journal)
        job.target_activation_outcome = "candidate_validated"
        validate_cleanup(job, "discard_candidate", journal)
        journal["activation_started"] = None
        with pytest.raises(VaultRewindError) as error:
            validate_cleanup(job, "discard_candidate", journal)
        assert error.value.code == "CLEANUP_UNSAFE"


def test_inventory_is_cached_allowlisted_and_uses_correct_operation_ids(env):  # noqa: F811
    remote = Remote({})
    worker, ctx, historical_id, instance_id = context(env, remote)
    run_inventory(worker, ctx)
    with worker.sessions() as db:
        view = storage_view(db, instance_id)
        assert view["source_staging_bytes"] == 400 and view["image_cache_bytes"] == 200
        assert view["staging_bytes"] == 600 and view["quota_bytes"] == 10000
        assert view["operations"][0]["retained_generation_bytes"] == 90
        assert view["operations"][0]["eligible_cleanup"] == ["generations", "staging"]
        assert "/secret/" not in str(view) and "private_path" not in str(view)
        assert db.get(Job, ctx.id).state == "succeeded"
    assert [(verb, operation) for verb, _, operation, _, _ in remote.calls] == [
        ("preflight", ctx.id), ("status", historical_id)]


def test_old_helper_accounting_is_unavailable_not_zero(env):  # noqa: F811
    remote = Remote({}, accounting=False)
    worker, ctx, _, instance_id = context(env, remote)
    with pytest.raises(VaultRewindError) as error:
        run_inventory(worker, ctx)
    assert error.value.code == "REMOTE_ACCOUNTING_UNAVAILABLE"
    with worker.sessions() as db:
        assert storage_view(db, instance_id)["source_staging_bytes"] is None
        assert not db.get(Job, ctx.id).result.get("remote_storage")


def test_cleanup_uses_new_lease_fence_and_historical_operation_uuid(env):  # noqa: F811
    remote = Remote({})
    worker, ctx, historical_id, instance_id = context(env, remote, "cleanup")
    run_cleanup(worker, ctx)
    mutation = [call for call in remote.calls if call[0] == "cleanup"]
    assert mutation == [("cleanup", instance_id, historical_id, ctx.token, {"kind": "generations"})]
    assert historical_id != ctx.id
    with worker.sessions() as db:
        assert db.get(Job, ctx.id).state == "succeeded"
        assert storage_view(db, instance_id)["operations"][0]["generations_cleaned"] is True
        keys = set(db.scalars(select(JobResource.resource_key).where(JobResource.job_id == ctx.id)))
        assert set(resources_for_instance(db, instance_id, [])) <= keys
        assert not any(key.startswith("repository:") for key in keys)


@pytest.mark.parametrize("field", ["instance_id", "operation_id"])
def test_mismatched_remote_journal_never_reaches_cleanup(env, field):  # noqa: F811
    remote = Remote({})
    worker, ctx, _, _ = context(env, remote, "cleanup")
    remote.operation_status[field] = uid()
    with pytest.raises(VaultRewindError) as error:
        run_cleanup(worker, ctx)
    assert error.value.code == "TARGET_CHANGED"
    assert not any(call[0] == "cleanup" for call in remote.calls)


def test_remote_activation_uncertainty_never_reaches_cleanup(env):  # noqa: F811
    remote = Remote({})
    worker, ctx, _, _ = context(env, remote, "cleanup")
    remote.operation_status.update(phase="activation_started")
    with pytest.raises(VaultRewindError):
        run_cleanup(worker, ctx)
    assert not any(call[0] == "cleanup" for call in remote.calls)


def test_cleanup_waits_for_an_existing_physical_owner(env):  # noqa: F811
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        original = history(db, instance.id)
        active = enqueue(db, kind="backup", request={}, key="active", instance_id=instance.id)
        cleanup = queue_cleanup(db, original.id, "generations", key="later")
        active_id, cleanup_id = active.id, cleanup.id
    with factory.begin() as db:
        assert claim(db, "first").id == active_id
    with factory.begin() as db:
        assert claim(db, "second") is None
        assert db.get(Job, cleanup_id).state == "queued"


def test_current_mount_change_retains_old_and_new_leases(env):  # noqa: F811
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        original = history(db, instance.id)
        old_identity = instance.physical_identity
        instance.physical_identity = "d" * 64
        instance.physical_keys = ["b" * 64, "e" * 64]
        cleanup = queue_cleanup(db, original.id, "generations", key="new-inode")
        db.flush()
        keys = set(db.scalars(select(JobResource.resource_key).where(JobResource.job_id == cleanup.id)))
        assert f"instance:{old_identity}" in keys
        assert "instance:" + "d" * 64 in keys and "mount:" + "e" * 64 in keys


def test_full_disk_keeps_cleanup_visible_with_unknown_counters(env):  # noqa: F811
    class FullRemote(Remote):
        async def request(self, verb, instance, operation, fence, payload=None):
            if verb == "preflight":
                raise VaultRewindError("STAGING_QUOTA_EXCEEDED", "synthetic full staging")
            return await super().request(verb, instance, operation, fence, payload)
    remote = FullRemote({})
    worker, ctx, _, instance_id = context(env, remote)
    run_inventory(worker, ctx)
    with worker.sessions() as db:
        assert db.get(Job, ctx.id).state == "partial"
        view = storage_view(db, instance_id)
        assert view["accounting_error"] == "STAGING_QUOTA_EXCEEDED"
        assert view["staging_bytes"] is None
        assert "staging" in view["operations"][0]["eligible_cleanup"]

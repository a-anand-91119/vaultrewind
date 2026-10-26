"""Controller reconciliation must retain the same operation and leases until the journal proves safety."""
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.unit.test_server import env, seed  # noqa: F401 - shared database fixture
from vaultrewind.server.db import uid
from vaultrewind.server.models import Job, ResourceLease
from vaultrewind.server.queue import claim, enqueue, finish


def test_reconcile_requeues_same_operation_and_preserves_physical_ownership(env):  # noqa: F811
    _settings, _engine, factory, store, app = env
    with factory.begin() as db:
        user, host, instance, _policy, _repo = seed(db, store)
        instance_id, resource = instance.id, f"host:{host.physical_identity}"
        original = enqueue(db, kind="backup", request={"instance_id": instance.id}, key=uid(),
                           instance_id=instance.id, actor_id=user.id, resources=[resource])
        original_id = original.id
    with factory.begin() as db:
        original = claim(db, "lost-worker")
        finish(db, original, "needs_attention")
    client = TestClient(app, base_url="http://localhost")
    login = client.post("/api/v1/sessions", json={"username": "owner", "password": "synthetic-password"},
                        headers={"Origin": "http://localhost"})
    client.headers.update({"Origin": "http://localhost", "X-CSRF-Token": login.json()["csrf_token"]})
    first = client.post(f"/api/v1/jobs/{original_id}/reconcile", json={})
    second = client.post(f"/api/v1/jobs/{original_id}/reconcile", json={})
    assert first.status_code == second.status_code == 202
    assert first.json()["job_id"] == second.json()["job_id"] == original_id
    with factory.begin() as db:
        assert db.scalar(select(ResourceLease).where(ResourceLease.resource_key == resource)).owner_job_id == original_id
        reclaimer = claim(db, "reconciler")
        assert reclaimer.id == original_id and reclaimer.reconcile_required
        assert reclaimer.fencing_token > 1
        assert db.get(Job, original_id).request == {"instance_id": instance_id}


def test_completed_success_cannot_be_requeued_as_a_reconciliation(env):  # noqa: F811
    _settings, _engine, factory, store, app = env
    with factory.begin() as db:
        user, _host, instance, _policy, _repo = seed(db, store)
        original = enqueue(db, kind="backup", request={"instance_id": instance.id}, key=uid(),
                           instance_id=instance.id, actor_id=user.id, resources=[])
        original_id = original.id
    with factory.begin() as db:
        finish(db, claim(db, "completed-worker"), "succeeded")
    client = TestClient(app, base_url="http://localhost")
    login = client.post("/api/v1/sessions", json={"username": "owner", "password": "synthetic-password"},
                        headers={"Origin": "http://localhost"})
    client.headers.update({"Origin": "http://localhost", "X-CSRF-Token": login.json()["csrf_token"]})
    assert client.post(f"/api/v1/jobs/{original_id}/reconcile", json={}).status_code == 409


def test_missing_journal_never_repeats_issued_capture_or_releases_ownership(env):  # noqa: F811
    import pytest

    from vaultrewind.core.errors import VaultRewindError
    from vaultrewind.server.models import JobStep
    from vaultrewind.server.worker import Context, Worker
    settings, engine, factory, store, _app = env
    class Remote:
        def __init__(self):
            self.calls = []
        async def request(self, verb, *_args):
            self.calls.append(verb)
            assert verb == "status", "An ambiguous capture must never be blindly repeated"
            return {"exists": False}
    remote = Remote()
    class Adapters:
        def remote(self, *_args):
            return remote, "fixture"
    worker = Worker(settings, engine=engine, adapters=Adapters(), owner="new-worker")
    with factory.begin() as db:
        user, _host, instance, _policy, _repo = seed(db, store)
        original = enqueue(db, kind="backup", request={"instance_id": instance.id}, key=uid(),
                           instance_id=instance.id, actor_id=user.id, resources=["physical:lost-journal"])
    with factory.begin() as db:
        original = claim(db, worker.owner)
        db.add(JobStep(job_id=original.id, name="capture", sequence=1, fencing_token=original.fencing_token))
    ctx = Context(worker, original)
    with pytest.raises(VaultRewindError) as error:
        ctx.request_remote(remote, "fixture", "capture")
    assert error.value.code == "REMOTE_JOURNAL_MISSING"
    worker.failure(ctx, error.value)
    with factory() as db:
        assert db.get(Job, original.id).state == "needs_attention"
        assert db.get(Job, original.id).error_code == "REMOTE_JOURNAL_MISSING"
        assert db.get(ResourceLease, "physical:lost-journal").owner_job_id == original.id


def test_internal_startup_alone_cannot_satisfy_public_restore_success():
    import pytest

    from vaultrewind.core.errors import VaultRewindError
    from vaultrewind.server.worker import Worker
    with pytest.raises(VaultRewindError) as error:
        Worker.require_public_activation({"phase": "complete", "candidate_validated": True})
    assert error.value.code == "PUBLIC_READINESS_UNCONFIRMED"
    Worker.require_public_activation({"phase": "complete", "public_ports_verified": True, "public_endpoint_verified": True})
    Worker.require_public_activation({"phase": "data_restored_service_stopped"})

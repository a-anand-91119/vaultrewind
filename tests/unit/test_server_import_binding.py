"""A recovered catalog must be usable without replacing its historical identities."""
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.unit.test_server import add_snapshot, env, seed  # noqa: F401
from vaultrewind.server.db import now, uid
from vaultrewind.server.models import BackupPolicy, Instance, Job, Repository, SnapshotProtection
from vaultrewind.server.recovery_import import _ensure_placeholder


def test_import_placeholder_binds_verified_host_and_preserves_recovery_protections(env):  # noqa: F811
    _settings, _engine, factory, store, app = env
    with factory.begin() as db:
        _user, host, _old_instance, _old_policy, repo = seed(db, store)
        ident = uid()
        placeholder = _ensure_placeholder(db, store, ident, "Recovered vault",
                                         {"instances_created": 0, "instances_existing": 0})
        repo.instance_id, repo.imported, repo.health = ident, True, "imported"
        snapshot, _copy = add_snapshot(db, placeholder, repo, now())
        db.add(SnapshotProtection(snapshot_id=snapshot.id, reason="import_review"))
        evidence_id = store.put(db, "discovery", ident, {
            "database_engine": "sqlite", "recovery_verified": True, "resource_keys": ["d" * 64],
            "fingerprint": "e" * 64, "source_state": "running", "restore_enabled": True,
            "enrolled_profile": {"capture_budget": 300, "restore_budget": 900}})
        discovery = Job(id=uid(), kind="discover", state="succeeded", phase="finalizing",
                        idempotency_scope="synthetic-import", idempotency_key=uid(), request_hash="a" * 64,
                        request={"host_id": host.id, "instance_id": ident},
                        result={"private_evidence_id": evidence_id})
        db.add(discovery)
        host_id, discovery_id, repo_id, snapshot_id = host.id, discovery.id, repo.id, snapshot.id
    client = TestClient(app, base_url="http://localhost")
    login = client.post("/api/v1/sessions", json={"username": "owner", "password": "synthetic-password"},
                        headers={"Origin": "http://localhost"})
    client.headers.update({"Origin": "http://localhost", "X-CSRF-Token": login.json()["csrf_token"]})
    body = {"host_id": host_id, "name": "Recovered vault", "container_id": "synthetic",
            "configuration": {"discovery_job_id": discovery_id, "remote_instance_id": ident}}
    response = client.post("/api/v1/instances", json=body)
    assert response.status_code == 201, response.json()
    assert response.json()["id"] == ident
    assert client.post("/api/v1/instances", json=body).status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Instance).where(Instance.id == ident)) == 1
        assert db.get(Instance, ident).host_id == host_id
        assert db.get(Repository, repo_id).imported
        assert db.scalar(select(SnapshotProtection).where(SnapshotProtection.snapshot_id == snapshot_id))
        policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == ident))
        assert not policy.enabled and policy.retention_days is None
        assert policy.next_run_at is None and policy.next_test_at is None and policy.next_verify_at is None


def test_hypothetical_retention_preview_does_not_change_saved_policy(env):  # noqa: F811
    _settings, _engine, factory, store, app = env
    with factory.begin() as db:
        _user, _host, instance, policy, _repo = seed(db, store)
        ident, revision, days = instance.id, policy.revision, policy.retention_days
    client = TestClient(app, base_url="http://localhost")
    login = client.post("/api/v1/sessions", json={"username": "owner", "password": "synthetic-password"},
                        headers={"Origin": "http://localhost"})
    client.headers.update({"Origin": "http://localhost", "X-CSRF-Token": login.json()["csrf_token"]})
    first = client.post(f"/api/v1/instances/{ident}/retention-preview", json={"retention_days": 7})
    assert first.status_code == 200 and first.json()["retention_days"] == 7 and first.json()["hypothetical"]
    forever = client.post(f"/api/v1/instances/{ident}/retention-preview", json={"keep_forever": True})
    assert forever.status_code == 200 and forever.json()["cutoff"] is None
    with factory() as db:
        policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == ident))
        assert (policy.retention_days, policy.revision) == (days, revision)


def test_explicit_pagination_is_parsed_and_bounded(env):  # noqa: F811
    _settings, _engine, factory, store, app = env
    with factory.begin() as db:
        seed(db, store)
    client = TestClient(app, base_url="http://localhost")
    login = client.post("/api/v1/sessions", json={"username": "owner", "password": "synthetic-password"},
                        headers={"Origin": "http://localhost"})
    assert login.status_code == 200
    assert client.get("/api/v1/jobs?limit=5&offset=0").status_code == 200
    assert client.get("/api/v1/instances?limit=100").status_code == 200
    assert client.get("/api/v1/jobs?limit=201").status_code == 422
    assert client.get("/api/v1/jobs?limit=abc").status_code == 422


def test_snapshot_cursor_pages_include_ties_without_gaps_or_duplicates(env):  # noqa: F811
    _settings, _engine, factory, store, app = env
    with factory.begin() as db:
        _user, _host, instance, _policy, repo = seed(db, store)
        instance_id = instance.id
        for _ in range(6):
            add_snapshot(db, instance, repo, now().replace(microsecond=0))
    client = TestClient(app, base_url="http://localhost")
    assert client.post("/api/v1/sessions", json={"username": "owner", "password": "synthetic-password"},
                       headers={"Origin": "http://localhost"}).status_code == 200
    seen, cursor = [], {}
    for _ in range(3):
        page = client.get(f"/api/v1/instances/{instance_id}/snapshots", params={"limit": 2, **cursor})
        assert page.status_code == 200
        items = page.json()["items"]
        assert len(items) == 2
        seen.extend(item["id"] for item in items)
        cursor = {"before": items[-1]["captured_at"], "before_id": items[-1]["id"]}
    assert len(set(seen)) == 6
    assert client.get(f"/api/v1/instances/{instance_id}/snapshots", params=cursor).json()["items"] == []

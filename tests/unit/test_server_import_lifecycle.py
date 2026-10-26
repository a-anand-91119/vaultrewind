"""Protected recovery uses a real encrypted repository and the actual API/worker.

This is an API/catalog lifecycle test, not evidence that a Vaultwarden container
started. The separate controller-loss drill uses an actual captured application.
"""
from __future__ import annotations

import json
import secrets
import shutil

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.unit.test_core import canonical_fixture
from tests.unit.test_server import client_setup, env  # noqa: F401
from vaultrewind.core.manifest import manifest_hash
from vaultrewind.recovery.kit import build_recovery_kit, seal_recovery_kit
from vaultrewind.server.db import uid, utc
from vaultrewind.server.models import (
    BackupPolicy,
    Instance,
    Job,
    Repository,
    Secret,
    Snapshot,
    SnapshotCopy,
    SnapshotProtection,
)
from vaultrewind.server.worker import Worker
from vaultrewind.storage import providers
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository


class RecoveryMaterial(dict):
    def __repr__(self):
        return "<synthetic private recovery material>"


@pytest.fixture
def recovery_material(tmp_path):
    if not shutil.which("restic"):
        pytest.skip("real restic binary required")
    stage, manifest = canonical_fixture(tmp_path)
    instance_id, destination_id, repo_id = manifest["instance_uuid"], uid(), uid()
    configuration = {"path": str(tmp_path / "repositories"), "min_free_bytes": 0}
    location = providers.repository_location("local", configuration, instance_id, destination_id)
    password, passphrase = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
    repo = ResticRepository(RepositoryConfig(location=location, password=password, instance_uuid=instance_id,
        runtime_dir=tmp_path / "repo-runtime", cache_dir=tmp_path / "repo-cache"))
    repo.initialize()
    committed = repo.commit(stage, manifest["snapshot_uuid"], manifest["captured_at"])
    kit = build_recovery_kit(controller_id=uid(),
        destinations=[{"destination_id": destination_id, "backend": "local", "configuration": configuration}],
        repositories=[{"repository_id": repo_id, "destination_id": destination_id, "instance_id": instance_id,
                       "location": location, "password": password, "restic_repository_id": repo.describe()["repository_id"]}],
        instances=[{"instance_id": instance_id, "name": "Synthetic recovered vault"}])
    return RecoveryMaterial(kit=seal_recovery_kit(kit, passphrase).decode(), passphrase=passphrase, password=password,
                            manifest=manifest, repo_id=repo_id, restic_id=committed["restic_snapshot_id"])


def _post(client, path, payload, key=None):
    return client.post("/api/v1" + path, json=payload, headers={"Idempotency-Key": key or uid()})


def _run(client, worker, accepted, expected="succeeded"):
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]
    assert worker.run_once()
    job = client.get(f"/api/v1/jobs/{job_id}").json()
    assert job["state"] == expected, job
    return job_id, job


@pytest.mark.integration
def test_real_repository_import_review_apply_and_retention_hold(env, recovery_material):  # noqa: F811
    settings, engine, factory, store, app = env
    settings.per_job_quota_bytes = 32 * 1024**2
    settings.staging_quota_bytes = 64 * 1024**2
    client = client_setup(app, settings)
    worker = Worker(settings, engine=engine)
    material, manifest = recovery_material, recovery_material["manifest"]
    submission = {k: material[k] for k in ("kit", "passphrase")}
    accepted = _post(client, "/recovery/import-plans", submission, "recover-once")
    assert _post(client, "/recovery/import-plans", submission, "recover-once").json() == accepted.json()
    plan_id, job = _run(client, worker, accepted)
    assert job["result"]["import_summary"]["verified_copies"] == 1
    review = client.get(f"/api/v1/recovery/import-plans/{plan_id}")
    assert review.status_code == 200, review.text
    plan = review.json()
    assert plan["summary"]["mode"] == "protected"
    assert plan["summary"]["automatic_deletion_enabled"] is False
    assert plan["snapshots"][0]["snapshot_uuid"] == manifest["snapshot_uuid"]
    assert plan["snapshots"][0]["manifest_hash"] == manifest_hash(manifest)
    assert _post(client, "/users", {"username": "reader", "password": "synthetic-viewer-password",
                                    "role": "viewer"}).status_code == 201
    viewer = TestClient(app, base_url="http://localhost", headers={"Origin": "http://localhost"})
    login = _post(viewer, "/sessions", {"username": "reader", "password": "synthetic-viewer-password"})
    assert login.status_code == 200
    viewer.headers.update({"Origin": "http://localhost", "X-CSRF-Token": login.json()["csrf_token"]})
    assert viewer.get(f"/api/v1/recovery/import-plans/{plan_id}").status_code == 403
    assert _post(viewer, f"/recovery/import-plans/{plan_id}/apply", {"plan_hash": plan["plan_hash"]}).status_code == 403
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Snapshot)) == 0  # Review does not apply.
        assert store.get(db, db.get(Job, plan_id).request["secret_id"]) == {"consumed": True}
    assert _post(client, f"/recovery/import-plans/{plan_id}/apply", {"plan_hash": "0" * 64}).status_code == 409
    apply_path = f"/recovery/import-plans/{plan_id}/apply"
    apply_body = {"plan_hash": plan["plan_hash"]}
    apply_request = _post(client, apply_path, apply_body, "apply-once")
    assert _post(client, apply_path, apply_body, "apply-once").json() == apply_request.json()
    _, result = _run(client, worker, apply_request)
    assert result["result"]["apply_summary"]["snapshots_created"] == 1
    _run(client, worker, _post(client, apply_path, apply_body))  # Replay under a new job stays idempotent.
    with factory() as db:
        instance = db.get(Instance, manifest["instance_uuid"])
        assert instance.host_id is None and instance.readiness == "imported"
        policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance.id))
        assert not policy.enabled and policy.retention_days is None
        assert policy.next_run_at is None and policy.next_verify_at is None and policy.next_test_at is None
        snapshot = db.get(Snapshot, manifest["snapshot_uuid"])
        assert snapshot.imported and snapshot.manifest_hash == manifest_hash(manifest)
        assert utc(snapshot.captured_at).isoformat() == manifest["captured_at"]
        assert db.scalar(select(func.count()).select_from(Snapshot)) == 1
        copy = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot.id))
        assert copy.restic_snapshot_id == material["restic_id"] and copy.state == "complete"
        repository = db.get(Repository, material["repo_id"])
        assert repository.imported and repository.health == "imported"
        assert store.get(db, repository.key_id) == material["password"]
        holds = set(db.scalars(select(SnapshotProtection.reason).where(SnapshotProtection.snapshot_id == snapshot.id)))
        assert "import_review" in holds
        assert material["password"] not in str(db.get(Secret, repository.key_id).envelope)
    preview = _post(client, f"/instances/{manifest['instance_uuid']}/retention-preview", {"retention_days": 1})
    assert preview.status_code == 200, preview.text
    assert preview.json()["copy_ids"] == []
    public = json.dumps([job, plan, result, preview.json(),
                        client.get(f"/api/v1/snapshots/{manifest['snapshot_uuid']}").json()])
    for secret in (material["password"], material["passphrase"], material["kit"]):
        assert secret not in public


@pytest.mark.integration
def test_wrong_kit_passphrase_fails_without_creating_recovery_rows(env, recovery_material):  # noqa: F811
    settings, engine, factory, _, app = env
    client = client_setup(app, settings)
    worker = Worker(settings, engine=engine)
    _, job = _run(client, worker, _post(client, "/recovery/import-plans", {
        "kit": recovery_material["kit"], "passphrase": secrets.token_urlsafe(40)}), expected="failed")
    assert job["error_code"] == "RECOVERY_KIT_PASSPHRASE_INVALID"
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Instance)) == 0
        assert db.scalar(select(func.count()).select_from(Repository)) == 0
        assert db.scalar(select(func.count()).select_from(Snapshot)) == 0

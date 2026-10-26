"""Real in-memory relational/API tests; remote correctness is tested at its own boundary."""
import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.app import create_app
from vaultrewind.server.auth import PASSWORDS
from vaultrewind.server.db import Base, make_engine, now, sessions, uid, utc
from vaultrewind.server.models import (
    BackupPolicy,
    Host,
    Instance,
    Job,
    Repository,
    Snapshot,
    SnapshotCopy,
    SnapshotProtection,
    StorageDestination,
    User,
    VerificationRun,
)
from vaultrewind.server.policy import advance_missed, next_run, retention_preview
from vaultrewind.server.queue import assert_fence, claim, enqueue, finish
from vaultrewind.server.schemas import Restore
from vaultrewind.server.secrets import Secrets
from vaultrewind.server.services import execute_restore, new_restore_plan
from vaultrewind.server.settings import Settings


@pytest.fixture
def env(tmp_path):
    key, bootstrap = tmp_path / "master", tmp_path / "bootstrap"
    key.write_bytes(os.urandom(32))
    bootstrap.write_text("synthetic-bootstrap-" + "z" * 32)
    key.chmod(0o600)
    bootstrap.chmod(0o600)
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", master_key_file=key,
        bootstrap_secret_file=bootstrap, public_origin="http://localhost", secure_cookies=False,
        local_storage_root=tmp_path / "backups", staging_dir=tmp_path / "staging",
        per_job_quota_bytes=1024**2, staging_quota_bytes=4 * 1024**2, min_free_bytes=0)
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    app = create_app(settings, engine=engine)
    yield settings, engine, sessions(engine), Secrets(settings), app
    engine.dispose()


def seed(db, store):
    user = User(id=uid(), username="owner", role="administrator", password_hash=PASSWORDS.hash("synthetic-password"))
    db.add(user)
    sid = store.put(db, "ssh", "fixture", {"private_key": "private-key-must-never-be-returned"})
    host = Host(id=uid(), name="Synthetic", endpoint="localhost", port=22, username="backup",
        host_public_key="public", credential_id=sid, readiness="ready", physical_identity="host" * 16, helper_protocol=1)
    db.add(host)
    db.flush()
    config = store.put(db, "instance", "fixture", {"restore_enabled": True, "remote_instance_id": uid()})
    instance = Instance(id=uid(), host_id=host.id, name="Synthetic Vault", container_id="a" * 64,
        physical_identity="data" * 16, physical_keys=["b"*64], fingerprint="c"*64,
        configuration_secret_id=config, readiness="ready", backup_health="healthy")
    db.add(instance)
    db.flush()
    policy = BackupPolicy(id=uid(), instance_id=instance.id, next_run_at=now()+timedelta(days=1))
    db.add(policy)
    ds = store.put(db, "storage", "fixture", {"path": "/synthetic/private"})
    destination = StorageDestination(id=uid(), name="Local", backend="local", configuration_secret_id=ds)
    db.add(destination)
    db.flush()
    repo = Repository(id=uid(), instance_id=instance.id, destination_id=destination.id,
        configuration_secret_id=ds, key_id=sid, physical_identity="repo"*16, health="healthy")
    db.add(repo)
    db.flush()
    return user, host, instance, policy, repo


def add_snapshot(db, instance, repo, captured, *, verified=False):
    snap = Snapshot(id=uid(), instance_id=instance.id, captured_at=captured, capture_started_at=captured,
        trigger="manual", manifest_hash="e"*64, completeness="complete", logical_bytes=42,
        image_id="sha256:"+"f"*64, vaultwarden_version="synthetic", source_state="running")
    db.add(snap)
    db.flush()
    copy = SnapshotCopy(id=uid(), snapshot_id=snap.id, repository_id=repo.id, restic_snapshot_id="a"*64,
                        state="complete", manifest_hash=snap.manifest_hash, verified_at=now())
    db.add(copy)
    db.flush()
    return snap, copy


def client_setup(app, settings):
    client = TestClient(app, base_url="http://localhost", raise_server_exceptions=False)
    response = client.post("/api/v1/setup", headers={"Origin":"http://localhost"}, json={
        "bootstrap_secret": settings.bootstrap_secret_file.read_text(), "username":"owner",
        "password":"synthetic-password", "timezone":"UTC"})
    assert response.status_code == 200, response.text
    client.headers.update({"Origin":"http://localhost", "X-CSRF-Token":response.json()["csrf_token"]})
    return client


def test_bootstrap_requires_private_one_time_secret(env):
    settings, _, factory, _, app = env
    client = TestClient(app, base_url="http://localhost")
    payload = {"bootstrap_secret":"wrong", "username":"attacker", "password":"synthetic-password"}
    assert client.post("/api/v1/setup", json=payload, headers={"Origin":"http://localhost"}).status_code == 403
    owner = client_setup(app, settings)
    payload["bootstrap_secret"] = settings.bootstrap_secret_file.read_text()
    assert owner.post("/api/v1/setup", json=payload).status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1


def test_auth_csrf_session_revocation_and_sanitized_validation(env):
    settings, _, _factory, _, app = env
    client = client_setup(app, settings)
    assert client.post("/api/v1/metadata/export", json={}, headers={"X-CSRF-Token":"bad","Idempotency-Key":"csrf"}).status_code == 403
    response = client.post("/api/v1/hosts", json={"private_key":"SECRET_SHOULD_NOT_ECHO"})
    assert response.status_code == 422 and "SECRET_SHOULD_NOT_ECHO" not in response.text
    response = client.post("/api/v1/sessions/revoke", json={})
    assert response.status_code == 200
    assert client.get("/api/v1/instances").status_code == 401


def test_login_rate_limit_is_durable(env):
    settings, _, _, _, app = env
    client_setup(app, settings)
    client = TestClient(app, base_url="http://localhost")
    for _ in range(8):
        assert client.post("/api/v1/sessions", json={"username":"owner","password":"bad"},
                           headers={"Origin":"http://localhost"}).status_code == 401
    assert client.post("/api/v1/sessions", json={"username":"owner","password":"synthetic-password"},
                       headers={"Origin":"http://localhost"}).status_code == 429


@pytest.mark.parametrize("method,path,payload", [
    ("POST","/instances/not-found/backups",{}), ("POST","/snapshots/no/restore-plans",{}),
    ("POST","/restore-plans/no/execute",{"confirmation_token":"x"*32}),
    ("POST","/snapshots/no/verify",{}), ("POST","/snapshots/no/pin",{}), ("DELETE","/snapshots/no/pin",None),
    ("POST","/snapshots/no/deletion-plans",{}), ("POST","/deletion-plans/no/execute",{"confirmation_token":"x"*32}),
    ("PATCH","/instances/no/policy",{}), ("POST","/recovery-kits/export",{"passphrase":"x"*32}),
    ("POST","/recovery/import-plans",{"kit":"synthetic","passphrase":"x"*32}),
    ("POST","/metadata/export",{}), ("POST","/hosts/no/discover",{}),
    ("POST","/storage-destinations/no/test",{}), ("POST","/jobs/no/cancel",{}),
    ("POST","/storage-destinations/no/authorize",{}), ("GET","/jobs/no/artifact",None),
    ("POST","/controller-backups",{}),
    ("PUT","/controller-backup-policy",{"destination_id":"11111111-1111-4111-8111-111111111111"}),
])
def test_viewer_cannot_mutate_or_export(method,path,payload,env):
    settings, _, _factory, _, app = env
    owner = client_setup(app, settings)
    assert owner.post("/api/v1/users",json={"username":"reader","password":"viewer-password-long","role":"viewer"}).status_code == 201
    client = TestClient(app,base_url="http://localhost")
    response = client.post("/api/v1/sessions",json={"username":"reader","password":"viewer-password-long"},headers={"Origin":"http://localhost"})
    client.headers.update({"Origin":"http://localhost","X-CSRF-Token":response.json()["csrf_token"],"Idempotency-Key":"test"})
    result = client.request(method,"/api/v1"+path,json=payload)
    assert result.status_code == 403, result.text
    assert client.get("/api/v1/doctor").status_code == 200


def test_idempotency_conflicts_duplicate_clicks_and_claim_fencing(env):
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, inst, _, _ = seed(db,store)
        job = enqueue(db,kind="backup",request={"n":1},key="first",instance_id=inst.id)
        first = job.id
    with factory.begin() as db:
        assert enqueue(db,kind="backup",request={"n":1},key="first",instance_id=inst.id).id == first
        assert enqueue(db,kind="backup",request={"n":1},key="second",instance_id=inst.id).id == first
        with pytest.raises(VaultRewindError,match="different inputs"):
            enqueue(db,kind="backup",request={"n":2},key="first",instance_id=inst.id)
    with factory.begin() as db:
        job=claim(db,"one",lease_seconds=60)
        token=job.fencing_token
        assert claim(db,"two",lease_seconds=60) is None
        job.lease_expires_at=now()-timedelta(seconds=1)
    with factory.begin() as db:
        reclaimed=claim(db,"two",lease_seconds=60)
        assert reclaimed.id==first and reclaimed.reconcile_required and reclaimed.fencing_token>token
    with factory.begin() as db, pytest.raises(VaultRewindError,match="lease"):
        assert_fence(db,first,"one",token)
    with factory.begin() as db:
        job=db.get(Job,first)
        finish(db,job,"succeeded")
    with factory.begin() as db, pytest.raises(VaultRewindError):
        enqueue(db,kind="backup",request={"n":2},key="second",instance_id=inst.id)


def test_expired_owner_reconciles_before_another_job_owns_physical_resource(env):
    _, _, factory, store, _ = env
    with factory.begin() as db:
        _,_,inst,_,_=seed(db,store)
        first=enqueue(db,kind="verify",request={},key="first",instance_id=inst.id)
        second=enqueue(db,kind="delete",request={},key="second",instance_id=inst.id)
    with factory.begin() as db:
        job=claim(db,"one")
        assert job.id==first.id
        job.lease_expires_at=now()-timedelta(seconds=2)
    with factory.begin() as db:
        job=claim(db,"two")
        assert job.id==first.id
        finish(db,job,"needs_attention")
    with factory.begin() as db:
        assert claim(db,"three") is None
        assert db.get(Job,second.id).state=="queued"


def test_retention_exact_cutoff_and_all_protections(env):
    _,_,factory,store,_=env
    current=datetime(2026,10,25,12,tzinfo=UTC)
    with factory.begin() as db:
        _,_,inst,policy,repo=seed(db,store)
        policy.next_run_at=current+timedelta(days=1)
        _old,oldcopy=add_snapshot(db,inst,repo,current-timedelta(days=31))
        _boundary,_bcopy=add_snapshot(db,inst,repo,current-timedelta(days=30))
        _newest,_ncopy=add_snapshot(db,inst,repo,current-timedelta(days=1))
        pinned,_pcopy=add_snapshot(db,inst,repo,current-timedelta(days=90))
        db.add(SnapshotProtection(snapshot_id=pinned.id,reason="pin"))
        tested,tcopy=add_snapshot(db,inst,repo,current-timedelta(days=70))
        testjob=enqueue(db,kind="verify",request={},key="tested",instance_id=inst.id)
        testjob.state="succeeded"
        db.add(VerificationRun(snapshot_id=tested.id,copy_id=tcopy.id,job_id=testjob.id,result="succeeded",
                               evidence={"application_started":True},cleanup_result="complete"))
    with factory.begin() as db:
        preview=retention_preview(db,inst.id,current)
        assert preview["copy_ids"]==[oldcopy.id]
        assert not preview["frozen"]
        db.get(Instance,inst.id).backup_health="degraded"
    with factory() as db:
        preview=retention_preview(db,inst.id,current)
        assert preview["frozen"] and preview["copy_ids"]==[]


@pytest.mark.parametrize("after,expected", [
    (datetime(2026,3,28,12,tzinfo=UTC),datetime(2026,3,29,1,tzinfo=UTC)),
    (datetime(2026,10,24,12,tzinfo=UTC),datetime(2026,10,25,0,30,tzinfo=UTC)),
    (datetime(2026,10,25,0,31,tzinfo=UTC),datetime(2026,10,26,1,30,tzinfo=UTC)),
])
def test_daily_schedule_dst_first_valid_and_once(after,expected):
    policy=BackupPolicy(schedule_kind="daily",timezone="Europe/Berlin",daily_time="02:30",interval_hours=1)
    assert next_run(policy,after)==expected


def test_hourly_catchup_is_one_and_utc():
    policy=BackupPolicy(schedule_kind="hourly",timezone="America/New_York",daily_time="02:00",interval_hours=1)
    due=datetime(2026,10,1,tzinfo=UTC)
    upcoming,count=advance_missed(policy,due,due+timedelta(days=3,minutes=10))
    assert count==72 and upcoming==due+timedelta(hours=73)


def test_restore_plan_bound_single_use_revision_and_immutable_snapshot(env):
    _,_,factory,store,_=env
    with factory.begin() as db:
        owner,_,inst,_policy,repo=seed(db,store)
        snapshot,_copy=add_snapshot(db,inst,repo,now())
        plan=new_restore_plan(db,store,snapshot.id,owner.id,Restore())
        ident, token=plan["id"],plan["confirmation_token"]
    with factory.begin() as db:
        db.get(Instance,inst.id).revision+=1
    with factory.begin() as db, pytest.raises(VaultRewindError,match="changed"):
        execute_restore(db,ident,token,owner.id,"run")
    with factory.begin() as db:
        plan=new_restore_plan(db,store,snapshot.id,owner.id,Restore())
    with factory.begin() as db:
        job=execute_restore(db,plan["id"],plan["confirmation_token"],owner.id,"run")
        job_id=job.id
    with factory.begin() as db:
        assert execute_restore(db,plan["id"],plan["confirmation_token"],owner.id,"run").id==job_id
        with pytest.raises(VaultRewindError):
            execute_restore(db,plan["id"],plan["confirmation_token"],owner.id,"other-key")
    with pytest.raises(VaultRewindError,match="immutable"), factory.begin() as db:
        db.get(Snapshot,snapshot.id).manifest_hash="0"*64


def test_spa_fallback_never_masks_api_routes(env,tmp_path):
    settings,engine,_,_,_=env
    folder=tmp_path/"frontend"
    folder.mkdir()
    (folder/"index.html").write_text("<html>synthetic ui</html>")
    settings.frontend_dir=folder
    app=create_app(settings,engine=engine)
    client=TestClient(app,base_url="http://localhost")
    assert "synthetic ui" in client.get("/instances/anything").text
    assert client.get("/api/v1/nonexistent").status_code==404
    assert client.get("/api/v1/nonexistent").headers["content-type"].startswith("application/json")


def test_transaction_conflict_is_reported_before_success_response(env):
    settings,_,_,_,app=env
    client=client_setup(app,settings)
    result=client.post("/api/v1/users",json={"username":"owner","password":"sensitive-password-canary","role":"viewer"})
    assert result.status_code==409
    assert result.json()["error"]["code"]=="CONFIGURATION_CONFLICT"
    assert "sensitive-password-canary" not in result.text


def test_chunked_request_body_is_bounded_before_json_parsing(env):
    _,_,_,_,app=env
    client=TestClient(app,base_url="http://localhost")
    chunks=(b"sensitive-body-canary"*40000 for _ in range(10))
    result=client.post("/api/v1/setup",content=chunks,headers={"Content-Type":"application/json"})
    assert result.status_code==413
    assert "sensitive-body-canary" not in result.text


def test_unexpected_http_exception_cannot_escape_into_response_or_logs(env,monkeypatch,caplog):
    _,_,_,_,app=env
    def unsafe_factory():
        raise ValueError("DO_NOT_LOG_PRIVATE_CANARY")
    monkeypatch.setattr(app.state,"sessions",unsafe_factory)
    client=TestClient(app,base_url="http://localhost",raise_server_exceptions=False)
    result=client.get("/api/v1/instances")
    assert result.status_code==503 and "DO_NOT_LOG_PRIVATE_CANARY" not in result.text
    assert "DO_NOT_LOG_PRIVATE_CANARY" not in caplog.text


def test_scheduler_persists_one_catchup_and_keeps_overdue_freeze_after_advance(env):
    from vaultrewind.server.models import PolicyDestination, ScheduleOccurrence
    from vaultrewind.server.policy import is_overdue
    from vaultrewind.server.scheduler import tick
    _,_,factory,store,_=env
    current=now()
    with factory.begin() as db:
        _,_,inst,policy,repo=seed(db,store)
        policy.schedule_kind="hourly"
        policy.next_run_at=current-timedelta(days=3,minutes=10)
        db.add(PolicyDestination(policy_id=policy.id,repository_id=repo.id,required=True))
    with factory.begin() as db:
        assert len(tick(db,current))==1
        saved=utc(db.get(BackupPolicy,policy.id).next_run_at)
        occurrence=db.scalar(select(ScheduleOccurrence))
        assert occurrence.catch_up and occurrence.coalesced==72
        assert is_overdue(db,db.get(BackupPolicy,policy.id),current)
    with factory.begin() as db:
        assert tick(db,current)==[]
        assert utc(db.get(BackupPolicy,policy.id).next_run_at)==saved
        job=db.get(Job,occurrence.job_id)
        finish(db,job,"succeeded")
        db.get(Instance,inst.id).last_complete_at=current
    with factory.begin() as db:
        assert not is_overdue(db,db.get(BackupPolicy,policy.id),current)
        enqueue(db,kind="backup",request={"trigger":"manual"},key="manual",instance_id=inst.id)
        assert utc(db.get(BackupPolicy,policy.id).next_run_at)==saved


def test_verified_remote_fence_floor_is_adopted_without_resetting_generations(env):
    from vaultrewind.server.worker import Context, Worker
    _,engine,factory,_,_=env
    with factory.begin() as db:
        enqueue(db,kind="doctor",request={},key="first",resources=["physical:fixture"])
    worker=Worker(env[0],engine=engine,owner="fence-test")
    with factory.begin() as db:
        job=claim(db,worker.owner)
    ctx=Context(worker,job)
    old=ctx.token
    ctx.adopt_fence_floor(2**40)
    assert ctx.token==2**40+1
    with factory.begin() as db, pytest.raises(VaultRewindError):
        assert_fence(db,job.id,worker.owner,old)
    ctx.finish("succeeded")
    with factory.begin() as db:
        enqueue(db,kind="doctor",request={},key="second",resources=["physical:fixture"])
    with factory.begin() as db:
        next_job=claim(db,"next-worker")
        assert next_job.fencing_token>ctx.token

"""Worker integration with real catalog, encryption, core verification and restic.

The synthetic image bytes here test persistence/storage contracts, not Docker startup.
Real helper/Docker/systemd evidence belongs to the disposable integration harness.
"""
import shutil
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import select

from tests.unit.test_server import client_setup, env, seed  # noqa: F401
from tests.unit.test_storage_support import make_snapshot_tree
from vaultrewind.core.manifest import verify_snapshot
from vaultrewind.recovery.kit import open_recovery_kit
from vaultrewind.recovery.offline import discover, restore_snapshot
from vaultrewind.server.models import Job, SnapshotCopy, StorageDestination, VerificationRun
from vaultrewind.server.queue import claim, enqueue
from vaultrewind.server.services import create_repository
from vaultrewind.server.worker import Context, Worker
from vaultrewind.storage.local import LocalDestination, initialize_local_destination


def test_metadata_export_is_background_and_download_is_authorized(env):  # noqa: F811
    settings, engine, _factory, _store, app = env
    client = client_setup(app,settings)
    response=client.post("/api/v1/metadata/export",json={},headers={"Idempotency-Key":"metadata"})
    assert response.status_code==202
    job_id=response.json()["job_id"]
    assert client.get(f"/api/v1/jobs/{job_id}/artifact").status_code==409
    assert Worker(settings,engine=engine).run_once()
    view=client.get(f"/api/v1/jobs/{job_id}").json()
    assert view["state"]=="succeeded" and view["artifact_ready"]
    output=client.get(view["artifact_url"])
    assert output.status_code==200 and output.json()["schema_version"]==1
    assert "password_hash" not in output.text and "envelope" not in output.text
    events=client.get(f"/api/v1/jobs/{job_id}/events?after=0").json()
    sequences=[event["sequence"] for event in events["events"]]
    assert sequences==list(range(1,len(sequences)+1))
    assert client.get(f"/api/v1/jobs/{job_id}/events?after={sequences[-1]}").json()["events"]==[]


def test_retained_artifact_accounts_actual_bytes_and_reserves_again_before_resume(env):  # noqa: F811
    settings, engine, factory, _store, _app = env
    worker = Worker(settings, engine=engine, owner="quota-worker")
    with factory.begin() as db:
        enqueue(db, kind="metadata_export", request={}, key="retained-quota", resources=[])
    with factory.begin() as db:
        job = claim(db, worker.owner)
    ctx = Context(worker, job)
    ctx.reserve()
    (ctx.root / "artifact").write_bytes(b"synthetic export")
    ctx.cleanup(preserve=True)
    from vaultrewind.server.models import StagingAllocation
    with factory() as db:
        row = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == job.id))
        assert row.actual_bytes == row.reserved_bytes == len(b"synthetic export")
    ctx.reserve()
    with factory() as db:
        row = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == job.id))
        assert row.reserved_bytes == settings.per_job_quota_bytes and row.state == "reserved"
    ctx.finish("succeeded")
    ctx.cleanup()


def test_destination_quota_failure_retains_visible_failed_copy(env, tmp_path):  # noqa: F811
    from vaultrewind.core.errors import VaultRewindError
    settings, engine, factory, store, _app = env
    worker = Worker(settings, engine=engine, owner="quota-copy-worker")
    with factory.begin() as db:
        _user, _host, instance, _policy, repository = seed(db, store)
        db.get(StorageDestination, repository.destination_id).quota_bytes = 1
        enqueue(db, kind="backup", request={}, key="quota-copy", instance_id=instance.id)
        instance_id, repository_id = instance.id, repository.id
    with factory.begin() as db:
        job = claim(db, worker.owner)
    ctx = Context(worker, job)
    stage, _manifest = make_snapshot_tree(tmp_path / "quota-snapshot", instance_uuid=instance_id)
    snapshot_id = worker.catalog_capture(ctx, verify_snapshot(stage))
    with pytest.raises(VaultRewindError) as error:
        worker.commit_copy(ctx, snapshot_id, repository_id, stage)
    assert error.value.code == "INSUFFICIENT_SPACE"
    with factory() as db:
        copy = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot_id))
        assert copy is not None and copy.state == "failed" and copy.error_code == "INSUFFICIENT_SPACE"


@pytest.fixture
def persistent_disk():
    with tempfile.TemporaryDirectory(prefix="vaultrewind-server-test-", dir="/var/tmp") as directory:
        yield Path(directory)


@pytest.mark.skipif(shutil.which("restic") is None,reason="Pinned real restic binary required")
def test_real_worker_catalog_commit_verification_and_independent_exported_kit(env,tmp_path,persistent_disk):  # noqa: F811
    settings, engine, factory, store, _ = env
    settings.local_storage_root=persistent_disk/"backups"
    settings.local_storage_root.mkdir(mode=0o700)
    with factory.begin() as db:
        owner,_,inst,_,old=seed(db,store)
        destination=db.get(StorageDestination,old.destination_id)
        local_config={"path":str(settings.local_storage_root),"min_free_bytes":0,"require_dedicated_mount":False}
        destination.configuration_secret_id=store.put(db,"destination_configuration",destination.id,local_config)
        db.delete(old)
        db.flush()
        repo=create_repository(db,store,settings,inst.id,destination)
        enqueue(db,kind="backup",request={"trigger":"manual"},key="capture",instance_id=inst.id)
        instance_id, repository_id, destination_id=inst.id,repo.id,destination.id
    initialize_local_destination(LocalDestination.from_config(local_config,destination_id))
    stage,_manifest=make_snapshot_tree(tmp_path/"synthetic",instance_uuid=instance_id)
    worker=Worker(settings,engine=engine,owner="unit-worker")
    with factory.begin() as db:
        claimed=claim(db,worker.owner)
    ctx=Context(worker,claimed)
    ctx.reserve()
    snapshot_id=worker.catalog_capture(ctx,verify_snapshot(stage))
    first=worker.commit_copy(ctx,snapshot_id,repository_id,stage)
    repeated=worker.commit_copy(ctx,snapshot_id,repository_id,stage)
    assert repeated["restic_snapshot_id"]==first["restic_snapshot_id"]
    ctx.finish("succeeded")
    ctx.cleanup()
    with factory.begin() as db:
        copies=list(db.scalars(select(SnapshotCopy).where(SnapshotCopy.snapshot_id==snapshot_id)))
        assert len(copies)==1 and copies[0].state=="complete" and copies[0].verified_at
        verify=enqueue(db,kind="verify",request={"snapshot_id":snapshot_id,"copy_id":copies[0].id,
                       "level":"full_data","runner_id":None},key="full-read",instance_id=instance_id)
        verify_id=verify.id
    assert worker.run_once()
    with factory.begin() as db:
        assert db.get(Job,verify_id).state=="succeeded"
        run=db.scalar(select(VerificationRun).where(VerificationRun.job_id==verify_id))
        assert run.evidence["full_data_verified"] is True and run.evidence["user_login_tested"] is False
        phrase="Synthetic recovery passphrase number42"
        private_id=store.put(db,"job_input","recovery_export",{"passphrase":phrase})
        export=enqueue(db,kind="recovery_export",request={"secret_id":private_id,"input_hash":"synthetic"},
                       key="export-kit",actor_id=owner.id,resources=["controller:catalog"])
        export_id=export.id
    assert worker.run_once()
    with factory() as db:
        assert db.get(Job,export_id).state=="succeeded", db.get(Job,export_id).error_code
        assert store.get(db,private_id)=={"consumed":True}
    blob=(settings.staging_dir/export_id/"recovery-kit.enc").read_bytes()
    assert b"Synthetic recovery passphrase" not in blob
    kit=open_recovery_kit(blob,phrase)
    # No controller DB or controller key is passed to discovery/restore.
    listing=discover(kit,work_dir=tmp_path/"new-controller-discovery")
    recovered=[r for d in listing["destinations"] for r in d["repositories"]]
    assert any(r["status"]=="ok" and r["snapshots"] for r in recovered)
    restored=restore_snapshot(kit,snapshot_id,tmp_path/"recovered",work_dir=tmp_path/"new-controller-restore")
    assert restored["verification"]["restored_bytes_verified"] is True
    assert (tmp_path/"recovered/data/attachments/cipher-one/attachment-one").read_bytes()==b"synthetic attachment bytes\x00\xff"

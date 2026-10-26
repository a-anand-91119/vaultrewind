"""A kit re-exported by controller A retains controller B's independently sealed history."""
import json

import pytest
from sqlalchemy import select

from tests.unit.test_server import client_setup, env  # noqa: F401
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.recovery.kit import build_recovery_kit, open_recovery_kit
from vaultrewind.server.controller_backup import _seal_catalog, decrypt_catalog
from vaultrewind.server.db import uid
from vaultrewind.server.models import ControllerState, Secret
from vaultrewind.server.queue import enqueue
from vaultrewind.server.recovery_import import apply_import_plan, private_materials
from vaultrewind.server.services import recovery_root
from vaultrewind.server.worker import Worker
from vaultrewind.storage import layout, providers


def test_import_rejects_conflicting_root_for_current_controller_identity(env):  # noqa: F811
    settings, _engine, factory, store, app = env
    client_setup(app, settings)
    with factory.begin() as db:
        own_root = recovery_root(db, store)
        own_id = db.get(ControllerState, 1).controller_id
        kit = build_recovery_kit(controller_id=own_id, recovery_root_secret=layout.new_recovery_root_secret(),
                                 destinations=[], repositories=[])
        plan = {"mode":"protected", "plan_version":1, "destinations":[], "repositories":[], "snapshots":[], "instances":[]}
        with pytest.raises(VaultRewindError) as error:
            apply_import_plan(db, store, plan, private_materials(kit), actor_id=None, job_id=uid())
        assert error.value.code == "CONTROLLER_RECOVERY_ROOT_CONFLICT"
        assert recovery_root(db, store) == own_root
        assert not db.scalar(select(Secret.id).where(Secret.kind == "controller_recovery_root", Secret.owner_scope == own_id))


def test_existing_unidentified_local_root_is_not_bound_to_a_foreign_controller(env):  # noqa: F811
    settings, engine, factory, store, app = env
    client_setup(app, settings)
    foreign_id, foreign_root = uid(), layout.new_recovery_root_secret()
    kit = build_recovery_kit(controller_id=foreign_id, recovery_root_secret=foreign_root,
                             destinations=[], repositories=[])
    plan = {"mode":"protected", "plan_version":1, "destinations":[], "repositories":[], "snapshots":[], "instances":[]}
    with factory.begin() as db:
        own_root = recovery_root(db, store)
        assert db.get(ControllerState, 1).controller_id is not None
        db.get(ControllerState, 1).controller_id = None  # Legacy initialized catalog.
        apply_import_plan(db, store, plan, private_materials(kit), actor_id=None, job_id=uid())
        local_id = db.get(ControllerState, 1).controller_id
        assert local_id and local_id != foreign_id
        assert recovery_root(db, store) == own_root
        secret_id = store.put(db, "job_input", "recovery_export", {"passphrase":"Synthetic legacy root recovery phrase 42"})
        job = enqueue(db, kind="recovery_export", request={"secret_id":secret_id}, key="legacy-root-reexport")
        job_id = job.id
    assert Worker(settings, engine=engine).run_once()
    exported = open_recovery_kit((settings.staging_dir / job_id / "recovery-kit.enc").read_bytes(),
                                 "Synthetic legacy root recovery phrase 42")
    assert exported["controller_id"] == local_id
    assert exported["recovery_root_secret"] == own_root
    assert exported["controller_recovery_roots"][foreign_id] == foreign_root


def test_foreign_controller_root_survives_import_reexport_and_opens_its_sealed_catalog(env, tmp_path):  # noqa: F811
    settings, engine, factory, store, app = env
    client_setup(app, settings)
    local_id, foreign_id, destination_id = uid(), uid(), uid()
    foreign_root = layout.new_recovery_root_secret()
    configuration = {"path": str(settings.local_storage_root)}
    entry = {"repository_id": uid(), "instance_id": foreign_id, "purpose": "controller",
             "destination_id": destination_id, "restic_repository_id": "a" * 64,
             "location": providers.repository_location("local", configuration, foreign_id, destination_id),
             "password": "synthetic-history-repository-password"}
    kit = build_recovery_kit(controller_id=foreign_id, recovery_root_secret=foreign_root,
        destinations=[{"destination_id": destination_id, "backend": "local", "configuration": configuration}],
        repositories=[entry])
    plan = {"mode": "protected", "plan_version": 1, "destinations": kit["destinations"],
            "repositories": [entry], "instances": [], "snapshots": []}
    with factory.begin() as db:
        db.get(ControllerState, 1).controller_id = local_id
        own_root = recovery_root(db, store)
        apply_import_plan(db, store, plan, private_materials(kit), actor_id=None, job_id=uid())
        assert recovery_root(db, store) == own_root
        imported = db.scalar(select(Secret).where(Secret.kind == "controller_recovery_root", Secret.owner_scope == foreign_id))
        assert store.get(db, imported.id) == foreign_root
        secret_id = store.put(db, "job_input", "recovery_export", {"passphrase": "Synthetic independent historical key 42"})
        job = enqueue(db, kind="recovery_export", request={"secret_id": secret_id}, key="historical-kit")
        job_id = job.id
    assert Worker(settings, engine=engine).run_once()
    exported = open_recovery_kit((settings.staging_dir / job_id / "recovery-kit.enc").read_bytes(),
                                 "Synthetic independent historical key 42")
    assert exported["controller_id"] == local_id
    assert exported["controller_recovery_roots"][foreign_id] == foreign_root
    assert exported["repositories"][0]["instance_id"] == foreign_id
    staging = tmp_path / "sealed"
    staging.mkdir()
    plaintext = staging / "catalog.json"
    catalog = {"format": "vaultrewind-controller-catalog", "schema_version": 1, "tables": []}
    plaintext.write_text(json.dumps(catalog))
    snapshot = uid()
    _seal_catalog(plaintext, staging, root_secret=foreign_root, controller_id=foreign_id,
                  physical_identity="b" * 64, snapshot_id=snapshot, max_bytes=1024**2)
    evidence = decrypt_catalog(staging, recovery_root_secret=exported["controller_recovery_roots"][foreign_id],
        controller_id=foreign_id, repository_identity="b" * 64, snapshot_uuid=snapshot)
    assert evidence["catalog"] == catalog

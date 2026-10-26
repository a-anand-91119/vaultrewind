"""Successful provider refresh must cross the recovery-to-controller persistence boundary."""
import shutil

from tests.unit.test_storage_drive import DEST, FOLDER, seeded_store, stored
from vaultrewind.recovery.offline import OfflineSession
from vaultrewind.security.secrets import SecretBox, generate_master_key
from vaultrewind.server.recovery_import import private_materials
from vaultrewind.storage.credentials import credential_context


def test_import_material_keeps_rotated_drive_token_after_discovery_workspace_cleanup(tmp_path):
    box = SecretBox(generate_master_key())
    original = stored(seeded_store(box), box)
    kit = {"controller_id": "informational-legacy-id", "destinations": [{"destination_id": DEST,
           "backend": "drive", "configuration": {"folder_id": FOLDER}, "credential": original}],
           "repositories": [], "instances": []}
    workspace = tmp_path / "import"
    session = OfflineSession(kit, workspace)
    current = session.store.load(DEST)
    rotated = {**original, "token": {**original["token"], "refresh_token": "synthetic-rotated-after-kit-export"}}
    session.store.compare_and_swap(DEST, session.box.encrypt(rotated, context=credential_context(DEST)),
                                  current.revision, expected_generation=current.generation)
    materials = private_materials(kit, work_dir=workspace)
    shutil.rmtree(workspace)
    assert materials["destinations"][0]["credential"]["token"]["refresh_token"] == "synthetic-rotated-after-kit-export"
    assert kit["destinations"][0]["credential"]["token"]["refresh_token"] != "synthetic-rotated-after-kit-export"


def test_offline_fresh_override_grant_survives_reopening_without_override(tmp_path):
    box = SecretBox(generate_master_key())
    original = stored(seeded_store(box), box)
    kit = {"destinations":[{"destination_id":DEST, "backend":"drive",
                            "configuration":{"folder_id":FOLDER}, "credential":original}]}
    workspace = tmp_path / "offline-override"
    OfflineSession(kit, workspace)
    override = {DEST:{"token":{**original["token"], "refresh_token":"synthetic-new-private-grant"}}}
    session = OfflineSession(kit, workspace, override)
    current = session.store.load(DEST)
    fresh = stored(session.store, session.box)
    assert fresh["grant_id"] != original["grant_id"]
    fresh["token"] = {**fresh["token"], "refresh_token":"synthetic-refreshed-private-grant"}
    session.store.compare_and_swap(DEST, session.box.encrypt(fresh, context=credential_context(DEST)),
                                   current.revision, expected_generation=current.generation)
    revision = session.store.load(DEST).revision
    for credentials in ({}, override, {}):
        resumed = OfflineSession(kit, workspace, credentials)
        assert stored(resumed.store, resumed.box) == fresh
        assert resumed.store.load(DEST).revision == revision

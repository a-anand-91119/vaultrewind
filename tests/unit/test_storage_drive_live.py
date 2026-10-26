"""Opt-in live Google Drive harness (AC14). Never runs without privately supplied test credentials.

Supply ONE of (all files must be owner-only, chmod 600, outside the repository):

* ``VAULTREWIND_LIVE_DRIVE_CREDENTIAL_FILE`` - JSON ``{"credential": {...}, "configuration": {...},
  "destination_id": "<uuid>"}`` exactly as returned by ``DriveAuthorization.complete`` /
  ``import_headless_token`` after authorizing the dedicated test account through the app; or
* ``VAULTREWIND_LIVE_DRIVE_CLIENT_FILE`` (``{"client_id", "client_secret"}``) plus
  ``VAULTREWIND_LIVE_DRIVE_TOKEN_FILE`` (the JSON printed by ``rclone authorize drive``); the harness then
  runs the headless import itself and creates a fresh test folder.

Run: ``python -m pytest -m live_drive tests/unit/test_storage_drive_live.py``. Rotated tokens persist in
``VAULTREWIND_LIVE_DRIVE_STATE`` (default ``.runtime/drive-live``, git-ignored). The destructive revocation
check runs only with ``VAULTREWIND_LIVE_DRIVE_ALLOW_REVOKE=1`` and requires re-authorizing afterwards.
Sanitized evidence (no tokens, folder ID hashed) is written to ``docs/evidence/drive-live.json``.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from tests.unit.test_storage_support import RCLONE, RESTIC, make_snapshot_tree, snapshot_args
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.oauth import utcnow
from vaultrewind.security.secrets import (
    SecretBox,
    load_master_key_file,
    write_master_key_file,
)
from vaultrewind.storage import drive, layout, providers
from vaultrewind.storage.credentials import FileCredentialStore, credential_context

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV = os.environ
CONFIGURED = bool(ENV.get("VAULTREWIND_LIVE_DRIVE_CREDENTIAL_FILE")
                  or (ENV.get("VAULTREWIND_LIVE_DRIVE_CLIENT_FILE") and ENV.get("VAULTREWIND_LIVE_DRIVE_TOKEN_FILE")))

pytestmark = [pytest.mark.live_drive, pytest.mark.integration,
              pytest.mark.skipif(not CONFIGURED, reason="live Drive credentials not supplied (AC14 remains pending)"),
              pytest.mark.skipif(RESTIC is None or RCLONE is None, reason="restic/rclone not installed")]


def _private_json(variable: str) -> dict | str:
    path = Path(ENV[variable])
    info = path.stat()
    if info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
        pytest.fail(f"{variable} must point to a regular chmod-600 file")
    text = path.read_text()
    try:
        return json.loads(text)
    except ValueError:
        return text


@pytest.fixture(scope="module")
def live():
    state = Path(ENV.get("VAULTREWIND_LIVE_DRIVE_STATE", REPO_ROOT / ".runtime" / "drive-live"))
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_file = state / "harness.key"
    if not key_file.exists():
        write_master_key_file(key_file)
    box = SecretBox(load_master_key_file(key_file))
    store = FileCredentialStore(state / "credentials")
    meta_file = state / "destination.json"
    if meta_file.exists():
        meta = json.loads(meta_file.read_text())
    else:
        if ENV.get("VAULTREWIND_LIVE_DRIVE_CREDENTIAL_FILE"):
            authorized = _private_json("VAULTREWIND_LIVE_DRIVE_CREDENTIAL_FILE")
            destination_id = authorized.get("destination_id") or str(uuid.uuid4())
        else:
            client = drive.GoogleClient(**_private_json("VAULTREWIND_LIVE_DRIVE_CLIENT_FILE"))
            token = _private_json("VAULTREWIND_LIVE_DRIVE_TOKEN_FILE")
            destination_id = str(uuid.uuid4())
            authorized = drive.import_headless_token(client, token if isinstance(token, str) else json.dumps(token),
                                                     destination_id=destination_id,
                                                     folder_name=f"VaultRewind live test {destination_id[:8]}")
        store.compare_and_swap(destination_id, box.encrypt(authorized["credential"],
                                                           context=credential_context(destination_id)), None)
        meta = {"destination_id": destination_id, "configuration": authorized["configuration"],
                "instance_id": str(uuid.uuid4())}
        meta_file.write_text(json.dumps(meta))
        meta_file.chmod(0o600)
    return {"state": state, "box": box, "store": store, **meta, "evidence": {}}


def _credential(live) -> dict:
    record = live["store"].load(live["destination_id"])
    return live["box"].decrypt(record.envelope, context=credential_context(live["destination_id"]))


def _evidence(live, step: str, outcome: dict) -> None:
    live["evidence"][step] = outcome
    path = REPO_ROOT / "docs" / "evidence" / "drive-live.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    folder_hash = hashlib.sha256(live["configuration"]["folder_id"].encode()).hexdigest()[:16]
    path.write_text(json.dumps({"provider": "google_drive", "scope": drive.SCOPE_NAME, "folder_id_sha256_16": folder_hash,
                                "restic": "0.19.1", "rclone": "1.75.2", "recorded_at": utcnow().isoformat(),
                                "steps": live["evidence"]}, indent=2) + "\n")


def test_live_probe_and_quota(live):
    result = providers.test_destination("drive", live["configuration"], None, destination_id=live["destination_id"],
                                        work_dir=live["state"] / "work", credential_store=live["store"], box=live["box"])
    _evidence(live, "probe", {"backup_ready": result["backup_ready"], "retention_ready": result["retention_ready"],
                              "credential_state": result["credential_state"], "quota_reported": bool(result["quota"])})
    assert result["backup_ready"] and result["retention_ready"]


def test_live_token_refresh_is_persisted_encrypted(live):
    credential = _credential(live)
    before_revision = live["store"].load(live["destination_id"]).revision
    expired = {**credential, "token": {**credential["token"], "expiry": drive._rfc3339(utcnow() - timedelta(hours=1))}}
    live["store"].compare_and_swap(live["destination_id"], live["box"].encrypt(
        expired, context=credential_context(live["destination_id"])), before_revision)
    result = providers.test_destination("drive", live["configuration"], None, destination_id=live["destination_id"],
                                        work_dir=live["state"] / "work", credential_store=live["store"], box=live["box"])
    after = _credential(live)
    refreshed = drive.token_expiry(after["token"]) > utcnow() + timedelta(minutes=30)
    _evidence(live, "refresh", {"refreshed_by_rclone": result["token_refresh"]["refreshed"],
                                "persisted": result["token_refresh"]["persisted"], "new_expiry_future": refreshed,
                                "revision_advanced": live["store"].load(live["destination_id"]).revision
                                > before_revision + 1})
    assert result["token_refresh"]["persisted"] >= 1 and refreshed


def test_live_backup_restore_and_retention(live, tmp_path):
    instance = live["instance_id"]
    password = layout.derive_repository_password(layout.new_recovery_root_secret(), instance, live["destination_id"])
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance, image_bytes=256 * 1024)
    kwargs = {"instance_id": instance, "destination_id": live["destination_id"], "password": password,
              "work_dir": live["state"] / "work", "credential_store": live["store"], "box": live["box"]}
    with providers.open_repository("drive", live["configuration"], None, **kwargs) as repo:
        repo_id = repo.initialize()["repository_id"]
        committed = repo.commit(*snapshot_args(stage, manifest))
        restored = repo.restore(committed["restic_snapshot_id"], tmp_path / "restored",
                                expected_manifest_hash=committed["manifest_hash"])
        check = repo.check()
        forgotten = repo.forget([committed["restic_snapshot_id"]])
        pruned = repo.prune()
    _evidence(live, "backup_restore_retention", {
        "repository_initialized": bool(repo_id), "stored_copy_verified": committed["stored_copy_verified"],
        "restored_bytes_verified": restored["restored_bytes_verified"], "structure_check_ok": check["ok"],
        "forget_complete": forgotten["complete"], "prune_check_ok": pruned["check"]["ok"]})
    assert committed["stored_copy_verified"] and restored["restored_bytes_verified"] and forgotten["complete"]


@pytest.mark.skipif(ENV.get("VAULTREWIND_LIVE_DRIVE_ALLOW_REVOKE") != "1",
                    reason="destructive revocation check needs VAULTREWIND_LIVE_DRIVE_ALLOW_REVOKE=1")
def test_live_revoked_token_reports_reconnect_required(live):
    assert drive.revoke(_credential(live))
    with pytest.raises(VaultRewindError) as error, providers.open_repository(
            "drive", live["configuration"], None, instance_id=live["instance_id"],
            destination_id=live["destination_id"], password="synthetic-unused-password-000",
            work_dir=live["state"] / "work", credential_store=live["store"], box=live["box"]) as repo:
        credential = _credential(live)
        expired = {**credential, "token": {**credential["token"], "expiry": drive._rfc3339(utcnow())}}
        live["store"].compare_and_swap(live["destination_id"], live["box"].encrypt(
            expired, context=credential_context(live["destination_id"])),
            live["store"].load(live["destination_id"]).revision)
        repo.list_snapshots()
    state = drive.classify_credential_state(error.value.code)
    _evidence(live, "revocation", {"error_code": error.value.code, "credential_state": state})
    assert state == "reconnect_required"
    (live["state"] / "destination.json").unlink()  # the next run must re-authorize

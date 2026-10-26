"""Registered Drive session recovery after SIGKILL, using synthetic credentials and local OAuth only."""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import threading
from datetime import timedelta
from http.server import HTTPServer
from pathlib import Path

import pytest

from tests.unit.test_storage_credential_recovery import persistent_store
from tests.unit.test_storage_drive import (
    CLIENT,
    DEST,
    FOLDER,
    _RejectExternalProxy,
    _TokenEndpoint,
    rotate_config,
    stored,
)
from tests.unit.test_storage_support import RCLONE
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.storage import drive
from vaultrewind.storage.credentials import (
    MAX_DRIVE_SESSIONS,
    MAX_RCLONE_CONFIG,
    DriveSessionJournal,
    credential_context,
    has_pending_credentials,
    has_unrecovered_drive_sessions,
)

REWRITE_AND_DIE = """
import os, sys
from pathlib import Path
from vaultrewind.storage.credentials import open_recovery_credentials
from vaultrewind.storage.drive import DriveCredentialSession, rclone_config_text
root, dest, folder = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
box, store = open_recovery_credentials(root)
s = DriveCredentialSession(dest, store, box, folder_id=folder, lock_dir=root/'locks',
                            runtime_dir=root/'old-job'/'runtime').__enter__()
credential = dict(s.base_credential)
credential['token'] = {**credential['token'], 'refresh_token': '1//synthetic-rewritten-before-kill'}
s.config_path.write_text(rclone_config_text(credential, folder))
with s.config_path.open('rb') as handle: os.fsync(handle.fileno())
os._exit(71)
"""


def orphaned(tmp_path):
    box, store = persistent_store(tmp_path)
    result = subprocess.run([sys.executable, "-c", REWRITE_AND_DIE, str(tmp_path / "offline"), DEST, FOLDER],
                            capture_output=True, check=False, timeout=20)
    assert result.returncode == 71, result.stderr.decode()
    config = next((tmp_path / "offline" / "old-job").rglob("rclone.conf"))
    assert not has_pending_credentials(store.state_directory)
    assert has_unrecovered_drive_sessions(store.state_directory)
    return box, store, config


def open_session(tmp_path, box, store):
    return drive.DriveCredentialSession(DEST, store, box, folder_id=FOLDER,
                                        lock_dir=tmp_path / "new-job" / "locks",
                                        runtime_dir=tmp_path / "new-job" / "runtime")


def test_abrupt_exit_recovers_registered_config_from_a_different_job_runtime(tmp_path):
    box, store, config = orphaned(tmp_path)
    with open_session(tmp_path, box, store) as session:
        assert drive.read_rclone_token(session.config_path)["refresh_token"] == "1//synthetic-rewritten-before-kill"
        assert session.recovered_sessions == 1 and session.outcome["persisted"] == 1
    assert not config.exists() and not config.parent.exists()
    assert not has_unrecovered_drive_sessions(store.state_directory)
    assert not has_pending_credentials(store.state_directory)
    assert store.load(DEST).revision == 2


@pytest.mark.skipif(RCLONE is None, reason="pinned rclone binary not installed")
def test_sigkill_after_real_rclone_rotation_replays_in_a_fresh_process(tmp_path):
    box, store = persistent_store(tmp_path)
    oauth = HTTPServer(("127.0.0.1", 0), _TokenEndpoint)
    proxy = HTTPServer(("127.0.0.1", 0), _RejectExternalProxy)
    for server in (oauth, proxy):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    _TokenEndpoint.bodies = []
    script = """
import json, os, sys
from pathlib import Path
from vaultrewind.storage import drive
from vaultrewind.storage.credentials import open_recovery_credentials
root, dest, folder, oauth, proxy = sys.argv[1:]
root = Path(root)
box, store = open_recovery_credentials(root)
s = drive.DriveCredentialSession(dest, store, box, folder_id=folder, lock_dir=root/'locks',
    runtime_dir=root/'old-job'/'runtime', rclone_overrides={'token_url': oauth}).__enter__()
real_run = drive.subprocess.run
def local_only(*args, **kwargs):
    kwargs['env'] = {**kwargs['env'], 'HTTPS_PROXY': proxy, 'HTTP_PROXY': proxy, 'NO_PROXY': '127.0.0.1,localhost'}
    return real_run(*args, **kwargs)
drive.subprocess.run = local_only
drive._rclone(s, ['lsjson', drive.REMOTE + ':'], timeout=30)
assert drive.read_rclone_token(s.config_path)['refresh_token'] == '1//synthetic-rotated-by-real-rclone'
with s.config_path.open('rb') as handle: os.fsync(handle.fileno())
print(json.dumps({'ready': True, 'config': str(s.config_path)}), flush=True)
sys.stdin.read()
"""
    proc = subprocess.Popen([sys.executable, "-c", script, str(tmp_path / "offline"), DEST, FOLDER,
                             f"http://127.0.0.1:{oauth.server_port}/token", f"http://127.0.0.1:{proxy.server_port}"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([proc.stdout], [], [], 40)[0], "rclone did not finish its synthetic refresh"
        line = proc.stdout.readline()
        assert line, proc.stderr.read() if proc.poll() is not None else "child exited without readiness"
        ready = json.loads(line)
        config = Path(ready["config"])
        metadata = next(store.state_directory.rglob("*.drive-session"))
        assert config.stat().st_mode & 0o777 == 0o600
        assert config.parent.stat().st_mode & 0o777 == 0o700
        assert metadata.stat().st_mode & 0o777 == 0o600
        for secret in (CLIENT.client_secret, "1//synthetic-rotated-by-real-rclone", "synthetic-session-refresh"):
            assert secret not in metadata.read_text()
        assert store.load(DEST).revision == 1 and not has_pending_credentials(store.state_directory)
        proc.kill()
        assert proc.wait(timeout=10) == -signal.SIGKILL
        resume = """
import json, sys, time
from pathlib import Path
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.storage.credentials import open_recovery_credentials, has_unrecovered_drive_sessions
from vaultrewind.storage.drive import DriveCredentialSession, read_rclone_token
root = Path(sys.argv[1])
box, store = open_recovery_credentials(root)
deadline = time.monotonic() + 5
while True:
    try:
        with DriveCredentialSession(sys.argv[2], store, box, folder_id=sys.argv[3], lock_dir=root/'locks',
                                    runtime_dir=root/'new-job'/'runtime') as s:
            token = read_rclone_token(s.config_path)
            assert token['refresh_token'] == '1//synthetic-rotated-by-real-rclone'
            print(json.dumps({'recovered': s.recovered_sessions, 'persisted': s.outcome['persisted']}))
        break
    except VaultRewindError as error:
        # A process can become temporarily unreadable during exec/exit. The
        # product must fail closed; retry only its explicit visibility result.
        if (error.code != 'CREDENTIAL_PERSIST_FAILED' or
                error.details.get('persistence_error_code') != 'CREDENTIAL_SESSION_BUSY'):
            raise
        assert has_unrecovered_drive_sessions(store.state_directory)
        assert store.load(sys.argv[2]).revision == 1
        assert read_rclone_token(Path(sys.argv[4]))['refresh_token'] == '1//synthetic-rotated-by-real-rclone'
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.1)
"""
        result = subprocess.run([sys.executable, "-c", resume, str(tmp_path / "offline"), DEST, FOLDER, str(config)],
                                capture_output=True, text=True, timeout=20, check=False)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"recovered": 1, "persisted": 1}
        assert _TokenEndpoint.bodies and not config.exists()
        assert stored(store, box)["token"]["refresh_token"] == "1//synthetic-rotated-by-real-rclone"
        assert not has_unrecovered_drive_sessions(store.state_directory)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)
        for server in (oauth, proxy):
            server.shutdown()
            server.server_close()


@pytest.mark.parametrize("boundary", ["delete", "reconnect", "tombstone", "new_record"])
def test_orphan_recovery_obeys_revocation_and_generation_boundaries(tmp_path, boundary):
    box, store, config = orphaned(tmp_path)
    current = stored(store, box)
    if boundary in {"delete", "new_record"}:
        store._path(DEST).unlink()
        if boundary == "new_record":
            store.compare_and_swap(DEST, box.encrypt(current, context=credential_context(DEST)), None)
    else:
        current.update({"grant_id": "synthetic-fresh-grant"} if boundary == "reconnect" else {"revoked": True})
        store.compare_and_swap(DEST, box.encrypt(current, context=credential_context(DEST)), 1)
    if boundary in {"delete", "tombstone"}:
        with pytest.raises(VaultRewindError) as error:
            open_session(tmp_path, box, store).__enter__()
        assert error.value.code == ("STORAGE_CREDENTIALS_MISSING" if boundary == "delete" else "STORAGE_AUTH_EXPIRED")
    else:
        with open_session(tmp_path, box, store) as session:
            assert session.outcome["stale_rejected"] == 1
    assert not config.exists() and not has_pending_credentials(store.state_directory)
    assert store.load(DEST) is None if boundary == "delete" else stored(store, box) == current


def test_live_session_lease_prevents_recovering_its_uncommitted_config(tmp_path):
    box, store = persistent_store(tmp_path)
    with open_session(tmp_path, box, store) as first:
        rotate_config(first, "ya29.synthetic-live-session-rotation", timedelta(hours=2))
        with open_session(tmp_path, box, store) as second:
            assert second.recovered_sessions == 0 and store.load(DEST).revision == 1
            assert first.config_path.exists()
    assert store.load(DEST).revision == 2 and not has_unrecovered_drive_sessions(store.state_directory)


@pytest.mark.parametrize("tamper", ["config_link", "workspace_link", "replaced_workspace", "permissions",
                                    "hardlink", "oversized", "wrong_client", "metadata"])
def test_orphan_recovery_rejects_untrusted_config_provenance(tmp_path, tamper):
    box, store, config = orphaned(tmp_path)
    if tamper == "config_link":
        outside = tmp_path / "unrelated.conf"
        config.rename(outside)
        config.symlink_to(outside)
    elif tamper == "workspace_link":
        outside = config.parent.with_name("renamed-workspace")
        config.parent.rename(outside)
        config.parent.symlink_to(outside, target_is_directory=True)
    elif tamper == "replaced_workspace":
        old = config.read_bytes()
        config.unlink()
        config.parent.rmdir()
        config.parent.mkdir(mode=0o700)
        config.write_bytes(old)
        config.chmod(0o600)
    elif tamper == "permissions":
        config.chmod(0o644)
    elif tamper == "hardlink":
        os.link(config, tmp_path / "other.conf")
    elif tamper == "oversized":
        with config.open("ab") as handle:
            handle.write(b"x" * MAX_RCLONE_CONFIG)
    elif tamper == "wrong_client":
        config.write_text(config.read_text().replace(CLIENT.client_id, "different-client.apps.googleusercontent.com"))
    else:
        metadata = next(store.state_directory.rglob("*.drive-session"))
        metadata.write_text(metadata.read_text()[:-10] + "not-valid!")
    with pytest.raises(VaultRewindError) as error:
        open_session(tmp_path, box, store).__enter__()
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED"
    assert store.load(DEST).revision == 1 and has_unrecovered_drive_sessions(store.state_directory)


def test_unregistered_config_is_never_used_or_scrubbed(tmp_path):
    box, store = persistent_store(tmp_path)
    unrelated = tmp_path / "new-job" / "runtime" / "vaultrewind-rclone-unregistered"
    unrelated.mkdir(mode=0o700, parents=True)
    config = unrelated / "rclone.conf"
    credential = stored(store, box)
    credential["token"] = {**credential["token"], "refresh_token": "1//synthetic-untrusted-refresh"}
    config.write_text(drive.rclone_config_text(credential, FOLDER))
    config.chmod(0o600)
    with open_session(tmp_path, box, store) as session:
        assert session.recovered_sessions == 0
        assert drive.read_rclone_token(session.config_path)["refresh_token"] != "1//synthetic-untrusted-refresh"
    assert config.exists() and store.load(DEST).revision == 1


def test_orphan_is_encrypted_and_scrubbed_even_if_store_is_temporarily_unavailable(tmp_path, monkeypatch):
    box, store, config = orphaned(tmp_path)
    original = store.load

    def broken(*args):
        raise VaultRewindError("DB_DOWN", "synthetic store outage")

    with monkeypatch.context() as patch:
        patch.setattr(store, "load", broken)
        with pytest.raises(VaultRewindError) as error:
            open_session(tmp_path, box, store).__enter__()
        assert error.value.code == "CREDENTIAL_PERSIST_FAILED" and error.value.details["pending_encrypted"]
    assert not config.exists() and has_pending_credentials(store.state_directory)
    assert not has_unrecovered_drive_sessions(store.state_directory)
    assert original(DEST).revision == 1
    with open_session(tmp_path, box, store):
        pass
    assert stored(store, box)["token"]["refresh_token"] == "1//synthetic-rewritten-before-kill"


def test_orphan_recovery_waits_for_a_lingering_provider_process(tmp_path):
    box, store, config = orphaned(tmp_path)
    env = {**os.environ, "RCLONE_CONFIG": str(config)}
    proc = subprocess.Popen([sys.executable, "-c", "import sys; print('ready', flush=True); sys.stdin.read()"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
    try:
        assert select.select([proc.stdout], [], [], 10)[0] and proc.stdout.readline().strip() == "ready"
        with pytest.raises(VaultRewindError) as error:
            open_session(tmp_path, box, store).__enter__()
        assert error.value.details["persistence_error_code"] == "CREDENTIAL_SESSION_BUSY"
        assert config.exists() and store.load(DEST).revision == 1
    finally:
        proc.kill()
        proc.communicate(timeout=10)
    with open_session(tmp_path, box, store):
        pass
    assert not config.exists() and store.load(DEST).revision == 2


def test_registered_session_scan_is_bounded(tmp_path):
    box, store = persistent_store(tmp_path)
    journal = DriveSessionJournal(store.state_directory, box, DEST)
    for index in range(MAX_DRIVE_SESSIONS + 1):
        (journal.directory / f"{DEST}.{index}.drive-session").write_text("synthetic-invalid-metadata")
    with pytest.raises(VaultRewindError) as error:
        journal.paths()
    assert error.value.code == "CREDENTIAL_SESSION_LIMIT"


@pytest.mark.parametrize("boundary", ["before_config", "after_config", "finalized"])
def test_session_registration_and_retirement_crash_windows_are_recoverable(tmp_path, boundary):
    box, store = persistent_store(tmp_path)
    script = """
import os, sys
from pathlib import Path
from vaultrewind.storage import drive
from vaultrewind.storage.credentials import open_recovery_credentials, DriveSessionJournal
root, dest, folder, boundary = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
box, store = open_recovery_credentials(root)
if boundary == 'before_config':
    def interrupted(*args, **kwargs): os._exit(73)
    drive.write_private_file = interrupted
elif boundary == 'after_config':
    original = DriveSessionJournal.save
    def interrupted(self, record, *, phase=None):
        if phase == 'ready': os._exit(73)
        return original(self, record, phase=phase)
    DriveSessionJournal.save = interrupted
s = drive.DriveCredentialSession(dest, store, box, folder_id=folder, lock_dir=root/'locks',
                                 runtime_dir=root/'old-job'/'runtime').__enter__()
s.sessions.save(s.session_record, phase='finalized')
os._exit(73)
"""
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path / "offline"), DEST, FOLDER, boundary],
                            check=False, capture_output=True, timeout=20)
    assert result.returncode == 73, result.stderr.decode()
    with open_session(tmp_path, box, store):
        pass
    assert not has_unrecovered_drive_sessions(store.state_directory)
    assert store.load(DEST).revision == 1
    assert not list((tmp_path / "offline" / "old-job").rglob("rclone.conf"))


def test_orphan_journal_write_failure_keeps_the_only_rotated_config_for_automatic_retry(tmp_path, monkeypatch):
    from vaultrewind.storage.credentials import PendingCredentialUpdates
    box, store, config = orphaned(tmp_path)

    def broken(*args):
        raise OSError("synthetic journal IO failure")

    with monkeypatch.context() as patch:
        patch.setattr(PendingCredentialUpdates, "save", broken)
        with pytest.raises(VaultRewindError) as error:
            open_session(tmp_path, box, store).__enter__()
        assert not error.value.details["pending_encrypted"] and error.value.details["cleanup_blocked"]
    assert config.exists() and has_unrecovered_drive_sessions(store.state_directory)
    with open_session(tmp_path, box, store):
        pass
    assert not config.exists() and store.load(DEST).revision == 2


def test_missing_registered_ready_config_does_not_silently_reuse_an_old_token(tmp_path):
    box, store, config = orphaned(tmp_path)
    config.unlink()
    with pytest.raises(VaultRewindError) as error:
        open_session(tmp_path, box, store).__enter__()
    assert error.value.details["persistence_error_code"] == "CREDENTIAL_SESSION_MISSING"
    assert store.load(DEST).revision == 1 and has_unrecovered_drive_sessions(store.state_directory)


def test_recovery_metadata_checkpoints_lineage_after_an_explicit_sync(tmp_path):
    box, store = persistent_store(tmp_path)
    script = REWRITE_AND_DIE.replace(
        "with s.config_path.open('rb') as handle: os.fsync(handle.fileno())",
        """s.sync()
credential['token'] = {**credential['token'], 'refresh_token': '1//synthetic-second-rotation-before-kill'}
s.config_path.write_text(rclone_config_text(credential, folder))
with s.config_path.open('rb') as handle: os.fsync(handle.fileno())""")
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path / "offline"), DEST, FOLDER],
                            check=False, capture_output=True, timeout=20)
    assert result.returncode == 71, result.stderr.decode()
    assert store.load(DEST).revision == 2
    with open_session(tmp_path, box, store):
        pass
    assert store.load(DEST).revision == 3
    assert stored(store, box)["token"]["refresh_token"] == "1//synthetic-second-rotation-before-kill"

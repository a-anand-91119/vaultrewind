"""Synthetic credential-store outages, restarts, refresh rotation, and revocation boundaries."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import timedelta

import pytest

from tests.unit.test_storage_drive import CLIENT, DEST, FOLDER, rotate_config, seeded_store, stored
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.oauth import utcnow
from vaultrewind.security.secrets import SecretBox, generate_master_key
from vaultrewind.storage import drive
from vaultrewind.storage.credentials import (
    FileCredentialStore,
    MemoryCredentialStore,
    credential_context,
    has_pending_credentials,
    open_recovery_credentials,
)


def persistent_store(tmp_path):
    box, store = open_recovery_credentials(tmp_path / "offline")
    credential = stored(seeded_store(box), box)
    store.compare_and_swap(DEST, box.encrypt(credential, context=credential_context(DEST)), None)
    return box, store


def session_for(tmp_path, box, store):
    return drive.DriveCredentialSession(DEST, store, box, folder_id=FOLDER,
                                        lock_dir=tmp_path / "disposable" / "locks",
                                        runtime_dir=tmp_path / "scratch")


def fail_persistence(tmp_path, box, store, *, operation_error=False):
    original = store.compare_and_swap

    def broken(*args, **kwargs):
        raise VaultRewindError("DB_DOWN", "synthetic database unavailable")

    with pytest.raises(VaultRewindError) as error, session_for(tmp_path, box, store) as session:
        rotate_config(session, "ya29.synthetic-pending-rotation", timedelta(hours=1))
        token = drive.read_rclone_token(session.config_path)
        token["refresh_token"] = "1//synthetic-rotated-refresh-B"
        text = session.config_path.read_text().splitlines()
        session.config_path.write_text("\n".join(
            "token = " + json.dumps(token) if line.startswith("token = ") else line for line in text) + "\n")
        store.compare_and_swap = broken
        if operation_error:
            raise VaultRewindError("STORAGE_TIMEOUT", "synthetic operation timeout", True)
    store.compare_and_swap = original
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED"
    assert error.value.details == {"pending_recovery_required": True, "cleanup_blocked": True,
                                   "pending_encrypted": True,
                                   "operation_error_code": "STORAGE_TIMEOUT" if operation_error else None,
                                   "persistence_error_code": "DB_DOWN"}
    assert not session.workspace.exists()
    assert store.load(DEST).revision == 1
    assert has_pending_credentials(store.state_directory)
    for path in store.state_directory.rglob("*"):
        if path.is_file():
            for secret in (b"ya29.synthetic-pending-rotation", b"1//synthetic-rotated-refresh-B",
                           CLIENT.client_secret.encode()):
                assert secret not in path.read_bytes()
    return session


@pytest.mark.parametrize("operation_error", [False, True])
def test_outage_preserves_encrypted_rotation_and_recovers_in_a_fresh_process(tmp_path, operation_error):
    box, store = persistent_store(tmp_path)
    fail_persistence(tmp_path, box, store, operation_error=operation_error)
    # A real new interpreter loads only the durable key, store and pending encrypted update.
    script = """
import sys
from pathlib import Path
from vaultrewind.storage.credentials import open_recovery_credentials
from vaultrewind.storage.drive import DriveCredentialSession
box, store = open_recovery_credentials(Path(sys.argv[1]))
with DriveCredentialSession(sys.argv[2], store, box, folder_id=sys.argv[3],
                            lock_dir=Path(sys.argv[1]) / 'locks', runtime_dir=Path(sys.argv[1]) / 'runtime') as s:
    assert s.outcome['persisted'] == 1
"""
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path / "offline"), DEST, FOLDER],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    reopened_box, reopened = open_recovery_credentials(tmp_path / "offline")
    assert reopened_box.key_id == box.key_id
    token = stored(reopened, reopened_box)["token"]
    assert token["access_token"] == "ya29.synthetic-pending-rotation"
    assert token["refresh_token"] == "1//synthetic-rotated-refresh-B"
    assert reopened.load(DEST).revision == 2
    assert not has_pending_credentials(reopened.state_directory)


def test_cas_conflict_reloads_current_revision_and_preserves_other_credential_metadata(tmp_path):
    box, store = persistent_store(tmp_path)
    real_cas = store.compare_and_swap
    calls = []

    def racing(destination_id, envelope, expected_revision, **kwargs):
        calls.append((expected_revision, kwargs["expected_generation"]))
        if len(calls) == 1:
            current = {**stored(store, box), "operator_note": "synthetic-updated-metadata"}
            real_cas(DEST, box.encrypt(current, context=credential_context(DEST)), expected_revision,
                     **kwargs)
            raise VaultRewindError("CREDENTIAL_STALE", "synthetic concurrent metadata update")
        return real_cas(destination_id, envelope, expected_revision, **kwargs)

    with session_for(tmp_path, box, store) as session:
        rotate_config(session, "ya29.synthetic-cas-retry", timedelta(hours=2))
        store.compare_and_swap = racing
    assert [revision for revision, _ in calls] == [1, 2]
    assert stored(store, box)["operator_note"] == "synthetic-updated-metadata"
    assert stored(store, box)["token"]["access_token"] == "ya29.synthetic-cas-retry"
    assert not has_pending_credentials(store.state_directory)


@pytest.mark.parametrize("boundary", ["delete", "reconnect", "tombstone", "new_record", "newer_refresh"])
def test_pending_refresh_never_revives_a_revoked_or_superseded_grant(tmp_path, boundary):
    box, store = persistent_store(tmp_path)
    fail_persistence(tmp_path, box, store)
    current = stored(store, box)
    expected = store.load(DEST)
    if boundary in {"delete", "new_record"}:
        store._path(DEST).unlink()
        if boundary == "new_record":
            # Even identical grant labels and a reset revision must not allow an ABA rollback.
            store.compare_and_swap(DEST, box.encrypt(current, context=credential_context(DEST)), None)
            assert store.load(DEST).generation != expected.generation
    else:
        if boundary == "reconnect":
            current.update(grant_id="synthetic-new-grant")
        elif boundary == "tombstone":
            current.update(revoked_at=drive._rfc3339(utcnow()))
        else:
            current["token"] = {**current["token"], "refresh_token": "1//synthetic-newest-refresh-C",
                                "access_token": "ya29.synthetic-newest-generation",
                                "expiry": drive._rfc3339(utcnow() + timedelta(hours=3))}
        store.compare_and_swap(DEST, box.encrypt(current, context=credential_context(DEST)), expected.revision)
    if boundary == "newer_refresh":
        with pytest.raises(VaultRewindError) as error:
            session_for(tmp_path, box, store).__enter__()
        assert error.value.code == "CREDENTIAL_PERSIST_FAILED"
        assert has_pending_credentials(store.state_directory)
        assert stored(store, box) == current
        # Explicit reconnect resolves the conflict without replaying either old grant.
        current["grant_id"] = "synthetic-resolved-with-new-grant"
        store.compare_and_swap(DEST, box.encrypt(current, context=credential_context(DEST)), store.load(DEST).revision)
        with session_for(tmp_path, box, store):
            pass
    elif boundary in {"delete", "tombstone"}:
        with pytest.raises(VaultRewindError) as error:
            session_for(tmp_path, box, store).__enter__()
        assert error.value.code == ("STORAGE_CREDENTIALS_MISSING" if boundary == "delete" else "STORAGE_AUTH_EXPIRED")
    else:
        with session_for(tmp_path, box, store) as session:
            assert session.outcome["stale_rejected"] == 1
    assert not has_pending_credentials(store.state_directory)
    if boundary == "delete":
        assert store.load(DEST) is None
    else:
        assert stored(store, box) == current


def test_replacement_record_during_cas_cannot_reuse_its_revision_to_restore_old_grant(tmp_path):
    box, store = persistent_store(tmp_path)
    real_cas = store.compare_and_swap
    entered = False

    def racing(destination_id, envelope, expected_revision, **kwargs):
        nonlocal entered
        if not entered:
            entered = True
            replacement = {**stored(store, box), "grant_id": "new-record-and-grant"}
            store._path(DEST).unlink()
            real_cas(DEST, box.encrypt(replacement, context=credential_context(DEST)), None)
        return real_cas(destination_id, envelope, expected_revision, **kwargs)

    with session_for(tmp_path, box, store) as session:
        rotate_config(session, "ya29.synthetic-old-generation", timedelta(hours=3))
        store.compare_and_swap = racing
    assert stored(store, box)["grant_id"] == "new-record-and-grant"
    assert store.load(DEST).revision == 1 and session.outcome["stale_rejected"] == 1


def test_lost_commit_acknowledgment_reconciles_without_duplicate_revision(tmp_path):
    box, store = persistent_store(tmp_path)
    real_cas = store.compare_and_swap

    def ack_lost(*args, **kwargs):
        real_cas(*args, **kwargs)
        raise VaultRewindError("DB_DOWN", "synthetic response lost after commit")

    with pytest.raises(VaultRewindError) as error, session_for(tmp_path, box, store) as session:
        rotate_config(session, "ya29.synthetic-committed-before-crash", timedelta(hours=2))
        store.compare_and_swap = ack_lost
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED" and store.load(DEST).revision == 2
    store.compare_and_swap = real_cas
    with session_for(tmp_path, box, store):
        pass
    assert store.load(DEST).revision == 2 and not has_pending_credentials(store.state_directory)


def test_pending_updates_survive_master_key_rotation_when_previous_key_is_loaded(tmp_path):
    box, store = persistent_store(tmp_path)
    old_key = (tmp_path / "offline" / "recovery-credentials" / "master.key").read_bytes()
    from vaultrewind.security.secrets import decode_master_key
    fail_persistence(tmp_path, box, store)
    new_box = SecretBox(generate_master_key(), previous_keys=[decode_master_key(old_key)])
    with session_for(tmp_path, new_box, store):
        pass
    assert SecretBox.envelope_key_id(store.load(DEST).envelope) == new_box.key_id
    assert stored(store, new_box)["token"]["refresh_token"] == "1//synthetic-rotated-refresh-B"
    assert not has_pending_credentials(store.state_directory)


def test_missing_decryption_key_keeps_pending_update_and_prevents_session_start(tmp_path):
    box, store = persistent_store(tmp_path)
    fail_persistence(tmp_path, box, store)
    with pytest.raises(VaultRewindError) as error:
        session_for(tmp_path, SecretBox(generate_master_key()), store).__enter__()
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED" and error.value.details["pending_encrypted"]
    assert has_pending_credentials(store.state_directory)
    key = tmp_path / "offline" / "recovery-credentials" / "master.key"
    key.unlink()
    with pytest.raises(VaultRewindError) as missing:
        open_recovery_credentials(tmp_path / "offline")
    assert missing.value.code == "SECRET_KEY_UNAVAILABLE" and not key.exists()


@pytest.mark.parametrize("boundary", ["root_link", "directory_link", "key_link", "key_permissions",
                                      "directory_permissions", "store_link", "credential_link"])
def test_persistent_recovery_state_rejects_symlinks_and_permissive_credentials(tmp_path, boundary):
    root = tmp_path / "offline"
    _box, store = persistent_store(tmp_path)
    directory = root / "recovery-credentials"
    key = directory / "master.key"
    if boundary in {"root_link", "directory_link", "store_link", "key_link", "credential_link"}:
        path = {"root_link": root, "directory_link": directory, "store_link": directory / "store",
                "key_link": key, "credential_link": store._path(DEST)}[boundary]
        target = path.with_name(path.name + ".real")
        path.rename(target)
        path.symlink_to(target)
    elif boundary == "key_permissions":
        key.chmod(0o644)
    else:
        directory.chmod(0o755)
    with pytest.raises((VaultRewindError, OSError)):
        if boundary == "credential_link":
            store.load(DEST)
        else:
            open_recovery_credentials(root)


@pytest.mark.parametrize("kind", [MemoryCredentialStore, FileCredentialStore])
def test_generation_cas_rejects_identical_revision_from_replacement_store(tmp_path, kind):
    store = kind(tmp_path / "credentials") if kind is FileCredentialStore else kind()
    store.compare_and_swap(DEST, "synthetic-envelope-first", None)
    first = store.load(DEST)
    if kind is FileCredentialStore:
        store._path(DEST).unlink()
    else:
        store._items.pop(DEST)
    store.compare_and_swap(DEST, "synthetic-envelope-new-record", None)
    with pytest.raises(VaultRewindError) as error:
        store.compare_and_swap(DEST, "synthetic-stale-envelope", first.revision,
                               expected_generation=first.generation)
    assert error.value.code == "CREDENTIAL_STALE"
    assert store.load(DEST).envelope == "synthetic-envelope-new-record"


def test_private_recovery_files_are_owner_only(tmp_path):
    _, store = persistent_store(tmp_path)
    for path in (tmp_path / "offline" / "recovery-credentials").rglob("*"):
        assert path.stat().st_uid == os.geteuid()
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    assert store.state_directory.is_relative_to(tmp_path / "offline")


def test_store_load_outage_after_refresh_cannot_lose_the_candidate(tmp_path):
    box, store = persistent_store(tmp_path)
    original = store.load

    def broken(*args):
        raise VaultRewindError("DB_DOWN", "synthetic load outage")

    with pytest.raises(VaultRewindError) as error, session_for(tmp_path, box, store) as session:
        rotate_config(session, "ya29.synthetic-pending-load-outage", timedelta(hours=1))
        store.load = broken
    store.load = original
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED" and not session.workspace.exists()
    assert has_pending_credentials(store.state_directory)
    with session_for(tmp_path, box, store):
        pass
    assert stored(store, box)["token"]["access_token"] == "ya29.synthetic-pending-load-outage"


def test_refresh_token_rotation_is_preserved_even_without_later_access_expiry(tmp_path):
    box, store = persistent_store(tmp_path)
    with session_for(tmp_path, box, store) as session:
        credential = stored(store, box)
        credential["token"]["refresh_token"] = "1//synthetic-rotated-equal-expiry"
        session.config_path.write_text(drive.rclone_config_text(credential, FOLDER))
    assert stored(store, box)["token"]["refresh_token"] == "1//synthetic-rotated-equal-expiry"
    assert session.outcome["persisted"] == 1


def test_unparseable_config_is_preserved_encrypted_and_invalidated_only_by_fresh_grant(tmp_path):
    box, store = persistent_store(tmp_path)
    with pytest.raises(VaultRewindError) as error, session_for(tmp_path, box, store) as session:
        session.config_path.write_text("[broken\ntoken = 1//synthetic-truncated-rotated-token\n")
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED"
    assert error.value.details["persistence_error_code"] == "CREDENTIAL_REFRESH_UNREADABLE"
    assert not session.workspace.exists() and has_pending_credentials(store.state_directory)
    pending = next(store.state_directory.rglob("*.pending-credential"))
    assert "1//synthetic-truncated-rotated-token" not in pending.read_text()
    with pytest.raises(VaultRewindError):
        session_for(tmp_path, box, store).__enter__()
    credential = {**stored(store, box), "grant_id": "synthetic-reconnected-after-truncation"}
    store.compare_and_swap(DEST, box.encrypt(credential, context=credential_context(DEST)), 1)
    with session_for(tmp_path, box, store):
        pass
    assert not has_pending_credentials(store.state_directory)


def test_journal_io_failure_uses_guarded_encrypted_store_before_cleaning_scratch(tmp_path, monkeypatch):
    box, store = persistent_store(tmp_path)
    with session_for(tmp_path, box, store) as session:
        rotate_config(session, "ya29.synthetic-journal-disk-fault", timedelta(hours=1))

        def broken(*args):
            raise OSError("synthetic journal disk fault")

        monkeypatch.setattr(session.pending, "save", broken)
    assert not session.workspace.exists()
    assert stored(store, box)["token"]["access_token"] == "ya29.synthetic-journal-disk-fault"


def test_total_persistence_outage_blocks_scrub_until_a_durable_encrypted_copy_exists(tmp_path, monkeypatch):
    box, store = persistent_store(tmp_path)
    session = session_for(tmp_path, box, store).__enter__()
    rotate_config(session, "ya29.synthetic-double-storage-outage", timedelta(hours=1))
    config = session.config_path

    def broken(*args, **kwargs):
        raise OSError("synthetic both persistence channels unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(session.pending, "save", broken)
        patch.setattr(store, "compare_and_swap", broken)
        with pytest.raises(VaultRewindError) as error:
            session.__exit__(None, None, None)
        assert error.value.code == "CREDENTIAL_PERSIST_FAILED"
        assert error.value.details["cleanup_blocked"] and not error.value.details["pending_encrypted"]
        assert config.exists(), "never delete the only refreshed token while every durable store is unavailable"
    # Once storage recovers, the retained session can journal/CAS and then scrub all scratch.
    session.__exit__(None, None, None)
    assert not config.exists() and not session.workspace.exists()
    assert stored(store, box)["token"]["access_token"] == "ya29.synthetic-double-storage-outage"


def test_recovery_helper_accepts_persistent_raw32_key_material(tmp_path):
    root = tmp_path / "offline"
    open_recovery_credentials(root)
    master_key = generate_master_key()
    (root / "recovery-credentials" / "master.key").write_bytes(master_key)
    box, _ = open_recovery_credentials(root)
    assert box.key_id == SecretBox(master_key).key_id

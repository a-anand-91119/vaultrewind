"""Private rotation uses disposable SQLite only; no provider probes or source writes."""
# ruff: noqa: F811  # Imported pytest fixture is intentionally requested by name.
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from tests.unit.test_server import env, seed  # noqa: F401
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.adapters import SQLCredentialStore
from vaultrewind.server.db import now, uid
from vaultrewind.server.destination_updates import destination_view, update_destination
from vaultrewind.server.models import (
    AuditEvent,
    ControllerState,
    Repository,
    ResourceLease,
    Secret,
    StorageDestination,
)
from vaultrewind.storage import drive, providers
from vaultrewind.storage.credentials import PendingCredentialUpdates, credential_context

CLIENT = {"client_id": "123456789012-synthetic.apps.googleusercontent.com",
          "client_secret": "GOCSPX-syntheticClientSecret"}
S3 = {"endpoint": "https://minio.synthetic.invalid", "bucket": "synthetic-bucket", "prefix": "copies"}
KEYS = {"access_key_id": "synthetic-old-key", "secret_access_key": "synthetic-old-secret",
        "session_token": "synthetic-old-session"}


def destination(db, store, backend="s3", config=None, credential=None):
    ident = uid()
    config = config if config is not None else S3
    credential = credential if credential is not None else KEYS
    row = StorageDestination(id=ident, name="Synthetic destination", backend=backend,
        configuration_secret_id=store.put(db, "destination_configuration", ident, config),
        credential_id=store.put(db, "provider_credentials", ident, credential) if credential else None,
        health="healthy", last_test_at=now())
    db.add(row)
    db.flush()
    return row


def repository(db, store, row, *, owner=None, controller=False):
    config = store.get(db, row.configuration_secret_id)
    ident, owner = uid(), owner or uid()
    private = {"location": providers.repository_location(row.backend, config, owner, row.id),
               "backend": row.backend, "destination_id": row.id, "destination_configuration": config}
    if controller:
        private["controller_id"] = owner
    repo = Repository(id=ident, instance_id=None if controller else owner, destination_id=row.id,
        purpose="controller" if controller else "instance",
        configuration_secret_id=store.put(db, "repository_configuration", ident, private),
        key_id=store.put(db, "repository_key", ident, "synthetic-repository-password"),
        physical_identity=providers.physical_identity(row.backend, config, owner, row.id))
    db.add(repo)
    db.flush()
    return repo


def test_detail_and_update_never_return_credentials_or_private_ca(env):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        original_id = row.credential_id
        view = destination_view(db, store, row.id)
        assert view["credential_flags"] == dict.fromkeys(KEYS, True)
        assert not any(value in json.dumps(view) for value in KEYS.values())
        result = update_destination(db, store, settings, row.id,
            {"credentials": {"access_key_id": "synthetic-new-key", "secret_access_key": "synthetic-new-secret"}}, 1, None)
        assert row.credential_id != original_id
        assert result["revision"] == 2 and result["health"] == "untested"
        assert result["last_test_at"] is None
        assert store.get(db, row.credential_id) == {
            "access_key_id": "synthetic-new-key", "secret_access_key": "synthetic-new-secret"}
        assert store.get(db, original_id) == KEYS
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "storage.update"))
        assert event.changes["fields"] == ["credentials.access_key_id", "credentials.secret_access_key"]
        serialized = json.dumps(result) + json.dumps(event.changes)
        assert "synthetic-new-key" not in serialized and "synthetic-new-secret" not in serialized
        assert "ca_cert_pem" not in result["configuration"]


def test_blank_fields_keep_pair_and_name_only_keeps_health(env):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        original = row.credential_id
        result = update_destination(db, store, settings, row.id, {"name": "Renamed",
            "credentials": {"access_key_id": "", "secret_access_key": "", "session_token": ""}}, 1, None)
        assert row.credential_id == original and result["health"] == "healthy"
        assert result["name"] == "Renamed" and result["last_test_at"]


@pytest.mark.parametrize("changes", [
    {"credentials": {"access_key_id": "only-key"}},
    {"credentials": {"secret_access_key": "only-secret"}},
    {"credentials": {"session_token": "only-token"}},
    {"credentials": {"access_key_id": "key", "secret_access_key": "bad\nsecret"}},
    {"configuration": {"recovery_mode": False}}, {"credentials": {"recovery_mode": True}},
    {"recovery_mode": False}, {"backend": "drive"}, {"name": ""},
    {"configuration": {"development_http": "true"}}, {"configuration": {"region": 3}},
    {"configuration": {"endpoint": "https://key:secret@example.invalid"}},
    {"configuration": {"ca_cert_pem": "PRIVATE KEY"}}, {"configuration": None},
])
def test_invalid_update_leaves_rows_unchanged(env, changes):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        before = (row.credential_id, row.configuration_secret_id, row.revision)
        with pytest.raises(VaultRewindError):
            update_destination(db, store, settings, row.id, changes, 1, None)
        assert (row.credential_id, row.configuration_secret_id, row.revision) == before


@pytest.mark.parametrize("revision", [None, 0, 2, True, '1'])
def test_revision_guard(env, revision):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        with pytest.raises(VaultRewindError) as failure:
            update_destination(db, store, settings, row.id, {"name": "Other"}, revision, None)
        assert failure.value.code == "REVISION_CONFLICT"
        assert row.revision == 1


@pytest.mark.parametrize("expired", [False, True])
def test_owned_credential_lease_cannot_be_bypassed(env, expired):
    from vaultrewind.server.queue import enqueue
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        job = enqueue(db, kind="storage_test", request={}, key=uid(), resources=[f"credential:{row.id}"])
        lease = db.get(ResourceLease, f"credential:{row.id}")
        lease.owner_job_id = job.id
        lease.expires_at = now() + timedelta(seconds=-60 if expired else 60)
        with pytest.raises(VaultRewindError) as failure:
            update_destination(db, store, settings, row.id, {"name": "Busy"}, 1, None)
        assert failure.value.code == "RESOURCE_BUSY"


@pytest.mark.parametrize("backend,config,delta", [
    ("s3", S3, {"bucket": "another-bucket"}),
    ("s3", S3, {"endpoint": "https://other.synthetic.invalid"}),
    ("s3", S3, {"prefix": "another-prefix"}),
    ("local", {"path": "/synthetic/backups"}, {"path": "/synthetic/backups/other"}),
    ("drive", {"folder_id": "SyntheticFolder0001", "scope": "drive.file"}, {"folder_id": "OtherFolder00001"}),
])
def test_controller_repository_identity_is_immutable(env, backend, config, delta):
    settings, _, factory, store, _ = env
    if backend == "local":
        settings = settings.model_copy(update={"local_storage_root": Path("/synthetic/backups")})
    with factory.begin() as db:
        row = destination(db, store, backend, config, CLIENT if backend == "drive" else {})
        repo = repository(db, store, row, controller=True)
        identity, key = repo.physical_identity, repo.key_id
        with pytest.raises(VaultRewindError) as failure:
            update_destination(db, store, settings, row.id, {"configuration": delta}, 1, None)
        assert failure.value.code == "DESTINATION_IDENTITY_CHANGED"
        assert repo.physical_identity == identity and repo.key_id == key


def test_instance_repository_credentials_follow_destination_and_settings_keep_identity(env):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        _, _, instance, _, _ = seed(db, store)
        row = destination(db, store)
        repo = repository(db, store, row, owner=instance.id)
        before = (repo.id, repo.physical_identity, repo.key_id, repo.configuration_secret_id)
        update_destination(db, store, settings, row.id, {"configuration": {"region": "us-west-2"},
            "credentials": {"access_key_id": "synthetic-repaired-key", "secret_access_key": "synthetic-repaired-secret"}}, 1, None)
        assert (repo.id, repo.physical_identity, repo.key_id, repo.configuration_secret_id) == before
        assert store.get(db, db.get(StorageDestination, repo.destination_id).credential_id)["access_key_id"] == "synthetic-repaired-key"


def test_controller_owner_falls_back_to_current_state(env):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        owner = uid()
        repo = repository(db, store, row, owner=owner, controller=True)
        private = store.get(db, repo.configuration_secret_id)
        private.pop("controller_id")
        store.replace(db, repo.configuration_secret_id, private)
        db.add(ControllerState(id=1, controller_id=owner))
        result = update_destination(db, store, settings, row.id, {"name": "State fallback"}, 1, None)
        assert result["repository_count"] == 1


def test_drive_client_rotation_invalidates_old_grant_and_rejects_stale_sql_cas(env):
    settings, _, factory, store, _ = env
    old = {"type": "google_drive_oauth", **CLIENT, "scope": "drive.file", "folder_id": "SyntheticFolder0001",
           "grant_id": uid(), "token": {"access_token": "synthetic-old-access", "refresh_token": "synthetic-old-refresh"}}
    with factory.begin() as db:
        row = destination(db, store, "drive", {"folder_id": old["folder_id"]}, old)
        ident, generation = row.id, row.credential_id
    sql = SQLCredentialStore(SimpleNamespace(settings=settings, sessions=factory, secrets=store))
    stale = sql.load(ident)
    fresh_client = {"client_id": "987654321012-replacement.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-replacementSyntheticSecret"}
    with factory.begin() as db:
        result = update_destination(db, store, settings, ident, {"credentials": fresh_client}, 1, None)
        current = db.get(StorageDestination, ident)
        fresh = store.get(db, current.credential_id)
        assert current.credential_id != generation
        assert fresh["grant_id"] != old["grant_id"] and fresh["token"] == {}
        assert fresh["revoked"] and fresh["revoked_at"]
        assert fresh["client_id"] == fresh_client["client_id"]
        assert result["health"] == "reauthorization_required"
        assert result["credential_flags"]["authorized"] is False
        assert not any(value in json.dumps(result) for value in (*CLIENT.values(), *fresh_client.values(), "synthetic-old-refresh"))
    envelope = store.box().encrypt(old, context=credential_context(ident))
    with pytest.raises(VaultRewindError) as failure:
        sql.compare_and_swap(ident, envelope, stale.revision, expected_generation=stale.generation)
    assert failure.value.code == "CREDENTIAL_STALE"
    with factory() as db:
        assert store.get(db, db.get(StorageDestination, ident).credential_id) == fresh
    # Simulate an encrypted refresh journal left by the old process before rotation.
    pending = PendingCredentialUpdates(sql.state_directory, store.box(), ident)
    pending.save({"version": 1, "credential": old, "token": old["token"], "base_token": old["token"],
                  "base_revision": stale.revision, "generation": stale.generation})
    session = drive.DriveCredentialSession(ident, sql, store.box(), folder_id=old["folder_id"],
                                           lock_dir=settings.staging_dir / "locks")
    session.pending = pending
    session._retry_pending()
    assert session.outcome["stale_rejected"] == 1 and not list(pending.load())
    with factory() as db:
        assert store.get(db, db.get(StorageDestination, ident).credential_id) == fresh


def test_detail_does_not_upgrade_legacy_secret_binding(env):
    _, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store)
        secret = db.get(Secret, row.credential_id)
        secret.envelope = store.box().encrypt(KEYS)
        secret.binding = "unverified"
        view = destination_view(db, store, row.id)
        assert view["credentials_configured"] and secret.binding == "unverified" and secret.revision == 1


def test_drive_pair_and_scope_validation(env):
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store, "drive", {"folder_id": "SyntheticFolder0001"}, CLIENT)
        for change in ({"credentials": {"client_id": CLIENT["client_id"]}},
                       {"credentials": {"client_secret": CLIENT["client_secret"]}},
                       {"configuration": {"scope": "drive"}}):
            with pytest.raises(VaultRewindError):
                update_destination(db, store, settings, row.id, change, 1, None)


def test_public_view_hides_unrecognized_private_configuration(env):
    _, _, factory, store, _ = env
    with factory.begin() as db:
        row = destination(db, store, config={**S3, "client_secret": "synthetic-private-config-value"})
        assert "synthetic-private-config-value" not in json.dumps(destination_view(db, store, row.id))


def test_private_ca_is_retained_without_roundtrip_and_can_be_removed(env):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    settings, _, factory, store, _ = env
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic destination CA")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(1).not_valid_before(now() - timedelta(days=1)).not_valid_after(now() + timedelta(days=1))
            .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM).decode()
    with factory.begin() as db:
        row = destination(db, store, config={**S3, "ca_cert_pem": cert})
        view = destination_view(db, store, row.id)
        assert view["configuration"]["custom_ca"] is True and "CERTIFICATE" not in json.dumps(view)
        update_destination(db, store, settings, row.id, {"configuration": {"region": "us-west-2"}}, 1, None)
        assert store.get(db, row.configuration_secret_id)["ca_cert_pem"] == cert
        view = update_destination(db, store, settings, row.id, {"configuration": {"ca_cert_pem": None}}, 2, None)
        assert view["configuration"]["custom_ca"] is False


def test_rotated_drive_client_can_start_new_browser_authorization(env):
    from urllib.parse import parse_qs, urlsplit

    from vaultrewind.server.models import OAuthState, Session
    from vaultrewind.server.oauth import start
    settings, _, factory, store, _ = env
    with factory.begin() as db:
        user, _, _, _, _ = seed(db, store)
        session = Session(id=uid(), user_id=user.id, token_hash="s" * 64, csrf_hash="c" * 64,
                          expires_at=now() + timedelta(hours=1))
        db.add(session)
        db.flush()
        row = destination(db, store, "drive", {"folder_id": "SyntheticFolder0001"}, CLIENT)
        old_authorization = start(db, store, settings, row, session)
        db.flush()
        old_state = db.scalar(select(OAuthState).where(OAuthState.destination_id == row.id))
        client = {"client_id": "987654321012-replacement.apps.googleusercontent.com",
                  "client_secret": "GOCSPX-replacementSyntheticSecret"}
        update_destination(db, store, settings, row.id, {"credentials": client}, 1, user.id)
        assert old_state.consumed_at is not None
        new_authorization = start(db, store, settings, row, session)
        assert parse_qs(urlsplit(new_authorization["authorization_url"]).query)["client_id"] == [client["client_id"]]
        assert old_authorization["authorization_url"] != new_authorization["authorization_url"]

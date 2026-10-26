"""Google Drive provider: deterministic OAuth/token/session tests and real rclone/restic transport tests.

No real Google account is used here (see test_storage_drive_live.py for the opt-in live harness).
All tokens and client secrets below are synthetic.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import typing
import uuid
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from tests.unit.test_storage_support import (
    RCLONE,
    RESTIC,
    FakeRestic,
    make_snapshot_tree,
    respond,
    snapshot_args,
)
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.oauth import InMemoryAuthorizationStateStore, utcnow
from vaultrewind.security.secrets import SecretBox, generate_master_key
from vaultrewind.storage import drive, providers
from vaultrewind.storage.credentials import MemoryCredentialStore, credential_context, has_pending_credentials
from vaultrewind.storage.errors import classify_output
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

CLIENT = drive.GoogleClient("123456789012-synthetic.apps.googleusercontent.com", "GOCSPX-syntheticClientSecret")
ORIGIN = "https://vaultrewind.synthetic.invalid"
FOLDER = "SyntheticFolderId00001"
DEST = str(uuid.uuid4())


class FakeGoogle:
    """Deterministic stand-in for Google's token and Drive v3 endpoints."""

    def __init__(self, *, scope=drive.SCOPE_FILE, refresh_token="1//synthetic-refresh-token-0001", folder=None,
                 token_error=None):
        self.scope, self.refresh_token, self.token_error = scope, refresh_token, token_error
        self.folder = folder or {"id": FOLDER, "name": "VaultRewind synthetic", "mimeType": drive.FOLDER_MIME,
                                 "trashed": False, "capabilities": {"canAddChildren": True}}
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url == drive.TOKEN_URL:
            form = parse_qs(request.content.decode())
            if self.token_error:
                return httpx.Response(400, json={"error": self.token_error})
            body = {"access_token": "ya29.synthetic-access-" + uuid.uuid4().hex, "expires_in": 3599,
                    "token_type": "Bearer", "scope": self.scope}
            if form["grant_type"] == ["authorization_code"] and self.refresh_token:
                body["refresh_token"] = self.refresh_token
            return httpx.Response(200, json=body)
        if url == drive.REVOKE_URL:
            return httpx.Response(200)
        if request.url.path == "/drive/v3/files" and request.method == "POST":
            return httpx.Response(200, json={**self.folder, "name": json.loads(request.content)["name"]})
        if request.url.path.startswith("/drive/v3/files/"):
            if self.folder is None or self.folder.get("missing"):
                return httpx.Response(404, json={"error": {"errors": [{"reason": "notFound"}]}})
            return httpx.Response(200, json=self.folder)
        return httpx.Response(500)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def form(self, index: int) -> dict:
        return parse_qs(self.requests[index].content.decode())


def authorization(google: FakeGoogle):
    box = SecretBox(generate_master_key())
    store = InMemoryAuthorizationStateStore()
    return drive.DriveAuthorization(box, store, ORIGIN, http=google.client()), store


def callback(start: dict, **extra) -> dict:
    query = parse_qs(urlsplit(start["authorization_url"]).query)
    return {"state": query["state"][0], "code": "4/synthetic-authorization-code", **extra}


def test_begin_builds_pkce_url_without_secrets_and_stores_only_hashes():
    google = FakeGoogle()
    auth, store = authorization(google)
    start = auth.begin(DEST, "session-1", CLIENT)
    parts = urlsplit(start["authorization_url"])
    query = parse_qs(parts.query)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == drive.AUTH_URL
    assert query["redirect_uri"] == [ORIGIN + drive.CALLBACK_PATH] and query["scope"] == [drive.SCOPE_FILE]
    assert query["access_type"] == ["offline"] and query["prompt"] == ["consent"]
    assert query["code_challenge_method"] == ["S256"] and query["include_granted_scopes"] == ["false"]
    assert CLIENT.client_secret not in start["authorization_url"]
    record = next(iter(store._records.values()))
    assert query["state"][0] not in json.dumps(record.__dict__, default=str)
    assert CLIENT.client_secret not in record.client_envelope


def test_complete_exchanges_code_with_pkce_and_creates_folder():
    google = FakeGoogle()
    auth, _ = authorization(google)
    start = auth.begin(DEST, "session-1", CLIENT)
    result = auth.complete(request_origin=ORIGIN, params=callback(start), session_id="session-1",
                           folder_name="VaultRewind Synthetic")
    token_form = google.form(0)
    challenge = parse_qs(urlsplit(start["authorization_url"]).query)["code_challenge"][0]
    verifier = token_form["code_verifier"][0]
    assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == challenge
    assert token_form["client_secret"] == [CLIENT.client_secret] and "client_secret" not in str(google.requests[0].url)
    assert token_form["redirect_uri"] == [ORIGIN + drive.CALLBACK_PATH]
    created = json.loads(google.requests[1].content)
    assert created["mimeType"] == drive.FOLDER_MIME and created["appProperties"] == {"vaultrewindDestination": DEST}
    assert google.requests[1].headers["authorization"].startswith("Bearer ya29.")
    credential = result["credential"]
    assert result["configuration"] == {"folder_id": FOLDER, "folder_name": "VaultRewind Synthetic",
                                       "scope": "drive.file"}
    assert credential["token"]["refresh_token"] == google.refresh_token and credential["grant_id"]
    assert drive.token_expiry(credential["token"]) > utcnow() + timedelta(minutes=50)
    with pytest.raises(VaultRewindError) as reused:
        auth.complete(request_origin=ORIGIN, params=callback(start), session_id="session-1")
    assert reused.value.code == "OAUTH_STATE_INVALID"


@pytest.mark.parametrize("kwargs, code", [
    ({"request_origin": "https://evil.synthetic.invalid"}, "OAUTH_ORIGIN_MISMATCH"),
    ({"session_id": "other-session"}, "OAUTH_SESSION_MISMATCH"),
    ({"params_extra": {"error": "access_denied"}}, "OAUTH_DENIED"),
    ({"params_override": {"state": "forged-state-value-000000000000"}}, "OAUTH_STATE_INVALID"),
])
def test_complete_rejects_bad_callbacks(kwargs, code):
    google = FakeGoogle()
    auth, _ = authorization(google)
    start = auth.begin(DEST, "session-1", CLIENT)
    params = {**callback(start, **kwargs.get("params_extra", {})), **kwargs.get("params_override", {})}
    with pytest.raises(VaultRewindError) as error:
        auth.complete(request_origin=kwargs.get("request_origin", ORIGIN), params=params,
                      session_id=kwargs.get("session_id", "session-1"))
    assert error.value.code == code
    assert not [r for r in google.requests if str(r.url) == drive.TOKEN_URL], "no code exchange on rejection"


@pytest.mark.parametrize("google, code", [
    (FakeGoogle(scope="https://www.googleapis.com/auth/drive.readonly"), "OAUTH_SCOPE_INSUFFICIENT"),
    (FakeGoogle(refresh_token=None), "OAUTH_NO_REFRESH_TOKEN"),
    (FakeGoogle(token_error="invalid_grant"), "STORAGE_AUTH_EXPIRED"),
    (FakeGoogle(token_error="invalid_client"), "STORAGE_CLIENT_INVALID"),
    (FakeGoogle(token_error="redirect_uri_mismatch"), "OAUTH_REDIRECT_MISMATCH"),
])
def test_complete_rejects_unusable_grants(google, code):
    auth, _ = authorization(google)
    start = auth.begin(DEST, "session-1", CLIENT)
    with pytest.raises(VaultRewindError) as error:
        auth.complete(request_origin=ORIGIN, params=callback(start), session_id="session-1")
    assert error.value.code == code


@pytest.mark.parametrize("folder, code", [
    ({"id": FOLDER, "mimeType": drive.FOLDER_MIME, "trashed": True}, "DRIVE_FOLDER_UNAVAILABLE"),
    ({"id": FOLDER, "mimeType": drive.FOLDER_MIME, "trashed": False, "driveId": "0AsharedDrive"},
     "DRIVE_SHARED_DRIVE_UNSUPPORTED"),
    ({"id": FOLDER, "mimeType": drive.FOLDER_MIME, "missing": True}, "DRIVE_FOLDER_UNAVAILABLE"),
    ({"id": FOLDER, "mimeType": drive.FOLDER_MIME, "trashed": False, "capabilities": {"canAddChildren": False}},
     "DRIVE_FOLDER_UNAVAILABLE"),
])
def test_reconnect_verifies_the_existing_folder(folder, code):
    google = FakeGoogle(folder=folder)
    auth, _ = authorization(google)
    start = auth.begin(DEST, "session-1", CLIENT, purpose="reconnect")
    with pytest.raises(VaultRewindError) as error:
        auth.complete(request_origin=ORIGIN, params=callback(start), session_id="session-1",
                      existing_folder_id=FOLDER)
    assert error.value.code == code


def test_headless_import_validates_by_refreshing():
    google = FakeGoogle()
    pasted = ("Paste the following into your remote machine --->\n" + json.dumps({
        "access_token": "ya29.synthetic-old-access", "token_type": "Bearer",
        "refresh_token": "1//synthetic-headless-refresh", "expiry": "2026-01-01T00:00:00.123456789Z"}) +
        "\n<---End paste")
    result = drive.import_headless_token(CLIENT, pasted, destination_id=DEST, existing_folder_id=FOLDER,
                                         http=google.client())
    form = google.form(0)
    assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == ["1//synthetic-headless-refresh"]
    assert result["credential"]["token"]["refresh_token"] == "1//synthetic-headless-refresh"
    for bad in ("not json", json.dumps({"access_token": "ya29.x"}), "x" * 20000):
        with pytest.raises(VaultRewindError):
            drive.import_headless_token(CLIENT, bad, destination_id=DEST, http=google.client())


def test_revoke_sends_token_in_body_and_instructions_have_no_secrets():
    google = FakeGoogle()
    credential = {"token": {"access_token": "ya29.synthetic", "refresh_token": "1//synthetic-revoke-token",
                            "expiry": "2026-01-01T00:00:00Z"}}
    assert drive.revoke(credential, http=google.client())
    assert str(google.requests[0].url) == drive.REVOKE_URL
    assert parse_qs(google.requests[0].content.decode())["token"] == ["1//synthetic-revoke-token"]
    text = drive.headless_instructions(CLIENT.client_id)
    assert CLIENT.client_secret not in text and "read -rs RCLONE_DRIVE_CLIENT_SECRET" in text
    assert "RCLONE_DRIVE_SCOPE=drive.file" in text and "rclone authorize drive" in text


def test_client_and_config_injection_are_rejected():
    with pytest.raises(VaultRewindError):
        drive.GoogleClient("not-a-client-id", "secret-value-123")
    with pytest.raises(VaultRewindError):
        drive.GoogleClient(CLIENT.client_id, "secret\n[evil]\ntype = local")
    credential = {**CLIENT.as_dict(), "token": {"access_token": "ya29.synthetic", "refresh_token": "1//synthetic-ok",
                                                "expiry": "2026-01-01T00:00:00Z"}}
    with pytest.raises(VaultRewindError):
        drive.rclone_config_text(credential, "folder\ntype = local")
    with pytest.raises(VaultRewindError):
        drive.rclone_config_text(credential, FOLDER, overrides={"type": "local"})
    text = drive.rclone_config_text(credential, FOLDER)
    assert "use_trash = false" in text and "scope = drive.file" in text and f"root_folder_id = {FOLDER}" in text


def test_classification_of_provider_failures():
    assert classify_output("oauth2: \"invalid_grant\" \"Token has been expired or revoked.\"", "X", "x").code == \
        "STORAGE_AUTH_EXPIRED"
    assert classify_output("googleapi: Error 403: storageQuotaExceeded", "X", "x").details["credential_state"] == \
        "quota_exceeded"
    assert classify_output("Error 403: User Rate Limit Exceeded, userRateLimitExceeded", "X", "x").retryable
    assert drive.classify_credential_state("STORAGE_AUTH_EXPIRED") == "reconnect_required"
    assert drive.classify_credential_state(None) == "connected"


# ---------------------------------------------------------------- credential sessions
def seeded_store(box: SecretBox, *, expiry_offset=timedelta(hours=-1), grant="grant-1"):
    store = MemoryCredentialStore()
    credential = {"type": "google_drive_oauth", "version": 1, **CLIENT.as_dict(), "scope": "drive.file",
                  "folder_id": FOLDER, "grant_id": grant,
                  "token": {"access_token": "ya29.synthetic-initial-access", "token_type": "Bearer",
                            "refresh_token": "1//synthetic-session-refresh",
                            "expiry": drive._rfc3339(utcnow() + expiry_offset)}}
    store.compare_and_swap(DEST, box.encrypt(credential, context=credential_context(DEST)), None)
    return store


def rotate_config(session: drive.DriveCredentialSession, access: str, expiry_offset: timedelta) -> None:
    """Simulate rclone rewriting its config after a refresh (the real binary is exercised below)."""
    text = session.config_path.read_text().splitlines()
    token = {"access_token": access, "token_type": "Bearer", "refresh_token": "1//synthetic-session-refresh",
             "expiry": drive._rfc3339(utcnow() + expiry_offset), "expires_in": 3599}
    session.config_path.write_text("\n".join(
        "token = " + json.dumps(token) if line.startswith("token = ") else line for line in text) + "\n")


def stored(store, box) -> dict:
    return box.decrypt(store.load(DEST).envelope, context=credential_context(DEST))


def test_session_persists_newer_token_and_scrubs_config(tmp_path):
    box = SecretBox(generate_master_key())
    store = seeded_store(box)
    with drive.DriveCredentialSession(DEST, store, box, folder_id=FOLDER, lock_dir=tmp_path / "locks",
                                      runtime_dir=tmp_path / "rt") as session:
        config = session.config_path
        assert oct(config.stat().st_mode & 0o777) == "0o600"
        assert oct(config.parent.stat().st_mode & 0o777) == "0o700"
        rotate_config(session, "ya29.synthetic-rotated-access", timedelta(hours=1))
    assert not config.exists() and not config.parent.exists()
    assert stored(store, box)["token"]["access_token"] == "ya29.synthetic-rotated-access"
    assert store.load(DEST).revision == 2 and session.outcome["persisted"] == 1


def test_concurrent_sessions_never_overwrite_newer_tokens(tmp_path):
    box = SecretBox(generate_master_key())
    store = seeded_store(box)
    kwargs = {"folder_id": FOLDER, "lock_dir": tmp_path / "locks", "runtime_dir": tmp_path / "rt"}
    first = drive.DriveCredentialSession(DEST, store, box, **kwargs).__enter__()
    second = drive.DriveCredentialSession(DEST, store, box, **kwargs).__enter__()
    rotate_config(first, "ya29.synthetic-newest", timedelta(hours=2))
    rotate_config(second, "ya29.synthetic-older", timedelta(hours=1))
    first.__exit__(None, None, None)
    second.__exit__(None, None, None)
    assert stored(store, box)["token"]["access_token"] == "ya29.synthetic-newest"
    assert second.outcome["stale_rejected"] == 1 and store.load(DEST).revision == 2


def test_reconnect_during_a_job_wins_over_the_jobs_refresh(tmp_path):
    box = SecretBox(generate_master_key())
    store = seeded_store(box)
    session = drive.DriveCredentialSession(DEST, store, box, folder_id=FOLDER, lock_dir=tmp_path / "locks",
                                           runtime_dir=tmp_path / "rt").__enter__()
    reconnected = {**stored(store, box), "grant_id": "grant-2",
                   "token": {"access_token": "ya29.synthetic-reconnected", "token_type": "Bearer",
                             "refresh_token": "1//synthetic-new-grant", "expiry": drive._rfc3339(utcnow())}}
    store.compare_and_swap(DEST, box.encrypt(reconnected, context=credential_context(DEST)), 1)
    rotate_config(session, "ya29.synthetic-from-old-grant", timedelta(hours=3))
    session.__exit__(None, None, None)
    assert stored(store, box)["grant_id"] == "grant-2" and session.outcome["stale_rejected"] == 1


def test_persist_failure_is_reported_after_encrypted_preservation_and_scratch_cleanup(tmp_path):
    box = SecretBox(generate_master_key())
    store = seeded_store(box)

    def broken(*args, **kwargs):
        raise VaultRewindError("DB_DOWN", "synthetic outage")

    session = drive.DriveCredentialSession(DEST, store, box, folder_id=FOLDER, lock_dir=tmp_path / "locks",
                                           runtime_dir=tmp_path / "rt")
    with pytest.raises(VaultRewindError) as error, session:
        rotate_config(session, "ya29.synthetic-unsaved", timedelta(hours=1))
        store.compare_and_swap = broken
    assert error.value.code == "CREDENTIAL_PERSIST_FAILED"
    assert error.value.details["pending_recovery_required"] and error.value.details["pending_encrypted"]
    assert has_pending_credentials(tmp_path / "locks")
    assert store.load(DEST).revision == 1
    pending = next((tmp_path / "locks").rglob("*.pending-credential"))
    assert b"ya29.synthetic-unsaved" not in pending.read_bytes()
    assert not any((tmp_path / "rt").iterdir())


def test_session_rejects_folder_mismatch_and_missing_credential(tmp_path):
    box = SecretBox(generate_master_key())
    with pytest.raises(VaultRewindError) as missing:
        drive.DriveCredentialSession(DEST, MemoryCredentialStore(), box, folder_id=FOLDER,
                                     lock_dir=tmp_path / "l").__enter__()
    assert missing.value.code == "STORAGE_CREDENTIALS_MISSING"
    with pytest.raises(VaultRewindError) as mismatch:
        drive.DriveCredentialSession(DEST, seeded_store(box), box, folder_id="AnotherFolder000001",
                                     lock_dir=tmp_path / "l").__enter__()
    assert mismatch.value.code == "DRIVE_FOLDER_UNAVAILABLE"


def test_drive_repository_passes_config_by_file_and_never_tokens_in_arguments(tmp_path):
    box = SecretBox(generate_master_key())
    store = seeded_store(box, expiry_offset=timedelta(hours=1))
    fake = FakeRestic(tmp_path / "fake", {"snapshots": [respond("[]")]})
    instance = str(uuid.uuid4())
    with drive.drive_repository(DEST, {"folder_id": FOLDER}, instance_id=instance,
                                password="synthetic-drive-repo-password-1", store=store, box=box,
                                work_dir=tmp_path / "state", restic_binary=str(fake.binary),
                                rclone_binary=RCLONE or "/bin/true") as repo:
        assert repo.list_snapshots() == []
    call = fake.calls()[-1]
    joined = " ".join(call["argv"])
    assert call["env"]["RESTIC_REPOSITORY"] == f"rclone:vrdrive:vaultrewind/{instance}/{DEST}"
    assert call["env"]["RCLONE_CONFIG"].endswith("rclone.conf") and "rclone.program=" in joined
    for secret in ("ya29.", "1//", CLIENT.client_secret, "synthetic-drive-repo-password-1"):
        assert secret not in joined
    assert not Path(call["env"]["RCLONE_CONFIG"]).exists(), "session config must be scrubbed after use"


# ---------------------------------------------------------------- real rclone / restic
class _TokenEndpoint(BaseHTTPRequestHandler):
    bodies: typing.ClassVar[list[str]] = []

    def do_POST(self):
        self.bodies.append(self.rfile.read(int(self.headers["Content-Length"])).decode())
        payload = json.dumps({"access_token": "ya29.synthetic-refreshed-by-rclone", "expires_in": 3600,
                              "refresh_token": "1//synthetic-rotated-by-real-rclone",
                              "token_type": "Bearer"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _RejectExternalProxy(BaseHTTPRequestHandler):
    """Never forwards a connection: the rclone test cannot contact live Drive."""

    def do_CONNECT(self):
        self.send_error(502, "Synthetic test forbids external connections")

    def log_message(self, *args):
        pass


@pytest.mark.skipif(RCLONE is None, reason="pinned rclone binary not installed")
def test_real_rclone_writes_refreshed_token_and_session_persists_it(tmp_path, monkeypatch):
    """Real rclone 1.75.2 refreshes an expired token (local fake endpoint) and rewrites its private config."""
    server = HTTPServer(("127.0.0.1", 0), _TokenEndpoint)
    proxy = HTTPServer(("127.0.0.1", 0), _RejectExternalProxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    _TokenEndpoint.bodies = []
    real_run = drive.subprocess.run

    def local_only(*args, **kwargs):
        kwargs["env"] = {**kwargs["env"], "HTTPS_PROXY": f"http://127.0.0.1:{proxy.server_port}",
                         "HTTP_PROXY": f"http://127.0.0.1:{proxy.server_port}", "NO_PROXY": "127.0.0.1,localhost"}
        return real_run(*args, **kwargs)

    monkeypatch.setattr(drive.subprocess, "run", local_only)
    try:
        box = SecretBox(generate_master_key())
        store = seeded_store(box, expiry_offset=timedelta(hours=-1))
        with drive.DriveCredentialSession(
                DEST, store, box, folder_id=FOLDER, lock_dir=tmp_path / "locks", runtime_dir=tmp_path / "rt",
                rclone_overrides={"token_url": f"http://127.0.0.1:{server.server_port}/token"}) as session:
            drive._rclone(session, ["lsjson", f"{drive.REMOTE}:"], timeout=90)  # Drive API call itself fails
            assert "synthetic-refreshed-by-rclone" in session.config_path.read_text()
    finally:
        server.shutdown()
        proxy.shutdown()
    form = parse_qs(_TokenEndpoint.bodies[0])
    assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == ["1//synthetic-session-refresh"]
    credential = stored(store, box)
    assert credential["token"]["access_token"] == "ya29.synthetic-refreshed-by-rclone"
    assert credential["token"]["refresh_token"] == "1//synthetic-rotated-by-real-rclone"
    assert drive.token_expiry(credential["token"]) > utcnow() + timedelta(minutes=50)
    assert session.outcome == {"refreshed": True, "persisted": 1, "stale_rejected": 0}


@pytest.mark.skipif(RCLONE is None or RESTIC is None, reason="pinned restic/rclone binaries not installed")
def test_real_restic_rclone_backend_round_trip_over_local_remote(tmp_path):
    """Exercises restic's rclone backend, RCLONE_CONFIG and rclone.program exactly as Drive uses them."""
    config_dir = tmp_path / "rclone"
    config_dir.mkdir(mode=0o700)
    config = config_dir / "rclone.conf"
    config.write_text("[vrdrive]\ntype = local\n")
    config.chmod(0o600)
    remote_root = tmp_path / "remote"
    instance = str(uuid.uuid4())
    repo = ResticRepository(RepositoryConfig(location=f"rclone:vrdrive:{remote_root}/vaultrewind/{instance}/{DEST}",
                                             password="synthetic-rclone-password-0123",
                                             rclone_config=config, cache_dir=tmp_path / "cache",
                                             runtime_dir=tmp_path / "rt", instance_uuid=instance))
    repo.initialize()
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    committed = repo.commit(*snapshot_args(stage, manifest))
    assert committed["stored_copy_verified"]
    assert (remote_root / "vaultrewind" / instance / DEST / "config").is_file()
    restored = repo.restore(committed["restic_snapshot_id"], tmp_path / "restored")
    assert restored["restored_bytes_verified"]
    assert repo.forget([committed["restic_snapshot_id"]])["complete"]


def test_provider_validation_for_drive():
    assert providers.validate_destination("drive", {"folder_id": FOLDER, "folder_name": "x"})["scope"] == "drive.file"
    for bad in ({"folder_id": "bad id"}, {"folder_id": FOLDER, "scope": "drive"}, {"folder_id": FOLDER, "team_drive": "x"}):
        with pytest.raises(VaultRewindError):
            providers.validate_destination("drive", bad)


def test_worker_side_exchange_matches_complete():
    google = FakeGoogle()
    result = drive.exchange_authorization_code(CLIENT, "4/synthetic-worker-code", "v" * 64,
                                               ORIGIN + drive.CALLBACK_PATH, destination_id=DEST,
                                               http=google.client())
    form = google.form(0)
    assert form["code"] == ["4/synthetic-worker-code"] and form["code_verifier"] == ["v" * 64]
    assert result["configuration"]["folder_id"] == FOLDER and result["credential"]["type"] == "google_drive_oauth"
    for bad_redirect in ("http://evil.example.org/cb", ORIGIN + "/cb?x=1", "not a url"):
        with pytest.raises(VaultRewindError):
            drive.exchange_authorization_code(CLIENT, "4/synthetic-worker-code", "v" * 64, bad_redirect,
                                              destination_id=DEST, http=google.client())


def test_ui_input_normalization_and_pending_authorization(tmp_path):
    configuration, credential = providers.normalize_destination_input(
        "s3", {"endpoint": "https://s3.example.org", "bucket": "vaultrewind-synthetic", "prefix": "",
               "addressing_mode": "virtual", "allow_insecure_local": False},
        {"access_key_id": "AKIASYNTHETIC0000000", "secret_access_key": "synthetic-secret"})
    assert configuration == {"endpoint": "https://s3.example.org", "bucket": "vaultrewind-synthetic",
                             "bucket_lookup": "virtual", "development_http": False}
    assert providers.validate_destination("s3", configuration, credential)["bucket_lookup"] == "dns"
    local_config, local_credential = providers.normalize_destination_input(
        "local", {"root": "/var/lib/vaultrewind/backups", "path": "/var/lib/vaultrewind/backups"}, None)
    assert local_config == {"path": "/var/lib/vaultrewind/backups"} and local_credential is None
    drive_config, drive_credential = providers.normalize_destination_input(
        "drive", {"client_id": CLIENT.client_id, "root_folder_id": "", "scope": "drive.file"},
        {"client_secret": CLIENT.client_secret})
    assert drive_config == {"scope": "drive.file"}
    assert drive_credential == {"type": "google_drive_client", **CLIENT.as_dict()}
    assert providers.validate_destination("drive", drive_config, drive_credential)["authorization_required"]
    box = SecretBox(generate_master_key())
    store = MemoryCredentialStore()
    store.compare_and_swap(DEST, box.encrypt(drive_credential, context=credential_context(DEST)), None)
    with pytest.raises(VaultRewindError) as no_folder:
        providers.test_destination("drive", drive_config, None, destination_id=DEST, work_dir=tmp_path / "w",
                                   credential_store=store, box=box)
    assert no_folder.value.code == "STORAGE_AUTHORIZATION_REQUIRED"
    with pytest.raises(VaultRewindError) as no_token:
        drive.DriveCredentialSession(DEST, store, box, folder_id=FOLDER, lock_dir=tmp_path / "l").__enter__()
    assert no_token.value.code == "STORAGE_AUTHORIZATION_REQUIRED"

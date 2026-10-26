"""SecretBox envelopes, master-key files, nested redaction and OAuth callback hygiene."""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import socket
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security import oauth
from vaultrewind.security.redaction import (
    CALLBACK_RESPONSE_HEADERS,
    REDACTED,
    OAuthCallbackScrubber,
    RedactingFilter,
    callback_params,
    redact,
    register_secret,
)
from vaultrewind.security.secrets import (
    SecretBox,
    decode_master_key,
    generate_master_key,
    load_master_key_file,
    write_master_key_file,
)

json_values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=40),
                           lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10),
                                                                                            children, max_size=4),
                           max_leaves=12)


@given(st.dictionaries(st.text(max_size=12), json_values, max_size=6) | st.text(max_size=200))
@settings(max_examples=60, deadline=None)
def test_round_trip_preserves_type_and_value(value):
    box = SecretBox(generate_master_key())
    envelope = box.encrypt(value, context="secret:row-1")
    assert box.decrypt(envelope, context="secret:row-1") == value
    assert envelope.startswith("vr1." + box.key_id + ".")
    if isinstance(value, str) and len(value) >= 4:
        assert value not in envelope


def test_nonce_is_random_and_ciphertext_differs():
    box = SecretBox(generate_master_key())
    assert box.encrypt("same") != box.encrypt("same")


def test_context_binding_and_tamper_detection():
    box = SecretBox(generate_master_key())
    envelope = box.encrypt({"password": "synthetic"}, context="secret:a")
    with pytest.raises(VaultRewindError) as moved:
        box.decrypt(envelope, context="secret:b")
    assert moved.value.code == "SECRET_DECRYPT_FAILED"
    head, kid, nonce, body = envelope.split(".")
    flipped = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1]
    with pytest.raises(VaultRewindError):
        box.decrypt(f"{head}.{kid}.{nonce}.{flipped}", context="secret:a")
    with pytest.raises(VaultRewindError) as malformed:
        box.decrypt("plaintext-not-an-envelope")
    assert malformed.value.code == "SECRET_ENVELOPE_INVALID"


def test_other_master_key_cannot_decrypt_and_no_global_key():
    first, second = SecretBox(generate_master_key()), SecretBox(generate_master_key())
    with pytest.raises(VaultRewindError) as error:
        second.decrypt(first.encrypt("value"))
    assert error.value.code == "SECRET_KEY_UNAVAILABLE"
    with pytest.raises(VaultRewindError):
        SecretBox(b"\x00" * 32)  # not random key material
    with pytest.raises(VaultRewindError):
        SecretBox(b"short")
    assert "key" not in repr(first).lower().replace("key_id", "").replace("keys", "")


def test_master_key_rotation_keeps_old_envelopes_readable():
    old_key, new_key = generate_master_key(), generate_master_key()
    old_box = SecretBox(old_key)
    envelope = old_box.encrypt({"repository_password": "synthetic-repo-secret"}, context="repo:1")
    rotating = SecretBox(new_key, previous_keys=[old_key])
    assert rotating.needs_rotation(envelope)
    rotated = rotating.rotate(envelope, context="repo:1")
    assert not rotating.needs_rotation(rotated)
    assert SecretBox(new_key).decrypt(rotated, context="repo:1") == {"repository_password": "synthetic-repo-secret"}
    with pytest.raises(VaultRewindError):
        SecretBox(new_key).decrypt(envelope, context="repo:1")


def test_master_key_files(tmp_path):
    path = tmp_path / "master.key"
    write_master_key_file(path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    key = load_master_key_file(path)
    assert len(key) == 32
    with pytest.raises(VaultRewindError) as exists:
        write_master_key_file(path)
    assert exists.value.code == "MASTER_KEY_EXISTS"
    path.chmod(0o644)
    with pytest.raises(VaultRewindError) as loose:
        load_master_key_file(path)
    assert loose.value.code == "MASTER_KEY_PERMISSIONS"
    raw = generate_master_key()
    assert decode_master_key(raw) == raw
    assert decode_master_key(raw.hex().encode() + b"\n") == raw
    with pytest.raises(VaultRewindError):
        decode_master_key(b"not a key")


def test_nested_redaction_of_keys_and_free_text():
    register_secret("registered-synthetic-secret-value")
    event = {
        "job": {"state": "running", "phase": "committing_copies", "credential_id": "abc"},
        "client_secret": "GOCSPX-syntheticSecretValue123", "nested": [{"refresh_token": "1//synthetic-refresh-value"}],
        "message": ("Bearer ya29.syntheticAccessToken12345 failed for https://user:pw@example.invalid/x?code=4/abc&"
                    "state=xyz and AKIAABCDEFGHIJKLMNOP; registered-synthetic-secret-value; "
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"),
        "count": 3, "ok": True}
    result = redact(event)
    text = json.dumps(result)
    for secret in ("GOCSPX-syntheticSecretValue123", "1//synthetic-refresh-value", "ya29.syntheticAccessToken12345",
                   "user:pw", "4/abc", "AKIAABCDEFGHIJKLMNOP", "registered-synthetic-secret-value", "AAAA"):
        assert secret not in text
    assert result["job"]["state"] == "running" and result["job"]["credential_id"] == "abc"
    assert result["count"] == 3 and result["ok"] is True and result["client_secret"] == REDACTED


def test_log_filter_redacts_messages_args_and_exceptions():
    stream = io.StringIO()
    logger = logging.getLogger("vaultrewind.test.redaction")
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.warning("token=%s for %s", "ya29.syntheticLoggedToken99", {"password": "synthetic-pw"})
        try:
            raise RuntimeError("refresh_token=1//syntheticExceptionToken000")
        except RuntimeError:
            logger.exception("failure")
    finally:
        logger.removeHandler(handler)
    output = stream.getvalue()
    assert "ya29.syntheticLoggedToken99" not in output and "synthetic-pw" not in output
    assert "1//syntheticExceptionToken000" not in output and "RuntimeError" in output


def test_callback_scrubber_moves_query_before_the_app():
    seen = {}

    async def app(scope, receive, send):
        seen["query"] = scope["query_string"]
        seen["raw_path"] = scope["raw_path"]
        seen["params"] = callback_params(scope)

    scope = {"type": "http", "path": "/cb", "raw_path": b"/cb?code=SYNTHETIC-CODE&state=S1",
             "query_string": b"code=SYNTHETIC-CODE&state=S1&evil=1"}
    asyncio.run(OAuthCallbackScrubber(app, {"/cb"})(scope, None, None))
    assert seen == {"query": b"", "raw_path": b"/cb", "params": {"code": "SYNTHETIC-CODE", "state": "S1"}}
    assert CALLBACK_RESPONSE_HEADERS["Cache-Control"].startswith("no-store")


def test_uvicorn_access_log_never_contains_the_authorization_code():
    uvicorn = pytest.importorskip("uvicorn")
    import httpx

    captured = io.StringIO()

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            await receive()
            await send({"type": "lifespan.shutdown.complete"})
            return
        assert callback_params(scope)["code"] == "SYNTHETIC-AUTH-CODE-123"
        headers = [(k.lower().encode(), v.encode()) for k, v in CALLBACK_RESPONSE_HEADERS.items()]
        await send({"type": "http.response.start", "status": 303,
                    "headers": headers + [(b"location", b"/storage?authorized=1")]})
        await send({"type": "http.response.body", "body": b""})

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = uvicorn.Config(OAuthCallbackScrubber(app, {"/api/v1/storage-destinations/oauth/callback"}),
                            host="127.0.0.1", port=port, access_log=True, log_config=None, lifespan="on")
    server = uvicorn.Server(config)
    handler = logging.StreamHandler(captured)
    access = logging.getLogger("uvicorn.access")
    previous_disabled, previous_level = access.disabled, access.level
    # Alembic's logging configuration can disable existing loggers in this test process.
    # This probe deliberately enables real access logging and requires a nonempty record.
    access.disabled = False
    access.addHandler(handler)
    access.setLevel(logging.INFO)

    async def scenario():
        task = asyncio.create_task(server.serve())
        while not server.started:
            await asyncio.sleep(0.05)
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{port}/api/v1/storage-destinations/oauth/callback"
                                        "?code=SYNTHETIC-AUTH-CODE-123&state=SYNTHETIC-STATE-456")
        server.should_exit = True
        await task
        return response

    try:
        response = asyncio.run(scenario())
    finally:
        access.removeHandler(handler)
        access.disabled, access.level = previous_disabled, previous_level
    assert response.status_code == 303 and response.headers["referrer-policy"] == "no-referrer"
    assert "/api/v1/storage-destinations/oauth/callback" in captured.getvalue()
    assert "SYNTHETIC-AUTH-CODE-123" not in captured.getvalue()
    assert "SYNTHETIC-STATE-456" not in captured.getvalue()


def test_oauth_state_single_use_session_binding_and_expiry():
    store = oauth.InMemoryAuthorizationStateStore()
    now = oauth.utcnow()
    state = oauth.new_state()

    def record(state_value, expires):
        return oauth.PendingAuthorization(state_hash=oauth.sha256_hex(state_value), destination_id="d",
                                          session_binding=oauth.sha256_hex("session-1"), redirect_uri="https://x/cb",
                                          verifier_envelope="v", client_envelope="c", created_at=now,
                                          expires_at=expires)

    store.put(record(state, now + timedelta(minutes=10)))
    with pytest.raises(VaultRewindError) as wrong_session:
        oauth.consume_state(store, state, "session-2", now)
    assert wrong_session.value.code == "OAUTH_SESSION_MISMATCH"
    with pytest.raises(VaultRewindError) as reused:  # consumed by the failed attempt: single use
        oauth.consume_state(store, state, "session-1", now)
    assert reused.value.code == "OAUTH_STATE_INVALID"
    expired = oauth.new_state()
    store.put(record(expired, now - timedelta(seconds=1)))
    with pytest.raises(VaultRewindError):
        oauth.consume_state(store, expired, "session-1", now)
    fresh = oauth.new_state()
    store.put(record(fresh, now + timedelta(minutes=10)))
    assert oauth.consume_state(store, fresh, "session-1", now).destination_id == "d"


def test_public_origin_rules():
    assert oauth.normalize_origin("https://Vault.Example.org:443/") == "https://vault.example.org"
    assert oauth.normalize_origin("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    for bad in ("http://vault.example.org", "https://user:pw@vault.example.org", "https://x.org/path",
                "https://x.org/?q=1", "ftp://x.org"):
        with pytest.raises(VaultRewindError):
            oauth.normalize_origin(bad)
    with pytest.raises(VaultRewindError) as mismatch:
        oauth.require_same_origin("https://evil.example.org", "https://vault.example.org")
    assert mismatch.value.code == "OAUTH_ORIGIN_MISMATCH"
    verifier, challenge = oauth.pkce_pair()
    assert 43 <= len(verifier) <= 128 and "=" not in challenge


def test_private_files_are_owner_only(tmp_path):
    from vaultrewind.security.privatefiles import private_workspace, write_private_file
    with private_workspace(tmp_path) as workspace:
        assert oct(workspace.stat().st_mode & 0o777) == "0o700"
        secret = write_private_file(workspace / "pw", "synthetic")
        assert oct(secret.stat().st_mode & 0o777) == "0o600"
        link = workspace / "link"
        link.symlink_to(tmp_path / "elsewhere")
        with pytest.raises(OSError):
            write_private_file(link, "x")
    assert not workspace.exists()
    assert not (tmp_path / "elsewhere").exists()
    assert os.listdir(tmp_path) == []


def test_secret_registry_is_bounded():
    from vaultrewind.security import redaction
    first = "first-bounded-secret-" + "0" * 8
    register_secret(first)
    for index in range(redaction.REGISTRY_LIMIT + 10):
        register_secret(f"bounded-synthetic-secret-{index:06d}")
    assert len(redaction._registered) <= redaction.REGISTRY_LIMIT
    assert first not in redaction._registered
    assert redaction.redact_text("x bounded-synthetic-secret-004100 y") == "x [REDACTED] y"

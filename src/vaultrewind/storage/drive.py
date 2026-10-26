"""Google Drive destinations through restic's rclone backend (rclone 1.75.2).

Least privilege: the ``drive.file`` scope (only files and folders this OAuth client
created).  Recovery therefore needs an OAuth client from the same Google Cloud
project; the recovery kit carries the client ID/secret for that reason.
Personal My Drive is supported; shared drives are rejected as untested.

Tokens are never placed in URLs, browser storage, logs or process arguments.
Each job gets a private writable rclone config (0600 in a 0700 directory) so
rclone can persist refreshed tokens; afterwards the newest token is merged back
into encrypted controller storage under a per-destination credential lock,
using a grant identifier, the token expiry and a revision compare-and-swap so a
concurrent job can never overwrite a newer credential with an older one.
"""
from __future__ import annotations

import configparser
import contextlib
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self
from urllib.parse import urlencode, urlsplit

import httpx

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.oauth import (
    STATE_TTL,
    AuthorizationStateStore,
    PendingAuthorization,
    consume_state,
    new_state,
    normalize_origin,
    pkce_pair,
    require_same_origin,
    sha256_hex,
    utcnow,
)
from vaultrewind.security.privatefiles import (
    ensure_private_directory,
    private_workspace,
    scrub_tree,
    write_private_file,
)
from vaultrewind.security.redaction import register_secret
from vaultrewind.security.secrets import SecretBox

from . import layout
from .credentials import (
    CredentialStore,
    DriveSessionJournal,
    PendingCredentialUpdates,
    credential_context,
    credential_lock,
    read_registered_config,
    registered_config_in_use,
    registered_workspace,
    scrub_registered_workspace,
)
from .errors import classify_output
from .restic import SAFE_PATH, RepositoryConfig, ResticRepository, parse_utc, resolve_binary, utc_iso

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
DRIVE_API = "https://www.googleapis.com/drive/v3"
SCOPE_FILE = "https://www.googleapis.com/auth/drive.file"
SCOPE_NAME = "drive.file"
CALLBACK_PATH = "/api/v1/storage-destinations/oauth/callback"
REMOTE = "vrdrive"
FOLDER_MIME = "application/vnd.google-apps.folder"

_CLIENT_ID = re.compile(r"^[A-Za-z0-9._-]{8,200}\.apps\.googleusercontent\.com$")
_CLIENT_SECRET = re.compile(r"^[A-Za-z0-9._~-]{8,200}$")
_FOLDER_ID = re.compile(r"^[A-Za-z0-9_-]{10,200}$")
_TOKEN_TEXT = re.compile(r"^[A-Za-z0-9._~+/=-]{8,4096}$")
_RCLONE_OVERRIDE_KEYS = frozenset({"token_url"})  # test seam only; never reachable from destination settings


@dataclass
class GoogleClient:
    client_id: str
    client_secret: str = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.client_id, str) or not _CLIENT_ID.fullmatch(self.client_id):
            raise VaultRewindError("OAUTH_CLIENT_INVALID", "Enter the OAuth client ID from your Google Cloud project.")
        if not isinstance(self.client_secret, str) or not _CLIENT_SECRET.fullmatch(self.client_secret):
            raise VaultRewindError("OAUTH_CLIENT_INVALID", "Enter the OAuth client secret from your Google Cloud project.")
        register_secret(self.client_secret)

    def as_dict(self) -> dict:
        return {"client_id": self.client_id, "client_secret": self.client_secret}


def classify_credential_state(error_code: str | None) -> str:
    from .errors import CREDENTIAL_STATE_BY_CODE
    return CREDENTIAL_STATE_BY_CODE.get(error_code or "", "connected" if not error_code else "error")


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def token_expiry(token: dict) -> datetime:
    try:
        return parse_utc(str(token.get("expiry", "")))
    except VaultRewindError:
        return datetime.min.replace(tzinfo=UTC)


def validate_token(token: object) -> dict:
    if not isinstance(token, dict):
        raise VaultRewindError("OAUTH_TOKEN_INVALID", "The OAuth token is malformed.")
    access, refresh = token.get("access_token"), token.get("refresh_token")
    if not isinstance(refresh, str) or not _TOKEN_TEXT.fullmatch(refresh):
        raise VaultRewindError("OAUTH_NO_REFRESH_TOKEN",
                               "The authorization did not include a refresh token; revoke access and reconnect.")
    if access not in (None, "") and (not isinstance(access, str) or not _TOKEN_TEXT.fullmatch(access)):
        raise VaultRewindError("OAUTH_TOKEN_INVALID", "The OAuth access token is malformed.")
    clean = {"access_token": access or "", "token_type": "Bearer", "refresh_token": refresh,
             "expiry": _rfc3339(token_expiry(token)) if token.get("expiry") else _rfc3339(utcnow() - timedelta(minutes=1))}
    register_secret(refresh)
    register_secret(access)
    return clean


def _token_from_response(response: dict, previous_refresh: str | None, now: datetime) -> dict:
    expires_in = response.get("expires_in")
    if not isinstance(expires_in, int) or not 0 < expires_in <= 86400 * 7:
        raise VaultRewindError("OAUTH_TOKEN_INVALID", "The provider returned an unusable token lifetime.")
    if str(response.get("token_type", "")).lower() != "bearer":
        raise VaultRewindError("OAUTH_TOKEN_INVALID", "The provider returned an unsupported token type.")
    return validate_token({"access_token": response.get("access_token"),
                           "refresh_token": response.get("refresh_token") or previous_refresh,
                           "expiry": _rfc3339(now + timedelta(seconds=expires_in))})


class GoogleApi:
    """Minimal OAuth token endpoint and Drive v3 client (httpx). Endpoints are fixed Google URLs."""

    def __init__(self, http: httpx.Client | None = None):
        self.http = http or httpx.Client(timeout=httpx.Timeout(30.0), follow_redirects=False,
                                         headers={"User-Agent": "VaultRewind"})

    def _token(self, form: dict) -> dict:
        try:
            response = self.http.post(TOKEN_URL, data=form, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise VaultRewindError("STORAGE_UNREACHABLE", "Google's token service could not be reached.", True) from exc
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code == 200 and isinstance(body, dict):
            return body
        error = str(body.get("error", "")) if isinstance(body, dict) else ""
        mapping = {"invalid_grant": ("STORAGE_AUTH_EXPIRED",
                                     "Google rejected the authorization grant (expired, revoked or already used)."),
                   "invalid_client": ("STORAGE_CLIENT_INVALID", "Google rejected the OAuth client ID or secret."),
                   "unauthorized_client": ("STORAGE_CLIENT_INVALID", "This OAuth client may not use this grant."),
                   "redirect_uri_mismatch": ("OAUTH_REDIRECT_MISMATCH",
                                             "The callback URL is not registered on the OAuth client."),
                   "invalid_scope": ("OAUTH_SCOPE_INSUFFICIENT", "Google rejected the requested Drive scope.")}
        code, message = mapping.get(error, ("OAUTH_TOKEN_EXCHANGE_FAILED", "Google's token service returned an error."))
        raise VaultRewindError(code, message, response.status_code >= 500,
                               credential_state="reconnect_required" if code == "STORAGE_AUTH_EXPIRED" else None)

    def exchange_code(self, client: GoogleClient, code: str, verifier: str, redirect_uri: str) -> dict:
        return self._token({"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                            "redirect_uri": redirect_uri, **client.as_dict()})

    def refresh(self, client: GoogleClient, refresh_token: str) -> dict:
        return self._token({"grant_type": "refresh_token", "refresh_token": refresh_token, **client.as_dict()})

    def revoke(self, token: str) -> bool:
        try:
            response = self.http.post(REVOKE_URL, data={"token": token})
        except httpx.HTTPError as exc:
            raise VaultRewindError("STORAGE_UNREACHABLE", "Google's revocation service could not be reached.", True) from exc
        return response.status_code in (200, 400)

    def _drive(self, method: str, path: str, access_token: str, **kwargs) -> dict:
        try:
            response = self.http.request(method, DRIVE_API + path,
                                         headers={"Authorization": f"Bearer {access_token}",
                                                  "Accept": "application/json"}, **kwargs)
        except httpx.HTTPError as exc:
            raise VaultRewindError("STORAGE_UNREACHABLE", "Google Drive could not be reached.", True) from exc
        if response.status_code in (200, 201):
            return response.json()
        reasons = ""
        with contextlib.suppress(ValueError, AttributeError, TypeError):
            reasons = " ".join(str(e.get("reason", "")) for e in response.json()["error"].get("errors", []))
        if response.status_code == 401:
            raise VaultRewindError("STORAGE_AUTH_EXPIRED", "Google Drive rejected the access token.", False,
                                   credential_state="reconnect_required")
        if response.status_code == 404:
            raise VaultRewindError("DRIVE_FOLDER_UNAVAILABLE",
                                   "The configured Drive folder is not accessible to this authorization.",
                                   credential_state="folder_unavailable")
        raise classify_output(f"{response.status_code} {reasons}", "DRIVE_API_FAILED", "Google Drive returned an error.")

    def get_folder(self, access_token: str, folder_id: str) -> dict:
        if not _FOLDER_ID.fullmatch(folder_id or ""):
            raise VaultRewindError("STORAGE_CONFIGURATION", "The Drive folder ID is malformed.")
        return self._drive("GET", f"/files/{folder_id}", access_token,
                           params={"fields": "id,name,mimeType,trashed,driveId,capabilities(canAddChildren)",
                                   "supportsAllDrives": "true"})

    def create_folder(self, access_token: str, name: str, destination_id: str) -> dict:
        return self._drive("POST", "/files", access_token, params={"fields": "id,name,mimeType,trashed,driveId"},
                           json={"name": name, "mimeType": FOLDER_MIME,
                                 "appProperties": {"vaultrewindDestination": destination_id}})

    def quota(self, access_token: str) -> dict:
        about = self._drive("GET", "/about", access_token, params={"fields": "storageQuota"})
        quota = about.get("storageQuota") or {}
        as_int = lambda value: int(value) if str(value or "").isdigit() else None
        return {"limit_bytes": as_int(quota.get("limit")), "used_bytes": as_int(quota.get("usage")),
                "trash_bytes": as_int(quota.get("usageInDriveTrash"))}


def _folder_name(name: str | None, destination_id: str) -> str:
    candidate = (name or f"VaultRewind {destination_id[:8]}").strip()
    if not 1 <= len(candidate) <= 100 or any(ord(c) < 32 for c in candidate):
        raise VaultRewindError("STORAGE_CONFIGURATION", "The Drive folder name must be 1-100 printable characters.")
    return candidate


def _finalize(api: GoogleApi, client: GoogleClient, token_response: dict, *, destination_id: str,
              previous_refresh: str | None, existing_folder_id: str | None, folder_name: str | None,
              now: datetime) -> dict:
    scopes = str(token_response.get("scope", "")).split()
    if SCOPE_FILE not in scopes:
        raise VaultRewindError("OAUTH_SCOPE_INSUFFICIENT",
                               "Google did not grant the Drive file permission; approve it when reconnecting.")
    token = _token_from_response(token_response, previous_refresh, now)
    if existing_folder_id:
        folder = api.get_folder(token["access_token"], existing_folder_id)
    else:
        folder = api.create_folder(token["access_token"], _folder_name(folder_name, destination_id), destination_id)
    if folder.get("driveId"):
        raise VaultRewindError("DRIVE_SHARED_DRIVE_UNSUPPORTED", "Shared drives are not supported in this release.")
    if folder.get("mimeType") != FOLDER_MIME or folder.get("trashed") or not _FOLDER_ID.fullmatch(str(folder.get("id"))):
        raise VaultRewindError("DRIVE_FOLDER_UNAVAILABLE", "The Drive folder is missing, trashed or not a folder.",
                               credential_state="folder_unavailable")
    if existing_folder_id and (folder.get("capabilities") or {}).get("canAddChildren") is False:
        raise VaultRewindError("DRIVE_FOLDER_UNAVAILABLE", "This authorization cannot write to the Drive folder.",
                               credential_state="folder_unavailable")
    credential = {"type": "google_drive_oauth", "version": 1, **client.as_dict(), "scope": SCOPE_NAME,
                  "granted_scopes": scopes, "token": token, "folder_id": folder["id"],
                  "grant_id": str(uuid.uuid4()), "authorized_at": utc_iso(now)}
    return {"destination_id": destination_id, "credential": credential, "granted_scopes": scopes,
            "configuration": {"folder_id": folder["id"], "folder_name": str(folder.get("name") or ""),
                              "scope": SCOPE_NAME}}


class DriveAuthorization:
    """Guided browser authorization with the owner's own Web-application OAuth client."""

    def __init__(self, box: SecretBox, state_store: AuthorizationStateStore, public_origin: str, *,
                 callback_path: str = CALLBACK_PATH, http: httpx.Client | None = None, clock=utcnow):
        self.box, self.store, self.clock = box, state_store, clock
        self.public_origin = normalize_origin(public_origin)
        if not callback_path.startswith("/") or "?" in callback_path or "#" in callback_path:
            raise VaultRewindError("PUBLIC_ORIGIN_INVALID", "The OAuth callback path is invalid.")
        self.redirect_uri = self.public_origin + callback_path
        self.api = GoogleApi(http)

    def begin(self, destination_id: str, session_id: str, client: GoogleClient, *, purpose: str = "authorize") -> dict:
        destination_id = layout.canonical_uuid(destination_id, "destination ID")
        if not session_id or purpose not in ("authorize", "reconnect"):
            raise VaultRewindError("OAUTH_REQUEST_INVALID", "Authorization must start from an authenticated session.")
        state = new_state()
        verifier, challenge = pkce_pair()
        state_hash, now = sha256_hex(state), self.clock()
        self.store.put(PendingAuthorization(
            state_hash=state_hash, destination_id=destination_id, session_binding=sha256_hex(session_id),
            redirect_uri=self.redirect_uri,
            verifier_envelope=self.box.encrypt(verifier, context=f"oauth:{state_hash}:verifier"),
            client_envelope=self.box.encrypt(client.as_dict(), context=f"oauth:{state_hash}:client"),
            created_at=now, expires_at=now + STATE_TTL, purpose=purpose))
        query = urlencode({"client_id": client.client_id, "redirect_uri": self.redirect_uri, "response_type": "code",
                           "scope": SCOPE_FILE, "access_type": "offline", "prompt": "consent",
                           "include_granted_scopes": "false", "state": state, "code_challenge": challenge,
                           "code_challenge_method": "S256"})
        return {"authorization_url": f"{AUTH_URL}?{query}", "expires_at": utc_iso(now + STATE_TTL),
                "redirect_uri": self.redirect_uri}

    def complete(self, *, request_origin: str, params: dict, session_id: str, existing_folder_id: str | None = None,
                 folder_name: str | None = None) -> dict:
        require_same_origin(request_origin, self.public_origin)
        now = self.clock()
        record = consume_state(self.store, str(params.get("state") or ""), session_id, now)
        if record.redirect_uri != self.redirect_uri:
            raise VaultRewindError("OAUTH_ORIGIN_MISMATCH", "The authorization was started for a different callback.")
        if params.get("error"):
            raise VaultRewindError("OAUTH_DENIED", "Google authorization was cancelled or denied.")
        code = params.get("code")
        if not isinstance(code, str) or not 10 <= len(code) <= 2048 or any(ord(c) < 33 for c in code):
            raise VaultRewindError("OAUTH_STATE_INVALID", "The authorization response is incomplete.")
        state_hash = record.state_hash
        verifier = self.box.decrypt(record.verifier_envelope, context=f"oauth:{state_hash}:verifier")
        client = GoogleClient(**self.box.decrypt(record.client_envelope, context=f"oauth:{state_hash}:client"))
        response = self.api.exchange_code(client, code, verifier, self.redirect_uri)
        return _finalize(self.api, client, response, destination_id=record.destination_id, previous_refresh=None,
                         existing_folder_id=existing_folder_id, folder_name=folder_name, now=now)


def exchange_authorization_code(client: GoogleClient, code: str, verifier: str, redirect_uri: str, *,
                                destination_id: str, existing_folder_id: str | None = None,
                                folder_name: str | None = None, http: httpx.Client | None = None,
                                clock=utcnow) -> dict:
    """Worker-side exchange for servers that keep their own single-use state/PKCE records.

    The caller must already have consumed the state (single use, session-bound, unexpired) and must pass
    the exact registered ``redirect_uri``. Returns the same structure as ``DriveAuthorization.complete``.
    """
    destination_id = layout.canonical_uuid(destination_id, "destination ID")
    if not isinstance(code, str) or not 10 <= len(code) <= 2048 or any(ord(c) < 33 for c in code):
        raise VaultRewindError("OAUTH_STATE_INVALID", "The authorization response is incomplete.")
    if not isinstance(verifier, str) or not 43 <= len(verifier) <= 128:
        raise VaultRewindError("OAUTH_STATE_INVALID", "The PKCE verifier is invalid.")
    parts = urlsplit(redirect_uri if isinstance(redirect_uri, str) else "")
    normalize_origin(f"{parts.scheme}://{parts.netloc}")
    if not parts.path.startswith("/") or parts.query or parts.fragment:
        raise VaultRewindError("OAUTH_REDIRECT_MISMATCH", "The OAuth redirect URI must be an exact callback URL.")
    api = GoogleApi(http)
    response = api.exchange_code(client, code, verifier, redirect_uri)
    return _finalize(api, client, response, destination_id=destination_id, previous_refresh=None,
                     existing_folder_id=existing_folder_id, folder_name=folder_name, now=clock())


def import_headless_token(client: GoogleClient, token_json: str, *, destination_id: str,
                          existing_folder_id: str | None = None, folder_name: str | None = None,
                          http: httpx.Client | None = None, clock=utcnow) -> dict:
    """Advanced path: validate an ``rclone authorize drive`` token by refreshing it, then finalize."""
    destination_id = layout.canonical_uuid(destination_id, "destination ID")
    if not isinstance(token_json, str) or len(token_json) > 16384:
        raise VaultRewindError("OAUTH_TOKEN_INVALID", "Paste only the JSON token printed by rclone authorize.")
    text = token_json.strip()
    start, end = text.find("{"), text.rfind("}")
    try:
        token = json.loads(text[start:end + 1]) if start >= 0 and end > start else None
    except ValueError:
        token = None
    token = validate_token(token)
    api = GoogleApi(http)
    response = api.refresh(client, token["refresh_token"])
    return _finalize(api, client, response, destination_id=destination_id, previous_refresh=token["refresh_token"],
                     existing_folder_id=existing_folder_id, folder_name=folder_name, now=clock())


def revoke(credential: dict, *, http: httpx.Client | None = None) -> bool:
    token = validate_token((credential or {}).get("token"))
    return GoogleApi(http).revoke(token["refresh_token"])


def headless_instructions(client_id: str | None = None) -> str:
    """Shown in the UI for the advanced path. Contains no secrets and no token values."""
    shown = client_id if client_id and _CLIENT_ID.fullmatch(client_id) else "<your OAuth client ID>"
    return (
        "On a computer with a web browser and rclone 1.75.2:\n"
        "  1. In the same Google Cloud project, allow the redirect URI http://127.0.0.1:53682/ on this OAuth client\n"
        "     (or create a 'Desktop app' client in that project).\n"
        "  2. Run these commands; the secret is read without echo and never appears in a command line:\n"
        "       read -r RCLONE_DRIVE_CLIENT_ID        # paste: " + shown + "\n"
        "       read -rs RCLONE_DRIVE_CLIENT_SECRET   # paste the client secret (hidden)\n"
        "       export RCLONE_DRIVE_CLIENT_ID RCLONE_DRIVE_CLIENT_SECRET RCLONE_DRIVE_SCOPE=drive.file\n"
        "       rclone authorize drive\n"
        "       unset RCLONE_DRIVE_CLIENT_SECRET\n"
        "  3. Sign in with the dedicated Google account and approve access.\n"
        "  4. Copy only the JSON object rclone prints between the arrows into VaultRewind's private token field.\n"
        "     Do not paste it into chat, tickets, email or the vault you are protecting.")


# ---------------------------------------------------------------------- rclone sessions
def _safe_value(value: str, pattern: re.Pattern, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise VaultRewindError("STORAGE_CONFIGURATION", f"The Drive {what} is malformed.")
    return value


def rclone_config_text(credential: dict, folder_id: str, *, overrides: dict | None = None) -> str:
    token = validate_token(credential.get("token"))
    lines = [f"[{REMOTE}]", "type = drive",
             f"client_id = {_safe_value(credential.get('client_id'), _CLIENT_ID, 'client ID')}",
             f"client_secret = {_safe_value(credential.get('client_secret'), _CLIENT_SECRET, 'client secret')}",
             f"scope = {SCOPE_NAME}", f"root_folder_id = {_safe_value(folder_id, _FOLDER_ID, 'folder ID')}",
             "token = " + json.dumps(token, separators=(",", ":")),
             "use_trash = false", "stop_on_upload_limit = true", "stop_on_download_limit = true"]
    for key, value in (overrides or {}).items():
        if key not in _RCLONE_OVERRIDE_KEYS or not re.fullmatch(r"https?://[A-Za-z0-9.:\[\]/_-]{1,200}", str(value)):
            raise VaultRewindError("STORAGE_CONFIGURATION", "Unsupported rclone override.")
        lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"


def read_rclone_token(path: Path) -> dict | None:
    try:
        return _parse_rclone_token(Path(path).read_text())
    except OSError:
        return None


def _parse_rclone_token(text: str) -> dict | None:
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read_string(text)
        return validate_token(json.loads(parser.get(REMOTE, "token")))
    except (configparser.Error, ValueError, VaultRewindError):
        return None


def _config_fingerprint(text: str) -> str:
    parser = configparser.RawConfigParser(strict=True)
    try:
        parser.read_string(text)
        if parser.sections() != [REMOTE] or parser.defaults():
            raise ValueError("unexpected config sections")
        settings = dict(parser.items(REMOTE, raw=True))
        settings.pop("token", None)
        return hashlib.sha256(json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except (configparser.Error, ValueError) as exc:
        raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE", "The orphaned Drive config has unexpected settings.") from exc


def _load_credential(store: CredentialStore, box: SecretBox, destination_id: str):
    stored = store.load(destination_id)
    if stored is None:
        raise VaultRewindError("STORAGE_CREDENTIALS_MISSING", "Authorize this Google Drive destination first.",
                               credential_state="reconnect_required")
    credential = box.decrypt(stored.envelope, context=credential_context(destination_id))
    if isinstance(credential, dict) and credential.get("type") != "google_drive_oauth" and credential.get("client_id"):
        raise VaultRewindError("STORAGE_AUTHORIZATION_REQUIRED", "Authorize this Google Drive destination first.",
                               credential_state="authorization_required")
    if not isinstance(credential, dict) or credential.get("type") != "google_drive_oauth":
        raise VaultRewindError("STORAGE_CREDENTIALS_INVALID", "The stored Drive credential is malformed.")
    if credential.get("revoked_at") or credential.get("revoked"):
        raise VaultRewindError("STORAGE_AUTH_EXPIRED", "The Drive grant was revoked; reconnect the destination.",
                               credential_state="reconnect_required")
    return stored, credential


class DriveCredentialSession:
    """Context manager yielding a private writable rclone config for one destination."""

    def __init__(self, destination_id: str, store: CredentialStore, box: SecretBox, *, folder_id: str,
                 lock_dir: Path, runtime_dir: Path | None = None, rclone_overrides: dict | None = None):
        self.destination_id = layout.canonical_uuid(destination_id, "destination ID")
        self.store, self.box, self.folder_id = store, box, folder_id
        self.state_directory = Path(getattr(store, "state_directory", None) or lock_dir)
        self.lock_dir = self.state_directory / "session-locks"
        self.runtime_dir, self.overrides = runtime_dir, rclone_overrides
        self.workspace: Path | None = None
        self.config_path: Path | None = None
        self._cleanup_safe = True
        self.pending = None
        self.sessions = None
        self.session_record = None
        self.recovered_sessions = 0
        self._orphan_copy_durable = True
        self.outcome = {"refreshed": False, "persisted": 0, "stale_rejected": 0}

    def __enter__(self) -> Self:
        self.pending = PendingCredentialUpdates(self.state_directory, self.box, self.destination_id)
        self.sessions = DriveSessionJournal(self.state_directory, self.box, self.destination_id)
        try:
            with credential_lock(self.lock_dir, self.destination_id):
                self._recover_orphaned_sessions()
                self._retry_pending()
                stored, credential = _load_credential(self.store, self.box, self.destination_id)
        except Exception as error:
            if (any(self.pending.directory.glob(f"{self.destination_id}.*.pending-credential")) or
                    self.sessions.paths()):
                raise self._persistence_error(pending_encrypted=self._orphan_copy_durable,
                                              persistence_error=error) from error
            raise
        if credential.get("folder_id") != self.folder_id:
            raise VaultRewindError("DRIVE_FOLDER_UNAVAILABLE",
                                   "The Drive authorization belongs to a different folder; reconnect the destination.",
                                   credential_state="folder_unavailable")
        self.grant_id = credential.get("grant_id")
        if not isinstance(self.grant_id, str) or not self.grant_id or stored.generation is None:
            raise VaultRewindError("STORAGE_CREDENTIALS_INVALID",
                                   "Reconnect Drive using a revisioned credential store before running jobs.")
        self.base_credential, self.base_stored = credential, stored
        self.base_token = validate_token(credential.get("token"))
        base = Path(self.runtime_dir).absolute() if self.runtime_dir else Path(tempfile.gettempdir())
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.workspace = Path(tempfile.mkdtemp(prefix="vaultrewind-rclone-", dir=base))
        os.chmod(self.workspace, 0o700)
        try:
            config_text = rclone_config_text(credential, self.folder_id, overrides=self.overrides)
            self.session_record = self.sessions.register(self.workspace, {
                "version": 1, "credential": credential, "base_token": self.base_token,
                "base_revision": stored.revision, "generation": stored.generation},
                _config_fingerprint(config_text))
            self.config_path = write_private_file(self.workspace / "rclone.conf",
                                                  config_text)
            self.sessions.save(self.session_record, phase="ready")
        except BaseException:
            scrub_tree(self.workspace)
            if self.session_record is not None:
                try:
                    self.sessions.remove(self.session_record)
                finally:
                    self.session_record.close()
            raise
        return self

    def _recover_orphaned_sessions(self) -> None:
        """Recover only sealed, inactive registered configs; caller holds the destination lock."""
        for path in self.sessions.paths():
            self._orphan_copy_durable = False
            try:
                record = self.sessions.acquire_orphan(path)
            except FileNotFoundError:
                if not path.exists():
                    continue  # a normal session completed after this scan
                raise
            if record is None:
                self._orphan_copy_durable = True
                continue
            try:
                self._orphan_copy_durable = record.value["phase"] == "finalized"
                if registered_config_in_use(record):
                    raise VaultRewindError("CREDENTIAL_SESSION_BUSY",
                                           "An orphaned Drive provider is still running. Retry after it exits.", True)
                if record.value["phase"] == "finalized":
                    try:
                        scrub_registered_workspace(record)
                    except FileNotFoundError:
                        pass  # already scrubbed before the owner died
                    self.sessions.remove(record)
                    continue
                try:
                    config_text = read_registered_config(record)
                except FileNotFoundError:
                    if record.value["phase"] != "prepared":
                        raise VaultRewindError("CREDENTIAL_SESSION_MISSING",
                                               "A registered Drive config disappeared before token recovery.") from None
                    # A crash before the initial private config was created is safe to retire.
                    try:
                        with registered_workspace(record) as directory, os.scandir(directory) as entries:
                            if next(entries, None) is not None:
                                raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE",
                                                       "An incomplete Drive workspace contains unexpected files.")
                        scrub_registered_workspace(record)
                    except FileNotFoundError:
                        pass
                    self.sessions.remove(record)
                    self._orphan_copy_durable = True
                    continue
                if _config_fingerprint(config_text) != record.value["configuration_fingerprint"]:
                    raise VaultRewindError("CREDENTIAL_SESSION_UNSAFE",
                                           "The registered Drive config provenance changed; keep it for review.")
                update = dict(record.value["update"])
                candidate = _parse_rclone_token(config_text)
                if candidate is None:
                    update["unparsed_config"] = config_text
                else:
                    update["token"] = candidate
                # This is the durable encrypted handoff: no database availability is needed
                # before the orphan's plaintext config can be scrubbed.
                self.pending.save(update)
                self._orphan_copy_durable = True
                self.sessions.save(record, phase="finalized")
                scrub_registered_workspace(record)
                self.sessions.remove(record)
                self.recovered_sessions += 1
                if candidate is not None and candidate != update["base_token"]:
                    self.outcome["refreshed"] = True
            finally:
                record.close()

    def sync(self) -> dict:
        """Journal first, then retry grant/generation/revision-aware persistence under the credential lock."""
        candidate = read_rclone_token(self.config_path) if self.config_path else None
        if candidate is None and self.config_path is not None:
            self._cleanup_safe = False
            # A truncated/unparseable rewrite may still contain the only rotated refresh token.
            # Keep the raw config encrypted, then fail rather than silently scrubbing it.
            self.pending.save({"version": 1, "credential": self.base_credential,
                               "unparsed_config": self.config_path.read_text(), "base_token": self.base_token,
                               "base_revision": self.base_stored.revision, "generation": self.base_stored.generation})
            self._cleanup_safe = True
            raise VaultRewindError("CREDENTIAL_REFRESH_UNREADABLE",
                                   "The rewritten Drive config is unreadable. Preserve encrypted updates and reconnect.")
        if candidate is None or candidate == self.base_token:
            with credential_lock(self.lock_dir, self.destination_id):
                self._retry_pending()
            return self.outcome
        if (candidate["refresh_token"] == self.base_token["refresh_token"] and
                token_expiry(candidate) <= token_expiry(self.base_token)):
            return self.outcome
        self._cleanup_safe = False
        self.outcome["refreshed"] = True
        update = {"version": 1, "credential": self.base_credential, "token": candidate,
                  "base_token": self.base_token, "base_revision": self.base_stored.revision,
                  "generation": self.base_stored.generation}
        try:
            self.pending.save(update)
        except (OSError, VaultRewindError):
            # If local journal storage failed but the encrypted database is healthy, complete
            # the same guarded CAS there rather than retaining a plaintext emergency config.
            with credential_lock(self.lock_dir, self.destination_id):
                self._apply_pending(update)
            self._cleanup_safe = True
            self.base_token = candidate
            self._checkpoint_session()
            return self.outcome
        self._cleanup_safe = True  # fsynced encrypted copy exists even if the database is unavailable
        self.base_token = candidate
        with credential_lock(self.lock_dir, self.destination_id):
            self._retry_pending()
        self._checkpoint_session()
        return self.outcome

    def _checkpoint_session(self) -> None:
        if self.session_record is not None:
            self.session_record.value["update"]["base_token"] = self.base_token
            self.session_record.value["update"]["base_revision"] = getattr(
                self, "_persisted_revision", self.base_stored.revision)
            self.sessions.save(self.session_record)

    def _retry_pending(self) -> None:
        updates = sorted(self.pending.load(), key=lambda item: (item[1]["base_revision"], item[0].name))
        for path, update in updates:
            self._apply_pending(update)
            self.pending.remove(path)

    def _apply_pending(self, update: dict) -> None:
        original = update["credential"]
        for _ in range(3):  # CAS conflicts from SQL/reconnect paths need a fresh grant check on every attempt
            stored = self.store.load(self.destination_id)
            if stored is None:
                self.outcome["stale_rejected"] += 1  # revoked/deleted credentials are never recreated
                return
            current = self.box.decrypt(stored.envelope, context=credential_context(self.destination_id))
            if (stored.generation != update["generation"] or not isinstance(current, dict) or
                    current.get("revoked_at") or current.get("revoked") or
                    current.get("type") != "google_drive_oauth" or not original.get("grant_id") or
                    any(current.get(key) != original.get(key) for key in
                        ("grant_id", "client_id", "client_secret", "folder_id", "scope"))):
                self.outcome["stale_rejected"] += 1
                return
            token = _parse_rclone_token(update["unparsed_config"]) if "unparsed_config" in update else update["token"]
            if token is None:
                raise VaultRewindError("CREDENTIAL_REFRESH_UNREADABLE",
                                       "The saved Drive refresh is unreadable. Preserve encrypted updates and reconnect.")
            candidate, base = validate_token(token), validate_token(update["base_token"])
            current_token = validate_token(current.get("token"))
            if current_token == candidate:
                return  # commit succeeded before an acknowledgment was lost
            if current_token["refresh_token"] not in (base["refresh_token"], candidate["refresh_token"]):
                if candidate["refresh_token"] != base["refresh_token"]:
                    # Two independent refresh-token rotations cannot be ordered by access-token expiry.
                    # Preserve both encrypted candidates until an explicit fresh grant supersedes them.
                    raise VaultRewindError("CREDENTIAL_REFRESH_CONFLICT",
                                           "Drive refresh tokens diverged. Preserve pending updates and reconnect "
                                           "with a new authorization grant before retrying.")
                self.outcome["stale_rejected"] += 1
                return
            if (current_token["refresh_token"] == candidate["refresh_token"] and
                    token_expiry(candidate) <= token_expiry(current_token)):
                self.outcome["stale_rejected"] += 1
                return
            updated = {**current, "token": candidate, "token_refreshed_at": utc_iso()}
            envelope = self.box.encrypt(updated, context=credential_context(self.destination_id))
            try:
                revision = self.store.compare_and_swap(self.destination_id, envelope, stored.revision,
                                                       expected_generation=stored.generation)
            except VaultRewindError as error:
                if error.code == "CREDENTIAL_STALE":
                    continue
                raise
            self.outcome["persisted"] += 1
            self._persisted_revision = revision
            return
        raise VaultRewindError("CREDENTIAL_STALE", "The Drive credential kept changing; retry pending recovery.", True)

    @staticmethod
    def _persistence_error(*, pending_encrypted: bool, operation_error_code: str | None = None,
                           persistence_error: Exception | None = None):
        code = persistence_error.code if isinstance(persistence_error, VaultRewindError) else "CREDENTIAL_STORAGE_UNAVAILABLE"
        conflict = code in {"CREDENTIAL_REFRESH_CONFLICT", "CREDENTIAL_REFRESH_UNREADABLE"}
        review = code in {"CREDENTIAL_SESSION_UNSAFE", "CREDENTIAL_SESSION_MISSING", "CREDENTIAL_SESSION_LIMIT"}
        if conflict:
            message = "Drive refresh needs a new grant. Keep encrypted pending updates and reconnect."
        elif review:
            message = "Drive session recovery needs review. Preserve credential state and the registered config before retrying."
        elif code == "CREDENTIAL_SESSION_BUSY":
            message = "A Drive provider from an interrupted job may still be running. Keep its config and retry after it exits."
        else:
            message = ("A refreshed Drive credential needs recovery. Keep credential state and retry after "
                       "storage is available; do not delete pending updates or reconnect with an older token.")
        return VaultRewindError(
            "CREDENTIAL_PERSIST_FAILED", message, not (conflict or review),
            pending_recovery_required=True, cleanup_blocked=True, pending_encrypted=pending_encrypted,
            operation_error_code=operation_error_code,
            persistence_error_code=code)

    def __exit__(self, exc_type, exc, tb):
        failure = None
        try:
            self.sync()
        except Exception as error:  # noqa: BLE001 - re-raised below as a sanitized error
            failure = error
        finally:
            try:
                if self.workspace is not None and self._cleanup_safe:
                    if self.session_record is not None:
                        self.sessions.save(self.session_record, phase="finalized")
                        scrub_registered_workspace(self.session_record)
                        self.sessions.remove(self.session_record)
                    else:
                        scrub_tree(self.workspace)
                    self.config_path = None
            except Exception as error:  # noqa: BLE001 - always surface a sanitized recovery failure
                if failure is None:
                    failure = error
            finally:
                if self.session_record is not None:
                    self.session_record.close()
        if failure is not None:
            raise self._persistence_error(pending_encrypted=self._cleanup_safe,
                                          operation_error_code=exc.code if isinstance(exc, VaultRewindError)
                                          else "STORAGE_OPERATION_FAILED" if exc is not None else None,
                                          persistence_error=failure) from failure
        return False


def drive_location(instance_id: str, destination_id: str) -> str:
    return f"rclone:{REMOTE}:{layout.repository_prefix(instance_id, destination_id)}"


@contextlib.contextmanager
def drive_repository(destination_id: str, configuration: dict, *, instance_id: str, password: str,
                     store: CredentialStore, box: SecretBox, work_dir: Path, repository_id: str | None = None,
                     cancel_event=None, rclone_overrides: dict | None = None, location: str | None = None,
                     restic_binary: str = "restic", rclone_binary: str = "rclone") -> Iterator[ResticRepository]:
    folder_id = _safe_value(configuration.get("folder_id"), _FOLDER_ID, "folder ID")
    work_dir = ensure_private_directory(Path(work_dir))
    with DriveCredentialSession(destination_id, store, box, folder_id=folder_id, lock_dir=work_dir / "locks",
                                runtime_dir=work_dir / "runtime", rclone_overrides=rclone_overrides) as session:
        config = RepositoryConfig(location=location or drive_location(instance_id, destination_id), password=password,
                                  rclone_config=session.config_path, cache_dir=work_dir / "cache" / "restic",
                                  instance_uuid=instance_id, expected_repository_id=repository_id,
                                  runtime_dir=work_dir / "runtime", restic_binary=restic_binary,
                                  rclone_binary=rclone_binary, options=("rclone.timeout=2m",))
        yield ResticRepository(config, cancel_event=cancel_event)


def _rclone(session: DriveCredentialSession, args: list[str], *, data: bytes | None = None, timeout: int = 300,
            rclone_binary: str = "rclone") -> subprocess.CompletedProcess:
    binary = resolve_binary(rclone_binary, "rclone")
    with private_workspace(session.runtime_dir, prefix="vaultrewind-rclone-home-") as home:
        env = {"PATH": SAFE_PATH, "HOME": str(home), "TZ": "UTC", "LC_ALL": "C.UTF-8",
               "RCLONE_CONFIG": str(session.config_path), "XDG_CACHE_HOME": str(home / "cache")}
        try:
            return subprocess.run([binary, "--low-level-retries", "2", "--retries", "1", "--contimeout", "15s",
                                   "--timeout", "60s", *args], input=data, capture_output=True, env=env,
                                  timeout=timeout, cwd=home, check=False)
        except subprocess.TimeoutExpired as exc:
            raise VaultRewindError("STORAGE_TIMEOUT", "Google Drive did not respond in time.", True) from exc


def _rclone_ok(session, args, operation, **kwargs) -> bytes:
    result = _rclone(session, args, **kwargs)
    if result.returncode != 0:
        raise classify_output(result.stderr.decode("utf-8", "replace"), "STORAGE_OPERATION_FAILED",
                              "The Google Drive operation failed.", operation=operation)
    return result.stdout


def probe_drive(session: DriveCredentialSession, *, rclone_binary: str = "rclone") -> dict:
    """Writes, reads and deletes one probe file in <folder>/vaultrewind/.probe; may refresh the token."""
    key = f"{REMOTE}:{layout.LAYOUT_ROOT}/.probe/{uuid.uuid4()}.probe"
    payload = os.urandom(32).hex().encode()
    results = {name: {"ok": False, "error_code": None} for name in ("write", "read", "delete", "quota")}
    quota = None
    for name, action in (("write", lambda: _rclone_ok(session, ["rcat", key], "probe", data=payload,
                                                      rclone_binary=rclone_binary)),
                         ("read", lambda: _rclone_ok(session, ["cat", key], "probe", rclone_binary=rclone_binary)),
                         ("delete", lambda: _rclone_ok(session, ["deletefile", key], "probe",
                                                       rclone_binary=rclone_binary)),
                         ("quota", lambda: _rclone_ok(session, ["about", f"{REMOTE}:", "--json"], "probe",
                                                      rclone_binary=rclone_binary))):
        if name in ("read", "delete") and not results["write"]["ok"]:
            results[name]["error_code"] = "PROBE_NOT_WRITTEN"
            continue
        try:
            output = action()
            results[name]["ok"] = True
            if name == "read" and output != payload:
                results[name] = {"ok": False, "error_code": "STORAGE_PROBE_FAILED"}
            if name == "quota":
                with contextlib.suppress(ValueError, TypeError):
                    about = json.loads(output)
                    quota = {"limit_bytes": about.get("total"), "used_bytes": about.get("used"),
                             "free_bytes": about.get("free"), "trash_bytes": about.get("trashed")}
        except VaultRewindError as error:
            results[name]["error_code"] = error.code
    first_error = next((r["error_code"] for r in results.values() if r["error_code"]), None)
    return {"backend": "drive", "folder_id": session.folder_id, "probe": results, "quota": quota,
            "backup_ready": all(results[n]["ok"] for n in ("write", "read")),
            "retention_ready": results["delete"]["ok"], "credential_state": classify_credential_state(
                first_error if first_error not in ("PROBE_NOT_WRITTEN", "STORAGE_PROBE_FAILED") else None),
            "writes_disclosed": ["probe file created and deleted", "OAuth access token may be refreshed and saved"]}


def list_drive_repositories(session: DriveCredentialSession, *, rclone_binary: str = "rclone") -> list[dict]:
    output = _rclone_ok(session, ["lsjson", "--recursive", "--max-depth", "3", "--files-only",
                                  f"{REMOTE}:{layout.LAYOUT_ROOT}"], "list", rclone_binary=rclone_binary)
    found = []
    try:
        entries = json.loads(output or b"[]")
    except ValueError as exc:
        raise VaultRewindError("DRIVE_API_FAILED", "The Drive folder listing was unreadable.") from exc
    for entry in entries:
        path = str(entry.get("Path", ""))
        if path.endswith("/config") and path.count("/") == 2:
            parsed = layout.parse_repository_prefix(f"{layout.LAYOUT_ROOT}/{path.rsplit('/', 1)[0]}")
            if parsed:
                found.append({"instance_id": parsed[0], "destination_id": parsed[1],
                              "location": drive_location(*parsed)})
    return found

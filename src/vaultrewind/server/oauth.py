"""Server-owned OAuth state and PKCE. Token exchange runs only in the worker."""
import base64
import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from sqlalchemy import select
from starlette.responses import RedirectResponse

from vaultrewind.core.errors import VaultRewindError

from .auth import hash_token
from .db import now, utc
from .models import OAuthState
from .queue import audit, enqueue

SCOPE = "https://www.googleapis.com/auth/drive.file"
AUTHORIZATION = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


def start(db, store, settings, destination, session):
    config = store.get(db, destination.configuration_secret_id)
    credentials = store.get(db, destination.credential_id) if destination.credential_id else {}
    client_id = config.get("client_id") or credentials.get("client_id")
    client_secret = credentials.get("client_secret")
    if not client_id or not client_secret:
        raise VaultRewindError("OAUTH_CLIENT_REQUIRED", "Configure your own Google OAuth client before authorization.")
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    private_id = store.put(db, "oauth_pkce", destination.id, {"verifier": verifier})
    db.add(OAuthState(destination_id=destination.id, session_id=session.id, state_hash=hash_token(state),
                     verifier_secret_id=private_id, expires_at=now() + timedelta(minutes=10)))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    query = {"client_id": client_id, "redirect_uri": settings.public_origin + settings.drive_redirect_path,
             "response_type": "code", "scope": SCOPE, "state": state, "access_type": "offline",
             "prompt": "consent", "code_challenge": challenge, "code_challenge_method": "S256"}
    audit(db, session.user_id, "storage.authorize_start", destination.id)
    return {"authorization_url": AUTHORIZATION + "?" + urlencode(query), "scope": "drive.file",
            "expires_in_seconds": 600, "shared_drives_verified": False}


def callback(db, store, settings, session, actor_id, state, code, error):
    if len(state) > 256 or len(code) > 8192:
        raise VaultRewindError("PLAN_INVALID", "Invalid OAuth return.")
    item = db.scalar(select(OAuthState).where(OAuthState.state_hash == hash_token(state)).with_for_update())
    if not item or item.session_id != session.id or item.consumed_at or utc(item.expires_at) <= now():
        raise VaultRewindError("PLAN_INVALID", "Authorization state expired or does not match this session.")
    if error or not code:
        item.consumed_at = now()
        audit(db, actor_id, "storage.authorize_callback", item.destination_id, "denied")
        return RedirectResponse(settings.public_origin + "/?authorization=denied", status_code=303)
    verifier = store.get(db, item.verifier_secret_id)["verifier"]
    private_id = store.put(db, "oauth_exchange", item.destination_id, {"destination_id": item.destination_id,
                           "code": code, "verifier": verifier})
    job = enqueue(db, kind="drive_exchange", request={"secret_id": private_id}, key=f"oauth:{item.id}",
                  actor_id=actor_id, resources=[f"credential:{item.destination_id}"])
    item.consumed_at = now()
    audit(db, actor_id, "storage.authorize_callback", item.destination_id)
    return RedirectResponse(settings.public_origin + f"/?authorization_job={job.id}", status_code=303)

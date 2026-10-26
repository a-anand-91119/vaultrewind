import hashlib
import hmac
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Request
from sqlalchemy import func, select

from vaultrewind.core.errors import VaultRewindError

from .db import now, uid, utc
from .models import ControllerState, LoginAttempt, ResourceLease, Session, User
from .queue import audit, ensure_resource
from .settings import read_private_file

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY = PASSWORDS.hash(secrets.token_urlsafe(32))


def hash_token(value):
    return hashlib.sha256(value.encode()).hexdigest()


def origin_check(request: Request):
    if request.headers.get("origin") != request.app.state.settings.public_origin:
        raise VaultRewindError("CSRF_INVALID", "The request origin is invalid.")


def current(request, db):
    token = request.cookies.get("vr_session", "")
    session = db.scalar(select(Session).where(Session.token_hash == hash_token(token)))
    user = db.get(User, session.user_id) if session else None
    if not session or session.revoked_at or utc(session.expires_at) <= now() or not user or not user.active:
        raise VaultRewindError("AUTH_REQUIRED", "Sign in to continue.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin_check(request)
        csrf = request.headers.get("x-csrf-token", "")
        if not csrf or not hmac.compare_digest(hash_token(csrf), session.csrf_hash):
            raise VaultRewindError("CSRF_INVALID", "The CSRF token is invalid.")
    return user, session


def admin(request, db):
    user, session = current(request, db)
    if user.role != "administrator":
        raise VaultRewindError("FORBIDDEN", "Administrator access is required.")
    return user, session


def user_view(user):
    return {"id": user.id, "username": user.username, "role": user.role, "timezone": user.timezone}


def issue(db, request, response, user):
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    cfg = request.app.state.settings
    db.add(Session(user_id=user.id, token_hash=hash_token(token), csrf_hash=hash_token(csrf),
                   expires_at=now() + timedelta(hours=cfg.session_hours)))
    args = {"secure": cfg.secure_cookies, "samesite": "lax", "path": "/", "max_age": cfg.session_hours * 3600}
    response.set_cookie("vr_session", token, httponly=True, **args)
    response.set_cookie("vr_csrf", csrf, httponly=False, **args)
    return {"user": user_view(user), "csrf_token": csrf}


def rate_limit(db, keys, maximum=8):
    for text in sorted(keys):
        key = hash_token(text)
        dialect = db.bind.dialect.name
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        db.execute(insert(LoginAttempt).values(key=key, count=0, window_start=now()).on_conflict_do_nothing())
        row = db.scalar(select(LoginAttempt).where(LoginAttempt.key == key).with_for_update())
        if now() - utc(row.window_start) > timedelta(minutes=15):
            row.count, row.window_start = 0, now()
        row.count += 1
        if row.count > maximum:
            db.commit()
            raise VaultRewindError("RATE_LIMITED", "Too many authentication attempts.")
    # Persist failed attempts even when credential verification raises.
    db.commit()


def setup(db, request, response, body):
    origin_check(request)
    rate_limit(db, [f"setup:{request.client.host if request.client else 'unknown'}"], 8)
    ensure_resource(db, "controller:bootstrap")
    db.scalar(select(ResourceLease).where(ResourceLease.resource_key == "controller:bootstrap").with_for_update())
    state = db.get(ControllerState, 1)
    if state is None:
        state = ControllerState(id=1, bootstrap_used=False)
        db.add(state)
    if state.bootstrap_used or db.scalar(select(func.count()).select_from(User)):
        raise VaultRewindError("SETUP_COMPLETE", "Setup has already completed.")
    try:
        expected = read_private_file(request.app.state.settings.bootstrap_secret_file).decode().strip()
    except (VaultRewindError, UnicodeError):
        raise VaultRewindError("BOOTSTRAP_DENIED", "The bootstrap secret is unavailable.") from None
    if len(expected) < 24 or not hmac.compare_digest(expected, body.bootstrap_secret):
        raise VaultRewindError("BOOTSTRAP_DENIED", "The bootstrap secret is invalid.")
    from zoneinfo import ZoneInfo
    ZoneInfo(body.timezone)
    configured = request.app.state.settings.local_storage_root
    if body.local_storage_directory and body.local_storage_directory != str(configured):
        raise VaultRewindError("VALIDATION_ERROR", "Select the configured persistent storage mount.")
    user = User(id=uid(), username=body.username, password_hash=PASSWORDS.hash(body.password),
                role="administrator", timezone=body.timezone)
    db.add(user)
    db.flush()
    state.bootstrap_used, state.local_storage_root = True, str(configured)
    audit(db, user.id, "setup", user.id, "succeeded")
    return issue(db, request, response, user)


def login(db, request, response, body):
    origin_check(request)
    peer = request.client.host if request.client else "unknown"
    rate_limit(db, [f"login-account:{body.username}", f"login-peer:{peer}"], 8)
    user = db.scalar(select(User).where(User.username == body.username))
    valid = False
    try:
        valid = PASSWORDS.verify(user.password_hash if user else DUMMY, body.password)
    except (VerificationError, InvalidHashError):
        pass
    if not valid or not user or not user.active:
        raise VaultRewindError("LOGIN_FAILED", "The username or password is incorrect.")
    if PASSWORDS.check_needs_rehash(user.password_hash):
        user.password_hash = PASSWORDS.hash(body.password)
    audit(db, user.id, "session.login", user.id, "succeeded")
    return issue(db, request, response, user)

"""Provider-neutral OAuth authorization-code safeguards.

* ``state`` is 256 random bits; only its SHA-256 is stored, bound to a hash of the
  initiating browser session, the destination and the exact redirect URI.
* State is single use (atomic ``consume``) and expires after ten minutes.
* PKCE S256 is always used; the verifier is stored only as a SecretBox envelope.
* The callback must arrive on the configured public origin (HTTPS, with a
  documented loopback exception for development).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol
from urllib.parse import urlsplit

from vaultrewind.core.errors import VaultRewindError

STATE_TTL = timedelta(minutes=10)


def utcnow() -> datetime:
    return datetime.now(UTC)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_state() -> str:
    return secrets.token_urlsafe(32)


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 characters, within RFC 7636's 43..128
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def normalize_origin(origin: str) -> str:
    """Return ``scheme://host[:port]`` or raise. HTTPS is required except on loopback."""
    try:
        parts = urlsplit(origin)
        port = parts.port
    except ValueError as exc:
        raise VaultRewindError("PUBLIC_ORIGIN_INVALID", "The configured public origin is invalid.") from exc
    host = (parts.hostname or "").lower()
    if (parts.scheme not in ("https", "http") or not host or parts.username or parts.password
            or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise VaultRewindError("PUBLIC_ORIGIN_INVALID", "The public origin must be scheme://host[:port] only.")
    if parts.scheme == "http" and not _is_loopback(host):
        raise VaultRewindError("PUBLIC_ORIGIN_INSECURE",
                               "OAuth callbacks require HTTPS except on a loopback development address.")
    default = 443 if parts.scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{port}" if port and port != default else "")


def require_same_origin(request_origin: str, configured_origin: str) -> None:
    if not hmac.compare_digest(normalize_origin(request_origin).encode(), normalize_origin(configured_origin).encode()):
        raise VaultRewindError("OAUTH_ORIGIN_MISMATCH", "The authorization callback arrived on an unexpected origin.")


@dataclass(frozen=True)
class PendingAuthorization:
    state_hash: str
    destination_id: str
    session_binding: str          # sha256 of the initiating session identifier
    redirect_uri: str
    verifier_envelope: str        # SecretBox envelope of the PKCE verifier
    client_envelope: str          # SecretBox envelope of the owner's OAuth client credentials
    created_at: datetime
    expires_at: datetime
    purpose: str = "authorize"    # authorize | reconnect
    consumed_at: datetime | None = None


class AuthorizationStateStore(Protocol):
    """Server implementations must make ``consume`` atomic (e.g. UPDATE .. WHERE consumed_at IS NULL)."""

    def put(self, record: PendingAuthorization) -> None: ...

    def consume(self, state_hash: str, now: datetime) -> PendingAuthorization | None: ...


class InMemoryAuthorizationStateStore:
    """Thread-safe single-process store (tests, single-worker deployments, CLI)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: dict[str, PendingAuthorization] = {}

    def put(self, record: PendingAuthorization) -> None:
        with self._lock:
            if record.state_hash in self._records:
                raise VaultRewindError("OAUTH_STATE_COLLISION", "Authorization state collision.")
            self._records[record.state_hash] = record

    def consume(self, state_hash: str, now: datetime) -> PendingAuthorization | None:
        with self._lock:
            record = self._records.get(state_hash)
            if record is None or record.consumed_at is not None:
                return None
            self._records[state_hash] = replace(record, consumed_at=now)
            if record.expires_at <= now:
                return None
            return record

    def purge(self, now: datetime) -> int:
        with self._lock:
            stale = [key for key, item in self._records.items() if item.expires_at <= now - STATE_TTL]
            for key in stale:
                del self._records[key]
            return len(stale)


def consume_state(store: AuthorizationStateStore, state: str, session_id: str, now: datetime | None = None
                  ) -> PendingAuthorization:
    if not isinstance(state, str) or not 20 <= len(state) <= 128:
        raise VaultRewindError("OAUTH_STATE_INVALID", "The authorization response is invalid or expired.")
    now = now or utcnow()
    record = store.consume(sha256_hex(state), now)
    if record is None:
        raise VaultRewindError("OAUTH_STATE_INVALID", "The authorization response is invalid, reused or expired.")
    if not hmac.compare_digest(record.session_binding.encode(), sha256_hex(session_id or "").encode()):
        raise VaultRewindError("OAUTH_SESSION_MISMATCH",
                               "Authorization must be completed in the browser session that started it.")
    return record

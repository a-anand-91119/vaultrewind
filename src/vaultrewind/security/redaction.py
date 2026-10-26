"""Defensive redaction for anything that may reach logs, events, errors or API responses.

``redact`` walks nested dict/list/tuple/set structures.  Values under sensitive
keys are replaced, and free text is scrubbed of private-key blocks, bearer
tokens, Google OAuth tokens/client secrets, AWS key IDs, credential-bearing URL
query parameters, URL user-info and any explicitly registered secret values.

``OAuthCallbackScrubber`` is an ASGI middleware: for OAuth callback paths it moves
the query parameters into ``scope["state"]["vaultrewind_oauth_callback"]`` and
empties ``query_string``/``raw_path`` *in place* before any handler, access log
or error reporter can observe the authorization code.
"""
from __future__ import annotations

import logging
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import asdict, is_dataclass
from urllib.parse import parse_qsl

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "password", "passphrase", "secret", "token", "access_token", "refresh_token", "id_token",
    "client_secret", "private_key", "authorization", "cookie", "set-cookie", "api_key", "apikey",
    "secret_access_key", "aws_secret_access_key", "session_token", "aws_session_token", "master_key",
    "code_verifier", "credentials", "credential", "signature", "recovery_passphrase", "repository_password",
    "restic_password", "aws_access_key_id", "access_key_id", "auth_code", "authorization_code",
    "proxy-authorization", "x-amz-security-token", "recovery_root_secret", "root_secret", "kit",
}
_SENSITIVE_SUFFIXES = ("_password", "_passphrase", "_secret", "_token", "_private_key", "_credentials",
                       "_credential", "_envelope_plaintext")

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.DOTALL), REDACTED),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    (re.compile(r"\bya29\.[0-9A-Za-z_-]{10,}"), REDACTED),
    (re.compile(r"\b1//[0-9A-Za-z_-]{16,}"), REDACTED),
    (re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{10,}"), REDACTED),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"(?i)([?&;](?:code|state|token|access_token|refresh_token|id_token|client_secret|password|"
                r"passphrase|x-amz-signature|x-amz-credential|x-amz-security-token|sig|signature|key)=)[^&\s\"'<>]+"),
     r"\1" + REDACTED),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@\"']+:[^/\s@\"']*@"), r"\1" + REDACTED + "@"),
    (re.compile(r"(?i)([\"']?(?:password|passphrase|secret|client_secret|refresh_token|access_token|token|"
                r"secret_access_key|private_key)[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}]+)"),
     r"\1" + '"' + REDACTED + '"'),
]

_registry_lock = threading.Lock()
_registered: dict[str, None] = {}  # insertion ordered; bounded
REGISTRY_LIMIT = 4096


def register_secret(value: str | None) -> None:
    """Remember a live secret value so free text containing it is scrubbed process-wide."""
    if isinstance(value, str) and len(value) >= 6:
        with _registry_lock:
            _registered.pop(value, None)
            _registered[value] = None
            while len(_registered) > REGISTRY_LIMIT:
                del _registered[next(iter(_registered))]


def forget_secret(value: str | None) -> None:
    with _registry_lock:
        _registered.pop(value, None)


def is_sensitive_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    lowered = key.strip().lower().replace(" ", "_")
    return lowered in _SENSITIVE_KEYS or lowered.endswith(_SENSITIVE_SUFFIXES)


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    with _registry_lock:
        known = set(_registered)
    for value in sorted({*known, *(s for s in secrets if isinstance(s, str) and len(s) >= 6)}, key=len, reverse=True):
        text = text.replace(value, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value, secrets: Iterable[str] = (), _depth: int = 0):
    """Return a redacted deep copy suitable for persistence or display."""
    secrets = tuple(secrets)
    if _depth > 32:
        return REDACTED
    if isinstance(value, str):
        return redact_text(value, secrets)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return "[BYTES]"
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if is_sensitive_key(key) and item not in (None, "", [], {}):
                result[key] = REDACTED
            else:
                result[redact_text(str(key), secrets) if not isinstance(key, str) else key] = redact(
                    item, secrets, _depth + 1)
        return result
    if isinstance(value, list | tuple | set | frozenset):
        items = [redact(item, secrets, _depth + 1) for item in value]
        return items if isinstance(value, list | set | frozenset) else tuple(items)
    if isinstance(value, BaseException):
        return f"{type(value).__name__}: {redact_text(str(value), secrets)}"
    return redact_text(str(value), secrets)


class RedactingFilter(logging.Filter):
    """Scrubs log messages, arguments and exception text before any handler formats them."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if record.args:
                if isinstance(record.args, Mapping):
                    record.args = redact(dict(record.args))
                else:
                    record.args = tuple(redact(arg) if not isinstance(arg, int | float) else arg
                                        for arg in record.args)
            if not isinstance(record.msg, str):
                record.msg = str(record.msg)
            record.msg = redact_text(record.msg)
            if record.exc_info:
                formatter = logging.Formatter()
                record.exc_text = redact_text(formatter.formatException(record.exc_info))
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = redact_text(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_text(record.stack_info)
        except Exception:  # noqa: BLE001 - a broken filter must not leak the original record
            record.msg, record.args, record.exc_info, record.exc_text = "log record redaction failed", (), None, None
        return True


def install_log_redaction(*logger_names: str) -> RedactingFilter:
    """Attach one filter to the root handlers and to the named loggers (e.g. uvicorn.access)."""
    flt = RedactingFilter()
    names = logger_names or ("", "uvicorn", "uvicorn.access", "uvicorn.error", "httpx", "asyncssh")
    for name in names:
        logger = logging.getLogger(name)
        if not any(isinstance(existing, RedactingFilter) for existing in logger.filters):
            logger.addFilter(flt)
        for handler in logger.handlers:
            if not any(isinstance(existing, RedactingFilter) for existing in handler.filters):
                handler.addFilter(flt)
    return flt


# Response headers for OAuth callback/redirect responses: never cache, never leak the URL.
CALLBACK_RESPONSE_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

_CALLBACK_FIELDS = {"code", "state", "error", "error_description", "scope", "authuser", "prompt", "hd"}
SCOPE_KEY = "vaultrewind_oauth_callback"


class OAuthCallbackScrubber:
    """ASGI middleware. Wrap the outermost application object given to the server."""

    def __init__(self, app, paths: Iterable[str]):
        self.app = app
        self.paths = frozenset(paths)

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") in self.paths:
            raw = scope.get("query_string") or b""
            params: dict[str, str] = {}
            if len(raw) <= 8192:
                for key, value in parse_qsl(raw.decode("latin-1"), keep_blank_values=True, max_num_fields=16):
                    if key in _CALLBACK_FIELDS and key not in params:
                        params[key] = value
            scope.setdefault("state", {})[SCOPE_KEY] = params
            scope["query_string"] = b""
            if isinstance(scope.get("raw_path"), bytes | bytearray):
                scope["raw_path"] = bytes(scope["raw_path"]).split(b"?", 1)[0]
        await self.app(scope, receive, send)


def callback_params(scope_or_request) -> dict[str, str]:
    """Fetch scrubbed callback parameters from an ASGI scope or Starlette request."""
    scope = getattr(scope_or_request, "scope", scope_or_request)
    return dict((scope.get("state") or {}).get(SCOPE_KEY) or {})

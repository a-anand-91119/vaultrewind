"""Versioned AES-256-GCM envelopes for controller secrets.

Envelope text format (version 1)::

    vr1.<key id: 16 hex>.<nonce: base64url>.<ciphertext+tag: base64url>

The encryption key and the public key identifier are derived from the 32-byte
controller master key with HKDF-SHA256 using separate labels, so the identifier
reveals nothing useful about the key.  The associated data binds the format
version, key identifier and an optional caller context (for example
``"destination:<uuid>"``) so an envelope cannot be silently moved to another row.
Older master keys may be supplied for decryption during key rotation; new
envelopes are always written with the current key.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Iterable
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vaultrewind.core.errors import VaultRewindError

KEY_BYTES = 32
NONCE_BYTES = 12
ENVELOPE_VERSION = "vr1"
_MAX_PLAINTEXT = 16 * 1024 * 1024
_ENVELOPE_RE = re.compile(r"^vr1\.([0-9a-f]{16})\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{22,})$")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hkdf(master_key: bytes, label: bytes, length: int = KEY_BYTES) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"vaultrewind-secretbox-v1",
                info=label).derive(master_key)


def _check_key(master_key: bytes) -> bytes:
    if not isinstance(master_key, bytes | bytearray) or len(master_key) != KEY_BYTES:
        raise VaultRewindError("MASTER_KEY_INVALID", "The controller master key must be exactly 32 random bytes.")
    if len(set(master_key)) < 8:
        raise VaultRewindError("MASTER_KEY_INVALID", "The controller master key is not random key material.")
    return bytes(master_key)


class _Key:
    __slots__ = ("aead", "key_id")

    def __init__(self, master_key: bytes):
        master_key = _check_key(master_key)
        self.aead = AESGCM(_hkdf(master_key, b"aes-256-gcm encryption key"))
        self.key_id = _hkdf(master_key, b"public key identifier", 8).hex()


class SecretBox:
    """Encrypts ``dict`` or ``str`` values; ``decrypt`` returns the same type.

    No global or default key exists: every caller supplies the controller key.
    """

    def __init__(self, master_key: bytes, previous_keys: Iterable[bytes] = ()):
        self._current = _Key(master_key)
        self._keys = {self._current.key_id: self._current}
        for key in previous_keys:
            candidate = _Key(key)
            self._keys.setdefault(candidate.key_id, candidate)

    def __repr__(self) -> str:  # never reveal key material
        return f"SecretBox(key_id={self._current.key_id!r}, keys={len(self._keys)})"

    @property
    def key_id(self) -> str:
        return self._current.key_id

    @staticmethod
    def _aad(key_id: str, context: str | None) -> bytes:
        if context is not None and (not isinstance(context, str) or len(context) > 512):
            raise VaultRewindError("SECRET_CONTEXT_INVALID", "Invalid secret binding context.")
        return f"{ENVELOPE_VERSION}|{key_id}|{context or ''}".encode()

    def encrypt(self, value: dict | str, *, context: str | None = None) -> str:
        if isinstance(value, str):
            payload = {"t": "str", "v": value}
        elif isinstance(value, dict):
            payload = {"t": "dict", "v": value}
        else:
            raise VaultRewindError("SECRET_TYPE_INVALID", "Only text or JSON object secrets can be stored.")
        try:
            plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                   allow_nan=False).encode()
        except (TypeError, ValueError) as exc:
            raise VaultRewindError("SECRET_TYPE_INVALID", "The secret is not JSON serializable.") from exc
        if len(plaintext) > _MAX_PLAINTEXT:
            raise VaultRewindError("SECRET_TOO_LARGE", "The secret exceeds the supported size.")
        nonce = os.urandom(NONCE_BYTES)
        key = self._current
        ciphertext = key.aead.encrypt(nonce, plaintext, self._aad(key.key_id, context))
        return f"{ENVELOPE_VERSION}.{key.key_id}.{_b64e(nonce)}.{_b64e(ciphertext)}"

    @staticmethod
    def envelope_key_id(envelope: str) -> str:
        match = _ENVELOPE_RE.fullmatch(envelope) if isinstance(envelope, str) else None
        if not match:
            raise VaultRewindError("SECRET_ENVELOPE_INVALID", "The encrypted secret has an unsupported format.")
        return match.group(1)

    def decrypt(self, envelope: str, *, context: str | None = None) -> dict | str:
        key_id = self.envelope_key_id(envelope)
        _, _, nonce_text, cipher_text = envelope.split(".")
        key = self._keys.get(key_id)
        if key is None:
            raise VaultRewindError("SECRET_KEY_UNAVAILABLE",
                                   "The secret was encrypted with a master key that is not loaded.")
        try:
            nonce, ciphertext = _b64d(nonce_text), _b64d(cipher_text)
            if len(nonce) != NONCE_BYTES:
                raise ValueError("nonce")
            plaintext = key.aead.decrypt(nonce, ciphertext, self._aad(key_id, context))
            payload = json.loads(plaintext)
        except (InvalidTag, ValueError, binascii.Error) as exc:
            raise VaultRewindError("SECRET_DECRYPT_FAILED",
                                   "The encrypted secret failed authentication.") from exc
        kind, value = payload.get("t"), payload.get("v")
        if kind == "str" and isinstance(value, str) or kind == "dict" and isinstance(value, dict):
            return value
        raise VaultRewindError("SECRET_DECRYPT_FAILED", "The encrypted secret payload is malformed.")

    def needs_rotation(self, envelope: str) -> bool:
        return self.envelope_key_id(envelope) != self._current.key_id

    def rotate(self, envelope: str, *, context: str | None = None) -> str:
        """Re-encrypt with the current key. Historical repository passwords are unchanged."""
        if not self.needs_rotation(envelope):
            return envelope
        return self.encrypt(self.decrypt(envelope, context=context), context=context)


def generate_master_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def decode_master_key(material: bytes) -> bytes:
    """Accept 32 raw bytes, or base64/base64url/hex text encoding exactly 32 bytes."""
    if len(material) == KEY_BYTES:
        return _check_key(material)
    text = material.strip()
    if re.fullmatch(rb"[0-9a-fA-F]{64}", text):
        return _check_key(bytes.fromhex(text.decode()))
    if re.fullmatch(rb"[A-Za-z0-9+/_-]{43}=?", text):
        normalized = text.replace(b"+", b"-").replace(b"/", b"_").rstrip(b"=")
        return _check_key(base64.urlsafe_b64decode(normalized + b"="))
    raise VaultRewindError("MASTER_KEY_INVALID", "The controller master key file has an unsupported format.")


def write_master_key_file(path: Path) -> None:
    """Create a new owner-only key file; never overwrites an existing key."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise VaultRewindError("MASTER_KEY_EXISTS", "A controller master key already exists; it was not replaced.") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(_b64e(generate_master_key()).encode() + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def load_master_key_file(path: Path, *, require_private: bool = True) -> bytes:
    path = Path(path)
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise VaultRewindError("MASTER_KEY_INVALID", "The controller master key must be a regular file.")
        if require_private and info.st_mode & 0o037:
            raise VaultRewindError("MASTER_KEY_PERMISSIONS",
                                   "The controller master key file must not be writable by group or readable by others.")
        material = path.read_bytes()
    except OSError as exc:
        raise VaultRewindError("MASTER_KEY_UNAVAILABLE", "The controller master key file is unavailable.") from exc
    return decode_master_key(material)


def constant_time_equal(left: str | bytes, right: str | bytes) -> bool:
    left_bytes = left.encode() if isinstance(left, str) else left
    right_bytes = right.encode() if isinstance(right, str) else right
    return hmac.compare_digest(left_bytes, right_bytes)

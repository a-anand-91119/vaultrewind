"""Bounded JSON and framed binary transport. Never interpret request text as code."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
from dataclasses import dataclass
from typing import BinaryIO

from vaultrewind.core.errors import VaultRewindError

MAX_JSON = 1024 * 1024
MAX_FRAME = 1024 * 1024
MAGIC = b"VRW1\x00\r\n\x00"
VERBS = frozenset({"discover", "preflight", "capture", "export", "stage_restore",
                   "commit_restore", "rollback", "status", "cancel", "cleanup"})
HEX = re.compile(r"[0-9a-f]{64}\Z")


def fail(code: str, message: str):
    raise VaultRewindError(code, message)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("PROTOCOL_INVALID", "Duplicate JSON field.")
        result[key] = value
    return result


def decode(raw: bytes, limit=MAX_JSON):
    if len(raw) > limit:
        fail("PROTOCOL_LIMIT", "JSON limit exceeded.")
    try:
        obj = json.loads(raw, object_pairs_hook=unique_object,
                         parse_constant=lambda _: fail("PROTOCOL_INVALID", "Non-finite JSON number."))
        if not isinstance(obj, dict):
            raise TypeError()
        return obj
    except (ValueError, TypeError, UnicodeError, RecursionError):
        fail("PROTOCOL_INVALID", "Invalid JSON object.")


def identifier(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
        return value
    except (ValueError, AttributeError):
        fail("PROTOCOL_INVALID", "Canonical UUID required.")


@dataclass(frozen=True)
class Request:
    instance_id: str
    operation_id: str
    fencing_token: int
    idempotency_key: str
    verb: str
    payload: dict

    @classmethod
    def parse(cls, obj):
        if set(obj) != {"schema_version", "instance_id", "operation_id", "fencing_token",
                        "idempotency_key", "verb", "payload"} or obj["schema_version"] != 1:
            fail("PROTOCOL_VERSION", "Expected helper protocol version 1 and exact request fields.")
        token = obj["fencing_token"]
        key = obj["idempotency_key"]
        if type(token) is not int or not 1 <= token <= 2**63 - 1:
            fail("PROTOCOL_INVALID", "A positive fencing token is required.")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", key):
            fail("PROTOCOL_INVALID", "Invalid idempotency key.")
        if obj["verb"] not in VERBS or not isinstance(obj["payload"], dict):
            fail("PROTOCOL_INVALID", "Unsupported request verb or payload.")
        return cls(identifier(obj["instance_id"]), identifier(obj["operation_id"]), token,
                   key, obj["verb"], obj["payload"])

    def identity(self):
        return digest({"instance_id": self.instance_id, "operation_id": self.operation_id,
                       "verb": self.verb, "payload": self.payload})


def read_request(stream: BinaryIO):
    raw = stream.readline(MAX_JSON + 1)
    if not raw.endswith(b"\n"):
        fail("PROTOCOL_LIMIT", "Request must be one bounded JSON line.")
    return Request.parse(decode(raw))


def exact(stream: BinaryIO, size: int):
    chunks = []
    while size:
        data = stream.read(size)
        if not data:
            fail("TRANSFER_TRUNCATED", "Transfer ended before the declared size.")
        chunks.append(data)
        size -= len(data)
    return b"".join(chunks)


def send_frames(source: BinaryIO, target: BinaryIO, max_bytes: int):
    target.write(MAGIC)
    count = 0
    sha = hashlib.sha256()
    while chunk := source.read(MAX_FRAME):
        count += len(chunk)
        if count > max_bytes:
            fail("TRANSFER_LIMIT", "Archive exceeds the configured transfer limit.")
        sha.update(chunk)
        target.write(struct.pack("!I", len(chunk)))
        target.write(chunk)
    target.write(struct.pack("!I", 0))
    trailer = canonical({"bytes": count, "sha256": sha.hexdigest()})
    target.write(struct.pack("!I", len(trailer)))
    target.write(trailer)
    target.flush()
    return {"bytes": count, "sha256": sha.hexdigest()}


def receive_frames(source: BinaryIO, target: BinaryIO, max_bytes: int):
    if exact(source, len(MAGIC)) != MAGIC:
        fail("PROTOCOL_INVALID", "Invalid stream header.")
    count = 0
    sha = hashlib.sha256()
    while True:
        length = struct.unpack("!I", exact(source, 4))[0]
        if length == 0:
            break
        if length > MAX_FRAME or count + length > max_bytes:
            fail("TRANSFER_LIMIT", "Archive exceeds the configured frame or byte limit.")
        chunk = exact(source, length)
        target.write(chunk)
        sha.update(chunk)
        count += length
    length = struct.unpack("!I", exact(source, 4))[0]
    if length > 1024:
        fail("PROTOCOL_LIMIT", "Invalid stream trailer.")
    trailer = decode(exact(source, length), 1024)
    expected = {"bytes": count, "sha256": sha.hexdigest()}
    if trailer != expected:
        fail("TRANSFER_CHECKSUM", "Archive transport checksum mismatch.")
    return expected

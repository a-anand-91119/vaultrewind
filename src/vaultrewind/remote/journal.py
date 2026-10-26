"""Fsynced journals, physical locks, and monotonic resource fencing."""
from __future__ import annotations

import contextlib
import fcntl
import math
import os
import time
from pathlib import Path

from .protocol import canonical, decode, digest, fail

TERMINAL = {"complete", "cancelled", "rolled_back", "data_restored_service_stopped", "cleaned"}
POST_ACTIVATION = {"activation_started", "activated", "complete", "data_restored_service_stopped", "needs_attention"}


def fsync_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path: Path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            return decode(stream.read(16 * 1024 * 1024 + 1), 16 * 1024 * 1024)
    except FileNotFoundError:
        return None
    except Exception:  # noqa: BLE001 -- malformed recovery records must always fail closed.
        fail("JOURNAL_CORRUPT", "Recovery journal cannot be verified; preserve all generations and repair locally.")


class Journal:
    def __init__(self, root: Path, operation_id: str):
        self.root = root
        self.path = root / "journals" / (operation_id + ".json")
        self.value = read_json(self.path)

    def create(self, request, resource_keys, **fields):
        if self.value is not None:
            if self.value["instance_id"] != request.instance_id:
                fail("OPERATION_CONFLICT", "Operation identity belongs to another instance.")
            return
        self.value = {"schema_version": 1, "operation_id": request.operation_id,
                      "instance_id": request.instance_id, "fencing_token": request.fencing_token,
                      "resource_keys": resource_keys, "phase": "preparing", "requests": {},
                      "created_at": time.time(), "history": [], **fields}
        self.save()

    def save(self):
        atomic_json(self.path, self.value)

    def transition(self, phase, **fields):
        self.value.update(fields)
        self.value["phase"] = phase
        self.value["updated_at"] = time.time()
        self.value["history"].append({"phase": phase, "at": self.value["updated_at"]})
        self.save()

    def cached(self, request):
        if self.value is None:
            return None
        old = self.value["requests"].get(request.idempotency_key)
        if old:
            if old["hash"] != request.identity():
                fail("IDEMPOTENCY_CONFLICT", "Idempotency key was already used with different inputs.")
            return old.get("result")
        return None

    def reserve(self, request):
        old = self.value["requests"].get(request.idempotency_key)
        if old and old["hash"] != request.identity():
            fail("IDEMPOTENCY_CONFLICT", "Idempotency key was already used with different inputs.")
        if not old:
            self.value["requests"][request.idempotency_key] = {"hash": request.identity(), "result": None}
            self.save()

    def remember(self, request, result):
        self.value["requests"][request.idempotency_key] = {"hash": request.identity(), "result": result}
        self.save()

    def public(self):
        if self.value is None:
            return {"exists": False}
        allowed = {"operation_id", "instance_id", "fencing_token", "phase", "kind", "source_state",
                   "source_service_outcome", "snapshot_uuid", "manifest_hash", "safety_snapshot_uuid",
                   "safety_manifest_hash", "empty_target", "activation_started", "candidate_validated",
                   "error_code", "deadline", "active_generation", "bytes", "created_at", "updated_at",
                   "rollback_cleanup_after", "staging_cleaned", "generations_cleaned", "persistent_bytes",
                   "generation_logical_bytes", "retained_generation_logical_bytes", "candidate_cleanup_outcome",
                   "candidate_cleanup_remaining", "discarded_candidate_bytes",
                   "public_ports_verified", "public_endpoint_verified", "historical_public_readiness",
                   "historical_superseded_by", "historical_warning_code", "historical_status_reconciled"}
        return {"exists": True, **{k: v for k, v in self.value.items() if k in allowed}}

    def original_completion_at(self):
        """Original successful boundary, excluding later historical repair events."""
        value = self.value or {}
        if (value.get("kind") != "restore" or value.get("activation_started") is not True
                or value.get("watchdog_armed") is not False):
            return None
        history = value.get("history", [])
        if (not isinstance(history, list) or not history or any(not isinstance(item, dict) for item in history)
                or history[-1].get("phase") != value.get("phase")):
            return None
        completed = [(i, item.get("at")) for i, item in enumerate(history)
                     if item.get("phase") == "complete" and item.get("reason") != "historical_status_reconciled"]
        if not completed:
            return None
        index, timestamp = completed[-1]
        created = value.get("created_at")
        if (type(timestamp) not in (int, float) or not math.isfinite(timestamp)
                or type(created) not in (int, float) or not math.isfinite(created) or timestamp < created):
            return None
        if not any(item.get("phase") == "activation_started" for item in history[:index]):
            return None
        if any(item.get("phase") != "needs_attention" and item.get("reason") != "historical_status_reconciled"
               for item in history[index + 1:]):
            return None
        return timestamp

    def note_historical(self, *, successor=None, reconcile=False, original_sha256=None):
        """Preserve prior evidence/errors and append a distinct, fsynced audit event."""
        fields = {"historical_public_readiness": "unverified", "historical_warning_code": "PUBLIC_READINESS_UNVERIFIED",
                  "public_ports_verified": False, "public_endpoint_verified": False}
        if successor:
            fields["historical_superseded_by"] = successor
        if reconcile:
            fields.update(phase="complete", historical_status_reconciled=True)
            at = time.time()
            self.value["history"].append({"phase": "complete", "at": at, "reason": "historical_status_reconciled",
                                          "superseded_by": successor, "prior_error_code": self.value["error_code"],
                                          "prior_journal_sha256": original_sha256})
            fields["updated_at"] = at
        if any(self.value.get(key) != val for key, val in fields.items()):
            self.value.update(fields)
            self.save()
        return self.public()


def resource_keys(machine_id: str, daemon_id: str, mounts: list[dict]):
    keys = []
    for mount in mounts:
        path = Path(mount["source"])
        # Stable canonical paths coordinate duplicate registrations across bind renames.
        keys.append(digest({"machine": machine_id, "daemon": daemon_id, "path": str(path)}))
        if path.exists():
            s = path.stat()
            keys.append(digest({"machine": machine_id, "device": s.st_dev, "inode": s.st_ino}))
        if mount["type"] == "volume":
            keys.append(digest({"machine": machine_id, "daemon": daemon_id, "volume": mount["volume_name"]}))
    return sorted(set(keys))


class Locks:
    def __init__(self, root: Path, keys: list[str]):
        self.root = root
        self.keys = sorted(set(keys))
        self.stack = contextlib.ExitStack()

    def __enter__(self):
        (self.root / "locks").mkdir(exist_ok=True, mode=0o700)
        try:
            # Host-wide lock prevents changed or overlapping mount sets racing discovery.
            for key in ["host", *self.keys]:
                fd = os.open(self.root / "locks" / (key + ".lock"),
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                self.stack.callback(os.close, fd)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    fail("RESOURCE_BUSY", "A helper owns this physical resource; reconcile its journal.")
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *exc):
        self.stack.close()

    def fence(self, request, allow_reconcile=False):
        # A durable host reservation spans separated restore phases. This also covers
        # partially overlapping roots and bind aliases whose inode changed during rename.
        if not allow_reconcile:
            for path in (self.root / "journals").glob("*.json"):
                previous = read_json(path)
                if previous and previous["operation_id"] != request.operation_id and previous["phase"] not in TERMINAL | {"captured", "failed_safe"}:
                    fail("RECONCILIATION_REQUIRED", "Reconcile the previous host operation before admitting another mutating job.")
        records = []
        for key in self.keys:
            path = self.root / "fences" / (key + ".json")
            old = read_json(path)
            if old:
                if request.fencing_token < old["token"]:
                    fail("STALE_FENCE", "This worker's resource lease is stale.")
                if old["operation_id"] != request.operation_id:
                    old_journal = Journal(self.root, old["operation_id"]).value
                    if old_journal is None or old_journal["phase"] not in TERMINAL | {"captured", "failed_safe"}:
                        fail("RECONCILIATION_REQUIRED", "Reconcile the previous physical-resource operation first.")
                    if request.fencing_token <= old["token"]:
                        fail("STALE_FENCE", "A new operation requires a higher resource fencing token.")
            records.append((path, {"token": request.fencing_token, "operation_id": request.operation_id}))
        if not allow_reconcile:
            for path, value in records:
                atomic_json(path, value)

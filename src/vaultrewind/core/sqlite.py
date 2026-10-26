"""SQLite operates exclusively on private staged copies, never source paths."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .errors import VaultRewindError
from .manifest import canonical_json, logical_path


def _open(path: Path):
    if path.is_symlink() or not path.is_file():
        raise VaultRewindError("DATABASE_UNAVAILABLE", "The staged SQLite database is missing or unsafe.")
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30)


def _required_file(data_root: Path, relative: str):
    path = data_root / str(logical_path(relative))
    if not path.resolve().is_relative_to(data_root.resolve()) or not path.is_file():
        raise VaultRewindError("SNAPSHOT_INCOMPLETE", "A database-referenced attachment or Send file is absent.")


def validate_sqlite(data_root: Path) -> dict:
    path = data_root.resolve() / "db.sqlite3"
    try:
        with _open(path) as connection:
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise VaultRewindError("DATABASE_INTEGRITY_FAILED", "SQLite integrity verification failed.")
            schema = connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            tables = {row[0] for row in schema}
            if not {"users", "ciphers"}.issubset(tables):
                raise VaultRewindError("UNSUPPORTED_SCHEMA", "The staged database is not a supported Vaultwarden schema.")
            if "attachments" in tables:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(attachments)")}
                if not {"id", "cipher_uuid"}.issubset(columns):
                    raise VaultRewindError("UNSUPPORTED_SCHEMA", "Attachment schema cannot be verified safely.")
                for attachment_id, cipher_uuid in connection.execute("SELECT id,cipher_uuid FROM attachments"):
                    _required_file(data_root, f"attachments/{cipher_uuid}/{attachment_id}")
            if "sends" in tables:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(sends)")}
                if not {"uuid", "atype", "data", "deletion_date"}.issubset(columns):
                    raise VaultRewindError("UNSUPPORTED_SCHEMA", "Send schema cannot be verified safely.")
                now = datetime.now(UTC)
                for send_id, data, deleted in connection.execute("SELECT uuid,data,deletion_date FROM sends WHERE atype=1"):
                    # Vaultwarden removes Send files when deletion_date passes; expired orphan bytes are retained.
                    deadline = datetime.fromisoformat(deleted) if deleted else None
                    if deadline and deadline.replace(tzinfo=deadline.tzinfo or UTC) <= now:
                        continue
                    content = json.loads(data)
                    file_id = content.get("Id") or content.get("id")
                    if not file_id:
                        raise VaultRewindError("UNSUPPORTED_SCHEMA", "A file Send has unrecognized metadata.")
                    _required_file(data_root, f"sends/{send_id}/{file_id}")
            return {"database_integrity": "ok", "database_schema_evidence": {
                "schema_sha256": hashlib.sha256(canonical_json(schema)).hexdigest(),
                "sqlite_version": sqlite3.sqlite_version,
                "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
                "tables": sorted(tables)}, "attachment_references_verified": True}
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise VaultRewindError("DATABASE_VALIDATION_FAILED", "The staged database could not be validated.") from exc


def normalize_sqlite(data_root: Path) -> dict:
    path = data_root.resolve() / "db.sqlite3"
    normalized = path.with_name(".db.sqlite3.normalized")
    if normalized.exists():
        raise VaultRewindError("STAGING_CONFLICT", "SQLite normalization staging already exists.")
    try:
        original = path.stat()
        with _open(path) as source, sqlite3.connect(normalized) as target:
            source.backup(target)
            target.execute("PRAGMA journal_mode=DELETE")
            if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise VaultRewindError("DATABASE_INTEGRITY_FAILED", "Normalized SQLite integrity verification failed.")
        os.chmod(normalized, original.st_mode & 0o777)
        for name in os.listxattr(path):
            os.setxattr(normalized, name, os.getxattr(path, name))
        if os.geteuid() == 0:
            os.chown(normalized, original.st_uid, original.st_gid)
        with normalized.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(normalized, path)
        for suffix in ("-wal", "-shm"):
            path.with_name(path.name + suffix).unlink(missing_ok=True)
        return {**validate_sqlite(data_root), "normalization_method": "sqlite3_backup_api", "wal_incorporated": True}
    except (OSError, sqlite3.Error) as exc:
        raise VaultRewindError("DATABASE_NORMALIZATION_FAILED", "The private staged database could not be normalized.") from exc
    finally:
        normalized.unlink(missing_ok=True)

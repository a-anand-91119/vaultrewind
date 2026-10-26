"""Complete, encrypted backup and offline validation of VaultRewind controller metadata."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time as time_module
import uuid
from datetime import UTC, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psycopg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from psycopg.types.json import Json
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import ensure_private_directory, scrub_tree, write_private_file
from vaultrewind.security.secrets import SecretBox
from vaultrewind.storage import layout, providers
from vaultrewind.storage.controller import (
    canonical_json,
    commit_controller_snapshot,
    file_inventory,
    repository_lock,
    restore_controller_snapshot,
)

from .db import now
from .models import (
    ControllerBackup,
    ControllerBackupPolicy,
    ControllerState,
    Repository,
    ResourceLease,
    Secret,
    StagingAllocation,
    StorageDestination,
)
from .queue import ensure_resource
from .secrets import Secrets

_FORMAT = "vaultrewind-controller-backup"
_SCHEMA = 1
_CATALOG_FORMAT = "vaultrewind-controller-catalog"
_CATALOG_SCHEMA = 1
_CATALOG_CHUNK_BYTES = 4 * 1024 * 1024
_SAFE_ID = re.compile(r"^[0-9a-f]{64}$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_hash(value: dict) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _aware(value: datetime | None = None) -> datetime:
    value = value or now()
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _next_daily(current: datetime, daily_time: str, timezone: str) -> datetime:
    try:
        zone = ZoneInfo(timezone)
        hour, minute = (int(part) for part in daily_time.split(":"))
        if not 0 <= hour <= 23 or not 0 <= minute <= 59:
            raise ValueError()
    except (ValueError, TypeError, ZoneInfoNotFoundError) as exc:
        raise VaultRewindError(
            "CONTROLLER_BACKUP_POLICY_INVALID", "The controller backup schedule is invalid."
        ) from exc
    local = _aware(current).astimezone(zone)
    candidate = datetime.combine(local.date(), time(hour, minute), zone)
    if candidate <= local:
        candidate = datetime.combine(local.date() + timedelta(days=1), time(hour, minute), zone)
    return candidate.astimezone(UTC)


def configure_policy(
    db,
    destination_id: str,
    *,
    enabled: bool = True,
    schedule_kind: str = "daily",
    timezone: str = "UTC",
    daily_time: str = "02:00",
) -> ControllerBackupPolicy:
    """Select a durable destination and daily schedule; repository setup happens in the worker."""
    destination = db.get(StorageDestination, destination_id)
    if not destination or destination.archived:
        raise VaultRewindError(
            "STORAGE_NOT_CONFIGURED", "Choose an active storage destination for controller backups."
        )
    if schedule_kind != "daily":
        raise VaultRewindError(
            "CONTROLLER_BACKUP_POLICY_INVALID", "Controller metadata backups support a daily schedule."
        )
    candidate = _next_daily(now(), daily_time, timezone)
    upcoming = candidate if enabled else None
    row = db.scalar(select(ControllerBackupPolicy).where(ControllerBackupPolicy.id == 1).with_for_update())
    if row is None:
        row = ControllerBackupPolicy(
            id=1,
            destination_id=destination_id,
            enabled=enabled,
            schedule_kind=schedule_kind,
            timezone=timezone,
            daily_time=daily_time,
            next_run_at=upcoming,
            revision=1,
        )
        db.add(row)
    else:
        row.destination_id, row.enabled = destination_id, enabled
        row.schedule_kind, row.timezone, row.daily_time = schedule_kind, timezone, daily_time
        row.next_run_at, row.revision = upcoming, row.revision + 1
    db.flush()
    return row


def schedule_due(db, current: datetime | None = None) -> dict | None:
    """Claim one due policy occurrence; caller enqueues it in the same transaction."""
    current = _aware(current)
    row = db.scalar(
        select(ControllerBackupPolicy).where(ControllerBackupPolicy.id == 1).with_for_update(skip_locked=True)
    )
    if not row or not row.enabled or not row.next_run_at or _aware(row.next_run_at) > current:
        return None
    due = _aware(row.next_run_at)
    row.next_run_at = _next_daily(current, row.daily_time, row.timezone)
    return {
        "policy_id": row.id,
        "revision": row.revision,
        "destination_id": row.destination_id,
        "scheduled_at": due.isoformat(),
        "next_run_at": row.next_run_at.isoformat(),
    }


def public_status(db, max_age_days: int = 7) -> dict:
    """Return safe controller-backup status without ORM serialization or credential fields."""
    policy = db.get(ControllerBackupPolicy, 1)
    latest = db.scalar(
        select(ControllerBackup)
        .where(ControllerBackup.state == "complete")
        .order_by(ControllerBackup.captured_at.desc())
        .limit(1)
    )
    attempt = db.scalar(select(ControllerBackup).order_by(ControllerBackup.created_at.desc()).limit(1))
    age_limit = timedelta(days=max_age_days)
    age = _aware() - _aware(latest.captured_at) if latest else None
    return {
        "configured": policy is not None,
        "enabled": bool(policy.enabled) if policy else False,
        "destination_id": policy.destination_id if policy else None,
        "schedule_kind": policy.schedule_kind if policy else None,
        "timezone": policy.timezone if policy else None,
        "daily_time": policy.daily_time if policy else None,
        "next_run_at": _aware(policy.next_run_at).isoformat() if policy and policy.next_run_at else None,
        "last_backup_id": latest.id if latest else None,
        "last_captured_at": _aware(latest.captured_at).isoformat() if latest else None,
        "last_attempt_id": attempt.id if attempt else None,
        "last_state": attempt.state if attempt else None,
        "last_error_code": attempt.error_code if attempt else None,
        "last_bytes": latest.bytes if latest else None,
        "last_pg_dump_included": latest.pg_dump_included if latest else False,
        "stale": age is None or age > age_limit,
        "max_age_days": max_age_days,
    }


def list_status(db) -> list[dict]:
    return [
        {
            "id": row.id,
            "job_id": row.job_id,
            "destination_id": row.destination_id,
            "repository_id": row.repository_id,
            "snapshot_uuid": row.snapshot_uuid,
            "restic_snapshot_id": row.restic_snapshot_id,
            "manifest_hash": row.manifest_hash,
            "captured_at": _aware(row.captured_at).isoformat(),
            "state": row.state,
            "alembic_version": row.alembic_version,
            "tables": row.tables,
            "rows": row.rows,
            "bytes": row.bytes,
            "pg_dump_included": row.pg_dump_included,
            "error_code": row.error_code,
        }
        for row in db.scalars(select(ControllerBackup).order_by(ControllerBackup.captured_at.desc()))
    ]


def _controller_identity(db) -> str:
    state = db.scalar(select(ControllerState).where(ControllerState.id == 1).with_for_update())
    if state is None:
        state = ControllerState(id=1, controller_id=str(uuid.uuid4()))
        db.add(state)
    elif not state.controller_id:
        state.controller_id = str(uuid.uuid4())
    db.flush()
    return str(uuid.UUID(state.controller_id))


def _reserve_staging(ctx, quota_bytes: int) -> None:
    """Reserve only the controller-specific bound, not the larger generic instance-job quota."""
    settings = ctx.settings
    root = settings.staging_dir
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_mode & 0o077:
        raise VaultRewindError("STAGING_UNSAFE", "Controller backup staging requires a private directory.")
    ctx.guard()
    with ctx.sessions.begin() as db:
        ensure_resource(db, "controller:quota")
        db.scalar(
            select(ResourceLease).where(ResourceLease.resource_key == "controller:quota").with_for_update()
        )
        allocation = db.scalar(
            select(StagingAllocation).where(StagingAllocation.job_id == ctx.id).with_for_update()
        )
        if allocation is None:
            used = int(
                db.scalar(
                    select(func.coalesce(func.sum(StagingAllocation.reserved_bytes), 0)).where(
                        StagingAllocation.state != "released"
                    )
                )
                or 0
            )
            actual = int(
                db.scalar(
                    select(func.coalesce(func.sum(StagingAllocation.actual_bytes), 0)).where(
                        StagingAllocation.state != "released"
                    )
                )
                or 0
            )
            outstanding = max(0, used - actual)
            if used + quota_bytes > settings.staging_quota_bytes:
                raise VaultRewindError(
                    "INSUFFICIENT_SPACE", "The global controller staging quota is exhausted."
                )
            if shutil.disk_usage(root).free < outstanding + quota_bytes + settings.min_free_bytes:
                raise VaultRewindError(
                    "INSUFFICIENT_SPACE", "The controller backup staging reserve is insufficient."
                )
            db.add(StagingAllocation(job_id=ctx.id, reserved_bytes=quota_bytes, actual_bytes=0))
    ctx.root.mkdir(mode=0o700, exist_ok=True)
    if ctx.root.is_symlink():
        raise VaultRewindError("STAGING_UNSAFE", "The controller backup staging directory is unsafe.")
    os.chmod(ctx.root, 0o700)


def _controller_repository_work_dir(ctx, settings) -> Path:
    """Keep restic caches and temporary credentials in private state, outside job staging."""
    job_root = Path(ctx.root)
    capture_root = job_root / "controller-backup"
    state_root = ensure_private_directory(Path(settings.staging_dir).parent / "cache" / "controller-backup")
    work_root = ensure_private_directory(state_root / str(ctx.id))
    try:
        work_root.resolve().relative_to(capture_root.resolve())
    except ValueError:
        pass
    else:
        raise VaultRewindError(
            "STAGING_UNSAFE", "Controller repository scratch space overlaps the captured database backup."
        )
    try:
        work_root.resolve().relative_to(Path(settings.staging_dir).resolve())
    except ValueError:
        return work_root
    raise VaultRewindError(
        "STAGING_UNSAFE", "Controller repository scratch space overlaps disposable job staging."
    )


def _repository(db, store: Secrets, settings, controller_id: str, destination_id: str):
    destination = db.scalar(
        select(StorageDestination).where(StorageDestination.id == destination_id).with_for_update()
    )
    if not destination or destination.archived:
        raise VaultRewindError(
            "STORAGE_NOT_CONFIGURED", "The selected controller backup destination is unavailable."
        )
    config = store.get(db, destination.configuration_secret_id)
    if destination.backend == "local" and not Path(config.get("path", "")).is_relative_to(
        settings.local_storage_root
    ):
        raise VaultRewindError(
            "STORAGE_PATH_UNSAFE", "Controller backups must use the configured persistent storage mount."
        )
    repo = db.scalar(
        select(Repository)
        .where(Repository.purpose == "controller", Repository.destination_id == destination.id)
        .with_for_update()
    )
    root_secret = None
    from .services import recovery_root

    root_secret = recovery_root(db, store)
    password = layout.derive_repository_password(root_secret, controller_id, destination.id)
    if repo is None:
        repo_id = str(uuid.uuid4())
        location = providers.repository_location(destination.backend, config, controller_id, destination.id)
        private = {
            "location": location,
            "controller_id": controller_id,
            "backend": destination.backend,
            "destination_id": destination.id,
            "destination_configuration": config,
        }
        config_id = store.put(db, "repository_configuration", repo_id, private)
        key_id = store.put(db, "repository_key", repo_id, password)
        repo = Repository(
            id=repo_id,
            instance_id=None,
            destination_id=destination.id,
            configuration_secret_id=config_id,
            key_id=key_id,
            physical_identity=providers.physical_identity(
                destination.backend, config, controller_id, destination.id
            ),
            purpose="controller",
        )
        db.add(repo)
        db.flush()
    else:
        private = store.get(db, repo.configuration_secret_id)
        if private.get("controller_id", controller_id) != controller_id:
            raise VaultRewindError("CONTROLLER_REPOSITORY_IMPORT_REVIEW", "This imported repository belongs to a different controller; select a new destination for new controller backups.")
        if private.get("destination_id") != destination.id or private.get("backend") != destination.backend:
            raise VaultRewindError(
                "REPOSITORY_IDENTITY_MISMATCH",
                "The controller repository does not match its selected destination.",
            )
        stored_password = store.get(db, repo.key_id)
        if stored_password != password:
            # A user-rotated key remains authoritative. It is never overwritten by derivation.
            password = stored_password
    credential = store.get(db, destination.credential_id) if destination.credential_id else None
    return destination, repo, private, credential, password, root_secret


def _pg_service(database_url: str, directory: Path) -> tuple[Path, dict[str, str], dict[str, Any]]:
    try:
        url = make_url(database_url)
    except Exception as exc:
        raise VaultRewindError(
            "CONTROLLER_DATABASE_CONFIGURATION", "The controller PostgreSQL URL is invalid."
        ) from exc
    if url.get_backend_name() != "postgresql":
        raise VaultRewindError(
            "CONTROLLER_DATABASE_UNSUPPORTED", "Controller metadata backup requires PostgreSQL."
        )
    driver = {
        "host": url.host,
        "port": url.port,
        "dbname": url.database,
        "user": url.username,
        "password": url.password,
    }
    pgpass = directory / f"pgpass-{uuid.uuid4().hex}"

    def escaped(value):
        return str(value or "").replace("\\", "\\\\").replace(":", "\\:").replace("\n", "")

    host = url.host or "*"
    port = url.port or "*"
    dbname = url.database or "*"
    username = url.username or "*"
    write_private_file(
        pgpass, ":".join(escaped(item) for item in (host, port, dbname, username, url.password or "")) + "\n"
    )
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(directory),
        "TZ": "UTC",
        "PGPASSFILE": str(pgpass),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    libpq_env = {
        "sslmode": "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "sslcert": "PGSSLCERT",
        "sslkey": "PGSSLKEY",
        "application_name": "PGAPPNAME",
        "connect_timeout": "PGCONNECT_TIMEOUT",
    }
    for key, env_name in libpq_env.items():
        value = url.query.get(key)
        if value is not None:
            env[env_name] = str(value)
    return pgpass, env, driver


def _connect_args(database_url: str) -> dict[str, Any]:
    url = make_url(database_url)
    args: dict[str, Any] = {
        "dbname": url.database,
        "user": url.username,
        "password": url.password,
        "host": url.host,
        "port": url.port,
    }
    for key in ("sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "connect_timeout"):
        if key in url.query:
            args[key] = url.query[key]
    return {key: value for key, value in args.items() if value is not None}


def _json_value(value):
    if isinstance(value, datetime):
        return {"$type": "datetime", "value": value.isoformat()}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"$type": "bytes", "value": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, Decimal):
        return {"$type": "decimal", "value": str(value)}
    if value.__class__.__name__ == "date" or value.__class__.__name__ == "time":
        return {"$type": value.__class__.__name__, "value": value.isoformat()}
    if isinstance(value, uuid.UUID):
        return {"$type": "uuid", "value": str(value)}
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "total_seconds"):
        return {"$type": "interval_seconds", "value": value.total_seconds()}
    raise VaultRewindError(
        "CONTROLLER_CATALOG_VALUE_UNSUPPORTED", "A PostgreSQL catalog value has an unsupported type."
    )


def _alembic_version(cursor) -> str | None:
    cursor.execute("SELECT to_regclass('public.alembic_version')")
    if cursor.fetchone()[0] is None:
        return None
    cursor.execute("SELECT version_num FROM public.alembic_version ORDER BY version_num")
    values = [str(row[0]) for row in cursor.fetchall()]
    return ",".join(values) if values else None


def _export_catalog(
    connection, output: Path, *, controller_id: str, captured_at: datetime, snapshot_id: str, max_bytes: int
) -> tuple[dict, int, int, str]:
    from psycopg import sql

    cursor = connection.cursor()
    cursor.execute("SELECT current_setting('server_version_num')::integer")
    server_version = int(cursor.fetchone()[0])
    alembic = _alembic_version(cursor)
    cursor.execute("""SELECT table_schema, table_name FROM information_schema.tables
                     WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema')
                     ORDER BY table_schema, table_name""")
    table_names = cursor.fetchall()
    total_rows = 0
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)

        def write(value):
            data = value.encode("utf-8") if isinstance(value, str) else value
            handle.write(data)
            if handle.tell() > max_bytes:
                raise VaultRewindError(
                    "CONTROLLER_BACKUP_TOO_LARGE", "The controller catalog exceeds its configured size limit."
                )

        write(b'{"format":"vaultrewind-controller-catalog","schema_version":1,')
        write(
            b'"controller_uuid":'
            + canonical_json(controller_id)
            + b',"snapshot_uuid":'
            + canonical_json(snapshot_id)
        )
        write(b',"captured_at":' + canonical_json(captured_at.isoformat().replace("+00:00", "Z")))
        write(
            b',"database":{"server_version_num":'
            + str(server_version).encode()
            + b',"alembic_version":'
            + canonical_json(alembic)
            + b'},"tables":['
        )
        for table_index, (schema, table) in enumerate(table_names):
            if table_index:
                write(b",")
            ident = sql.Identifier(schema, table)
            cursor.execute(
                sql.SQL(
                    "SELECT column_name, data_type, udt_name, is_nullable, ordinal_position "
                    "FROM information_schema.columns WHERE table_schema=%s AND table_name=%s "
                    "ORDER BY ordinal_position"
                ),
                (schema, table),
            )
            columns = cursor.fetchall()
            column_data = [
                {
                    "name": row[0],
                    "data_type": row[1],
                    "udt_name": row[2],
                    "nullable": row[3] == "YES",
                    "ordinal": int(row[4]),
                }
                for row in columns
            ]
            write(
                b'{"schema":'
                + canonical_json(schema)
                + b',"name":'
                + canonical_json(table)
                + b',"columns":'
                + canonical_json(column_data)
                + b',"rows":['
            )
            row_count = 0
            with connection.cursor(name=f"controller_catalog_{table_index}") as table_cursor:
                table_cursor.itersize = 500
                table_cursor.execute(sql.SQL("SELECT * FROM {}").format(ident))
                first = True
                for record in table_cursor:
                    if not first:
                        write(b",")
                    first = False
                    write(canonical_json([_json_value(item) for item in record]))
                    row_count += 1
            total_rows += row_count
            write(b'],"row_count":' + str(row_count).encode() + b"}")
        write(b"]}")
        handle.flush()
        os.fsync(handle.fileno())
    digest = hashlib.sha256()
    with output.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return (
        {
            "tables": len(table_names),
            "rows": total_rows,
            "alembic_version": alembic,
            "server_version_num": server_version,
        },
        len(table_names),
        total_rows,
        digest.hexdigest(),
    )


def _pg_dump(database_url: str, directory: Path, dump_path: Path, snapshot_token: str, max_bytes: int) -> int:
    pgpass, env, driver = _pg_service(database_url, directory)
    pg_dump = shutil.which("pg_dump", path=env["PATH"])
    if not pg_dump:
        pgpass.unlink(missing_ok=True)
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_UNAVAILABLE", "The PostgreSQL dump utility is not installed."
        )
    command = [
        pg_dump,
        "--no-password",
        "--format=custom",
        "--no-owner",
        "--no-acl",
        f"--snapshot={snapshot_token}",
        f"--file={dump_path}",
    ]
    for flag, value in (
        ("--host", driver["host"]),
        ("--port", driver["port"]),
        ("--username", driver["user"]),
        ("--dbname", driver["dbname"]),
    ):
        if value is not None:
            command.extend((flag, str(value)))
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
        deadline = time_module.monotonic() + 3600
        while process.poll() is None:
            if dump_path.exists() and dump_path.stat().st_size > max_bytes:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                dump_path.unlink(missing_ok=True)
                raise VaultRewindError(
                    "CONTROLLER_BACKUP_TOO_LARGE",
                    "The controller PostgreSQL dump exceeds its configured size limit.",
                )
            if time_module.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                dump_path.unlink(missing_ok=True)
                raise VaultRewindError("CONTROLLER_PG_DUMP_FAILED", "pg_dump exceeded its time limit.")
            time_module.sleep(0.1)
        result_code = process.returncode
    except VaultRewindError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_FAILED", "The PostgreSQL dump could not be completed."
        ) from exc
    finally:
        pgpass.unlink(missing_ok=True)
    if result_code != 0 or not dump_path.is_file() or dump_path.stat().st_size == 0:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_FAILED", "pg_dump did not produce a complete database archive."
        )
    size = dump_path.stat().st_size
    if size > max_bytes:
        raise VaultRewindError(
            "CONTROLLER_BACKUP_TOO_LARGE", "The controller PostgreSQL dump exceeds the configured size limit."
        )
    pg_restore = shutil.which("pg_restore", path=env["PATH"])
    if not pg_restore:
        raise VaultRewindError(
            "CONTROLLER_PG_RESTORE_UNAVAILABLE", "The PostgreSQL restore utility is not installed."
        )
    try:
        check = subprocess.run(
            [pg_restore, "--list", str(dump_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_INVALID", "The PostgreSQL dump archive could not be inspected."
        ) from exc
    if check.returncode != 0:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_INVALID", "The PostgreSQL dump archive failed its structural check."
        )
    return size


def _postgres_tool_version(binary_name: str) -> str:
    binary = shutil.which(binary_name, path="/usr/local/bin:/usr/bin:/bin")
    if not binary:
        raise VaultRewindError(
            "CONTROLLER_PG_TOOL_UNAVAILABLE", "A required PostgreSQL client utility is not installed."
        )
    try:
        result = subprocess.run(
            [binary, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "TZ": "UTC"},
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VaultRewindError(
            "CONTROLLER_PG_TOOL_UNAVAILABLE", "A PostgreSQL client utility could not be inspected."
        ) from exc
    match = (
        re.search(rb"PostgreSQL\)\s+([0-9]+(?:\.[0-9]+){1,2})", result.stdout)
        if result.returncode == 0
        else None
    )
    if not match:
        raise VaultRewindError(
            "CONTROLLER_PG_TOOL_UNAVAILABLE", "A PostgreSQL client utility version is unsupported."
        )
    return match.group(1).decode("ascii")


def _catalog_key(root_secret: str, controller_id: str, physical_identity: str) -> SecretBox:
    try:
        material = base64.urlsafe_b64decode(root_secret + "=" * (-len(root_secret) % 4))
    except (ValueError, TypeError) as exc:
        raise VaultRewindError("RECOVERY_ROOT_INVALID", "The controller recovery root is invalid.") from exc
    if len(material) != 32:
        raise VaultRewindError("RECOVERY_ROOT_INVALID", "The controller recovery root is invalid.")
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(b"vaultrewind-controller-catalog-v1" + controller_id.encode()).digest(),
        info=f"controller-catalog|{controller_id}|{physical_identity}".encode(),
    ).derive(material)
    return SecretBox(key)


def _seal_catalog(
    plaintext: Path,
    root: Path,
    *,
    root_secret: str,
    controller_id: str,
    physical_identity: str,
    snapshot_id: str,
    max_bytes: int,
) -> dict:
    box = _catalog_key(root_secret, controller_id, physical_identity)
    catalog_dir = root / "catalog.sealed"
    catalog_dir.mkdir(mode=0o700)
    digest = hashlib.sha256()
    length = 0
    chunks = []
    with plaintext.open("rb") as source:
        index = 0
        while block := source.read(_CATALOG_CHUNK_BYTES):
            length += len(block)
            digest.update(block)
            envelope = box.encrypt(
                base64.b64encode(block).decode("ascii"),
                context=f"controller-catalog:{controller_id}:{physical_identity}:{snapshot_id}:chunk:{index}",
            )
            name = f"{index:08d}.sealed"
            write_private_file(catalog_dir / name, envelope)
            chunks.append(
                {
                    "name": name,
                    "sealed_sha256": hashlib.sha256(envelope.encode()).hexdigest(),
                    "plain_bytes": len(block),
                }
            )
            index += 1
            if sum(item["plain_bytes"] for item in chunks) > max_bytes:
                raise VaultRewindError(
                    "CONTROLLER_BACKUP_TOO_LARGE", "The controller catalog exceeds its configured size limit."
                )
    description = {
        "format": _CATALOG_FORMAT,
        "schema_version": _CATALOG_SCHEMA,
        "controller_uuid": controller_id,
        "repository_identity": physical_identity,
        "snapshot_uuid": snapshot_id,
        "plaintext_sha256": digest.hexdigest(),
        "plaintext_bytes": length,
        "chunks": chunks,
    }
    descriptor = box.encrypt(
        description,
        context=f"controller-catalog:{controller_id}:{physical_identity}:{snapshot_id}:descriptor",
    )
    write_private_file(root / "catalog.sealed.json", descriptor)
    plaintext.unlink()
    return description


def decrypt_catalog(
    staging_root: Path,
    *,
    recovery_root_secret: str,
    controller_id: str,
    repository_identity: str,
    snapshot_uuid: str,
    output_path: Path | None = None,
) -> dict:
    """Authenticate and decrypt the sealed JSON catalog without PostgreSQL or the controller master key."""
    staging_root, controller_id = Path(staging_root), str(uuid.UUID(controller_id))
    if not _SAFE_ID.fullmatch(repository_identity):
        raise VaultRewindError(
            "CONTROLLER_BACKUP_FORMAT_INVALID", "The controller repository identity is invalid."
        )
    box = _catalog_key(recovery_root_secret, controller_id, repository_identity)
    try:
        envelope = (staging_root / "catalog.sealed.json").read_text("ascii")
        descriptor = box.decrypt(
            envelope,
            context=f"controller-catalog:{controller_id}:{repository_identity}:{snapshot_uuid}:descriptor",
        )
    except (OSError, UnicodeError, VaultRewindError) as exc:
        raise VaultRewindError(
            "CONTROLLER_CATALOG_AUTH_FAILED",
            "The independently sealed controller catalog could not be authenticated.",
        ) from exc
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("format") != _CATALOG_FORMAT
        or descriptor.get("schema_version") != _CATALOG_SCHEMA
        or descriptor.get("controller_uuid") != controller_id
        or descriptor.get("repository_identity") != repository_identity
        or descriptor.get("snapshot_uuid") != snapshot_uuid
    ):
        raise VaultRewindError(
            "CONTROLLER_CATALOG_FORMAT_INVALID", "The sealed controller catalog descriptor is incompatible."
        )
    target = Path(output_path) if output_path else staging_root / "catalog.decrypted.json"
    ensure_private_directory(target.parent)
    digest, size = hashlib.sha256(), 0
    try:
        with target.open("xb") as out:
            os.fchmod(out.fileno(), 0o600)
            for index, chunk in enumerate(descriptor.get("chunks", [])):
                name = chunk.get("name")
                if name != f"{index:08d}.sealed":
                    raise ValueError("chunk sequence")
                sealed = (staging_root / "catalog.sealed" / name).read_text("ascii")
                if hashlib.sha256(sealed.encode()).hexdigest() != chunk.get("sealed_sha256"):
                    raise ValueError("chunk digest")
                encoded = box.decrypt(
                    sealed,
                    context=f"controller-catalog:{controller_id}:{repository_identity}:{snapshot_uuid}:chunk:{index}",
                )
                block = base64.b64decode(encoded, validate=True)
                if len(block) != chunk.get("plain_bytes"):
                    raise ValueError("chunk size")
                out.write(block)
                digest.update(block)
                size += len(block)
            out.flush()
            os.fsync(out.fileno())
    except (OSError, ValueError, VaultRewindError) as exc:
        with contextlib.suppress(FileNotFoundError):
            target.unlink()
        raise VaultRewindError(
            "CONTROLLER_CATALOG_AUTH_FAILED",
            "The independently sealed controller catalog failed authentication.",
        ) from exc
    if digest.hexdigest() != descriptor.get("plaintext_sha256") or size != descriptor.get("plaintext_bytes"):
        target.unlink(missing_ok=True)
        raise VaultRewindError(
            "CONTROLLER_CATALOG_AUTH_FAILED",
            "The independently sealed controller catalog failed its digest check.",
        )
    try:
        data = json.loads(target.read_bytes())
    except (OSError, ValueError) as exc:
        target.unlink(missing_ok=True)
        raise VaultRewindError(
            "CONTROLLER_CATALOG_FORMAT_INVALID", "The decrypted controller catalog is malformed."
        ) from exc
    if data.get("format") != _CATALOG_FORMAT or data.get("schema_version") != _CATALOG_SCHEMA:
        target.unlink(missing_ok=True)
        raise VaultRewindError(
            "CONTROLLER_CATALOG_VERSION_UNSUPPORTED", "The controller catalog schema is unsupported."
        )
    return {
        "path": target,
        "catalog": data,
        "sha256": digest.hexdigest(),
        "bytes": size,
        "tables": len(data.get("tables", [])),
        "rows": sum(item.get("row_count", 0) for item in data.get("tables", [])),
    }


def _capture_postgres(
    database_url: str,
    directory: Path,
    *,
    controller_id: str,
    captured_at: datetime,
    snapshot_uuid: str,
    max_bytes: int,
) -> tuple[dict, int, int, int, str]:
    dump_path, catalog_path = directory / "database.dump", directory / "catalog.plain.json"
    conn = _connect_args(database_url)
    try:
        with psycopg.connect(**conn) as connection:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            snapshot_token = connection.execute("SELECT pg_export_snapshot()").fetchone()[0]
            catalog_info, table_count, row_count, catalog_hash = _export_catalog(
                connection,
                catalog_path,
                controller_id=controller_id,
                captured_at=captured_at,
                snapshot_id=snapshot_uuid,
                max_bytes=max_bytes,
            )
            dump_size = _pg_dump(database_url, directory, dump_path, snapshot_token, max_bytes)
            catalog_info["pg_dump_version"] = _postgres_tool_version("pg_dump")
            catalog_info["pg_restore_version"] = _postgres_tool_version("pg_restore")
            connection.commit()
    except VaultRewindError:
        raise
    except Exception as exc:  # psycopg errors can contain connection details; never persist them
        raise VaultRewindError(
            "CONTROLLER_DATABASE_CAPTURE_FAILED",
            "A consistent PostgreSQL catalog snapshot could not be read.",
        ) from exc
    if dump_size + catalog_path.stat().st_size > max_bytes:
        raise VaultRewindError(
            "CONTROLLER_BACKUP_TOO_LARGE", "The PostgreSQL dump and catalog exceed the configured size limit."
        )
    return catalog_info, table_count, row_count, dump_size, catalog_hash


def _verify_committed_content(
    root: Path,
    manifest: dict,
    *,
    controller_id: str,
    destination_id: str,
    repository_identity: str,
    recovery_root_secret: str,
) -> None:
    """Check PostgreSQL archive and independent catalog inside the exact restic readback tree."""
    if (
        manifest.get("controller_uuid") != controller_id
        or manifest.get("destination_id") != destination_id
        or manifest.get("repository_identity") != repository_identity
    ):
        raise VaultRewindError(
            "REPOSITORY_OWNERSHIP_MISMATCH", "The stored controller snapshot belongs to another repository."
        )
    dump_path = root / "database.dump"
    pg_dump = manifest.get("pg_dump") or {}
    if dump_path.stat().st_size != pg_dump.get("bytes") or _sha256_file(dump_path) != pg_dump.get("sha256"):
        raise VaultRewindError(
            "CONTROLLER_BACKUP_READBACK_FAILED", "The PostgreSQL dump failed its stored hash check."
        )
    sealed = decrypt_catalog(
        root,
        recovery_root_secret=recovery_root_secret,
        controller_id=controller_id,
        repository_identity=repository_identity,
        snapshot_uuid=manifest["snapshot_uuid"],
        output_path=root / "catalog.readback.json",
    )
    try:
        if sealed["sha256"] != (manifest.get("catalog") or {}).get("plaintext_sha256"):
            raise VaultRewindError(
                "CONTROLLER_CATALOG_AUTH_FAILED", "The sealed catalog does not match its manifest."
            )
    finally:
        sealed["path"].unlink(missing_ok=True)
    pg_restore = shutil.which("pg_restore", path="/usr/local/bin:/usr/bin:/bin")
    if not pg_restore:
        raise VaultRewindError(
            "CONTROLLER_PG_RESTORE_UNAVAILABLE", "The PostgreSQL restore utility is not installed."
        )
    checked = subprocess.run(
        [pg_restore, "--list", str(dump_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root), "TZ": "UTC"},
        timeout=300,
        check=False,
    )
    if checked.returncode:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_INVALID", "The stored PostgreSQL archive failed structural verification."
        )


def run_controller_backup(worker, ctx) -> None:
    """Worker handler. A full pg_dump and independently sealed full-row catalog are required for success."""
    settings, sessions, store = ctx.settings, ctx.sessions, worker.store
    max_bytes = min(settings.controller_backup_max_bytes, settings.per_job_quota_bytes)
    _reserve_staging(ctx, max_bytes)
    work = ensure_private_directory(ctx.root / "controller-backup")
    repository_work = _controller_repository_work_dir(ctx, settings)
    backup_row_id = None
    try:
        with sessions() as db:
            prior = db.scalar(select(ControllerBackup).where(ControllerBackup.job_id == ctx.id))
            prior_view = (
                {
                    "id": prior.id,
                    "destination_id": prior.destination_id,
                    "snapshot_uuid": prior.snapshot_uuid,
                    "captured_at": prior.captured_at,
                    "state": prior.state,
                    "repository_id": prior.repository_id,
                    "restic_snapshot_id": prior.restic_snapshot_id,
                    "manifest_hash": prior.manifest_hash,
                    "tables": prior.tables,
                    "rows": prior.rows,
                    "bytes": prior.bytes,
                    "pg_dump_included": prior.pg_dump_included,
                }
                if prior
                else None
            )
        if prior_view and prior_view["state"] == "complete":
            ctx.update(
                result={
                    "controller_backup_id": prior_view["id"],
                    "destination_id": prior_view["destination_id"],
                    "repository_id": prior_view["repository_id"],
                    "restic_snapshot_id": prior_view["restic_snapshot_id"],
                    "manifest_hash": prior_view["manifest_hash"],
                    "tables": prior_view["tables"],
                    "rows": prior_view["rows"],
                    "bytes": prior_view["bytes"],
                    "pg_dump_included": prior_view["pg_dump_included"],
                }
            )
            ctx.finish("succeeded")
            return
        snapshot_id = prior_view["snapshot_uuid"] if prior_view else str(uuid.uuid4())
        captured_at = _aware(prior_view["captured_at"]) if prior_view else now()
        backup_row_id = prior_view["id"] if prior_view else None
        destination_id = ctx.request.get("destination_id") or (
            prior_view["destination_id"] if prior_view else None
        )
        if not destination_id:
            with sessions() as db:
                policy = db.get(ControllerBackupPolicy, 1)
                destination_id = policy.destination_id if policy else None
        if not destination_id:
            raise VaultRewindError(
                "CONTROLLER_BACKUP_NOT_CONFIGURED",
                "Choose a durable destination before backing up the controller.",
            )
        with sessions.begin() as db:
            controller_id = _controller_identity(db)
            destination, repo_row, repo_config, credential, password, root_secret = _repository(
                db, store, settings, controller_id, destination_id
            )
            if backup_row_id:
                backup = db.get(ControllerBackup, backup_row_id)
                if backup.destination_id != destination.id or backup.repository_id != repo_row.id:
                    raise VaultRewindError(
                        "CONTROLLER_BACKUP_IDENTITY_MISMATCH",
                        "The retried controller backup changed its destination.",
                    )
                backup.state, backup.error_code = "capturing", None
            else:
                backup = ControllerBackup(
                    job_id=ctx.id,
                    destination_id=destination.id,
                    repository_id=repo_row.id,
                    snapshot_uuid=snapshot_id,
                    captured_at=captured_at,
                    state="capturing",
                    pg_dump_included=False,
                )
                db.add(backup)
                db.flush()
                backup_row_id = backup.id
            backend, destination_config = (
                destination.backend,
                store.get(db, destination.configuration_secret_id),
            )
            repo_password, restic_id = password, repo_config.get("restic_repository_id")
            physical_identity = repo_row.physical_identity
        if ctx.cancellation():
            raise VaultRewindError("STORAGE_OPERATION_CANCELLED", "The controller backup was cancelled.")
        with repository_lock(settings.staging_dir, physical_identity):
            # Reconcile a restic commit whose worker response or catalog-row update was lost.
            from .adapters import SQLCredentialStore

            with providers.open_repository(
                backend,
                destination_config,
                credential,
                instance_id=controller_id,
                destination_id=destination_id,
                password=repo_password,
                work_dir=repository_work,
                repository_id=restic_id,
                credential_store=SQLCredentialStore(worker.adapters, ctx.guard),
                box=store.box(),
                cancel_event=ctx._lost,
                location=repo_config["location"],
                protected_paths=[settings.staging_dir, settings.master_key_file],
            ) as repository:
                identity = repository.initialize()
                from vaultrewind.storage.controller import find_controller_snapshot

                existing_snapshot = find_controller_snapshot(
                    repository,
                    controller_id=controller_id,
                    destination_id=destination_id,
                    snapshot_uuid=snapshot_id,
                )
                if existing_snapshot:
                    reconcile_root = work / "reconciled-snapshot"
                    reconcile_root.mkdir(mode=0o700)
                    try:
                        from vaultrewind.storage.controller import restore_controller_snapshot

                        evidence = restore_controller_snapshot(
                            repository,
                            existing_snapshot["id"],
                            reconcile_root,
                            expected_manifest_hash=existing_snapshot["manifest_hash"],
                        )
                        manifest = evidence["manifest"]
                        if (
                            manifest.get("controller_uuid") != controller_id
                            or manifest.get("destination_id") != destination_id
                            or manifest.get("repository_identity") != physical_identity
                            or manifest.get("snapshot_uuid") != snapshot_id
                        ):
                            raise VaultRewindError(
                                "SNAPSHOT_IDENTITY_CONFLICT",
                                "The stored controller snapshot identity conflicts with its job.",
                            )
                        dump_path = reconcile_root / "database.dump"
                        if (
                            dump_path.stat().st_size != manifest["pg_dump"]["bytes"]
                            or _sha256_file(dump_path) != manifest["pg_dump"]["sha256"]
                        ):
                            raise VaultRewindError(
                                "CONTROLLER_BACKUP_READBACK_FAILED",
                                "The stored PostgreSQL archive failed its hash check.",
                            )
                        sealed = decrypt_catalog(
                            reconcile_root,
                            recovery_root_secret=root_secret,
                            controller_id=controller_id,
                            repository_identity=physical_identity,
                            snapshot_uuid=snapshot_id,
                            output_path=reconcile_root / "catalog.reconcile.json",
                        )
                        if sealed["sha256"] != manifest.get("catalog", {}).get("plaintext_sha256"):
                            raise VaultRewindError(
                                "CONTROLLER_CATALOG_AUTH_FAILED",
                                "The stored catalog does not match its manifest.",
                            )
                        sealed["path"].unlink(missing_ok=True)
                        pg_restore = shutil.which("pg_restore", path="/usr/local/bin:/usr/bin:/bin")
                        if (
                            not pg_restore
                            or subprocess.run(
                                [pg_restore, "--list", str(dump_path)],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(work), "TZ": "UTC"},
                                timeout=300,
                                check=False,
                            ).returncode
                            != 0
                        ):
                            raise VaultRewindError(
                                "CONTROLLER_PG_DUMP_INVALID",
                                "The stored PostgreSQL archive failed structural verification.",
                            )
                        with sessions.begin() as db:
                            backup = db.get(ControllerBackup, backup_row_id)
                            repo_row = db.get(Repository, backup.repository_id)
                            repo_secret = store.get(db, repo_row.configuration_secret_id)
                            repo_secret["restic_repository_id"] = identity["repository_id"]
                            store.replace(db, repo_row.configuration_secret_id, repo_secret)
                            repo_row.health = "healthy"
                            backup.restic_snapshot_id = existing_snapshot["id"]
                            backup.manifest_hash = manifest["manifest_hash"]
                            backup.state, backup.pg_dump_included = "complete", True
                            backup.alembic_version = manifest.get("alembic_version")
                            backup.tables, backup.rows = manifest["tables"], manifest["rows"]
                            backup.bytes = sum(
                                item.get("size", 0)
                                for item in evidence["inventory"]["files"]
                                if item["type"] == "file"
                            )
                        ctx.update(
                            result={
                                "controller_backup_id": backup_row_id,
                                "repository_id": repo_row.id,
                                "destination_id": destination_id,
                                "restic_snapshot_id": existing_snapshot["id"],
                                "manifest_hash": manifest["manifest_hash"],
                                "tables": manifest["tables"],
                                "rows": manifest["rows"],
                                "bytes": backup.bytes,
                                "pg_dump_included": True,
                                "reconciled": True,
                            }
                        )
                        ctx.finish("succeeded")
                        return
                    finally:
                        scrub_tree(reconcile_root)
            # A previous worker process may have died between durable phases. Its private
            # staging tree is not a valid capture; keep the snapshot UUID but recapture cleanly.
            scrub_tree(work)
            work = ensure_private_directory(ctx.root / "controller-backup")
            ctx.phase("controller_database_capture")
            capture_info, tables, rows, dump_size, catalog_hash = _capture_postgres(
                settings.database_url,
                work,
                controller_id=controller_id,
                captured_at=captured_at,
                snapshot_uuid=snapshot_id,
                max_bytes=max_bytes,
            )
            ctx.usage()
            with sessions.begin() as db:
                backup = db.get(ControllerBackup, backup_row_id)
                backup.tables, backup.rows, backup.alembic_version = (
                    tables,
                    rows,
                    capture_info["alembic_version"],
                )
            ctx.guard()
            with sessions.begin() as db:
                # Snapshot the current recovery root secret under the same repository identity.
                root_secret = store.get(
                    db,
                    db.scalar(
                        select(Secret).where(
                            Secret.kind == "recovery_root", Secret.owner_scope == "controller"
                        )
                    ).id,
                )
            _seal_catalog(
                work / "catalog.plain.json",
                work,
                root_secret=root_secret,
                controller_id=controller_id,
                physical_identity=physical_identity,
                snapshot_id=snapshot_id,
                max_bytes=max_bytes,
            )
            inventory_files = file_inventory(work)
            inventory = {
                "format": _FORMAT,
                "schema_version": _SCHEMA,
                "controller_uuid": controller_id,
                "snapshot_uuid": snapshot_id,
                "files": inventory_files,
            }
            inventory_hash = _canonical_hash(inventory)
            write_private_file(work / "controller-inventory.json", canonical_json(inventory))
            manifest_body = {
                "format": _FORMAT,
                "schema_version": _SCHEMA,
                "controller_uuid": controller_id,
                "destination_id": destination_id,
                "repository_identity": physical_identity,
                "snapshot_uuid": snapshot_id,
                "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
                "alembic_version": capture_info["alembic_version"],
                "postgres_server_version_num": capture_info["server_version_num"],
                "postgres_client_tools": {
                    "pg_dump": capture_info["pg_dump_version"],
                    "pg_restore": capture_info["pg_restore_version"],
                },
                "tables": tables,
                "rows": rows,
                "pg_dump": {
                    "path": "database.dump",
                    "bytes": dump_size,
                    "sha256": _sha256_file(work / "database.dump"),
                    "format": "PostgreSQL custom archive",
                },
                "catalog": {
                    "format": _CATALOG_FORMAT,
                    "schema_version": _CATALOG_SCHEMA,
                    "plaintext_sha256": catalog_hash,
                    "independently_sealed": True,
                    "seal": "SecretBox AES-256-GCM; key derived from recovery root and controller/repository identity",
                },
                "inventory_sha256": inventory_hash,
            }
            manifest_hash = _canonical_hash(manifest_body)
            manifest = {**manifest_body, "manifest_hash": manifest_hash}
            write_private_file(work / "controller-manifest.json", canonical_json(manifest))
            actual_bytes = sum(item.get("size", 0) for item in file_inventory(work) if item["type"] == "file")
            if actual_bytes > max_bytes:
                raise VaultRewindError(
                    "CONTROLLER_BACKUP_TOO_LARGE",
                    "The complete controller backup exceeds its configured size limit.",
                )
            ctx.usage()
            ctx.phase("controller_repository_commit")
            with providers.open_repository(
                backend,
                destination_config,
                credential,
                instance_id=controller_id,
                destination_id=destination_id,
                password=repo_password,
                work_dir=repository_work,
                repository_id=restic_id,
                credential_store=SQLCredentialStore(worker.adapters, ctx.guard),
                box=store.box(),
                cancel_event=ctx._lost,
                location=repo_config["location"],
                protected_paths=[settings.staging_dir, settings.master_key_file],
            ) as repository:
                identity = repository.initialize()
                if restic_id and identity["repository_id"] != restic_id:
                    raise VaultRewindError(
                        "REPOSITORY_IDENTITY_MISMATCH", "The controller repository identity changed."
                    )
                committed = commit_controller_snapshot(
                    repository,
                    work,
                    controller_id=controller_id,
                    destination_id=destination_id,
                    snapshot_uuid=snapshot_id,
                    captured_at=captured_at.isoformat().replace("+00:00", "Z"),
                    manifest_hash=manifest_hash,
                    verify_callback=lambda restored_root, stored_manifest, _stored_inventory: (
                        _verify_committed_content(
                            restored_root,
                            stored_manifest,
                            controller_id=controller_id,
                            destination_id=destination_id,
                            repository_identity=physical_identity,
                            recovery_root_secret=root_secret,
                        )
                    ),
                )
            with sessions.begin() as db:
                backup = db.get(ControllerBackup, backup_row_id)
                repo_row = db.get(Repository, backup.repository_id)
                repo_secret = store.get(db, repo_row.configuration_secret_id)
                repo_secret["restic_repository_id"] = committed["repository_id"]
                store.replace(db, repo_row.configuration_secret_id, repo_secret)
                repo_row.health = "healthy"
                backup.restic_snapshot_id = committed["restic_snapshot_id"]
                backup.manifest_hash = manifest_hash
                backup.state, backup.pg_dump_included = "complete", True
                backup.bytes = actual_bytes
                backup.error_code = None
            ctx.update(
                result={
                    "controller_backup_id": backup_row_id,
                    "repository_id": repo_row.id,
                    "destination_id": destination_id,
                    "pg_dump_included": True,
                    "tables": tables,
                    "rows": rows,
                    "bytes": actual_bytes,
                    "manifest_hash": manifest_hash,
                    "restic_snapshot_id": committed["restic_snapshot_id"],
                }
            )
            ctx.finish("succeeded")
    except Exception as exc:
        code = getattr(exc, "code", "CONTROLLER_BACKUP_FAILED")
        if backup_row_id:
            with contextlib.suppress(Exception), sessions.begin() as db:
                backup = db.get(ControllerBackup, backup_row_id)
                if backup and backup.state != "complete":
                    backup.state, backup.error_code = "failed", str(code)[:80]
        scrub_tree(work)
        raise
    finally:
        if work.exists():
            scrub_tree(work)
        with contextlib.suppress(Exception):
            scrub_tree(repository_work)
        ctx.cleanup()


def validate_controller_snapshot(
    repository,
    restic_snapshot_id: str,
    target: Path,
    *,
    recovery_root_secret: str,
    expected_manifest_hash: str | None = None,
) -> dict:
    """Offline-friendly verification: restic bytes, controller manifest, sealed catalog and SQL dump hash."""
    restored = restore_controller_snapshot(
        repository, restic_snapshot_id, target, expected_manifest_hash=expected_manifest_hash
    )
    root, manifest, inventory = restored["root"], restored["manifest"], restored["inventory"]
    if not manifest.get("pg_dump", {}).get("path") == "database.dump":
        raise VaultRewindError(
            "CONTROLLER_BACKUP_FORMAT_INVALID", "This controller backup has no PostgreSQL dump."
        )
    dump_path = root / "database.dump"
    if (
        dump_path.stat().st_size != manifest["pg_dump"]["bytes"]
        or _sha256_file(dump_path) != manifest["pg_dump"]["sha256"]
    ):
        raise VaultRewindError(
            "CONTROLLER_BACKUP_READBACK_FAILED", "The PostgreSQL dump failed its recorded hash check."
        )
    pg_restore = shutil.which("pg_restore", path="/usr/local/bin:/usr/bin:/bin")
    if not pg_restore:
        raise VaultRewindError(
            "CONTROLLER_PG_RESTORE_UNAVAILABLE", "The PostgreSQL restore utility is not installed."
        )
    checked = subprocess.run(
        [pg_restore, "--list", str(dump_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root), "TZ": "UTC"},
        timeout=300,
        check=False,
    )
    if checked.returncode:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_INVALID", "The PostgreSQL archive failed structural verification."
        )
    catalog = decrypt_catalog(
        root,
        recovery_root_secret=recovery_root_secret,
        controller_id=manifest["controller_uuid"],
        repository_identity=manifest["repository_identity"],
        snapshot_uuid=manifest["snapshot_uuid"],
    )
    if catalog["sha256"] != manifest.get("catalog", {}).get("plaintext_sha256"):
        catalog["path"].unlink(missing_ok=True)
        raise VaultRewindError(
            "CONTROLLER_CATALOG_AUTH_FAILED", "The sealed catalog does not match its controller manifest."
        )
    catalog["path"].unlink(missing_ok=True)
    return {
        "manifest": manifest,
        "inventory": inventory,
        "verified": True,
        "pg_dump_verified": True,
        "catalog_verified": True,
        "tables": manifest["tables"],
        "rows": manifest["rows"],
        "bytes": manifest["pg_dump"]["bytes"],
    }


def restore_dump_to_empty_database(
    dump_path: Path,
    target_database_url: str,
    *,
    operator_authorized: bool = False,
    source_database_url: str | None = None,
) -> dict:
    """Restore only to an explicitly authorized empty prepared PostgreSQL database.

    The caller must provision credentials and database, then invoke this function while workers are stopped.
    It refuses a source-equal URL and refuses any existing user table/schema before running pg_restore.
    """
    if operator_authorized is not True:
        raise VaultRewindError(
            "CONTROLLER_RESTORE_AUTH_REQUIRED",
            "An administrator must explicitly authorize controller database recovery.",
        )
    target = make_url(target_database_url)
    if target.get_backend_name() != "postgresql":
        raise VaultRewindError(
            "CONTROLLER_DATABASE_UNSUPPORTED",
            "Controller metadata restore requires a prepared PostgreSQL database.",
        )
    if source_database_url and target.set(password=None) == make_url(source_database_url).set(password=None):
        raise VaultRewindError(
            "CONTROLLER_RESTORE_TARGET_INVALID",
            "The source controller database cannot be used as the recovery target.",
        )
    root = Path(dump_path)
    if root.is_symlink() or not root.is_file() or root.stat().st_size == 0:
        raise VaultRewindError(
            "CONTROLLER_PG_DUMP_INVALID", "The controller database archive is missing or unsafe."
        )
    conn_args = {
        "dbname": target.database,
        "user": target.username,
        "password": target.password,
        "host": target.host,
        "port": target.port,
    }
    conn_args.update(
        {
            key: target.query[key]
            for key in ("sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout")
            if key in target.query
        }
    )
    conn_args = {key: value for key, value in conn_args.items() if value is not None}
    try:
        with psycopg.connect(**conn_args) as connection:
            connection.execute("BEGIN")
            schemas = connection.execute(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name NOT IN ('pg_catalog','information_schema') "
                "AND schema_name <> 'public'"
            ).fetchall()
            user_objects = connection.execute("""SELECT
                EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
                          AND c.relkind IN ('r','p','v','m','S','f')) OR
                EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                        WHERE n.nspname NOT IN ('pg_catalog','information_schema')) OR
                EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                        WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
                          AND t.typtype IN ('c','d','e','r'))""").fetchone()[0]
            if schemas or user_objects:
                raise VaultRewindError(
                    "CONTROLLER_RESTORE_TARGET_NOT_EMPTY",
                    "The prepared recovery database contains user data.",
                )
            connection.commit()
    except VaultRewindError:
        raise
    except Exception as exc:
        raise VaultRewindError(
            "CONTROLLER_RESTORE_TARGET_INVALID", "The prepared recovery database could not be checked."
        ) from exc
    directory = ensure_private_directory(root.parent / "pg-restore-credentials")
    _, env, _ = _pg_service(target_database_url, directory)
    try:
        pg_restore = shutil.which("pg_restore", path=env["PATH"])
        if not pg_restore:
            raise VaultRewindError(
                "CONTROLLER_PG_RESTORE_UNAVAILABLE", "The PostgreSQL restore utility is not installed."
            )
        pg_restore_args = [
            pg_restore,
            "--no-password",
            "--no-owner",
            "--no-acl",
            "--exit-on-error",
            "--single-transaction",
            "--dbname",
            target.database,
            str(root),
        ]
        for flag, value in (
            ("--host", target.host),
            ("--port", target.port),
            ("--username", target.username),
        ):
            if value is not None:
                pg_restore_args.extend((flag, str(value)))
        result = subprocess.run(
            pg_restore_args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=3600,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VaultRewindError(
            "CONTROLLER_PG_RESTORE_FAILED", "The controller database restore did not complete."
        ) from exc
    finally:
        scrub_tree(directory)
    if result.returncode != 0:
        raise VaultRewindError(
            "CONTROLLER_PG_RESTORE_FAILED", "The controller database restore did not complete."
        )
    hold = hold_restored_policies(target_database_url)
    return {
        **hold,
        "restored": True,
        "target_database": target.database,
    }


def hold_restored_policies(database_url: str) -> dict:
    """Disable automation and quarantine restored work before any worker is resumed."""
    args = _connect_args(database_url)
    try:
        with psycopg.connect(**args) as connection:
            connection.execute("UPDATE backup_policies SET enabled=FALSE, next_run_at=NULL")
            if connection.execute("SELECT to_regclass('public.controller_backup_policies')").fetchone()[0]:
                connection.execute("UPDATE controller_backup_policies SET enabled=FALSE, next_run_at=NULL")
            connection.execute("UPDATE snapshots SET imported=TRUE")
            connection.execute("""INSERT INTO snapshot_protections (id, created_at, snapshot_id, copy_id, reason, actor_id, job_id, expires_at)
                SELECT md5(s.id || ':imported-review'), now(), s.id, NULL, 'imported_review', NULL, NULL, NULL
                FROM snapshots s WHERE NOT EXISTS (SELECT 1 FROM snapshot_protections p
                    WHERE p.snapshot_id=s.id AND p.reason='imported_review')""")
            quarantined = _quarantine_restored_jobs(connection)
            sessions_revoked = _invalidate_restored_authentication(connection)
    except Exception as exc:
        raise VaultRewindError(
            "CONTROLLER_IMPORT_HOLD_FAILED",
            "Restored controller policies could not be placed in protected mode.",
        ) from exc
    return {
        "policies_disabled": True,
        "snapshots_protected": True,
        "imported_snapshots_held": True,
        "jobs_cancelled_unstarted": quarantined["cancelled_unstarted"],
        "jobs_held_for_reconciliation": quarantined["held_for_reconciliation"],
        "sessions_revoked": sessions_revoked["sessions_revoked"],
        "oauth_states_consumed": sessions_revoked["oauth_states_consumed"],
        "workers_may_resume": False,
    }


_RECOVERY_REVIEW_REQUIRED = "CONTROLLER_RECOVERY_REVIEW_REQUIRED"


def _table_exists(connection, name: str) -> bool:
    return connection.execute("SELECT to_regclass(%s)", (f"public.{name}",)).fetchone()[0] is not None


def _quarantine_restored_jobs(connection) -> dict[str, int]:
    """Cancel never-issued queued work and retain locks for every possibly issued operation."""
    if not _table_exists(connection, "jobs"):
        return {"cancelled_unstarted": 0, "held_for_reconciliation": 0}

    jobs = connection.execute(
        """SELECT id, state, phase, attempts, started_at, finished_at, lease_owner,
                  lease_expires_at, reconcile_required, result
           FROM jobs
           WHERE state IN ('queued', 'running', 'waiting_retry', 'cancel_requested',
                           'needs_attention', 'rollback_failed')
           ORDER BY created_at, id FOR UPDATE"""
    ).fetchall()
    if not jobs:
        return {"cancelled_unstarted": 0, "held_for_reconciliation": 0}

    job_ids = [row[0] for row in jobs]
    jobs_with_steps: set[str] = set()
    if _table_exists(connection, "job_steps"):
        jobs_with_steps = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT job_id FROM job_steps WHERE job_id = ANY(%s)", (job_ids,)
            ).fetchall()
        }

    owned_leases: dict[str, list[str]] = {}
    if _table_exists(connection, "resource_leases"):
        for resource_key, owner_job_id in connection.execute(
            "SELECT resource_key, owner_job_id FROM resource_leases "
            "WHERE owner_job_id = ANY(%s) FOR UPDATE",
            (job_ids,),
        ).fetchall():
            owned_leases.setdefault(owner_job_id, []).append(resource_key)

    resources_by_job: dict[str, list[str]] = {}
    if _table_exists(connection, "job_resources"):
        for job_id, resource_key in connection.execute(
            "SELECT job_id, resource_key FROM job_resources WHERE job_id = ANY(%s) "
            "ORDER BY job_id, resource_key",
            (job_ids,),
        ).fetchall():
            resources_by_job.setdefault(job_id, []).append(resource_key)

    current = connection.execute("SELECT now()").fetchone()[0]
    counts = {"cancelled_unstarted": 0, "held_for_reconciliation": 0}
    for row in jobs:
        (
            job_id,
            state,
            _phase,
            attempts,
            started_at,
            _finished_at,
            lease_owner,
            lease_expires_at,
            reconcile_required,
            result,
        ) = row
        result = result if isinstance(result, dict) else {}
        previous_hold = result.get("controller_recovery_hold")
        unstarted = (
            state == "queued"
            and int(attempts or 0) == 0
            and started_at is None
            and job_id not in jobs_with_steps
            and not owned_leases.get(job_id)
            and lease_owner is None
            and lease_expires_at is None
            and not reconcile_required
        )
        classification = "cancelled_unstarted" if unstarted else "reconcile_required"
        next_state = "cancelled" if unstarted else "needs_attention"
        result = {
            **result,
            "controller_recovery_hold": {
                "error_code": _RECOVERY_REVIEW_REQUIRED,
                "classification": classification,
            },
        }

        # If earlier attempts released a lease before entering waiting_retry, reacquire
        # vacant physical keys for review. Never take a key from another recorded owner.
        if not unstarted and _table_exists(connection, "resource_leases"):
            for resource_key in resources_by_job.get(job_id, ()):
                connection.execute(
                    "INSERT INTO resource_leases (resource_key, owner_job_id, expires_at, generation) "
                    "VALUES (%s, NULL, NULL, 0) ON CONFLICT (resource_key) DO NOTHING",
                    (resource_key,),
                )
                connection.execute(
                    "UPDATE resource_leases SET owner_job_id=%s, expires_at=NULL "
                    "WHERE resource_key=%s AND owner_job_id IS NULL",
                    (job_id, resource_key),
                )
            # Keep the owner_job_id as a durable physical hold, but discard every stale
            # time-bound worker lease. An explicit reconciliation can adopt it later.
            connection.execute(
                "UPDATE resource_leases SET expires_at=NULL WHERE owner_job_id=%s", (job_id,)
            )

        connection.execute(
            """UPDATE jobs SET state=%s, error_code=%s, reconcile_required=%s,
                      lease_owner=NULL, lease_expires_at=NULL, finished_at=COALESCE(finished_at, %s),
                      result=%s WHERE id=%s""",
            (
                next_state,
                _RECOVERY_REVIEW_REQUIRED,
                not unstarted,
                current,
                Json(result),
                job_id,
            ),
        )

        # An already quarantined record remains held without duplicating its audit trail.
        if previous_hold:
            counts["cancelled_unstarted" if unstarted else "held_for_reconciliation"] += 1
            continue
        if _table_exists(connection, "job_events"):
            sequence = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM job_events WHERE job_id=%s", (job_id,)
            ).fetchone()[0]
            connection.execute(
                """INSERT INTO job_events (id, created_at, job_id, sequence, phase, code, progress)
                   VALUES (%s, %s, %s, %s, 'controller_recovery_hold', %s, '{}'::json)""",
                (str(uuid.uuid4()), current, job_id, sequence, _RECOVERY_REVIEW_REQUIRED),
            )
        if _table_exists(connection, "audit_events"):
            connection.execute(
                """INSERT INTO audit_events (id, created_at, actor_id, action, object_id, outcome, changes)
                   VALUES (%s, %s, NULL, 'controller_recovery.job_quarantine', %s, %s, %s)""",
                (
                    str(uuid.uuid4()),
                    current,
                    job_id,
                    classification,
                    Json({"error_code": _RECOVERY_REVIEW_REQUIRED}),
                ),
            )
        counts["cancelled_unstarted" if unstarted else "held_for_reconciliation"] += 1
    return counts


def _invalidate_restored_authentication(connection) -> dict[str, int]:
    """Invalidate browser sessions, OAuth exchanges and old destructive-plan confirmations."""
    counts = {"sessions_revoked": 0, "oauth_states_consumed": 0}
    if _table_exists(connection, "sessions"):
        counts["sessions_revoked"] = connection.execute(
            "UPDATE sessions SET revoked_at=COALESCE(revoked_at, now()) WHERE revoked_at IS NULL"
        ).rowcount
    if _table_exists(connection, "oauth_states"):
        counts["oauth_states_consumed"] = connection.execute(
            "UPDATE oauth_states SET consumed_at=COALESCE(consumed_at, now()) WHERE consumed_at IS NULL"
        ).rowcount
    for table in ("restore_plans", "deletion_plans"):
        if _table_exists(connection, table):
            connection.execute(
                f"UPDATE {table} SET consumed_at=COALESCE(consumed_at, now()) WHERE consumed_at IS NULL"
            )
    return counts

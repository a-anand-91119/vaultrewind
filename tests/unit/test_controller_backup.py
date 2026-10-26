"""Controller metadata backup tests use only generated catalogs and a disposable PostgreSQL database."""

from __future__ import annotations

import hashlib
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy.engine import make_url

from tests.unit.test_server import env  # noqa: F401 - shared in-memory server fixtures
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.controller_backup import (
    _capture_postgres,
    _controller_repository_work_dir,
    _seal_catalog,
    configure_policy,
    decrypt_catalog,
    hold_restored_policies,
    public_status,
    restore_dump_to_empty_database,
    schedule_due,
)
from vaultrewind.server.db import make_engine, sessions
from vaultrewind.server.models import ControllerBackupPolicy, StorageDestination
from vaultrewind.server.queue import claim
from vaultrewind.storage import layout
from vaultrewind.storage.controller import (
    _FORMAT,
    _SCHEMA,
    canonical_json,
    commit_controller_snapshot,
    file_inventory,
    restore_controller_snapshot,
)
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository


@dataclass(repr=False)
class DisposableDatabases:
    source_url: str = field(repr=False)
    target_url: str = field(repr=False)
    unstarted_restore_id: str = field(repr=False)
    issued_restore_id: str = field(repr=False)
    issued_resource_key: str = field(repr=False)
    session_id: str = field(repr=False)
    oauth_state_id: str = field(repr=False)


def test_controller_policy_persists_destination_and_one_daily_occurrence(env):  # noqa: F811
    _, _, sessions, store, _ = env
    with sessions.begin() as db:
        config = store.put(db, "destination_configuration", "controller-test", {"path": "/synthetic/backups"})
        destination = StorageDestination(
            id=str(uuid.uuid4()), name="synthetic", backend="local", configuration_secret_id=config
        )
        db.add(destination)
        db.flush()
        policy = configure_policy(db, destination.id, timezone="UTC", daily_time="02:00")
        assert policy.destination_id == destination.id and policy.next_run_at
        row = db.get(ControllerBackupPolicy, 1)
        row.next_run_at = datetime(2026, 10, 24, 2, tzinfo=UTC)
        due = schedule_due(db, datetime(2026, 10, 25, 12, tzinfo=UTC))
        assert due["destination_id"] == destination.id
        assert due["scheduled_at"] == "2026-10-24T02:00:00+00:00"
        assert due["next_run_at"] > "2026-10-25T12:00:00+00:00"
        status = public_status(db)
        assert status["configured"] and status["enabled"] and status["destination_id"] == destination.id
        assert "credential" not in status and "password" not in status


def test_sealed_catalog_is_independent_context_bound_and_detects_tampering(tmp_path):
    root = tmp_path / "stage"
    root.mkdir(mode=0o700)
    controller_id = str(uuid.uuid4())
    secret = layout.new_recovery_root_secret()
    identity = "a" * 64
    snapshot = str(uuid.uuid4())
    plaintext = root / "catalog.plain.json"
    data = {
        "format": "vaultrewind-controller-catalog",
        "schema_version": 1,
        "tables": [{"schema": "public", "name": "secrets", "rows": [["synthetic-private-value"]]}],
    }
    plaintext.write_bytes(canonical_json(data))
    _seal_catalog(
        plaintext,
        root,
        root_secret=secret,
        controller_id=controller_id,
        physical_identity=identity,
        snapshot_id=snapshot,
        max_bytes=1024 * 1024,
    )
    sealed_bytes = b"".join(path.read_bytes() for path in sorted(root.rglob("*.sealed")) if path.is_file())
    assert b"synthetic-private-value" not in sealed_bytes
    decrypted = decrypt_catalog(
        root,
        recovery_root_secret=secret,
        controller_id=controller_id,
        repository_identity=identity,
        snapshot_uuid=snapshot,
    )
    assert decrypted["catalog"] == data
    assert decrypted["path"].stat().st_mode & 0o777 == 0o600
    decrypted["path"].unlink()
    chunk = root / "catalog.sealed" / "00000000.sealed"
    chunk.write_text(chunk.read_text()[:-2] + "aa")
    with pytest.raises(VaultRewindError, match="authentication"):
        decrypt_catalog(
            root,
            recovery_root_secret=secret,
            controller_id=controller_id,
            repository_identity=identity,
            snapshot_uuid=snapshot,
        )
    with pytest.raises(VaultRewindError) as wrong_context:
        decrypt_catalog(
            root,
            recovery_root_secret=secret,
            controller_id=controller_id,
            repository_identity="b" * 64,
            snapshot_uuid=snapshot,
        )
    assert wrong_context.value.code == "CONTROLLER_CATALOG_AUTH_FAILED"


def _database_url_file() -> Path:
    return Path(".runtime/controller/database-url")


def _connect(url_text: str):
    url = make_url(url_text)
    args = {
        "dbname": url.database,
        "user": url.username,
        "password": url.password,
        "host": url.host,
        "port": url.port,
    }
    args.update(
        {
            key: url.query[key]
            for key in ("sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout")
            if key in url.query
        }
    )
    return psycopg.connect(**{key: value for key, value in args.items() if value is not None})


def _create_db(database_url: str, name: str) -> None:
    owner = make_url(database_url).username
    result = subprocess.run(
        ["runuser", "-u", "postgres", "--", "createdb", "--owner", str(owner), name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if result.returncode:
        pytest.skip("the local PostgreSQL admin role cannot create a disposable test database")


def _drop_db(database_url: str, name: str) -> None:
    subprocess.run(
        ["runuser", "-u", "postgres", "--", "dropdb", "--if-exists", "--force", name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=60,
    )


@pytest.fixture
def disposable_controller_databases(tmp_path):
    """Use only two randomly named disposable databases; never connect to the configured app DB itself."""
    url_file = _database_url_file()
    if not url_file.is_file() or url_file.stat().st_mode & 0o077:
        pytest.skip("private PostgreSQL integration URL file is unavailable")
    database_url = url_file.read_text().strip()
    if not database_url:
        pytest.skip("private PostgreSQL integration URL file is empty")
    suffix = uuid.uuid4().hex[:16]
    source_name, target_name = f"vr_ctrl_test_{suffix}", f"vr_ctrl_restore_{suffix}"
    source_url = make_url(database_url).set(database=source_name)
    target_url = make_url(database_url).set(database=target_name)
    unstarted_restore_id = str(uuid.uuid4())
    issued_restore_id = str(uuid.uuid4())
    issued_resource_key = f"instance:synthetic-{uuid.uuid4()}"
    session_id = str(uuid.uuid4())
    oauth_state_id = str(uuid.uuid4())
    made = []
    try:
        _create_db(database_url, source_name)
        made.append(source_name)
        _create_db(database_url, target_name)
        made.append(target_name)
        with _connect(source_url.render_as_string(hide_password=False)) as connection:
            connection.execute("""CREATE TABLE vault_rows(id integer PRIMARY KEY, value text NOT NULL, created_at timestamptz NOT NULL);
                INSERT INTO vault_rows VALUES (1, 'synthetic-catalog-fixture', now());
                CREATE TABLE alembic_version(version_num varchar(64) PRIMARY KEY);
                INSERT INTO alembic_version VALUES ('synthetic_revision');
                CREATE TABLE backup_policies(id text PRIMARY KEY, enabled boolean NOT NULL, next_run_at timestamptz);
                INSERT INTO backup_policies VALUES ('p1', true, now());
                CREATE TABLE controller_backup_policies(id integer PRIMARY KEY, enabled boolean NOT NULL, next_run_at timestamptz);
                INSERT INTO controller_backup_policies VALUES (1, true, now());
                CREATE TABLE snapshots(id text PRIMARY KEY, imported boolean NOT NULL);
                INSERT INTO snapshots VALUES ('s1', false);
                CREATE TABLE snapshot_protections(id text PRIMARY KEY, created_at timestamptz NOT NULL, snapshot_id text NOT NULL,
                    copy_id text, reason text NOT NULL, actor_id text, job_id text, expires_at timestamptz);
                CREATE TABLE controller_secrets(id integer PRIMARY KEY, secret text NOT NULL);
                INSERT INTO controller_secrets VALUES (1, 'synthetic-secret-row');""")
            connection.execute("""CREATE TABLE jobs (
                id varchar(36) PRIMARY KEY, created_at timestamptz NOT NULL, kind varchar(40) NOT NULL,
                instance_id varchar(36), actor_id varchar(36), state varchar(30) NOT NULL, phase varchar(40) NOT NULL,
                idempotency_scope varchar(100) NOT NULL, idempotency_key varchar(160) NOT NULL,
                request_hash varchar(64) NOT NULL, request json NOT NULL, policy_revision integer,
                lease_owner varchar(100), lease_expires_at timestamptz, fencing_token bigint NOT NULL,
                attempts integer NOT NULL, next_attempt_at timestamptz, started_at timestamptz, finished_at timestamptz,
                reconcile_required boolean NOT NULL, content_commit varchar(30) NOT NULL,
                required_copy_outcome varchar(30) NOT NULL, source_service_outcome varchar(30) NOT NULL,
                target_activation_outcome varchar(30) NOT NULL, error_code varchar(80), result json NOT NULL
            );
            CREATE TABLE job_resources(job_id varchar(36) NOT NULL, resource_key varchar(180) NOT NULL,
                PRIMARY KEY(job_id, resource_key));
            CREATE TABLE resource_leases(resource_key varchar(180) PRIMARY KEY, owner_job_id varchar(36),
                expires_at timestamptz, generation bigint NOT NULL);
            CREATE TABLE job_steps(id varchar(36) PRIMARY KEY, created_at timestamptz NOT NULL,
                job_id varchar(36) NOT NULL, name varchar(80) NOT NULL, sequence integer NOT NULL,
                state varchar(20) NOT NULL, attempt integer NOT NULL, fencing_token bigint NOT NULL,
                evidence json NOT NULL, completed_at timestamptz);
            CREATE TABLE job_events(id varchar(36) PRIMARY KEY, created_at timestamptz NOT NULL,
                job_id varchar(36) NOT NULL, sequence integer NOT NULL, phase varchar(40) NOT NULL,
                code varchar(80) NOT NULL, progress json NOT NULL);
            CREATE TABLE audit_events(id varchar(36) PRIMARY KEY, created_at timestamptz NOT NULL,
                actor_id varchar(36), action varchar(60) NOT NULL, object_id varchar(100) NOT NULL,
                outcome varchar(40) NOT NULL, changes json NOT NULL);
            CREATE TABLE sessions(id varchar(36) PRIMARY KEY, created_at timestamptz NOT NULL,
                user_id varchar(36) NOT NULL, token_hash varchar(64) NOT NULL, csrf_hash varchar(64) NOT NULL,
                expires_at timestamptz NOT NULL, revoked_at timestamptz);
            CREATE TABLE oauth_states(id varchar(36) PRIMARY KEY, created_at timestamptz NOT NULL,
                destination_id varchar(36) NOT NULL, session_id varchar(36) NOT NULL,
                state_hash varchar(64) NOT NULL, verifier_secret_id varchar(36) NOT NULL,
                expires_at timestamptz NOT NULL, consumed_at timestamptz);
            CREATE TABLE restore_plans(id varchar(36) PRIMARY KEY, consumed_at timestamptz);
            CREATE TABLE deletion_plans(id varchar(36) PRIMARY KEY, consumed_at timestamptz);""")
            current = connection.execute("SELECT now()").fetchone()[0]
            connection.execute("""INSERT INTO jobs
                (id,created_at,kind,state,phase,idempotency_scope,idempotency_key,request_hash,request,
                 fencing_token,attempts,reconcile_required,content_commit,required_copy_outcome,
                 source_service_outcome,target_activation_outcome,result)
                VALUES (%s,%s,'restore','queued','queued','recovery','never-issued',%s,
                        '{"snapshot_id":"synthetic"}'::json,0,0,false,'unknown','unknown','unknown','not_started','{}'::json)""",
                (unstarted_restore_id, current, "a" * 64))
            connection.execute("""INSERT INTO jobs
                (id,created_at,kind,state,phase,idempotency_scope,idempotency_key,request_hash,request,
                 lease_owner,lease_expires_at,fencing_token,attempts,started_at,reconcile_required,
                 content_commit,required_copy_outcome,source_service_outcome,target_activation_outcome,result)
                VALUES (%s,%s,'restore','running','switching','recovery','possibly-issued',%s,
                        '{"snapshot_id":"synthetic"}'::json,'old-worker',%s,5,1,%s,false,
                        'unknown','unknown','unknown','not_started','{}'::json)""",
                (issued_restore_id, current, "b" * 64, current, current))
            connection.execute("INSERT INTO job_resources VALUES (%s,%s)", (unstarted_restore_id, "instance:queued"))
            connection.execute("INSERT INTO resource_leases VALUES (%s,NULL,NULL,0)", ("instance:queued",))
            connection.execute("INSERT INTO job_resources VALUES (%s,%s)", (issued_restore_id, issued_resource_key))
            connection.execute("INSERT INTO resource_leases VALUES (%s,%s,%s,5)",
                               (issued_resource_key, issued_restore_id, current))
            connection.execute("""INSERT INTO job_steps
                (id,created_at,job_id,name,sequence,state,attempt,fencing_token,evidence)
                VALUES (%s,%s,%s,'switch_generation',1,'started',1,5,'{}'::json)""",
                (str(uuid.uuid4()), current, issued_restore_id))
            connection.execute("""INSERT INTO sessions
                (id,created_at,user_id,token_hash,csrf_hash,expires_at)
                VALUES (%s,%s,'synthetic-user','t','c',%s)""", (session_id, current, current))
            connection.execute("""INSERT INTO oauth_states
                (id,created_at,destination_id,session_id,state_hash,verifier_secret_id,expires_at)
                VALUES (%s,%s,'synthetic-destination',%s,'s','v',%s)""",
                (oauth_state_id, current, session_id, current))
            connection.execute("INSERT INTO restore_plans VALUES ('synthetic-restore-plan',NULL)")
            connection.execute("INSERT INTO deletion_plans VALUES ('synthetic-deletion-plan',NULL)")
        yield DisposableDatabases(
            source_url.render_as_string(hide_password=False),
            target_url.render_as_string(hide_password=False),
            unstarted_restore_id,
            issued_restore_id,
            issued_resource_key,
            session_id,
            oauth_state_id,
        )
    finally:
        for name in made:
            _drop_db(database_url, name)


@pytest.mark.integration
def test_real_pg_snapshot_catalog_restic_readback_and_empty_db_restore(
    disposable_controller_databases, tmp_path
):
    source_url, target_url = (
        disposable_controller_databases.source_url,
        disposable_controller_databases.target_url,
    )
    controller_id, destination_id, snapshot_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    recovery_root = layout.new_recovery_root_secret()
    physical_identity = "c" * 64
    job_root = tmp_path / "controller-job"
    job_root.mkdir(mode=0o700)
    stage = job_root / "controller-backup"
    stage.mkdir(mode=0o700)
    captured = datetime.now(UTC)
    info, tables, rows, dump_bytes, catalog_hash = _capture_postgres(
        source_url,
        stage,
        controller_id=controller_id,
        captured_at=captured,
        snapshot_uuid=snapshot_id,
        max_bytes=32 * 1024 * 1024,
    )
    assert not (stage / "pgpass").exists()
    assert tables >= 7 and rows >= 6 and info["alembic_version"] == "synthetic_revision"
    _seal_catalog(
        stage / "catalog.plain.json",
        stage,
        root_secret=recovery_root,
        controller_id=controller_id,
        physical_identity=physical_identity,
        snapshot_id=snapshot_id,
        max_bytes=32 * 1024 * 1024,
    )
    files = file_inventory(stage)
    inventory = {
        "format": _FORMAT,
        "schema_version": _SCHEMA,
        "controller_uuid": controller_id,
        "snapshot_uuid": snapshot_id,
        "files": files,
    }
    inventory_hash = hashlib.sha256(canonical_json(inventory)).hexdigest()
    (stage / "controller-inventory.json").write_bytes(canonical_json(inventory))
    body = {
        "format": _FORMAT,
        "schema_version": _SCHEMA,
        "controller_uuid": controller_id,
        "destination_id": destination_id,
        "repository_identity": physical_identity,
        "snapshot_uuid": snapshot_id,
        "captured_at": captured.isoformat().replace("+00:00", "Z"),
        "alembic_version": info["alembic_version"],
        "postgres_server_version_num": info["server_version_num"],
        "tables": tables,
        "rows": rows,
        "pg_dump": {
            "path": "database.dump",
            "bytes": dump_bytes,
            "sha256": hashlib.sha256((stage / "database.dump").read_bytes()).hexdigest(),
            "format": "PostgreSQL custom archive",
        },
        "catalog": {
            "format": "vaultrewind-controller-catalog",
            "schema_version": 1,
            "plaintext_sha256": catalog_hash,
            "independently_sealed": True,
        },
        "inventory_sha256": inventory_hash,
    }
    manifest_hash = hashlib.sha256(canonical_json(body)).hexdigest()
    (stage / "controller-manifest.json").write_bytes(canonical_json({**body, "manifest_hash": manifest_hash}))

    settings = SimpleNamespace(staging_dir=tmp_path / "job-staging")
    repository_work = _controller_repository_work_dir(
        SimpleNamespace(root=job_root, id=str(uuid.uuid4())), settings
    )
    assert not repository_work.is_relative_to(job_root)
    assert not repository_work.is_relative_to(settings.staging_dir)
    assert not repository_work.is_relative_to(stage)
    repository = ResticRepository(
        RepositoryConfig(
            location=str(tmp_path / "restic"),
            password="synthetic-controller-repository-password",
            instance_uuid=controller_id,
            runtime_dir=repository_work / "runtime",
            cache_dir=repository_work / "cache",
        )
    )
    committed = commit_controller_snapshot(
        repository,
        stage,
        controller_id=controller_id,
        destination_id=destination_id,
        snapshot_uuid=snapshot_id,
        captured_at=captured.isoformat().replace("+00:00", "Z"),
        manifest_hash=manifest_hash,
    )
    assert committed["restic_snapshot_id"] and committed["files"] >= 3
    replayed = commit_controller_snapshot(
        repository,
        stage,
        controller_id=controller_id,
        destination_id=destination_id,
        snapshot_uuid=snapshot_id,
        captured_at=captured.isoformat().replace("+00:00", "Z"),
        manifest_hash=manifest_hash,
    )
    assert replayed["restic_snapshot_id"] == committed["restic_snapshot_id"] and replayed["reconciled"]
    recovered = tmp_path / "restored"
    validated = restore_controller_snapshot(
        repository, committed["restic_snapshot_id"], recovered, expected_manifest_hash=manifest_hash
    )
    assert validated["verified"] and (recovered / "database.dump").stat().st_size == dump_bytes
    catalog = decrypt_catalog(
        recovered,
        recovery_root_secret=recovery_root,
        controller_id=controller_id,
        repository_identity=physical_identity,
        snapshot_uuid=snapshot_id,
    )
    assert catalog["rows"] == rows and catalog["tables"] == tables
    secret_table = next(
        table for table in catalog["catalog"]["tables"] if table["name"] == "controller_secrets"
    )
    assert secret_table["rows"] == [[1, "synthetic-secret-row"]]
    catalog["path"].unlink()

    with pytest.raises(VaultRewindError) as denied:
        restore_dump_to_empty_database(recovered / "database.dump", target_url)
    assert denied.value.code == "CONTROLLER_RESTORE_AUTH_REQUIRED"
    result = restore_dump_to_empty_database(
        recovered / "database.dump", target_url, operator_authorized=True, source_database_url=source_url
    )
    assert (
        result["policies_disabled"] and result["imported_snapshots_held"] and not result["workers_may_resume"]
    )
    assert result["jobs_cancelled_unstarted"] == 1
    assert result["jobs_held_for_reconciliation"] == 1
    with _connect(target_url) as connection:
        assert (
            connection.execute("SELECT value FROM vault_rows WHERE id=1").fetchone()[0]
            == "synthetic-catalog-fixture"
        )
        assert connection.execute("SELECT enabled FROM backup_policies WHERE id='p1'").fetchone()[0] is False
        assert connection.execute("SELECT imported FROM snapshots WHERE id='s1'").fetchone()[0] is True
        assert (
            connection.execute("SELECT reason FROM snapshot_protections WHERE snapshot_id='s1'").fetchone()[0]
            == "imported_review"
        )
        unstarted = connection.execute(
            "SELECT state,error_code,reconcile_required,lease_owner,lease_expires_at "
            "FROM jobs WHERE id=%s", (disposable_controller_databases.unstarted_restore_id,)
        ).fetchone()
        assert unstarted == ("cancelled", "CONTROLLER_RECOVERY_REVIEW_REQUIRED", False, None, None)
        issued = connection.execute(
            "SELECT state,error_code,reconcile_required,lease_owner,lease_expires_at "
            "FROM jobs WHERE id=%s", (disposable_controller_databases.issued_restore_id,)
        ).fetchone()
        assert issued == ("needs_attention", "CONTROLLER_RECOVERY_REVIEW_REQUIRED", True, None, None)
        lease = connection.execute(
            "SELECT owner_job_id,expires_at FROM resource_leases WHERE resource_key=%s",
            (disposable_controller_databases.issued_resource_key,),
        ).fetchone()
        assert lease == (disposable_controller_databases.issued_restore_id, None)
        assert connection.execute(
            "SELECT code FROM job_events WHERE job_id=%s",
            (disposable_controller_databases.unstarted_restore_id,),
        ).fetchone()[0] == "CONTROLLER_RECOVERY_REVIEW_REQUIRED"
        assert connection.execute(
            "SELECT count(*) FROM audit_events WHERE action='controller_recovery.job_quarantine'"
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT revoked_at IS NOT NULL FROM sessions WHERE id=%s",
            (disposable_controller_databases.session_id,),
        ).fetchone()[0]
        assert connection.execute(
            "SELECT consumed_at IS NOT NULL FROM oauth_states WHERE id=%s",
            (disposable_controller_databases.oauth_state_id,),
        ).fetchone()[0]
        assert connection.execute(
            "SELECT consumed_at IS NOT NULL FROM restore_plans WHERE id='synthetic-restore-plan'"
        ).fetchone()[0]
        assert connection.execute(
            "SELECT consumed_at IS NOT NULL FROM deletion_plans WHERE id='synthetic-deletion-plan'"
        ).fetchone()[0]

    # The restored queue must not claim either the old unstarted destructive intent or
    # uncertain work before an operator explicitly requests reconciliation.
    engine = make_engine(target_url)
    try:
        with sessions(engine).begin() as db:
            assert claim(db, "recovery-probe") is None
    finally:
        engine.dispose()

    # Reapplying the hold is safe and does not duplicate quarantine audit records.
    reapplied = hold_restored_policies(target_url)
    assert reapplied["workers_may_resume"] is False
    with _connect(target_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM audit_events WHERE action='controller_recovery.job_quarantine'"
        ).fetchone()[0] == 2


def test_database_restore_refuses_source_database_even_with_operator_authorization():
    with pytest.raises(VaultRewindError) as error:
        restore_dump_to_empty_database(
            Path("/no-dump"),
            "postgresql://u@localhost/source",
            operator_authorized=True,
            source_database_url="postgresql://u@localhost/source",
        )
    assert error.value.code == "CONTROLLER_RESTORE_TARGET_INVALID"

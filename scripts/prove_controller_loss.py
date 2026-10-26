#!/usr/bin/env python3
"""Synthetic AC30 drill: API kit export, independent offline restore, fresh PG API import.

The default stage exports and imports without changing an application. An
explicit application stage uses a separately coordinated disposable helper target.
Secrets are read/written through private files and never printed or passed in argv.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

PROJECT = Path(__file__).resolve().parents[1]
TERMINAL = {"succeeded", "failed", "partial", "cancelled", "rolled_back", "rollback_failed", "needs_attention"}


class DrillError(Exception):
    """Contains only an intentionally public stage/code; never a raw tool exception."""


def private_write(path: Path, value: bytes | str | dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if isinstance(value, dict):
        value = json.dumps(value, indent=2).encode()
    if isinstance(value, str):
        value = value.encode()
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as out:
        out.write(value)


def private_read(path: Path) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        if os.fstat(source.fileno()).st_mode & 0o077:
            raise DrillError("PRIVATE_INPUT_PERMISSIONS")
        return source.read()


def request(client, method: str, path: str, *, expected=200, body=None, key=None):
    headers = {"Idempotency-Key": key or str(uuid4())} if method != "GET" else {}
    response = client.request(method, "/api/v1" + path, json=body, headers=headers)
    if response.status_code != expected:
        try:
            code = response.json().get("error", {}).get("code", "HTTP_ERROR")
        except (ValueError, AttributeError):
            code = "HTTP_ERROR"
        raise DrillError(f"{method} {path}: HTTP {response.status_code} {code}")
    return response.json()


def wait_job(client, accepted, worker=None, timeout=900):
    ident = accepted["job_id"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = request(client, "GET", f"/jobs/{ident}")
        if job["state"] in TERMINAL:
            if job["state"] != "succeeded":
                raise DrillError(f"JOB {ident}: {job['state']} {job.get('error_code')}")
            return job
        if worker is not None:
            if not worker.run_once():
                time.sleep(0.25)
        else:
            time.sleep(1)
    raise DrillError(f"JOB {ident}: TIMEOUT")


def clean_environment() -> dict:
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("VAULTREWIND_", "PG", "RESTIC_", "RCLONE_"))}


def provision(args) -> None:
    """Export only; obtain DB connection auth without querying the source DB."""
    run = args.run_dir.resolve()
    run.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(run, 0o700)
    # The private source URL is used ONLY to retain transport authentication and
    # replace the database name; neither SQLAlchemy nor psycopg opens it here.
    source_url = make_url(private_read(args.connection_auth_file).decode().strip())
    target_name = "vr_loss_" + uuid4().hex[:20]
    target_url = source_url.set(database=target_name)
    assert target_url.database != source_url.database
    result = subprocess.run(["runuser", "-u", "postgres", "--", "createdb", "--owner", source_url.username,
                             target_name], capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise DrillError("DISPOSABLE_POSTGRES_CREATE_FAILED")
    private_write(run / "database-url", target_url.render_as_string(hide_password=False))
    del source_url, target_url
    private_write(run / "master", secrets.token_bytes(32))
    private_write(run / "bootstrap", secrets.token_urlsafe(48))
    private_write(run / "owner-password", secrets.token_urlsafe(40))
    private_write(run / "kit-passphrase", secrets.token_urlsafe(48))
    cookies = json.loads(private_read(args.source_session_file))
    with httpx.Client(base_url=args.source_origin, cookies=cookies, timeout=30,
                      headers={"Origin": args.source_origin, "X-CSRF-Token": cookies["vr_csrf"]}) as client:
        selected = request(client, "GET", f"/instances/{args.instance}/snapshots")
        available = [s for s in selected["items"] if s["completeness"] == "complete" and not s["safety"]]
        snapshot = next((s for s in available if s["id"] == args.snapshot), None) if args.snapshot else None
        if args.snapshot and snapshot is None:
            raise DrillError("REQUESTED_SNAPSHOT_NOT_AVAILABLE")
        snapshot = snapshot or (available[0] if available else None)
        if not snapshot:
            raise DrillError("NO_COMPLETE_SYNTHETIC_SNAPSHOT")
        exported = wait_job(client, request(client, "POST", "/recovery-kits/export", expected=202,
            body={"passphrase": private_read(run / "kit-passphrase").decode()}))
        artifact = client.get(f"/api/v1/jobs/{exported['id']}/artifact")
        if artifact.status_code != 200:
            raise DrillError("KIT_ARTIFACT_UNAVAILABLE")
        private_write(run / "recovery-kit.enc", artifact.content)
        # Export/readback is the final operation allowed against the old API.
    private_write(run / "fresh-input.json", {
        "instance_id": args.instance, "snapshot_id": snapshot["id"], "captured_at": snapshot["captured_at"],
        "image_id": snapshot["image_id"], "export_job_id": exported["id"],
        "old_private_directory": str(args.source_session_file.resolve().parent),
        "target_database": target_name,
    })
    print("Independent kit exported; starting fresh-controller stage.", flush=True)
    child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--fresh-stage", str(run),
                            "--evidence", str(args.evidence.resolve())], env=clean_environment(),
                           check=False)
    if child.returncode:
        raise DrillError("FRESH_STAGE_FAILED (private state retained for diagnosis)")


def deny_original_reads(old_directory: Path) -> list:
    """Fail before opening old key/session/URL files in this fresh process."""
    denied = []
    old_directory = old_directory.resolve()

    def guard(event, args):
        if event != "open" or not args or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        path = Path(os.fsdecode(args[0])).absolute()
        if path == old_directory or old_directory in path.parents:
            denied.append("original_private_directory")
            raise DrillError("ORIGINAL_CONTROLLER_FILE_ACCESS_DENIED")

    sys.addaudithook(guard)
    return denied


def offline_cli(run: Path, *arguments) -> dict:
    """Run the shipped CLI entrypoint and keep its potentially private output private."""
    from vaultrewind.recovery.cli import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = main(list(arguments))
    if status:
        raise DrillError("OFFLINE_CLI_FAILED")
    return json.loads(out.getvalue())


def save_checkpoint(path: Path, value: dict) -> None:
    from vaultrewind.security.privatefiles import atomic_private_write
    atomic_private_write(path, json.dumps(value, indent=2).encode())


@contextlib.contextmanager
def resumed_controller(run: Path):
    """Reopen only the independent controller and enforce its original-file boundary."""
    from vaultrewind.server.db import make_engine
    from vaultrewind.server.settings import Settings
    from vaultrewind.server.worker import Worker

    config = json.loads(private_read(run / "fresh-input.json"))
    denied = deny_original_reads(Path(config["old_private_directory"]))
    for key in list(os.environ):
        if key.startswith(("VAULTREWIND_", "PG", "RESTIC_", "RCLONE_")):
            del os.environ[key]
    database_url = private_read(run / "database-url").decode().strip()
    if make_url(database_url).database != config["target_database"]:
        raise DrillError("FRESH_DATABASE_IDENTITY_MISMATCH")
    origin = private_read(run / "fresh-origin").decode()
    settings = Settings(database_url=database_url, master_key_file=run / "master",
        bootstrap_secret_file=run / "bootstrap", public_origin=origin, secure_cookies=False,
        local_storage_root=run / "new-backups", staging_dir=run / "fresh-staging", min_free_bytes=0,
        helper_bundle_dir=PROJECT / ".runtime/helper-bundle")
    engine = make_engine(database_url)
    worker = Worker(settings, engine=engine)
    environment = clean_environment()
    environment.update({"VAULTREWIND_DATABASE_URL": database_url, "VAULTREWIND_MASTER_KEY_FILE": str(run / "master"),
        "VAULTREWIND_BOOTSTRAP_SECRET_FILE": str(run / "bootstrap"), "VAULTREWIND_PUBLIC_ORIGIN": origin,
        "VAULTREWIND_SECURE_COOKIES": "false", "VAULTREWIND_LOCAL_STORAGE_ROOT": str(run / "new-backups"),
        "VAULTREWIND_STAGING_DIR": str(run / "fresh-staging"), "VAULTREWIND_MIN_FREE_BYTES": "0",
        "VAULTREWIND_HELPER_BUNDLE_DIR": str(settings.helper_bundle_dir)})
    with (run / "application-api.log").open("ab") as log:
        os.chmod(run / "application-api.log", 0o600)
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "vaultrewind.server.app:create_app", "--factory",
            "--host", "127.0.0.1", "--port", str(urlsplit(origin).port), "--no-access-log"],
            cwd=PROJECT, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    try:
        cookies = json.loads(private_read(run / "fresh-session.json"))
        with httpx.Client(base_url=origin, timeout=60, cookies=cookies,
                          headers={"Origin": origin, "X-CSRF-Token": cookies["vr_csrf"]}) as client:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    if client.get("/api/v1/health/live").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.2)
            else:
                raise DrillError("FRESH_HTTP_SERVER_UNAVAILABLE")
            request(client, "GET", "/sessions/current")
            yield config, client, worker, denied
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=15)
        engine.dispose()


# Fixed read-only program; all dynamic input uses JSON stdin, never shell/argv.
# It reads only the selected target's approved data root/container and emits
# counts, hashes and booleans, never rows, environment values, or filenames.
TARGET_READBACK = r'''
import hashlib,json,pathlib,sqlite3,subprocess,sys,urllib.request
v=json.load(sys.stdin)
root=pathlib.Path(v['root']).resolve(strict=True)
missing=bad=checked=0
for item in v['files']:
    rel=pathlib.PurePosixPath(item['path'])
    if rel.is_absolute() or '..' in rel.parts: raise ValueError('path')
    path=root.joinpath(*rel.parts)
    if not path.is_file(): missing+=1; continue
    if not path.resolve(strict=True).is_relative_to(root): raise ValueError('boundary')
    checked+=1
    if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']: bad+=1
counts={}
with sqlite3.connect('file:'+str(root/'db.sqlite3')+'?mode=ro',uri=True) as db:
    db.execute('PRAGMA query_only=ON')
    integrity=db.execute('PRAGMA integrity_check').fetchone()[0]
    for table in v['rows']:
        counts[table]=db.execute('SELECT count(*) FROM "'+table.replace('"','""')+'"').fetchone()[0]
raw=subprocess.run(['/usr/bin/docker','inspect',v['name']],capture_output=True,check=True,timeout=30).stdout
c=json.loads(raw)[0]
env=dict(x.split('=',1) for x in c['Config'].get('Env',[]) if '=' in x)
alive=config_ready=False
app_config={}
public_probe_errors=[]
try:
    with urllib.request.urlopen('http://127.0.0.1:'+str(v['port'])+'/alive',timeout=10) as r:
        alive=r.status==200
except Exception as error:
    public_probe_errors.append({'check':'alive','error_type':type(error).__name__})
try:
    with urllib.request.urlopen('http://127.0.0.1:'+str(v['port'])+'/api/config',timeout=10) as r:
        app_config=json.load(r); config_ready=r.status==200 and isinstance(app_config,dict) and bool(app_config.get('version'))
except Exception as error:
    public_probe_errors.append({'check':'config','error_type':type(error).__name__})
public_environment=app_config.get('environment') or {}
public_url_matches=public_environment.get('api','').rstrip('/').removesuffix('/api')==v['domain'].rstrip('/')
print(json.dumps({'regular_files_checked':checked,'missing_files':missing,'mismatched_files':bad,
 'sqlite_integrity':integrity,'selected_tables_checked':len(counts),'selected_table_counts_match':counts==v['rows'],
 'recorded_image_matches':c['Image']==v['image'],'running':c['State']['Running'],
 'target_instance_label_matches':c['Config'].get('Labels',{}).get('org.vaultrewind.instance')==v['instance_id'],
 'target_operation_label_matches':c['Config'].get('Labels',{}).get('org.vaultrewind.operation')==v['operation_id'],
 'target_public_url_matches':env.get('DOMAIN')==v['domain'],'public_http_alive':alive,
 'public_application_config_ready':config_ready,'public_application_url_matches':public_url_matches,
 'public_probe_errors':public_probe_errors}))
'''


JOURNAL_READBACK = r'''
import hashlib,json,pathlib,re
root=pathlib.Path('/var/lib/vaultrewind-helper/journals')
result={}
for path in root.glob('*.json'):
    if not re.fullmatch('[0-9a-f-]{36}\\.json',path.name) or path.is_symlink(): raise ValueError('journal')
    result[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(result))
'''


def journal_readback(descriptor: dict) -> dict:
    """Read existing helper journals without reconciling or modifying them."""
    import shlex

    import asyncssh

    host = descriptor["host_create"]
    credential = host["activation_credential"]

    async def read():
        pinned = asyncssh.import_public_key(host["host_public_key"])
        key = asyncssh.import_private_key(credential["private_key"], credential.get("passphrase"))
        prefix = "/usr/bin/python3 -I -c " if credential["username"] == "root" else "sudo -n -- /usr/bin/python3 -I -c "
        async with asyncssh.connect(host["endpoint"], port=host["port"], username=credential["username"],
                client_keys=[key], known_hosts=([pinned], [], []), config=[], agent_path=None,
                agent_forwarding=False, connect_timeout=20) as connection:
            result = await connection.run(prefix + shlex.quote(JOURNAL_READBACK), check=False, timeout=60)
            if result.exit_status:
                raise DrillError("EXISTING_JOURNAL_READBACK_FAILED")
            return json.loads(result.stdout)

    return asyncio.run(read())


def target_readback(descriptor: dict, run: Path, config: dict, operation_id: str) -> dict:
    import shlex

    import asyncssh

    profile = descriptor["policy"]["instances"][descriptor["remote_instance_id"]]
    mounts = [m for m in profile["mounts"] if m["snapshot_path"] == "data"]
    if len(mounts) != 1 or mounts[0]["type"] != "bind":
        raise DrillError("READBACK_REQUIRES_APPROVED_BIND_FIXTURE")
    manifest = json.loads((run / "offline-restored/manifest/manifest.json").read_bytes())
    files = [{"path": i["path"].removeprefix("/").removeprefix("data/"), "sha256": i["sha256"]}
             for i in manifest["inventory"] if i["type"] == "file" and i["path"].lstrip("/").startswith("data/")
             and i["path"].split("/")[-1] not in {"db.sqlite3", "db.sqlite3-wal", "db.sqlite3-shm"}]
    rows = {}
    with sqlite3.connect(f"file:{run / 'offline-restored/data/db.sqlite3'}?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in sorted(tables & {"users", "organizations", "ciphers", "attachments", "sends"}):
            rows[table] = db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
    recovery = profile["recovery_profile"]
    bindings = recovery.get("port_bindings") or profile["port_bindings"]
    port = bindings["80/tcp"][0]["HostPort"]
    payload = {"root": mounts[0]["source"], "files": files, "rows": rows, "name": profile["container_name"],
               "image": config["image_id"], "instance_id": descriptor["remote_instance_id"],
               "operation_id": operation_id, "port": port, "domain": recovery["environment"]["DOMAIN"]}
    host = descriptor["host_create"]
    credential = host["activation_credential"]

    async def read():
        pinned = asyncssh.import_public_key(host["host_public_key"])
        key = asyncssh.import_private_key(credential["private_key"], credential.get("passphrase"))
        prefix = "/usr/bin/python3 -I -c " if credential["username"] == "root" else "sudo -n -- /usr/bin/python3 -I -c "
        async with asyncssh.connect(host["endpoint"], port=host["port"], username=credential["username"],
                client_keys=[key], known_hosts=([pinned], [], []), config=[], agent_path=None,
                agent_forwarding=False, connect_timeout=20) as connection:
            result = await connection.run(prefix + shlex.quote(TARGET_READBACK), input=json.dumps(payload), check=False, timeout=90)
            if result.exit_status:
                import re
                frames = re.findall(r'File "[^"]+", line (\d+)', result.stderr)
                final = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ""
                kind = re.match(r"([A-Za-z_.]+):", final)
                status = re.search(r"HTTP Error (\d+)", final)
                diagnostic = {"exit_status": result.exit_status, "error_type": kind.group(1) if kind else "unknown",
                              "line_numbers": [int(line) for line in frames],
                              "http_status": int(status.group(1)) if status else None}
                save_checkpoint(run / "target-readback-diagnostic.json", diagnostic)
                raise DrillError("TARGET_READBACK_FAILED")
            return json.loads(result.stdout)

    return asyncio.run(read())


def application_stage(run: Path, target_file: Path, evidence_path: Path, *, execute: bool) -> None:
    from vaultrewind.server.models import ActivationPlan, BackupPolicy, Job, SnapshotProtection

    report = json.loads(evidence_path.read_bytes())
    stage = report["application_restore"]
    checkpoint_path = None
    checkpoint = {}
    report["overall"] = "partial"
    denied = []
    try:
        with resumed_controller(run) as (config, client, worker, denied):
            descriptor = json.loads(private_read(target_file))
            target_id = descriptor["remote_instance_id"]
            if target_id == config["instance_id"] or target_id not in descriptor["policy"]["instances"]:
                raise DrillError("ONLY_SEPARATE_PREPARED_TARGET_ALLOWED")
            previous_target = stage.get("target_id")
            if previous_target and previous_target != target_id:
                # An explicitly supplied new descriptor starts a new attempt. Keep
                # the prior activated target and its observed outcome immutable.
                history = report.setdefault("application_attempts", [])
                identity = (previous_target, stage.get("restore_job_id"))
                if not any((item.get("target_id"), item.get("restore_job_id")) == identity for item in history):
                    history.append(json.loads(json.dumps(stage)))
                stage = {"state": "preparing", "user_login_tested": False, "application_started": False}
                report["application_restore"] = stage
            stage.update(state="preparing", user_login_tested=False, application_started=False)
            checkpoint_path = run / f"application-checkpoint-{target_id}.json"
            legacy = run / "application-checkpoint.json"
            if legacy.exists() and json.loads(private_read(legacy)).get("target_id") == target_id:
                checkpoint_path = legacy
            checkpoint = json.loads(private_read(checkpoint_path)) if checkpoint_path.exists() else {}
            if checkpoint.get("target_id", target_id) != target_id:
                raise DrillError("APPLICATION_TARGET_CHANGED")
            if checkpoint.get("snapshot_id", config["snapshot_id"]) != config["snapshot_id"]:
                raise DrillError("APPLICATION_SNAPSHOT_CHANGED")
            checkpoint["target_id"] = target_id
            checkpoint["snapshot_id"] = config["snapshot_id"]
            stage.pop("original_source_changed", None)
            stage.update(target_id=target_id, snapshot_id=config["snapshot_id"], original_source_targeted=False,
                         application_mutation_target="explicitly approved disposable VM target only",
                         private_checkpoint=checkpoint_path.name)
            evidence_path.write_text(json.dumps(report, indent=2) + "\n")
            if "host_id" not in checkpoint:
                host = request(client, "POST", "/hosts", expected=201, body=descriptor["host_create"])
                checkpoint["host_id"] = host["id"]
                save_checkpoint(checkpoint_path, checkpoint)
            host_id = checkpoint["host_id"]
            if "administrative_discovery_job_id" not in checkpoint:
                accepted = request(client, "POST", f"/hosts/{host_id}/discover", expected=202, body={})
                checkpoint["administrative_discovery_job_id"] = accepted["job_id"]
                save_checkpoint(checkpoint_path, checkpoint)
            job_id = checkpoint["administrative_discovery_job_id"]
            wait_job(client, {"job_id": job_id}, worker)
            with worker.sessions() as db:
                discovery = db.get(Job, job_id)
                facts = worker.store.get(db, discovery.result["private_evidence_id"])
                if facts.get("pending_operations"):
                    raise DrillError("HOST_NOT_READY_FOR_REVIEWED_ACTIVATION")
                if not set(facts["installed_instances"]) <= set(descriptor["policy"]["instances"]):
                    raise DrillError("APPROVED_POLICY_OMITS_EXISTING_INSTANCE")
                stage["previously_installed_profiles_preserved"] = len(facts["installed_instances"])
            stage.update(host_id=host_id, administrative_discovery_job_id=job_id)
            if not execute:
                stage.update(state="prepared", reason="Read-only setup complete; awaiting coordinated helper bundle before activation/restore.")
                print("Fresh host registered and read-only administrative discovery passed. No activation or restore started.")
                return
            if "existing_journals" not in checkpoint:
                checkpoint["existing_journals"] = journal_readback(descriptor)
                save_checkpoint(checkpoint_path, checkpoint)
            if "activation_job_id" not in checkpoint:
                plan_job = wait_job(client, request(client, "POST", f"/hosts/{host_id}/activation-plans", expected=202,
                                                   body={"policy": descriptor["policy"]}), worker)
                plan = plan_job["result"]
                with worker.sessions() as db:
                    reviewed = db.get(ActivationPlan, plan["plan_id"])
                    private = worker.store.get(db, reviewed.secret_id)
                    if private["policy"] != descriptor["policy"]:
                        raise DrillError("REVIEWED_POLICY_DIFFERS_FROM_APPROVED_INSTALLED_POLICY")
                    stage["reviewed_helper_bundle_sha256"] = private["bundle_sha256"]
                    stage["policy_entries_preserved"] = len(private["policy"]["instances"])
                accepted = request(client, "POST", f"/hosts/{host_id}/activate", expected=202,
                    body={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
                checkpoint["activation_job_id"] = accepted["job_id"]
                save_checkpoint(checkpoint_path, checkpoint)
            wait_job(client, {"job_id": checkpoint["activation_job_id"]}, worker)
            stage["activation_job_id"] = checkpoint["activation_job_id"]
            if "target_discovery_job_id" not in checkpoint:
                accepted = request(client, "POST", f"/hosts/{host_id}/discover", expected=202, body={"instance_id": target_id})
                checkpoint["target_discovery_job_id"] = accepted["job_id"]
                save_checkpoint(checkpoint_path, checkpoint)
            discovered = wait_job(client, {"job_id": checkpoint["target_discovery_job_id"]}, worker)
            with worker.sessions() as db:
                job = db.get(Job, discovered["id"])
                facts = worker.store.get(db, job.result["private_evidence_id"])
                if not checkpoint.get("restore_job_id") and not facts.get("empty_target"):
                    raise DrillError("RECOVERY_TARGET_NOT_EMPTY")
                if facts.get("restore_ready") is not True:
                    raise DrillError("RECOVERY_TARGET_PUBLIC_NETWORK_NOT_READY")
                stage["preflight_restore_ready"] = True
            enrolled = client.get(f"/api/v1/instances/{target_id}")
            if enrolled.status_code == 404:
                enrollment = request(client, "GET", f"/jobs/{discovered['id']}/enrollment")
                request(client, "POST", "/instances", expected=201, body={"host_id": host_id, "name": descriptor["name"],
                    "container_id": descriptor["container_id"], "configuration": enrollment["configuration"]})
                target = request(client, "GET", f"/instances/{target_id}")
                # This dedicated recovery target must not gain an unattended backup schedule.
                response = client.patch(f"/api/v1/instances/{target_id}/policy", json={"enabled": False, "retention_days": None},
                    headers={"If-Match": str(target["policy"]["revision"])})
                if response.status_code != 200:
                    raise DrillError("TARGET_POLICY_PAUSE_FAILED")
            elif enrolled.status_code != 200:
                raise DrillError("TARGET_ENROLLMENT_UNAVAILABLE")
            if "restore_job_id" not in checkpoint:
                plan = request(client, "POST", f"/snapshots/{config['snapshot_id']}/restore-plans", expected=201,
                    body={"target_id": target_id, "start_on_completion": True})
                if plan["snapshot_id"] != config["snapshot_id"] or plan["target_id"] != target_id:
                    raise DrillError("RESTORE_PLAN_IDENTITY_MISMATCH")
                accepted = request(client, "POST", f"/restore-plans/{plan['id']}/execute", expected=202,
                    body={"confirmation_token": plan["confirmation_token"]})
                checkpoint["restore_job_id"] = accepted["job_id"]
                save_checkpoint(checkpoint_path, checkpoint)
            restore_id = checkpoint["restore_job_id"]
            stage.update(state="running", reason="Actual prepared-target restore is in progress.",
                         restore_job_id=restore_id, target_discovery_job_id=discovered["id"])
            evidence_path.write_text(json.dumps(report, indent=2) + "\n")
            restored = wait_job(client, {"job_id": restore_id}, worker, timeout=1800)
            result = restored["result"]
            if (not all(result.get(k) for k in ("candidate_validated", "activation_started", "restored_bytes_verified", "application_started",
                                               "public_ports_verified", "public_endpoint_verified"))
                    or restored["target_activation_outcome"] != "complete"):
                raise DrillError("APPLICATION_RESTORE_INVARIANTS_INCOMPLETE")
            remote, remote_id = worker.adapters.remote(host_id, target_id)
            with worker.sessions() as db:
                token = db.get(Job, restore_id).fencing_token
                holds = set(db.scalars(select(SnapshotProtection.reason).where(SnapshotProtection.snapshot_id == config["snapshot_id"])))
                source_policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == config["instance_id"]))
                if "import_review" not in holds or source_policy.enabled or source_policy.retention_days is not None:
                    raise DrillError("IMPORTED_PROTECTION_CHANGED")
                storage_probes = [{"job_id": job.id, "state": job.state, "error_code": job.error_code}
                                  for job in db.scalars(select(Job).where(Job.kind == "storage_test"))]
            status = asyncio.run(remote.request("status", remote_id, restore_id, token))
            view = asyncio.run(remote.request("discover", remote_id, restore_id, token))
            preflight = asyncio.run(remote.request("preflight", remote_id, restore_id, token,
                                                  {"controller_time": datetime.now(UTC).isoformat()}))
            if (status.get("phase") != "complete" or status.get("manifest_hash") != report["offline_restore"]["manifest_hash"]
                    or not status.get("candidate_validated") or status.get("source_service_outcome") != "running"
                    or status.get("public_ports_verified") is not True or status.get("public_endpoint_verified") is not True
                    or view.get("source_state") != "running" or preflight.get("empty_target") or not preflight.get("recovery_verified")
                    or preflight.get("restore_ready") is not True or preflight.get("current_public_ports_ready") is not True):
                raise DrillError("HELPER_APPLICATION_READBACK_INCOMPLETE")
            readback = target_readback(descriptor, run, config, restore_id)
            stage["target_readback"] = readback
            if (not readback["regular_files_checked"] or not readback["selected_tables_checked"]
                    or readback["missing_files"] or readback["mismatched_files"] or readback["sqlite_integrity"] != "ok"
                    or not all(value for key, value in readback.items() if isinstance(value, bool))):
                raise DrillError("RESTORED_APPLICATION_CONTENT_READBACK_FAILED")
            journals = journal_readback(descriptor)
            if any(journals.get(name) != digest for name, digest in checkpoint["existing_journals"].items()):
                raise DrillError("EXISTING_HELPER_JOURNAL_CHANGED")
            stage.update(state="passed", reason=None, restore_job_state=restored["state"],
                candidate_validated=True, activation_started=True, restored_bytes_verified=True, application_started=True,
                user_login_tested=False, target_activation_outcome=restored["target_activation_outcome"],
                public_ports_verified=True, public_endpoint_verified=True, public_application_verified=True,
                public_http_alive=readback["public_http_alive"],
                active_generation=result["active_generation"], imported_review_hold_preserved=True,
                imported_automatic_retention_disabled=True, helper_phase=status["phase"],
                helper_source_service_outcome=status["source_service_outcome"], helper_recovery_verified=True,
                helper_candidate_validation=status["candidate_validated"], empty_target_before_restore=True,
                existing_helper_journals_preserved=len(checkpoint["existing_journals"]),
                new_backup_storage_probe_outcomes=storage_probes,
                target_readback=readback, completed_at=datetime.now(UTC).isoformat())
            report["overall"] = "passed"
            stage.pop("failure", None)
            print("AC30 passed: fresh-controller helper restore, isolated validation, activation and content/HTTP readback confirmed.")
    except Exception as error:
        stage.update(state="failed", reason="Inspect the durable job/helper outcome before retrying.",
                     failure=str(error) if isinstance(error, DrillError) else type(error).__name__)
        if checkpoint.get("restore_job_id"):
            stage["restore_job_id"] = checkpoint["restore_job_id"]
            # Record the durable outcome even when the API has already stopped.
            # Failure evidence must distinguish rollback from possible activation.
            try:
                with worker.sessions() as db:
                    job = db.get(Job, checkpoint["restore_job_id"])
                    stage.update(restore_job_state=job.state, restore_error_code=job.error_code,
                        target_activation_outcome=job.target_activation_outcome,
                        candidate_validated=bool(job.result.get("candidate_validated")),
                        application_started=bool(job.result.get("application_started")),
                        activation_started=bool(job.result.get("activation_started")))
                    token = job.fencing_token
                remote, remote_id = worker.adapters.remote(checkpoint["host_id"], checkpoint["target_id"])
                status = asyncio.run(remote.request("status", remote_id, checkpoint["restore_job_id"], token))
                stage.update(helper_phase=status.get("phase"), helper_source_service_outcome=status.get("source_service_outcome"),
                             helper_activation_started=bool(status.get("activation_started")))
            except Exception as readback_error:  # noqa: BLE001 - preserve the first failure without private exceptions
                stage["failure_readback"] = type(readback_error).__name__
        raise
    finally:
        stage["old_private_directory_access_attempts"] = len(denied)
        report["recorded_at"] = datetime.now(UTC).isoformat()
        evidence_path.write_text(json.dumps(report, indent=2) + "\n")


def fresh_stage(run: Path, evidence_path: Path) -> None:
    config = json.loads(private_read(run / "fresh-input.json"))
    denied = deny_original_reads(Path(config["old_private_directory"]))
    for key in list(os.environ):
        if key.startswith(("VAULTREWIND_", "PG", "RESTIC_", "RCLONE_")):
            del os.environ[key]
    report = {
        "acceptance": "AC30", "recorded_at": datetime.now(UTC).isoformat(),
        "fixture": "existing synthetic SSH Vaultwarden backup in real encrypted local restic",
        "production_access": False, "source_mutations": False, "overall": "partial",
        "export": {"state": "passed", "authenticated_api": True, "job_id": config["export_job_id"]},
        "fresh_controller": {"state": "pending", "database": "separate randomly named PostgreSQL database",
            "original_database_connected": False, "original_master_key_read": False,
            "new_master_key": True, "new_bootstrap_secret": True, "new_owner_via_api": False,
            "old_private_directory_read_guard": True,
            "isolation_boundary": "after authenticated encrypted-kit download",
            "original_database_url_passed_to_fresh_process": False,
            "original_master_key_passed_to_fresh_process": False,
            "original_controller_environment_removed": True,
            "guard_scope": "offline CLI and worker process; HTTP subprocess receives only fresh controller settings"},
        "offline_restore": {"state": "pending"}, "protected_import": {"state": "pending"},
        "application_restore": {"state": "not_run", "reason": "Requires ROOT-coordinated prepared helper target; no application mutation authorized yet.",
                                "application_started": False, "user_login_tested": False},
    }
    server = None
    engine = None
    try:
        common = ["--kit", str(run / "recovery-kit.enc"), "--passphrase-file", str(run / "kit-passphrase"),
                  "--work-dir", str(run / "offline-work")]
        discovered = offline_cli(run, "discover", *common)
        matching = [s for d in discovered["destinations"] for r in d["repositories"] for s in r["snapshots"]
                    if s["snapshot_uuid"] == config["snapshot_id"] and s["manifest_verified"]]
        if not matching:
            raise DrillError("OFFLINE_SNAPSHOT_NOT_DISCOVERED")
        restored = offline_cli(run, "restore", *common, "--snapshot", config["snapshot_id"],
                               "--target", str(run / "offline-restored"))
        plan = offline_cli(run, "plan", "--restored", str(run / "offline-restored"), "--same-instance")
        if not plan["ready"]:
            raise DrillError("OFFLINE_TARGET_PLAN_BLOCKED")
        verified = restored["verification"]
        with sqlite3.connect(f"file:{run / 'offline-restored/data/db.sqlite3'}?mode=ro", uri=True) as db:
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        if (integrity != "ok" or not verified["restored_bytes_verified"] or
                not plan["validation"]["inventory_verified"]):
            raise DrillError("OFFLINE_RESTORED_BYTES_INVALID")
        report["offline_restore"] = {"state": "passed", "shipped_cli": True,
            "snapshot_id": config["snapshot_id"], "instance_id": config["instance_id"],
            "manifest_hash": verified["manifest_hash"], "inventory_verified": True, "sqlite_integrity": integrity,
            "restored_bytes_verified": verified["restored_bytes_verified"],
            "repository_content_verified": verified["repository_content_verified"],
            "saved_image_hash_verified": plan["validation"]["image_archive_hash_matches"],
            "deployment_fingerprint_verified": plan["validation"]["descriptor_fingerprint_matches"],
            "application_started": False}

        from alembic import command
        from alembic.config import Config

        from vaultrewind.server import models  # noqa: F401 - register metadata for migrations
        from vaultrewind.server.db import make_engine
        from vaultrewind.server.models import (
            BackupPolicy,
            Instance,
            Repository,
            Snapshot,
            SnapshotCopy,
            SnapshotProtection,
            User,
        )
        from vaultrewind.server.settings import Settings
        from vaultrewind.server.worker import Worker

        database_url = private_read(run / "database-url").decode().strip()
        if make_url(database_url).database != config["target_database"]:
            raise DrillError("FRESH_DATABASE_IDENTITY_MISMATCH")
        engine = make_engine(database_url)
        migration_config = Config(str(PROJECT / "alembic.ini"))
        migration_config.set_main_option("script_location", str(PROJECT / "migrations"))
        with engine.begin() as connection:
            migration_config.attributes["connection"] = connection
            command.upgrade(migration_config, "head")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        settings = Settings(database_url=database_url, master_key_file=run / "master",
            bootstrap_secret_file=run / "bootstrap", public_origin=origin, secure_cookies=False,
            local_storage_root=run / "new-backups", staging_dir=run / "fresh-staging", min_free_bytes=0)
        environment = clean_environment()
        environment.update({"VAULTREWIND_DATABASE_URL": database_url, "VAULTREWIND_MASTER_KEY_FILE": str(run / "master"),
            "VAULTREWIND_BOOTSTRAP_SECRET_FILE": str(run / "bootstrap"), "VAULTREWIND_PUBLIC_ORIGIN": origin,
            "VAULTREWIND_SECURE_COOKIES": "false", "VAULTREWIND_LOCAL_STORAGE_ROOT": str(run / "new-backups"),
            "VAULTREWIND_STAGING_DIR": str(run / "fresh-staging"), "VAULTREWIND_MIN_FREE_BYTES": "0"})
        # API is an actual loopback HTTP server; the real worker claims its PG queue.
        with (run / "fresh-api.log").open("xb") as log:
            os.chmod(run / "fresh-api.log", 0o600)
            server = subprocess.Popen([sys.executable, "-m", "uvicorn", "vaultrewind.server.app:create_app", "--factory",
                "--host", "127.0.0.1", "--port", str(port), "--no-access-log"], cwd=PROJECT,
                env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        worker = Worker(settings, engine=engine)
        with httpx.Client(base_url=origin, timeout=60, headers={"Origin": origin}) as client:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    if client.get("/api/v1/health/live").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.2)
            else:
                raise DrillError("FRESH_HTTP_SERVER_UNAVAILABLE")
            setup = request(client, "POST", "/setup", body={"bootstrap_secret": private_read(run / "bootstrap").decode(),
                "username": "recovered-owner-" + uuid4().hex[:12], "password": private_read(run / "owner-password").decode(),
                "timezone": "UTC"})
            client.headers["X-CSRF-Token"] = setup["csrf_token"]
            report["fresh_controller"].update(state="passed", new_owner_via_api=True, owner_id=setup["user"]["id"])
            private_write(run / "fresh-session.json", dict(client.cookies))
            private_write(run / "fresh-origin", origin)
            imported = wait_job(client, request(client, "POST", "/recovery/import-plans", expected=202, body={
                "kit": private_read(run / "recovery-kit.enc").decode(),
                "passphrase": private_read(run / "kit-passphrase").decode()}), worker)
            review = request(client, "GET", f"/recovery/import-plans/{imported['id']}")
            summary = review["summary"]
            if summary["mode"] != "protected" or summary["automatic_deletion_enabled"] or summary["conflicts"] or summary["errors"]:
                raise DrillError("IMPORT_REVIEW_NOT_SAFE")
            reviewed = next(s for s in review["snapshots"] if s["snapshot_uuid"] == config["snapshot_id"])
            assert reviewed["manifest_hash"] == verified["manifest_hash"]
            applied = wait_job(client, request(client, "POST", f"/recovery/import-plans/{imported['id']}/apply", expected=202,
                body={"plan_hash": review["plan_hash"]}), worker)
            recovered = request(client, "GET", f"/snapshots/{config['snapshot_id']}")
            instance = request(client, "GET", f"/instances/{config['instance_id']}")
            retention = request(client, "POST", f"/instances/{config['instance_id']}/retention-preview", body={"retention_days": 1})
            with worker.sessions() as db:
                historical = db.get(Snapshot, config["snapshot_id"])
                policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == config["instance_id"]))
                holds = sorted(db.scalars(select(SnapshotProtection.reason).where(SnapshotProtection.snapshot_id == historical.id)))
                repo = db.scalar(select(Repository).where(Repository.instance_id == config["instance_id"]))
                copy = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == historical.id, SnapshotCopy.repository_id == repo.id))
                assert historical.imported and historical.manifest_hash == verified["manifest_hash"]
                assert historical.image_id == config["image_id"]
                assert copy.state == "complete" and repo.imported and repo.health == "imported"
                assert not policy.enabled and policy.retention_days is None
                assert policy.next_run_at is None and policy.next_verify_at is None and policy.next_test_at is None
                assert "import_review" in holds
                assert db.scalar(select(func.count()).select_from(User)) == 1
                assert db.get(Instance, config["instance_id"]).host_id is None
                purpose_counts = dict(db.execute(select(Repository.purpose, func.count())
                                                 .group_by(Repository.purpose)).all())
                snapshot_count = db.scalar(select(func.count()).select_from(Snapshot))
                placeholder_count = db.scalar(select(func.count()).select_from(Instance))
            assert instance["readiness"] == "imported" and recovered["id"] == config["snapshot_id"]
            assert recovered["captured_at"] == config["captured_at"]
            assert not retention["copy_ids"]
            report["protected_import"] = {"state": "passed", "actual_loopback_http_api": True,
                "actual_postgresql_worker": True, "plan_job_id": imported["id"], "apply_job_id": applied["id"],
                "reviewed_plan_hash": review["plan_hash"], "snapshot_id": recovered["id"],
                "instance_id": recovered["instance_id"], "captured_at": recovered["captured_at"],
                "manifest_hash": historical.manifest_hash, "repository_id": repo.id, "restic_snapshot_id": copy.restic_snapshot_id,
                "protections": holds, "historical_ids_and_metadata_preserved": True,
                "automatic_retention_disabled": True, "retention_deletion_candidates": 0,
                "placeholder_host_id": None, "placeholder_readiness": instance["readiness"],
                "readback_counts": {"repositories_by_purpose": purpose_counts, "snapshots": snapshot_count,
                                    "application_placeholders": placeholder_count},
                "summary": applied["result"]["apply_summary"]}
            private_write(run / "ready.json", {"database": config["target_database"], "snapshot_id": config["snapshot_id"],
                "instance_id": config["instance_id"], "repository_id": repo.id})
    except Exception as error:
        report["failure"] = str(error) if isinstance(error, DrillError) else type(error).__name__
        import traceback
        report["failure_locations"] = [{"file": Path(frame.filename).name, "line": frame.lineno,
                                        "function": frame.name} for frame in traceback.extract_tb(error.__traceback__)]
        raise
    finally:
        report["fresh_controller"]["old_private_directory_access_attempts"] = len(denied)
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=15)
        if engine is not None:
            engine.dispose()
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(report, indent=2) + "\n")
    print("Offline byte restore and fresh-controller protected API import passed. Application stage pending.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-origin", default="http://127.0.0.1:8098")
    parser.add_argument("--source-session-file", type=Path, default=Path(".runtime/controller/api-cookies.json"))
    parser.add_argument("--connection-auth-file", type=Path, default=Path(".runtime/controller/database-url"))
    parser.add_argument("--instance")
    parser.add_argument("--snapshot")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--fresh-stage", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--application-target-private-file", type=Path,
                        help="private descriptor for the separately authorized disposable target; reuses --run-dir")
    parser.add_argument("--execute-application-restore", action="store_true",
                        help="activate the reviewed helper and restore after the coordinated helper update")
    parser.add_argument("--evidence", type=Path, default=Path("docs/evidence/controller-loss.json"))
    args = parser.parse_args()
    try:
        if args.application_target_private_file:
            if not args.run_dir:
                parser.error("--run-dir must select the completed independent-controller state")
            application_stage(args.run_dir.resolve(), args.application_target_private_file.resolve(),
                              args.evidence.resolve(), execute=args.execute_application_restore)
        elif args.fresh_stage:
            fresh_stage(args.fresh_stage.resolve(), args.evidence.resolve())
        else:
            if not args.instance or not args.run_dir:
                parser.error("--instance and a new private --run-dir are required")
            provision(args)
        return 0
    except Exception as error:  # noqa: BLE001 - public output must never expose raw exceptions
        # Raw exceptions may contain URLs, tokens or captured tool output.
        print(str(error) if isinstance(error, DrillError) else type(error).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

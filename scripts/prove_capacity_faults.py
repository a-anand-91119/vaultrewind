#!/usr/bin/env python3
"""AC26 boundary drill: unique synthetic fixtures, real controller methods and restic.

Never accepts source paths, database URLs, endpoints, container names or credentials.
Only mounts created below this run's fresh directory may be filled or unmounted.
Physical mount failures are recorded as blocked; logical quota tests still run.
This does not exercise SSH, the remote helper, a complete backup job or live cloud quota.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import uuid4
from xml.sax.saxutils import escape

from sqlalchemy import func, select

from vaultrewind.core.archive import create_archive
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.core.manifest import create_manifest, manifest_hash, sha256_file
from vaultrewind.server.db import Base, make_engine
from vaultrewind.server.models import Job, StagingAllocation
from vaultrewind.server.queue import claim, enqueue
from vaultrewind.server.settings import Settings
from vaultrewind.server.worker import Context, Worker
from vaultrewind.storage import local, providers
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

MIB = 1024**2
PROJECT = Path(__file__).resolve().parents[1]
TIMEOUTS = {key: 30 for key in ("init", "probe", "list", "commit", "verify", "restore", "check")}
ACTIVE = {"queued", "running", "waiting_retry", "cancel_requested", "needs_attention"}


def require(condition, code):
    if not condition:
        raise AssertionError(code)


def command(*args):
    return subprocess.run(args, capture_output=True, timeout=30, check=False)


def checked(*args):
    result = command(*args)
    require(result.returncode == 0, f"FIXTURE_COMMAND_FAILED:{args[0]}")
    return result.stdout


def tree_hash(root):
    """Bytes and namespace, excluding access timestamps; never skip repository files."""
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            entry = ("symlink", os.readlink(path))
        elif path.is_dir():
            entry = ("directory", None)
        else:
            entry = ("file", sha256_file(path))
        entries.append((path.relative_to(root).as_posix(), *entry))
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def error_chain(exc):
    chain = []
    while exc is not None:
        chain.append({"type": type(exc).__name__, "code": getattr(exc, "code", None),
                      "errno": getattr(exc, "errno", None)})
        exc = exc.__cause__
    return chain


def expect_error(callback, code=None):
    try:
        callback()
    except (VaultRewindError, OSError) as exc:
        if code:
            require(getattr(exc, "code", None) == code, f"UNEXPECTED_ERROR:{error_chain(exc)}")
        return exc
    raise AssertionError("FAULT_DID_NOT_FAIL")


def decode_s3_upload(data, decoded_length):
    """Remove AWS streaming chunk frames; signatures are deliberately not authenticated here."""
    if decoded_length is None:
        return data
    position, pieces = 0, []
    while True:
        boundary = data.find(b"\r\n", position)
        require(boundary >= position, "S3_UPLOAD_CHUNK_HEADER_MISSING")
        size = int(data[position:boundary].split(b";", 1)[0], 16)
        position = boundary + 2
        if size == 0:
            break
        require(position + size <= len(data) and data[position+size:position+size+2] == b"\r\n",
                "S3_UPLOAD_CHUNK_TRUNCATED")
        pieces.append(data[position:position+size])
        position += size + 2
    result = b"".join(pieces)
    require(len(result) == int(decoded_length), "S3_UPLOAD_LENGTH_MISMATCH")
    return result


class Controller:
    """Real isolated schema/queue/fence; no remote adapter is invoked by these boundary jobs."""

    def __init__(self, root):
        root.mkdir(mode=0o700)
        key = root / "master"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        self.settings = Settings(database_url=f"sqlite+pysqlite:///{root / 'controller.sqlite3'}",
            master_key_file=key, bootstrap_secret_file=root / "unused-bootstrap",
            staging_dir=root / "staging", local_storage_root=root / "unused-backups",
            per_job_quota_bytes=4*MIB, staging_quota_bytes=16*MIB, min_free_bytes=0,
            lease_seconds=600, retry_limit=0)
        self.engine = make_engine(self.settings.database_url)
        Base.metadata.create_all(self.engine)
        self.worker = Worker(self.settings, engine=self.engine, owner="capacity-private-drill")

    def context(self):
        with self.worker.sessions.begin() as db:
            enqueue(db, kind="capacity_fault", request={}, key=str(uuid4()), resources=[])
            job = claim(db, self.worker.owner, self.settings.lease_seconds)
        require(job is not None, "JOB_NOT_CLAIMED")
        return Context(self.worker, job)

    def failed(self, ctx, exc):
        self.worker.failure(ctx, exc)
        with self.worker.sessions() as db:
            job = db.get(Job, ctx.id)
            active = db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(ACTIVE)))
            row = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == ctx.id))
            require(job.state == "failed" and active == 0, "FAULT_JOB_NOT_TERMINAL")
            require(row is None or row.state == "released", "STAGING_NOT_RELEASED")
            return {"state": job.state, "error_code": job.error_code, "active_job_count": active,
                    "allocation_state": row.state if row else "never_allocated"}


@contextmanager
def private_mount(run, path, *args):
    require(path.is_relative_to(run) and path != run and not path.is_symlink(), "UNSAFE_MOUNT_PATH")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    before = Path("/proc/self/mountinfo").read_text()
    require(not any(m["mount_point"] == str(path) for m in local.parse_mountinfo(before)), "MOUNT_EXISTS")
    result = command("mount", *args, str(path))
    if result.returncode:
        raise MountBlocked(result.returncode, result.stderr.decode(errors="replace").strip())
    try:
        mounted = local.mount_for(path, local.parse_mountinfo(Path("/proc/self/mountinfo").read_text()))
        require(mounted["mount_point"] == str(path), "PRIVATE_MOUNT_NOT_FOUND")
        yield mounted
    finally:
        # Exact path and mount ID must still belong to this run before unmounting.
        current = local.mount_for(path, local.parse_mountinfo(Path("/proc/self/mountinfo").read_text()))
        require(current["mount_id"] == mounted["mount_id"], "PRIVATE_MOUNT_ID_CHANGED")
        checked("umount", str(path))


class MountBlocked(Exception):
    def __init__(self, exit_code, message):
        self.exit_code, self.message = exit_code, message


class QuotaS3:
    """Small bounded loopback S3 wire fixture. No real account or signature validation.

    Implements the object/list subset needed by restic, with real XML QuotaExceeded
    responses for PUTs. Old objects remain readable while quota is enabled.
    """

    def __init__(self):
        self.objects, self.quota, self.rejected = {}, False, []
        self.lock = threading.RLock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def reply(self, code, data=b"", **headers):
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Type", "application/xml")
                for key, value in headers.items():
                    self.send_header(key.replace("_", "-"), value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            def parsed_request(self):
                url = urlsplit(self.path)
                parts = unquote(url.path).lstrip("/").split("/", 1)
                require(parts[0] == "capacity-fixture", "S3_UNEXPECTED_BUCKET")
                return (parts[1] if len(parts) > 1 else ""), parse_qs(url.query, keep_blank_values=True)

            def do_HEAD(self):
                key, _ = self.parsed_request()
                with fixture.lock:
                    if not key:
                        self.reply(200)
                    elif key in fixture.objects:
                        self.reply(200, fixture.objects[key], Last_Modified="Sun, 25 Oct 2026 00:00:00 GMT",
                                   ETag=f'"{hashlib.md5(fixture.objects[key]).hexdigest()}"')
                    else:
                        self.reply(404)

            def do_GET(self):
                key, query = self.parsed_request()
                with fixture.lock:
                    if not key and "location" in query:
                        self.reply(200, b'<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>')
                    elif not key:
                        prefix = query.get("prefix", [""])[0]
                        contents = "".join(f"<Contents><Key>{escape(k)}</Key><LastModified>2026-10-25T00:00:00Z</LastModified>"
                            f'<ETag>"{hashlib.md5(v).hexdigest()}"</ETag><Size>{len(v)}</Size><StorageClass>STANDARD</StorageClass></Contents>'
                            for k, v in sorted(fixture.objects.items()) if k.startswith(prefix))
                        self.reply(200, ('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                            f'<Name>capacity-fixture</Name><Prefix>{escape(prefix)}</Prefix><IsTruncated>false</IsTruncated>'
                            f'{contents}</ListBucketResult>').encode())
                    elif key not in fixture.objects:
                        self.reply(404, b"<Error><Code>NoSuchKey</Code></Error>")
                    else:
                        data = fixture.objects[key]
                        range_ = self.headers.get("Range")
                        if range_:
                            start, end = range_.removeprefix("bytes=").split("-", 1)
                            begin = int(start)
                            last = min(int(end) if end else len(data)-1, len(data)-1)
                            self.reply(206, data[begin:last+1], Content_Range=f"bytes {begin}-{last}/{len(data)}",
                                       Last_Modified="Sun, 25 Oct 2026 00:00:00 GMT",
                                       ETag=f'"{hashlib.md5(data).hexdigest()}"')
                        else:
                            self.reply(200, data, Last_Modified="Sun, 25 Oct 2026 00:00:00 GMT",
                                       ETag=f'"{hashlib.md5(data).hexdigest()}"')

            def do_PUT(self):
                key, _ = self.parsed_request()
                size = int(self.headers.get("Content-Length", "0"))
                require(0 <= size <= 16*MIB, "S3_FIXTURE_OBJECT_TOO_LARGE")
                data = self.rfile.read(size)
                data = decode_s3_upload(data, self.headers.get("X-Amz-Decoded-Content-Length"))
                with fixture.lock:
                    if fixture.quota:
                        fixture.rejected.append({"method": "PUT", "status": 403, "code": "QuotaExceeded"})
                        self.reply(403, b"<Error><Code>QuotaExceeded</Code><Message>Storage quota exceeded</Message></Error>")
                    else:
                        require(sum(map(len, fixture.objects.values())) + size < 32*MIB, "S3_FIXTURE_MEMORY_LIMIT")
                        fixture.objects[key] = data
                        self.reply(200, ETag=f'"{hashlib.md5(data).hexdigest()}"')

            def do_DELETE(self):
                key, _ = self.parsed_request()
                with fixture.lock:
                    fixture.objects.pop(key, None)
                self.reply(204)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def digest(self):
        with self.lock:
            return hashlib.sha256(json.dumps(sorted((k, hashlib.sha256(v).hexdigest())
                for k, v in self.objects.items())).encode()).hexdigest()


class Drill:
    def __init__(self, run, *, docker=True):
        self.run, self.docker = run, docker
        self.controller = Controller(run / "controller")
        self.instance = str(uuid4())
        self.password = os.urandom(24).hex()
        self.source = run / "synthetic-source"
        self.container = None
        self.result = {"acceptance": "AC26", "synthetic_only": True, "run_id": run.name,
            "recorded_at": datetime.now(UTC).isoformat(), "source_scope": "application-shaped SQLite files",
            "workflow_scope": "real Context.reserve/extract, Worker.failure, provider and restic boundaries; no full SSH backup job",
            "cloud_scope": "loopback synthetic S3 HTTP; no live Google/MinIO quota",
            "cases": {}, "limitations": []}

    def seed(self):
        self.source.mkdir(mode=0o700)
        with sqlite3.connect(self.source / "db.sqlite3") as db:
            db.executescript("CREATE TABLE users(uuid TEXT PRIMARY KEY); CREATE TABLE ciphers(uuid TEXT PRIMARY KEY);"
                             "INSERT INTO users VALUES('synthetic-user'); INSERT INTO ciphers VALUES('synthetic-cipher');")
        (self.source / "attachment").write_bytes(os.urandom(MIB))
        (self.source / "attachment").chmod(0o600)
        if self.docker:
            # Unique inert source-state sentinel; no source helper/SSH installation or stop calls.
            # Its actual process/container state is checked, but this is not a running Vaultwarden app.
            image = command("docker", "image", "inspect", "vaultrewind:0.1.0", "--format", "{{.Id}}")
            if image.returncode == 0:
                self.container = "vr-capacity-" + uuid4().hex
                checked("docker", "run", "-d", "--pull=never", "--name", self.container,
                    "--label", f"vaultrewind.capacity-fixture={self.run.name}", "--network", "none",
                    "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                    "--mount", f"type=bind,source={self.source},target=/synthetic-source,readonly",
                    "--entrypoint", "python", image.stdout.decode().strip(), "-c", "import time; time.sleep(3600)")
                self.result["source_scope"] = "application-shaped SQLite files plus new inert Docker source-state sentinel"
            else:
                self.result["limitations"].append("Docker sentinel unavailable; source byte preservation only.")
        else:
            self.result["limitations"].append("Docker sentinel disabled; source byte preservation only.")
        self.initial = self.source_state()
        self.stage, self.manifest = self.snapshot("older")
        self.archive = self.run / "new-capture.tar"
        create_archive(self.stage, self.archive)
        self.repo = self.repository(self.run / "older-repository", "local-work")
        self.repo.initialize()
        self.old = self.repo.commit(self.stage, self.manifest["snapshot_uuid"], self.manifest["captured_at"])
        self.old_hash = tree_hash(Path(self.repo.config.location))

    def source_state(self):
        state = {"tree_sha256": tree_hash(self.source)}
        if self.container:
            info = json.loads(checked("docker", "inspect", self.container))[0]
            require(info["Config"]["Labels"].get("vaultrewind.capacity-fixture") == self.run.name,
                    "NOT_OUR_CONTAINER")
            state.update(container_id=info["Id"], running=info["State"]["Running"],
                         started_at=info["State"]["StartedAt"], restart_count=info["RestartCount"])
            require(state["running"], "SOURCE_SENTINEL_NOT_RUNNING")
        return state

    def snapshot(self, name):
        root = self.run / name
        root.mkdir(mode=0o700)
        shutil.copytree(self.source, root / "data")
        (root / "deployment").mkdir()
        (root / "deployment" / "fixture.json").write_text('{"synthetic_capacity_fixture":true}')
        (root / "images").mkdir()
        image = root / "images" / "fixture-placeholder"
        image.write_bytes(b"capacity-test-only; not a saved Docker image")
        captured = datetime.now(UTC).isoformat()
        manifest = create_manifest(root, {"snapshot_uuid": str(uuid4()), "instance_uuid": self.instance,
            "capture_started_at": captured, "captured_at": captured, "source_state": "running",
            "image_id": "sha256:" + "ab"*32, "image_archive_hash": sha256_file(image),
            "platform": "linux/amd64", "deployment_fingerprint": "cd"*32,
            "consistency_mode": "synthetic_immutable_capacity_fixture"})
        return root, manifest

    def repository(self, path, work):
        return ResticRepository(RepositoryConfig(location=str(path), password=self.password,
            instance_uuid=self.instance, runtime_dir=self.run / work, lock_wait="1s", timeouts=TIMEOUTS))

    def verify_old(self, repo=None, old=None, suffix="older", expected_hash=None):
        repo, old = repo or self.repo, old or self.old
        before = tree_hash(Path(repo.config.location)) if repo.config.backend == "local" else None
        require({x["restic_snapshot_id"] for x in repo.list_snapshots()} == {old["restic_snapshot_id"]},
                "OLDER_SNAPSHOT_SET_CHANGED")
        require(manifest_hash(repo.read_manifest(old["restic_snapshot_id"])) == old["manifest_hash"],
                "OLDER_MANIFEST_CHANGED")
        full = repo.check(read_data=True)
        require(full["full_data_verified"], "OLDER_DATA_CHECK_FAILED")
        restored = repo.restore(old["restic_snapshot_id"], self.run / f"restore-{suffix}-{uuid4().hex[:8]}",
                                expected_manifest_hash=old["manifest_hash"])
        if before:
            after = tree_hash(Path(repo.config.location))
            require(before == after and (expected_hash is None or after == expected_hash), "OLDER_REPOSITORY_BYTES_CHANGED")
        return {"restic_snapshot_id": old["restic_snapshot_id"], "manifest_sha256": old["manifest_hash"],
                "repository_bytes_sha256": before, "snapshot_set_unchanged": True,
                "full_data_verified": full["full_data_verified"], "restored_bytes_verified": restored["restored_bytes_verified"]}

    def preserve(self, name, extra):
        require(self.source_state() == self.initial, "SOURCE_STATE_OR_BYTES_CHANGED")
        return {**extra, "source_state_and_bytes_unchanged": True, "source_stop_calls": 0,
                "older_backup": self.verify_old(suffix=name, expected_hash=self.old_hash)}

    def logical(self):
        ctl = self.controller
        for name in ("per_job_reserve", "global_reserve", "archive_expansion"):
            ctl.settings.per_job_quota_bytes, ctl.settings.staging_quota_bytes = 4*MIB, 16*MIB
            ctx = ctl.context()
            if name == "per_job_reserve":
                action = lambda ctx=ctx: ctx.reserve(4*MIB+1)
                code = "INSUFFICIENT_SPACE"
            elif name == "global_reserve":
                ctl.settings.staging_quota_bytes = 1024
                action = ctx.reserve
                code = "INSUFFICIENT_SPACE"
            else:
                ctl.settings.per_job_quota_bytes = 1024
                ctx.reserve()
                action = lambda ctx=ctx: ctx.extract(self.archive, ctx.root / "snapshot", manifest_hash(self.manifest))
                code = "STAGING_QUOTA_EXCEEDED"
            exc = expect_error(action, code)
            outcome = ctl.failed(ctx, exc)
            self.result["cases"][name] = self.preserve(name, {"result": "passed", "fault": "logical_quota",
                "physical_ENOSPC": False, "error": error_chain(exc), "job": outcome})
        ctl.settings.per_job_quota_bytes, ctl.settings.staging_quota_bytes = 4*MIB, 16*MIB

    def physical(self):
        ctl, mount = self.controller, self.run / "private-staging-tmpfs"
        original = ctl.settings.staging_dir
        try:
            with private_mount(self.run, mount, "-t", "tmpfs", "-o", "size=8m,mode=0700", "vr-capacity-private") as info:
                ctl.settings.staging_dir = mount
                ctx = ctl.context()
                ctx.reserve()
                require(info["fs_type"] == "tmpfs", "FILL_REQUIRES_PRIVATE_TMPFS")
                written = 0
                try:
                    with (mount / "bounded-filler").open("xb", buffering=0) as output:
                        for _ in range(8*16+1):
                            written += output.write(b"x"*(64*1024))
                    raise AssertionError("PRIVATE_TMPFS_DID_NOT_FILL_WITHIN_8MIB")
                except OSError as exc:
                    require(exc.errno == errno.ENOSPC, "UNEXPECTED_FILL_ERROR")
                require(shutil.disk_usage(mount).free == 0, "PRIVATE_TMPFS_NOT_FULL")
                extract_error = expect_error(lambda: ctx.extract(self.archive, ctx.root / "snapshot",
                                                                  manifest_hash(self.manifest)))
                require(any(e["errno"] == errno.ENOSPC for e in error_chain(extract_error)), "NO_PHYSICAL_ENOSPC")
                outcome = ctl.failed(ctx, extract_error)
                self.result["cases"]["controller_full_extract"] = self.preserve("physical-extract", {
                    "result": "passed", "fault": "physical_ENOSPC", "filesystem": "private_tmpfs",
                    "limit_bytes": 8*MIB, "filler_bytes": written, "error": error_chain(extract_error), "job": outcome})
                reserve = ctl.context()
                reserve_error = expect_error(reserve.reserve, "INSUFFICIENT_SPACE")
                self.result["cases"]["controller_full_reserve"] = self.preserve("physical-reserve", {
                    "result": "passed", "fault": "physical_free_space_guard", "error": error_chain(reserve_error),
                    "job": ctl.failed(reserve, reserve_error)})
        except MountBlocked as exc:
            self.result["cases"]["controller_full_extract"] = {"result": "blocked", "mount_exit": exc.exit_code,
                "reason": exc.message, "physical_ENOSPC": False}
            self.result["limitations"].append("Private tmpfs mount denied; physical ENOSPC unproved. Logical quota tests remain valid.")
        finally:
            ctl.settings.staging_dir = original

    def missing_mount(self):
        path = self.run / "dedicated-backups"
        destination = local.LocalDestination(str(uuid4()), path=path, min_free_bytes=0)
        configuration = {"path": str(path), "min_free_bytes": 0}
        try:
            with private_mount(self.run, path, "--bind", str(path)) as info:
                local.initialize_local_destination(destination)
                repo = self.repository(Path(local.local_repository_location(destination, self.instance)), "mount-work")
                repo.initialize()
                old = repo.commit(self.stage, self.manifest["snapshot_uuid"], self.manifest["captured_at"])
                digest = tree_hash(path)
                checked("mount", "-o", "remount,bind,ro", str(path))
                readonly = expect_error(lambda: local.inspect_local_destination(destination), "STORAGE_READ_ONLY")
                with providers.open_recovery_repository("local", configuration, None, instance_id=self.instance,
                        destination_id=destination.destination_id, password=self.password, work_dir=self.run / "recovery-ro",
                        repository_id=repo.repository_id) as recovery:
                    recovery.config.timeouts = TIMEOUTS
                    verified_ro = self.verify_old(recovery, old, "readonly")
                require(tree_hash(path) == digest, "READONLY_REPOSITORY_CHANGED")
                fs_type = info["fs_type"]
            # Self-bind removal preserves the actual old files, but /proc now shows the root mount.
            # No synthetic mountinfo or marker deletion is used to manufacture this failure.
            before = tree_hash(path)
            def attempt_open():
                with providers.open_repository("local", configuration, None, instance_id=self.instance,
                        destination_id=destination.destination_id, password=self.password,
                        work_dir=self.run / "missing-mount-work", repository_id=repo.repository_id):
                    raise AssertionError("MISSING_MOUNT_ACCEPTED")
            absent = expect_error(attempt_open, "LOCAL_MOUNT_MISSING")
            require(tree_hash(path) == before == digest, "MISSING_MOUNT_WROTE_REPLACEMENT")
            with providers.open_recovery_repository("local", configuration, None, instance_id=self.instance,
                    destination_id=destination.destination_id, password=self.password, work_dir=self.run / "recovery-after-umount",
                    repository_id=repo.repository_id) as recovery:
                recovery.config.timeouts = TIMEOUTS
                recovered = self.verify_old(recovery, old, "unmounted")
            require(tree_hash(path) == digest, "RECOVERY_CHANGED_OLD_REPOSITORY")
            with self.controller.worker.sessions() as db:
                active = db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(ACTIVE)))
            require(active == 0, "MOUNT_PREFLIGHT_LEFT_ACTIVE_JOB")
            self.result["cases"]["missing_local_mount"] = self.preserve("missing-mount", {
                "result": "passed", "fault": "physical_dedicated_self_bind_removed", "filesystem": fs_type,
                "real_mountinfo": True, "marker_retained": True, "error": error_chain(absent),
                "read_only_error": error_chain(readonly), "no_empty_replacement": True,
                "active_job_count": active, "mounted_older_repository_bytes_unchanged": True,
                "older_readonly_restore": verified_ro, "older_restore_after_umount": recovered})
        except MountBlocked as exc:
            self.result["cases"]["missing_local_mount"] = {"result": "blocked", "reason": exc.message,
                "mount_exit": exc.exit_code}
            self.result["limitations"].append("Physical self-bind mount unavailable; missing-mount drill unproved.")

    def cloud(self):
        with QuotaS3() as s3:
            config = RepositoryConfig(location=f"s3:http://127.0.0.1:{s3.server.server_port}/capacity-fixture/repository",
                password=self.password, instance_uuid=self.instance, allow_insecure_http=True,
                environment={"AWS_ACCESS_KEY_ID": "synthetic-capacity-key", "AWS_SECRET_ACCESS_KEY": "synthetic-only-value",
                             "AWS_DEFAULT_REGION": "us-east-1"},
                options=("s3.bucket-lookup=path",), runtime_dir=self.run / "s3-work", lock_wait="1s", timeouts=TIMEOUTS)
            repo = ResticRepository(config)
            repo.initialize()
            old = repo.commit(self.stage, self.manifest["snapshot_uuid"], self.manifest["captured_at"])
            stage, manifest = self.snapshot("quota-new-snapshot")
            before = s3.digest()
            s3.quota = True
            ctx = self.controller.context()
            exc = expect_error(lambda: repo.commit(stage, manifest["snapshot_uuid"], manifest["captured_at"]))
            require(getattr(exc, "code", None) in {"STORAGE_QUOTA_EXCEEDED", "STORAGE_TIMEOUT"},
                    "UNEXPECTED_QUOTA_FAILURE")
            outcome = self.controller.failed(ctx, exc)
            require(s3.rejected and s3.digest() == before, "S3_QUOTA_CHANGED_OLDER_OBJECTS")
            # --no-lock reads keep working while every write is rejected, just like recovery access.
            repo.config.read_only = True
            verified = self.verify_old(repo, old, "s3-quota")
            require(s3.digest() == before, "S3_VERIFICATION_MUTATED_OBJECTS")
            quota_classified = exc.code == "STORAGE_QUOTA_EXCEEDED"
            if not quota_classified:
                self.result["limitations"].append("Real S3 QuotaExceeded responses were received by restic, but its "
                    "write retries reached the adapter deadline: STORAGE_TIMEOUT. Quota classification was not verified.")
            self.result["cases"]["cloud_quota"] = self.preserve("cloud-quota", {
                "result": "passed" if quota_classified else "preservation_passed_with_adapter_timeout",
                "fault": "synthetic_S3_HTTP_403_QuotaExceeded", "real_restic": True,
                "quota_rejections": s3.rejected, "error": error_chain(exc), "job": outcome,
                "older_S3_objects_sha256": before, "older_S3_objects_unchanged": True,
                "older_S3_backup": verified, "live_provider_quota": False,
                "quota_error_classification_verified": quota_classified})

    def close(self):
        if self.container:
            # Only the uniquely named container created by this run; no daemon/service restart.
            info = json.loads(checked("docker", "inspect", self.container))[0]
            require(info["Config"]["Labels"].get("vaultrewind.capacity-fixture") == self.run.name,
                    "CLEANUP_NOT_OUR_CONTAINER")
            checked("docker", "rm", "-f", self.container)
            self.container = None
        self.controller.engine.dispose()
        remaining = [mount for mount in local.parse_mountinfo(Path("/proc/self/mountinfo").read_text())
                     if Path(mount["mount_point"]).is_relative_to(self.run)]
        require(not remaining, "PRIVATE_MOUNTS_NOT_CLEANED")
        self.result["cleanup"] = {"private_mounts_remaining": 0, "new_container_removed": True,
                                  "controller_engine_disposed": True}

    def execute(self):
        try:
            self.seed()
            for method in (self.logical, self.physical, self.missing_mount, self.cloud):
                started = time.monotonic()
                print(f"running {method.__name__}", flush=True)
                method()
                print(f"finished {method.__name__} ({time.monotonic()-started:.1f}s)", flush=True)
            self.result["source_initial"] = self.initial
            self.result["source_final_before_cleanup"] = self.source_state()
            self.result["restic_version"] = self.repo.restic_version
            self.result["limitations"].extend([
                "Source free-reserve/full-disk is a separate agent drill and is not tested here.",
                "No expired real Google Drive credentials tested; user deferred that evidence.",
                "Snapshot image member is an explicit synthetic placeholder, not a recoverable Docker image; no application restore claim.",
                "Controller jobs are focused capacity-boundary jobs, not API/SSH full backup workflow jobs."])
            self.result["result"] = "passed_with_explicit_scope" if all(
                x["result"] == "passed" for x in self.result["cases"].values()) else "partial"
        except Exception as exc:
            self.result["result"] = "failed"
            self.result["failure"] = error_chain(exc)
            raise
        finally:
            self.close()
        return self.result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT / "docs/evidence/capacity-faults.json")
    parser.add_argument("--no-docker", action="store_true", help="Record source byte checks without a Docker state sentinel.")
    args = parser.parse_args()
    # /var/tmp is persistent on this Linux host; /tmp may itself be tmpfs (invalid local-backup fixture).
    with tempfile.TemporaryDirectory(prefix="vr-capacity-", dir="/var/tmp") as directory:
        drill = Drill(Path(directory), docker=not args.no_docker)
        try:
            result = drill.execute()
        finally:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(drill.result, indent=2) + "\n")
    print(json.dumps({"result": result["result"], "output": str(args.output)}))
    return 0 if result["result"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

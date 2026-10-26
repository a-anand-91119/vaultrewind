#!/usr/bin/env python3
"""AC26 physical SOURCE staging/data exhaustion, using an immutable real helper.

Staging requires --rootgo after ROOTGO; data requires --rootgo-data-full after ROOTGO_DATA_FULL.
No caller-provided source, container, credentials, endpoints, or mount paths.
Only a new UUID-labeled Docker fixture and two private tmpfs mounts are used.
Systemd is a labeled double; this makes no watchdog/reboot or API/SSH claim.
"""
from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import importlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

PROJECT = Path(__file__).resolve().parents[1]
BUNDLE = PROJECT / "helper/.final-bundle/helper.pyz"
BUNDLE_SHA256 = "cbf84b999eab462a6ad08b86ef06c631c148e796d242459f227c79df2a0a0093"
MIB = 1024**2
STAGING_LIMIT = 8 * MIB
SOURCE_LIMIT = 16 * MIB
MAX_ADVERTISED_STAGING = 2 * 1024**3
LABEL = "org.vaultrewind.source-capacity-fixture"
IMAGE = "ghcr.io/dani-garcia/vaultwarden:1.37.4"
DATA_CASE = "full_live_data_filesystem"
SQLITE_FILES = frozenset({"db.sqlite3", "db.sqlite3-wal", "db.sqlite3-shm", "db.sqlite3-journal"})
LIMITATIONS = [
    "Systemd recovery is a journal-writing double; no independent watchdog, reboot, or controller-loss claim.",
    "Real frozen Helper methods run locally, without SSH, native API/controller, worker, or helper installation.",
    "Only remote SOURCE staging is filled; the separate synthetic live-data tmpfs remains writable.",
    "The staging filesystem initially advertises sparse capacity for a successful preflight, then is remounted at 8 MiB.",
    "No post-preflight capture race, cloud fault, authenticated login, or production workload is tested here.",
]


def require(condition, code):
    if not condition:
        raise AssertionError(code)


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_hash(root, exclusions=frozenset()):
    """Include bytes, namespace and durable metadata; exclude access timestamps."""
    entries = []
    for path in sorted(root.rglob("*")):
        if path.relative_to(root).as_posix() in exclusions:
            continue
        item = path.lstat()
        kind = stat.S_IFMT(item.st_mode)
        content = (os.readlink(path) if stat.S_ISLNK(item.st_mode) else
                   file_hash(path) if stat.S_ISREG(item.st_mode) else None)
        require(kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK), "UNEXPECTED_FIXTURE_FILE_TYPE")
        entries.append((path.relative_to(root).as_posix(), kind, stat.S_IMODE(item.st_mode),
                        item.st_uid, item.st_gid, item.st_mtime_ns, content))
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def logical_sqlite(path):
    """A closed read-only transaction including committed WAL rows; emit hashes/counts only."""
    require(path.is_file() and not path.is_symlink(), "SQLITE_FIXTURE_PATH_UNSAFE")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "LIVE_SQLITE_INTEGRITY_FAILED")
        schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()
        def canonical(value):
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(canonical(schema))
        counts = {}
        for kind, name, _, _ in schema:
            if kind != "table":
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            rows = []
            for row in connection.execute("SELECT * FROM " + quoted):
                rows.append(canonical([(type(value).__name__, value.hex() if isinstance(value, bytes) else value)
                                       for value in row]))
            counts[name] = len(rows)
            digest.update(canonical(name))
            for row in sorted(rows):
                digest.update(len(row).to_bytes(8, "big"))
                digest.update(row)
        return {"logical_sha256": digest.hexdigest(), "schema_sha256": hashlib.sha256(canonical(schema)).hexdigest(),
                "row_counts": counts, "integrity": "ok",
                "user_version": connection.execute("PRAGMA user_version").fetchone()[0]}
    finally:
        connection.close()


def persistent_fingerprint(data):
    item = (data / "db.sqlite3").stat()
    return {"sqlite": logical_sqlite(data / "db.sqlite3"),
            "sqlite_file_metadata": {"mode": stat.S_IMODE(item.st_mode), "uid": item.st_uid, "gid": item.st_gid},
            "non_database_tree_sha256": tree_hash(data, SQLITE_FILES)}


def error_chain(error):
    """Only safe classifications, never raw errors, environment or Docker config."""
    result, seen = [], set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        result.append({"type": type(error).__name__, "code": getattr(error, "code", None),
                       "errno": getattr(error, "errno", None)})
        if isinstance(error, AssertionError) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,100}", str(error)):
            result[-1]["assertion_code"] = str(error)
        error = error.__cause__
    return result


def expect_failure(action, *, code=None, physical=False):
    try:
        action()
    except Exception as error:  # noqa: BLE001 -- classify opaque frozen-helper errors without exposing messages.
        chain = error_chain(error)
        if code:
            require(getattr(error, "code", None) == code, "UNEXPECTED_HELPER_ERROR_CODE")
        if physical:
            require(any(item["errno"] == errno.ENOSPC for item in chain), "PHYSICAL_ENOSPC_REQUIRED")
        return chain
    raise AssertionError("FAULT_DID_NOT_FAIL")


def verify_bundle(bundle=BUNDLE):
    require(file_hash(bundle) == BUNDLE_SHA256, "FROZEN_HELPER_SHA256_MISMATCH")
    with zipfile.ZipFile(bundle) as archive:
        helper = archive.read("vaultrewind/remote/helper.py")
        require(helper == (PROJECT / "src/vaultrewind/remote/helper.py").read_bytes(),
                "CURRENT_HELPER_DIFFERS_FROM_FROZEN_SOURCE")
        modules = [name for name in archive.namelist()
                   if name.endswith(".py") and name.startswith(("vaultrewind/core/", "vaultrewind/remote/"))]
        identical = all((PROJECT / "src" / name).read_bytes() == archive.read(name) for name in modules)
    return {"bundle_sha256": BUNDLE_SHA256, "helper_source_sha256": hashlib.sha256(helper).hexdigest(),
            "helper_source_identical_to_current": True, "all_core_remote_sources_identical": identical,
            "compared_module_count": len(modules)}


def load_runtime():
    require(not any(name == "vaultrewind" or name.startswith("vaultrewind.") for name in sys.modules),
            "RUN_IN_FRESH_ISOLATED_PYTHON_PROCESS")
    sys.path.insert(0, str(BUNDLE))
    helper = importlib.import_module("vaultrewind.remote.helper")
    require(str(BUNDLE) in helper.__file__, "HELPER_DID_NOT_LOAD_FROM_FROZEN_BUNDLE")
    package = importlib.import_module("vaultrewind")
    package.__path__.append(str(PROJECT / "src/vaultrewind"))
    return {name: importlib.import_module("vaultrewind." + name) for name in
            ("core", "remote.helper", "remote.policy", "remote.journal", "remote.protocol",
             "remote.docker", "storage.restic")}


def prior_failed_attempts(previous):
    attempts = list(previous.get("failed_attempts", []))
    if previous.get("result") == "failed" and not any(
            attempt.get("recorded_at") == previous.get("recorded_at") for attempt in attempts):
        attempts.append({key: value for key, value in previous.items() if key != "failed_attempts"})
    return attempts


def merge_live_data_result(previous, extension):
    """Retain the complete staging PASS/history, with a separately scoped extension outcome."""
    merged = copy.deepcopy(previous)
    merged["live_data_filesystem_full"] = extension
    merged["cases"][DATA_CASE] = {**extension.get("cases", {}).get(DATA_CASE, {}),
        "result": extension["result"], "evidence_ref": "live_data_filesystem_full"}
    merged["overall_source_capacity_result"] = extension["result"]
    merged["result_scope"] = ("physical source staging and live-data filesystem cases" if extension["result"] == "passed"
                              else "existing physical SOURCE staging PASS; live-data outcome is recorded separately")
    return merged


def mount_at(path):
    """Read exact kernel mount identity; never infer a mount from directory existence."""
    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        separator = fields.index("-")
        point = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        if point == str(path):
            matches.append({"mount_id": fields[0], "device": fields[2], "mount_point": point,
                            "fs_type": fields[separator + 1], "source": fields[separator + 2]})
    require(len(matches) <= 1, "STACKED_FIXTURE_MOUNT_FORBIDDEN")
    return matches[0] if matches else None


def checked(*arguments):
    outcome = subprocess.run(arguments, capture_output=True, timeout=20, check=False)
    require(outcome.returncode == 0, "FIXTURE_COMMAND_FAILED_" + arguments[0].upper())


def guard_private_mount(run, path, expected):
    require(path != run and path.is_relative_to(run), "MOUNT_OUTSIDE_OWN_RUN")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "MOUNT_SYMLINK_FORBIDDEN")
    actual = mount_at(path)
    require(actual == expected and actual is not None, "PRIVATE_MOUNT_IDENTITY_CHANGED")
    require(actual["fs_type"] == "tmpfs" and actual["source"] == run.name, "PRIVATE_TMPFS_REQUIRED")
    require(path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o700,
            "PRIVATE_ROOT_OWNED_MOUNT_REQUIRED")
    require(path.stat().st_dev != run.stat().st_dev, "SHARED_ROOT_FILL_FORBIDDEN")
    return actual


def bounded_fill(write, limit):
    """A non-sparse write must hit real ENOSPC within the known filesystem bound."""
    written = 0
    block = b"x" * (64 * 1024)
    while written <= limit:
        try:
            count = write(block[:min(len(block), limit + 1 - written)])
            require(type(count) is int and count > 0, "FILLER_WRITE_MADE_NO_PROGRESS")
            written += count
        except OSError as error:
            require(error.errno == errno.ENOSPC, "UNEXPECTED_FILL_ERRNO")
            return {"errno": error.errno, "filler_bytes": written, "write_bound_bytes": limit + 1}
    raise AssertionError("PRIVATE_TMPFS_DID_NOT_FILL_WITHIN_BOUND")


class PrivateTmpfs:
    def __init__(self, run, name, limit):
        require(type(limit) is int and MIB <= limit <= MAX_ADVERTISED_STAGING, "UNSAFE_TMPFS_LIMIT")
        require(name in {"source-filesystem", "source-staging"}, "UNSAFE_FIXTURE_MOUNT_NAME")
        self.run, self.path, self.limit = run, run / name, limit
        self.identity = None

    def open(self):
        self.path.mkdir(mode=0o700)
        require(mount_at(self.path) is None, "MOUNT_ALREADY_EXISTS")
        checked("mount", "-t", "tmpfs", "-o", f"size={self.limit},mode=0700,nosuid,nodev", self.run.name,
                str(self.path))
        # Retain identity before any follow-up command so cleanup also covers a failed make-private.
        self.identity = mount_at(self.path)
        checked("mount", "--make-private", str(self.path))
        guard_private_mount(self.run, self.path, self.identity)
        return self.path

    def shrink_and_fill(self):
        guard_private_mount(self.run, self.path, self.identity)
        checked("mount", "-t", "tmpfs", "-o", f"remount,size={STAGING_LIMIT},mode=0700,nosuid,nodev",
                self.run.name, str(self.path))
        guard_private_mount(self.run, self.path, self.identity)
        usage = shutil.disk_usage(self.path)
        require(usage.total == STAGING_LIMIT, "UNEXPECTED_PHYSICAL_FILESYSTEM_LIMIT")
        with (self.path / "bounded-filler").open("xb", buffering=0) as stream:
            result = bounded_fill(stream.write, STAGING_LIMIT)
            os.fsync(stream.fileno())
        require(shutil.disk_usage(self.path).free == 0, "PRIVATE_TMPFS_NOT_ZERO_FREE")
        return {**result, **self.identity, "limit_bytes": STAGING_LIMIT, "free_bytes": 0,
                "source_live_data_same_filesystem": False}

    def fill_outside_data(self, data):
        guard_private_mount(self.run, self.path, self.identity)
        require(self.path.name == "source-filesystem" and self.limit == SOURCE_LIMIT,
                "LIVE_FILL_REQUIRES_OWN_16MIB_TMPFS")
        require(data.parent == self.path and data.name == "data" and data.stat().st_dev == self.path.stat().st_dev,
                "LIVE_DATA_NOT_ON_OWN_DEDICATED_FILESYSTEM")
        require(shutil.disk_usage(self.path).total == SOURCE_LIMIT, "UNEXPECTED_LIVE_FILESYSTEM_LIMIT")
        filler = self.path / "outside-data-filler"
        require(not filler.is_relative_to(data), "FILLER_INSIDE_ENROLLED_DATA")
        with filler.open("xb", buffering=0) as stream:
            self.outside_filler_identity = {"filler_path": str(filler), "filler_inode": os.fstat(stream.fileno()).st_ino}
            result = bounded_fill(stream.write, SOURCE_LIMIT)
            os.fsync(stream.fileno())
        require(shutil.disk_usage(self.path).free == 0, "LIVE_FILESYSTEM_NOT_ZERO_FREE")
        return {**result, **self.identity, "limit_bytes": SOURCE_LIMIT, "free_bytes": 0,
                "filler_path": str(filler), "filler_inode": filler.stat().st_ino,
                "filler_outside_enrolled_data": True, "same_filesystem_as_live_data": True}

    def remove_outside_filler(self, data, physical):
        guard_private_mount(self.run, self.path, self.identity)
        filler = self.path / "outside-data-filler"
        require(str(filler) == physical["filler_path"] and not filler.is_relative_to(data), "FILLER_PATH_CHANGED")
        require(filler.is_file() and not filler.is_symlink() and filler.stat().st_ino == physical["filler_inode"],
                "FILLER_IDENTITY_CHANGED")
        filler.unlink()

    def close(self):
        if self.identity is not None:
            guard_private_mount(self.run, self.path, self.identity)
            checked("umount", str(self.path))
            require(mount_at(self.path) is None, "PRIVATE_TMPFS_UNMOUNT_FAILED")
            self.identity = None


class RecoveryDouble:
    """Deliberately does not run systemd or an independent recovery process."""
    def __init__(self):
        self.arms = 0

    def verify(self):
        pass

    def arm(self, journal, seconds):
        self.arms += 1
        journal.value.update(watchdog_armed=True, deadline=time.time() + seconds,
                             monotonic_deadline=time.monotonic() + seconds,
                             boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        journal.save()

    def disarm(self, journal):
        journal.value["watchdog_armed"] = False
        journal.save()


def audited_docker(runtime, owner, run):
    class AuditedDocker(runtime["remote.docker"].Docker):
        def __init__(self):
            super().__init__()
            self.calls, self.owned_containers, self.owned_networks, self.owned_execs = [], set(), set(), set()
            self.boundary_observer = None

        def api(self, method, path, body=None, **kwargs):
            route = path.split("?", 1)[0]
            parts = route.strip("/").split("/")
            if method not in {"GET", "HEAD"}:
                if method == "POST" and route == "/containers/create":
                    require(body.get("Labels", {}).get(LABEL) == owner, "DOCKER_CREATE_NOT_OUR_FIXTURE")
                    for mount in body["HostConfig"]["Mounts"]:
                        require(mount["Type"] == "bind" and Path(mount["Source"]).is_relative_to(run),
                                "DOCKER_MOUNT_OUTSIDE_OWN_RUN")
                elif method == "POST" and route == "/networks/create":
                    require(body.get("Labels", {}).get(LABEL) == owner, "NETWORK_CREATE_NOT_OUR_FIXTURE")
                elif len(parts) >= 2 and parts[0] == "containers":
                    require(parts[1] in self.owned_containers, "DOCKER_MUTATION_NOT_OUR_CONTAINER")
                    require((self.inspect(parts[1])["Config"].get("Labels") or {}).get(LABEL) == owner,
                            "DOCKER_CONTAINER_OWNER_CHANGED")
                elif len(parts) == 3 and parts[0] == "exec":
                    require(parts[1] in self.owned_execs, "DOCKER_EXEC_NOT_OUR_FIXTURE")
                elif method == "DELETE" and len(parts) == 2 and parts[0] == "networks":
                    require(parts[1] in self.owned_networks, "DOCKER_NETWORK_NOT_OUR_FIXTURE")
                    require((self.network(parts[1]).get("Labels") or {}).get(LABEL) == owner,
                            "DOCKER_NETWORK_OWNER_CHANGED")
                else:
                    raise AssertionError("DOCKER_MUTATION_FORBIDDEN")
            self.calls.append((method, route))
            boundary = ("container_" + parts[2] if method == "POST" and len(parts) == 3
                        and parts[0] == "containers" and parts[2] in {"stop", "start"} else None)
            if boundary and self.boundary_observer:
                self.boundary_observer("before_" + boundary)
            result = super().api(method, path, body, **kwargs)
            if boundary and self.boundary_observer:
                self.boundary_observer("after_" + boundary)
            if method == "POST" and route == "/containers/create":
                self.owned_containers.add(result["Id"])
            elif method == "POST" and route == "/networks/create":
                self.owned_networks.add(result["Id"])
            elif method == "POST" and len(parts) == 3 and parts[0] == "containers" and parts[2] == "exec":
                self.owned_execs.add(result["Id"])
            return result

        def health(self, container, window=30):
            if self.boundary_observer:
                self.boundary_observer("before_http_health")
            result = super().health(container, window)
            if self.boundary_observer:
                self.boundary_observer("after_http_health")
            return result
    return AuditedDocker()


class Drill:
    def __init__(self, run, result, runtime, *, live_data_full=False):
        self.run, self.result, self.runtime = run, result, runtime
        self.owner = str(uuid4())
        self.docker = audited_docker(runtime, self.owner, run)
        self.recovery = RecoveryDouble()
        self.mounts = []
        self.source = None
        self.live_data_full = live_data_full

    def request(self, verb, token=1):
        return self.runtime["remote.protocol"].Request(self.owner, str(uuid4()), token, verb, verb,
            {"controller_time": datetime.now(UTC).isoformat(),
             **({"snapshot_uuid": str(uuid4())} if verb == "capture" else {})})

    def source_state(self):
        item = self.docker.inspect(self.source)
        state = item["State"]
        return {"container_id": item["Id"], "image_id": item["Image"], "running": state["Running"],
                "pid": state["Pid"], "started_at": state["StartedAt"], "restart_count": item["RestartCount"],
                "restart_policy": item["HostConfig"]["RestartPolicy"], "data_sha256": tree_hash(self.data)}

    def check_preserved(self, baseline, before_calls, before_arms):
        after = self.source_state()
        require(baseline == after and after["running"], "SOURCE_PROCESS_CONTENT_OR_METADATA_CHANGED")
        mutations = [call for call in self.docker.calls[before_calls:] if call[0] not in {"GET", "HEAD"}]
        require(not mutations, "DOCKER_MUTATION_BEFORE_CAPACITY_REJECTION")
        require(self.recovery.arms == before_arms, "WATCHDOG_ARMED_BEFORE_CAPACITY_REJECTION")
        return {"source_process_content_metadata_unchanged": True, "docker_mutations": 0,
                "source_stop_calls": 0, "watchdog_arms": 0}

    def new_helper(self, root, entry):
        root.mkdir(mode=0o700, exist_ok=True)
        policy = self.runtime["remote.policy"].Policy({"schema_version": 1,
            "machine_id": Path("/etc/machine-id").read_text().strip(), "daemon_id": self.docker.info()["ID"],
            "instances": {self.owner: copy.deepcopy(entry)}}, root)
        return self.runtime["remote.helper"].Helper(policy, self.docker, self.recovery)

    def execute(self):
        docker = self.docker
        self.result["stage"] = "read_only_image_and_headroom_checks"
        # Inspect an already present pinned tag. No image pull/build/commit/load is allowed.
        image = docker.image(IMAGE)
        require(image["Size"] <= 384 * MIB, "FIXTURE_IMAGE_EXCEEDS_RESOURCE_BOUND")
        require(shutil.disk_usage(self.run).free > image["Size"] * 8 + 256 * MIB,
                "INSUFFICIENT_PRIVATE_WORKSPACE_HEADROOM")
        source_mount = PrivateTmpfs(self.run, "source-filesystem", SOURCE_LIMIT)
        self.mounts.append(source_mount)
        self.data = source_mount.open() / "data"
        self.data.mkdir(mode=0o700)
        private = self.data / ".root-private-synthetic"
        private.write_bytes(secrets.token_bytes(512 * 1024))
        private.chmod(0o600)
        (self.data / "config.json").write_text('{"signups_allowed":false}')
        (self.data / "config.json").chmod(0o600)
        name = "vrw-source-capacity-" + self.owner
        network = docker.api("POST", "/networks/create", {"Name": name, "Internal": True,
                            "Labels": {LABEL: self.owner}})["Id"]
        self.source = docker.create(name, {"Image": image["Id"], "Labels": {LABEL: self.owner},
            "Env": ["ROCKET_WORKERS=1", "SIGNUPS_ALLOWED=false"], "Healthcheck": {"Test": ["NONE"]},
            "HostConfig": {"NetworkMode": name, "RestartPolicy": {"Name": "no"},
                           "Mounts": [{"Type": "bind", "Source": str(self.data), "Target": "/data"}]}})
        docker.start(self.source)
        ready = docker.health(self.source, 60)
        self.result["source_application_readiness"] = ready
        require(len(docker.inspect(self.source)["Mounts"]) == 1, "UNEXPECTED_IMPLICIT_DOCKER_VOLUME")
        entry = {"container_id": self.source, "container_name": name, "ownership": "exclusive",
            "external_dependencies_ready": True, "allowed_operations": ["preflight", "capture"],
            "allowed_image_ids": [image["Id"]], "allowed_networks": [name], "port_bindings": {},
            "capture_budget": 300, "validation_window": 60, "free_space_reserve": 0,
            "mounts": [{"type": "bind", "source": str(self.data), "target": "/data",
                        "snapshot_path": "data", "read_only": False}]}
        helper = self.new_helper(self.run / "baseline-state", entry)
        healthy = helper.dispatch(self.request("preflight"))
        self.result["stage"] = "baseline_capture"
        print("Creating older encrypted recovery point through frozen Helper.capture.", flush=True)
        request = self.request("capture")
        captured = helper.dispatch(request)
        require(captured["phase"] == "captured" and captured["source_service_outcome"] == "running",
                "BASELINE_HELPER_CAPTURE_FAILED")
        self.result["baseline_capture"] = {"phase": captured["phase"],
            "source_service_outcome": captured["source_service_outcome"],
            "watchdog_double_disarmed": True, "source_after_capture": self.source_state()}
        print("Baseline capture source safely resumed; sealing complete, committing encrypted restic backup.", flush=True)
        snapshot = helper.root / "operations" / request.operation_id / "capture"
        core = self.runtime["core"]
        manifest = core.verify_snapshot(snapshot, captured["manifest_hash"])["manifest"]
        storage = self.runtime["storage.restic"]
        repository = storage.ResticRepository(storage.RepositoryConfig(location=str(self.run / "older-repository"),
            password=secrets.token_urlsafe(48), instance_uuid=self.owner, runtime_dir=self.run / "restic-runtime",
            lock_wait="1s", timeouts={key: 120 for key in ("init", "probe", "list", "commit", "verify", "restore", "check")}))
        repository.initialize()
        self.result["stage"] = "older_restic_commit"
        old = repository.commit(snapshot, captured["snapshot_uuid"], manifest["captured_at"])
        repository.config.read_only = True
        repository_digest = tree_hash(Path(repository.config.location))
        self.result["older_backup"] = {"captured_by_frozen_helper": True,
            "restic_snapshot_id": old["restic_snapshot_id"], "manifest_sha256": old["manifest_hash"],
            "repository_bytes_sha256": repository_digest, "full_data_verified": False,
            "restored_bytes_verified": False, "application_startup_after_restore_tested": False}
        if self.live_data_full:
            return self.live_data_case(helper, source_mount, repository, old, private, repository_digest, image)
        stage_limit = max(STAGING_LIMIT, healthy["estimated_staging_bytes"] + 4 * MIB)
        staging = PrivateTmpfs(self.run, "source-staging", stage_limit)
        self.mounts.append(staging)
        full_helper = self.new_helper(staging.open(), entry)
        require(self.data.stat().st_dev != full_helper.root.stat().st_dev, "SOURCE_AND_STAGING_SHARE_FILESYSTEM")
        # A real positive control before reducing advertised size, with unchanged helper policy.
        positive = full_helper.dispatch(self.request("preflight"))
        direct_request = self.request("capture")
        journal = self.runtime["remote.journal"].Journal(full_helper.root, direct_request.operation_id)
        journal.create(direct_request, self.runtime["remote.journal"].resource_keys(
            full_helper.policy.value["machine_id"], full_helper.policy.value["daemon_id"], entry["mounts"]))
        baseline = self.source_state()
        self.result["source_before_fault"] = baseline
        self.result["positive_control"] = {"preflight_passed_before_fault": True, "free_space_reserve_bytes": 0,
            "advertised_tmpfs_limit_bytes": stage_limit, "estimated_staging_bytes": positive["estimated_staging_bytes"]}
        calls, arms = len(docker.calls), self.recovery.arms
        print("Filling only the private 8 MiB remote staging tmpfs to physical ENOSPC.", flush=True)
        self.result["stage"] = "source_staging_shrink_remount_and_fill"
        physical = staging.shrink_and_fill()
        self.result["physical_source_staging"] = physical
        cases = self.result["cases"]
        for label, action in (
            ("full_source_staging_preflight", lambda: full_helper.dispatch(self.request("preflight"))),
            ("full_source_staging_capture_entry", lambda: full_helper.capture(
                full_helper.policy.instance(self.owner), journal, direct_request.payload)),
        ):
            self.result["stage"] = label
            errors = expect_failure(action, code="INSUFFICIENT_SPACE")
            cases[label] = {"result": "passed", "error": errors,
                            **self.check_preserved(baseline, calls, arms)}
        # Dispatch admission durably writes fencing/journal records before capture's own preflight.
        # Reuse the precreated operation: a different operation would correctly be blocked
        # by this preparing journal before any admission write could reach the full disk.
        self.result["stage"] = "full_source_staging_capture_dispatch_admission"
        errors = expect_failure(lambda: full_helper.dispatch(direct_request), physical=True)
        cases["full_source_staging_capture_dispatch_admission"] = {"result": "passed", "error": errors,
            "boundary": "physical ENOSPC during durable dispatch admission, before capture/preflight",
            **self.check_preserved(baseline, calls, arms)}
        require(shutil.disk_usage(staging.path).free == 0, "STAGING_NO_LONGER_PHYSICALLY_FULL")
        print("All source capacity rejections preserved the running process; verifying older restic data.", flush=True)
        self.result["stage"] = "older_restic_full_check_and_verified_readback"
        require({item["restic_snapshot_id"] for item in repository.list_snapshots()} == {old["restic_snapshot_id"]},
                "OLDER_SNAPSHOT_SET_CHANGED")
        require(core.manifest_hash(repository.read_manifest(old["restic_snapshot_id"])) == old["manifest_hash"],
                "OLDER_MANIFEST_CHANGED")
        checked_data = repository.check(read_data=True)
        self.result["older_backup"]["restic_full_data_check"] = checked_data
        require(checked_data["full_data_verified"], "OLDER_FULL_RESTIC_DATA_CHECK_FAILED")
        restored_root = self.run / "older-restored"
        restored = repository.restore(old["restic_snapshot_id"], restored_root,
                                      expected_manifest_hash=old["manifest_hash"])
        self.result["older_backup"]["restic_verified_restore"] = restored
        require(restored["restored_bytes_verified"], "OLDER_RESTORE_BYTES_NOT_VERIFIED")
        require(file_hash(restored_root / "data" / private.name) == file_hash(private), "OLDER_PRIVATE_FILE_CHANGED")
        helper.verify_image_archive(restored_root / "images/vaultwarden.tar", image["Id"])
        require(tree_hash(Path(repository.config.location)) == repository_digest, "OLDER_REPOSITORY_BYTES_CHANGED")
        preserved = self.check_preserved(baseline, calls, arms)
        self.result.update(source_before_fault=baseline, source_after_fault=self.source_state(),
            source_application_readiness=ready, source_filesystem=source_mount.identity,
            physical_source_staging=physical,
            positive_control={"preflight_passed_before_fault": True, "free_space_reserve_bytes": 0,
                              "advertised_tmpfs_limit_bytes": stage_limit,
                              "estimated_staging_bytes": positive["estimated_staging_bytes"]},
            older_backup={"captured_by_frozen_helper": True, "exact_saved_image_verified": True,
                "restic_snapshot_id": old["restic_snapshot_id"], "manifest_sha256": old["manifest_hash"],
                "repository_bytes_sha256": repository_digest, "repository_bytes_unchanged": True,
                "snapshot_set_unchanged": True, "full_data_verified": True,
                "restored_bytes_verified": True, "private_file_bytes_verified": True,
                "restic_full_data_check": checked_data, "restic_verified_restore": restored,
                "saved_image_archive_sha256": file_hash(restored_root / "images/vaultwarden.tar"),
                "application_startup_after_restore_tested": False},
            source_preservation=preserved, restic_version=repository.restic_version,
            optional_post_preflight_race={"executed": False, "reason": "Scope limited to pre-downtime physical staging-full proof."},
            fixture_network_id=network, physical_source_staging_enospc_proven=True, stage="complete", result="passed")

    def live_data_case(self, helper, source_mount, repository, old, private, repository_digest, image):
        core, docker = self.runtime["core"], self.docker
        timeline, started = [], time.monotonic()
        physical = None
        before = persistent_fingerprint(self.data)
        original = self.source_state()
        self.result.update(source_before_fault=original, logical_content_before_fault=before,
                           source_filesystem=source_mount.identity)

        def boundary(label):
            usage = shutil.disk_usage(source_mount.path)
            state = docker.inspect(self.source)["State"]
            timeline.append({"boundary": label, "utc": datetime.now(UTC).isoformat(),
                "elapsed_seconds": round(time.monotonic() - started, 6), "free_bytes": usage.free,
                "total_bytes": usage.total, "source_running": state["Running"], "pid": state["Pid"],
                "exit_code": state.get("ExitCode"), "oom_killed": state.get("OOMKilled")})

        self.result["free_space_timeline"] = timeline
        self.result["healthy_before_fault"] = docker.health(self.source, 60)
        boundary("before_fill")
        calls = len(docker.calls)
        try:
            self.result["stage"] = "live_data_outside_tree_fill"
            physical = source_mount.fill_outside_data(self.data)
            self.result["physical_live_data_filesystem"] = physical
            boundary("after_fill")
            require(helper.root.stat().st_dev != self.data.stat().st_dev,
                    "HELPER_STAGING_SHARES_FULL_LIVE_FILESYSTEM")
            self.result["independent_helper_staging_free_bytes"] = shutil.disk_usage(helper.root).free
            print("Live-data filesystem physically full; verifying older encrypted backup before source stop.", flush=True)
            self.result["stage"] = "older_backup_verification_while_live_filesystem_full"
            boundary("before_older_repository_verification")
            require(shutil.disk_usage(self.data).free == 0, "LIVE_FILESYSTEM_NOT_FULL_BEFORE_OLDER_CHECK")
            require({item["restic_snapshot_id"] for item in repository.list_snapshots()} == {old["restic_snapshot_id"]},
                    "OLDER_SNAPSHOT_SET_CHANGED")
            require(core.manifest_hash(repository.read_manifest(old["restic_snapshot_id"])) == old["manifest_hash"],
                    "OLDER_MANIFEST_CHANGED")
            checked_data = repository.check(read_data=True)
            self.result["older_backup"]["restic_full_data_check"] = checked_data
            require(checked_data["full_data_verified"], "OLDER_FULL_RESTIC_DATA_CHECK_FAILED")
            restored_root = self.run / "older-restored"
            restored = repository.restore(old["restic_snapshot_id"], restored_root,
                                          expected_manifest_hash=old["manifest_hash"])
            self.result["older_backup"]["restic_verified_restore"] = restored
            require(restored["restored_bytes_verified"], "OLDER_RESTORE_BYTES_NOT_VERIFIED")
            require(file_hash(restored_root / "data" / private.name) == file_hash(private), "OLDER_PRIVATE_FILE_CHANGED")
            helper.verify_image_archive(restored_root / "images/vaultwarden.tar", image["Id"])
            require(tree_hash(Path(repository.config.location)) == repository_digest, "OLDER_REPOSITORY_BYTES_CHANGED")
            boundary("after_older_repository_verification")
            require(shutil.disk_usage(self.data).free == 0, "LIVE_FILESYSTEM_NOT_FULL_AFTER_OLDER_CHECK")
            self.result["older_backup"].update(full_data_verified=True, restored_bytes_verified=True,
                repository_bytes_unchanged=True, snapshot_set_unchanged=True, exact_saved_image_verified=True,
                verified_at_zero_free_before_and_after=True)
            self.result["healthy_at_zero_free"] = docker.health(self.source, 60)
            boundary("operation_start")
            require(shutil.disk_usage(self.data).free == 0, "LIVE_FILESYSTEM_NOT_FULL_AT_OPERATION_START")
            self.result["stage"] = "live_data_full_helper_preflight_and_capture"
            try:
                self.result["preflight"] = helper.dispatch(self.request("preflight"))
            except Exception as error:  # noqa: BLE001 -- persist only safe classifications from the frozen helper.
                self.result["preflight_error"] = error_chain(error)
                require(getattr(error, "code", None) == "INSUFFICIENT_SPACE", "UNEXPECTED_LIVE_FULL_PREFLIGHT_ERROR")
            boundary("after_preflight")
            require(shutil.disk_usage(self.data).free == 0, "LIVE_FILESYSTEM_NOT_FULL_AT_CAPTURE_ENTRY")
            request = self.request("capture", 2)
            docker.boundary_observer = boundary
            boundary("capture_entry")
            try:
                captured = helper.dispatch(request)
            except Exception as error:  # noqa: BLE001 -- distinguish a safe capacity rejection from a failed capture.
                self.result["capture_error"] = error_chain(error)
                stops = [call for call in docker.calls[calls:] if call == ("POST", f"/containers/{self.source}/stop")]
                require(getattr(error, "code", None) == "INSUFFICIENT_SPACE" and not stops,
                        "LIVE_FULL_CAPTURE_FAILED_AFTER_ADMISSION")
                outcome = "rejected_before_stop"
            else:
                self.result["fault_capture"] = captured
                require(captured["phase"] == "captured" and captured["source_service_outcome"] == "running",
                        "LIVE_FULL_CAPTURE_DID_NOT_RESUME_SOURCE")
                snapshot = helper.root / "operations" / request.operation_id / "capture"
                core.verify_snapshot(snapshot, captured["manifest_hash"])
                require(persistent_fingerprint(snapshot / "data") == before, "LIVE_FULL_CAPTURE_CONTENT_CHANGED")
                outcome = "coherent_capture_and_source_resumed"
                print("Live-data-full capture source safely resumed and captured content verified.", flush=True)
            boundary("capture_terminal")
            self.result["http_health_after_operation"] = docker.health(self.source, 60)
            after = persistent_fingerprint(self.data)
            self.result.update(logical_content_after_operation=after, source_after_fault=self.source_state())
            require(after == before, "LIVE_LOGICAL_DATABASE_OR_NON_DATABASE_METADATA_CHANGED")
            current = self.source_state()
            require(current["running"] and current["container_id"] == original["container_id"]
                    and current["image_id"] == original["image_id"]
                    and current["restart_policy"] == original["restart_policy"], "ORIGINAL_SOURCE_NOT_RECOVERED")
            stops = [item for item in timeline if item["boundary"] == "after_container_stop"]
            require(not any(item["oom_killed"] or item["exit_code"] == 137 or item["source_running"] for item in stops),
                    "FORCED_OR_UNCLEAN_SOURCE_STOP")
            require(not any(method == "POST" and route.endswith("/kill") for method, route in docker.calls[calls:]),
                    "FORCED_SOURCE_KILL_FORBIDDEN")
            self.result["cases"][DATA_CASE] = {"result": "passed", "outcome": outcome,
                "full_at_operation_start": True, "continuous_fullness_proven": False,
                "logical_sqlite_and_non_database_metadata_unchanged": True, "original_http_healthy": True,
                "forced_kill_calls": 0, "graceful_stops": len(stops),
                "older_full_check_and_verified_restore_at_zero_free": True}
            self.result.update(result="passed", stage="operation_verified", physical_live_data_full_at_operation_start=True,
                fullness_scope="Zero free at operation/capture entry; stop/restart may free WAL blocks. See sampled boundaries.")
        except Exception as error:
            self.result["fault_failure"] = error_chain(error)
            self.result["failure_stage"] = self.result.get("stage")
            self.result["possible_product_defect"] = self.result.get("stage") == "live_data_full_helper_preflight_and_capture"
            raise
        finally:
            docker.boundary_observer = None
            filler_identity = physical or getattr(source_mount, "outside_filler_identity", None)
            if filler_identity is not None:
                self.result["stage"] = "live_data_filler_release_and_original_health"
                boundary("before_filler_release")
                source_mount.remove_outside_filler(self.data, filler_identity)
                boundary("after_filler_release")
                recovery = {"only_own_outside_data_filler_removed": True}
                if not docker.inspect(self.source)["State"]["Running"]:
                    docker.start(self.source)
                    recovery["preexisting_source_started_after_space_release"] = True
                recovery["http_health"] = docker.health(self.source, 60)
                recovery["persistent_fingerprint"] = persistent_fingerprint(self.data)
                recovery["logical_content_and_metadata_unchanged"] = recovery["persistent_fingerprint"] == before
                self.result["after_filler_release"] = recovery
                require(recovery["logical_content_and_metadata_unchanged"], "LIVE_DATA_CHANGED_AFTER_FILLER_RELEASE")
                self.result["safe_original_recovery_verified"] = True
                boundary("after_space_release_http_health")
        self.result["stage"] = "complete"

    def close(self):
        errors = []
        if self.live_data_full and self.source and self.result.get("source_application_readiness"):
            self.docker.boundary_observer = None
            fault_filler_created = any(hasattr(mount, "outside_filler_identity") for mount in self.mounts)
            if fault_filler_created and not self.result.get("safe_original_recovery_verified"):
                self.result["cleanup"] = {"retained_for_unverified_recovery": True,
                    "containers_remaining": len(self.docker.owned_containers),
                    "private_mounts_remaining": sum(m.identity is not None for m in self.mounts),
                    "networks_remaining": len(self.docker.owned_networks), "errors": []}
                raise AssertionError("LIVE_DATA_RECOVERY_UNVERIFIED_RETAIN_OWN_FIXTURE")
            self.docker.health(self.source, 60)
        if self.source and self.data.exists():
            self.result["source_final_before_cleanup"] = self.source_state()
        for container in self.docker.owned_containers:
            try:
                info = self.docker.inspect(container, missing=True)
                if info:
                    require(info["Config"].get("Labels", {}).get(LABEL) == self.owner, "CLEANUP_NOT_OUR_CONTAINER")
                    if info["State"]["Running"]:
                        self.docker.stop(container, 30)
                    self.docker.api("DELETE", f"/containers/{container}?v=true&force=false")
            except Exception as error:  # noqa: BLE001 -- finish all independent owned-resource cleanup attempts.
                errors.extend(error_chain(error))
        for network in self.docker.owned_networks:
            try:
                self.docker.api("DELETE", "/networks/" + network)
            except Exception as error:  # noqa: BLE001 -- retain safe evidence and attempt mount cleanup.
                errors.extend(error_chain(error))
        # Never unmount a source tree if its container could still be using it.
        remaining = [cid for cid in self.docker.owned_containers if self.docker.inspect(cid, missing=True)]
        networks_remaining = [nid for nid in self.docker.owned_networks
                              if self.docker.api("GET", "/networks/" + nid, missing=True)]
        if not remaining:
            for mount in reversed(self.mounts):
                try:
                    mount.close()
                except Exception as error:  # noqa: BLE001 -- retain the workspace if any mount cannot be cleaned.
                    errors.extend(error_chain(error))
        self.result["cleanup"] = {"containers_remaining": len(remaining),
            "private_mounts_remaining": sum(mount.identity is not None for mount in self.mounts),
            "networks_created": len(self.docker.owned_networks), "networks_remaining": len(networks_remaining),
            "containers_removed": len(self.docker.owned_containers) - len(remaining), "errors": errors,
            "no_shared_resource_cleanup": True}
        require(not errors and not remaining and not networks_remaining and not any(m.identity for m in self.mounts),
                "OWN_FIXTURE_CLEANUP_INCOMPLETE")
        require(not any(mount_at(m.path) for m in self.mounts), "UNTRACKED_PRIVATE_MOUNT_REMAINS")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootgo", action="store_true", help="Required only after ROOTGO releases the shared-engine reservation.")
    parser.add_argument("--live-data-full", action="store_true", help="Run the independent live-data filesystem case.")
    parser.add_argument("--rootgo-data-full", action="store_true", help="Required only after ROOTGO_DATA_FULL.")
    parser.add_argument("--output", type=Path, default=PROJECT / "docs/evidence/source-capacity.json")
    args = parser.parse_args(argv)
    authorized = args.rootgo_data_full if args.live_data_full else args.rootgo
    if not authorized:
        gate = "ROOTGO_DATA_FULL" if args.live_data_full else "ROOTGO"
        print(f"Not run: waiting for {gate}. No Docker, mount, source, or repository mutation performed.")
        return 2
    require(os.geteuid() == 0, "DISPOSABLE_ROOT_REQUIRED_FOR_PRIVATE_TMPFS")
    previous = json.loads(args.output.read_text()) if args.output.is_file() else {}
    if args.live_data_full:
        require(previous.get("result") == "passed", "PRESERVED_STAGING_PASS_REQUIRED")
    attempts = prior_failed_attempts(previous.get("live_data_filesystem_full", {}) if args.live_data_full else previous)
    limits = ([*LIMITATIONS[:2], "Only the dedicated 16 MiB live-data tmpfs is filled, outside the enrolled data tree.",
               "Source stop/restart can free WAL blocks; zero free at operation start is the tested boundary.",
               "No continuous-fullness, independent watchdog/reboot, login, or new application restore claim."]
              if args.live_data_full else LIMITATIONS)
    result = {"schema_version": 1, "acceptance_ids": ["AC26"], "recorded_at": datetime.now(UTC).isoformat(),
              "result": "failed", "synthetic_disposable_only": True, "cases": {}, "limitations": limits,
              "frozen_helper": verify_bundle(), "failed_attempts": attempts}
    if args.live_data_full:
        result["preparation_checks"] = previous.get("live_data_filesystem_full", {}).get("preparation_checks", {})
    runtime = load_runtime()
    # /root ancestors satisfy helper trust policy; never chmod the shared /tmp or /var/tmp directories.
    run = Path(tempfile.mkdtemp(prefix="vrw-source-capacity-", dir="/root"))
    drill = Drill(run, result, runtime, live_data_full=args.live_data_full)
    started = time.monotonic()
    failed = False
    try:
        drill.execute()
    except Exception as error:  # noqa: BLE001 -- persist safe evidence of any fixture failure.
        failed = True
        result.update(result="failed", failure=error_chain(error),
                      failure_stage=result.get("failure_stage", result.get("stage")))
    finally:
        try:
            drill.close()
        except Exception as error:  # noqa: BLE001 -- never remove a workspace after incomplete cleanup.
            failed = True
            result.update(result="failed", cleanup_failure=error_chain(error), retained_private_workspace=str(run))
        else:
            shutil.rmtree(run)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        saved = merge_live_data_result(previous, result) if args.live_data_full else result
        args.output.write_text(json.dumps(saved, indent=2) + "\n")
    print(json.dumps({"result": result["result"], "output": str(args.output), "cases": len(result["cases"])}))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

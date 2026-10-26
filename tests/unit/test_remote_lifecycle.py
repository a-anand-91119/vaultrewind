"""Filesystem/journal state tests. Docker and systemd are controlled unit doubles."""
import copy
import hashlib
import io
import json
import os
import sqlite3
import tarfile
import time
import uuid
from pathlib import Path

import pytest

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote import helper as helper_module
from vaultrewind.remote.docker import require_public_endpoint, verify_published_ports
from vaultrewind.remote.helper import Helper, utc
from vaultrewind.remote.journal import Journal
from vaultrewind.remote.policy import Policy
from vaultrewind.remote.protocol import Request, send_frames

INSTANCE = "11111111-1111-4111-8111-111111111111"
CID = "a" * 64
IMAGE_CONFIG = b'{"architecture":"amd64","os":"linux","config":{}}'
IMAGE = "sha256:" + hashlib.sha256(IMAGE_CONFIG).hexdigest()
PORTS = {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18103"}]}


class DockerFixture:
    def __init__(self, data, running):
        self.calls = []
        self.items = {CID: {"Id": CID, "Name": "/synthetic", "Image": IMAGE,
                           "State": {"Running": running}, "Config": {"Env": [], "Entrypoint": None, "Cmd": None, "Labels": {}},
                           "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "NetworkMode": "bridge", "PortBindings": copy.deepcopy(PORTS)},
                           "NetworkSettings": {"Ports": copy.deepcopy(PORTS) if running else {}},
                           "Mounts": [{"Destination": "/data", "Source": str(data), "Type": "bind", "RW": True, "Propagation": "rprivate"}]}}
        self.bad_candidate = False
        self.bad_final = False
        self.serial = 0
        self.volumes = {}
        self.networks = {}
        self.base = data.parent

    def info(self):
        return {"ID": "daemon-identity", "OSType": "linux"}

    def inspect(self, identity, missing=False):
        item = self.items.get(identity) or next((i for i in self.items.values() if i["Name"] == "/" + identity), None)
        if item is None and not missing:
            raise VaultRewindError("MISSING", "Synthetic container is missing")
        return copy.deepcopy(item)

    def image(self, identity):
        return {"Id": IMAGE, "Os": "linux", "Architecture": "amd64", "RepoDigests": [], "Config": {"Entrypoint": None, "Cmd": None}}

    def network(self, name):
        return self.networks.get(name, {"Name": name, "Driver": "bridge", "Scope": "local", "Internal": False})

    def containers(self):
        return [{"Id": cid, "Labels": i["Config"].get("Labels", {}), "Mounts": i["Mounts"], "Ports": []} for cid, i in self.items.items()]

    def restart_policy(self, cid, policy):
        self.calls.append(("restart", cid, policy))
        self.items[cid]["HostConfig"]["RestartPolicy"] = policy

    def stop(self, cid, timeout=30):
        self.calls.append(("stop", cid))
        self.items[cid]["State"]["Running"] = False
        self.items[cid]["NetworkSettings"]["Ports"] = {}

    def start(self, cid):
        self.calls.append(("start", cid))
        self.items[cid]["State"]["Running"] = True
        self.items[cid]["NetworkSettings"]["Ports"] = copy.deepcopy(self.items[cid]["HostConfig"].get("PortBindings") or {})

    def public_health(self, cid, expected, window):
        # Unit double verifies real mapping rules; real HTTP has opt-in coverage.
        require_public_endpoint(expected)
        verify_published_ports(self.inspect(cid), expected)
        return {"public_ports_verified": True, "public_endpoint_verified": True,
                "public_endpoint_count": sum(len(bindings) for bindings in expected.values())}

    def health(self, cid, window):
        role = self.items[cid]["Config"].get("Labels", {}).get("org.vaultrewind.role")
        if role == "candidate" and self.bad_candidate or role == "active" and self.bad_final:
            raise VaultRewindError("APPLICATION_NOT_READY", "Synthetic readiness failure")
        return {"application_started": True, "internal_http_alive": True}

    def save_image(self, image, path, max_bytes):
        with tarfile.open(path, "w") as tar:
            config = tarfile.TarInfo("config.json")
            config.size = len(IMAGE_CONFIG)
            tar.addfile(config, io.BytesIO(IMAGE_CONFIG))
            manifest = json.dumps([{"Config": "config.json", "Layers": []}]).encode()
            item = tarfile.TarInfo("manifest.json")
            item.size = len(manifest)
            tar.addfile(item, io.BytesIO(manifest))

    def load_image(self, path):
        self.calls.append(("load_image",))

    def create(self, name, config):
        self.serial += 1
        cid = f"{self.serial:064x}"
        mounts = []
        for m in config["HostConfig"]["Mounts"]:
            source = m["Source"] if m["Type"] == "bind" else self.volumes[m["Source"]]["Mountpoint"]
            mounts.append({"Destination": m["Target"], "Source": source, "Type": m["Type"], "RW": not m["ReadOnly"],
                           "Name": m["Source"] if m["Type"] == "volume" else None})
        self.items[cid] = {"Id": cid, "Name": "/" + name, "Image": config["Image"], "State": {"Running": False},
                           "Config": {k: v for k, v in config.items() if k not in ("HostConfig", "Image")},
                           "HostConfig": config["HostConfig"], "Mounts": mounts}
        self.items[cid]["NetworkSettings"] = {"Ports": {}}
        self.calls.append(("create", cid, copy.deepcopy(config)))
        return cid

    def rename(self, cid, name):
        self.items[cid]["Name"] = "/" + name

    def remove(self, cid):
        del self.items[cid]

    def volume(self, name, missing=False):
        return self.volumes.get(name)

    def remove_volume(self, name):
        import shutil
        volume = self.volumes.pop(name, None)
        if volume:
            shutil.rmtree(volume['Mountpoint'])

    def create_volume(self, name, labels):
        path = self.base / name
        path.mkdir()
        volume = {"Name": name, "Mountpoint": str(path), "Driver": "local", "Scope": "local", "Options": {}, "Labels": labels}
        self.volumes[name] = volume
        return volume


class RecoveryFixture:
    def __init__(self):
        self.armed = []

    def verify(self):
        pass

    def arm(self, journal, seconds):
        self.armed.append(journal.value["operation_id"])
        journal.value.update({"watchdog_armed": True, "deadline": time.time() + seconds,
                              "monotonic_deadline": time.monotonic() + seconds,
                              "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()})
        journal.save()

    def disarm(self, journal):
        journal.value["watchdog_armed"] = False
        journal.save()


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    # Root policy validation itself has dedicated tests. tmp_path lives under writable /tmp.
    monkeypatch.setattr(helper_module, "root_trusted", lambda *a, **k: None)
    data = tmp_path / "data"
    data.mkdir()
    with sqlite3.connect(data / "db.sqlite3") as db:
        db.executescript("CREATE TABLE users(id TEXT); CREATE TABLE ciphers(id TEXT); INSERT INTO users VALUES ('synthetic');")
    (data / "secret").write_bytes(b"synthetic-private-file")
    (data / "secret").chmod(0o600)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    docker = DockerFixture(data, True)
    value = {"schema_version": 1, "machine_id": Path("/etc/machine-id").read_text().strip(), "daemon_id": "daemon-identity",
             "instances": {INSTANCE: {"container_id": CID, "container_name": "synthetic", "ownership": "exclusive",
                                      "external_dependencies_ready": True, "allowed_operations": ["discover", "preflight", "capture", "export", "stage_restore", "commit_restore", "rollback", "status", "cancel", "cleanup"],
                                      "allowed_image_ids": [IMAGE], "allowed_networks": ["bridge"], "port_bindings": copy.deepcopy(PORTS),
                                      "free_space_reserve": 0, "validation_window": 1,
                                      "mounts": [{"source": str(data), "target": "/data", "snapshot_path": "data", "type": "bind", "read_only": False}]}}}
    service = Helper(Policy(value, state), docker, RecoveryFixture())
    return service, docker, data


def request(verb, operation_id=None, fence=1, payload=None):
    payload = payload or {}
    return Request(INSTANCE, operation_id or str(uuid.uuid4()), fence, verb + ":" + payload.get("phase", "default"), verb, payload)


def capture(service, fence=1):
    op = str(uuid.uuid4())
    result = service.dispatch(request("capture", op, fence, {"snapshot_uuid": str(uuid.uuid4()), "controller_time": utc()}))
    return op, result


def stage(service, capture_op, fence=2):
    op = str(uuid.uuid4())
    journal = Journal(service.root, capture_op).value
    archive = service.root / "operations" / capture_op / "capture.tar"
    wire = io.BytesIO()
    with archive.open("rb") as stream:
        transfer = send_frames(stream, wire, 1024**3)
    payload = {"controller_time": utc(), "manifest_hash": journal["manifest_hash"],
               "expected_fingerprint": service.inspect(service.policy.instance(INSTANCE))["fingerprint"],
               "archive_bytes": transfer["bytes"], "archive_sha256": transfer["sha256"]}
    service.dispatch(request("stage_restore", op, fence, payload), incoming=io.BytesIO(wire.getvalue()))
    return op


def safety_ack(value):
    return {"snapshot_uuid": value["safety_snapshot_uuid"], "manifest_hash": value["safety_manifest_hash"],
            "restic_snapshot_id": "b" * 64, "repository_id": str(uuid.uuid4()), "durable": True,
            "encrypted": True, "pinned": True, "stored_copy_verified": True}


def prepare(service, op):
    return service.dispatch(request("commit_restore", op, 2, {"phase": "prepare_safety"}))


def switch(service, op, safety):
    return service.dispatch(request("commit_restore", op, 2, {"phase": "switch_validate", "safety_ack": safety_ack(safety)}))


def test_backup_initially_stopped_stays_stopped_and_captures_unknown_private_file(fixture):
    service, docker, data = fixture
    docker.items[CID]["State"]["Running"] = False
    op, result = capture(service)
    assert result["phase"] == "captured"
    assert result["source_service_outcome"] == "stopped"
    assert not any(call[0] == "start" for call in docker.calls)
    copied = service.root / "operations" / op / "capture" / "data" / "secret"
    assert copied.read_bytes() == (data / "secret").read_bytes()
    assert copied.stat().st_mode & 0o777 == 0o600
    service.policy.value["max_staging_bytes"] = 1024**3
    accounting = service.preflight(service.policy.instance(INSTANCE), {"controller_time": utc()})
    assert accounting["source_staging_bytes"] > 0 and accounting["image_cache_bytes"] > 0
    assert accounting["staging_bytes"] == accounting["source_staging_bytes"] + accounting["image_cache_bytes"]
    assert accounting["staging_quota_bytes"] == 1024**3


def test_source_resumes_before_normalization(fixture, monkeypatch):
    service, docker, _data = fixture
    original = helper_module.core.normalize_sqlite
    def checked(root):
        assert docker.items[CID]["State"]["Running"] is True
        return original(root)
    monkeypatch.setattr(helper_module.core, "normalize_sqlite", checked)
    capture(service)
    assert docker.items[CID]["State"]["Running"]


def test_safety_ack_required_before_any_generation_switch(fixture):
    service, docker, data = fixture
    captured, _ = capture(service)
    (data / "new-writes").write_text("later")
    op = stage(service, captured)
    safety = prepare(service, op)
    assert safety["phase"] == "safety_ready"
    assert not docker.items[CID]["State"]["Running"]
    with pytest.raises(VaultRewindError, match="safety"):
        service.dispatch(request("commit_restore", op, 2, {"phase": "switch_validate"}))
    assert (data / "new-writes").read_text() == "later"
    value = Journal(service.root, op).value
    assert all(step["phase"] == "materialized" for step in value["generation_steps"])
    bad = safety_ack(safety)
    bad["manifest_hash"] = "0" * 64
    with pytest.raises(VaultRewindError, match="different"):
        service.dispatch(request("commit_restore", op, 2, {"phase": "switch_validate", "safety_ack": bad}))


def test_candidate_failure_recovers_old_generation_and_running_state(fixture):
    service, docker, data = fixture
    captured, _ = capture(service)
    (data / "new-writes").write_text("keep")
    op = stage(service, captured)
    safety = prepare(service, op)
    docker.bad_candidate = True
    with pytest.raises(VaultRewindError):
        switch(service, op, safety)
    value = Journal(service.root, op).value
    assert value["phase"] == "rolled_back"
    assert (data / "new-writes").read_text() == "keep"
    assert docker.items[CID]["State"]["Running"]
    candidate = next(call[2] for call in docker.calls if call[0] == "create")
    assert candidate["HostConfig"]["NetworkMode"] == "none"
    assert candidate["HostConfig"]["PortBindings"] == {}
    assert candidate["HostConfig"]["PublishAllPorts"] is False


def test_activation_failure_never_reverts_to_old_writes(fixture):
    service, docker, data = fixture
    captured, _ = capture(service)
    (data / "new-writes").write_text("old-generation")
    op = stage(service, captured)
    switch(service, op, prepare(service, op))
    assert not (data / "new-writes").exists()
    docker.bad_final = True
    with pytest.raises(VaultRewindError):
        service.dispatch(request("commit_restore", op, 2, {"phase": "activate"}))
    (data / "post-activation-writes").write_text("must survive")
    service.recover(op)
    value = Journal(service.root, op).value
    assert value["phase"] == "needs_attention"
    assert value["activation_started"] is True
    assert (data / "post-activation-writes").read_text() == "must survive"
    assert not (data / "new-writes").exists()
    assert not docker.items[CID]["State"]["Running"]
    with pytest.raises(VaultRewindError, match="new confirmed"):
        service.dispatch(request("rollback", op, 2))


def test_restore_initially_stopped_validates_candidate_but_does_not_start_public_service(fixture):
    service, docker, _data = fixture
    docker.items[CID]["State"]["Running"] = False
    captured, _ = capture(service)
    op = stage(service, captured)
    switch(service, op, prepare(service, op))
    result = service.dispatch(request("commit_restore", op, 2, {"phase": "activate"}))
    assert result["phase"] == "data_restored_service_stopped"
    active = service.active(INSTANCE)
    assert not docker.items[active["container_id"]]["State"]["Running"]
    assert not docker.items[CID]["State"]["Running"]
    assert service.inspect(service.policy.instance(INSTANCE))["source_state"] == "stopped"


def test_recovery_reconciles_death_between_first_rename_and_journal_update(fixture):
    service, _docker, data = fixture
    captured, _ = capture(service)
    (data / "new-writes").write_text("preserve")
    op = stage(service, captured)
    prepare(service, op)
    journal = Journal(service.root, op)
    step = journal.value["generation_steps"][0]
    step["phase"] = "old_rename_started"
    journal.transition("switching")
    os.rename(data, step["old"])
    service.recover(op)
    assert (data / "new-writes").read_text() == "preserve"
    assert Journal(service.root, op).value["phase"] == "rolled_back"


@pytest.mark.parametrize("setting", ["Privileged", "Devices", "CapAdd", "AutoRemove", "VolumesFrom"])
def test_discovery_blocks_unsafe_docker_settings_before_writes(fixture, setting):
    service, docker, _ = fixture
    docker.items[CID]["HostConfig"][setting] = True
    with pytest.raises(VaultRewindError):
        service.dispatch(request("discover"))
    assert docker.calls == []


def test_external_database_and_unapproved_image_fail_read_only(fixture):
    service, docker, _ = fixture
    docker.items[CID]["Config"]["Env"] = ["DATABASE_URL=postgresql://do-not-log:secret@db/test"]
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request("discover"))
    assert error.value.code == "UNSUPPORTED_DATABASE"
    assert "secret" not in str(error.value)
    assert docker.calls == []


def test_arbitrary_payload_path_and_command_rejected(fixture):
    service, docker, _ = fixture
    for key in ("path", "command", "mounts", "docker_args"):
        with pytest.raises(VaultRewindError):
            service.dispatch(request("capture", payload={key: ";touch /root/pwned"}))
    assert docker.calls == []


def test_prepared_empty_alternate_restore_never_touches_original_source(fixture):
    service, docker, original_data = fixture
    captured, _ = capture(service)
    original_calls = len(docker.calls)
    alternate = str(uuid.uuid4())
    enrolled = copy.deepcopy(service.policy.value["instances"][INSTANCE])
    alternate_data = original_data.parent / "alternate"
    enrolled.update({"container_id": None, "container_name": "synthetic-alternate",
                     "recovery_profile": {"revision": 1, "environment": {"DOMAIN": "https://alternate.invalid"}}})
    enrolled["mounts"][0]["source"] = str(alternate_data)
    service.policy.value["instances"][alternate] = enrolled
    op = str(uuid.uuid4())
    archive = service.root / "operations" / captured / "capture.tar"
    wire = io.BytesIO()
    with archive.open("rb") as stream:
        transfer = send_frames(stream, wire, 1024**3)
    view = service.inspect(service.policy.instance(alternate))
    payload = {"controller_time": utc(), "manifest_hash": Journal(service.root, captured).value["manifest_hash"],
               "expected_fingerprint": view["fingerprint"], "archive_bytes": transfer["bytes"], "archive_sha256": transfer["sha256"],
               "start_on_completion": True}
    service.dispatch(Request(alternate, op, 2, "stage", "stage_restore", payload), incoming=io.BytesIO(wire.getvalue()))
    safety = service.dispatch(Request(alternate, op, 2, "safety", "commit_restore", {"phase": "prepare_safety"}))
    assert safety["empty_target"] is True
    service.dispatch(Request(alternate, op, 2, "switch", "commit_restore", {"phase": "switch_validate"}))
    result = service.dispatch(Request(alternate, op, 2, "activate", "commit_restore", {"phase": "activate"}))
    assert result["phase"] == "complete"
    assert (alternate_data / "secret").read_bytes() == (original_data / "secret").read_bytes()
    assert docker.items[CID]["State"]["Running"]
    assert not any(call[0] in ("stop", "restart", "start") and call[1] == CID for call in docker.calls[original_calls:])


def test_restore_cancel_recovers_original_before_terminal_result(fixture):
    service, docker, data = fixture
    captured, _ = capture(service)
    op = stage(service, captured)
    prepare(service, op)
    assert not docker.items[CID]["State"]["Running"]
    result = service.dispatch(request("cancel", op, 2))
    assert result["phase"] == "rolled_back"
    assert docker.items[CID]["State"]["Running"]
    assert (data / "secret").exists()


def test_post_activation_reconciliation_records_cleanup_grace_and_generation_usage(fixture):
    service, docker, _data = fixture
    captured, _ = capture(service)
    op = stage(service, captured)
    switch(service, op, prepare(service, op))
    docker.bad_final = True
    with pytest.raises(VaultRewindError):
        service.dispatch(request("commit_restore", op, 2, {"phase": "activate"}))
    docker.bad_final = False
    result = service.recover(op)
    assert result["phase"] == "complete"
    assert result["rollback_cleanup_after"] > time.time()
    assert result["generation_logical_bytes"] > 0
    assert result["retained_generation_logical_bytes"] > 0
    with pytest.raises(VaultRewindError, match="grace period"):
        service.dispatch(request("cleanup", op, 2, {"kind": "generations"}))


def test_cleaned_export_reports_expired_staging_without_recapture(fixture):
    service, docker, _ = fixture
    op, _ = capture(service)
    calls = len(docker.calls)
    service.dispatch(request("cleanup", op, 1))
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request("export", op, 1), outgoing=io.BytesIO())
    assert error.value.code == "STAGING_EXPIRED"
    assert len(docker.calls) == calls


def test_immutable_capture_export_still_works_after_a_later_capture(fixture):
    service, docker, _ = fixture
    first, _ = capture(service, fence=1)
    capture(service, fence=2)
    mutations = len(docker.calls)
    output = io.BytesIO()
    transfer = service.dispatch(request("export", first, 1), outgoing=output)
    assert transfer["sha256"] == Journal(service.root, first).value["sha256"]
    assert len(docker.calls) == mutations
    assert service.dispatch(request("status", first, 1))["phase"] == "captured"
    service.dispatch(request("cleanup", first, 1))
    assert not (service.root / "operations" / first).exists()


def test_status_reconciliation_claims_higher_fence_before_next_restore_phase(fixture):
    service, docker, _ = fixture
    captured, _ = capture(service)
    op = stage(service, captured)
    state = service.dispatch(request("status", op, 3))
    assert state["fencing_token"] == 3
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request("commit_restore", op, 2, {"phase": "prepare_safety"}))
    assert error.value.code == "STALE_FENCE"
    assert docker.items[CID]["State"]["Running"]


def test_unknown_status_does_not_create_a_phantom_resource_owner(fixture):
    service, _, _ = fixture
    assert service.dispatch(request("status", fence=100)) == {"exists": False}
    assert not (service.root / "fences").exists()
    assert capture(service, fence=1)[1]["phase"] == "captured"


def test_status_closes_interrupted_preflight_without_source_side_effects(fixture):
    service, docker, _ = fixture
    op = str(uuid.uuid4())
    with pytest.raises(VaultRewindError):
        service.dispatch(request("capture", op, 1, {"snapshot_uuid": str(uuid.uuid4())}))
    journal = Journal(service.root, op)
    journal.value["owner"] = None
    journal.save()
    assert service.dispatch(request("status", op, 2))["phase"] == "failed_safe"
    assert docker.calls == []
    assert capture(service, fence=3)[1]["phase"] == "captured"


@pytest.mark.parametrize('relationship', ['ancestor', 'descendant', 'symlink', 'equal', 'label_spoof', 'volume_alias'])
def test_discovery_rejects_stopped_peer_storage_overlap(fixture, relationship):
    service, docker, data = fixture
    source = data
    if relationship == 'ancestor':
        source = data.parent
    elif relationship == 'descendant':
        source = data / 'child'
        source.mkdir()
    elif relationship == 'symlink':
        source = data.parent / 'alias'
        source.symlink_to(data, target_is_directory=True)
    peer = copy.deepcopy(docker.items[CID])
    peer['Id'] = 'c' * 64
    peer['State']['Running'] = False
    peer['HostConfig']['RestartPolicy'] = {'Name': 'always'}
    peer['Mounts'][0]['Source'] = str(source)
    if relationship == 'label_spoof':
        peer['Config']['Labels'] = {'org.vaultrewind.instance': INSTANCE}
    if relationship == 'volume_alias':
        peer['Mounts'][0].update(Type='volume', Name='peer-volume')
    docker.items[peer['Id']] = peer
    with pytest.raises(VaultRewindError, match='overlaps') as error:
        service.inspect(service.policy.instance(INSTANCE))
    assert error.value.code == 'UNKNOWN_WRITER'


def test_physical_file_alias_and_sibling_boundaries(tmp_path):
    from vaultrewind.remote.docker import paths_overlap
    left, right = tmp_path / 'left', tmp_path / 'right'
    left.mkdir()
    right.mkdir()
    source = left / 'config'
    source.write_text('synthetic')
    alias = right / 'alias'
    os.link(source, alias)
    assert paths_overlap(source, alias)
    assert not paths_overlap(left, right)
    assert not paths_overlap(left / 'missing', right / 'missing')


def test_empty_target_rejects_parent_writer(fixture):
    service, docker, data = fixture
    empty = data.parent / 'empty'
    empty.mkdir()
    policy = service.policy.value['instances'][INSTANCE]
    policy['container_id'] = None
    policy['container_name'] = 'empty-target'
    policy['mounts'][0]['source'] = str(empty)
    docker.items[CID]['Mounts'][0]['Source'] = str(data.parent)
    with pytest.raises(VaultRewindError) as error:
        service.inspect(service.policy.instance(INSTANCE))
    assert error.value.code == 'UNKNOWN_WRITER'


def test_discard_candidate_removes_generations_and_staging_idempotently(fixture, monkeypatch):
    from vaultrewind.remote import cleanup
    monkeypatch.setattr(cleanup, 'root_trusted', lambda *a, **k: None)
    service, docker, data = fixture
    cap, _ = capture(service)
    restore = stage(service, cap)
    safety = service.dispatch(request('commit_restore', restore, 2, {'phase': 'prepare_safety'}))
    service.dispatch(request('commit_restore', restore, 2, {'phase': 'switch_validate', 'safety_ack': safety_ack(safety)}))
    result = service.dispatch(request('rollback', restore, 2))
    assert result['phase'] == 'rolled_back'
    value = Journal(service.root, restore).value
    candidate = Path(value['generation_steps'][0]['new'])
    assert candidate.exists()
    before = (data / 'secret').read_bytes()
    for _ in range(2):
        result = service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
        assert result['candidate_cleanup_outcome'] == 'complete'
        assert result['candidate_cleanup_remaining'] == 0
        assert result['discarded_candidate_bytes'] > 0
    assert not candidate.parent.exists()
    assert not (service.root / 'operations' / restore).exists()
    assert (data / 'secret').read_bytes() == before
    assert docker.items[CID]['State']['Running']


def test_discard_candidate_preserves_activation_and_changed_identity(fixture, monkeypatch):
    from vaultrewind.remote import cleanup
    monkeypatch.setattr(cleanup, 'root_trusted', lambda *a, **k: None)
    service, _, _ = fixture
    cap, _ = capture(service)
    restore = stage(service, cap)
    service.dispatch(request('rollback', restore, 2))
    journal = Journal(service.root, restore)
    journal.value['activation_started'] = True
    journal.save()
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
    assert error.value.code == 'CLEANUP_UNSAFE'
    journal.value['activation_started'] = False
    journal.value['generation_steps'][0]['new_identity'][1] += 1
    journal.save()
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
    assert error.value.code == 'CLEANUP_UNSAFE'


def test_discard_candidate_bounded_retry_then_resume(fixture, monkeypatch):
    from vaultrewind.remote import cleanup
    monkeypatch.setattr(cleanup, 'root_trusted', lambda *a, **k: None)
    service, _, _ = fixture
    cap, _ = capture(service)
    restore = stage(service, cap)
    service.dispatch(request('rollback', restore, 2))
    real = cleanup.delete_path
    attempts = []
    def broken(path):
        attempts.append(path)
        raise OSError('synthetic transient filesystem failure')
    monkeypatch.setattr(cleanup, 'delete_path', broken)
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
    assert error.value.code == 'CANDIDATE_CLEANUP_INCOMPLETE' and error.value.retryable
    assert len(attempts) == 3
    monkeypatch.setattr(cleanup, 'delete_path', real)
    result = service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
    assert result['candidate_cleanup_outcome'] == 'complete'


def test_immutable_export_releases_host_lock(fixture, monkeypatch):
    from vaultrewind.remote.journal import Locks
    service, _, _ = fixture
    op, _ = capture(service)
    original = helper_module.send_frames
    def verify_unlocked(source, target, maximum):
        with Locks(service.root, Journal(service.root, op).value['resource_keys']):
            pass
        return original(source, target, maximum)
    monkeypatch.setattr(helper_module, 'send_frames', verify_unlocked)
    assert service.dispatch(request('export', op), outgoing=io.BytesIO())['bytes'] > 0


@pytest.mark.parametrize('unsafe', ['running', 'public', 'restart', 'owner'])
def test_discard_rejects_unproven_candidate(fixture, monkeypatch, unsafe):
    from vaultrewind.remote import cleanup
    from vaultrewind.remote.docker import create_config
    monkeypatch.setattr(cleanup, 'root_trusted', lambda *a, **k: None)
    service, docker, _ = fixture
    cap, _ = capture(service)
    restore = stage(service, cap)
    service.dispatch(request('rollback', restore, 2))
    journal = Journal(service.root, restore)
    config = create_config(journal.value['restore_descriptor'], service.generation_mounts(journal, switched=False), INSTANCE, restore, isolated=True)
    cid = docker.create('leftover', config)
    journal.value['candidate_id'] = cid
    journal.save()
    container = docker.items[cid]
    if unsafe == 'running':
        container['State']['Running'] = True
    elif unsafe == 'public':
        container['HostConfig']['PortBindings'] = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19000'}]}
    elif unsafe == 'restart':
        container['HostConfig']['RestartPolicy'] = {'Name': 'always'}
    else:
        container['Config']['Labels']['org.vaultrewind.instance'] = str(uuid.uuid4())
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
    assert error.value.code == 'CLEANUP_UNSAFE'
    assert docker.inspect(cid) is not None
    assert Path(journal.value['generation_steps'][0]['new']).exists()


def test_safety_export_hashing_has_watchdog_owner(fixture, monkeypatch):
    service, _, _ = fixture
    cap, _ = capture(service)
    restore = stage(service, cap)
    service.dispatch(request('commit_restore', restore, 2, {'phase': 'prepare_safety'}))
    original = helper_module.file_hash
    checked = []
    def verify_owner(path):
        value = Journal(service.root, restore).value
        assert value['owner']['pid'] == os.getpid() and value['watchdog_armed']
        checked.append(path)
        return original(path)
    monkeypatch.setattr(helper_module, 'file_hash', verify_owner)
    service.dispatch(request('export', restore, 2, {'kind': 'safety'}), outgoing=io.BytesIO())
    assert checked
    assert Journal(service.root, restore).value['owner'] is None


def test_empty_verification_runner_is_empty_again_after_discard(fixture, monkeypatch):
    from vaultrewind.remote import cleanup
    monkeypatch.setattr(cleanup, 'root_trusted', lambda *a, **k: None)
    service, docker, data = fixture
    cap, _ = capture(service)
    empty = data.parent / 'runner'
    empty.mkdir()
    policy = service.policy.value['instances'][INSTANCE]
    policy.update(container_id=None, container_name='empty-runner',
                  recovery_profile={'environment': {'DOMAIN': 'https://runner.invalid'}})
    policy['mounts'][0]['source'] = str(empty)
    restore = stage(service, cap)
    safety = service.dispatch(request('commit_restore', restore, 2, {'phase': 'prepare_safety'}))
    assert safety['empty_target']
    service.dispatch(request('commit_restore', restore, 2, {'phase': 'switch_validate'}))
    service.dispatch(request('rollback', restore, 2))
    result = service.dispatch(request('cleanup', restore, 2, {'kind': 'discard_candidate'}))
    assert result['candidate_cleanup_outcome'] == 'complete'
    assert not any(empty.iterdir())
    assert service.inspect(service.policy.instance(INSTANCE))['empty_target']
    assert docker.items[CID]['State']['Running']
    assert (data / 'secret').exists()


def test_failed_recovery_remains_armed_without_unbounded_duplicate_history(fixture, monkeypatch):
    service, docker, _ = fixture
    op, _ = capture(service)
    journal = Journal(service.root, op)
    journal.value.update(phase='quiescing', watchdog_armed=True)
    journal.save()
    def unavailable(_):
        raise VaultRewindError('DOCKER_UNAVAILABLE', 'Synthetic daemon outage')
    monkeypatch.setattr(docker, 'start', unavailable)
    service.recover(op)
    first = Journal(service.root, op).value
    assert first['phase'] == 'source_recovery_failed' and first['watchdog_armed']
    for _ in range(10):
        service.recover(op)
    later = Journal(service.root, op).value
    assert later['history'] == first['history'] and later['watchdog_armed']


def test_armed_safe_phase_finishes_interrupted_disarm(fixture):
    service, _, _ = fixture
    op, _ = capture(service)
    journal = Journal(service.root, op)
    journal.value.update(phase='failed_safe', watchdog_armed=True)
    journal.save()
    service.recover(op)
    assert not Journal(service.root, op).value['watchdog_armed']


def public_profile(fixture, *, repaired=False):
    service, docker, _ = fixture
    item = service.policy.value['instances'][INSTANCE]
    ports = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18103'}]}
    item['port_bindings'] = ports
    docker.items[CID]['HostConfig']['PortBindings'] = copy.deepcopy(ports)
    docker.items[CID]['NetworkSettings']['Ports'] = {}
    docker.networks['bridge'] = {'Driver': 'bridge', 'Internal': True}
    if repaired:
        item['allowed_networks'] = ['bridge', 'public']
        item['recovery_profile'] = {'network': 'public', 'port_bindings': ports}
    return item


def test_broken_source_ports_do_not_block_capture_or_corrected_restore_profile(fixture):
    service, docker, _ = fixture
    public_profile(fixture, repaired=True)
    result = service.preflight(service.policy.instance(INSTANCE), {'controller_time': utc()})
    assert result['restore_ready'] and not result['current_public_ports_ready']
    assert result['current_public_error_code'] == 'PUBLIC_PORTS_UNAVAILABLE'
    captured, result = capture(service)
    assert result['phase'] == 'captured' and docker.items[CID]['State']['Running']
    staged = stage(service, captured)
    descriptor = Journal(service.root, staged).value['restore_descriptor']
    assert descriptor['host_config']['NetworkMode'] == 'public'


def test_invalid_desired_profile_reports_unready_and_blocks_before_downtime(fixture):
    service, docker, _ = fixture
    public_profile(fixture)
    preflight = service.preflight(service.policy.instance(INSTANCE), {'controller_time': utc()})
    assert preflight['recovery_verified'] and not preflight['restore_ready']
    assert preflight['restore_error_code'] == 'PUBLIC_NETWORK_UNPUBLISHABLE'
    discovered = service.dispatch(request('discover'))
    assert not discovered['restore_enabled'] and not discovered['restore_ready']
    captured, _ = capture(service)
    docker.calls.clear()
    with pytest.raises(VaultRewindError) as error:
        stage(service, captured)
    assert error.value.code == 'PUBLIC_NETWORK_UNPUBLISHABLE'
    assert not service.recovery.armed[1:] and not any(c[0] == 'stop' for c in docker.calls)
    assert docker.items[CID]['State']['Running']


def test_prepare_safety_rechecks_network_before_arming(fixture):
    service, docker, _ = fixture
    public_profile(fixture, repaired=True)
    captured, _ = capture(service)
    op = stage(service, captured)
    docker.networks['public'] = {'Driver': 'bridge', 'Internal': True}
    docker.calls.clear()
    with pytest.raises(VaultRewindError) as error:
        prepare(service, op)
    assert error.value.code == 'PUBLIC_NETWORK_UNPUBLISHABLE'
    assert not any(c[0] == 'stop' for c in docker.calls)
    assert Journal(service.root, op).value['phase'] == 'staged'


def test_public_failure_preserves_new_generation_and_never_reconciles_internal_only(fixture, monkeypatch):
    service, docker, data = fixture
    public_profile(fixture, repaired=True)
    captured, _ = capture(service)
    op = stage(service, captured)
    safety = prepare(service, op)
    switch(service, op, safety)
    original_start = docker.start
    def missing_allocation(cid):
        original_start(cid)
        docker.items[cid]['NetworkSettings']['Ports'] = {}
    monkeypatch.setattr(docker, 'start', missing_allocation)
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(request('commit_restore', op, 2, {'phase': 'activate'}))
    assert error.value.code == 'PUBLIC_PORTS_UNAVAILABLE'
    (data / 'new-writes').write_text('preserve after public failure')
    before = data.stat().st_ino
    result = service.recover(op)
    assert result['phase'] == 'needs_attention' and result['activation_started']
    assert (data / 'new-writes').read_text() == 'preserve after public failure'
    assert data.stat().st_ino == before and not docker.items[CID]['State']['Running']
    assert docker.items[Journal(service.root, op).value['final_id']]['State']['Running']


def test_legacy_internal_only_success_status_downgrades_without_restart(fixture):
    service, docker, data = fixture
    captured, _ = capture(service)
    op = stage(service, captured)
    switch(service, op, prepare(service, op))
    service.dispatch(request('commit_restore', op, 2, {'phase': 'activate'}))
    journal = Journal(service.root, op)
    journal.value['final_health'] = {'internal_http_alive': True}
    journal.value['restore_descriptor']['host_config']['PortBindings'] = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18103'}]}
    docker.items[journal.value['final_id']]['NetworkSettings']['Ports'] = {}
    journal.save()
    docker.calls.clear()
    (data / 'new-writes').write_text('legacy data remains')
    result = service.dispatch(request('status', op, 2))
    assert result['phase'] == 'needs_attention' and result['error_code'] == 'PUBLIC_PORTS_UNAVAILABLE'
    assert not docker.calls and (data / 'new-writes').read_text() == 'legacy data remains'
    assert not Journal(service.root, op).value['watchdog_armed']


def test_preflight_never_downgrades_systemd_or_docker_transport_failure(fixture, monkeypatch):
    service, docker, _ = fixture
    def broken_systemd():
        raise VaultRewindError('WATCHDOG_UNAVAILABLE', 'Synthetic unavailable watchdog')
    monkeypatch.setattr(service.recovery, 'verify', broken_systemd)
    with pytest.raises(VaultRewindError) as error:
        service.preflight(service.policy.instance(INSTANCE), {'controller_time': utc()})
    assert error.value.code == 'WATCHDOG_UNAVAILABLE'
    def broken_network(name):
        raise VaultRewindError('DOCKER_UNAVAILABLE', 'Synthetic unavailable daemon')
    monkeypatch.setattr(docker, 'network', broken_network)
    with pytest.raises(VaultRewindError) as error:
        service.restore_readiness(service.policy.instance(INSTANCE), {'empty_target': True})
    assert error.value.code == 'DOCKER_UNAVAILABLE'


def test_empty_public_target_reports_internal_network_unready(fixture):
    service, _docker, data = fixture
    policy = public_profile(fixture)
    empty = data.parent / 'empty-public'
    empty.mkdir()
    policy.update(container_id=None, container_name='empty-public')
    policy['mounts'][0]['source'] = str(empty)
    result = service.dispatch(request('discover'))
    assert result['empty_target'] and not result['restore_enabled']
    assert result['restore_error_code'] == 'PUBLIC_NETWORK_UNPUBLISHABLE'
    assert result['current_public_ports_ready'] is None
    assert not service.recovery.armed


def test_stopped_restore_with_valid_public_profile_remains_stopped_without_host_probe(fixture, monkeypatch):
    service, docker, _ = fixture
    public_profile(fixture, repaired=True)
    docker.items[CID]['State']['Running'] = False
    captured, _ = capture(service)
    op = stage(service, captured)
    switch(service, op, prepare(service, op))
    monkeypatch.setattr(docker, 'public_health', lambda *a, **k: pytest.fail('Stopped restoration must not probe/start public service'))
    result = service.dispatch(request('commit_restore', op, 2, {'phase': 'activate'}))
    assert result['phase'] == 'data_restored_service_stopped'
    final = docker.items[Journal(service.root, op).value['final_id']]
    assert not final['State']['Running'] and not final['NetworkSettings']['Ports']
    assert final['HostConfig']['NetworkMode'] == 'public'

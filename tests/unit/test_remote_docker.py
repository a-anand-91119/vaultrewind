"""Opt-in real Engine tests using only disposable, labeled synthetic containers.

The systemd dependency is substituted here; this test does NOT prove watchdog/boot recovery.
"""
import io
import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

from vaultrewind.remote.docker import Docker
from vaultrewind.remote.helper import Helper, utc
from vaultrewind.remote.journal import Journal
from vaultrewind.remote.policy import Policy
from vaultrewind.remote.protocol import Request, send_frames

pytestmark = [pytest.mark.docker, pytest.mark.skipif(os.environ.get("VAULTREWIND_REMOTE_DOCKER_TEST") != "1", reason="opt-in disposable Docker fixture")]


class TestRecoveryAdapter:
    """Explicitly no systemd guarantee; actual watchdog tests use installed VM fixtures."""
    __test__ = False
    def verify(self):
        pass

    def arm(self, journal, seconds):
        import time
        journal.value.update({"watchdog_armed": True, "deadline": time.time() + seconds,
                              "monotonic_deadline": time.monotonic() + seconds,
                              "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()})
        journal.save()

    def disarm(self, journal):
        journal.value["watchdog_armed"] = False
        journal.save()


@pytest.mark.parametrize("kind", ["bind", "volume"])
@pytest.mark.parametrize("outcome", ["activate", "discard"])
def test_real_docker_capture_replacement_and_stopped_data_restore(kind, outcome):
    docker = Docker()
    iid = str(uuid.uuid4())
    name = "vrw-test-" + iid
    workspace = Path(tempfile.mkdtemp(prefix="vrw-disposable-", dir=Path(__file__).parent))
    image = docker.image("ghcr.io/dani-garcia/vaultwarden:1.37.4")["Id"]
    created_volumes, network, source_id = [], None, None
    state = workspace / "state"
    state.mkdir(mode=0o700)
    try:
        network = docker.api("POST", "/networks/create", {"Name": name, "Internal": True, "Labels": {"org.vaultrewind.test": iid}})["Id"]
        if kind == "bind":
            data = workspace / "data"
            data.mkdir()
            mount = {"type": "bind", "source": str(data), "target": "/data", "snapshot_path": "data", "read_only": False}
        else:
            volume = docker.create_volume(name, {"org.vaultrewind.test": iid})
            created_volumes.append(name)
            data = Path(volume["Mountpoint"])
            mount = {"type": "volume", "source": str(data), "volume_name": name, "target": "/data", "snapshot_path": "data", "read_only": False}
        source_id = docker.create(name, {"Image": image, "Healthcheck": {"Test": ["NONE"]},
            "Labels": {"org.vaultrewind.test": iid}, "HostConfig": {"NetworkMode": name,
            "RestartPolicy": {"Name": "no"}, "Mounts": [{"Type": kind, "Source": str(data) if kind == "bind" else name, "Target": "/data"}]}})
        docker.start(source_id)
        docker.health(source_id, 60)
        private = data / ".synthetic-private"
        private.write_bytes(b"synthetic recovery data")
        private.chmod(0o600)
        docker.stop(source_id)
        policy = Policy({"schema_version": 1, "machine_id": Path("/etc/machine-id").read_text().strip(), "daemon_id": docker.info()["ID"],
            "instances": {iid: {"container_id": source_id, "container_name": name, "ownership": "exclusive", "external_dependencies_ready": True,
                "allowed_operations": ["discover", "preflight", "capture", "export", "stage_restore", "commit_restore", "rollback", "status", "cancel", "cleanup"],
                "allowed_image_ids": [image], "allowed_networks": [name], "port_bindings": {}, "mounts": [mount],
                "free_space_reserve": 0, "capture_budget": 300, "restore_budget": 900, "validation_window": 30}}}, state)
        helper = Helper(policy, docker, TestRecoveryAdapter())
        def req(verb, op, fence, payload=None):
            payload = payload or {}
            return Request(iid, op, fence, verb + ":" + payload.get("phase", "default"), verb, payload)
        captured = str(uuid.uuid4())
        result = helper.dispatch(req("capture", captured, 1, {"controller_time": utc(), "snapshot_uuid": str(uuid.uuid4())}))
        assert result["phase"] == "captured"
        assert not docker.inspect(source_id)["State"]["Running"]
        assert (state / "operations" / captured / "capture" / "data" / private.name).read_bytes() == private.read_bytes()
        (data / "after-snapshot").write_text("preserved only in safety and old generation")
        restore = str(uuid.uuid4())
        wire = io.BytesIO()
        with (state / "operations" / captured / "capture.tar").open("rb") as stream:
            transfer = send_frames(stream, wire, 1024**3)
        staged = helper.dispatch(req("stage_restore", restore, 2, {"controller_time": utc(), "manifest_hash": result["manifest_hash"],
            "expected_fingerprint": helper.inspect(policy.instance(iid))["fingerprint"], "archive_bytes": transfer["bytes"], "archive_sha256": transfer["sha256"]}),
            incoming=io.BytesIO(wire.getvalue()))
        assert staged["phase"] == "staged"
        safety = helper.dispatch(req("commit_restore", restore, 2, {"phase": "prepare_safety"}))
        # This unit fixture verifies the helper's exact acknowledgment boundary only;
        # controller+restic durable safety storage has separate integration coverage.
        ack = {"snapshot_uuid": safety["safety_snapshot_uuid"], "manifest_hash": safety["safety_manifest_hash"],
               "restic_snapshot_id": "b" * 64, "repository_id": str(uuid.uuid4()), "durable": True, "encrypted": True, "pinned": True, "stored_copy_verified": True}
        valid = helper.dispatch(req("commit_restore", restore, 2, {"phase": "switch_validate", "safety_ack": ack}))
        assert valid["candidate_validated"]["internal_http_alive"]
        if outcome == "discard":
            # Simulate a legacy/partial candidate with an engine-created anonymous
            # volume. The public path now rejects unapproved image-declared volumes.
            from vaultrewind.remote.docker import create_config
            journal = Journal(state, restore)
            docker.remove(journal.value["candidate_id"])
            config = create_config(journal.value["restore_descriptor"], helper.generation_mounts(journal, switched=True), iid, restore, isolated=True)
            config["HostConfig"]["Mounts"].append({"Type": "volume", "Target": "/synthetic-anonymous"})
            candidate = docker.create(journal.value["candidate_name"], config)
            anonymous = next(m for m in docker.inspect(candidate)["Mounts"] if m["Destination"] == "/synthetic-anonymous")
            created_volumes.append(anonymous["Name"])
            (Path(anonymous["Source"]) / "synthetic").write_text("disposable anonymous data")
            journal.value["candidate_id"] = candidate
            journal.save()
            recovered = helper.dispatch(req("rollback", restore, 2))
            assert recovered["phase"] == "rolled_back"
            new_paths = [Path(s["new"]) for s in Journal(state, restore).value["generation_steps"]]
            assert any(p.exists() for p in new_paths)
            for _ in range(2):
                cleaned = helper.dispatch(req("cleanup", restore, 2, {"kind": "discard_candidate"}))
                assert cleaned["candidate_cleanup_outcome"] == "complete"
                assert cleaned["candidate_cleanup_remaining"] == 0
                assert cleaned["discarded_candidate_bytes"] > 0
            assert not any(p.exists() for p in new_paths)
            assert not docker.volume(anonymous["Name"], missing=True)
            assert not docker.inspect(candidate, missing=True)
            assert not (state / "operations" / restore).exists()
            assert (data / "after-snapshot").exists()
            assert not docker.inspect(source_id)["State"]["Running"]
            return
        complete = helper.dispatch(req("commit_restore", restore, 2, {"phase": "activate"}))
        assert complete["phase"] == "data_restored_service_stopped"
        active = helper.active(iid)
        assert not docker.inspect(active["container_id"])["State"]["Running"]
        restored_data = Path(active["mounts"][0]["source"])
        assert (restored_data / private.name).read_bytes() == b"synthetic recovery data"
        assert not (restored_data / "after-snapshot").exists()
        assert helper.inspect(policy.instance(iid))["source_state"] == "stopped"
        assert (state / "managed" / iid / "compose.json").exists()
    finally:
        for container in docker.containers():
            if container["Id"] == source_id or container.get("Labels", {}).get("org.vaultrewind.instance") == iid:
                if docker.inspect(container["Id"])["State"]["Running"]:
                    docker.stop(container["Id"])
                docker.remove(container["Id"])
        volumes = docker.api("GET", "/volumes").get("Volumes") or []
        for volume in volumes:
            if volume["Name"] in created_volumes or (volume.get("Labels") or {}).get("org.vaultrewind.instance") == iid:
                docker.api("DELETE", "/volumes/" + volume["Name"])
        if network:
            docker.api("DELETE", "/networks/" + network)
        shutil.rmtree(workspace)


def test_real_stopped_peer_parent_bind_alias_is_rejected():
    """A second mount spelling aliases the enrolled parent inode, not its text path."""
    import subprocess

    from vaultrewind.core.errors import VaultRewindError
    from vaultrewind.remote.docker import paths_overlap, reject_other_writers
    docker = Docker()
    iid = str(uuid.uuid4())
    workspace = Path(tempfile.mkdtemp(prefix='vrw-alias-', dir=Path(__file__).parent))
    protected, alias = workspace / 'protected', workspace / 'alias'
    protected.mkdir()
    alias.mkdir()
    data = protected / 'data'
    data.mkdir()
    source = peer = None
    mounted = False
    try:
        result = subprocess.run(['mount', '--bind', str(protected), str(alias)], capture_output=True, check=False)
        if result.returncode:
            pytest.skip('Disposable host does not permit a real bind-mount alias fixture')
        mounted = True
        assert data.resolve() != alias.resolve() and protected.resolve() != alias.resolve()
        assert paths_overlap(data, alias)
        image = docker.image('ghcr.io/dani-garcia/vaultwarden:1.37.4')['Id']
        def config(path):
            return {'Image': image, 'Labels': {'org.vaultrewind.test': iid},
                    'HostConfig': {'NetworkMode': 'none', 'RestartPolicy': {'Name': 'always'},
                                   'Mounts': [{'Type': 'bind', 'Source': str(path), 'Target': '/data'}]}}
        source = docker.create('vrw-alias-source-' + iid, config(data))
        peer = docker.create('vrw-alias-peer-' + iid, config(alias))
        assert not docker.inspect(peer)['State']['Running']
        with pytest.raises(VaultRewindError) as error:
            reject_other_writers(docker, [{'type': 'bind', 'source': str(data)}], source)
        assert error.value.code == 'UNKNOWN_WRITER'
    finally:
        for container in (peer, source):
            if container:
                docker.remove(container)
        if mounted:
            subprocess.run(['umount', str(alias)], check=True)
        shutil.rmtree(workspace)


def test_real_repeated_detached_readiness_probes():
    """Only a new uniquely labelled container; no ROOT source/VM/job interaction."""
    docker = Docker()
    iid = str(uuid.uuid4())
    workspace = Path(tempfile.mkdtemp(prefix='vrw-health-', dir=Path(__file__).parent))
    data = workspace / 'data'
    data.mkdir(mode=0o700)
    container = None
    try:
        image = docker.image('ghcr.io/dani-garcia/vaultwarden:1.37.4')['Id']
        container = docker.create('vrw-health-' + iid, {'Image': image,
            'Labels': {'org.vaultrewind.test': iid}, 'Healthcheck': {'Test': ['NONE']},
            'HostConfig': {'NetworkMode': 'none', 'PortBindings': {}, 'RestartPolicy': {'Name': 'no'},
                           'Mounts': [{'Type': 'bind', 'Source': str(data), 'Target': '/data'}]}})
        docker.start(container)
        for _ in range(25):
            assert docker.health(container, 30)['internal_http_alive']
        found = docker.inspect(container)
        assert found['State']['Running'] and found['HostConfig']['NetworkMode'] == 'none'
        assert not found['HostConfig']['PortBindings']
    finally:
        if container:
            if docker.inspect(container)['State']['Running']:
                docker.stop(container)
            docker.remove(container)
            assert docker.inspect(container, missing=True) is None
        shutil.rmtree(workspace)
        assert not workspace.exists()

"""Opt-in AC22 test: real systemd, real Docker, helper process death after stop.

Uses uniquely named runtime units and a disposable synthetic container. Never
installs the production policy/helper or changes another fixture's units/data.
Does not reboot the shared host; AC23 requires the separate disposable VM drill.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from vaultrewind.remote.docker import Docker
from vaultrewind.remote.helper import Helper, utc
from vaultrewind.remote.journal import Journal
from vaultrewind.remote.policy import Policy
from vaultrewind.remote.protocol import Request
from vaultrewind.remote.recovery import SystemdRecovery, watchdog_loop


class RuntimeSystemd(SystemdRecovery):
    def __init__(self, prefix):
        self.prefix = prefix

    def _run(self, args, *, check=True):
        # Test-only namespace substitution; production request payload has no such option.
        mapped = [a.replace("vaultrewind-", self.prefix + "-") for a in args]
        return SystemdRecovery._run(mapped, check=check)


class DiesAfterStop(Docker):
    def stop(self, container, timeout=30):
        super().stop(container, timeout)
        os.kill(os.getpid(), signal.SIGKILL)  # test-only fault hook, never shipped in the helper bundle


def worker(mode, config_path, operation):
    config = json.loads(Path(config_path).read_bytes())
    policy = Policy(config["policy"], Path(config["state_root"]))
    service = Helper(policy, DiesAfterStop() if mode == "capture" else Docker(), RuntimeSystemd(config["prefix"]))
    if mode == "watchdog":
        watchdog_loop(service, operation)
    elif mode == "capture":
        service.dispatch(Request(config["instance_id"], operation, 1, "capture", "capture",
                                 {"snapshot_uuid": str(uuid.uuid4()), "controller_time": utc()}))
    else:
        for path in (service.root / "journals").glob("*.json"):
            if Journal(service.root, path.stem).value.get("watchdog_armed"):
                service.recover(path.stem, "boot")


@pytest.mark.systemd
@pytest.mark.skipif(os.environ.get("VAULTREWIND_REMOTE_SYSTEMD_TEST") != "1", reason="opt-in real systemd disposable fixture")
def test_ac22_independent_systemd_watchdog_recovers_after_helper_process_death():
    docker = Docker()
    instance_id, operation = str(uuid.uuid4()), str(uuid.uuid4())
    prefix = "vrwtest-" + instance_id
    workspace = Path(tempfile.mkdtemp(prefix="vrw-systemd-", dir=Path(__file__).parent))
    state, data = workspace / "state", workspace / "data"
    state.mkdir(mode=0o700)
    data.mkdir()
    image = docker.image("ghcr.io/dani-garcia/vaultwarden:1.37.4")["Id"]
    network, container = None, None
    unit_paths = []
    def systemctl(*args):
        return subprocess.run(["/usr/bin/systemctl", *args], check=True, capture_output=True, timeout=30)
    try:
        network = docker.api("POST", "/networks/create", {"Name": prefix, "Internal": True, "Labels": {"org.vaultrewind.test": instance_id}})["Id"]
        container = docker.create(prefix, {"Image": image, "Healthcheck": {"Test": ["NONE"]},
            "Labels": {"org.vaultrewind.test": instance_id}, "HostConfig": {"NetworkMode": prefix,
            "RestartPolicy": {"Name": "no"}, "Mounts": [{"Type": "bind", "Source": str(data), "Target": "/data"}]}})
        docker.start(container)
        docker.health(container, 30)
        policy = {"schema_version": 1, "machine_id": Path("/etc/machine-id").read_text().strip(), "daemon_id": docker.info()["ID"],
            "instances": {instance_id: {"container_id": container, "container_name": prefix,
                "ownership": "exclusive", "external_dependencies_ready": True, "allowed_operations": ["capture", "status", "cancel"],
                "allowed_image_ids": [image], "allowed_networks": [prefix], "port_bindings": {}, "free_space_reserve": 0,
                "capture_budget": 60, "validation_window": 10,
                "mounts": [{"source": str(data), "target": "/data", "snapshot_path": "data", "type": "bind", "read_only": False}]}}}
        config_path = workspace / "fixture.json"
        config_path.write_text(json.dumps({"policy": policy, "state_root": str(state), "prefix": prefix, "instance_id": instance_id}))
        repo = Path(__file__).resolve().parents[2]
        for stem, mode, extra in (("watchdog@", "watchdog", " %i"), ("reconcile", "reconcile", " unused")):
            original = (repo / "helper" / "systemd" / ("vaultrewind-" + stem + ".service")).read_text()
            line = next(line for line in original.splitlines() if line.startswith("ExecStart="))
            original = original.replace(line, f"ExecStart={sys.executable} {Path(__file__).resolve()} --worker {mode} {config_path}{extra}")
            original = original.replace("ReadWritePaths=/var/lib/vaultrewind-helper /run /var/lib/docker", f"ReadWritePaths={workspace} /run /var/lib/docker")
            unit_path = Path("/run/systemd/system") / (prefix + "-" + stem + ".service")
            unit_path.write_text(original)
            unit_paths.append(unit_path)
        systemctl("daemon-reload")
        systemctl("enable", "--runtime", prefix + "-reconcile.service")
        RuntimeSystemd(prefix).verify()
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", "capture", str(config_path), operation],
                               capture_output=True, timeout=180, check=False)
        assert child.returncode == -signal.SIGKILL, child.stderr.decode()[-1000:]
        journal = Journal(state, operation)
        assert journal.value["phase"] == "quiescing"
        assert journal.value["watchdog_armed"] is True
        assert not docker.inspect(container)["State"]["Running"]
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            journal = Journal(state, operation)
            if journal.value["phase"] == "failed_safe":
                break
            time.sleep(0.5)
        assert journal.value["phase"] == "failed_safe", journal.public()
        assert journal.value["source_service_outcome"] == "running"
        assert journal.value["recovery_reason"] == "deadline"
        assert journal.value["watchdog_armed"] is False
        assert docker.inspect(container)["State"]["Running"]
        assert docker.health(container, 10)["internal_http_alive"] is True
    finally:
        subprocess.run(["/usr/bin/systemctl", "stop", prefix + "-watchdog@" + operation + ".service"], capture_output=True, check=False)
        subprocess.run(["/usr/bin/systemctl", "disable", "--runtime", prefix + "-reconcile.service"], capture_output=True, check=False)
        for path in unit_paths:
            path.unlink(missing_ok=True)
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], capture_output=True, check=False)
        if container and docker.inspect(container, missing=True):
            if docker.inspect(container)["State"]["Running"]:
                docker.stop(container)
            docker.remove(container)
        if network:
            docker.api("DELETE", "/networks/" + network)
        shutil.rmtree(workspace)


if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--worker":
    worker(*sys.argv[2:])

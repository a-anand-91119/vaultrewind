"""TEST ONLY: disposable VM fault injection, excluded from the production zipapp."""
import json
import os
import signal
import sys
from pathlib import Path

BASE = Path("/root/vrw-vm-drill")
sys.path.insert(0, str(BASE / "bundle" / "helper.pyz"))

from vaultrewind.remote import helper as implementation
from vaultrewind.remote.docker import Docker
from vaultrewind.remote.helper import Helper
from vaultrewind.remote.journal import Journal, atomic_json, fsync_directory
from vaultrewind.remote.policy import Policy
from vaultrewind.remote.protocol import canonical, read_request


def pause(kind, operation):
    atomic_json(BASE / "trigger.json", {"kind": kind, "operation_id": operation})
    os.kill(os.getpid(), signal.SIGSTOP)
    raise RuntimeError("The VM fault process must end by reboot, never resume")


def setup():
    assert Path("/root/vaultrewind-fixture-ready").is_file()
    spec = json.loads((BASE / "spec.json").read_bytes())
    iid, expected_image = spec["instance_id"], spec["image_id"]
    root = Path("/srv") / ("vrw-ac23-" + iid)
    root.mkdir(mode=0o700)
    data = root / "data"
    data.mkdir()
    config_file = root / "synthetic-config"
    config_file.write_text("synthetic enrolled configuration\n")
    config_file.chmod(0o600)
    docker = Docker()
    image = docker.image("ghcr.io/dani-garcia/vaultwarden:1.37.4")["Id"]
    assert image == expected_image
    name = "vrw-ac23-" + iid
    docker.api("POST", "/networks/create", {"Name": name, "Internal": True, "Labels": {"org.vaultrewind.test": iid}})
    ports = {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18099"}]}
    cid = docker.create(name, {"Image": image, "Labels": {"org.vaultrewind.test": iid},
        "HostConfig": {"NetworkMode": name, "PortBindings": ports, "RestartPolicy": {"Name": "unless-stopped"},
                       "Mounts": [{"Type": "bind", "Source": str(data), "Target": "/data"},
                                  {"Type": "bind", "Source": str(config_file), "Target": "/etc/vrw-synthetic-config", "ReadOnly": True}]}})
    docker.start(cid)
    docker.health(cid, 90)
    (data / ".synthetic-private").write_text("original capture content\n")
    (data / ".synthetic-private").chmod(0o600)
    policy = {"schema_version": 1, "machine_id": Path("/etc/machine-id").read_text().strip(), "daemon_id": docker.info()["ID"],
        "instances": {iid: {"container_id": cid, "container_name": name, "ownership": "exclusive", "external_dependencies_ready": True,
            "allowed_operations": ["discover", "preflight", "capture", "export", "stage_restore", "commit_restore", "rollback", "status", "cancel", "cleanup"],
            "allowed_image_ids": [image], "allowed_networks": [name], "port_bindings": ports,
            "capture_budget": 300, "restore_budget": 900, "validation_window": 90, "free_space_reserve": 32 * 1024**2,
            "mounts": [{"type": "bind", "source": str(data), "target": "/data", "read_only": False, "snapshot_path": "data"},
                       {"type": "bind", "source": str(config_file), "target": "/etc/vrw-synthetic-config", "read_only": True, "snapshot_path": "deployment/mounts/config"}]}}}
    (BASE / "policy.json").write_text(json.dumps(policy))
    spec.update({"source_id": cid, "root": str(root), "data": str(data), "network": name})
    (BASE / "spec.json").write_text(json.dumps(spec))
    print(json.dumps({"instance_id": iid, "source_id": cid, "image_id": image, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}))


def fault(kind):
    request = read_request(sys.stdin.buffer)
    (BASE / "trigger.json").unlink(missing_ok=True)
    class FaultDocker(Docker):
        def stop(self, container, timeout=30):
            super().stop(container, timeout)
            if kind == "capture":
                pause("capture_after_stop", request.operation_id)
        def start(self, container):
            super().start(container)
            item = self.inspect(container)
            if kind == "activate" and item["Config"].get("Labels", {}).get("org.vaultrewind.role") == "active":
                data = Path(next(m["Source"] for m in item["Mounts"] if m["Destination"] == "/data"))
                sentinel = data / ".post-activation-write"
                sentinel.write_text("synthetic new-generation write must survive reboot\n")
                with sentinel.open("rb") as stream:
                    os.fsync(stream.fileno())
                fsync_directory(data)
                pause("after_public_start", request.operation_id)
    if kind == "switch":
        original = implementation.durable_rename
        def rename(source, target):
            original(source, target)
            if Path(target).name == "old":
                pause("after_first_old_rename", request.operation_id)
        implementation.durable_rename = rename
    service = Helper(Policy.load(), FaultDocker())
    result = service.dispatch(request, incoming=sys.stdin.buffer, outgoing=sys.stdout.buffer)
    print(canonical({"ok": True, "result": result}).decode())


def inspect(operation):
    spec = json.loads((BASE / "spec.json").read_bytes())
    policy = Policy.load()
    service = Helper(policy)
    journal = Journal(service.root, operation)
    active = service.active(spec["instance_id"])
    cid = active["container_id"] if active else spec["source_id"]
    container = service.docker.inspect(cid)
    data = Path(next(m["Source"] for m in container["Mounts"] if m["Destination"] == "/data"))
    print(json.dumps({"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      "journal": journal.public(), "container_id": cid, "running": container["State"]["Running"],
                      "source_running": service.docker.inspect(spec["source_id"])["State"]["Running"],
                      "original_content": (data / ".synthetic-private").exists(),
                      "later_original_content": (data / ".after-capture").exists(),
                      "post_activation_write": (data / ".post-activation-write").exists(),
                      "trigger": json.loads((BASE / "trigger.json").read_bytes()) if (BASE / "trigger.json").exists() else None}))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "setup":
        setup()
    elif mode.startswith("fault-"):
        fault(mode[6:])
    elif mode == "inspect":
        inspect(sys.argv[2])
    elif mode == "later-write":
        spec = json.loads((BASE / "spec.json").read_bytes())
        (Path(spec["data"]) / ".after-capture").write_text("later old-generation content\n")
    elif mode == "trigger":
        print((BASE / "trigger.json").read_text() if (BASE / "trigger.json").exists() else "{}")
    else:
        raise RuntimeError("Unsupported disposable VM fixture mode")

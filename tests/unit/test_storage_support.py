"""Shared helpers for storage tests (synthetic data only). Contains no tests itself."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import textwrap
import uuid
from datetime import UTC, datetime
from pathlib import Path

from tests.fixtures import synthetic_data
from vaultrewind.core.manifest import canonical_json, create_manifest, manifest_hash
from vaultrewind.core.sqlite import normalize_sqlite

RESTIC = shutil.which("restic", path="/usr/local/bin:/usr/bin:/bin")
RCLONE = shutil.which("rclone", path="/usr/local/bin:/usr/bin:/bin")


def descriptor() -> dict:
    return {"schema_version": 1, "image_id": "sha256:" + "ab" * 32, "registry_digest": None,
            "platform": "linux/amd64",
            "config": {"Env": ["DOMAIN=https://vault.synthetic.invalid", "ADMIN_TOKEN=synthetic-admin-token-value",
                               "SIGNUPS_ALLOWED=false"], "User": "1000:1000"},
            "host_config": {"NetworkMode": "bridge", "PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1",
                                                                                   "HostPort": "8080"}]},
                            "RestartPolicy": {"Name": "unless-stopped"}},
            "mounts": [{"type": "bind", "target": "/data", "read_only": False, "snapshot_path": "data"}],
            "dependencies": [{"kind": "reverse_proxy", "reference": "synthetic-proxy", "required": True}]}


def make_snapshot_tree(base: Path, *, instance_uuid: str | None = None, snapshot_uuid: str | None = None,
                       image_bytes: int = 64 * 1024, source_state: str = "running") -> tuple[Path, dict]:
    """A canonical snapshot root (data, deployment, images, manifest) built from synthetic data."""
    base.mkdir(parents=True, exist_ok=True)
    source = base / "source"
    synthetic_data(source).close()
    stage = base / "stage"
    stage.mkdir(mode=0o700)
    subprocess.run(["cp", "-a", str(source), str(stage / "data")], check=True)
    normalize_sqlite(stage / "data")
    (stage / "deployment").mkdir()
    deployment = descriptor()
    (stage / "deployment" / "recovery.json").write_bytes(canonical_json(deployment))
    (stage / "images").mkdir()
    image = stage / "images" / "vaultwarden.tar"
    image.write_bytes(os.urandom(image_bytes))
    captured = datetime.now(UTC).isoformat()
    manifest = create_manifest(stage, {
        "snapshot_uuid": snapshot_uuid or str(uuid.uuid4()), "instance_uuid": instance_uuid or str(uuid.uuid4()),
        "capture_started_at": captured, "captured_at": captured, "source_state": source_state,
        "image_id": deployment["image_id"], "image_archive_hash": hashlib.sha256(image.read_bytes()).hexdigest(),
        "platform": "linux/amd64", "deployment_fingerprint": hashlib.sha256(canonical_json(deployment)).hexdigest(),
        "dependency_inventory": deployment["dependencies"]})
    return stage, manifest


def snapshot_args(stage: Path, manifest: dict) -> tuple[Path, str, str]:
    return stage, manifest["snapshot_uuid"], manifest["captured_at"]


def mountinfo_for(path: Path, fs_type: str = "ext4", options: str = "rw,relatime") -> str:
    """Synthetic /proc/self/mountinfo declaring ``path`` a dedicated mount (root stays a separate mount)."""
    return (f"20 1 0:20 / / rw,relatime - overlay overlay rw\n"
            f"40 20 8:1 /backups {path} {options} - {fs_type} /dev/sdb1 rw\n")


FAKE_RESTIC = textwrap.dedent('''\
    #!/usr/bin/python3
    import hashlib, json, os, stat, sys
    HERE = os.path.dirname(os.path.abspath(__file__))
    args = sys.argv[1:]
    if args == ["version"]:
        print("restic 0.19.1 compiled with go1.26.4 on linux/amd64"); sys.exit(0)
    command, skip = None, False
    for index, arg in enumerate(args):
        if skip:
            skip = False; continue
        if arg in ("--retry-lock", "-o"):
            skip = True; continue
        if arg.startswith("-"):
            continue
        command = arg + (" " + args[index + 1] if arg in ("key", "cat") else ""); break
    password_file = os.environ.get("RESTIC_PASSWORD_FILE")
    record = {"argv": args, "command": command, "env_keys": sorted(os.environ),
              "env": {k: os.environ.get(k) for k in ("PATH", "TZ", "RESTIC_REPOSITORY", "AWS_ACCESS_KEY_ID",
                                                    "RCLONE_CONFIG", "HOME")},
              "password_sha256": None, "password_mode": None, "cwd": os.getcwd()}
    if password_file and os.path.exists(password_file):
        record["password_sha256"] = hashlib.sha256(open(password_file, "rb").read()).hexdigest()
        record["password_mode"] = oct(stat.S_IMODE(os.stat(password_file).st_mode))
        record["password_file"] = password_file
    with open(os.path.join(HERE, "calls.jsonl"), "a") as log:
        log.write(json.dumps(record) + "\\n")
    scenario = json.load(open(os.path.join(HERE, "scenario.json")))
    queue = scenario.get(command) or [{"stdout": "", "stderr": "", "exit": 0}]
    counter_file = os.path.join(HERE, "counter.json")
    counters = json.load(open(counter_file)) if os.path.exists(counter_file) else {}
    position = counters.get(command, 0)
    counters[command] = position + 1
    json.dump(counters, open(counter_file, "w"))
    response = queue[min(position, len(queue) - 1)]
    sys.stdout.write(response.get("stdout", "")); sys.stderr.write(response.get("stderr", ""))
    sys.exit(response.get("exit", 0))
''')


class FakeRestic:
    """A scriptable stand-in for deterministic adapter tests (records argv/env, never real data)."""

    def __init__(self, directory: Path, scenario: dict):
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.binary = directory / "restic"
        self.binary.write_text(FAKE_RESTIC)
        self.binary.chmod(0o755)
        (directory / "scenario.json").write_text(json.dumps(scenario))

    def calls(self) -> list[dict]:
        path = self.directory / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def commands(self) -> list[str]:
        return [call["command"] for call in self.calls()]


def snapshot_json(restic_id: str, tags: list[str], time: str = "2026-10-25T01:02:03Z") -> dict:
    return {"time": time, "tree": "0" * 64, "paths": ["/x"], "hostname": "vaultrewind", "username": "root",
            "tags": tags, "program_version": "restic 0.19.1", "id": restic_id, "short_id": restic_id[:8],
            "summary": {"total_bytes_processed": 10, "data_added_packed": 5}}


def respond(stdout="", stderr="", exit=0) -> dict:
    return {"stdout": stdout, "stderr": stderr, "exit": exit}


def stored_manifest_hash(manifest: dict) -> str:
    return manifest_hash(manifest)

#!/usr/bin/env python3
"""Disposable real Vaultwarden + saved image + restic round trip before UI development.

This tests application bytes/startup. Product SSH/transactional restore is a separate test.
Synthetic database rows deliberately contain no real client-encrypted secrets.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from vaultrewind.core import create_manifest, manifest_hash, normalize_sqlite, sha256_file, verify_snapshot

IMAGE = "ghcr.io/dani-garcia/vaultwarden@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055"


def run(*args, timeout=240, env=None, cwd=None):
    result = subprocess.run(list(args), capture_output=True, timeout=timeout, env=env, cwd=cwd, check=False)
    if result.returncode:
        raise RuntimeError(f"Fixture command failed: {args[0]} {args[1]} ({result.returncode}); private output withheld")
    return result.stdout


def healthy(container):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = subprocess.run(["docker", "exec", container, "/healthcheck.sh"], capture_output=True, check=False)
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError("Synthetic Vaultwarden startup did not become healthy")


def seed(path):
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    future = (datetime.now(UTC) + timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S.%f")
    users = [str(uuid4()), str(uuid4())]
    cipher, organization, attachment, send, send_file = [str(uuid4()) for _ in range(5)]
    with sqlite3.connect(path / "db.sqlite3") as db:
        def insert(table, values):
            for _, name, kind, required, default, _ in db.execute(f'PRAGMA table_info("{table}")'):
                if name not in values and required and default is None:
                    values[name] = (secrets.token_bytes(32) if "BLOB" in kind.upper() else
                                    1 if "INT" in kind.upper() or "BOOL" in kind.upper() else
                                    now if "DATE" in kind.upper() else "synthetic-fixture")
            columns = ",".join('"'+name+'"' for name in values)
            db.execute(f'INSERT INTO "{table}" ({columns}) VALUES ({",".join("?" for _ in values)})', tuple(values.values()))
        for index, user in enumerate(users):
            insert("users", {"uuid": user, "email": f"synthetic-{index}@example.invalid", "name": f"Synthetic {index}",
                             "equivalent_domains": "[]", "excluded_globals": "[]", "security_stamp": str(uuid4())})
        insert("organizations", {"uuid": organization, "name": "Synthetic Organization"})
        insert("ciphers", {"uuid": cipher, "user_uuid": users[0], "organization_uuid": None,
                           "atype": 1, "name": "2.fixture-only", "data": json.dumps({"Uri": None, "Username": "2.fixture", "Password": "2.fixture"})})
        insert("attachments", {"id": attachment, "cipher_uuid": cipher, "file_name": "2.fixture", "file_size": 28})
        insert("sends", {"uuid": send, "user_uuid": users[1], "organization_uuid": None, "atype": 1,
                         "data": json.dumps({"Id": send_file, "FileName": "2.fixture", "Size": 20}),
                         "deletion_date": future, "expiration_date": future, "disabled": False, "access_count": 0})
        db.commit()
    for relative, content in {f"attachments/{cipher}/{attachment}": b"synthetic private attachment",
                              f"sends/{send}/{send_file}": b"synthetic Send bytes", ".future-vaultwarden-state": b"unknown persistent file",
                              "nested/Unicode \u03bb with spaces": b"preserve Unicode paths"}.items():
        item = path / relative
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_bytes(content)
        item.chmod(0o600)
    (path / "empty directory").mkdir()
    os.link(path / ".future-vaultwarden-state", path / "hardlink")
    (path / "internal-link").symlink_to(".future-vaultwarden-state")
    return users


def main():
    started, names = time.monotonic(), []
    with tempfile.TemporaryDirectory(prefix="vaultrewind-application-") as directory:
        root = Path(directory)
        source, stage, restored = root / "source", root / "canonical", root / "restored"
        source.mkdir(mode=0o700)
        stage.mkdir(mode=0o700)
        source_name, candidate = "vr-fixture-" + uuid4().hex[:10], "vr-candidate-" + uuid4().hex[:10]
        try:
            run("docker", "run", "-d", "--name", source_name, "--label", "vaultrewind.fixture=true", "--network", "none",
                "--mount", f"type=bind,source={source},target=/data", "-e", "WEB_VAULT_ENABLED=false", IMAGE)
            names.append(source_name)
            healthy(source_name)
            run("docker", "stop", "--time", "30", source_name)
            users = seed(source)
            run("docker", "start", source_name)
            healthy(source_name)
            (stage / "images").mkdir()
            (stage / "deployment").mkdir()
            descriptor = json.loads(run("docker", "inspect", source_name))[0]
            image_id = descriptor["Image"]
            run("docker", "image", "save", "--output", str(stage / "images/vaultwarden.tar"), image_id)
            (stage / "deployment/actual-inspect.json").write_text(json.dumps(descriptor))
            (stage / "deployment/effective.env").write_text("\n".join(descriptor["Config"]["Env"]))
            captured_at = datetime.now(UTC).isoformat()
            pause_started = time.monotonic()
            run("docker", "stop", "--time", "30", source_name)
            run("cp", "-a", str(source), str(stage / "data"))
            run("docker", "start", source_name)
            healthy(source_name)
            pause_seconds = time.monotonic() - pause_started
            assert json.loads(run("docker", "inspect", source_name))[0]["State"]["Running"]
            validation = normalize_sqlite(stage / "data")
            metadata = {"snapshot_uuid": str(uuid4()), "instance_uuid": str(uuid4()),
                        "capture_started_at": captured_at, "captured_at": captured_at, "source_state": "running",
                        "image_id": image_id, "registry_digest": IMAGE.split("@", 1)[1],
                        "image_archive_hash": sha256_file(stage / "images/vaultwarden.tar"), "platform": "linux/amd64",
                        "deployment_fingerprint": hashlib.sha256((stage / "deployment/actual-inspect.json").read_bytes()).hexdigest(),
                        "vaultwarden_version": "1.37.4", "verification": validation}
            manifest = create_manifest(stage, metadata)
            password = root / "password"
            password.write_text(secrets.token_urlsafe(48)); password.chmod(0o600)
            environment = {**os.environ, "RESTIC_PASSWORD_FILE": str(password), "RESTIC_REPOSITORY": str(root / "repository")}
            def restic(*args):
                return run("restic", "--json", *args, env=environment, cwd=stage)
            restic("init")
            output = restic("backup", ".", "--tag", "vaultrewind:" + metadata["snapshot_uuid"])
            summary = next(json.loads(line) for line in output.splitlines() if json.loads(line).get("message_type") == "summary")
            snapshot_id = summary["snapshot_id"]
            assert manifest_hash(json.loads(restic("dump", snapshot_id, "/manifest/manifest.json"))) == manifest_hash(manifest)
            # Later source mutation must not appear in the selected restored point.
            with sqlite3.connect(source / "db.sqlite3") as db:
                db.execute("UPDATE users SET name='After capture' WHERE uuid=?", (users[0],)); db.commit()
            restic("restore", snapshot_id, "--target", str(restored))
            evidence = verify_snapshot(restored, manifest_hash(manifest))
            run("docker", "image", "load", "--input", str(restored / "images/vaultwarden.tar"))
            assert json.loads(run("docker", "image", "inspect", image_id))[0]["Id"] == image_id
            with sqlite3.connect(restored / "data/db.sqlite3") as db:
                assert db.execute("SELECT name FROM users WHERE uuid=?", (users[0],)).fetchone()[0] != "After capture"
            run("docker", "run", "-d", "--pull=never", "--name", candidate, "--label", "vaultrewind.fixture=true",
                "--network", "none", "--mount", f"type=bind,source={restored / 'data'},target=/data", image_id)
            names.append(candidate)
            healthy(candidate)
            candidate_inspect = json.loads(run("docker", "inspect", candidate))[0]
            assert not candidate_inspect["HostConfig"]["PortBindings"]
            assert candidate_inspect["HostConfig"]["NetworkMode"] == "none"
            restic("check", "--read-data")
            report = {"result": "passed", "synthetic_only": True, "vaultwarden_version": "1.37.4",
                      "image_id": image_id, "registry_digest": metadata["registry_digest"],
                      "saved_image_sha256": metadata["image_archive_hash"], "application_started": True,
                      "candidate_no_public_ports": True, "candidate_network_none": True, "authenticated_user_login_tested": False,
                      "source_resumed_before_normalize_upload": True, "capture_outage_seconds": round(pause_seconds, 3),
                      "later_source_change_absent": True, "source_running_during_restore": True,
                      "logical_bytes": evidence["logical_bytes"], "inventory_members": evidence["members"],
                      "total_seconds": round(time.monotonic() - started, 3),
                      "scope": "manual engineering pipeline; product helper transactional restore tested separately"}
            Path("docs/evidence/application-roundtrip.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        finally:
            for name in reversed(names):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Real SQLite/restic pipeline proof; separate from real Docker/SSH acceptance tests."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tests.fixtures import synthetic_data
from vaultrewind.core.manifest import create_manifest, manifest_hash, verify_snapshot
from vaultrewind.core.sqlite import normalize_sqlite


def main():
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="vaultrewind-core-") as directory:
        work = Path(directory)
        source, stage, restored = work / "source", work / "canonical", work / "restored"
        connection = synthetic_data(source)
        wal_bytes = (source / "db.sqlite3-wal").stat().st_size
        stage.mkdir(mode=0o700)
        subprocess.run(["cp", "-a", str(source), str(stage / "data")], check=True)
        # The captured raw WAL contains both committed users; source changes are later and excluded.
        connection.execute("INSERT INTO users VALUES('after-capture','Later synthetic user')")
        connection.commit()
        connection.close()
        database = normalize_sqlite(stage / "data")
        (stage / "deployment").mkdir()
        (stage / "deployment/recovery.json").write_text('{"fixture_only":true}')
        (stage / "images").mkdir()
        (stage / "images/fixture.txt").write_text("Core proof only. Docker image export is tested separately.")
        captured_at = datetime.now(UTC).isoformat()
        metadata = {"snapshot_uuid": str(uuid4()), "instance_uuid": str(uuid4()),
                    "capture_started_at": captured_at, "captured_at": captured_at, "source_state": "stopped",
                    "image_id": "synthetic-core-fixture", "image_archive_hash": "fixture-only",
                    "platform": "linux/amd64", "deployment_fingerprint": "fixture-only", "verification": database}
        manifest = create_manifest(stage, metadata)
        expected_hash = manifest_hash(manifest)
        password_file = work / "repository-password"
        password_file.write_text(secrets.token_urlsafe(48))
        password_file.chmod(0o600)
        environment = {**os.environ, "RESTIC_PASSWORD_FILE": str(password_file), "RESTIC_REPOSITORY": str(work / "repository")}

        def restic(*arguments):
            result = subprocess.run(["restic", "--json", *arguments], env=environment, cwd=stage,
                                    capture_output=True, text=True, timeout=180, check=False)
            if result.returncode:
                raise RuntimeError(f"restic failed ({result.returncode}); private output withheld")
            return result.stdout

        restic("init")
        backup_started = time.monotonic()
        output = restic("backup", ".", "--tag", "vaultrewind:" + metadata["snapshot_uuid"], "--host", metadata["instance_uuid"])
        summary = next(json.loads(line) for line in output.splitlines() if json.loads(line).get("message_type") == "summary")
        restic_id = summary["snapshot_id"]
        stored_manifest = json.loads(restic("dump", restic_id, "/manifest/manifest.json"))
        assert manifest_hash(stored_manifest) == expected_hash
        backup_seconds = time.monotonic() - backup_started
        restic("restore", restic_id, "--target", str(restored))
        evidence = verify_snapshot(restored, expected_hash)
        with sqlite3.connect(restored / "data/db.sqlite3") as db:
            assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 2
            assert db.execute("SELECT count(*) FROM users WHERE uuid='after-capture'").fetchone()[0] == 0
        # A second unchanged capture has a different logical identity, even if restic deduplicates bytes.
        metadata["snapshot_uuid"] = str(uuid4())
        metadata["captured_at"] = datetime.now(UTC).isoformat()
        create_manifest(stage, metadata)
        restic("backup", ".", "--tag", "vaultrewind:" + metadata["snapshot_uuid"], "--host", metadata["instance_uuid"])
        assert len(json.loads(restic("snapshots"))) == 2
        restic("check", "--read-data")
        report = {"result": "passed", "scope": "real SQLite WAL + encrypted restic local backup/readback/restore/data check",
                  "application_started": False, "ssh_tested": False, "synthetic_only": True,
                  "nonempty_raw_wal_bytes": wal_bytes, "restored_users": 2,
                  "later_source_change_absent": True, "distinct_logical_snapshots": 2,
                  "manifest_hash_verified": True, "inventory_members": evidence["members"],
                  "logical_bytes": evidence["logical_bytes"], "backup_seconds": round(backup_seconds, 3),
                  "total_seconds": round(time.monotonic() - started, 3),
                  "restic_version": subprocess.check_output(["restic", "version"], text=True).strip()}
        target = Path("docs/evidence/core-roundtrip.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

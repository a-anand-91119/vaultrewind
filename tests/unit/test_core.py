import io
import json
import os
import sqlite3
import tarfile
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.fixtures import synthetic_data
from vaultrewind.core.archive import create_archive, safe_extract
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.core.manifest import create_manifest, inventory, logical_path, manifest_hash, verify_snapshot
from vaultrewind.core.sqlite import normalize_sqlite


def canonical_fixture(tmp_path):
    source = tmp_path / "source"
    connection = synthetic_data(source)
    assert (source / "db.sqlite3-wal").stat().st_size > 0
    stage = tmp_path / "stage"
    stage.mkdir()
    # cp -a semantics used to preserve hardlinks in the fixture raw copy.
    import subprocess
    subprocess.run(["cp", "-a", str(source), str(stage / "data")], check=True)
    connection.close()
    evidence = normalize_sqlite(stage / "data")
    (stage / "deployment").mkdir()
    (stage / "deployment" / "recovery.json").write_text('{"fixture_only":true}')
    (stage / "images").mkdir()
    (stage / "images" / "fixture.txt").write_text("Not a real Docker image; core fixture only.")
    now = datetime.now(UTC).isoformat()
    metadata = {"snapshot_uuid": str(uuid4()), "instance_uuid": str(uuid4()), "capture_started_at": now,
                "captured_at": now, "source_state": "stopped", "image_id": "fixture-only",
                "image_archive_hash": "fixture-only", "platform": "linux/amd64",
                "deployment_fingerprint": "fixture-only", "verification": evidence}
    manifest = create_manifest(stage, metadata)
    return stage, manifest


def test_wal_complete_content_links_and_private_metadata(tmp_path):
    stage, manifest = canonical_fixture(tmp_path)
    assert verify_snapshot(stage, manifest_hash(manifest))["database_integrity"] == "ok"
    assert not (stage / "data/db.sqlite3-wal").exists()
    with sqlite3.connect(stage / "data/db.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 2
    assert any(item["mode"] == 0o600 for item in manifest["inventory"])
    if os.geteuid() == 0:
        assert any(item["uid"] == 1234 and item["gid"] == 2345 for item in manifest["inventory"])
    archive = tmp_path / "export.tar"
    create_archive(stage, archive)
    restored = tmp_path / "restored"
    safe_extract(archive, restored)
    assert verify_snapshot(restored, manifest_hash(manifest))["inventory_verified"]


def test_missing_attachment_fails_completeness(tmp_path):
    source = tmp_path / "data"
    db = synthetic_data(source)
    db.close()
    (source / "attachments/cipher-one/attachment-one").unlink()
    with pytest.raises(VaultRewindError, match="referenced"):
        normalize_sqlite(source)


def test_tampered_file_and_manifest_fail(tmp_path):
    stage, manifest = canonical_fixture(tmp_path)
    (stage / "data/.unknown-state").write_text("corrupted")
    with pytest.raises(VaultRewindError):
        verify_snapshot(stage, manifest_hash(manifest))
    path = stage / "manifest/manifest.json"
    tampered = json.loads(path.read_text())
    tampered["captured_at"] = "2000-01-01T00:00:00Z"
    path.write_text(json.dumps(tampered))
    with pytest.raises(VaultRewindError, match="manifest differs"):
        verify_snapshot(stage, manifest_hash(manifest))


@pytest.mark.parametrize("name,kind,link", [("../escape", "file", ""), ("/tmp/escape", "file", ""),
    ("link", "symlink", "../../escape"), ("device", "device", ""), ("hard", "hard", "../escape")])
def test_unsafe_archive_rejected(tmp_path, name, kind, link):
    archive = tmp_path / "attack.tar"
    with tarfile.open(archive, "w") as output:
        member = tarfile.TarInfo(name)
        if kind == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, link
        elif kind == "hard":
            member.type, member.linkname = tarfile.LNKTYPE, link
        elif kind == "device":
            member.type = tarfile.CHRTYPE
        output.addfile(member)
    with pytest.raises(VaultRewindError):
        safe_extract(archive, tmp_path / "target")
    assert not (tmp_path / "escape").exists()


def test_symlink_parent_archive_and_oversize_fail(tmp_path):
    archive = tmp_path / "attack.tar"
    with tarfile.open(archive, "w") as output:
        link = tarfile.TarInfo("link")
        link.type, link.linkname = tarfile.SYMTYPE, "safe"
        output.addfile(link)
        data = tarfile.TarInfo("link/file")
        data.size = 10
        output.addfile(data, io.BytesIO(b"1234567890"))
    with pytest.raises(VaultRewindError):
        safe_extract(archive, tmp_path / "target")
    with pytest.raises(VaultRewindError, match="quota"):
        safe_extract(archive, tmp_path / "target2", max_bytes=5)


def test_inventory_fails_on_external_symlink_and_fifo(tmp_path):
    (tmp_path / "outside").symlink_to("/etc/passwd")
    with pytest.raises(VaultRewindError):
        inventory(tmp_path)
    (tmp_path / "outside").unlink()
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(VaultRewindError):
        inventory(tmp_path)


@pytest.mark.parametrize("reverse", [False, True])
def test_archive_validates_forward_symlink_graph_before_materializing(tmp_path, reverse):
    archive = tmp_path / "graph.tar"
    pairs = [("data/up", ".."), ("data/escape", "up/../../outside")]
    with tarfile.open(archive, "w") as output:
        for name, target in reversed(pairs) if reverse else pairs:
            member = tarfile.TarInfo(name)
            member.type, member.linkname = tarfile.SYMTYPE, target
            output.addfile(member)
    with pytest.raises(VaultRewindError, match="escapes"):
        safe_extract(archive, tmp_path / "target")
    assert not any((tmp_path / "target").rglob("*"))


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1).filter(lambda s: "\x00" not in s))
def test_path_validation_never_allows_absolute_or_parent_escape(value):
    try:
        result = logical_path(value)
    except VaultRewindError:
        return
    assert not result.is_absolute()
    assert ".." not in result.parts

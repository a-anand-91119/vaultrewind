"""restic adapter: deterministic contract tests (fake binary) and real restic 0.19.1 round trips."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest

from tests.unit.test_storage_support import (
    RESTIC,
    FakeRestic,
    make_snapshot_tree,
    respond,
    snapshot_args,
    snapshot_json,
)
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.core.manifest import manifest_hash
from vaultrewind.storage import layout
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

PASSWORD = "synthetic-repository-password-0123456789"
real_restic = pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")


def fake_repo(tmp_path: Path, scenario: dict, **kwargs) -> tuple[ResticRepository, FakeRestic]:
    fake = FakeRestic(tmp_path / "fake", scenario)
    config = RepositoryConfig(location=str(tmp_path / "repo" / "vaultrewind" / "a" / "b"), password=PASSWORD,
                              restic_binary=str(fake.binary), runtime_dir=tmp_path / "runtime", **kwargs)
    return ResticRepository(config), fake


def real_repo(tmp_path: Path, name: str = "repo", password: str = PASSWORD, **kwargs) -> ResticRepository:
    return ResticRepository(RepositoryConfig(location=str(tmp_path / name / "vaultrewind" / "i" / "d"),
                                             password=password, cache_dir=tmp_path / "cache",
                                             runtime_dir=tmp_path / "runtime", **kwargs))


# ---------------------------------------------------------------- configuration validation
@pytest.mark.parametrize("kwargs, code", [
    ({"location": "sftp:host:/srv/repo"}, "REPOSITORY_BACKEND_UNSUPPORTED"),
    ({"location": "relative/repo"}, "REPOSITORY_BACKEND_UNSUPPORTED"),
    ({"location": "/srv/../etc/repo"}, "REPOSITORY_LOCATION_INVALID"),
    ({"location": "s3:http://minio:9000/bucket/p"}, "STORAGE_TLS_REQUIRED"),
    ({"location": "rclone:vrdrive:vaultrewind/x"}, "RCLONE_CONFIG_REQUIRED"),
    ({"password": "line1\nline2"}, "REPOSITORY_SECRET_INVALID"),
    ({"environment": {"RESTIC_PASSWORD": "x"}}, "STORAGE_ENVIRONMENT_INVALID"),
    ({"environment": {"LD_PRELOAD": "/tmp/x.so"}}, "STORAGE_ENVIRONMENT_INVALID"),
    ({"options": ("rclone.program=/tmp/evil",)}, "STORAGE_OPTION_INVALID"),
    ({"options": ("s3.region=eu-west-1",)}, "STORAGE_OPTION_INVALID"),  # s3 option on a local repository
    ({"options": ("s3.bucket-lookup=path;rm -rf /",)}, "STORAGE_OPTION_INVALID"),
])
def test_config_rejects_unsafe_values(kwargs, code):
    values = {"location": "/srv/vaultrewind/repo", "password": PASSWORD, **kwargs}
    with pytest.raises(VaultRewindError) as error:
        RepositoryConfig(**values)
    assert error.value.code == code


def test_config_repr_never_contains_secrets():
    config = RepositoryConfig(location="s3:https://s3.example.invalid/bucket/p", password=PASSWORD,
                              environment={"AWS_ACCESS_KEY_ID": "AKIASYNTHETIC0000000",
                                           "AWS_SECRET_ACCESS_KEY": "synthetic-secret-access-key"})
    text = repr(config)
    assert PASSWORD not in text and "synthetic-secret-access-key" not in text


# ---------------------------------------------------------------- deterministic process contract
def test_environment_is_rebuilt_and_password_never_in_arguments(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTREWIND_CANARY_SECRET", "controller-only-value")
    monkeypatch.setenv("RESTIC_PASSWORD", "inherited-password-must-not-leak")
    repo, fake = fake_repo(tmp_path, {"snapshots": [respond("[]")]},
                           environment={})
    assert repo.list_snapshots() == []
    call = next(c for c in fake.calls() if c["command"] == "snapshots")
    assert "VAULTREWIND_CANARY_SECRET" not in call["env_keys"] and "RESTIC_PASSWORD" not in call["env_keys"]
    assert call["env"]["PATH"] == "/usr/local/bin:/usr/bin:/bin" and call["env"]["TZ"] == "UTC"
    assert call["password_sha256"] == hashlib.sha256(PASSWORD.encode()).hexdigest()
    assert call["password_mode"] == "0o600"
    assert not Path(call["password_file"]).exists(), "temporary password file must be removed"
    assert all(PASSWORD not in arg for arg in call["argv"]) and "--json" in call["argv"]
    assert call["env"]["RESTIC_REPOSITORY"].endswith("/vaultrewind/a/b")


def test_exit_codes_map_to_stable_errors(tmp_path):
    repo, _ = fake_repo(tmp_path / "pw", {"cat config": [respond(exit=12)]})
    with pytest.raises(VaultRewindError) as wrong:
        repo.initialize()
    assert wrong.value.code == "REPOSITORY_PASSWORD_INVALID"
    repo, _ = fake_repo(tmp_path / "lock", {"snapshots": [respond(exit=11, stderr='{"message_type":"exit_error"}\n')]})
    with pytest.raises(VaultRewindError) as locked:
        repo.list_snapshots()
    assert locked.value.code == "REPOSITORY_LOCKED" and locked.value.retryable
    repo, _ = fake_repo(tmp_path / "unknown", {"snapshots": [respond(exit=42)]})
    with pytest.raises(VaultRewindError) as unknown:
        repo.list_snapshots()
    assert unknown.value.code == "STORAGE_OPERATION_FAILED"


def test_missing_recorded_repository_is_not_recreated(tmp_path):
    repo, fake = fake_repo(tmp_path, {"cat config": [respond(exit=10)]}, expected_repository_id="a" * 64)
    with pytest.raises(VaultRewindError) as error:
        repo.initialize()
    assert error.value.code == "REPOSITORY_NOT_FOUND"
    assert "init" not in fake.commands()


def _partial_scenario(stage_manifest: dict, created: str, *, exit_code: int, stderr: str) -> dict:
    summary = {"message_type": "summary", "snapshot_id": created, "data_added_packed": 1}
    listed = json.dumps([snapshot_json(created, [])])
    return {"snapshots": [respond("[]"), respond(listed), respond(listed)],
            "backup": [respond(json.dumps(summary) + "\n", stderr, exit_code)], "forget": [respond()]}


@pytest.mark.parametrize("exit_code, stderr", [
    (3, '{"message_type":"error","error":{"message":"open: permission denied"},"during":"archival","item":"/x"}\n'),
    (0, "/nonexistent does not exist, skipping\n"),          # warning text with a clean exit is still partial
    (0, '{"message_type":"error","error":{"message":"read failed"},"during":"archival","item":"/y"}\n'),
])
def test_partial_backups_are_discarded_by_exact_id(tmp_path, exit_code, stderr):
    stage, manifest = make_snapshot_tree(tmp_path / "tree")
    created = "c" * 64
    repo, fake = fake_repo(tmp_path, _partial_scenario(manifest, created, exit_code=exit_code, stderr=stderr))
    with pytest.raises(VaultRewindError) as error:
        repo.commit(*snapshot_args(stage, manifest))
    assert error.value.code == "STORAGE_COMMIT_PARTIAL"
    forget = [c for c in fake.calls() if c["command"] == "forget"]
    assert forget and forget[0]["argv"][-1] == created and "--keep-within" not in " ".join(forget[0]["argv"])
    backup = next(c for c in fake.calls() if c["command"] == "backup")
    assert backup["cwd"] == str(stage) and backup["argv"][-2:] == ["--", "."]
    assert layout.TAG_SNAPSHOT + manifest["snapshot_uuid"] in backup["argv"]


def test_unexpected_exit_status_is_a_failure_not_success(tmp_path):
    stage, manifest = make_snapshot_tree(tmp_path / "tree")
    repo, _ = fake_repo(tmp_path, {"snapshots": [respond("[]")], "backup": [respond(exit=2)]})
    with pytest.raises(VaultRewindError) as error:
        repo.commit(*snapshot_args(stage, manifest))
    assert error.value.code == "STORAGE_OPERATION_FAILED"


def test_check_reports_corruption_without_claiming_verification(tmp_path):
    summary = json.dumps({"message_type": "summary", "num_errors": 2, "broken_packs": ["p1"]}) + "\n"
    repo, _ = fake_repo(tmp_path, {"check": [respond(summary, '{"message_type":"error","message":"x"}\n', 1)]})
    result = repo.check(read_data=True)
    assert result["ok"] is False and result["full_data_verified"] is False
    assert result["error_code"] == "REPOSITORY_CHECK_FAILED" and result["broken_packs"] == 1


def test_structure_check_is_never_full_data_verification(tmp_path):
    repo, fake = fake_repo(tmp_path, {"check": [respond(json.dumps({"message_type": "summary", "num_errors": 0}))]})
    result = repo.check()
    assert result["ok"] and result["verification_level"] == "structure" and not result["full_data_verified"]
    assert "--read-data" not in fake.calls()[-1]["argv"]
    with pytest.raises(VaultRewindError):
        repo.check(read_data_subset="10%; rm -rf /")


def test_forget_refuses_foreign_or_malformed_ids(tmp_path):
    mine, other = str(uuid.uuid4()), str(uuid.uuid4())
    foreign = snapshot_json("d" * 64, [layout.TAG_SNAPSHOT + str(uuid.uuid4()), layout.TAG_INSTANCE + other])
    repo, fake = fake_repo(tmp_path, {"snapshots": [respond(json.dumps([foreign]))]}, instance_uuid=mine)
    with pytest.raises(VaultRewindError) as error:
        repo.forget(["d" * 64])
    assert error.value.code == "REPOSITORY_OWNERSHIP_MISMATCH"
    assert "forget" not in fake.commands()
    for bad in ("--keep-last=0", "deadbeef", "latest", "d" * 63 + "g"):
        with pytest.raises(VaultRewindError):
            repo.forget([bad])


def test_forget_reports_retained_copies_accurately(tmp_path):
    mine = str(uuid.uuid4())
    entry = snapshot_json("e" * 64, [layout.TAG_SNAPSHOT + str(uuid.uuid4()), layout.TAG_INSTANCE + mine])
    listed = respond(json.dumps([entry]))
    repo, _ = fake_repo(tmp_path, {"snapshots": [listed, listed],
                                   "forget": [respond(stderr="AccessDenied: delete not allowed\n", exit=3)]},
                        instance_uuid=mine)
    result = repo.forget(["e" * 64, "f" * 64])
    assert result["retained"] == ["e" * 64] and result["already_absent"] == ["f" * 64]
    assert result["complete"] is False and result["error_code"] == "STORAGE_DELETE_DENIED"


# ---------------------------------------------------------------- real restic
@real_restic
def test_real_lifecycle_round_trip_and_distinct_logical_snapshots(tmp_path):
    instance = str(uuid.uuid4())
    repo = real_repo(tmp_path, instance_uuid=instance)
    created = repo.initialize()
    assert created["created"] and len(created["repository_id"]) == 64
    assert repo.initialize() == {**created, "created": False}
    stage, manifest = make_snapshot_tree(tmp_path / "s1", instance_uuid=instance)
    first = repo.commit(*snapshot_args(stage, manifest))
    assert first["stored_copy_verified"] and not first["reconciled"]
    assert first["manifest_hash"] == manifest_hash(manifest) and first["logical_bytes"] > 64 * 1024
    assert first["verification"]["tree_matches_inventory"] and first["verification"]["rediscovered_by_uuid"]
    # Same content, new logical snapshot UUID: a distinct restic snapshot, deduplicated storage.
    manifest2 = {**manifest, "snapshot_uuid": str(uuid.uuid4())}
    (stage / "manifest" / "manifest.json").write_bytes(json.dumps(manifest2).encode())
    second = repo.commit(stage, manifest2["snapshot_uuid"], manifest2["captured_at"])
    assert second["restic_snapshot_id"] != first["restic_snapshot_id"]
    assert second["stored_bytes"] < first["stored_bytes"]
    listed = repo.list_snapshots()
    assert {s["snapshot_uuid"] for s in listed} == {manifest["snapshot_uuid"], manifest2["snapshot_uuid"]}
    assert all(s["instance_uuid"] == instance and s["kind"] == "backup" for s in listed)
    assert manifest_hash(repo.read_manifest(first["restic_snapshot_id"])) == first["manifest_hash"]
    restored = repo.restore(first["restic_snapshot_id"], tmp_path / "restored",
                            expected_manifest_hash=first["manifest_hash"])
    assert restored["restored_bytes_verified"] and restored["snapshot_uuid"] == manifest["snapshot_uuid"]
    assert (tmp_path / "restored" / "data" / "db.sqlite3").is_file()
    assert not (tmp_path / "restored" / "data" / "db.sqlite3-wal").exists()
    with pytest.raises(VaultRewindError) as not_empty:
        repo.restore(first["restic_snapshot_id"], tmp_path / "restored")
    assert not_empty.value.code == "RESTORE_TARGET_NOT_EMPTY"
    full = repo.check(read_data=True)
    assert full["ok"] and full["full_data_verified"]
    removed = repo.forget([first["restic_snapshot_id"]])
    assert removed["removed"] == [first["restic_snapshot_id"]] and removed["complete"]
    assert repo.forget([first["restic_snapshot_id"]])["already_absent"] == [first["restic_snapshot_id"]]
    pruned = repo.prune()
    assert pruned["pruned"] and pruned["check"]["ok"]
    assert [s["restic_snapshot_id"] for s in repo.list_snapshots()] == [second["restic_snapshot_id"]]


@real_restic
def test_real_commit_reconciles_after_crash_instead_of_duplicating(tmp_path):
    instance = str(uuid.uuid4())
    stage, manifest = make_snapshot_tree(tmp_path / "s", instance_uuid=instance)
    first_worker = real_repo(tmp_path, instance_uuid=instance)
    first_worker.initialize()
    committed = first_worker.commit(*snapshot_args(stage, manifest))
    # A second worker (fresh process state) retries the same logical snapshot after an ambiguous outcome.
    second_worker = real_repo(tmp_path, instance_uuid=instance)
    retried = second_worker.commit(*snapshot_args(stage, manifest))
    assert retried["reconciled"] and retried["restic_snapshot_id"] == committed["restic_snapshot_id"]
    assert len(second_worker.find_snapshots(manifest["snapshot_uuid"])) == 1


@real_restic
def test_real_same_uuid_with_different_content_is_a_conflict(tmp_path):
    instance = str(uuid.uuid4())
    stage, manifest = make_snapshot_tree(tmp_path / "s", instance_uuid=instance)
    repo = real_repo(tmp_path, instance_uuid=instance)
    repo.initialize()
    repo.commit(*snapshot_args(stage, manifest))
    changed = {**manifest, "source_state": "stopped"}
    (stage / "manifest" / "manifest.json").write_bytes(json.dumps(changed).encode())
    with pytest.raises(VaultRewindError) as error:
        repo.commit(stage, changed["snapshot_uuid"], changed["captured_at"])
    assert error.value.code == "SNAPSHOT_IDENTITY_CONFLICT"
    with pytest.raises(VaultRewindError) as mismatch:
        repo.commit(stage, changed["snapshot_uuid"], "2001-01-01T00:00:00+00:00")
    assert mismatch.value.code == "MANIFEST_MISMATCH"


@real_restic
def test_real_wrong_instance_and_extra_tree_content_are_rejected(tmp_path):
    stage, manifest = make_snapshot_tree(tmp_path / "s")
    repo = real_repo(tmp_path, instance_uuid=str(uuid.uuid4()))
    repo.initialize()
    with pytest.raises(VaultRewindError) as foreign:
        repo.commit(*snapshot_args(stage, manifest))
    assert foreign.value.code == "REPOSITORY_OWNERSHIP_MISMATCH"
    (stage / "stray-file").write_text("not part of the canonical tree")
    with pytest.raises(VaultRewindError) as stray:
        real_repo(tmp_path, "repo2").commit(*snapshot_args(stage, manifest))
    assert stray.value.code == "SNAPSHOT_INCOMPLETE"


@real_restic
@pytest.mark.skipif(os.geteuid() != 0 or not Path("/usr/bin/setpriv").exists(),
                    reason="needs root and setpriv to drop DAC override capabilities")
def test_real_unreadable_file_makes_restic_partial_and_copy_is_discarded(tmp_path):
    """A required file restic cannot read (root without CAP_DAC_*) can never become a committed copy."""
    wrapper = tmp_path / "restic-nodac"
    wrapper.write_text("#!/bin/sh\nexec /usr/bin/setpriv --bounding-set=-dac_override,-dac_read_search "
                       f"--inh-caps=-dac_override,-dac_read_search -- {RESTIC} \"$@\"\n")
    wrapper.chmod(0o755)
    instance = str(uuid.uuid4())
    stage, manifest = make_snapshot_tree(tmp_path / "s", instance_uuid=instance)
    unreadable = stage / "data" / "config.json"
    unreadable.chmod(0o000)
    repo = ResticRepository(RepositoryConfig(location=str(tmp_path / "repo" / "vaultrewind" / "i" / "d"),
                                             password=PASSWORD, cache_dir=tmp_path / "cache",
                                             runtime_dir=tmp_path / "runtime", restic_binary=str(wrapper),
                                             instance_uuid=instance))
    repo.initialize()
    with pytest.raises(VaultRewindError) as error:
        repo.commit(*snapshot_args(stage, manifest))
    assert error.value.code == "STORAGE_COMMIT_PARTIAL" and error.value.details["exit_code"] == 3
    assert repo.list_snapshots() == [], "the partial restic snapshot must be forgotten"
    assert oct(unreadable.stat().st_mode & 0o777) == "0o0", "live permissions are never changed"


@real_restic
def test_real_corruption_is_detected_only_by_reading_data(tmp_path):
    instance = str(uuid.uuid4())
    stage, manifest = make_snapshot_tree(tmp_path / "s", instance_uuid=instance, image_bytes=2 * 1024 * 1024)
    repo = real_repo(tmp_path, instance_uuid=instance)
    repo.initialize()
    committed = repo.commit(*snapshot_args(stage, manifest))
    packs = sorted((tmp_path / "repo").rglob("data/*/*"), key=lambda p: p.stat().st_size)
    largest = packs[-1]
    largest.chmod(0o600)
    data = bytearray(largest.read_bytes())
    middle = len(data) // 2
    data[middle:middle + 64] = bytes(b ^ 0xFF for b in data[middle:middle + 64])
    largest.write_bytes(bytes(data))
    structure = repo.check()
    assert structure["verification_level"] == "structure" and structure["full_data_verified"] is False
    full = repo.check(read_data=True)
    assert full["ok"] is False and full["error_code"] == "REPOSITORY_CHECK_FAILED"
    with pytest.raises(VaultRewindError):
        repo.restore(committed["restic_snapshot_id"], tmp_path / "restored")


@real_restic
def test_real_identity_binding_and_password_rotation(tmp_path):
    repo = real_repo(tmp_path)
    repository_id = repo.initialize()["repository_id"]
    other = real_repo(tmp_path, "other")
    other.initialize()
    with pytest.raises(VaultRewindError) as mismatch:
        real_repo(tmp_path, "other", expected_repository_id=repository_id).describe()
    assert mismatch.value.code == "REPOSITORY_IDENTITY_MISMATCH"
    stored = {}
    new_password = "rotated-synthetic-password-9876543210"
    outcome = repo.rotate_password(new_password, lambda value: stored.__setitem__("password", value))
    assert stored["password"] == new_password and outcome["previous_key_retained"]
    assert outcome["recovery_kit_reexport_required"]
    assert real_repo(tmp_path, password=new_password).describe()["repository_id"] == repository_id
    assert real_repo(tmp_path).describe()["repository_id"] == repository_id  # old key kept for old kits
    with pytest.raises(VaultRewindError) as wrong:
        real_repo(tmp_path, password="never-the-right-password-000").list_snapshots()
    assert wrong.value.code == "REPOSITORY_PASSWORD_INVALID"


def _successful_scenario(manifest: dict, created: str, stderr: str = "") -> dict:
    manifest_bytes = json.dumps(manifest)
    nodes = [{"message_type": "snapshot", "struct_type": "snapshot", "id": created}]
    expected = {"/manifest": ("dir", 0), "/manifest/manifest.json": ("file", len(manifest_bytes.encode())),
                "/manifest/inventory.json": ("file", 10), "/data": ("dir", 0), "/deployment": ("dir", 0),
                "/images": ("dir", 0)}
    kinds = {"file": "file", "directory": "dir", "symlink": "symlink"}
    for entry in manifest["inventory"]:
        expected["/" + entry["path"]] = (kinds[entry["type"]], entry.get("size", 0) if entry["type"] == "file" else 0)
    nodes += [{"message_type": "node", "struct_type": "node", "path": path, "type": kind, "size": size}
              for path, (kind, size) in expected.items()]
    tags = layout.snapshot_tags(manifest["snapshot_uuid"], manifest["instance_uuid"], manifest_hash(manifest), "backup")
    summary = {"message_type": "summary", "snapshot_id": created, "data_added_packed": 123}
    return {"snapshots": [respond("[]"), respond(json.dumps([snapshot_json(created, tags)]))],
            "backup": [respond(json.dumps(summary) + "\n", stderr)], "dump": [respond(manifest_bytes)],
            "ls": [respond("".join(json.dumps(n) + "\n" for n in nodes))]}


RCLONE_NOTICE = "2026/10/25 19:48:43 NOTICE: vrdrive root '': pacer: low level retry 1/2\n"


def test_rclone_transport_logs_do_not_turn_a_verified_copy_partial(tmp_path):
    stage, manifest = make_snapshot_tree(tmp_path / "tree")
    created = "a" * 64
    fake = FakeRestic(tmp_path / "fake", _successful_scenario(manifest, created, RCLONE_NOTICE))
    config_file = tmp_path / "rclone.conf"
    config_file.write_text("[vrdrive]\ntype = local\n")
    repo = ResticRepository(RepositoryConfig(location="rclone:vrdrive:vaultrewind/i/d", password=PASSWORD,
                                             rclone_config=config_file, restic_binary=str(fake.binary),
                                             rclone_binary="/bin/true", runtime_dir=tmp_path / "rt"))
    result = repo.commit(*snapshot_args(stage, manifest))
    assert result["restic_snapshot_id"] == created and result["stored_copy_verified"]
    backup = next(c for c in fake.calls() if c["command"] == "backup")
    assert backup["env"]["RCLONE_CONFIG"] == str(config_file)
    assert "forget" not in fake.commands()


def test_the_same_text_from_a_local_restic_run_is_still_a_warning(tmp_path):
    stage, manifest = make_snapshot_tree(tmp_path / "tree")
    repo, fake = fake_repo(tmp_path, _successful_scenario(manifest, "b" * 64, RCLONE_NOTICE))
    with pytest.raises(VaultRewindError) as error:
        repo.commit(*snapshot_args(stage, manifest))
    assert error.value.code == "STORAGE_COMMIT_PARTIAL" and "forget" in fake.commands()


def test_verified_success_requires_matching_tree(tmp_path):
    stage, manifest = make_snapshot_tree(tmp_path / "tree")
    scenario = _successful_scenario(manifest, "c" * 64)
    lines = scenario["ls"][0]["stdout"].splitlines()
    scenario["ls"] = [respond("\n".join(line for line in lines if '"/data/config.json"' not in line) + "\n")]
    repo, fake = fake_repo(tmp_path, scenario)
    with pytest.raises(VaultRewindError) as error:
        repo.commit(*snapshot_args(stage, manifest))
    assert error.value.code == "STORAGE_COMMIT_UNVERIFIED" and "forget" in fake.commands()

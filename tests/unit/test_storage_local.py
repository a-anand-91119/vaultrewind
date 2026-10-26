"""Local persistent destination validation and real local repositories through the provider entry point."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from tests.unit.test_storage_support import RESTIC, make_snapshot_tree, mountinfo_for, snapshot_args
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.storage import local, providers
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

DEST = str(uuid.uuid4())


def destination(path: Path, **kwargs) -> local.LocalDestination:
    return local.LocalDestination(destination_id=DEST, path=path, min_free_bytes=0, **kwargs)


def backup_dir(tmp_path: Path) -> Path:
    path = tmp_path / "backups"
    path.mkdir(mode=0o700)
    return path


def test_mountinfo_parsing_handles_escapes_and_overmounts():
    text = ("20 1 0:20 / / rw - overlay overlay rw\n"
            "30 20 8:1 / /var/lib/vaultrewind/backups rw,relatime shared:1 - ext4 /dev/sdb1 rw\n"
            "31 20 8:2 / /mnt/with\\040space rw - xfs /dev/sdc1 rw\n"
            "32 30 0:50 / /var/lib/vaultrewind/backups rw - tmpfs tmpfs rw\n")
    mounts = local.parse_mountinfo(text)
    assert mounts[2]["mount_point"] == "/mnt/with space"
    assert local.mount_for(Path("/var/lib/vaultrewind/backups/x"), mounts)["fs_type"] == "tmpfs"  # topmost wins
    assert local.mount_for(Path("/etc"), mounts)["mount_point"] == "/"


def test_valid_dedicated_mount_with_marker(tmp_path):
    path = backup_dir(tmp_path)
    dest = destination(path, host_path="/srv/synthetic-backups")
    info = mountinfo_for(path)
    with pytest.raises(VaultRewindError) as missing:
        local.inspect_local_destination(dest, mountinfo_text=info)
    assert missing.value.code == "LOCAL_MOUNT_MISSING", "no marker yet: must not be treated as the real mount"
    evidence = local.initialize_local_destination(dest, mountinfo_text=info)
    assert evidence["marker_present"] and evidence["mount"]["fs_type"] == "ext4"
    assert evidence["host_path"] == "/srv/synthetic-backups" and evidence["free_bytes"] > 0
    assert any("do not survive loss of the controller disk" in w for w in evidence["warnings"])
    marker = json.loads((path / local.MARKER_NAME).read_text())
    assert marker["destination_id"] == DEST and oct((path / local.MARKER_NAME).stat().st_mode & 0o777) == "0o600"
    assert oct(path.stat().st_mode & 0o777) == "0o700"
    assert local.inspect_local_destination(dest, mountinfo_text=info)["marker_present"]


def test_missing_mount_empty_underlying_directory_fails_closed(tmp_path):
    path = backup_dir(tmp_path)
    local.initialize_local_destination(destination(path), mountinfo_text=mountinfo_for(path))
    (path / local.MARKER_NAME).unlink()  # what an unmounted, empty mount point looks like
    with pytest.raises(VaultRewindError) as error:
        local.inspect_local_destination(destination(path), mountinfo_text=mountinfo_for(path))
    assert error.value.code == "LOCAL_MOUNT_MISSING"
    assert list(path.iterdir()) == [], "validation must not write anything"


def test_root_filesystem_is_not_a_dedicated_mount(tmp_path):
    path = backup_dir(tmp_path)
    rootfs_only = "20 1 0:20 / / rw,relatime - ext4 /dev/sda1 rw\n"
    with pytest.raises(VaultRewindError) as error:
        local.initialize_local_destination(destination(path), mountinfo_text=rootfs_only)
    assert error.value.code == "LOCAL_MOUNT_MISSING"
    evidence = local.initialize_local_destination(destination(path, require_dedicated_mount=False),
                                                  mountinfo_text=rootfs_only)
    assert evidence["mount"]["mount_point"] == "/"


@pytest.mark.parametrize("fs_type", ["tmpfs", "overlay", "cifs", "fuse.sshfs", "vfat"])
def test_unsupported_filesystems_are_rejected(tmp_path, fs_type):
    path = backup_dir(tmp_path)
    with pytest.raises(VaultRewindError) as error:
        local.initialize_local_destination(destination(path), mountinfo_text=mountinfo_for(path, fs_type))
    assert error.value.code == "LOCAL_FILESYSTEM_UNSUPPORTED"


def test_real_tmpfs_is_rejected_on_this_controller(tmp_path):
    mounts = local.parse_mountinfo(Path("/proc/self/mountinfo").read_text())
    if local.mount_for(tmp_path, mounts)["fs_type"] != "tmpfs":
        pytest.skip("pytest temporary directory is not on tmpfs here")
    with pytest.raises(VaultRewindError) as error:
        local.initialize_local_destination(destination(backup_dir(tmp_path)))
    assert error.value.code == "LOCAL_FILESYSTEM_UNSUPPORTED"


def test_read_only_mount_is_rejected(tmp_path):
    path = backup_dir(tmp_path)
    with pytest.raises(VaultRewindError) as error:
        local.initialize_local_destination(destination(path), mountinfo_text=mountinfo_for(path, options="ro"))
    assert error.value.code == "STORAGE_READ_ONLY"


@pytest.mark.parametrize("value", ["/", "/etc", "/var/lib", "/tmp", "relative/path", "/srv/../etc/x",
                                   "/var/lib/vaultrewind"])
def test_root_system_and_unnormalized_paths_are_rejected(value):
    with pytest.raises(VaultRewindError) as error:
        local.inspect_local_destination(destination(Path(value)), mountinfo_text=mountinfo_for(Path(value)))
    assert error.value.code in ("LOCAL_PATH_UNSAFE", "LOCAL_MOUNT_MISSING")


def test_symlinked_path_and_overlap_are_rejected(tmp_path):
    real = backup_dir(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(VaultRewindError) as linked:
        local.inspect_local_destination(destination(link), mountinfo_text=mountinfo_for(link), require_marker=False)
    assert linked.value.code == "LOCAL_PATH_UNSAFE"
    for protected in (real, real / "staging", tmp_path):
        with pytest.raises(VaultRewindError) as overlap:
            local.inspect_local_destination(destination(real), protected_paths=[protected],
                                            mountinfo_text=mountinfo_for(real), require_marker=False)
        assert overlap.value.code == "LOCAL_PATH_OVERLAP"


def test_permissions_and_foreign_marker(tmp_path):
    path = backup_dir(tmp_path)
    info = mountinfo_for(path)
    local.initialize_local_destination(destination(path), mountinfo_text=info)
    path.chmod(0o755)
    with pytest.raises(VaultRewindError) as loose:
        local.inspect_local_destination(destination(path), mountinfo_text=info)
    assert loose.value.code == "LOCAL_PERMISSIONS_UNSAFE"
    path.chmod(0o700)
    other = local.LocalDestination(destination_id=str(uuid.uuid4()), path=path, min_free_bytes=0)
    with pytest.raises(VaultRewindError) as foreign:
        local.inspect_local_destination(other, mountinfo_text=info)
    assert foreign.value.code == "LOCAL_DESTINATION_MISMATCH"


def test_free_space_threshold(tmp_path):
    path = backup_dir(tmp_path)
    huge = local.LocalDestination(destination_id=DEST, path=path, min_free_bytes=1 << 62)
    with pytest.raises(VaultRewindError) as error:
        local.initialize_local_destination(huge, mountinfo_text=mountinfo_for(path))
    assert error.value.code == "INSUFFICIENT_SPACE" and error.value.details["required_bytes"] == 1 << 62


def test_configuration_rejects_unknown_settings():
    with pytest.raises(VaultRewindError):
        local.LocalDestination.from_config({"path": "/srv/x", "chmod_everything": True}, DEST)
    with pytest.raises(VaultRewindError):
        local.LocalDestination.from_config({"min_free_bytes": -1}, DEST)


def test_probe_writes_reads_and_deletes_inside_namespace(tmp_path):
    path = backup_dir(tmp_path)
    info = mountinfo_for(path)
    result = providers.test_destination("local", {"path": str(path), "min_free_bytes": 0}, None, destination_id=DEST,
                                        work_dir=tmp_path / "state", mountinfo_text=info)
    assert result["probe"] == {"write": True, "read": True, "delete": True} and result["backup_ready"]
    assert list((path / "vaultrewind" / ".probe").iterdir()) == []


@pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")
def test_real_local_repository_via_provider_entry_point(tmp_path):
    path = backup_dir(tmp_path)
    info = mountinfo_for(path)
    configuration = {"path": str(path), "min_free_bytes": 0}
    instance = str(uuid.uuid4())
    providers.test_destination("local", configuration, None, destination_id=DEST, work_dir=tmp_path / "state",
                               mountinfo_text=info)
    location = providers.repository_location("local", configuration, instance, DEST)
    assert location == f"{path}/vaultrewind/{instance}/{DEST}"
    assert providers.physical_identity("local", configuration, instance, DEST) == providers.physical_identity(
        "local", {**configuration, "host_path": "/renamed/display"}, instance, DEST)
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    with providers.open_repository("local", configuration, None, instance_id=instance, destination_id=DEST,
                                   password="synthetic-local-password-123456", work_dir=tmp_path / "state",
                                   mountinfo_text=info) as repo:
        repository_id = repo.initialize()["repository_id"]
        committed = repo.commit(*snapshot_args(stage, manifest))
    assert oct(Path(location).stat().st_mode & 0o777) == "0o700"
    assert local.list_local_repositories(destination(path)) == [
        {"instance_id": instance, "destination_id": DEST, "location": location}]
    (path / local.MARKER_NAME).rename(path / "marker.bak")  # simulate a missing mount
    with pytest.raises(VaultRewindError) as error, providers.open_repository(
            "local", configuration, None, instance_id=instance, destination_id=DEST,
            password="synthetic-local-password-123456", work_dir=tmp_path / "state", repository_id=repository_id,
            mountinfo_text=info):
        pass
    assert error.value.code == "LOCAL_MOUNT_MISSING"
    (path / "marker.bak").rename(path / local.MARKER_NAME)
    with providers.open_repository("local", configuration, None, instance_id=instance, destination_id=DEST,
                                   password="synthetic-local-password-123456", work_dir=tmp_path / "state",
                                   repository_id=repository_id, mountinfo_text=info) as repo:
        assert [s["restic_snapshot_id"] for s in repo.list_snapshots()] == [committed["restic_snapshot_id"]]
    assert os.stat(tmp_path / "state").st_mode & 0o077 == 0


@pytest.mark.parametrize("flag", [True, False, None, "true", 1])
def test_operational_provider_boundaries_reject_recovery_setting(tmp_path, flag):
    path = backup_dir(tmp_path)
    config = {"path": str(path), "min_free_bytes": 0, "recovery_mode": flag}
    instance = str(uuid.uuid4())
    common = {"destination_id": DEST, "work_dir": tmp_path / "state"}
    calls = [lambda: local.LocalDestination.from_config(config, DEST),
             lambda: providers.normalize_destination_input("local", config, None),
             lambda: providers.validate_destination("local", config, None, DEST),
             lambda: providers.repository_location("local", config, instance, DEST),
             lambda: providers.physical_identity("local", config, instance, DEST),
             lambda: providers.test_destination("local", config, None, **common),
             lambda: providers.list_repositories("local", config, None, **common)]
    for call in calls:
        with pytest.raises(VaultRewindError) as error:
            call()
        assert error.value.code == "STORAGE_CONFIGURATION"
    with pytest.raises(VaultRewindError) as error, providers.open_repository(
            "local", config, None, instance_id=instance, password="synthetic-operational-recovery", **common):
        pytest.fail("operational provider accepted recovery settings")
    assert error.value.code == "STORAGE_CONFIGURATION"
    assert list(path.iterdir()) == [], "no marker, probe or repository can be created via this bypass"


def test_recovery_capability_cannot_initialize_or_probe_local_destination(tmp_path):
    path = backup_dir(tmp_path)
    path.chmod(0o755)
    dest = local.LocalRecoveryDestination.from_path(path, DEST)
    evidence = local.inspect_local_destination(dest, mountinfo_text=mountinfo_for(path, "tmpfs", "ro"))
    assert evidence["read_only"] and not evidence["durable_for_safety"] and not evidence["backup_ready"]
    for action in (local.initialize_local_destination, local.probe_local):
        with pytest.raises(VaultRewindError) as error:
            action(dest, mountinfo_text=mountinfo_for(path))
        assert error.value.code == "STORAGE_READ_ONLY"
    assert list(path.iterdir()) == [] and path.stat().st_mode & 0o777 == 0o755


@pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")
def test_readonly_recovery_of_markerless_old_copy_never_mutates_repository(tmp_path):
    path = backup_dir(tmp_path)
    instance = str(uuid.uuid4())
    location = str(path / "vaultrewind" / instance / DEST)
    password = "synthetic-old-copy-recovery-password"
    original = ResticRepository(RepositoryConfig(location, password, instance_uuid=instance,
                                                 runtime_dir=tmp_path / "runtime"))
    repository_id = original.initialize()["repository_id"]
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    committed = original.commit(*snapshot_args(stage, manifest))
    config = {"path": str(path), "min_free_bytes": 1 << 62}
    path.chmod(0o755)  # copied directory ownership/perms and durability need not satisfy new-backup rules
    before = {str(p.relative_to(path)): (p.stat().st_size, p.stat().st_mtime_ns)
              for p in path.rglob("*") if p.is_file()}
    common = {"destination_id": DEST, "work_dir": tmp_path / "recovery",
              "mountinfo_text": mountinfo_for(path, "tmpfs", "ro")}
    assert providers.list_recovery_repositories("local", config, None, **common) == [
        {"instance_id": instance, "destination_id": DEST, "location": location}]
    with providers.open_recovery_repository("local", config, None, instance_id=instance, password=password,
                                           repository_id=repository_id, **common) as repo:
        assert repo.config.read_only and not repo.durable_for_safety
        assert "--no-lock" in repo._command(["snapshots"])
        assert repo.describe()["repository_id"] == repository_id
        assert repo.restore(committed["restic_snapshot_id"], tmp_path / "restored")["restored_bytes_verified"]
        assert repo.check()["ok"]
        operations = [repo.initialize, lambda: repo.commit(*snapshot_args(stage, manifest), kind="safety"),
                      lambda: repo.restore(committed["restic_snapshot_id"], Path(location) / "restore-output"),
                      lambda: repo.forget([]), lambda: repo.forget([committed["restic_snapshot_id"]]),
                      repo.prune, repo.remove_stale_locks, lambda: repo.add_key("synthetic-another-password"),
                      lambda: repo.remove_key("a" * 64),
                      lambda: repo.rotate_password("synthetic-rotated-password", lambda _: pytest.fail("persist"))]
        for operation in operations:
            with pytest.raises(VaultRewindError) as error:
                operation()
            assert error.value.code == "STORAGE_READ_ONLY"
    after = {str(p.relative_to(path)): (p.stat().st_size, p.stat().st_mtime_ns)
             for p in path.rglob("*") if p.is_file()}
    assert before == after and not (path / local.MARKER_NAME).exists()
    marker = {"format": "vaultrewind-destination", "destination_id": str(uuid.uuid4())}
    (path / local.MARKER_NAME).write_text(json.dumps(marker))
    with pytest.raises(VaultRewindError) as error:
        providers.list_recovery_repositories("local", config, None, **common)
    assert error.value.code == "LOCAL_DESTINATION_MISMATCH"

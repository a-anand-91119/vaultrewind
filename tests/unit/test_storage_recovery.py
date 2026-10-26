"""Recovery kit cryptography and the offline controller-loss drill with real restic repositories.

The drill builds repositories through the normal provider entry points, exports a kit, destroys every piece
of controller state (work directory and master key; no database is consulted), then discovers, imports and
restores using only the kit, its passphrase and storage access.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from tests.unit.test_storage_support import RESTIC, make_snapshot_tree, mountinfo_for, snapshot_args
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.recovery import kit as kitmod
from vaultrewind.recovery import offline
from vaultrewind.security.secrets import SecretBox, load_master_key_file, write_master_key_file
from vaultrewind.storage import layout, providers

FAST_KDF = {"time_cost": 1, "memory_cost": 8192, "parallelism": 1}
PASSPHRASE = "correct horse synthetic staple 42"
REPO_ROOT = Path(__file__).resolve().parents[2]


def sample_contents(**overrides) -> dict:
    destination_id = str(uuid.uuid4())
    instance_id = str(uuid.uuid4())
    configuration = {"path": "/var/lib/vaultrewind/backups"}
    arguments = {
        "controller_id": str(uuid.uuid4()), "recovery_root_secret": layout.new_recovery_root_secret(),
        "destinations": [{"destination_id": destination_id, "backend": "local", "name": "Controller disk",
                          "configuration": configuration, "credential": None}],
        "repositories": [{"repository_id": "r1", "instance_id": instance_id, "destination_id": destination_id,
                          "location": providers.repository_location("local", configuration, instance_id,
                                                                    destination_id),
                          "password": "synthetic-kit-repository-password-1", "restic_repository_id": "a" * 64}],
        "instances": [{"instance_id": instance_id, "name": "Synthetic vault"}]}
    return kitmod.build_recovery_kit(**{**arguments, **overrides})


def test_kit_round_trip_with_default_argon2id_parameters():
    contents = sample_contents()
    blob = kitmod.seal_recovery_kit(contents, PASSPHRASE)
    header = json.loads(blob)
    assert header["kdf"]["name"] == "argon2id" and header["kdf"]["memory_cost"] == 262144
    assert header["cipher"]["name"] == "AES-256-GCM"
    assert "synthetic-kit-repository-password-1" not in blob.decode()
    assert contents["recovery_root_secret"] not in blob.decode()
    assert kitmod.open_recovery_kit(blob, PASSPHRASE) == contents


def test_wrong_passphrase_tampering_and_format_errors():
    blob = kitmod.seal_recovery_kit(sample_contents(), PASSPHRASE, kdf=FAST_KDF)
    with pytest.raises(VaultRewindError) as wrong:
        kitmod.open_recovery_kit(blob, PASSPHRASE + "x")
    assert wrong.value.code == "RECOVERY_KIT_PASSPHRASE_INVALID"
    envelope = json.loads(blob)
    envelope["kit_id"] = str(uuid.uuid4())  # header is authenticated
    with pytest.raises(VaultRewindError):
        kitmod.open_recovery_kit(json.dumps(envelope).encode(), PASSPHRASE)
    envelope = json.loads(blob)
    envelope["kdf"]["memory_cost"] = 1 << 40  # out-of-bounds parameters are refused before hashing
    with pytest.raises(VaultRewindError) as bounds:
        kitmod.open_recovery_kit(json.dumps(envelope).encode(), PASSPHRASE)
    assert bounds.value.code == "RECOVERY_KIT_INVALID"
    envelope = json.loads(blob)
    envelope["version"] = 99
    with pytest.raises(VaultRewindError) as version:
        kitmod.open_recovery_kit(json.dumps(envelope).encode(), PASSPHRASE)
    assert version.value.code == "RECOVERY_KIT_VERSION_UNSUPPORTED"
    with pytest.raises(VaultRewindError):
        kitmod.open_recovery_kit(b"PK\x03\x04 not a kit", PASSPHRASE)


@pytest.mark.parametrize("weak", ["short", "aaaaaaaaaaaaaaaa", "", "x" * 2000])
def test_weak_passphrases_are_rejected(weak):
    with pytest.raises(VaultRewindError) as error:
        kitmod.seal_recovery_kit(sample_contents(), weak, kdf=FAST_KDF)
    assert error.value.code == "RECOVERY_PASSPHRASE_WEAK"


def test_kit_validation_and_private_file(tmp_path):
    with pytest.raises(VaultRewindError):
        sample_contents(recovery_root_secret="not-base64-32-bytes")
    with pytest.raises(VaultRewindError):
        kitmod.build_recovery_kit(controller_id="c", destinations=[], repositories=[{
            "instance_id": str(uuid.uuid4()), "destination_id": str(uuid.uuid4()), "location": "/x/y/z",
            "password": "synthetic-password-000000"}])
    contents = sample_contents()
    blob = kitmod.seal_recovery_kit(contents, PASSPHRASE, kdf=FAST_KDF)
    path = kitmod.write_recovery_kit(tmp_path / "kit.vrkit", blob)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    with pytest.raises(FileExistsError):
        kitmod.write_recovery_kit(path, blob)
    summary = json.dumps(kitmod.kit_summary(kitmod.open_recovery_kit(path.read_bytes(), PASSPHRASE)))
    assert "synthetic-kit-repository-password-1" not in summary and contents["recovery_root_secret"] not in summary
    assert json.loads(summary)["has_recovery_root_secret"] is True


def test_derived_repository_passwords_are_unique_and_stable():
    root = layout.new_recovery_root_secret()
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    assert layout.derive_repository_password(root, a, b) == layout.derive_repository_password(root, a, b)
    assert layout.derive_repository_password(root, a, b) != layout.derive_repository_password(root, b, a)
    assert layout.derive_repository_password(root, a, b) != layout.derive_repository_password(
        layout.new_recovery_root_secret(), a, b)
    assert len(layout.derive_repository_password(root, a, b)) == 48


# ---------------------------------------------------------------- controller-loss drill
def _minio():
    try:
        from tests.unit.test_storage_s3 import MINIO, minio_config, minio_credentials
    except Exception:  # noqa: BLE001 - optional second backend
        return None
    return (minio_config, minio_credentials) if MINIO else None


@pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")
def test_controller_loss_drill_kit_only_discovery_import_restore_and_plan(tmp_path):
    controller = tmp_path / "controller"
    work = controller / "state"
    master_key = controller / "master.key"
    controller.mkdir(mode=0o700)
    write_master_key_file(master_key)
    box = SecretBox(load_master_key_file(master_key))
    root_secret = layout.new_recovery_root_secret()
    root_envelope = box.encrypt(root_secret, context="recovery-root")  # what the controller DB would hold

    disk = tmp_path / "backup-disk"
    disk.mkdir(mode=0o700)
    mounts = mountinfo_for(disk)
    local_dest = str(uuid.uuid4())
    local_config = {"path": str(disk), "min_free_bytes": 0}
    providers.test_destination("local", local_config, None, destination_id=local_dest, work_dir=work,
                               mountinfo_text=mounts)
    destinations = [{"destination_id": local_dest, "backend": "local", "name": "Controller disk",
                     "configuration": local_config, "credential": None}]
    minio = _minio()
    s3_dest = str(uuid.uuid4())
    if minio:
        s3_config, s3_credentials = minio[0](f"tests/{uuid.uuid4()}"), minio[1]()
        destinations.append({"destination_id": s3_dest, "backend": "s3", "name": "MinIO fixture",
                             "configuration": s3_config, "credential": s3_credentials})

    instance_a, instance_b = str(uuid.uuid4()), str(uuid.uuid4())
    password_a = layout.new_repository_password()  # random secret, listed explicitly in the kit
    committed: dict[str, dict] = {}

    def commit(destination, instance, password, tree, kind="backup"):
        with providers.open_repository(destination["backend"], destination["configuration"],
                                       destination["credential"], instance_id=instance,
                                       destination_id=destination["destination_id"], password=password,
                                       work_dir=work, mountinfo_text=mounts) as repo:
            repo.initialize()
            result = repo.commit(*tree, kind=kind)
            return result, repo.config.location, repo.repository_id

    stage_a, manifest_a = make_snapshot_tree(tmp_path / "a1", instance_uuid=instance_a)
    repositories = []
    for destination in destinations:
        result, location, restic_id = commit(destination, instance_a, password_a, snapshot_args(stage_a, manifest_a))
        committed[destination["backend"]] = result
        repositories.append({"repository_id": str(uuid.uuid4()), "instance_id": instance_a,
                             "destination_id": destination["destination_id"], "location": location,
                             "password": password_a, "restic_repository_id": restic_id})
    stage_s, manifest_s = make_snapshot_tree(tmp_path / "safety", instance_uuid=instance_a, source_state="stopped")
    safety, _, _ = commit(destinations[0], instance_a, password_a, snapshot_args(stage_s, manifest_s), kind="safety")

    blob = kitmod.seal_recovery_kit(kitmod.build_recovery_kit(
        controller_id=str(uuid.uuid4()), recovery_root_secret=box.decrypt(root_envelope, context="recovery-root"),
        destinations=destinations, repositories=repositories,
        instances=[{"instance_id": instance_a, "name": "Synthetic A"}]), PASSPHRASE, kdf=FAST_KDF)

    # Instance B is enrolled after the kit export; its password is derived from the recovery root secret.
    stage_b, manifest_b = make_snapshot_tree(tmp_path / "b1", instance_uuid=instance_b)
    commit(destinations[0], instance_b, layout.derive_repository_password(root_secret, instance_b, local_dest),
           snapshot_args(stage_b, manifest_b))

    # ---- total controller loss: state, caches, credentials and master key are gone.
    shutil.rmtree(controller)
    del box, root_envelope
    recovery_work = tmp_path / "fresh-machine"

    kit = kitmod.open_recovery_kit(blob, PASSPHRASE)
    discovery = offline.discover(kit, work_dir=recovery_work)
    local_repos = {r["instance_id"]: r for d in discovery["destinations"] if d["backend"] == "local"
                   for r in d["repositories"]}
    assert local_repos[instance_a]["password_source"] == "kit" and local_repos[instance_b]["password_source"] == "derived"
    assert all(r["status"] == "ok" for r in local_repos.values())
    found_a = {s["snapshot_uuid"]: s for s in local_repos[instance_a]["snapshots"]}
    assert found_a[manifest_a["snapshot_uuid"]]["manifest_verified"] and found_a[manifest_s["snapshot_uuid"]]["kind"] == \
        "safety"
    assert [s["snapshot_uuid"] for s in local_repos[instance_b]["snapshots"]] == [manifest_b["snapshot_uuid"]]

    plan = offline.import_plan(discovery, kit)
    assert plan["mode"] == "protected" and plan["retention"]["automatic_deletion_enabled"] is False
    assert plan["deletions"] == [] and plan["conflicts"] == []
    by_uuid = {s["snapshot_uuid"]: s for s in plan["snapshots"]}
    assert "imported_review" in by_uuid[manifest_a["snapshot_uuid"]]["protections"]
    assert "safety" in by_uuid[manifest_s["snapshot_uuid"]]["protections"]
    assert len(by_uuid[manifest_a["snapshot_uuid"]]["copies"]) == len(destinations)
    plan_text = json.dumps(plan)
    assert password_a not in plan_text and root_secret not in plan_text
    if minio:
        assert minio[1]()["secret_access_key"] not in plan_text

    restored = offline.restore_snapshot(kit, manifest_a["snapshot_uuid"], tmp_path / "restored", work_dir=recovery_work)
    assert restored["verification"]["restored_bytes_verified"] and restored["source"]["backend"] == "local"
    assert restored["manifest_hash"] == committed["local"]["manifest_hash"] and safety["stored_copy_verified"]

    target = offline.build_target_plan(tmp_path / "restored", kit=kit)
    assert target["executes_nothing"] and target["validation"]["descriptor_fingerprint_matches"]
    assert target["validation"]["image_archive_hash_matches"]
    assert {i["code"] for i in target["blocking_issues"]} == {"TARGET_PROFILE_REQUIRED"}
    env = {e["name"]: e["value"] for e in target["deployment"]["environment"]}
    assert env["ADMIN_TOKEN"] == "[REDACTED]" and env["DOMAIN"] == "https://vault.synthetic.invalid"
    ready = offline.build_target_plan(tmp_path / "restored", target_profile={"public_url": "https://dr.synthetic.invalid"})
    assert ready["ready"] and ready["substitutions"][0] == {"setting": "DOMAIN", "from": "https://vault.synthetic.invalid",
                                                            "to": "https://dr.synthetic.invalid"}
    assert "synthetic-admin-token-value" not in json.dumps(ready)


@pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")
def test_offline_restore_falls_back_only_to_an_equivalent_copy(tmp_path):
    instance = str(uuid.uuid4())
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance, image_bytes=512 * 1024)
    destinations, repositories = [], []
    password = layout.new_repository_password()
    for name in ("first", "second"):
        disk = tmp_path / name
        disk.mkdir(mode=0o700)
        destination_id = str(uuid.uuid4())
        configuration = {"path": str(disk), "min_free_bytes": 0}
        providers.test_destination("local", configuration, None, destination_id=destination_id,
                                   work_dir=tmp_path / "state", mountinfo_text=mountinfo_for(disk))
        with providers.open_repository("local", configuration, None, instance_id=instance,
                                       destination_id=destination_id, password=password, work_dir=tmp_path / "state",
                                       mountinfo_text=mountinfo_for(disk)) as repo:
            repo.initialize()
            repo.commit(*snapshot_args(stage, manifest))
            location = repo.config.location
        destinations.append({"destination_id": destination_id, "backend": "local", "name": name,
                             "configuration": configuration, "credential": None})
        repositories.append({"instance_id": instance, "destination_id": destination_id, "location": location,
                             "password": password})
    for pack in (tmp_path / "first").rglob("data/*/*"):  # corrupt every pack of the first copy
        pack.chmod(0o600)
        data = bytearray(pack.read_bytes())
        data[len(data) // 2] ^= 0xFF
        pack.write_bytes(bytes(data))
    kit = kitmod.open_recovery_kit(kitmod.seal_recovery_kit(kitmod.build_recovery_kit(
        controller_id="drill", destinations=destinations, repositories=repositories), PASSPHRASE, kdf=FAST_KDF),
        PASSPHRASE)
    result = offline.restore_snapshot(kit, manifest["snapshot_uuid"], tmp_path / "restored", work_dir=tmp_path / "w")
    assert result["source"]["destination_id"] == destinations[1]["destination_id"]
    assert result["attempts"] and result["attempts"][0]["destination_id"] == destinations[0]["destination_id"]
    assert result["verification"]["restored_bytes_verified"]


@pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")
def test_offline_cli_end_to_end_reads_secrets_only_from_private_files(tmp_path):
    instance = str(uuid.uuid4())
    disk = tmp_path / "disk"
    disk.mkdir(mode=0o700)
    destination_id = str(uuid.uuid4())
    configuration = {"path": str(disk), "min_free_bytes": 0}
    providers.test_destination("local", configuration, None, destination_id=destination_id,
                               work_dir=tmp_path / "state", mountinfo_text=mountinfo_for(disk))
    password = layout.new_repository_password()
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    with providers.open_repository("local", configuration, None, instance_id=instance, destination_id=destination_id,
                                   password=password, work_dir=tmp_path / "state",
                                   mountinfo_text=mountinfo_for(disk)) as repo:
        repo.initialize()
        repo.commit(*snapshot_args(stage, manifest))
        location = repo.config.location
    kit_file = kitmod.write_recovery_kit(tmp_path / "owner.vrkit", kitmod.seal_recovery_kit(kitmod.build_recovery_kit(
        controller_id="cli-drill", destinations=[{"destination_id": destination_id, "backend": "local", "name": "disk",
                                                  "configuration": configuration, "credential": None}],
        repositories=[{"instance_id": instance, "destination_id": destination_id, "location": location,
                       "password": password}]), PASSPHRASE, kdf=FAST_KDF))
    passphrase_file = tmp_path / "passphrase"
    passphrase_file.write_text(PASSPHRASE + "\n")
    passphrase_file.chmod(0o600)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path), "PYTHONPATH": str(REPO_ROOT / "src")}

    def cli(*args):
        return subprocess.run([sys.executable, "-m", "vaultrewind.recovery", *args, ], capture_output=True, text=True,
                              env=env, cwd=tmp_path, timeout=300, check=False)

    common = ["--kit", str(kit_file), "--passphrase-file", str(passphrase_file)]
    inspected = cli("inspect", *common)
    assert inspected.returncode == 0, inspected.stderr
    assert password not in inspected.stdout and PASSPHRASE not in inspected.stdout
    discovered = cli("discover", *common, "--work-dir", str(tmp_path / "w"))
    assert discovered.returncode == 0 and manifest["snapshot_uuid"] in discovered.stdout
    restored = cli("restore", *common, "--work-dir", str(tmp_path / "w"), "--snapshot", manifest["snapshot_uuid"],
                   "--target", str(tmp_path / "out"))
    assert restored.returncode == 0, restored.stderr
    assert json.loads(restored.stdout)["verification"]["restored_bytes_verified"] is True
    planned = cli("plan", "--restored", str(tmp_path / "out"), "--same-instance")
    assert planned.returncode == 0 and json.loads(planned.stdout)["ready"] is True
    imported = cli("import-plan", *common, "--work-dir", str(tmp_path / "w"), "--output", str(tmp_path / "plan.json"))
    assert imported.returncode == 0 and oct((tmp_path / "plan.json").stat().st_mode & 0o777) == "0o600"
    assert json.loads((tmp_path / "plan.json").read_text())["mode"] == "protected"
    passphrase_file.chmod(0o644)
    loose = cli("inspect", *common)
    assert loose.returncode == 2 and json.loads(loose.stderr)["error"]["code"] == "RECOVERY_INPUT_UNSAFE"
    assert all(PASSPHRASE not in arg for arg in common)
    assert not os.environ.get("VAULTREWIND_KIT_PASSPHRASE")


@pytest.mark.skipif(RESTIC is None, reason="pinned restic binary not installed")
def test_offline_discovery_of_a_remounted_disk_uses_kit_passwords(tmp_path):
    instance, destination_id = str(uuid.uuid4()), str(uuid.uuid4())
    disk = tmp_path / "original-mount"
    disk.mkdir(mode=0o700)
    configuration = {"path": str(disk), "min_free_bytes": 0}
    providers.test_destination("local", configuration, None, destination_id=destination_id,
                               work_dir=tmp_path / "state", mountinfo_text=mountinfo_for(disk))
    password = layout.new_repository_password()  # random: not derivable, only the kit knows it
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    with providers.open_repository("local", configuration, None, instance_id=instance, destination_id=destination_id,
                                   password=password, work_dir=tmp_path / "state",
                                   mountinfo_text=mountinfo_for(disk)) as repo:
        repo.initialize()
        repo.commit(*snapshot_args(stage, manifest))
        location = repo.config.location
    kit = kitmod.open_recovery_kit(kitmod.seal_recovery_kit(kitmod.build_recovery_kit(
        controller_id="remount", destinations=[{"destination_id": destination_id, "backend": "local", "name": "disk",
                                                "configuration": configuration, "credential": None}],
        repositories=[{"instance_id": instance, "destination_id": destination_id, "location": location,
                       "password": password}]), PASSPHRASE, kdf=FAST_KDF), PASSPHRASE)
    moved = tmp_path / "recovery-mount"
    disk.rename(moved)
    discovery = offline.discover(kit, work_dir=tmp_path / "w", local_paths={destination_id: str(moved)})
    repositories = discovery["destinations"][0]["repositories"]
    assert len(repositories) == 1 and repositories[0]["status"] == "ok"
    assert repositories[0]["password_source"] == "kit" and repositories[0]["location"].startswith(str(moved))
    assert [s["snapshot_uuid"] for s in repositories[0]["snapshots"]] == [manifest["snapshot_uuid"]]

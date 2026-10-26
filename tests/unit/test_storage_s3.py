"""S3-compatible destinations: deterministic validation plus real MinIO integration when available.

MinIO credentials are read from ``.runtime/minio/credentials.json`` (or VAULTREWIND_TEST_S3_* variables)
and are never printed. Every test uses a unique prefix in the synthetic bucket.
"""
from __future__ import annotations

import json
import os
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.unit.test_storage_support import RESTIC, make_snapshot_tree, snapshot_args
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.storage import providers, s3
from vaultrewind.storage.restic import RepositoryConfig

DEST = str(uuid.uuid4())
RUNTIME = Path(__file__).resolve().parents[2] / ".runtime" / "minio"
SYNTHETIC_CA = """-----BEGIN CERTIFICATE-----
MIIBfzCCASWgAwIBAgIUQbJvR7RsZx8n0mJm6r3X0qkqK8owCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKc3ludGhldGljMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAw
MDAwMFowFTETMBEGA1UEAwwKc3ludGhldGljMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE
-----END CERTIFICATE-----
"""


def config(**overrides) -> dict:
    return {"endpoint": "https://s3.eu-west-1.amazonaws.com", "bucket": "vaultrewind-synthetic",
            "prefix": "team/backups", "region": "eu-west-1", "bucket_lookup": "auto", **overrides}


def make_ca() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic test CA")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now)
                   .not_valid_after(now.replace(year=now.year + 1)).sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def test_location_options_and_public_view():
    destination = s3.S3Destination.from_config(config(prefix="/team/backups/"), DEST)
    instance = str(uuid.uuid4())
    assert destination.repository_location(instance) == (
        f"s3:https://s3.eu-west-1.amazonaws.com/vaultrewind-synthetic/team/backups/vaultrewind/{instance}/{DEST}")
    assert destination.restic_options() == ("s3.bucket-lookup=auto", "s3.region=eu-west-1")
    assert destination.public_view()["custom_ca"] is False
    assert providers.repository_location("s3", config(), instance, DEST) == destination.repository_location(instance)


@pytest.mark.parametrize("overrides, code", [
    ({"endpoint": "http://s3.example.org"}, "STORAGE_TLS_REQUIRED"),
    ({"endpoint": "http://s3.example.org", "development_http": True}, "STORAGE_TLS_REQUIRED"),
    ({"endpoint": "https://user:pw@s3.example.org"}, "STORAGE_CONFIGURATION"),
    ({"endpoint": "https://s3.example.org/bucket"}, "STORAGE_CONFIGURATION"),
    ({"endpoint": "https://s3.example.org?x=1"}, "STORAGE_CONFIGURATION"),
    ({"bucket": "Bad_Bucket"}, "STORAGE_CONFIGURATION"),
    ({"bucket": "192.168.1.1"}, "STORAGE_CONFIGURATION"),
    ({"prefix": "a/../b"}, "STORAGE_CONFIGURATION"),
    ({"prefix": "a b"}, "STORAGE_CONFIGURATION"),
    ({"bucket_lookup": "sideways"}, "STORAGE_CONFIGURATION"),
    ({"region": "EU WEST"}, "STORAGE_CONFIGURATION"),
    ({"ca_cert_pem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}, "STORAGE_CA_INVALID"),
    ({"ca_cert_pem": SYNTHETIC_CA}, "STORAGE_CA_INVALID"),
    ({"insecure_skip_verify": True}, "STORAGE_CONFIGURATION"),
])
def test_validation_rejects_unsafe_settings(overrides, code):
    with pytest.raises(VaultRewindError) as error:
        s3.S3Destination.from_config(config(**overrides), DEST)
    assert error.value.code == code


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:9000", "http://localhost:9000", "http://minio:9000",
                                      "http://10.1.2.3:9000", "http://[::1]:9000"])
def test_plain_http_only_for_explicit_local_fixtures(endpoint):
    destination = s3.S3Destination.from_config(config(endpoint=endpoint, development_http=True), DEST)
    location = destination.repository_location(str(uuid.uuid4()))
    with pytest.raises(VaultRewindError):
        RepositoryConfig(location=location, password="synthetic-password-0123456789")
    assert RepositoryConfig(location=location, password="synthetic-password-0123456789", allow_insecure_http=True)


def test_custom_ca_is_validated_and_reaches_restic_only_as_a_file():
    pem = make_ca()
    destination = s3.S3Destination.from_config(config(ca_cert_pem=pem, bucket_lookup="path"), DEST)
    assert destination.public_view()["custom_ca"] is True and destination.restic_options()[0] == "s3.bucket-lookup=path"
    repo_config = RepositoryConfig(location=destination.repository_location(str(uuid.uuid4())),
                                   password="synthetic-password-0123456789", ca_cert_pem=destination.ca_cert_pem,
                                   options=destination.restic_options())
    assert "BEGIN CERTIFICATE" not in repr(repo_config)


def test_credentials_validation_and_environment():
    with pytest.raises(VaultRewindError):
        s3.S3Credentials.from_dict({"access_key_id": "AKIA SPACE", "secret_access_key": "x" * 20})
    with pytest.raises(VaultRewindError):
        s3.S3Credentials.from_dict({"access_key_id": "AKIAOK000000", "secret_access_key": "a\nb"})
    with pytest.raises(VaultRewindError):
        s3.S3Credentials.from_dict(None)
    credentials = s3.S3Credentials.from_dict({"access_key_id": "AKIASYNTHETIC0000000",
                                              "secret_access_key": "synthetic-secret-value"})
    assert "synthetic-secret-value" not in repr(credentials)
    assert credentials.environment("eu-west-1") == {"AWS_ACCESS_KEY_ID": "AKIASYNTHETIC0000000",
                                                    "AWS_SECRET_ACCESS_KEY": "synthetic-secret-value",
                                                    "AWS_DEFAULT_REGION": "eu-west-1"}


# ---------------------------------------------------------------- real MinIO
def _minio() -> dict | None:
    if os.environ.get("VAULTREWIND_TEST_S3_ENDPOINT"):
        return {"endpoint": os.environ["VAULTREWIND_TEST_S3_ENDPOINT"],
                "access_key": os.environ["VAULTREWIND_TEST_S3_ACCESS_KEY"],
                "secret_key": os.environ["VAULTREWIND_TEST_S3_SECRET_KEY"],
                "bucket": os.environ.get("VAULTREWIND_TEST_S3_BUCKET", "vaultrewind-synthetic")}
    try:
        data = json.loads((RUNTIME / "credentials.json").read_text())
        with urllib.request.urlopen(data["endpoint"] + "/minio/health/live", timeout=3) as response:
            if response.status != 200:
                return None
        return {**data, "bucket": "vaultrewind-synthetic"}
    except (OSError, ValueError, KeyError):
        return None


MINIO = _minio()
needs_minio = pytest.mark.skipif(MINIO is None or RESTIC is None, reason="MinIO fixture or restic unavailable")


def minio_config(prefix: str) -> dict:
    return {"endpoint": MINIO["endpoint"], "bucket": MINIO["bucket"], "prefix": prefix, "region": "us-east-1",
            "bucket_lookup": "path", "development_http": MINIO["endpoint"].startswith("http://")}


def minio_credentials() -> dict:
    return {"access_key_id": MINIO["access_key"], "secret_access_key": MINIO["secret_key"]}


@pytest.mark.integration
@needs_minio
def test_minio_probe_reports_each_permission(tmp_path):
    prefix = f"tests/{uuid.uuid4()}"
    result = providers.test_destination("s3", minio_config(prefix), minio_credentials(), destination_id=DEST,
                                        work_dir=tmp_path / "state")
    assert {name: value["ok"] for name, value in result["probe"].items()} == {
        "list": True, "write": True, "read": True, "delete": True}
    assert result["backup_ready"] and result["retention_ready"] and not result["probe_left_behind"]
    bad = providers.test_destination("s3", minio_config(prefix), {**minio_credentials(),
                                                                  "secret_access_key": "wrong-synthetic-secret"},
                                     destination_id=DEST, work_dir=tmp_path / "state")
    assert not bad["backup_ready"] and bad["probe"]["list"]["error_code"] == "STORAGE_CREDENTIALS_INVALID"
    missing = providers.test_destination("s3", {**minio_config(prefix), "bucket": "vaultrewind-missing-bucket"},
                                         minio_credentials(), destination_id=DEST, work_dir=tmp_path / "state")
    assert missing["probe"]["list"]["error_code"] == "STORAGE_BUCKET_NOT_FOUND"


@pytest.mark.integration
@needs_minio
def test_minio_backup_restore_expire_and_discover(tmp_path):
    prefix = f"tests/{uuid.uuid4()}"
    instance = str(uuid.uuid4())
    password = "synthetic-s3-repository-password-0001"
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    with providers.open_repository("s3", minio_config(prefix), minio_credentials(), instance_id=instance,
                                   destination_id=DEST, password=password, work_dir=tmp_path / "state") as repo:
        repository_id = repo.initialize()["repository_id"]
        committed = repo.commit(*snapshot_args(stage, manifest))
        assert committed["stored_copy_verified"]
        restored = repo.restore(committed["restic_snapshot_id"], tmp_path / "restored",
                                expected_manifest_hash=committed["manifest_hash"])
        assert restored["restored_bytes_verified"]
        assert repo.check(read_data=True)["full_data_verified"]
    found = providers.list_repositories("s3", minio_config(prefix), minio_credentials(), destination_id=DEST,
                                        work_dir=tmp_path / "state")
    assert [(f["instance_id"], f["destination_id"]) for f in found] == [(instance, DEST)]
    with providers.open_repository("s3", minio_config(prefix), minio_credentials(), instance_id=instance,
                                   destination_id=DEST, password=password, work_dir=tmp_path / "state2",
                                   repository_id=repository_id) as repo:
        outcome = repo.forget([committed["restic_snapshot_id"]])
        assert outcome["removed"] == [committed["restic_snapshot_id"]] and outcome["complete"]
        assert repo.prune()["check"]["ok"]
        assert repo.list_snapshots() == []


def _restricted() -> dict | None:
    try:
        data = json.loads((RUNTIME / "restricted.json").read_text())
        expires = datetime.fromisoformat(data["Expiration"])
        if (expires - datetime.now(UTC)).total_seconds() < 300:
            return None
        return {"access_key_id": data["AccessKeyId"], "secret_access_key": data["SecretAccessKey"],
                "session_token": data["SessionToken"]}
    except (OSError, ValueError, KeyError):
        return None


@pytest.mark.integration
@needs_minio
@pytest.mark.skipif(_restricted() is None, reason="no unexpired delete-restricted STS credentials provisioned")
def test_minio_missing_delete_permission_reports_retained_copy(tmp_path):
    """Retention with credentials lacking DeleteObject must report the copy as still retained."""
    prefix = f"tests/{uuid.uuid4()}"
    instance = str(uuid.uuid4())
    password = "synthetic-s3-repository-password-0002"
    stage, manifest = make_snapshot_tree(tmp_path / "tree", instance_uuid=instance)
    with providers.open_repository("s3", minio_config(prefix), minio_credentials(), instance_id=instance,
                                   destination_id=DEST, password=password, work_dir=tmp_path / "admin") as repo:
        repo.initialize()
        committed = repo.commit(*snapshot_args(stage, manifest))
    probe = providers.test_destination("s3", minio_config(prefix), _restricted(), destination_id=DEST,
                                       work_dir=tmp_path / "probe")
    assert probe["backup_ready"] and not probe["retention_ready"]
    assert False in probe["delete_classes"].values()
    try:
        with providers.open_repository("s3", minio_config(prefix), _restricted(), instance_id=instance,
                                       destination_id=DEST, password=password, work_dir=tmp_path / "limited") as repo:
            outcome = repo.forget([committed["restic_snapshot_id"]])
        assert outcome["retained"] == [committed["restic_snapshot_id"]] and not outcome["complete"]
        assert outcome["error_code"]
    except VaultRewindError as error:  # policy may deny even the lock/list needed to attempt deletion
        assert error.code in ("STORAGE_PERMISSION_DENIED", "STORAGE_DELETE_DENIED", "REPOSITORY_LOCKED")
    with providers.open_repository("s3", minio_config(prefix), minio_credentials(), instance_id=instance,
                                   destination_id=DEST, password=password, work_dir=tmp_path / "admin") as repo:
        assert [s["restic_snapshot_id"] for s in repo.list_snapshots()] == [committed["restic_snapshot_id"]]

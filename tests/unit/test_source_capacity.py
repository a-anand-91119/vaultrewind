"""Pure safety and evidence checks. No Docker, mounts, real disk fill, or restic."""
import errno
import io
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import prove_source_capacity as proof


def test_rootgo_gate_does_not_load_runtime_or_write_evidence(tmp_path, monkeypatch, capsys):
    def forbidden():
        raise AssertionError("MUTATION_BEFORE_ROOTGO")
    monkeypatch.setattr(proof, "load_runtime", forbidden)
    output = tmp_path / "must-not-exist.json"
    assert proof.main(["--output", str(output)]) == 2
    assert not output.exists()
    assert "waiting for ROOTGO" in capsys.readouterr().out


def test_frozen_bundle_pin_and_actual_current_source_match():
    evidence = proof.verify_bundle()
    assert evidence["helper_source_identical_to_current"]
    assert evidence["all_core_remote_sources_identical"]
    assert evidence["compared_module_count"] > 5


def test_bundle_mismatch_rejected_before_zip_loading(tmp_path):
    other = tmp_path / "not-reviewed.pyz"
    other.write_bytes(b"unreviewed helper")
    with pytest.raises(AssertionError, match="FROZEN_HELPER_SHA256_MISMATCH"):
        proof.verify_bundle(other)


def test_filler_observes_enospc_with_bounded_non_sparse_writes():
    buffer = io.BytesIO()
    def write(data):
        if buffer.tell() == 5:
            raise OSError(errno.ENOSPC, "synthetic unit writer only")
        return buffer.write(data[:5])
    result = proof.bounded_fill(write, 8)
    assert result == {"errno": errno.ENOSPC, "filler_bytes": 5, "write_bound_bytes": 9}
    assert buffer.getvalue() == b"xxxxx"


def test_filler_stops_at_bound_when_filesystem_is_not_full():
    buffer = io.BytesIO()
    with pytest.raises(AssertionError, match="DID_NOT_FILL_WITHIN_BOUND"):
        proof.bounded_fill(buffer.write, 8)
    assert buffer.getvalue() == b"x" * 9


@pytest.mark.parametrize("error", [errno.EIO, errno.EPERM, errno.EDQUOT])
def test_filler_does_not_label_other_errors_as_physical_enospc(error):
    def write(_):
        raise OSError(error, "synthetic unit writer only")
    with pytest.raises(AssertionError, match="UNEXPECTED_FILL_ERRNO"):
        proof.bounded_fill(write, 8)


def test_filler_rejects_zero_write_instead_of_looping():
    with pytest.raises(AssertionError, match="NO_PROGRESS"):
        proof.bounded_fill(lambda _: 0, 8)


@pytest.mark.parametrize("limit", [0, -1, proof.MAX_ADVERTISED_STAGING + 1, True])
def test_tmpfs_rejects_unsafe_capacity_without_mounting(tmp_path, limit):
    with pytest.raises(AssertionError, match="UNSAFE_TMPFS_LIMIT"):
        proof.PrivateTmpfs(tmp_path, "source-staging", limit)


def test_tmpfs_rejects_arbitrary_mount_names(tmp_path):
    with pytest.raises(AssertionError, match="UNSAFE_FIXTURE_MOUNT_NAME"):
        proof.PrivateTmpfs(tmp_path, "../shared", proof.STAGING_LIMIT)


def test_fill_guard_rejects_shared_root_before_any_filler_write(tmp_path, monkeypatch):
    mount = proof.PrivateTmpfs(tmp_path, "source-staging", proof.STAGING_LIMIT)
    mount.path.mkdir(mode=0o700)
    mount.identity = {"mount_id": "123", "device": "0:1", "mount_point": str(mount.path),
                      "fs_type": "tmpfs", "source": tmp_path.name}
    monkeypatch.setattr(proof, "mount_at", lambda _: mount.identity)
    with pytest.raises(AssertionError, match="SHARED_ROOT_FILL_FORBIDDEN"):
        mount.shrink_and_fill()
    assert not (mount.path / "bounded-filler").exists()


def test_changed_mount_identity_blocks_fill_and_cleanup(tmp_path, monkeypatch):
    mount = proof.PrivateTmpfs(tmp_path, "source-staging", proof.STAGING_LIMIT)
    mount.path.mkdir(mode=0o700)
    mount.identity = {"mount_id": "old"}
    monkeypatch.setattr(proof, "mount_at", lambda _: {"mount_id": "replacement"})
    with pytest.raises(AssertionError, match="PRIVATE_MOUNT_IDENTITY_CHANGED"):
        mount.close()
    assert mount.identity == {"mount_id": "old"}


def test_outside_mount_rejected_before_kernel_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(proof, "mount_at", lambda _: pytest.fail("Unsafe path inspected"))
    with pytest.raises(AssertionError, match="MOUNT_OUTSIDE_OWN_RUN"):
        proof.guard_private_mount(tmp_path, Path("/"), None)


def test_content_digest_covers_empty_directories_modes_and_bytes(tmp_path):
    item = tmp_path / "private"
    item.write_bytes(b"synthetic")
    item.chmod(0o644)
    original = proof.tree_hash(tmp_path)
    (tmp_path / "empty").mkdir()
    directory = proof.tree_hash(tmp_path)
    assert directory != original
    item.chmod(0o600)
    private_mode = proof.tree_hash(tmp_path)
    assert private_mode != directory
    item.write_bytes(b"different")
    assert proof.tree_hash(tmp_path) != private_mode


def test_safe_error_chain_does_not_include_raw_secret_values():
    cause = OSError(errno.ENOSPC, "never emit fixture-secret-value")
    outer = RuntimeError("never emit raw Docker configuration")
    outer.__cause__ = cause
    chain = proof.error_chain(outer)
    assert chain[-1]["errno"] == errno.ENOSPC
    assert "fixture-secret-value" not in json.dumps(chain)
    assert "Docker configuration" not in json.dumps(chain)


def test_expected_physical_failure_rejects_nonphysical_exception():
    def fail():
        raise OSError(errno.EDQUOT, "synthetic logical quota")
    with pytest.raises(AssertionError, match="PHYSICAL_ENOSPC_REQUIRED"):
        proof.expect_failure(fail, physical=True)


def test_expected_failure_cannot_accept_success():
    with pytest.raises(AssertionError, match="FAULT_DID_NOT_FAIL"):
        proof.expect_failure(lambda: None)


@pytest.fixture
def audited(tmp_path):
    class DockerDouble:
        def api(self, method, path, body=None, **kwargs):
            if method == "GET":
                return {"Config": {"Labels": {proof.LABEL: "our-owner"}}}
            return {"Id": "our-container"}

        def inspect(self, container):
            return self.api("GET", f"/containers/{container}/json")
    return proof.audited_docker({"remote.docker": SimpleNamespace(Docker=DockerDouble)}, "our-owner", tmp_path)


@pytest.mark.parametrize("route", ["/images/create", "/build", "/commit", "/images/load"])
def test_docker_guard_forbids_image_and_daemon_mutations(audited, route):
    with pytest.raises(AssertionError, match="DOCKER_MUTATION_FORBIDDEN"):
        audited.api("POST", route)
    assert audited.calls == []


def test_docker_guard_rejects_unowned_container_before_transport(audited):
    with pytest.raises(AssertionError, match="NOT_OUR_CONTAINER"):
        audited.api("POST", "/containers/shared-primary-source/stop")
    assert audited.calls == []


def test_docker_guard_rejects_outside_bind_before_creation(audited):
    config = {"Labels": {proof.LABEL: "our-owner"},
              "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/shared-source"}]}}
    with pytest.raises(AssertionError, match="DOCKER_MOUNT_OUTSIDE_OWN_RUN"):
        audited.api("POST", "/containers/create?name=unique", config)
    assert audited.calls == []


def test_docker_guard_tracks_created_container_for_exact_cleanup(audited, tmp_path):
    config = {"Labels": {proof.LABEL: "our-owner"},
              "HostConfig": {"Mounts": [{"Type": "bind", "Source": str(tmp_path / "data")}]}}
    created = audited.api("POST", "/containers/create?name=unique", config)
    assert created["Id"] in audited.owned_containers
    audited.api("DELETE", "/containers/our-container?v=true&force=false")
    assert audited.calls[-1] == ("DELETE", "/containers/our-container")


def test_remount_supplies_explicit_tmpfs_type_and_original_source(tmp_path, monkeypatch):
    fixture = proof.PrivateTmpfs(tmp_path, "source-staging", 12 * proof.MIB)
    monkeypatch.setattr(proof, "guard_private_mount", lambda *_: None)
    calls = []
    def checked(*args):
        calls.append(args)
        raise RuntimeError("stop after recording remount; no physical operation")
    monkeypatch.setattr(proof, "checked", checked)
    with pytest.raises(RuntimeError, match="stop after recording remount"):
        fixture.shrink_and_fill()
    assert calls == [("mount", "-t", "tmpfs", "-o",
                      f"remount,size={proof.STAGING_LIMIT},mode=0700,nosuid,nodev", tmp_path.name, str(fixture.path))]


def test_safe_error_evidence_preserves_only_internal_assertion_codes():
    assert proof.error_chain(AssertionError("PRIVATE_TMPFS_NOT_ZERO_FREE"))[0]["assertion_code"] == "PRIVATE_TMPFS_NOT_ZERO_FREE"
    assert "assertion_code" not in proof.error_chain(AssertionError("raw fixture-secret-value"))[0]


def test_retry_evidence_preserves_failed_attempt_with_cleanup_before_overwriting():
    previous = {"result": "failed", "recorded_at": "first", "failure_stage": "remount",
                "cleanup": {"containers_remaining": 0, "private_mounts_remaining": 0}}
    attempts = proof.prior_failed_attempts(previous)
    assert attempts == [previous]
    assert "failed_attempts" not in previous


def test_retry_evidence_does_not_duplicate_already_retained_attempt():
    first = {"result": "failed", "recorded_at": "first"}
    assert proof.prior_failed_attempts({**first, "failed_attempts": [first]}) == [first]


def test_retry_evidence_does_not_treat_pending_or_passed_results_as_failure():
    assert proof.prior_failed_attempts({"result": "not_run_waiting_rootgo"}) == []
    assert proof.prior_failed_attempts({"result": "passed"}) == []


def test_live_data_requires_its_own_gate_even_with_old_rootgo(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(proof, "load_runtime", lambda: pytest.fail("Runtime loaded before data-full GO"))
    output = tmp_path / "evidence.json"
    output.write_text('{"result":"passed","cases":{}}')
    before = output.read_bytes()
    assert proof.main(["--live-data-full", "--rootgo", "--output", str(output)]) == 2
    assert output.read_bytes() == before
    assert "waiting for ROOTGO_DATA_FULL" in capsys.readouterr().out


@pytest.mark.parametrize("status", ["prepared", "passed", "failed"])
def test_live_extension_preserves_staging_pass_and_failure_history(status):
    original = {"result": "passed", "cases": {"source_staging": {"result": "passed"}},
                "source_before_fault": {"pid": 123}, "failed_attempts": [{"result": "failed", "id": "first"}]}
    before = json.dumps(original, sort_keys=True)
    merged = proof.merge_live_data_result(original, {"result": status, "cases": {}})
    assert merged["result"] == "passed"
    assert merged["failed_attempts"] == original["failed_attempts"]
    assert merged["source_before_fault"] == original["source_before_fault"]
    assert merged["cases"]["source_staging"] == {"result": "passed"}
    assert merged["cases"][proof.DATA_CASE]["result"] == status
    assert merged["overall_source_capacity_result"] == status
    assert json.dumps(original, sort_keys=True) == before


def test_logical_sqlite_ignores_page_rewrites_but_detects_row_content(tmp_path):
    database = tmp_path / "db.sqlite3"
    with sqlite3.connect(database) as writer:
        writer.executescript("CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB); INSERT INTO items VALUES(7,x'4142');")
    before = proof.logical_sqlite(database)
    raw_before = proof.file_hash(database)
    with sqlite3.connect(database) as writer:
        writer.execute("VACUUM")
    assert proof.file_hash(database) != raw_before
    assert proof.logical_sqlite(database) == before
    with sqlite3.connect(database) as writer:
        writer.execute("UPDATE items SET payload=x'4344' WHERE id=7")
    assert proof.logical_sqlite(database)["logical_sha256"] != before["logical_sha256"]


def test_logical_sqlite_includes_committed_wal_without_checkpointing(tmp_path):
    database = tmp_path / "db.sqlite3"
    writer = sqlite3.connect(database)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE items(value TEXT)")
        writer.commit()
        before = proof.logical_sqlite(database)
        raw_before = proof.file_hash(database)
        writer.execute("INSERT INTO items VALUES('synthetic-private-content')")
        writer.commit()
        after = proof.logical_sqlite(database)
        assert proof.file_hash(database) == raw_before
        assert after["row_counts"] == {"items": 1}
        assert before["logical_sha256"] != after["logical_sha256"]
        assert "synthetic-private-content" not in json.dumps(after)
    finally:
        writer.close()


def test_logical_sqlite_closes_read_transaction_before_source_stop(tmp_path):
    database = tmp_path / "db.sqlite3"
    with sqlite3.connect(database) as writer:
        writer.execute('CREATE TABLE "odd name"(value INTEGER)')
    assert proof.logical_sqlite(database)["row_counts"] == {"odd name": 0}
    with sqlite3.connect(database, timeout=0) as writer:
        writer.execute("BEGIN EXCLUSIVE")
        writer.execute('INSERT INTO "odd name" VALUES(1)')


def test_non_database_fingerprint_keeps_private_metadata_and_ignores_sqlite_raw_files(tmp_path, monkeypatch):
    (tmp_path / "db.sqlite3").write_bytes(b"synthetic test double database")
    private = tmp_path / "private"
    private.write_bytes(b"synthetic")
    private.chmod(0o644)
    monkeypatch.setattr(proof, "logical_sqlite", lambda _: {"logical_sha256": "same"})
    before = proof.persistent_fingerprint(tmp_path)
    (tmp_path / "db.sqlite3-wal").write_bytes(b"different physical WAL generation")
    (tmp_path / "db.sqlite3").write_bytes(b"rewritten main database")
    assert proof.persistent_fingerprint(tmp_path) == before
    private.chmod(0o600)
    assert proof.persistent_fingerprint(tmp_path) != before


def test_live_filler_is_outside_data_and_removed_by_exact_identity(tmp_path, monkeypatch):
    mount = proof.PrivateTmpfs(tmp_path, "source-filesystem", proof.SOURCE_LIMIT)
    mount.path.mkdir(mode=0o700)
    data = mount.path / "data"
    data.mkdir()
    protected = data / "protected"
    protected.write_bytes(b"unchanged")
    monkeypatch.setattr(proof, "guard_private_mount", lambda *_: None)
    monkeypatch.setattr(proof.shutil, "disk_usage", lambda _: SimpleNamespace(total=proof.SOURCE_LIMIT, free=0))
    monkeypatch.setattr(proof, "bounded_fill", lambda write, limit: {"errno": 28, "filler_bytes": 0})
    mount.identity = {"fs_type": "tmpfs"}
    physical = mount.fill_outside_data(data)
    assert Path(physical["filler_path"]).parent == mount.path
    assert not Path(physical["filler_path"]).is_relative_to(data)
    assert protected.read_bytes() == b"unchanged"
    mount.remove_outside_filler(data, physical)
    assert not Path(physical["filler_path"]).exists()
    assert protected.read_bytes() == b"unchanged"


def test_live_filler_rejects_a_staging_mount_before_any_write(tmp_path, monkeypatch):
    mount = proof.PrivateTmpfs(tmp_path, "source-staging", proof.STAGING_LIMIT)
    monkeypatch.setattr(proof, "guard_private_mount", lambda *_: None)
    with pytest.raises(AssertionError, match="LIVE_FILL_REQUIRES_OWN_16MIB_TMPFS"):
        mount.fill_outside_data(tmp_path)
    assert not mount.path.exists()


def test_live_cleanup_retains_fixture_when_original_recovery_is_unverified(tmp_path):
    drill = object.__new__(proof.Drill)
    drill.live_data_full = True
    drill.source = "own-source"
    drill.result = {"source_application_readiness": {"application_started": True}}
    drill.docker = SimpleNamespace(boundary_observer=None, owned_containers={"own-source"}, owned_networks={"own-network"})
    drill.mounts = [SimpleNamespace(outside_filler_identity={}, identity={"mount_id": "own"})]
    with pytest.raises(AssertionError, match="RECOVERY_UNVERIFIED_RETAIN_OWN_FIXTURE"):
        drill.close()
    assert drill.result["cleanup"]["retained_for_unverified_recovery"]
    assert drill.result["cleanup"]["containers_remaining"] == 1

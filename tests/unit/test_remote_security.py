import io
import json
import os
import tarfile
import uuid

import pytest

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote.files import copy_tree, extract_archive, walk_checked
from vaultrewind.remote.journal import Journal, Locks, resource_keys
from vaultrewind.remote.policy import clean_absolute, root_trusted
from vaultrewind.remote.protocol import Request, decode, receive_frames, send_frames


def req(verb="capture", op=None, fence=1, **payload):
    return Request.parse({"schema_version": 1, "instance_id": "11111111-1111-4111-8111-111111111111",
                          "operation_id": op or str(uuid.uuid4()), "fencing_token": fence,
                          "idempotency_key": "test:" + verb, "verb": verb, "payload": payload})


@pytest.mark.parametrize("value", ["/", "/etc", "/srv/../etc/passwd", "relative", "/srv//vault", "/srv/vault/", "/srv/\x00"])
def test_policy_paths_reject_traversal(value):
    with pytest.raises(VaultRewindError):
        clean_absolute(value)


def test_json_rejects_duplicate_fields_nan_and_oversized():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"[]", b"x" * (1024 * 1024 + 1)):
        with pytest.raises(VaultRewindError):
            decode(raw)


@pytest.mark.parametrize("token", [True, 0, -1, 2**63, 1.5])
def test_protocol_rejects_invalid_fence(token):
    with pytest.raises(VaultRewindError):
        req(fence=token)


def test_protocol_does_not_accept_shell_in_identity():
    value = json.loads(json.dumps({"schema_version": 1, "instance_id": "$(touch /tmp/unsafe)",
                                   "operation_id": str(uuid.uuid4()), "fencing_token": 1,
                                   "idempotency_key": "shell;id", "verb": "capture", "payload": {}}))
    with pytest.raises(VaultRewindError):
        Request.parse(value)


def test_root_policy_ancestor_permissions_are_enforced(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{}")
    path.chmod(0o666)
    with pytest.raises(VaultRewindError, match="root-owned"):
        root_trusted(path)


def archive_at(path, members):
    with tarfile.open(path, "w") as tar:
        for name, kind, link in members:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.linkname = link
            entry.size = 1 if kind == tarfile.REGTYPE else 0
            tar.addfile(entry, io.BytesIO(b"x") if entry.size else None)


@pytest.mark.parametrize("members", [
    [("../escape", tarfile.REGTYPE, "")],
    [("/etc/passwd", tarfile.REGTYPE, "")],
    [("data", tarfile.SYMTYPE, "/etc"), ("data/passwd", tarfile.REGTYPE, "")],
    [("data", tarfile.DIRTYPE, ""), ("data/x", tarfile.SYMTYPE, "../../etc/passwd")],
    [("data", tarfile.DIRTYPE, ""), ("data/x", tarfile.LNKTYPE, "etc/passwd")],
    [("data", tarfile.DIRTYPE, ""), ("data/x", tarfile.FIFOTYPE, "")],
    [("data", tarfile.DIRTYPE, ""), ("data/x", tarfile.REGTYPE, ""), ("data/x", tarfile.REGTYPE, "")],
])
def test_archive_validation_finishes_before_writing(tmp_path, members):
    archive = tmp_path / "input.tar"
    archive_at(archive, members)
    output = tmp_path / "out"
    with pytest.raises(VaultRewindError):
        extract_archive(archive, output, 1024**2, 100)
    assert not output.exists()


def test_framed_transport_detects_truncation_corruption_and_bounds():
    data = b"abc" * 900000
    wire = io.BytesIO()
    result = send_frames(io.BytesIO(data), wire, len(data))
    recovered = io.BytesIO()
    assert receive_frames(io.BytesIO(wire.getvalue()), recovered, len(data)) == result
    assert recovered.getvalue() == data
    for broken in (wire.getvalue()[:-20], wire.getvalue()[:20] + b"!" + wire.getvalue()[21:]):
        with pytest.raises(VaultRewindError):
            receive_frames(io.BytesIO(broken), io.BytesIO(), len(data))
    with pytest.raises(VaultRewindError):
        receive_frames(io.BytesIO(wire.getvalue()), io.BytesIO(), 100)


def test_copy_preserves_private_unknown_files_metadata_and_internal_links(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    (source / "empty").mkdir()
    private = source / ".unknown Unicode λ"
    private.write_bytes(b"synthetic-secret")
    private.chmod(0o600)
    os.setxattr(private, "user.test", b"metadata")
    os.link(private, source / "second")
    (source / "sym").symlink_to(private.name)
    copy_tree(source, target)
    assert (target / private.name).read_bytes() == b"synthetic-secret"
    assert (target / private.name).stat().st_mode & 0o777 == 0o600
    assert os.getxattr(target / private.name, "user.test") == b"metadata"
    assert os.path.samefile(target / private.name, target / "second")
    assert (target / "sym").is_symlink()
    assert (target / "empty").is_dir()
    assert private.stat().st_mode & 0o777 == 0o600


def test_copy_rejects_external_symlink_hardlink_fifo_and_capability(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("private")
    (source / "link").symlink_to(outside)
    with pytest.raises(VaultRewindError):
        walk_checked(source)
    (source / "link").unlink()
    os.link(outside, source / "link")
    with pytest.raises(VaultRewindError, match="Hard links"):
        walk_checked(source)
    (source / "link").unlink()
    os.mkfifo(source / "fifo")
    with pytest.raises(VaultRewindError, match="FIFO"):
        walk_checked(source)


def test_physical_identity_duplicates_and_partial_overlap(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    mounts = [{"type": "bind", "source": str(one)}]
    a = resource_keys("machine", "daemon", mounts)
    b = resource_keys("machine", "daemon", [*mounts, {"type": "bind", "source": str(two)}])
    assert set(a) & set(b)
    assert a == resource_keys("machine", "daemon", mounts)


def test_fencing_and_unfinished_operation_cannot_be_superseded(tmp_path):
    root = tmp_path
    first = req(fence=10)
    with Locks(root, ["physical"]) as lock:
        lock.fence(first)
        journal = Journal(root, first.operation_id)
        journal.create(first, ["physical"])
    with Locks(root, ["physical"]) as lock:
        with pytest.raises(VaultRewindError, match="stale"):
            lock.fence(req(op=first.operation_id, fence=9))
        with pytest.raises(VaultRewindError, match="Reconcile"):
            lock.fence(req(fence=11))
    journal.transition("captured")
    with Locks(root, ["physical"]) as lock:
        lock.fence(req(fence=11))


def test_os_flock_blocks_overlapping_worker(tmp_path):
    with Locks(tmp_path, ["a"]), pytest.raises(VaultRewindError, match="owns"), Locks(tmp_path, ["b"]):
        pass


def test_journal_idempotency_and_corruption(tmp_path):
    request = req(value=1)
    journal = Journal(tmp_path, request.operation_id)
    journal.create(request, ["physical"])
    journal.remember(request, {"done": True})
    assert Journal(tmp_path, request.operation_id).cached(request) == {"done": True}
    with pytest.raises(VaultRewindError, match="different"):
        journal.cached(req(op=request.operation_id, value=2))
    journal.path.write_text('{"partial":')
    with pytest.raises(VaultRewindError):
        Journal(tmp_path, request.operation_id)


def test_systemd_preflight_inspects_a_concrete_template_instance(monkeypatch):
    from types import SimpleNamespace

    from vaultrewind.remote.recovery import SystemdRecovery
    calls = []
    def systemctl(args, *, check=True):
        calls.append(args)
        assert "vaultrewind-watchdog@.service" not in args
        return SimpleNamespace(returncode=0, stdout=b"loaded\n")
    monkeypatch.setattr(SystemdRecovery, "_run", staticmethod(systemctl))
    SystemdRecovery().verify()
    assert any(args[:2] == ["show", "vaultrewind-watchdog@00000000-0000-4000-8000-000000000000.service"] for args in calls)


@pytest.mark.parametrize("health_status,expected", [("starting", True), ("healthy", True), ("unhealthy", False)])
def test_direct_http_readiness_accepts_starting_but_never_unhealthy(health_status, expected, monkeypatch):
    from vaultrewind.remote.docker import Docker
    docker = Docker()
    monkeypatch.setattr(docker, "inspect", lambda _: {"State": {"Running": True, "Health": {"Status": health_status}}})
    def api(method, path, *args, **kwargs):
        if path.endswith("/exec"):
            return {"Id": "synthetic-exec"}
        if path.endswith("/json"):
            return {"ExitCode": 0, "Running": False}
        return None
    monkeypatch.setattr(docker, "api", api)
    if expected:
        assert docker.health("a" * 64, 1)["internal_http_alive"] is True
    else:
        with pytest.raises(VaultRewindError, match="readiness"):
            docker.health("a" * 64, 0.01)


def test_compose_dependency_graph_requires_includes_environment_and_secret_files(tmp_path):
    from types import SimpleNamespace

    from vaultrewind.remote.dependencies import validate_compose_dependencies
    compose = tmp_path / "compose.yml"
    include = tmp_path / "included.yml"
    environment = tmp_path / ".env.instance"
    secret = tmp_path / "secret.txt"
    compose.write_text("include: [included.yml]\nservices:\n  app:\n    env_file: .env.instance\nsecrets:\n  signing:\n    file: secret.txt\n")
    include.write_text("services: {}\n")
    environment.write_text("SYNTHETIC=true\n")
    secret.write_text("synthetic-secret\n")
    labels = {"com.docker.compose.project.config_files": str(compose)}
    enrolled = SimpleNamespace(value={"additional_files": {"compose.yml": str(compose)}})
    with pytest.raises(VaultRewindError, match="Enroll every"):
        validate_compose_dependencies(labels, enrolled)
    enrolled.value["additional_files"] = {p.name: str(p) for p in (compose, include, environment, secret)}
    validate_compose_dependencies(labels, enrolled)


def test_reserved_request_key_is_bound_before_side_effects(tmp_path):
    request = req(value=1)
    journal = Journal(tmp_path, request.operation_id)
    journal.create(request, ["physical"])
    journal.reserve(request)
    with pytest.raises(VaultRewindError, match="different"):
        Journal(tmp_path, request.operation_id).reserve(req(op=request.operation_id, value=2))


def test_readiness_rechecks_running_after_http_probe(monkeypatch):
    from vaultrewind.remote.docker import Docker
    docker = Docker()
    states = iter([{'State': {'Running': True}}, {'State': {'Running': False}}])
    monkeypatch.setattr(docker, 'inspect', lambda _: next(states))
    def api(method, path, *args, **kwargs):
        if path.endswith('/exec'):
            return {'Id': 'synthetic-exec'}
        if path.endswith('/json'):
            return {'ExitCode': 0, 'Running': False}
        return None
    monkeypatch.setattr(docker, 'api', api)
    with pytest.raises(VaultRewindError) as error:
        docker.health('a' * 64, 1)
    assert error.value.code == 'APPLICATION_START_FAILED'

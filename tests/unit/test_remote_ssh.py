import hashlib
import io
import struct
import uuid

import asyncssh
import pytest

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote.protocol import MAGIC, canonical, decode, send_frames
from vaultrewind.remote.ssh import HELPER_COMMAND, SSHRemote


class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


@pytest.fixture
async def ssh_fixture():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    commands, requests = [], []
    content = b"synthetic archive bytes" * 100000
    async def process(proc):
        commands.append(proc.command)
        raw = await proc.stdin.readline()
        request = decode(raw)
        requests.append(request)
        failure = request["payload"].get("fixture_failure")
        if failure:
            if failure == "stall":
                await proc.wait_closed()
                return
            if failure == "truncated":
                proc.stdout.write(b'{"ok":')
            elif failure == "structured":
                proc.stdout.write(canonical({"ok": False, "error": {"code": "STALE_FENCE", "message": "Worker lease is stale.", "retryable": False}}))
            proc.exit(137 if failure == "empty" else 1)
            return
        if request["verb"] == "export":
            wire = io.BytesIO()
            send_frames(io.BytesIO(content), wire, len(content))
            proc.stdout.write(wire.getvalue())
        elif request["verb"] == "stage_restore":
            assert await proc.stdin.readexactly(len(MAGIC)) == MAGIC
            sha, size = hashlib.sha256(), 0
            while True:
                length = struct.unpack("!I", await proc.stdin.readexactly(4))[0]
                if length == 0:
                    break
                block = await proc.stdin.readexactly(length)
                sha.update(block)
                size += length
            length = struct.unpack("!I", await proc.stdin.readexactly(4))[0]
            trailer = decode(await proc.stdin.readexactly(length))
            assert trailer == {"bytes": size, "sha256": sha.hexdigest()}
            proc.stdout.write(canonical({"ok": True, "result": {"phase": "staged"}}))
        else:
            proc.stdout.write(canonical({"ok": True, "result": {"phase": "captured"}}))
        proc.exit(0)
    server = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[host_key],
                                         process_factory=process, encoding=None)
    config = {"endpoint": "127.0.0.1", "port": server.get_port(), "username": "synthetic",
              "host_public_key": host_key.export_public_key().decode(),
              "private_key": client_key.export_private_key().decode(), "request_timeout": 10}
    try:
        yield config, commands, requests, content
    finally:
        server.close()
        await server.wait_closed()


async def test_pinned_ssh_uses_fixed_command_even_with_shell_metacharacters_in_payload(ssh_fixture):
    config, commands, requests, _ = ssh_fixture
    remote = SSHRemote(config)
    result = await remote.request("status", str(uuid.uuid4()), str(uuid.uuid4()), 1,
                                  {"untrusted": "$(touch /root/pwned); cat /etc/shadow"})
    assert result == {"phase": "captured"}
    assert commands == [HELPER_COMMAND]
    assert requests[0]["payload"]["untrusted"].startswith("$(touch")


async def test_changed_ssh_host_key_blocks_before_helper_execution(ssh_fixture):
    config, commands, _, _ = ssh_fixture
    config["host_public_key"] = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
    with pytest.raises(VaultRewindError) as error:
        await SSHRemote(config).request("status", str(uuid.uuid4()), str(uuid.uuid4()), 1)
    assert error.value.code == "SSH_HOST_KEY_CHANGED"
    assert commands == []


async def test_real_ssh_export_and_upload_are_bounded_framed_streams(ssh_fixture, tmp_path):
    config, commands, requests, content = ssh_fixture
    remote = SSHRemote(config)
    path = tmp_path / "export.tar"
    result = await remote.export(str(uuid.uuid4()), str(uuid.uuid4()), 1, path)
    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    assert path.read_bytes() == content
    assert path.stat().st_mode & 0o777 == 0o600
    staged = await remote.upload_restore(str(uuid.uuid4()), str(uuid.uuid4()), 2, path, {"manifest_hash": "a" * 64})
    assert staged["phase"] == "staged"
    assert requests[-1]["payload"]["archive_bytes"] == len(content)
    assert commands == [HELPER_COMMAND, HELPER_COMMAND]


async def test_over_limit_ssh_export_leaves_no_partial_file(ssh_fixture, tmp_path):
    config, _, _, _ = ssh_fixture
    config["max_archive_bytes"] = 100
    target = tmp_path / "archive.tar"
    with pytest.raises(VaultRewindError, match="limits"):
        await SSHRemote(config).export(str(uuid.uuid4()), str(uuid.uuid4()), 1, target)
    assert not target.exists()
    assert not target.with_name("archive.tar.partial").exists()


@pytest.mark.parametrize("failure", ["empty", "truncated"])
async def test_empty_or_truncated_helper_exit_requires_reconciliation(ssh_fixture, failure):
    config, _, _, _ = ssh_fixture
    with pytest.raises(VaultRewindError) as error:
        await SSHRemote(config).request("status", str(uuid.uuid4()), str(uuid.uuid4()), 1,
                                        {"fixture_failure": failure})
    assert error.value.code == "REMOTE_OUTCOME_UNCERTAIN"
    assert error.value.retryable is True
    assert "reconcile" in error.value.message


async def test_structured_helper_rejection_preserves_actionable_nonretryable_error(ssh_fixture):
    config, _, _, _ = ssh_fixture
    with pytest.raises(VaultRewindError) as error:
        await SSHRemote(config).request("status", str(uuid.uuid4()), str(uuid.uuid4()), 1,
                                        {"fixture_failure": "structured"})
    assert error.value.code == "STALE_FENCE"
    assert error.value.retryable is False


@pytest.mark.parametrize("verb", ["request", "export", "upload_restore"])
async def test_request_deadline_is_retryable_transport_uncertainty(ssh_fixture, tmp_path, verb):
    config, _, _, _ = ssh_fixture
    config['request_timeout'] = 1
    remote = SSHRemote(config)
    args = [str(uuid.uuid4()), str(uuid.uuid4()), 1]
    path = tmp_path / 'snapshot.tar'
    if verb == 'upload_restore':
        path.write_bytes(b'synthetic')
    with pytest.raises(VaultRewindError) as error:
        if verb == 'request':
            await remote.request('status', *args, {'fixture_failure': 'stall'})
        else:
            await getattr(remote, verb)(*args, path, {'fixture_failure': 'stall'})
    assert error.value.code == 'SSH_TRANSPORT_FAILED' and error.value.retryable
    assert not path.with_name('snapshot.tar.partial').exists()


@pytest.mark.parametrize('failure', ['empty', 'truncated'])
async def test_failed_export_before_frames_is_retryable(ssh_fixture, tmp_path, failure):
    config, _, _, _ = ssh_fixture
    with pytest.raises(VaultRewindError) as error:
        await SSHRemote(config).export(str(uuid.uuid4()), str(uuid.uuid4()), 1, tmp_path / 'capture.tar',
                                       {'fixture_failure': failure})
    assert error.value.code in ('SSH_TRANSPORT_FAILED', 'REMOTE_OUTCOME_UNCERTAIN')
    assert error.value.retryable

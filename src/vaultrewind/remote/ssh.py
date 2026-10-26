"""Pinned AsyncSSH controller adapter. Only one constant remote command is executed."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import struct
from pathlib import Path

import asyncssh

from vaultrewind.core.errors import VaultRewindError, safe_transport_details

from .journal import fsync_directory
from .protocol import MAGIC, MAX_FRAME, MAX_JSON, Request, canonical, decode, fail

HELPER_COMMAND = "sudo -n -- /usr/local/libexec/vaultrewind-helper"


class SSHRemote:
    def __init__(self, config: dict):
        self.config = config
        self.max_bytes = int(config.get("max_archive_bytes", 1024**4))
        self.timeout = int(config.get("request_timeout", 7200))
        if not config.get("host_public_key") or not config.get("private_key"):
            fail("SSH_CONFIGURATION", "An explicitly verified host public key and private key are required.")

    def _request(self, verb, instance_id, operation_id, fencing_token, payload):
        payload = dict(payload or {})
        key = payload.pop("idempotency_key", None) or f"{operation_id}:{verb}:{payload.get('phase', payload.get('kind', 'default'))}"
        value = {"schema_version": 1, "verb": verb, "instance_id": instance_id,
                 "operation_id": operation_id, "fencing_token": fencing_token,
                 "idempotency_key": key, "payload": payload}
        Request.parse(value)
        raw = canonical(value) + b"\n"
        if len(raw) > MAX_JSON:
            fail("PROTOCOL_LIMIT", "Helper request exceeds the protocol limit.")
        return raw

    @contextlib.asynccontextmanager
    async def _connection(self):
        try:
            pinned = asyncssh.import_public_key(self.config["host_public_key"])
            private = asyncssh.import_private_key(self.config["private_key"], self.config.get("passphrase"))
            async with asyncssh.connect(
                    self.config["endpoint"], port=int(self.config.get("port", 22)),
                    username=self.config["username"], client_keys=[private],
                    known_hosts=([pinned], [], []), agent_path=None, agent_forwarding=False,
                    config=[], preferred_auth=["publickey"], password=None,
                    connect_timeout=20, login_timeout=20, keepalive_interval=15, keepalive_count_max=3) as conn:
                yield conn
        except asyncssh.HostKeyNotVerifiable:
            raise VaultRewindError("SSH_HOST_KEY_CHANGED", "SSH host key does not match the verified enrollment key.") from None
        except (TimeoutError, asyncssh.Error, OSError):
            raise VaultRewindError("SSH_TRANSPORT_FAILED", "SSH failed; reconcile the remote journal before retrying.", retryable=True) from None
        except (ValueError, TypeError):
            raise VaultRewindError("SSH_CONFIGURATION", "SSH key or endpoint configuration is invalid.") from None

    async def _response(self, process):
        output = bytearray()
        while chunk := await process.stdout.read(65536):
            output.extend(chunk)
            if len(output) > MAX_JSON:
                fail("PROTOCOL_LIMIT", "Helper response exceeds the JSON limit.")
        await process.wait_closed()
        try:
            result = decode(bytes(output))
        except VaultRewindError:
            raise VaultRewindError("REMOTE_OUTCOME_UNCERTAIN", "Helper response was empty or incomplete; reconcile the remote operation journal before retrying.", retryable=True) from None
        if not result.get("ok"):
            err = result.get("error", {})
            raise VaultRewindError(err.get("code", "REMOTE_FAILED"), err.get("message", "Remote helper failed."),
                                   retryable=bool(err.get("retryable")), **safe_transport_details(err.get("details")))
        if process.exit_status != 0:
            raise VaultRewindError("REMOTE_OUTCOME_UNCERTAIN", "Helper exited unsuccessfully; reconcile its journal before retrying.", retryable=True)
        return result["result"]

    async def request(self, verb, instance_id, operation_id, fencing_token, payload=None):
        if verb in ("export", "stage_restore"):
            fail("PROTOCOL_INVALID", "Use the streaming adapter method for archive operations.")
        request = self._request(verb, instance_id, operation_id, fencing_token, payload)
        async with self._connection() as conn, asyncio.timeout(self.timeout):  # noqa: SIM117 -- separate transport and process lifetimes
            async with conn.create_process(HELPER_COMMAND, encoding=None, stderr=asyncssh.DEVNULL) as process:
                process.stdin.write(request)
                process.stdin.write_eof()
                return await self._response(process)

    async def export(self, instance_id, operation_id, fencing_token, target: Path, payload=None):
        request = self._request("export", instance_id, operation_id, fencing_token, payload)
        target = Path(target)
        temporary = target.with_name(target.name + ".partial")
        if target.exists():
            fail("STAGING_CONFLICT", "Export destination already exists.")
        try:
            async with self._connection() as conn, asyncio.timeout(self.timeout):  # noqa: SIM117 -- separate transport and process lifetimes
                async with conn.create_process(HELPER_COMMAND, encoding=None, stderr=asyncssh.DEVNULL) as process:
                    process.stdin.write(request)
                    process.stdin.write_eof()
                    header = await process.stdout.readexactly(len(MAGIC))
                    if header != MAGIC:
                        # Structured pre-stream failure; bounded read, never echo raw stderr.
                        raw = header + await process.stdout.read(MAX_JSON - len(header) + 1)
                        try:
                            err = decode(raw).get("error", {})
                        except VaultRewindError:
                            raise VaultRewindError("REMOTE_OUTCOME_UNCERTAIN", "Export reply was incomplete; reconcile the remote journal.", retryable=True) from None
                        raise VaultRewindError(err.get("code", "PROTOCOL_INVALID"), err.get("message", "Invalid export response."), retryable=bool(err.get("retryable")))
                    count, sha = 0, hashlib.sha256()
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        while True:
                            length = struct.unpack("!I", await process.stdout.readexactly(4))[0]
                            if length == 0:
                                break
                            if length > MAX_FRAME or count + length > self.max_bytes:
                                fail("TRANSFER_LIMIT", "Remote archive exceeds transfer limits.")
                            block = await process.stdout.readexactly(length)
                            stream.write(block)
                            sha.update(block)
                            count += length
                        length = struct.unpack("!I", await process.stdout.readexactly(4))[0]
                        if length > 1024:
                            fail("PROTOCOL_LIMIT", "Invalid export trailer.")
                        trailer = decode(await process.stdout.readexactly(length), 1024)
                        if trailer != {"bytes": count, "sha256": sha.hexdigest()}:
                            fail("TRANSFER_CHECKSUM", "Export archive checksum mismatch.")
                        if await process.stdout.read(1):
                            fail("PROTOCOL_INVALID", "Unexpected trailing export bytes.")
                        await process.wait_closed()
                        if process.exit_status != 0:
                            raise VaultRewindError("REMOTE_OUTCOME_UNCERTAIN", "Remote export exited unsuccessfully; reconcile its journal.", retryable=True)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, target)
                    fsync_directory(target.parent)
                    return trailer
        except asyncio.IncompleteReadError:
            raise VaultRewindError("SSH_TRANSPORT_FAILED", "Remote archive transfer was interrupted; reconcile its journal.", retryable=True) from None
        finally:
            temporary.unlink(missing_ok=True)

    async def upload_restore(self, instance_id, operation_id, fencing_token, archive: Path, payload=None):
        archive = Path(archive)
        from .files import file_hash
        archive_hash = await asyncio.to_thread(file_hash, archive)
        size = archive.stat().st_size
        if size > self.max_bytes:
            fail("TRANSFER_LIMIT", "Restore archive exceeds transfer limits.")
        payload = {**(payload or {}), "archive_bytes": size, "archive_sha256": archive_hash}
        request = self._request("stage_restore", instance_id, operation_id, fencing_token, payload)
        async with self._connection() as conn, asyncio.timeout(self.timeout):  # noqa: SIM117 -- separate transport and process lifetimes
            async with conn.create_process(HELPER_COMMAND, encoding=None, stderr=asyncssh.DEVNULL) as process:
                process.stdin.write(request + MAGIC)
                stream = await asyncio.to_thread(archive.open, "rb")
                try:
                    while block := await asyncio.to_thread(stream.read, MAX_FRAME):
                        process.stdin.write(struct.pack("!I", len(block)) + block)
                        await process.stdin.drain()
                finally:
                    await asyncio.to_thread(stream.close)
                trailer = canonical({"bytes": size, "sha256": archive_hash})
                process.stdin.write(struct.pack("!II", 0, len(trailer)) + trailer)
                process.stdin.write_eof()
                return await self._response(process)

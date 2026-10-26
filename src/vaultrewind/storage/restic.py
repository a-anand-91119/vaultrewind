"""Standard encrypted restic repositories (restic >= 0.18; pinned 0.19.1).

Every invocation runs with a freshly built environment (nothing inherited from
the controller), the repository password in an owner-only temporary file
(``RESTIC_PASSWORD_FILE``), provider credentials only through the validated
environment allowlist, and ``--json`` machine output.  Subprocess output is
parsed in memory and never persisted; only sanitized codes leave this module.

A copy is reported committed only when restic exited 0 with no read errors or
warnings, the snapshot is rediscoverable by its VaultRewind UUID tag, the stored
manifest reads back with the expected canonical hash, and the stored tree
contains exactly the manifest inventory (types and sizes).  restic exit 3
(partial) still writes a snapshot; such snapshots are discarded by exact ID.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.core.manifest import manifest_hash
from vaultrewind.security.privatefiles import private_workspace, write_private_file
from vaultrewind.security.redaction import register_secret

from . import layout
from .errors import (
    EXIT_CANCELLED,
    EXIT_NO_REPOSITORY,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_WRONG_PASSWORD,
    restic_failure,
)

MIN_RESTIC_VERSION = (0, 18, 0)
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
MAX_MANIFEST_BYTES = 256 * 1024 * 1024

ALLOWED_ENVIRONMENT = frozenset({
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION",
    "RESTIC_PACK_SIZE", "RESTIC_COMPRESSION", "RESTIC_READ_CONCURRENCY", "RCLONE_BWLIMIT",
})
ALLOWED_OPTIONS = frozenset({"s3.bucket-lookup", "s3.region", "s3.storage-class", "s3.connections",
                             "rclone.timeout", "rclone.connections"})
DEFAULT_TIMEOUTS = {"probe": 300, "init": 600, "list": 600, "commit": 12 * 3600, "verify": 3600,
                    "restore": 12 * 3600, "check": 48 * 3600, "forget": 1800, "prune": 12 * 3600, "keys": 600}

_RCLONE_LOCATION = re.compile(r"^rclone:([A-Za-z0-9_-]{1,64}):([A-Za-z0-9._/-]{0,512})$")
_S3_LOCATION = re.compile(r"^s3:(https?)://([A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(:[0-9]{1,5})?/"
                          r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(/[A-Za-z0-9._/-]{0,900})?$")
_VERSION_CACHE: dict[str, tuple[int, int, int]] = {}
# rclone (started by restic for rclone repositories) logs "YYYY/MM/DD HH:MM:SS LEVEL : ..." to the same stderr.
_RCLONE_LOG_LINE = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (DEBUG|INFO|NOTICE|ERROR|CRITICAL)\s*:")


def utc_iso(moment: datetime | None = None) -> str:
    return (moment or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    """Parse RFC 3339 / ISO 8601 (including Go nanosecond fractions) into aware UTC."""
    if not isinstance(value, str) or not value:
        raise VaultRewindError("TIMESTAMP_INVALID", "A timestamp is missing or malformed.")
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})?", text)
    if not match:
        raise VaultRewindError("TIMESTAMP_INVALID", "A timestamp is missing or malformed.")
    base, fraction, offset = match.groups()
    rebuilt = base.replace(" ", "T") + ((fraction[:7]) if fraction else "") + (offset or "")
    try:
        moment = datetime.fromisoformat(rebuilt)
    except ValueError as exc:
        raise VaultRewindError("TIMESTAMP_INVALID", "A timestamp is missing or malformed.") from exc
    if moment.tzinfo is None:
        raise VaultRewindError("TIMESTAMP_INVALID", "Timestamps must carry an explicit UTC offset.")
    return moment.astimezone(UTC)


def _version_tuple(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", text)
    return tuple(int(part) for part in match.groups()) if match else None  # type: ignore[return-value]


def resolve_binary(name: str, what: str) -> str:
    candidate = name if os.path.isabs(name) else shutil.which(name, path=SAFE_PATH)
    if not candidate or not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
        raise VaultRewindError(f"{what.upper()}_UNAVAILABLE", f"The pinned {what} binary is not installed.")
    return os.path.realpath(candidate)


@dataclass
class RepositoryConfig:
    """Contract fields first (location, password, environment, cache_dir, rclone_config)."""

    location: str
    password: str = field(repr=False)
    environment: dict[str, str] = field(default_factory=dict, repr=False)
    cache_dir: Path | None = None
    rclone_config: Path | None = None
    instance_uuid: str | None = None
    expected_repository_id: str | None = None
    ca_cert_pem: str | None = field(default=None, repr=False)
    options: tuple[str, ...] = ()
    restic_binary: str = "restic"
    rclone_binary: str = "rclone"
    runtime_dir: Path | None = None
    temp_dir: Path | None = None
    allow_insecure_http: bool = False
    lock_wait: str = "2m"
    timeouts: dict[str, float] = field(default_factory=dict)
    read_only: bool = False

    def __post_init__(self):
        if not isinstance(self.password, str) or not self.password or any(c in self.password for c in "\r\n\x00"):
            raise VaultRewindError("REPOSITORY_SECRET_INVALID", "The repository unlock secret is malformed.")
        register_secret(self.password)
        self.backend = self._validate_location()
        for key, value in self.environment.items():
            if key not in ALLOWED_ENVIRONMENT or not isinstance(value, str) or "\x00" in value:
                raise VaultRewindError("STORAGE_ENVIRONMENT_INVALID",
                                       "A storage environment setting is not permitted.")
            if key in ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
                register_secret(value)
        options = []
        for option in self.options:
            key, sep, value = option.partition("=")
            if not sep or key not in ALLOWED_OPTIONS or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
                raise VaultRewindError("STORAGE_OPTION_INVALID", "A storage backend option is not permitted.")
            if key.startswith("s3.") and self.backend != "s3" or key.startswith("rclone.") and self.backend != "rclone":
                raise VaultRewindError("STORAGE_OPTION_INVALID", "A backend option does not match the repository type.")
            options.append(option)
        self.options = tuple(options)
        if self.ca_cert_pem is not None and (self.backend != "s3" or "-----BEGIN CERTIFICATE-----"
                                             not in self.ca_cert_pem):
            raise VaultRewindError("STORAGE_CA_INVALID", "A custom CA certificate applies only to S3 PEM bundles.")
        if self.instance_uuid is not None:
            self.instance_uuid = layout.canonical_uuid(self.instance_uuid, "instance UUID")
        if self.expected_repository_id is not None and not re.fullmatch(r"[0-9a-f]{64}", self.expected_repository_id):
            raise VaultRewindError("REPOSITORY_ID_INVALID", "The recorded repository ID is malformed.")
        if not re.fullmatch(r"\d{1,4}[smh]", self.lock_wait):
            raise VaultRewindError("STORAGE_OPTION_INVALID", "Invalid repository lock wait.")

    def _validate_location(self) -> str:
        location = self.location
        if not isinstance(location, str) or any(ord(c) < 32 for c in location):
            raise VaultRewindError("REPOSITORY_LOCATION_INVALID", "The repository location is malformed.")
        if location.startswith("/"):
            path = PurePosixPath(location)
            if ".." in path.parts or str(path) != location or len(path.parts) < 3:
                raise VaultRewindError("REPOSITORY_LOCATION_INVALID", "Local repositories need a normalized absolute path.")
            if self.rclone_config is not None:
                raise VaultRewindError("REPOSITORY_LOCATION_INVALID", "rclone configuration applies only to rclone repositories.")
            return "local"
        match = _S3_LOCATION.fullmatch(location)
        if match:
            scheme = match.group(1)
            if scheme == "http" and not self.allow_insecure_http:
                raise VaultRewindError("STORAGE_TLS_REQUIRED", "S3 repositories require verified HTTPS.")
            if ".." in location.split("/"):
                raise VaultRewindError("REPOSITORY_LOCATION_INVALID", "The S3 repository prefix is unsafe.")
            return "s3"
        match = _RCLONE_LOCATION.fullmatch(location)
        if match:
            if ".." in match.group(2).split("/"):
                raise VaultRewindError("REPOSITORY_LOCATION_INVALID", "The rclone repository path is unsafe.")
            if self.rclone_config is None:
                raise VaultRewindError("RCLONE_CONFIG_REQUIRED", "rclone repositories need a private writable configuration.")
            return "rclone"
        raise VaultRewindError("REPOSITORY_BACKEND_UNSUPPORTED",
                               "Only local, S3-compatible and rclone (Google Drive) repositories are supported.")


@dataclass
class _Result:
    exit_code: int
    stdout: bytes
    stderr: str
    error_messages: int
    warnings: int


class ResticRepository:
    def __init__(self, config: RepositoryConfig, *, cancel_event: threading.Event | None = None):
        self.config = config
        self.cancel_event = cancel_event
        self._restic = resolve_binary(config.restic_binary, "restic")
        self._rclone = resolve_binary(config.rclone_binary, "rclone") if config.backend == "rclone" else None
        self.repository_id: str | None = config.expected_repository_id
        self._check_version()

    def __repr__(self) -> str:
        return f"ResticRepository(backend={self.config.backend!r})"

    # ------------------------------------------------------------------ process plumbing
    def _check_version(self) -> None:
        version = _VERSION_CACHE.get(self._restic)
        if version is None:
            try:
                output = subprocess.run([self._restic, "version"], capture_output=True, text=True, timeout=30,
                                        env={"PATH": SAFE_PATH, "HOME": tempfile.gettempdir()}, check=False).stdout
            except (OSError, subprocess.SubprocessError) as exc:
                raise VaultRewindError("RESTIC_UNAVAILABLE", "The pinned restic binary could not be executed.") from exc
            version = _version_tuple(output or "")
            if version is None:
                raise VaultRewindError("RESTIC_UNAVAILABLE", "The restic version could not be determined.")
            _VERSION_CACHE[self._restic] = version
        if version < MIN_RESTIC_VERSION:
            raise VaultRewindError("RESTIC_VERSION_UNSUPPORTED", "The installed restic version is older than supported.")
        self.restic_version = ".".join(map(str, version))

    def _timeout(self, operation: str) -> float:
        return float(self.config.timeouts.get(operation, DEFAULT_TIMEOUTS.get(operation, 3600)))

    def _environment(self, workspace: Path, extra_password: str | None = None) -> dict[str, str]:
        config = self.config
        password_file = write_private_file(workspace / "repository-password", config.password)
        env = {
            "PATH": SAFE_PATH, "HOME": str(workspace), "TZ": "UTC", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
            "TMPDIR": str(config.temp_dir or tempfile.gettempdir()),
            "XDG_CACHE_HOME": str(workspace / "xdg-cache"), "XDG_CONFIG_HOME": str(workspace / "xdg-config"),
            "RESTIC_PASSWORD_FILE": str(password_file), "RESTIC_REPOSITORY": config.location,
            "RESTIC_PROGRESS_FPS": "0.2",
        }
        if config.cache_dir is not None:
            cache = Path(config.cache_dir)
            cache.mkdir(mode=0o700, parents=True, exist_ok=True)
            if cache.stat().st_mode & 0o077:
                os.chmod(cache, 0o700)
            env["RESTIC_CACHE_DIR"] = str(cache)
        if config.ca_cert_pem:
            env["RESTIC_CACERT"] = str(write_private_file(workspace / "ca.pem", config.ca_cert_pem))
        if config.rclone_config is not None:
            env["RCLONE_CONFIG"] = str(config.rclone_config)
            env["RCLONE_LOG_LEVEL"] = "ERROR"
        env.update(config.environment)
        return env

    def _command(self, args: list[str]) -> list[str]:
        command = [self._restic, "--json", "--retry-lock", self.config.lock_wait]
        if self.config.read_only:
            command.append("--no-lock")
        if self.config.cache_dir is None:
            command.append("--no-cache")
        for option in self.config.options:
            command += ["-o", option]
        if self._rclone:
            command += ["-o", f"rclone.program={self._rclone}"]
        return command + args

    def _execute(self, args: list[str], operation: str, *, cwd: Path | None = None,
                 stdout_line: Callable[[dict], None] | None = None, max_stdout: int = MAX_MANIFEST_BYTES,
                 prepare: Callable[[Path, dict], list[str]] | None = None) -> _Result:
        if self.config.read_only and (prepare is not None or not args or
                args[0] not in {"cat", "dump", "snapshots", "ls", "restore", "check", "stats"}
                and args[:2] != ["key", "list"]):
            self._require_writable()
        with private_workspace(self.config.runtime_dir, prefix="vaultrewind-restic-") as workspace:
            env = self._environment(workspace)
            final_args = prepare(workspace, env) if prepare else args
            try:
                process = subprocess.Popen(self._command(final_args), cwd=str(cwd or workspace), env=env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True, close_fds=True)
            except OSError as exc:
                raise VaultRewindError("RESTIC_UNAVAILABLE", "The restic process could not be started.") from exc
            stdout_chunks: list[bytes] = []
            stderr_tail: list[str] = []
            counters = {"stdout": 0, "errors": 0, "warnings": 0, "overflow": False}

            def read_stdout():
                assert process.stdout is not None
                for raw in process.stdout:
                    if stdout_line is not None:
                        try:
                            message = json.loads(raw)
                        except ValueError:
                            continue
                        if isinstance(message, dict):
                            stdout_line(message)
                        continue
                    counters["stdout"] += len(raw)
                    if counters["stdout"] > max_stdout:
                        counters["overflow"] = True
                        self._signal(process, signal.SIGTERM)
                        break
                    stdout_chunks.append(raw)

            def read_stderr():
                assert process.stderr is not None
                kept = 0
                for raw in process.stderr:
                    line = raw.decode("utf-8", "replace")
                    try:
                        message = json.loads(line)
                    except ValueError:
                        message = None
                    if isinstance(message, dict):
                        kind = message.get("message_type")
                        if kind == "error":
                            counters["errors"] += 1
                        elif kind != "exit_error":
                            counters["warnings"] += 1
                        text = json.dumps(message.get("error") or message.get("message") or "")
                    else:
                        text = line
                        transport_log = self._rclone is not None and _RCLONE_LOG_LINE.match(line)
                        if line.strip() and not transport_log:
                            counters["warnings"] += 1
                    if kept < 256 * 1024:  # in-memory classification only; never persisted
                        stderr_tail.append(text)
                        kept += len(text)

            readers = [threading.Thread(target=read_stdout, daemon=True),
                       threading.Thread(target=read_stderr, daemon=True)]
            for reader in readers:
                reader.start()
            deadline = time.monotonic() + self._timeout(operation)
            cancelled = timed_out = False
            escalate_at = None
            while True:
                try:
                    process.wait(timeout=1.0)
                    break
                except subprocess.TimeoutExpired:
                    now = time.monotonic()
                    if self.cancel_event is not None and self.cancel_event.is_set() and not cancelled:
                        cancelled = True
                        escalate_at = escalate_at or now + 60
                        self._signal(process, signal.SIGINT)  # restic releases its lock on SIGINT
                    if now > deadline and not timed_out:
                        timed_out = True
                        escalate_at = escalate_at or now + 60
                        self._signal(process, signal.SIGTERM)
                    if escalate_at is not None and now > escalate_at:
                        self._signal(process, signal.SIGKILL)
                        process.wait()
                        break
            for reader in readers:
                reader.join(timeout=30)
            if timed_out:
                raise VaultRewindError("STORAGE_TIMEOUT", "The storage operation exceeded its time limit.", True,
                                       operation=operation, outcome_ambiguous=True)
            if counters["overflow"]:
                raise VaultRewindError("STORAGE_OUTPUT_TOO_LARGE", "The repository returned unexpectedly large output.",
                                       operation=operation)
            code = process.returncode if process.returncode >= 0 else EXIT_CANCELLED
            if cancelled and code != EXIT_OK:
                code = EXIT_CANCELLED
            return _Result(code, b"".join(stdout_chunks), "".join(stderr_tail), counters["errors"],
                           counters["warnings"])

    @staticmethod
    def _signal(process: subprocess.Popen, signum: int) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signum)

    def _run_ok(self, args: list[str], operation: str, **kwargs) -> _Result:
        result = self._execute(args, operation, **kwargs)
        if result.exit_code != EXIT_OK:
            raise restic_failure(result.exit_code, result.stderr, operation)
        return result

    # ------------------------------------------------------------------ repository lifecycle
    def describe(self) -> dict:
        """Open the repository and return its restic config (ID/version). Raises if absent."""
        result = self._run_ok(["cat", "config"], "probe")
        try:
            config = json.loads(result.stdout)
            repository_id, version = config["id"], int(config["version"])
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultRewindError("REPOSITORY_INVALID", "The repository configuration is unreadable.") from exc
        self._bind_identity(repository_id)
        return {"repository_id": repository_id, "version": version}

    def _bind_identity(self, repository_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", str(repository_id)):
            raise VaultRewindError("REPOSITORY_INVALID", "The repository identity is malformed.")
        expected = self.config.expected_repository_id
        if expected and expected != repository_id:
            raise VaultRewindError("REPOSITORY_IDENTITY_MISMATCH",
                                   "A different repository exists at the recorded location.")
        self.repository_id = repository_id

    def _require_writable(self) -> None:
        if self.config.read_only:
            raise VaultRewindError("STORAGE_READ_ONLY", "An offline recovery repository cannot be modified.")

    @property
    def durable_for_safety(self) -> bool:
        return not self.config.read_only

    def initialize(self) -> dict:
        """Create the encrypted repository, or open and verify an existing one (idempotent)."""
        self._require_writable()
        probe = self._execute(["cat", "config"], "probe")
        if probe.exit_code == EXIT_OK:
            described = self.describe()
            return {"created": False, **described, "restic_version": self.restic_version}
        if probe.exit_code == EXIT_WRONG_PASSWORD:
            raise restic_failure(probe.exit_code, probe.stderr, "init")
        if probe.exit_code != EXIT_NO_REPOSITORY:
            raise restic_failure(probe.exit_code, probe.stderr, "init")
        if self.config.expected_repository_id:
            raise VaultRewindError("REPOSITORY_NOT_FOUND",
                                   "The recorded repository is missing; it was not silently recreated.")
        result = self._run_ok(["init", "--repository-version", "2"], "init")
        repository_id = None
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            with contextlib.suppress(ValueError):
                message = json.loads(line)
                if isinstance(message, dict) and message.get("message_type") == "initialized":
                    repository_id = message.get("id")
        if not repository_id:
            return {"created": True, **self.describe(), "restic_version": self.restic_version}
        self._bind_identity(repository_id)
        return {"created": True, "repository_id": repository_id, "version": 2, "restic_version": self.restic_version}

    # ------------------------------------------------------------------ catalog
    def list_snapshots(self) -> list[dict]:
        result = self._run_ok(["snapshots"], "list")
        try:
            raw = json.loads(result.stdout or b"[]") or []
        except ValueError as exc:
            raise VaultRewindError("REPOSITORY_INVALID", "The repository snapshot list is unreadable.") from exc
        snapshots = []
        for item in raw:
            if not isinstance(item, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("id", ""))):
                continue
            identity = layout.parse_tags(item.get("tags"))
            summary = item.get("summary") or {}
            try:
                created = utc_iso(parse_utc(item.get("time", "")))
            except VaultRewindError:
                created = None
            snapshots.append({
                "restic_snapshot_id": item["id"], "short_id": item["id"][:8], "time": created,
                "hostname": item.get("hostname"), "tags": list(item.get("tags") or []),
                "managed": bool(identity["snapshot_uuid"] and identity["instance_uuid"]), **identity,
                "total_bytes_processed": summary.get("total_bytes_processed"),
                "data_added_packed": summary.get("data_added_packed"),
            })
        snapshots.sort(key=lambda entry: (entry["time"] or "", entry["restic_snapshot_id"]))
        return snapshots

    def find_snapshots(self, snapshot_uuid: str) -> list[dict]:
        wanted = layout.canonical_uuid(snapshot_uuid, "snapshot UUID")
        return [entry for entry in self.list_snapshots() if entry["snapshot_uuid"] == wanted]

    def _dump(self, restic_id: str, path: str) -> bytes | None:
        """Return file bytes, or None when the snapshot genuinely lacks the path."""
        result = self._execute(["dump", "--", restic_id, path], "verify", max_stdout=MAX_MANIFEST_BYTES)
        if result.exit_code == EXIT_OK:
            return result.stdout
        if result.exit_code == 1 and re.search(r"not found|no such file|cannot dump", result.stderr, re.IGNORECASE):
            return None
        raise restic_failure(result.exit_code, result.stderr, "verify")

    def read_manifest(self, restic_id: str) -> dict:
        restic_id = layout.validate_restic_id(restic_id)
        data = self._dump(restic_id, layout.MANIFEST_PATH)
        if data is None:
            raise VaultRewindError("MANIFEST_MISSING", "The stored snapshot has no VaultRewind manifest.")
        try:
            manifest = json.loads(data)
        except ValueError as exc:
            raise VaultRewindError("MANIFEST_INVALID", "The stored manifest is unreadable.") from exc
        if not isinstance(manifest, dict) or not isinstance(manifest.get("schema_version"), int):
            raise VaultRewindError("MANIFEST_INVALID", "The stored manifest is malformed.")
        return manifest

    def _tree(self, restic_id: str) -> dict[str, tuple[str, int]]:
        nodes: dict[str, tuple[str, int]] = {}

        def collect(message: dict):
            if message.get("message_type", "node") == "node" and message.get("struct_type", "node") == "node":
                path = message.get("path")
                if isinstance(path, str) and path.startswith("/"):
                    nodes[path] = (str(message.get("type")), int(message.get("size") or 0))

        self._run_ok(["ls", "--", restic_id], "verify", stdout_line=collect)
        return nodes

    def _verify_stored(self, restic_id: str, manifest: dict, expected_hash: str) -> dict | None:
        """Manifest readback and structural tree comparison. None means a structurally invalid copy."""
        data = self._dump(restic_id, layout.MANIFEST_PATH)
        if data is None:
            return None
        try:
            stored = json.loads(data)
        except ValueError:
            return None
        if not isinstance(stored, dict):
            return None
        digest = manifest_hash(stored)
        if digest != expected_hash:
            if stored.get("snapshot_uuid") == manifest.get("snapshot_uuid"):
                raise VaultRewindError("SNAPSHOT_IDENTITY_CONFLICT",
                                       "The repository holds different content under the same snapshot UUID.")
            return None
        expected: dict[str, tuple[str, int | None]] = {
            "/manifest": ("dir", None), layout.MANIFEST_PATH: ("file", len(data)),
            layout.INVENTORY_PATH: ("file", None)}
        for section in ("data", "deployment", "images"):
            expected["/" + section] = ("dir", None)
        types = {"file": "file", "directory": "dir", "symlink": "symlink"}
        logical = 0
        for entry in stored.get("inventory", []):
            kind = types.get(entry.get("type"))
            if kind is None:
                return None
            size = int(entry.get("size") or 0) if kind == "file" else None
            logical += size or 0
            expected["/" + entry["path"]] = (kind, size)
        actual = self._tree(restic_id)
        if set(actual) != set(expected):
            return None
        for path, (kind, size) in expected.items():
            if actual[path][0] != kind or (size is not None and actual[path][1] != size):
                return None
        return {"members": len(stored.get("inventory", [])), "logical_bytes": logical}

    # ------------------------------------------------------------------ commit
    @staticmethod
    def _local_manifest(root: Path) -> tuple[dict, str]:
        try:
            info = root.lstat()
        except OSError as exc:
            raise VaultRewindError("SNAPSHOT_INCOMPLETE", "The canonical snapshot tree is unavailable.") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise VaultRewindError("SNAPSHOT_INCOMPLETE", "The canonical snapshot tree is not a directory.")
        names = sorted(entry.name for entry in os.scandir(root))
        if names != sorted(layout.CANONICAL_SECTIONS):
            raise VaultRewindError("SNAPSHOT_INCOMPLETE",
                                   "The canonical snapshot tree must contain exactly data, deployment, images and manifest.")
        for name in layout.CANONICAL_SECTIONS:
            if not stat.S_ISDIR((root / name).lstat().st_mode):
                raise VaultRewindError("SNAPSHOT_INCOMPLETE", "A canonical snapshot section is not a directory.")
        try:
            manifest = json.loads((root / "manifest" / "manifest.json").read_bytes())
        except (OSError, ValueError) as exc:
            raise VaultRewindError("MANIFEST_INVALID", "The staged manifest is unreadable.") from exc
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            raise VaultRewindError("MANIFEST_VERSION_UNSUPPORTED", "The staged manifest version is unsupported.")
        return manifest, manifest_hash(manifest)

    def commit(self, root: Path, snapshot_uuid: str, captured_at: str, *, kind: str = "backup",
               progress: Callable[[dict], None] | None = None) -> dict:
        self._require_writable()
        root = Path(root)
        snapshot_uuid = layout.canonical_uuid(snapshot_uuid, "snapshot UUID")
        manifest, expected_hash = self._local_manifest(root)
        if manifest.get("snapshot_uuid") != snapshot_uuid or manifest.get("captured_at") != captured_at:
            raise VaultRewindError("MANIFEST_MISMATCH", "The staged manifest does not describe the requested snapshot.")
        instance_uuid = layout.canonical_uuid(manifest.get("instance_uuid", ""), "instance UUID")
        if self.config.instance_uuid and instance_uuid != self.config.instance_uuid:
            raise VaultRewindError("REPOSITORY_OWNERSHIP_MISMATCH",
                                   "This repository belongs to a different instance.")
        captured = parse_utc(captured_at)
        tags = layout.snapshot_tags(snapshot_uuid, instance_uuid, expected_hash, kind)

        existing = self.list_snapshots()
        invalid: list[str] = []
        for candidate in [s for s in existing if s["snapshot_uuid"] == snapshot_uuid]:
            evidence = self._verify_stored(candidate["restic_snapshot_id"], manifest, expected_hash)
            if evidence is not None:
                return self._commit_result(candidate["restic_snapshot_id"], snapshot_uuid, instance_uuid,
                                           expected_hash, evidence, None, reconciled=True, discarded=[])
            invalid.append(candidate["restic_snapshot_id"])
        parents = [s for s in existing if s["instance_uuid"] == instance_uuid
                   and s["restic_snapshot_id"] not in invalid]

        args = ["backup", "--host", layout.SNAPSHOT_HOST, "--time", captured.strftime("%Y-%m-%d %H:%M:%S")]
        for tag in tags:
            args += ["--tag", tag]
        if parents:
            args += ["--parent", parents[-1]["restic_snapshot_id"]]
        args += ["--", "."]
        state: dict = {"summary": None, "status_errors": 0}

        def on_line(message: dict):
            kind_ = message.get("message_type")
            if kind_ == "summary":
                state["summary"] = message
            elif kind_ == "status":
                state["status_errors"] = max(state["status_errors"], int(message.get("error_count") or 0))
                if progress is not None:
                    with contextlib.suppress(Exception):
                        progress({key: message.get(key) for key in ("seconds_elapsed", "percent_done", "total_files",
                                                                     "files_done", "total_bytes", "bytes_done")})

        result = self._execute(args, "commit", cwd=root, stdout_line=on_line)
        summary = state["summary"] or {}
        created = summary.get("snapshot_id")
        if created and not re.fullmatch(r"[0-9a-f]{64}", str(created)):
            created = None
        problems = result.error_messages or result.warnings or state["status_errors"]
        if result.exit_code == EXIT_OK and created and not problems:
            evidence = self._verify_stored(created, manifest, expected_hash)
            rediscovered = created in {s["restic_snapshot_id"] for s in self.find_snapshots(snapshot_uuid)}
            if evidence is None or not rediscovered:
                discarded = self._discard([created])
                raise VaultRewindError("STORAGE_COMMIT_UNVERIFIED",
                                       "The stored copy failed manifest or inventory readback and was discarded.",
                                       discarded=bool(discarded))
            discarded = self._discard(invalid) if invalid else []
            return self._commit_result(created, snapshot_uuid, instance_uuid, expected_hash, evidence, summary,
                                       reconciled=False, discarded=discarded)
        if created:
            self._discard([created])
        if result.exit_code in (EXIT_OK, EXIT_PARTIAL):
            raise VaultRewindError("STORAGE_COMMIT_PARTIAL",
                                   "Some snapshot content could not be read; the incomplete copy was discarded.",
                                   False, exit_code=result.exit_code, read_errors=result.error_messages,
                                   warnings=result.warnings)
        raise restic_failure(result.exit_code, result.stderr, "commit")

    def _discard(self, ids: list[str]) -> list[str]:
        """Forget exact IDs of copies proven invalid by this adapter. Best effort; returns removed IDs."""
        try:
            return self.forget(ids, _internal=True)["removed"]
        except VaultRewindError:
            return []

    def _commit_result(self, restic_id, snapshot_uuid, instance_uuid, digest, evidence, summary, *,
                       reconciled: bool, discarded: list[str]) -> dict:
        return {
            "restic_snapshot_id": restic_id, "snapshot_uuid": snapshot_uuid, "instance_uuid": instance_uuid,
            "manifest_hash": digest, "logical_bytes": evidence["logical_bytes"],
            "stored_bytes": (summary or {}).get("data_added_packed"),
            "stored_copy_verified": True, "reconciled": reconciled, "repository_id": self.repository_id,
            "verification": {"exit_status_clean": not reconciled, "rediscovered_by_uuid": True,
                             "manifest_readback": True, "tree_matches_inventory": True,
                             "inventory_members": evidence["members"], "content_hashes_read": False},
            "discarded_invalid_ids": discarded, "committed_at": utc_iso(), "restic_version": self.restic_version,
        }

    # ------------------------------------------------------------------ restore / verification
    def restore(self, restic_id: str, target: Path, *, expected_manifest_hash: str | None = None) -> dict:
        restic_id = layout.validate_restic_id(restic_id)
        target = Path(target)
        if self.config.read_only and self.config.backend == "local":
            source, resolved_target = Path(self.config.location).resolve(), target.resolve()
            if (source == resolved_target or source in resolved_target.parents or
                    resolved_target in source.parents):
                raise VaultRewindError("STORAGE_READ_ONLY", "Recovery output cannot overlap the source repository.")
        if target.is_symlink():
            raise VaultRewindError("RESTORE_TARGET_UNSAFE", "The restore staging target must not be a symlink.")
        if target.exists():
            if not target.is_dir() or any(target.iterdir()):
                raise VaultRewindError("RESTORE_TARGET_NOT_EMPTY", "Restores require an empty private staging directory.")
        else:
            target.mkdir(mode=0o700)
        os.chmod(target, 0o700)
        manifest = self.read_manifest(restic_id)
        stored_hash = manifest_hash(manifest)
        if expected_manifest_hash and stored_hash != expected_manifest_hash:
            raise VaultRewindError("MANIFEST_HASH_MISMATCH", "The stored manifest differs from the cataloged identity.")
        state: dict = {"summary": None}

        def on_line(message: dict):
            if message.get("message_type") == "summary":
                state["summary"] = message

        result = self._execute(["restore", "--target", str(target), "--verify", "--", restic_id], "restore",
                               stdout_line=on_line)
        if result.exit_code != EXIT_OK or result.error_messages:
            raise (restic_failure(result.exit_code, result.stderr, "restore") if result.exit_code != EXIT_OK else
                   VaultRewindError("RESTORE_VERIFY_FAILED", "Restored bytes did not verify against the repository."))
        from vaultrewind.core.manifest import verify_snapshot
        evidence = verify_snapshot(target, stored_hash)
        summary = state["summary"] or {}
        return {"restic_snapshot_id": restic_id, "manifest_hash": stored_hash,
                "snapshot_uuid": evidence["snapshot_uuid"], "instance_uuid": evidence["instance_uuid"],
                "restored_bytes_verified": True, "repository_content_verified": True,
                "inventory_members": evidence["members"], "logical_bytes": evidence["logical_bytes"],
                "files_restored": summary.get("files_restored"), "bytes_restored": summary.get("bytes_restored"),
                "verified_at": utc_iso()}

    def check(self, read_data: bool = False, *, read_data_subset: str | None = None) -> dict:
        args = ["check"]
        if read_data and read_data_subset:
            raise VaultRewindError("CHECK_OPTIONS_INVALID", "Choose a full data read or a subset, not both.")
        if read_data:
            args.append("--read-data")
            level = "full_data"
        elif read_data_subset:
            if not re.fullmatch(r"\d{1,3}/\d{1,3}|\d{1,3}(\.\d{1,3})?%|\d{1,12}[kKmMgGtT]?", read_data_subset):
                raise VaultRewindError("CHECK_OPTIONS_INVALID", "Invalid data subset specification.")
            args += ["--read-data-subset", read_data_subset]
            level = "data_subset"
        else:
            level = "structure"
        state: dict = {"summary": None}

        def on_line(message: dict):
            if message.get("message_type") == "summary":
                state["summary"] = message

        started = utc_iso()
        result = self._execute(args, "check", stdout_line=on_line)
        summary = state["summary"]
        if result.exit_code not in (EXIT_OK, 1) or (result.exit_code == 1 and summary is None
                                                     and not result.error_messages):
            raise restic_failure(result.exit_code, result.stderr, "check")
        errors = int((summary or {}).get("num_errors") or 0) + result.error_messages
        ok = result.exit_code == EXIT_OK and errors == 0
        return {"ok": ok, "verification_level": level, "data_read": level != "structure",
                "full_data_verified": ok and level == "full_data", "read_data_subset": read_data_subset,
                "num_errors": errors, "broken_packs": len((summary or {}).get("broken_packs") or []),
                "suggest_repair_index": bool((summary or {}).get("suggest_repair_index")),
                "suggest_prune": bool((summary or {}).get("suggest_prune")),
                "error_code": None if ok else "REPOSITORY_CHECK_FAILED",
                "started_at": started, "finished_at": utc_iso(), "restic_version": self.restic_version}

    # ------------------------------------------------------------------ deletion
    def forget(self, ids: list[str], *, _internal: bool = False) -> dict:
        """Forget exactly these snapshot IDs (never a policy). Reports what really remains."""
        self._require_writable()
        wanted = sorted({layout.validate_restic_id(item) for item in ids})
        if not wanted:
            return {"requested": [], "removed": [], "already_absent": [], "retained": [], "complete": True}
        before = {entry["restic_snapshot_id"]: entry for entry in self.list_snapshots()}
        present = [item for item in wanted if item in before]
        absent = [item for item in wanted if item not in before]
        if self.config.instance_uuid and not _internal:
            foreign = [item for item in present if before[item]["instance_uuid"] != self.config.instance_uuid]
            if foreign:
                raise VaultRewindError("REPOSITORY_OWNERSHIP_MISMATCH",
                                       "Deletion targets a snapshot not owned by this instance; nothing was deleted.")
        exit_code = EXIT_OK
        error = None
        if present:
            result = self._execute(["forget", "--", *present], "forget")
            exit_code = result.exit_code
            if exit_code not in (EXIT_OK, EXIT_PARTIAL):
                error = restic_failure(exit_code, result.stderr, "forget")
        try:
            after = {entry["restic_snapshot_id"] for entry in self.list_snapshots()}
        except VaultRewindError:
            if error:
                raise error
            raise
        retained = [item for item in present if item in after]
        removed = [item for item in present if item not in after]
        outcome = {"requested": wanted, "removed": removed, "already_absent": absent, "retained": retained,
                   "complete": not retained, "exit_code": exit_code, "error_code": None}
        if retained:
            outcome["error_code"] = error.code if error else "STORAGE_DELETE_DENIED"
        return outcome

    def prune(self, *, verify: bool = True) -> dict:
        """Physically remove unreferenced data. Run outside captures/restores; verifies structure afterwards."""
        self._require_writable()
        started = utc_iso()
        self._run_ok(["prune"], "prune")
        outcome = {"pruned": True, "started_at": started, "finished_at": utc_iso()}
        if verify:
            outcome["check"] = self.check(read_data=False)
        return outcome

    def remove_stale_locks(self) -> dict:
        """Explicit administrative action: removes only locks restic itself classifies as stale."""
        self._require_writable()
        self._run_ok(["unlock"], "keys")
        return {"stale_locks_removed": True, "forced": False}

    def stats(self) -> dict:
        result = self._run_ok(["stats", "--mode", "raw-data"], "list")
        try:
            data = json.loads(result.stdout)
        except ValueError as exc:
            raise VaultRewindError("REPOSITORY_INVALID", "Repository statistics are unreadable.") from exc
        return {"stored_bytes": data.get("total_size"), "uncompressed_bytes": data.get("total_uncompressed_size"),
                "snapshots": data.get("snapshots_count")}

    # ------------------------------------------------------------------ repository key rotation
    def list_keys(self) -> list[dict]:
        result = self._run_ok(["key", "list"], "keys")
        try:
            keys = json.loads(result.stdout)
        except ValueError as exc:
            raise VaultRewindError("REPOSITORY_INVALID", "The repository key list is unreadable.") from exc
        return [{"key_id": item["id"], "current": bool(item.get("current")), "created": item.get("created")}
                for item in keys if isinstance(item, dict) and "id" in item]

    def add_key(self, new_password: str) -> str:
        self._require_writable()
        if not isinstance(new_password, str) or len(new_password) < 16 or any(c in new_password for c in "\r\n\x00"):
            raise VaultRewindError("REPOSITORY_SECRET_INVALID", "A new repository secret must be a strong single line.")
        register_secret(new_password)
        before = {item["key_id"] for item in self.list_keys()}

        def prepare(workspace: Path, env: dict) -> list[str]:
            path = write_private_file(workspace / "new-repository-password", new_password)
            return ["key", "add", "--host", layout.SNAPSHOT_HOST, "--user", "vaultrewind",
                    "--new-password-file", str(path)]

        result = self._execute([], "keys", prepare=prepare)
        if result.exit_code != EXIT_OK:
            raise restic_failure(result.exit_code, result.stderr, "keys")
        added = [item["key_id"] for item in self.list_keys() if item["key_id"] not in before]
        if len(added) != 1:
            raise VaultRewindError("REPOSITORY_KEY_UNCONFIRMED", "The new repository key could not be confirmed.")
        return added[0]

    def remove_key(self, key_id: str) -> None:
        self._require_writable()
        keys = {item["key_id"]: item for item in self.list_keys()}
        if key_id not in keys:
            raise VaultRewindError("REPOSITORY_KEY_NOT_FOUND", "The repository key does not exist.")
        if keys[key_id]["current"]:
            raise VaultRewindError("REPOSITORY_KEY_IN_USE", "The key used for this session cannot be removed.")
        self._run_ok(["key", "remove", "--", key_id], "keys")

    def rotate_password(self, new_password: str, persist: Callable[[str], None], *,
                        remove_old_key: bool = False) -> dict:
        """Add a key, prove it opens the repository, persist it, then optionally remove the old key.

        Old keys are kept by default because previously exported recovery kits still
        reference them; removing them requires re-exporting the recovery kit first.
        """
        self._require_writable()
        old = [item["key_id"] for item in self.list_keys() if item["current"]]
        new_key = self.add_key(new_password)
        rotated = ResticRepository(dataclasses.replace(self.config, password=new_password))
        rotated.describe()
        persist(new_password)
        self.config = rotated.config
        removed = []
        if remove_old_key:
            for key_id in old:
                rotated.remove_key(key_id)
                removed.append(key_id)
        return {"new_key_id": new_key, "removed_key_ids": removed, "previous_key_retained": not removed,
                "recovery_kit_reexport_required": True}

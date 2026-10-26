"""S3-compatible destinations (AWS S3, MinIO, ...) using restic's native S3 backend.

Credentials reach restic only through ``AWS_*`` variables in a freshly built
environment and reach boto3 only as explicit session arguments.  TLS
verification is never disabled: HTTPS is mandatory except for an explicitly
selected local development fixture (loopback, private IP or a single-label
Compose service name such as ``minio``).
"""
from __future__ import annotations

import ipaddress
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.security.privatefiles import private_workspace, write_private_file
from vaultrewind.security.redaction import register_secret

from . import layout
from .errors import classify_output

_BUCKET = re.compile(r"^(?!xn--)(?!sthree-)(?!.*\.\.)(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_PREFIX_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_REGION = re.compile(r"^[a-z0-9-]{1,40}$")
_ACCESS_KEY = re.compile(r"^[A-Za-z0-9+/=_.:@-]{3,256}$")
MAX_CA_BYTES = 256 * 1024


def _development_host_allowed(host: str) -> bool:
    if host == "localhost" or ("." not in host and ":" not in host and re.fullmatch(r"[a-z0-9-]{1,63}", host)):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def validate_ca_bundle(pem: str | None) -> str | None:
    if pem in (None, ""):
        return None
    if not isinstance(pem, str) or len(pem.encode()) > MAX_CA_BYTES or "PRIVATE KEY" in pem:
        raise VaultRewindError("STORAGE_CA_INVALID", "The custom CA must be a PEM certificate bundle (no keys).")
    from cryptography import x509
    try:
        certificates = x509.load_pem_x509_certificates(pem.encode())
    except ValueError as exc:
        raise VaultRewindError("STORAGE_CA_INVALID", "The custom CA bundle could not be parsed.") from exc
    if not certificates:
        raise VaultRewindError("STORAGE_CA_INVALID", "The custom CA bundle contains no certificates.")
    return pem if pem.endswith("\n") else pem + "\n"


@dataclass
class S3Credentials:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)

    @classmethod
    def from_dict(cls, data: dict | None) -> S3Credentials:
        if not isinstance(data, dict):
            raise VaultRewindError("STORAGE_CREDENTIALS_MISSING", "S3 access credentials are required.")
        unknown = set(data) - {"access_key_id", "secret_access_key", "session_token"}
        key, secret, token = data.get("access_key_id"), data.get("secret_access_key"), data.get("session_token")
        if unknown or not isinstance(key, str) or not _ACCESS_KEY.fullmatch(key):
            raise VaultRewindError("STORAGE_CREDENTIALS_INVALID", "The S3 access key ID is malformed.")
        if not isinstance(secret, str) or not 3 <= len(secret) <= 512 or any(c in secret for c in "\r\n\x00"):
            raise VaultRewindError("STORAGE_CREDENTIALS_INVALID", "The S3 secret access key is malformed.")
        if token is not None and (not isinstance(token, str) or any(c in token for c in "\r\n\x00")):
            raise VaultRewindError("STORAGE_CREDENTIALS_INVALID", "The S3 session token is malformed.")
        for value in (key, secret, token):
            register_secret(value)
        return cls(key, secret, token or None)

    def environment(self, region: str) -> dict[str, str]:
        env = {"AWS_ACCESS_KEY_ID": self.access_key_id, "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
               "AWS_DEFAULT_REGION": region}
        if self.session_token:
            env["AWS_SESSION_TOKEN"] = self.session_token
        return env


@dataclass
class S3Destination:
    destination_id: str
    endpoint: str
    bucket: str
    prefix: str = ""
    region: str = "us-east-1"
    bucket_lookup: str = "auto"
    ca_cert_pem: str | None = field(default=None, repr=False)
    development_http: bool = False

    @classmethod
    def from_config(cls, configuration: dict, destination_id: str) -> S3Destination:
        unknown = set(configuration) - {"endpoint", "bucket", "prefix", "region", "bucket_lookup", "ca_cert_pem",
                                        "development_http"}
        if unknown:
            raise VaultRewindError("STORAGE_CONFIGURATION", "Unknown S3 destination settings were supplied.")
        destination = cls(destination_id=layout.canonical_uuid(destination_id, "destination ID"),
                          endpoint=configuration.get("endpoint") or "https://s3.amazonaws.com",
                          bucket=configuration.get("bucket") or "", prefix=configuration.get("prefix") or "",
                          region=configuration.get("region") or "us-east-1",
                          bucket_lookup={"virtual": "dns"}.get(configuration.get("bucket_lookup") or "auto",
                                                               configuration.get("bucket_lookup") or "auto"),
                          ca_cert_pem=configuration.get("ca_cert_pem"),
                          development_http=configuration.get("development_http") is True)
        destination.validate()
        return destination

    def validate(self) -> None:
        try:
            parts = urlsplit(self.endpoint)
            port = parts.port
        except ValueError as exc:
            raise VaultRewindError("STORAGE_CONFIGURATION", "The S3 endpoint URL is malformed.") from exc
        host = (parts.hostname or "").lower()
        if (not host or parts.username or parts.password or parts.query or parts.fragment
                or parts.path not in ("", "/") or not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", host)):
            raise VaultRewindError("STORAGE_CONFIGURATION",
                                   "The S3 endpoint must be scheme://host[:port] without credentials or paths.")
        if parts.scheme == "http":
            if not self.development_http:
                raise VaultRewindError("STORAGE_TLS_REQUIRED", "S3 endpoints require certificate-verified HTTPS.")
            if not _development_host_allowed(host):
                raise VaultRewindError("STORAGE_TLS_REQUIRED",
                                       "Plain HTTP is allowed only for a local development fixture host.")
        elif parts.scheme != "https":
            raise VaultRewindError("STORAGE_CONFIGURATION", "The S3 endpoint must use HTTPS.")
        if port is not None and not 1 <= port <= 65535:
            raise VaultRewindError("STORAGE_CONFIGURATION", "The S3 endpoint port is invalid.")
        if not _BUCKET.fullmatch(self.bucket):
            raise VaultRewindError("STORAGE_CONFIGURATION", "The S3 bucket name is invalid.")
        prefix = self.prefix.strip("/")
        if prefix and (len(prefix) > 512 or not all(_PREFIX_SEGMENT.fullmatch(s) and s not in (".", "..")
                                                    for s in prefix.split("/"))):
            raise VaultRewindError("STORAGE_CONFIGURATION", "The S3 prefix may contain only safe path segments.")
        self.prefix = prefix
        if not _REGION.fullmatch(self.region):
            raise VaultRewindError("STORAGE_CONFIGURATION", "The S3 region is invalid.")
        if self.bucket_lookup not in ("auto", "path", "dns"):
            raise VaultRewindError("STORAGE_CONFIGURATION", "Bucket addressing must be auto, path or dns.")
        self.ca_cert_pem = validate_ca_bundle(self.ca_cert_pem)
        shown = f"[{host}]" if ":" in host else host
        self.endpoint = f"{parts.scheme}://{shown}" + (f":{port}" if port else "")

    def key_prefix(self, *more: str) -> str:
        return "/".join(part for part in (self.prefix, *more) if part)

    def repository_location(self, instance_id: str) -> str:
        return (f"s3:{self.endpoint}/{self.bucket}/"
                f"{self.key_prefix(layout.repository_prefix(instance_id, self.destination_id))}")

    def restic_options(self) -> tuple[str, ...]:
        return (f"s3.bucket-lookup={self.bucket_lookup}", f"s3.region={self.region}")

    def public_view(self) -> dict:
        return {"endpoint": self.endpoint, "bucket": self.bucket, "prefix": self.prefix, "region": self.region,
                "bucket_lookup": self.bucket_lookup, "custom_ca": bool(self.ca_cert_pem),
                "development_http": self.development_http}


def _client(destination: S3Destination, credentials: S3Credentials, ca_file: Path | None):
    import boto3
    from botocore.config import Config
    style = {"auto": "auto", "path": "path", "dns": "virtual"}[destination.bucket_lookup]
    session = boto3.session.Session(aws_access_key_id=credentials.access_key_id,
                                    aws_secret_access_key=credentials.secret_access_key,
                                    aws_session_token=credentials.session_token, region_name=destination.region)
    return session.client("s3", endpoint_url=destination.endpoint, verify=str(ca_file) if ca_file else True,
                          config=Config(signature_version="s3v4", s3={"addressing_style": style},
                                        retries={"max_attempts": 2, "mode": "standard"},
                                        connect_timeout=10, read_timeout=60))


def _classify(exc: Exception) -> str:
    code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = str((response.get("Error") or {}).get("Code") or "")
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        code = f"{code} {status or ''}"
    return classify_output(f"{type(exc).__name__} {code} {exc}", "STORAGE_OPERATION_FAILED",
                           "The storage operation failed.").code


def probe_s3(destination: S3Destination, credentials: S3Credentials, *, runtime_dir: Path | None = None) -> dict:
    """Scoped connection test below ``<prefix>/vaultrewind/.probe/<uuid>/``.

    Objects are written with restic-shaped key classes (locks/, snapshots/, data/) so path-scoped
    deny policies are noticed; each class's delete result is reported.  Only objects this probe
    created are touched.  Authoritative deletion outcomes still come from ``forget`` relisting.
    """
    probe_root = destination.key_prefix(layout.LAYOUT_ROOT, ".probe", str(uuid.uuid4()))
    blob = uuid.uuid4().hex + uuid.uuid4().hex
    keys = {"locks": f"{probe_root}/locks/{blob}", "snapshots": f"{probe_root}/snapshots/{blob}",
            "data": f"{probe_root}/data/{blob[:2]}/{blob}"}
    payload = os.urandom(32)
    results = {name: {"ok": False, "error_code": None} for name in ("list", "write", "read", "delete")}
    delete_classes: dict[str, bool] = {}
    written: list[str] = []
    with private_workspace(runtime_dir, prefix="vaultrewind-s3-") as workspace:
        ca_file = write_private_file(workspace / "ca.pem", destination.ca_cert_pem) if destination.ca_cert_pem else None
        client = _client(destination, credentials, ca_file)

        def attempt(name, operation):
            try:
                value = operation()
                results[name]["ok"] = True
                return value
            except Exception as exc:  # noqa: BLE001 - botocore raises many unrelated types
                results[name]["ok"] = False
                results[name]["error_code"] = results[name]["error_code"] or _classify(exc)
                return None

        attempt("list", lambda: client.list_objects_v2(Bucket=destination.bucket, Prefix=probe_root + "/", MaxKeys=1))
        for key in keys.values():
            if attempt("write", lambda key=key: client.put_object(Bucket=destination.bucket, Key=key, Body=payload)):
                written.append(key)
            elif not results["write"]["ok"]:
                break
        results["write"]["ok"] = len(written) == len(keys)
        if written:
            body = attempt("read", lambda: client.get_object(Bucket=destination.bucket, Key=written[0])["Body"].read())
            if results["read"]["ok"] and body != payload:
                results["read"] = {"ok": False, "error_code": "STORAGE_PROBE_FAILED"}
            for name, key in keys.items():
                if key not in written:
                    continue
                try:
                    client.delete_object(Bucket=destination.bucket, Key=key)
                    client.head_object(Bucket=destination.bucket, Key=key)
                    delete_classes[name] = False  # still present after a "successful" delete
                    results["delete"]["error_code"] = results["delete"]["error_code"] or "STORAGE_DELETE_DENIED"
                except Exception as exc:  # noqa: BLE001 - absence after delete is reported as an exception
                    code = str(((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", ""))
                    gone = code in ("404", "NoSuchKey", "NotFound")
                    delete_classes[name] = gone
                    if not gone:
                        results["delete"]["error_code"] = results["delete"]["error_code"] or _classify(exc)
            results["delete"]["ok"] = bool(delete_classes) and all(delete_classes.values()) and \
                len(delete_classes) == len(keys)
        else:
            results["read"]["error_code"] = results["delete"]["error_code"] = "PROBE_NOT_WRITTEN"
    backup_ready = all(results[name]["ok"] for name in ("list", "write", "read"))
    warnings = [("Provider lifecycle/expiration rules on this prefix can delete restic data still needed "
                 "by retained snapshots; disable them for the VaultRewind prefix."),
                "Bucket object versioning is separate from VaultRewind snapshot history."]
    if delete_classes.get("locks") is False:
        warnings.append("restic cannot remove its own lock files with these credentials; every operation would "
                        "leave stale locks that block retention.")
    return {"backend": "s3", "destination": destination.public_view(), "probe": results,
            "delete_classes": delete_classes, "backup_ready": backup_ready,
            "retention_ready": backup_ready and results["delete"]["ok"],
            "probe_left_behind": len([k for k, ok in delete_classes.items() if not ok]) + (len(written) - len(
                delete_classes)) if written else 0,
            "warnings": warnings}


def list_s3_repositories(destination: S3Destination, credentials: S3Credentials, *,
                         runtime_dir: Path | None = None) -> list[dict]:
    """Discover ``<prefix>/vaultrewind/<instance>/<destination>`` repositories that contain a restic config."""
    found = []
    with private_workspace(runtime_dir, prefix="vaultrewind-s3-") as workspace:
        ca_file = write_private_file(workspace / "ca.pem", destination.ca_cert_pem) if destination.ca_cert_pem else None
        client = _client(destination, credentials, ca_file)
        root = destination.key_prefix(layout.LAYOUT_ROOT) + "/"
        try:
            paginator = client.get_paginator("list_objects_v2")
            instances = [p["Prefix"] for page in paginator.paginate(Bucket=destination.bucket, Prefix=root,
                                                                    Delimiter="/")
                         for p in page.get("CommonPrefixes", [])]
            for instance_prefix in instances:
                for page in paginator.paginate(Bucket=destination.bucket, Prefix=instance_prefix, Delimiter="/"):
                    for item in page.get("CommonPrefixes", []):
                        relative = item["Prefix"][len(destination.key_prefix()) + 1 if destination.prefix else 0:]
                        parsed = layout.parse_repository_prefix(relative)
                        if not parsed:
                            continue
                        listing = client.list_objects_v2(Bucket=destination.bucket, Prefix=item["Prefix"] + "config",
                                                         MaxKeys=1)
                        if listing.get("KeyCount", 0):
                            found.append({"instance_id": parsed[0], "destination_id": parsed[1],
                                          "location": f"s3:{destination.endpoint}/{destination.bucket}/"
                                                      f"{item['Prefix'].rstrip('/')}"})
        except Exception as exc:
            raise VaultRewindError(_classify(exc), "Repositories could not be listed in this bucket prefix.") from exc
    return found

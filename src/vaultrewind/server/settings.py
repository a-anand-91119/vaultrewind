from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VAULTREWIND_", extra="ignore")
    database_url: str = "postgresql+psycopg://vaultrewind@db/vaultrewind"
    master_key_file: Path = Path("/run/secrets/vaultrewind_master_key")
    bootstrap_secret_file: Path = Path("/run/secrets/vaultrewind_bootstrap")
    migrations_dir: Path | None = None
    local_require_dedicated_mount: bool = True
    frontend_dir: Path | None = None
    helper_bundle_dir: Path | None = None
    staging_dir: Path = Path("/var/lib/vaultrewind/staging")
    provider_credential_state_dir: Path | None = None
    local_storage_root: Path = Path("/var/lib/vaultrewind/backups")
    public_origin: str = "https://localhost"
    secure_cookies: bool = True
    session_hours: int = Field(12, ge=1, le=168)
    lease_seconds: int = Field(60, ge=10)
    poll_seconds: float = Field(2.0, ge=0.1)
    global_concurrency: int = Field(2, ge=1, le=32)
    per_job_quota_bytes: int = Field(50 * 1024**3, ge=1024)
    staging_quota_bytes: int = Field(100 * 1024**3, ge=1024)
    safety_quota_bytes: int = Field(100 * 1024**3, ge=1024)
    min_free_bytes: int = Field(1024**3, ge=0)
    clock_skew_seconds: int = Field(120, ge=1)
    webhook_allowed_hosts: list[str] = []
    allow_private_webhooks: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_from: str | None = None
    drive_redirect_path: str = "/api/v1/oauth/drive/callback"
    retry_limit: int = Field(3, ge=0, le=10)
    # Rolling-upgrade compatibility: rows recorded as binding="unverified" may still decrypt with the historical
    # context-less envelope and are upgraded; rows recorded as row-bound never fall back. Disable after
    # `python -m vaultrewind.server.maintenance secret-bindings --apply` reports no remaining rows.
    accept_legacy_secret_envelopes: bool = True
    controller_backup_max_bytes: int = Field(512 * 1024**2, ge=1024**2)
    controller_backup_max_age_days: int = Field(7, ge=1, le=365)

    @model_validator(mode="after")
    def validate_origin(self):
        from urllib.parse import urlparse
        p = urlparse(self.public_origin)
        if p.scheme != "https" and not (p.scheme == "http" and p.hostname in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("HTTPS origin required except loopback development")
        if p.path not in {"", "/"} or p.query or p.fragment or p.username:
            raise ValueError("public_origin must be an origin")
        if not self.secure_cookies and p.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Insecure cookies allowed only on loopback")
        self.public_origin = self.public_origin.rstrip("/")
        return self


def read_private_file(path: Path, *, length: int | None = None) -> bytes:
    import os
    import stat

    from vaultrewind.core.errors import VaultRewindError
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError()
            value = stream.read(65537)
        if not value or len(value) > 65536 or (length is not None and len(value) != length):
            raise ValueError()
        return value
    except (OSError, ValueError):
        raise VaultRewindError("SECRET_FILE_UNAVAILABLE", "A protected controller secret file is unavailable.") from None

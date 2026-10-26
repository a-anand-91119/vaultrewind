from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator

Id = Annotated[str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
Label = Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")]
Password = Annotated[str, Field(min_length=12, max_length=1024)]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class Empty(Input):
    pass


class Login(Input):
    username: Annotated[str, Field(min_length=1, max_length=120)]
    password: Annotated[str, Field(min_length=1, max_length=1024)]


class UserCreate(Input):
    username: Label
    password: Password
    role: Literal["administrator", "viewer"] = "viewer"
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Invalid timezone") from None
        return value


class Setup(UserCreate):
    bootstrap_secret: Annotated[str, Field(min_length=1, max_length=1024)]
    local_storage_directory: str | None = None
    role: Literal["administrator"] = "administrator"


class UserPatch(Input):
    active: bool | None = None
    role: Literal["administrator", "viewer"] | None = None
    password: Password | None = None


class Revoke(Input):
    user_id: Id | None = None


class ActivationCredential(Input):
    username: Annotated[str, Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,79}$")]
    private_key: Annotated[str, Field(min_length=20, max_length=65536)]
    passphrase: Annotated[str | None, Field(max_length=4096)] = None


class HostCreate(Input):
    name: Label
    endpoint: Annotated[str, Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.:-]+$")]
    port: int = Field(22, ge=1, le=65535)
    username: Annotated[str, Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z_][a-zA-Z0-9_.-]*$")]
    host_public_key: Annotated[str, Field(min_length=20, max_length=16384)]
    private_key: Annotated[str, Field(min_length=20, max_length=65536)]
    passphrase: Annotated[str | None, Field(max_length=4096)] = None
    activation_credential: ActivationCredential | None = None


class Discover(Input):
    instance_id: Id | None = None


class HostReconcile(Input):
    remote_instance_id: Id
    operation_id: Id


class Activation(Input):
    policy: dict


class Activate(Input):
    plan_id: Id
    plan_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class InstanceCreate(Input):
    host_id: Id
    name: Label
    container_id: Annotated[str, Field(max_length=128)]
    configuration: dict
    is_runner: bool = False


class Backup(Input):
    label: Label | None = None


class RemoteCleanup(Input):
    kind: Literal["generations", "discard_candidate", "staging"]


class Restore(Input):
    target_id: Id | None = None
    copy_id: Id | None = None
    start_on_completion: bool = False


class Execute(Input):
    confirmation_token: Annotated[str, Field(min_length=20, max_length=256)]


class Verify(Input):
    level: Literal["full_data", "restore", "application"] = "full_data"
    copy_id: Id | None = None
    runner_id: Id | None = None


class DestinationCreate(Input):
    name: Label
    backend: Literal["local", "s3", "drive"]
    configuration: dict
    credentials: dict | None = None
    quota_bytes: int | None = Field(None, ge=1)


class DestinationPatch(Input):
    name: Label | None = None
    configuration: dict | None = None
    credentials: dict | None = None


class Authorize(Input):
    mode: Literal["browser", "headless"] = "browser"
    token: dict | None = None


class PolicyDestinationInput(Input):
    destination_id: Id
    required: bool = True


class PolicyPatch(Input):
    enabled: bool | None = None
    schedule_kind: Literal["daily", "hourly"] | None = None
    timezone: str | None = None
    daily_time: str | None = None
    interval_hours: int | None = Field(None, ge=1, le=24)
    retention_days: int | None = Field(None, ge=1, le=3650)
    outage_seconds: int | None = Field(None, ge=10, le=3600)
    maintenance_seconds: int | None = Field(None, ge=60, le=7200)
    validation_seconds: int | None = Field(None, ge=10, le=600)
    runner_id: Id | None = None
    destinations: list[PolicyDestinationInput] | None = None


class RetentionPreviewInput(Input):
    """Hypothetical retention inputs; omitted values use the stored policy. Nothing is written."""
    retention_days: int | None = Field(None, ge=1, le=3650)
    keep_forever: bool = False


class ControllerBackupRequest(Input):
    destination_id: Id | None = None


class ControllerBackupPolicyInput(Input):
    destination_id: Id
    enabled: bool = True
    timezone: str = "UTC"
    daily_time: str = "02:00"


class RecoveryExport(Input):
    passphrase: Annotated[str, Field(min_length=16, max_length=1024)]


class RecoveryImport(RecoveryExport):
    kit: Annotated[str, Field(min_length=1, max_length=4 * 1024 * 1024)]


class RecoveryApply(Input):
    plan_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class NotificationCreate(Input):
    kind: Literal["smtp", "webhook"]
    configuration: dict


class View(BaseModel):
    model_config = ConfigDict(extra="forbid")


class JobAccepted(View):
    job_id: str
    state: str
    status_url: str
    events_url: str


class CopyView(View):
    id: str
    repository_id: str
    destination_id: str | None = None
    destination_name: str | None = None
    backend: str | None = None
    state: str
    logical_bytes: int | None
    stored_bytes: int | None
    verified_at: str | None
    data_verified_at: str | None
    error_code: str | None


class SnapshotView(View):
    id: str
    instance_id: str
    captured_at: str
    capture_started_at: str
    trigger: str
    completeness: str
    logical_bytes: int
    vaultwarden_version: str
    image_id: str
    source_state: str
    pinned: bool
    safety: bool
    verification: dict[str, bool]
    copies: list[CopyView]

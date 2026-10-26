"""Private adapter construction and durable provider credential refresh handling."""
import asyncio
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .models import Host, Instance, Repository, Secret, StorageDestination
from .secrets import Secrets


class Adapters:
    def __init__(self, settings, sessions):
        self.settings, self.sessions = settings, sessions
        self.secrets = Secrets(settings)

    def discover_host(self, host_id):
        from .provisioning import Provisioner
        return Provisioner(self).discover_host(host_id)

    def activation_plan(self, host_id, policy):
        from .provisioning import Provisioner
        return Provisioner(self).activation_plan(host_id, policy)

    def activate(self, host_id, plan, operation_id, token, reconcile=False):
        from .provisioning import Provisioner
        return Provisioner(self).activate(host_id, plan, operation_id, token, reconcile=reconcile)

    def remote(self, host_id, instance_id=None):
        from vaultrewind.remote.ssh import SSHRemote
        with self.sessions() as db:
            host = db.get(Host, host_id)
            credentials = self.secrets.get(db, host.credential_id)
            config = {"endpoint": host.endpoint, "port": host.port, "username": host.username,
                      "host_public_key": host.host_public_key, **credentials,
                      "max_archive_bytes": self.settings.per_job_quota_bytes}
            remote_id = instance_id
            if instance_id:
                instance = db.get(Instance, instance_id)
                if instance:
                    private = self.secrets.get(db, instance.configuration_secret_id)
                    remote_id = private["remote_instance_id"]
            return SSHRemote(config), remote_id

    @contextmanager
    def repository(self, repository_id, workdir, guard=lambda: None, required_bytes=0):
        from vaultrewind.storage import providers
        with self.sessions() as db:
            repo = db.get(Repository, repository_id)
            dest = db.get(StorageDestination, repo.destination_id)
            config = self.secrets.get(db, repo.configuration_secret_id)
            password = self.secrets.get(db, repo.key_id)
            credentials = self.secrets.get(db, dest.credential_id) if dest.credential_id else None
            destination_config = self.secrets.get(db, dest.configuration_secret_id)
        guard()
        owner = getattr(guard, "__self__", None)
        with providers.open_repository(dest.backend, destination_config, credentials,
                instance_id=repo.instance_id, destination_id=dest.id, password=password,
                work_dir=Path(workdir), repository_id=config.get("restic_repository_id"), location=config["location"],
                credential_store=SQLCredentialStore(self, guard), box=self.secrets.box(),
                cancel_event=getattr(owner, "_lost", None), required_bytes=required_bytes,
                protected_paths=[self.settings.staging_dir, self.settings.master_key_file, self.settings.bootstrap_secret_file]) as adapter:
            yield adapter
        guard()

    def check_local(self, config):
        from vaultrewind.storage.local import LocalDestination, inspect_local_destination
        destination_id = config.get("_destination_id")
        if not destination_id:
            raise VaultRewindError("STORAGE_CONFIGURATION", "Local destination identity is unavailable.")
        clean = {k: v for k, v in config.items() if not k.startswith("_")}
        root = Path(clean.get("path", self.settings.local_storage_root))
        if not root.is_relative_to(self.settings.local_storage_root):
            raise VaultRewindError("STORAGE_PATH_UNSAFE", "Local storage must use its configured persistent mount.")
        return inspect_local_destination(LocalDestination.from_config(clean, destination_id),
            protected_paths=[self.settings.staging_dir, self.settings.master_key_file])

    def test_destination(self, destination_id, workdir=None, guard=lambda: None):
        from vaultrewind.storage import providers
        with self.sessions() as db:
            dest = db.get(StorageDestination, destination_id)
            config = self.secrets.get(db, dest.configuration_secret_id)
            credentials = self.secrets.get(db, dest.credential_id) if dest.credential_id else None
        guard()
        result = providers.test_destination(dest.backend, config, credentials, destination_id=dest.id,
            work_dir=Path(workdir or self.settings.staging_dir / ("probe-" + dest.id)),
            credential_store=SQLCredentialStore(self, guard), box=self.secrets.box(),
            protected_paths=[self.settings.staging_dir, self.settings.master_key_file])
        guard()
        if not result.get("backup_ready", True):
            raise VaultRewindError("STORAGE_PROBE_FAILED", "The scoped storage probe did not prove write/read access.")
        return {"accessible": True, "retention_ready": result.get("retention_ready", False)}

    def discover_recovery(self, kit, workdir, guard=lambda: None):
        from vaultrewind.recovery.offline import discover, import_plan
        guard()
        discovery = discover(kit, work_dir=Path(workdir), read_manifests=True)
        guard()
        return import_plan(discovery, kit)

    def test_application(self, runner_id, root, operation_id, token):
        from vaultrewind.core.archive import create_archive
        from vaultrewind.core.manifest import verify_snapshot

        from .db import now
        from .worker import POST_ACTIVATION
        verified = verify_snapshot(root)
        with self.sessions() as db:
            runner = db.get(Instance, runner_id)
            host_id = runner.host_id
            if not runner.is_runner:
                raise VaultRewindError("RUNNER_UNSAFE", "An enrolled isolated runner is required.")
        remote, rid = self.remote(host_id, runner_id)
        mutation_started = False

        def dispose():
            status = asyncio.run(remote.request("status", rid, operation_id, token))
            if not status.get("exists"):
                if mutation_started:
                    raise VaultRewindError("REMOTE_JOURNAL_MISSING", "The test operation journal is missing; preserve its private generations for reconciliation.")
                return
            if status.get("activation_started") or status.get("phase") in POST_ACTIVATION:
                raise VaultRewindError("RUNNER_UNSAFE", "The runner crossed the activation boundary; preserve it for review.")
            if status.get("phase") not in {"rolled_back", "failed_safe", "cancelled"}:
                status = asyncio.run(remote.request("rollback", rid, operation_id, token))
            if status.get("phase") not in {"rolled_back", "failed_safe", "cancelled"}:
                raise VaultRewindError("RUNNER_CLEANUP_FAILED", "The runner's empty profile was not recovered.")
            cleaned = asyncio.run(remote.request("cleanup", rid, operation_id, token, {"kind": "discard_candidate"}))
            if cleaned.get("candidate_cleanup_outcome") != "complete" or not cleaned.get("staging_cleaned"):
                raise VaultRewindError("RUNNER_CLEANUP_FAILED", "Candidate retirement and staging cleanup were not verified.")

        try:
            status = asyncio.run(remote.request("status", rid, operation_id, token))
            if status.get("activation_started") or status.get("phase") in POST_ACTIVATION:
                raise VaultRewindError("RUNNER_UNSAFE", "The test runner crossed the public activation boundary.")
            if status.get("candidate_validated"):
                candidate = status
            else:
                if status.get("exists"):
                    raise VaultRewindError("APPLICATION_TEST_FAILED", "The earlier isolated candidate did not complete validation.")
                preflight = asyncio.run(remote.request("preflight", rid, operation_id, token,
                                                       {"controller_time": now().isoformat()}))
                if not preflight.get("empty_target") or not preflight.get("recovery_verified"):
                    raise VaultRewindError("RUNNER_UNSAFE", "The verification profile must be a proven empty dedicated target.")
                archive = root.parent / "verification.tar"
                if archive.exists():
                    archive.unlink()
                create_archive(root, archive)
                mutation_started = True
                asyncio.run(remote.upload_restore(rid, operation_id, token, archive, {
                    "manifest_hash": verified["manifest_hash"], "expected_fingerprint": preflight["fingerprint"],
                    "controller_time": now().isoformat(), "start_on_completion": False}))
                safety = asyncio.run(remote.request("commit_restore", rid, operation_id, token, {"phase": "prepare_safety"}))
                if not safety.get("empty_target"):
                    raise VaultRewindError("RUNNER_UNSAFE", "The isolated target acquired unexpected existing data.")
                candidate = asyncio.run(remote.request("commit_restore", rid, operation_id, token,
                                                       {"phase": "switch_validate", "safety_ack": None}))
            if not candidate.get("candidate_validated"):
                raise VaultRewindError("APPLICATION_NOT_READY", "The isolated candidate did not start successfully.")
        except Exception as original:
            try:
                dispose()
            except Exception:  # noqa: BLE001 - unknown cleanup outcomes must retain the runner lease.
                raise VaultRewindError("RUNNER_CLEANUP_FAILED", "The isolated test requires journal-based cleanup before another test.",
                                       True, cleanup_result="incomplete",
                                       operation_error_code=original.code if isinstance(original, VaultRewindError) else "APPLICATION_TEST_FAILED") from None
            if isinstance(original, VaultRewindError):
                original.details["cleanup_result"] = "complete"
                raise
            raise VaultRewindError("APPLICATION_TEST_FAILED", "The isolated application test failed and its candidate was retired.",
                                   cleanup_result="complete") from None
        try:
            dispose()
        except Exception:  # noqa: BLE001 - never report retirement without positive remote proof.
            raise VaultRewindError("RUNNER_CLEANUP_FAILED", "The validated test candidate still needs verified retirement.",
                                   True, cleanup_result="incomplete") from None
        return {"application_started": True, "user_login_tested": False, "isolated": True,
                "outbound_access": False, "production_mounts": False, "public_ports": False,
                "cleanup_result": "complete"}



class SQLCredentialStore:
    """Bridge provider credential CAS to encrypted SQL rows without leaking ORM values."""
    def __init__(self, adapters, guard=lambda: None):
        self.adapters, self.guard = adapters, guard
        # Rotated provider tokens must survive both process death and per-job cleanup.
        self.state_directory = (adapters.settings.provider_credential_state_dir or
                                adapters.settings.staging_dir.parent / "provider-credentials")

    def load(self, destination_id):
        from vaultrewind.storage.credentials import StoredCredential, credential_context
        with self.adapters.sessions() as db:
            destination = db.get(StorageDestination, destination_id)
            if not destination or not destination.credential_id:
                return None
            row = db.get(Secret, destination.credential_id)
            value = self.adapters.secrets.get(db, row.id)
            envelope = self.adapters.secrets.box().encrypt(value, context=credential_context(destination_id))
            return StoredCredential(envelope, row.revision, generation=row.id)

    def compare_and_swap(self, destination_id, envelope, expected_revision, *, expected_generation=None):
        from vaultrewind.storage.credentials import credential_context
        self.guard()
        value = self.adapters.secrets.box().decrypt(envelope, context=credential_context(destination_id))
        with self.adapters.sessions.begin() as db:
            destination = db.scalar(select(StorageDestination).where(StorageDestination.id == destination_id).with_for_update())
            if not destination or not destination.credential_id:
                raise VaultRewindError("CREDENTIAL_STALE", "The destination credential was removed or replaced.")
            row = db.scalar(select(Secret).where(Secret.id == destination.credential_id).with_for_update())
            if not row or row.revision != expected_revision or (expected_generation is not None and row.id != expected_generation):
                raise VaultRewindError("CREDENTIAL_STALE", "A newer credential already exists.")
            self.adapters.secrets.replace(db, row.id, value)
            return row.revision

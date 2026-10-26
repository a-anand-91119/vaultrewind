"""Durable worker entry point. Every destructive boundary is journaled and fenced."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import shutil
import signal
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta

from sqlalchemy import func, select

from vaultrewind.core.errors import VaultRewindError

from .adapters import Adapters
from .db import make_engine, now, sessions, uid, utc
from .errors import safe_code
from .models import (
    ActivationPlan,
    BackupPolicy,
    Host,
    Instance,
    Job,
    JobStep,
    Repository,
    ResourceLease,
    Snapshot,
    SnapshotCopy,
    SnapshotProtection,
    StagingAllocation,
    StorageDestination,
    VerificationRun,
)
from .policy import TERMINAL, retention_preview
from .queue import assert_fence, audit, claim, digest, enqueue, ensure_resource, event, finish, heartbeat
from .secrets import Secrets
from .settings import Settings

POST_ACTIVATION = {"activation_started", "activated", "complete", "data_restored_service_stopped", "needs_attention"}
# Journal phases after which the helper holds no further responsibility for the source/target.
REMOTE_SETTLED = {"failed_safe", "captured", "complete", "cancelled", "rolled_back", "data_restored_service_stopped",
                  "cleaned", "needs_attention", "rollback_failed", "source_recovery_failed"}
SAFE_SOURCE = {"running", "stopped", "healthy", "recovered"}
# Codes that describe the controller's view of a lost conversation, not what happened on the host.
TRANSPORT_CODES = {"SSH_TRANSPORT_FAILED", "REMOTE_OUTCOME_UNCERTAIN", "PROTOCOL_LIMIT", "INTERNAL_ERROR", "LEASE_LOST"}
REMOTE_FIELDS = {"phase", "exists", "source_state", "source_service_outcome", "snapshot_uuid", "manifest_hash",
                 "safety_snapshot_uuid", "safety_manifest_hash", "empty_target", "candidate_validated",
                 "activation_started", "active_generation", "bytes", "recovery_verified", "protocol_version"}


class Context:
    def __init__(self, worker, job):
        self.worker, self.id, self.token = worker, job.id, job.fencing_token
        self.owner, self.settings, self.sessions = worker.owner, worker.settings, worker.sessions
        self.store, self.adapters = worker.store, worker.adapters
        self.kind, self.instance_id, self.request = job.kind, job.instance_id, job.request
        self.root = self.settings.staging_dir / self.id
        self._token_lock = threading.RLock()
        self._lost = threading.Event()
        self._stop = threading.Event()

    def adopt_fence_floor(self, floor):
        if type(floor) is not int or not 0 <= floor < 2**63 - 2:
            raise VaultRewindError("REMOTE_FENCE_INVALID", "The remote fencing state could not be verified.")
        if floor < self.token:
            return
        with self._token_lock:
            with self.sessions.begin() as db:
                job = assert_fence(db, self.id, self.owner, self.token)
                token = floor + 1
                job.fencing_token = token
                for lease in db.scalars(select(ResourceLease).where(ResourceLease.owner_job_id == self.id).with_for_update()):
                    lease.generation = token
                job.result = {**job.result, "remote_fence_adopted": True}
            self.token = token

    def guard(self):
        if self._lost.is_set():
            raise VaultRewindError("LEASE_LOST", "The worker lease was lost.")
        with self.sessions.begin() as db:
            return assert_fence(db, self.id, self.owner, self.token)

    @contextmanager
    def keepalive(self):
        def pump():
            while not self._stop.wait(self.settings.lease_seconds / 4):
                try:
                    with self._token_lock, self.sessions.begin() as db:
                        heartbeat(db, self.id, self.owner, self.token, self.settings.lease_seconds)
                except Exception:  # noqa: BLE001 - crash boundary preserves leases and never logs raw exceptions
                    self._lost.set()
                    return
        thread = threading.Thread(target=pump, name=f"lease-{self.id}", daemon=True)
        # In-memory SQLite uses a single shared connection; tests explicitly renew at phase boundaries.
        if self.worker.engine.dialect.name != "sqlite":
            thread.start()
        try:
            yield
        finally:
            self._stop.set()
            if thread.is_alive():
                thread.join(timeout=2)

    def phase(self, name):
        with self.sessions.begin() as db:
            job = assert_fence(db, self.id, self.owner, self.token)
            job.phase = name
            heartbeat(db, self.id, self.owner, self.token, self.settings.lease_seconds)
            event(db, job, "PHASE_STARTED")

    def update(self, **values):
        with self.sessions.begin() as db:
            job = assert_fence(db, self.id, self.owner, self.token)
            for field, value in values.items():
                if field == "result":
                    job.result = {**job.result, **value}
                else:
                    setattr(job, field, value)

    def step(self, name, callback, *, reconcile=None):
        self.guard()
        with self.sessions.begin() as db:
            assert_fence(db, self.id, self.owner, self.token)
            old = db.scalar(select(JobStep).where(JobStep.job_id == self.id, JobStep.name == name))
            if old and old.state == "complete":
                return self.store.get(db, old.evidence["private_evidence_id"])
            ambiguous = old is not None
            if old:
                old.attempt += 1
                old.fencing_token = self.token
            else:
                seq = (db.scalar(select(func.max(JobStep.sequence)).where(JobStep.job_id == self.id)) or 0) + 1
                db.add(JobStep(job_id=self.id, name=name, sequence=seq, fencing_token=self.token))
        if ambiguous and reconcile:
            result = reconcile()
        else:
            result = callback()
        self.guard()
        if result is None:
            result = {}
        with self.sessions.begin() as db:
            assert_fence(db, self.id, self.owner, self.token)
            row = db.scalar(select(JobStep).where(JobStep.job_id == self.id, JobStep.name == name).with_for_update())
            evidence = self.store.put(db, "step_evidence", self.id, result)
            row.evidence = {"private_evidence_id": evidence}
            row.state, row.completed_at = "complete", now()
        return result

    def remote(self, instance_id=None, host_id=None, remote_id=None):
        ident = instance_id or self.instance_id
        if host_id is None:
            with self.sessions() as db:
                host_id = db.get(Instance, ident).host_id
        remote, selected = self.adapters.remote(host_id, ident if ident else remote_id)
        return remote, remote_id or selected

    def request_remote(self, remote, remote_id, verb, payload=None, name=None, accepted_phases=None):
        name = name or verb
        def perform():
            self.guard()
            return asyncio.run(remote.request(verb, remote_id, self.id, self.token, payload))
        def reconcile():
            status = asyncio.run(remote.request("status", remote_id, self.id, self.token))
            if not status.get("exists"):
                if verb in {"capture", "stage_restore", "commit_restore"}:
                    raise VaultRewindError("REMOTE_JOURNAL_MISSING", "The host journal for an issued operation is missing; preserve generations and reconcile locally before retrying.")
                return perform()
            if accepted_phases and status.get("phase") in accepted_phases:
                return status
            if verb in {"preflight", "discover", "status", "cleanup", "rollback", "cancel"}:
                return perform()
            if status.get("phase") == "failed_safe":
                # The host already recovered the source after an interrupted capture/restore; the content is gone.
                raise VaultRewindError(safe_code(status.get("error_code") or "CAPTURE_FAILED_SAFE"),
                                       "The host recovered the source after an interrupted operation; no capture completed.")
            if status.get("phase") in POST_ACTIVATION or status.get("activation_started"):
                raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "Activation may have occurred; preserve the restored generation.")
            # Journal/status has reconciled orphaned work. Never blindly repeat a partially applied transaction.
            raise VaultRewindError("REMOTE_OPERATION_INTERRUPTED", "The interrupted transaction requires recovery before new work.")
        return self.step(name, perform, reconcile=reconcile)

    def reserve(self, minimum=0):
        quota = self.settings.per_job_quota_bytes
        if minimum > quota:
            raise VaultRewindError("INSUFFICIENT_SPACE", "The operation exceeds the per-job staging quota.")
        self.settings.staging_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.settings.staging_dir.is_symlink() or self.settings.staging_dir.stat().st_mode & 0o077:
            raise VaultRewindError("STAGING_UNSAFE", "Staging requires a private directory.")
        with self.sessions.begin() as db:
            assert_fence(db, self.id, self.owner, self.token)
            ensure_resource(db, "controller:quota")
            db.scalar(select(ResourceLease).where(ResourceLease.resource_key == "controller:quota").with_for_update())
            previous = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == self.id))
            if not previous or previous.reserved_bytes < quota:
                used = db.scalar(select(func.coalesce(func.sum(StagingAllocation.reserved_bytes), 0))
                                 .where(StagingAllocation.state != "released"))
                extra = quota - (previous.reserved_bytes if previous else 0)
                if used + extra > self.settings.staging_quota_bytes:
                    raise VaultRewindError("INSUFFICIENT_SPACE", "The global staging quota is exhausted.")
                actual = db.scalar(select(func.coalesce(func.sum(StagingAllocation.actual_bytes), 0))
                                   .where(StagingAllocation.state != "released"))
                outstanding = max(0, used - actual)
                if shutil.disk_usage(self.settings.staging_dir).free < outstanding + extra + self.settings.min_free_bytes:
                    raise VaultRewindError("INSUFFICIENT_SPACE", "The controller staging reserve is insufficient.")
                if previous:
                    previous.reserved_bytes, previous.state, previous.retry_until = quota, "reserved", None
                else:
                    db.add(StagingAllocation(job_id=self.id, reserved_bytes=quota))
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.is_symlink():
            raise VaultRewindError("STAGING_UNSAFE", "Unsafe operation staging directory.")
        os.chmod(self.root, 0o700)

    def usage(self):
        total = sum(p.lstat().st_size for p in self.root.rglob("*") if p.is_file() and not p.is_symlink())
        if total > self.settings.per_job_quota_bytes:
            raise VaultRewindError("INSUFFICIENT_SPACE", "The operation reached its staging quota.")
        with self.sessions.begin() as db:
            row = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == self.id))
            if row:
                row.actual_bytes = total
        return total

    def cancellation(self):
        return self.guard().state == "cancel_requested"

    def finish(self, state):
        with self.sessions.begin() as db:
            job = assert_fence(db, self.id, self.owner, self.token)
            finish(db, job, state)
            if self.kind in {"recovery_export", "recovery_import", "drive_import", "drive_exchange"} and self.request.get("secret_id"):
                self.store.replace(db, self.request["secret_id"], {"consumed": True})
            if state not in {"needs_attention", "rollback_failed"}:
                for protection in db.scalars(select(SnapshotProtection).where(SnapshotProtection.job_id == self.id,
                                                SnapshotProtection.reason.in_(["active_restore", "active_test"]))):
                    db.delete(protection)

    def extract(self, archive, target, manifest_hash):
        from vaultrewind.core.archive import safe_extract
        from vaultrewind.core.manifest import verify_snapshot
        if target.exists():
            try:
                return verify_snapshot(target, manifest_hash)
            except VaultRewindError:
                shutil.rmtree(target)
        budget = self.settings.per_job_quota_bytes - self.usage()
        if budget <= 0:
            raise VaultRewindError("INSUFFICIENT_SPACE", "No extraction quota remains.")
        safe_extract(archive, target, max_bytes=budget)
        self.usage()
        return verify_snapshot(target, manifest_hash)

    def cleanup(self, preserve=False):
        from vaultrewind.storage.credentials import has_pending_credentials, has_unrecovered_drive_sessions
        preserve = (preserve or has_pending_credentials(self.root) or has_unrecovered_drive_sessions(self.root)
                    or any(self.root.rglob("rclone.conf")))
        with self.sessions.begin() as db:
            allocation = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == self.id))
            if allocation and preserve:
                # Retained exports/retry content occupies its actual bytes, rather than reserving
                # a whole future capture budget. Resuming work must reserve the full budget again.
                try:
                    actual = sum(p.lstat().st_size for p in self.root.rglob("*") if p.is_file() and not p.is_symlink())
                    allocation.actual_bytes = allocation.reserved_bytes = actual
                except OSError:
                    pass  # Keep the conservative existing reservation if accounting is unavailable.
                allocation.state, allocation.retry_until = "retained", now() + timedelta(days=2)
                return
        try:
            if self.root.exists():
                shutil.rmtree(self.root)
            state, error = "released", None
        except OSError:
            state, error = "cleanup_failed", "CLEANUP_FAILED"
        with self.sessions.begin() as db:
            allocation = db.scalar(select(StagingAllocation).where(StagingAllocation.job_id == self.id))
            if allocation:
                allocation.state, allocation.error_code = state, error


class Worker:
    def __init__(self, settings=None, *, engine=None, adapters=None, owner=None):
        self.settings = settings or Settings()
        self.engine = engine or make_engine(self.settings.database_url)
        self.sessions = sessions(self.engine)
        self.store = Secrets(self.settings)
        self.adapters = adapters or Adapters(self.settings, self.sessions)
        self.owner = owner or f"worker:{uid()}"

    def run_once(self):
        with self.sessions.begin() as db:
            job = claim(db, self.owner, self.settings.lease_seconds, self.settings.global_concurrency)
        if job is None:
            return False
        ctx = Context(self, job)
        try:
            with ctx.keepalive():
                handler = getattr(self, "handle_" + job.kind, None)
                if handler is None:
                    raise VaultRewindError("JOB_UNSUPPORTED", "This job kind is not supported by this worker version.")
                if ctx.cancellation() and not job.reconcile_required:
                    ctx.finish("cancelled")
                    return True
                if job.reconcile_required and self.resume_remote_job(ctx):
                    return True
                handler(ctx)
        except Exception as exc:  # noqa: BLE001 - all tool failures are sanitized before persistence
            self.failure(ctx, exc)
        return True

    def resume_remote_job(self, ctx):
        if ctx.kind not in {"backup", "restore"}:
            return False
        ctx.phase("reconciling")
        remote, rid = ctx.remote()
        status = asyncio.run(remote.request("status", rid, ctx.id, ctx.token))
        if not status.get("exists"):
            if self.remote_change_issued(ctx):
                raise VaultRewindError("REMOTE_JOURNAL_MISSING", "The host journal for an issued operation is missing; preserve all generations.")
            return False
        phase = status.get("phase")
        if ctx.kind == "restore" and phase in {"complete", "data_restored_service_stopped"}:
            self.require_public_activation(status)
            if (status.get("manifest_hash") != ctx.request["manifest_hash"] or not status.get("candidate_validated")):
                raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "The activation journal does not prove the confirmed content.")
            with self.sessions() as db:
                if not status.get("empty_target"):
                    safety = db.scalar(select(Snapshot).where(Snapshot.safety_for_job_id == ctx.id))
                    protected = db.scalar(select(SnapshotProtection.id).where(SnapshotProtection.snapshot_id == safety.id,
                                             SnapshotProtection.reason == "safety")) if safety else None
                    durable = db.scalar(select(SnapshotCopy.id).join(Repository).join(StorageDestination)
                        .where(SnapshotCopy.snapshot_id == safety.id, SnapshotCopy.state == "complete",
                               SnapshotCopy.manifest_hash == safety.manifest_hash, StorageDestination.backend == "local")) if safety else None
                    if not safety or safety.manifest_hash != status.get("safety_manifest_hash") or not protected or not durable:
                        raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "The durable pinned safety evidence is incomplete.")
            view = asyncio.run(remote.request("discover", rid, ctx.id, ctx.token))
            physical = asyncio.run(remote.request("preflight", rid, ctx.id, ctx.token, {"controller_time": now().isoformat()}))
            if not view.get("fingerprint"):
                raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "The active target identity cannot be verified.")
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                target = db.get(Instance, ctx.instance_id)
                if target.fingerprint != view["fingerprint"]:
                    target.fingerprint = view["fingerprint"]
                    target.revision += 1
                target.physical_keys = physical["resource_keys"]
                target.physical_identity = digest(sorted(target.physical_keys))
                for resource in target.physical_keys:
                    ensure_resource(db, f"mount:{resource}")
                target.active_generation = status.get("active_generation")
                target.source_health = status.get("source_service_outcome", "unknown")
                configuration = self.store.get(db, target.configuration_secret_id)
                configuration["source_public_ports_ready"] = physical.get("current_public_ports_ready")
                configuration["restore_enabled"] = physical.get("restore_ready") is True
                configuration["restore_error_code"] = physical.get("restore_error_code")
                self.store.replace(db, target.configuration_secret_id, configuration)
            ctx.update(target_activation_outcome=phase, content_commit="complete",
                source_service_outcome=status.get("source_service_outcome", "unknown"),
                result={"active_generation": status.get("active_generation"), "candidate_validated": True,
                        "restored_bytes_verified": True, "application_started": phase == "complete",
                        "public_ports_verified": status.get("public_ports_verified", False),
                        "public_endpoint_verified": status.get("public_endpoint_verified", False),
                        "user_login_tested": False})
            ctx.finish("succeeded")
            ctx.cleanup()
            return True
        if ctx.kind == "restore" and (status.get("activation_started") or phase in POST_ACTIVATION):
            raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "Activation requires non-destructive reconciliation.")
        if phase in {"rolled_back", "cancelled", "failed_safe"}:
            source = status.get("source_service_outcome")
            original = (self.step_result(ctx, "preflight") or {}).get("source_state")
            if source not in {"running", "stopped", "absent"} or (original in SAFE_SOURCE and source != original):
                raise VaultRewindError("SOURCE_RECOVERY_FAILED", "The remote journal has not verified its original service state.")
            with self.sessions.begin() as db:
                job = assert_fence(db, ctx.id, self.owner, ctx.token)
                # The explicit reconcile proves the host recovered; report why the operation failed, not the recovery.
                failure_code = job.result.get("failure_code")
                if not failure_code or failure_code in TRANSPORT_CODES:
                    failure_code = safe_code(status.get("error_code") or ("CAPTURE_FAILED_SAFE" if ctx.kind == "backup"
                                                                           else "REMOTE_OPERATION_INTERRUPTED"))
                job.error_code = failure_code
                job.result = {**job.result, "remote_phase": phase, "source_recovery": "confirmed",
                              "original_source_state": original}
            ctx.update(source_service_outcome=source)
            ctx.finish("rolled_back" if ctx.kind == "restore" else "failed")
            ctx.cleanup(preserve=ctx.kind == "backup")
            return True
        return False

    def step_result(self, ctx, name):
        """Stored private evidence of a completed step, or None."""
        with self.sessions() as db:
            row = db.scalar(select(JobStep).where(JobStep.job_id == ctx.id, JobStep.name == name,
                                                  JobStep.state == "complete"))
            if not row or not row.evidence.get("private_evidence_id"):
                return None
            return self.store.get(db, row.evidence["private_evidence_id"], upgrade=False)

    def await_remote_settled(self, ctx, remote, rid, window_seconds):
        """Poll the helper journal until it settles or the bounded window ends.

        A busy physical lock or a dropped connection means the host-local recovery is still running; that is
        not evidence of failure. Returns ``(status, settled)``; ``status`` is the last sanitized status view.
        """
        deadline, delay, last = time.monotonic() + window_seconds, 1.0, {"exists": True, "phase": "unknown"}
        while True:
            ctx.guard()
            try:
                last = asyncio.run(remote.request("status", rid, ctx.id, ctx.token))
                if not last.get("exists") or last.get("phase") in REMOTE_SETTLED:
                    return last, True
            except VaultRewindError as error:
                if error.code not in {"RESOURCE_BUSY", "REMOTE_OUTCOME_UNCERTAIN", "SSH_TRANSPORT_FAILED",
                                      "RECONCILIATION_REQUIRED"}:
                    raise
                last = {"exists": True, "phase": "unknown", "status_error": safe_code(error.code)}
            if time.monotonic() >= deadline:
                return last, False
            time.sleep(delay)
            delay = min(delay * 1.5, 15.0)

    def failure(self, ctx, exc):
        code = safe_code(exc.code) if isinstance(exc, VaultRewindError) else "INTERNAL_ERROR"
        if code == "LEASE_LOST":
            return
        try:
            ctx.guard()
        except VaultRewindError:
            return
        original_code = code
        with self.sessions.begin() as db:
            job = assert_fence(db, ctx.id, self.owner, ctx.token)
            # The first failure is evidence; later reconciliation may change the state but never erases it.
            job.result = {**job.result, "failure_code": original_code, "failure_phase": job.phase}
            if isinstance(exc, VaultRewindError):
                from vaultrewind.core.errors import safe_transport_details
                job.result.update({"failure_" + k: v for k, v in safe_transport_details(exc.details).items()})
            event(db, job, original_code)
        # Uncertain remote work must be reconciled before a lease can be released.
        state, retryable = "failed", isinstance(exc, VaultRewindError) and exc.retryable
        if ctx.kind in {"backup", "restore"}:
            try:
                remote, rid = ctx.remote()
                if ctx.kind == "backup":
                    state, code = self.classify_backup_failure(ctx, remote, rid, code)
                else:
                    status = asyncio.run(remote.request("status", rid, ctx.id, ctx.token))
                if ctx.kind == "restore":
                    if not status.get("exists") and self.remote_change_issued(ctx):
                        state, code = "needs_attention", "REMOTE_JOURNAL_MISSING"
                    elif status.get("activation_started") or status.get("phase") in POST_ACTIVATION:
                        if status.get("phase") in {"complete", "data_restored_service_stopped"}:
                            ctx.update(target_activation_outcome=status["phase"],
                                       result={"active_generation": status.get("active_generation")})
                            # Other postconditions are still not proven; retain ownership for explicit reconciliation.
                        state, code = "needs_attention", "RESTORE_ACTIVATION_UNCERTAIN"
                    elif status.get("exists"):
                        recovered = asyncio.run(remote.request("rollback", rid, ctx.id, ctx.token))
                        state = "rolled_back" if recovered.get("phase") == "rolled_back" else "rollback_failed"
                        ctx.update(source_service_outcome=recovered.get("source_service_outcome", "unknown"))
            except VaultRewindError as error:
                if error.code == "LEASE_LOST":
                    return
                state = "needs_attention"
                code = "RESTORE_ACTIVATION_UNCERTAIN" if ctx.kind == "restore" else "SOURCE_RECOVERY_UNCONFIRMED"
                ctx.update(result={"reconciliation_error": safe_code(error.code)})
            except Exception:  # noqa: BLE001 - crash boundary preserves leases and never logs raw exceptions
                state = "needs_attention"
                code = "RESTORE_ACTIVATION_UNCERTAIN" if ctx.kind == "restore" else "SOURCE_RECOVERY_UNCONFIRMED"
        with self.sessions.begin() as db:
            job = assert_fence(db, ctx.id, self.owner, ctx.token)
            job.error_code = code
            if ctx.kind == "verify" and code == "RUNNER_CLEANUP_FAILED" and job.attempts > self.settings.retry_limit:
                state = "needs_attention"  # Preserve runner/resource ownership until explicit cleanup proof.
            if retryable and state == "failed" and job.attempts <= self.settings.retry_limit:
                job.state = "waiting_retry"
                job.next_attempt_at = now() + timedelta(seconds=min(300, 2 ** job.attempts * 5) + random.uniform(0, 2))
                job.lease_expires_at = None
                event(db, job, "RETRY_SCHEDULED", {"attempt": job.attempts})
                # Keep physical ownership across a safe retry.
            else:
                finish(db, job, state)
                if job.kind in {"recovery_export", "recovery_import", "drive_import", "drive_exchange"} and job.request.get("secret_id"):
                    self.store.replace(db, job.request["secret_id"], {"consumed": True})
            if job.kind == "verify":
                copy = db.get(SnapshotCopy, job.request.get("copy_id"))
                if copy:
                    copy.error_code = code
                    db.get(Repository, copy.repository_id).health = "verification_failed"
                verification = db.scalar(select(VerificationRun).where(VerificationRun.job_id == job.id))
                if verification:
                    cleanup = exc.details.get("cleanup_result", "unknown") if isinstance(exc, VaultRewindError) else "unknown"
                    verification.result, verification.cleanup_result = "failed", cleanup
            if job.instance_id and job.kind in {"backup", "verify", "restore", "delete", "retention"}:
                instance = db.get(Instance, job.instance_id)
                if job.kind == "backup":
                    instance.backup_health = "failed"
                from .notifications import raise_alert
                raise_alert(db, job.instance_id, code)
        ctx.cleanup(preserve=ctx.kind in {"backup", "restore"} or code in {"STORAGE_TOKEN_PERSIST_FAILED", "CREDENTIAL_PERSIST_FAILED", "RUNNER_CLEANUP_FAILED"})

    def classify_backup_failure(self, ctx, remote, rid, code):
        """Decide the backup job's end state from the host journal, never from the lost conversation alone.

        The helper owns source recovery (watchdog, boot reconciliation). The controller waits a bounded window
        for the journal to settle, confirms the source returned to its original service state and keeps the
        real failure code (for example OUTAGE_BUDGET_EXCEEDED) instead of relabeling it as a source failure.
        """
        preflight = self.step_result(ctx, "preflight") or {}
        original_state = preflight.get("source_state")
        window = min(max(int(ctx.request.get("outage_seconds") or 300), 30) + 90, 600)
        status, settled = self.await_remote_settled(ctx, remote, rid, window)
        source = status.get("source_service_outcome") or "unknown"
        if settled and status.get("exists") and status.get("phase") != "captured" and source not in SAFE_SOURCE:
            # Terminal journal without a recovered source: ask the helper to recover once, then re-read.
            asyncio.run(remote.request("cancel", rid, ctx.id, ctx.token))
            status, settled = self.await_remote_settled(ctx, remote, rid, min(window, 120))
            source = status.get("source_service_outcome") or "unknown"
        state = "failed"
        if not status.get("exists") and self.remote_change_issued(ctx):
            state, code = "needs_attention", "REMOTE_JOURNAL_MISSING"
        if status.get("exists"):
            remote_code = safe_code(status.get("error_code") or "")
            if code in TRANSPORT_CODES and remote_code != "INTERNAL_ERROR":
                code = remote_code  # the journal explains what the host actually did
            if not settled:
                state, code = "needs_attention", "SOURCE_RECOVERY_UNCONFIRMED"
            elif source not in SAFE_SOURCE or (original_state in SAFE_SOURCE and source != original_state):
                state, code = "needs_attention", "SOURCE_RECOVERY_FAILED"
        ctx.update(source_service_outcome=source, result={
            "remote_phase": status.get("phase"), "source_recovery": "unconfirmed" if not settled
            else ("confirmed" if state == "failed" else "failed"), "original_source_state": original_state})
        return state, code

    def remote_change_issued(self, ctx):
        with self.sessions() as db:
            return bool(db.scalar(select(JobStep.id).where(JobStep.job_id == ctx.id,
                JobStep.name.in_(["capture", "stage_restore", "prepare_safety", "switch_validate", "activate"])).limit(1)))

    @staticmethod
    def require_public_activation(status):
        if status.get("phase") == "complete" and (status.get("public_ports_verified") is not True
                or status.get("public_endpoint_verified") is not True):
            raise VaultRewindError("PUBLIC_READINESS_UNCONFIRMED", "The helper has not proved the approved public endpoint; preserve the activated generation and reconcile it.")

    def catalog_capture(self, ctx, verified, *, safety=False):
        manifest = verified["manifest"]
        captured = datetime.fromisoformat(manifest["captured_at"])
        started = datetime.fromisoformat(manifest["capture_started_at"])
        if abs((now() - utc(captured)).total_seconds()) > 7 * 86400 or utc(captured) > now() + timedelta(seconds=self.settings.clock_skew_seconds):
            raise VaultRewindError("CLOCK_SKEW", "Capture time cannot be reconciled with controller UTC.")
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            row = db.get(Snapshot, manifest["snapshot_uuid"])
            if row and row.manifest_hash != verified["manifest_hash"]:
                raise VaultRewindError("SNAPSHOT_IDENTITY_CONFLICT", "Immutable snapshot content changed.")
            if not row:
                row = Snapshot(id=manifest["snapshot_uuid"], instance_id=ctx.instance_id,
                    captured_at=captured, capture_started_at=started, trigger="safety" if safety else ctx.request.get("trigger", "manual"),
                    manifest_hash=verified["manifest_hash"], completeness="complete",
                    logical_bytes=verified.get("logical_bytes", sum(x.get("size", 0) for x in manifest["inventory"])),
                    image_id=manifest["image_id"], vaultwarden_version=manifest.get("vaultwarden_version", "recorded-image"),
                    source_state=manifest["source_state"], verification={"capture_validated": True,
                        "database_schema_evidence": manifest.get("database_schema_evidence", {}),
                        "helper_version": manifest.get("helper_version"), "platform": manifest.get("platform"),
                        "image_archive_hash": manifest.get("image_archive_hash"),
                        "deployment_fingerprint": manifest.get("deployment_fingerprint")},
                    safety_for_job_id=ctx.id if safety else None)
                db.add(row)
                db.flush()
                if safety:
                    db.add(SnapshotProtection(snapshot_id=row.id, reason="safety", job_id=ctx.id))
            return row.id

    def commit_copy(self, ctx, snapshot_id, repository_id, root):
        from vaultrewind.core.manifest import manifest_hash
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            snapshot = db.get(Snapshot, snapshot_id)
            copy = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot_id,
                                                        SnapshotCopy.repository_id == repository_id))
            if not copy:
                copy = SnapshotCopy(id=uid(), snapshot_id=snapshot_id, repository_id=repository_id, state="committing")
                db.add(copy)
            elif copy.state == "complete":
                return {"copy_id": copy.id, "restic_snapshot_id": copy.restic_snapshot_id,
                        "manifest_hash": copy.manifest_hash, "stored_copy_verified": True}
            copy_id, capture_time, expected = copy.id, utc(snapshot.captured_at).isoformat(), snapshot.manifest_hash
            kind = "safety" if snapshot.safety_for_job_id else "backup"
            logical_bytes = snapshot.logical_bytes
            destination = db.get(StorageDestination, db.get(Repository, repository_id).destination_id)
            quota_exceeded = False
            if destination.quota_bytes is not None:
                used = db.scalar(select(func.coalesce(func.sum(SnapshotCopy.logical_bytes), 0))
                                 .join(Repository).where(Repository.destination_id == destination.id,
                                                        SnapshotCopy.state == "complete"))
                if used + snapshot.logical_bytes > destination.quota_bytes:
                    quota_exceeded = True
        def commit():
            with self.adapters.repository(repository_id, ctx.root, ctx.guard, required_bytes=logical_bytes) as repo:
                # initialize is itself idempotent and refuses incompatible/incorrect-key repositories.
                repo.initialize()
                # Adapter reconciles UUID commit acknowledgement loss; never change logical snapshot ID.
                result = repo.commit(root, snapshot_id, capture_time, kind=kind)
                if not result.get("stored_copy_verified") or result.get("manifest_hash") != expected:
                    raise VaultRewindError("SNAPSHOT_INCOMPLETE", "The committed copy could not be verified.")
                readback = repo.read_manifest(result["restic_snapshot_id"])
                if manifest_hash(readback) != expected or readback["snapshot_uuid"] != snapshot_id:
                    raise VaultRewindError("SNAPSHOT_INCOMPLETE", "Stored manifest differs from the captured recovery point.")
                return result
        try:
            if quota_exceeded:
                raise VaultRewindError("INSUFFICIENT_SPACE", "The selected destination quota would be exceeded.")
            result = ctx.step(f"commit:{copy_id}", commit, reconcile=commit)
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                copy = db.get(SnapshotCopy, copy_id)
                copy.state, copy.restic_snapshot_id, copy.manifest_hash = "complete", result["restic_snapshot_id"], expected
                copy.logical_bytes, copy.stored_bytes = result.get("logical_bytes"), result.get("stored_bytes")
                copy.verified_at, copy.error_code = now(), None
                repository_row = db.get(Repository, repository_id)
                if repository_row.health != "verification_failed":
                    repository_row.health = "healthy"
                private = self.store.get(db, repository_row.configuration_secret_id)
                actual_id = result.get("repository_id")
                if actual_id:
                    if private.get("restic_repository_id") and private["restic_repository_id"] != actual_id:
                        raise VaultRewindError("REPOSITORY_IDENTITY_CHANGED", "The physical repository identity changed.")
                    private["restic_repository_id"] = actual_id
                    self.store.replace(db, repository_row.configuration_secret_id, private)
                db.get(StorageDestination, destination.id).health = "healthy"
            return {**result, "copy_id": copy_id}
        except Exception as exc:
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                copy = db.get(SnapshotCopy, copy_id)
                copy.state, copy.error_code = "uncertain" if getattr(exc, "retryable", False) else "failed", safe_code(getattr(exc, "code", "INTERNAL_ERROR"))
                db.get(Repository, repository_id).health = "uncertain"
                from vaultrewind.storage.errors import CREDENTIAL_STATE_BY_CODE
                db.get(StorageDestination, destination.id).health = CREDENTIAL_STATE_BY_CODE.get(copy.error_code, "unhealthy")
            raise

    def handle_backup(self, ctx):
        ctx.phase("preflight")
        with self.sessions() as db:
            instance = db.get(Instance, ctx.instance_id)
            if instance.revision != ctx.request["configuration_revision"] or instance.fingerprint != ctx.request["fingerprint"]:
                raise VaultRewindError("TARGET_CHANGED", "Source configuration changed before capture.")
        remote, rid = ctx.remote()
        preflight = ctx.request_remote(remote, rid, "preflight", {"controller_time": now().isoformat(),
                        "expected_fingerprint": ctx.request["fingerprint"]})
        if preflight.get("protocol_version") != 1 or not preflight.get("recovery_verified"):
            raise VaultRewindError("HELPER_NOT_READY", "Helper recovery/version checks failed.")
        if set(preflight.get("resource_keys", [])) != set(instance.physical_keys):
            raise VaultRewindError("TARGET_CHANGED", "Physical mounts changed since enrollment.")
        ctx.reserve(preflight.get("estimated_data_bytes", 0) * 2)
        ctx.phase("preparing")
        identity = ctx.step("capture_identity", lambda: {"snapshot_id": uid(), "controller_time": now().isoformat()})
        if ctx.cancellation():
            ctx.finish("cancelled")
            ctx.cleanup()
            return
        ctx.phase("capturing")
        capture = ctx.request_remote(remote, rid, "capture", {"snapshot_uuid": identity["snapshot_id"],
                    "controller_time": now().isoformat(), "expected_fingerprint": ctx.request["fingerprint"]},
                    accepted_phases={"captured"})
        ctx.phase("resuming_source")
        source = capture.get("source_service_outcome", "unknown")
        ctx.update(source_service_outcome=source)
        # A valid capture can be committed even if source recovery subsequently failed, but never overall success.
        if not capture.get("manifest_hash"):
            raise VaultRewindError("SNAPSHOT_INCOMPLETE", "The remote capture did not produce immutable verified content.")
        ctx.phase("transferring")
        archive = ctx.root / "capture.tar"
        def export():
            if archive.exists():
                return {"bytes": archive.stat().st_size}
            return asyncio.run(remote.export(rid, ctx.id, ctx.token, archive))
        ctx.step("export", export, reconcile=export)
        ctx.phase("validating")
        verified = ctx.extract(archive, ctx.root / "snapshot", capture["manifest_hash"])
        if verified["manifest"]["snapshot_uuid"] != identity["snapshot_id"] or verified["manifest"]["instance_uuid"] != rid:
            raise VaultRewindError("SNAPSHOT_IDENTITY_CONFLICT", "Capture belongs to a different enrolled source.")
        snapshot_id = self.catalog_capture(ctx, verified)
        ctx.update(result={"snapshot_id": snapshot_id})
        if ctx.cancellation():
            status = ctx.request_remote(remote, rid, "status")
            if status.get("source_service_outcome") not in {"running", "stopped", "healthy", "recovered"}:
                raise VaultRewindError("SOURCE_RECOVERY_FAILED", "Source recovery is not confirmed.")
            ctx.finish("cancelled")
            ctx.cleanup()
            return
        ctx.phase("committing_copies")
        successes, required_failures, optional_failures = 0, 0, 0
        for destination in ctx.request["repositories"]:
            ctx.guard()
            try:
                self.commit_copy(ctx, snapshot_id, destination["repository_id"], ctx.root / "snapshot")
                successes += 1
            except VaultRewindError as exc:
                if exc.code == "LEASE_LOST":
                    raise
                if destination["required"]:
                    required_failures += 1
                else:
                    optional_failures += 1
        status = ctx.request_remote(remote, rid, "status", name="source_final_status")
        source = status.get("source_service_outcome", source)
        source_ok = source == preflight.get("source_state")
        ctx.phase("finalizing")
        ctx.update(content_commit="complete" if successes else "failed",
                   required_copy_outcome="failed" if required_failures else "complete",
                   source_service_outcome=source,
                   error_code="SOURCE_RECOVERY_FAILED" if not source_ok else "REQUIRED_COPY_FAILED" if required_failures else "OPTIONAL_COPY_FAILED" if optional_failures else None)
        state = "succeeded" if not required_failures and source_ok else "partial" if successes else "failed"
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            inst = db.get(Instance, ctx.instance_id)
            inst.source_health = source
            inst.backup_health = "healthy" if state == "succeeded" and not optional_failures else "degraded"
            if state == "succeeded":
                inst.last_complete_at = db.get(Snapshot, snapshot_id).captured_at
                from .notifications import clear_alerts
                clear_alerts(db, ctx.instance_id, {"REQUIRED_COPY_FAILED", "OPTIONAL_COPY_FAILED", "SOURCE_RECOVERY_FAILED", "BACKUP_OVERDUE"})
                if not optional_failures:
                    enqueue(db, kind="retention", request={"instance_id": inst.id},
                            key=f"retention:{ctx.id}", instance_id=inst.id)
            if required_failures or optional_failures or not source_ok:
                from .notifications import raise_alert
                raise_alert(db, ctx.instance_id, "SOURCE_RECOVERY_FAILED" if not source_ok else "REQUIRED_COPY_FAILED" if required_failures else "OPTIONAL_COPY_FAILED")
        # Retain staging on a copy failure for same-content retry; source has already recovered.
        ctx.request_remote(remote, rid, "cleanup", {"kind": "staging"}, name="cleanup_remote") if not required_failures and not optional_failures else None
        ctx.finish(state if source_ok else "needs_attention")
        ctx.cleanup(preserve=bool(required_failures or optional_failures or not source_ok))

    def restore_input(self, ctx, snapshot, copy, name="input"):
        from vaultrewind.core.manifest import verify_snapshot
        target = ctx.root / name
        def read():
            if target.exists():
                try:
                    verify_snapshot(target, snapshot.manifest_hash)
                    return {"restored_bytes_verified": True}
                except VaultRewindError:
                    shutil.rmtree(target)
            with self.adapters.repository(copy.repository_id, ctx.root, ctx.guard) as repo:
                repo.restore(copy.restic_snapshot_id, target)
            ctx.usage()
            verify_snapshot(target, snapshot.manifest_hash)
            return {"restored_bytes_verified": True}
        ctx.step(f"read:{name}", read, reconcile=read)
        # Cached evidence never replaces checking the staged bytes after controller restart.
        return verify_snapshot(target, snapshot.manifest_hash)

    def handle_restore(self, ctx):
        from vaultrewind.core.archive import create_archive
        ctx.phase("planning")
        with self.sessions() as db:
            target = db.get(Instance, ctx.instance_id)
            snapshot = db.get(Snapshot, ctx.request["snapshot_id"])
            copy = db.get(SnapshotCopy, ctx.request["copy_id"])
            policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == target.id))
            mapping = self.store.get(db, ctx.request["mappings_secret_id"])
            if (target.revision != ctx.request["target_revision"] or target.fingerprint != ctx.request["fingerprint"] or
                    policy.revision != ctx.request["policy_revision"] or snapshot.manifest_hash != ctx.request["manifest_hash"] or
                    copy.state != "complete"):
                raise VaultRewindError("TARGET_CHANGED", "The confirmed restore inputs changed.")
            local_repos = list(db.scalars(select(Repository).join(StorageDestination)
                .where(Repository.instance_id == target.id, StorageDestination.backend == "local")))
        ctx.reserve(snapshot.logical_bytes * 2)
        remote, rid = ctx.remote()
        # Check target profile and available space before downloading/stopping it.
        preflight = ctx.request_remote(remote, rid, "preflight", {"controller_time": now().isoformat(),
            "expected_fingerprint": ctx.request["fingerprint"]}, name="restore_preflight")
        if preflight.get("protocol_version") != 1 or not preflight.get("recovery_verified"):
            raise VaultRewindError("HELPER_NOT_READY", "Restore requires verified helper recovery facilities.")
        if preflight.get("restore_ready") is not True:
            raise VaultRewindError("TARGET_NOT_READY", "The approved restore network is unready or the helper needs an update.")
        if set(preflight.get("resource_keys", [])) != set(target.physical_keys):
            raise VaultRewindError("TARGET_CHANGED", "Physical target resources changed.")
        if not preflight.get("empty_target") and not local_repos:
            raise VaultRewindError("LOCAL_SAFETY_NOT_CONFIGURED", "Configure an encrypted durable local safety repository before replacement.")
        if not preflight.get("empty_target"):
            # Verify persistent mount, safety key, repository and reserved safety budget before target downtime.
            safety_repo = local_repos[0]
            with self.adapters.repository(safety_repo.id, ctx.root, ctx.guard, required_bytes=self.settings.per_job_quota_bytes) as repo:
                repo.initialize()
            estimate = preflight.get("estimated_data_bytes", 0)
            with self.sessions() as db:
                used = db.scalar(select(func.coalesce(func.sum(func.coalesce(SnapshotCopy.stored_bytes, SnapshotCopy.logical_bytes)), 0))
                                 .join(Snapshot, Snapshot.id == SnapshotCopy.snapshot_id)
                                 .where(Snapshot.safety_for_job_id.is_not(None), SnapshotCopy.state == "complete"))
            if used + estimate > self.settings.safety_quota_bytes or estimate * 2 + ctx.usage() > self.settings.per_job_quota_bytes:
                raise VaultRewindError("INSUFFICIENT_SPACE", "The reserved safety snapshot capacity is insufficient.")
        ctx.phase("reading_snapshot")
        self.restore_input(ctx, snapshot, copy)
        if ctx.cancellation():
            ctx.finish("cancelled")
            ctx.cleanup()
            return
        ctx.phase("staging")
        archive = ctx.root / "restore.tar"
        def pack():
            if archive.exists():
                archive.unlink()
            create_archive(ctx.root / "input", archive)
            ctx.usage()
            return {"bytes": archive.stat().st_size}
        ctx.step("restore_archive", pack, reconcile=pack)
        if not archive.exists():
            pack()
        def stage():
            return asyncio.run(remote.upload_restore(rid, ctx.id, ctx.token, archive, {
                "manifest_hash": snapshot.manifest_hash, "expected_fingerprint": ctx.request["fingerprint"],
                "start_on_completion": mapping["start_on_completion"], "controller_time": now().isoformat()}))
        def reconcile_stage():
            status = asyncio.run(remote.request("status", rid, ctx.id, ctx.token))
            if not status.get("exists"):
                raise VaultRewindError("REMOTE_JOURNAL_MISSING", "The staged restore journal is missing; preserve generations and reconcile locally.")
            if status.get("phase") in {"staged", "safety_ready", "candidate_validated", "complete", "data_restored_service_stopped"}:
                return status
            if status.get("activation_started") or status.get("phase") in POST_ACTIVATION:
                raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "Activation may have occurred.")
            raise VaultRewindError("REMOTE_OPERATION_INTERRUPTED", "Reconcile the incomplete target generation before a new restore.")
        ctx.step("stage_restore", stage, reconcile=reconcile_stage)
        ctx.phase("preparing_safety")
        safety = ctx.request_remote(remote, rid, "commit_restore", {"phase": "prepare_safety"},
                name="prepare_safety", accepted_phases={"safety_ready", "candidate_validated", "complete", "data_restored_service_stopped"})
        acknowledgment = None
        if not safety.get("empty_target"):
            if not safety.get("safety_snapshot_uuid") or not safety.get("safety_manifest_hash"):
                raise VaultRewindError("SAFETY_REQUIRED", "The target safety capture is incomplete.")
            ctx.phase("capturing_safety")
            safety_archive = ctx.root / "safety.tar"
            def export_safety():
                if safety_archive.exists():
                    return {"bytes": safety_archive.stat().st_size}
                return asyncio.run(remote.export(rid, ctx.id, ctx.token, safety_archive, {"kind": "safety"}))
            ctx.step("export_safety", export_safety, reconcile=export_safety)
            verified = ctx.extract(safety_archive, ctx.root / "safety", safety["safety_manifest_hash"])
            if verified["manifest"]["snapshot_uuid"] != safety["safety_snapshot_uuid"]:
                raise VaultRewindError("SAFETY_REQUIRED", "Safety content differs from its immutable transaction identity.")
            safety_id = self.catalog_capture(ctx, verified, safety=True)
            committed = self.commit_copy(ctx, safety_id, local_repos[0].id, ctx.root / "safety")
            acknowledgment = {"snapshot_uuid": safety_id, "manifest_hash": safety["safety_manifest_hash"],
                              "restic_snapshot_id": committed["restic_snapshot_id"], "repository_id": local_repos[0].id,
                              "durable": True, "encrypted": True, "pinned": True, "stored_copy_verified": True}
            ctx.update(result={"safety_snapshot_id": safety_id})
        if ctx.cancellation():
            restored = ctx.request_remote(remote, rid, "rollback", name="cancel_rollback")
            if restored.get("phase") != "rolled_back":
                raise VaultRewindError("ROLLBACK_FAILED", "Cancellation could not verify the original target recovery.")
            ctx.update(source_service_outcome=restored.get("source_service_outcome", "unknown"))
            ctx.finish("cancelled")
            ctx.cleanup()
            return
        ctx.phase("switching")
        candidate = ctx.request_remote(remote, rid, "commit_restore", {"phase": "switch_validate", "safety_ack": acknowledgment},
                       name="switch_validate", accepted_phases={"candidate_validated", "complete", "data_restored_service_stopped"})
        if not candidate.get("candidate_validated"):
            raise VaultRewindError("CANDIDATE_NOT_VALIDATED", "Public activation requires successful isolated application validation.")
        ctx.phase("validating_candidate")
        ctx.update(target_activation_outcome="candidate_validated", result={"candidate_validated": True})
        if ctx.cancellation():
            rollback = ctx.request_remote(remote, rid, "rollback", name="cancel_validated_rollback")
            if rollback.get("phase") != "rolled_back":
                raise VaultRewindError("ROLLBACK_FAILED", "The original target recovery was not verified.")
            ctx.finish("cancelled")
            ctx.cleanup()
            return
        ctx.phase("activating")
        # Persist the controller decision before any public exposure can happen.
        ctx.update(target_activation_outcome="activation_started", result={"activation_started": True})
        activation = ctx.request_remote(remote, rid, "commit_restore", {"phase": "activate"}, name="activate",
                                       accepted_phases={"complete", "data_restored_service_stopped"})
        if activation.get("phase") not in {"complete", "data_restored_service_stopped"}:
            raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "The restored generation's final service state is unresolved.")
        self.require_public_activation(activation)
        ctx.phase("finalizing")
        view = asyncio.run(remote.request("discover", rid, ctx.id, ctx.token))
        physical = asyncio.run(remote.request("preflight", rid, ctx.id, ctx.token, {"controller_time": now().isoformat()}))
        if not view.get("fingerprint"):
            raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "The active deployment identity could not be verified.")
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            target = db.get(Instance, ctx.instance_id)
            target.active_generation = activation.get("active_generation")
            target.source_health = activation.get("source_service_outcome", "unknown")
            target.revision += 1
            target.fingerprint = view["fingerprint"]
            target.physical_keys = physical["resource_keys"]
            target.physical_identity = digest(sorted(target.physical_keys))
            configuration = self.store.get(db, target.configuration_secret_id)
            configuration["source_public_ports_ready"] = physical.get("current_public_ports_ready")
            configuration["restore_enabled"] = physical.get("restore_ready") is True
            configuration["restore_error_code"] = physical.get("restore_error_code")
            self.store.replace(db, target.configuration_secret_id, configuration)
            for resource in target.physical_keys:
                ensure_resource(db, f"mount:{resource}")
            job = db.get(Job, ctx.id)
            job.target_activation_outcome = activation["phase"]
            job.content_commit = "complete"
            job.source_service_outcome = activation.get("source_service_outcome", "unknown")
            job.result = {**job.result, "active_generation": target.active_generation,
                          "restored_bytes_verified": True, "application_started": activation["phase"] == "complete", "user_login_tested": False,
                          "public_ports_verified": activation.get("public_ports_verified", False),
                          "public_endpoint_verified": activation.get("public_endpoint_verified", False)}
        ctx.request_remote(remote, rid, "cleanup", {"kind": "staging"}, name="restore_cleanup")
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_retry_copy(self, ctx):
        from vaultrewind.core.archive import create_archive
        from vaultrewind.core.manifest import verify_snapshot
        with self.sessions() as db:
            snapshot = db.get(Snapshot, ctx.request["snapshot_id"])
            existing = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot.id,
                SnapshotCopy.state == "complete", SnapshotCopy.repository_id != ctx.request["repository_id"]))
        ctx.reserve(snapshot.logical_bytes * 2)
        ctx.phase("reading_snapshot")
        if existing:
            self.restore_input(ctx, snapshot, existing, "snapshot")
        else:
            original = ctx.request.get("original_job_id")
            root = self.settings.staging_dir / original / "snapshot" if original else None
            if root is None or not root.is_dir() or root.is_symlink():
                raise VaultRewindError("COPY_RETRY_UNAVAILABLE", "The immutable capture retry window expired and no equivalent complete copy is available.")
            verify_snapshot(root, snapshot.manifest_hash)
            archive = ctx.root / "retry.tar"
            create_archive(root, archive)
            ctx.extract(archive, ctx.root / "snapshot", snapshot.manifest_hash)
        ctx.phase("committing_copies")
        self.commit_copy(ctx, snapshot.id, ctx.request["repository_id"], ctx.root / "snapshot")
        ctx.update(content_commit="complete", result={"snapshot_id": snapshot.id})
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == snapshot.instance_id))
            from .models import PolicyDestination
            required = list(db.scalars(select(PolicyDestination.repository_id).where(
                PolicyDestination.policy_id == policy.id, PolicyDestination.required.is_(True))))
            complete = set(db.scalars(select(SnapshotCopy.repository_id).where(SnapshotCopy.snapshot_id == snapshot.id,
                                                                              SnapshotCopy.state == "complete")))
            source_job = db.get(Job, ctx.request.get("original_job_id")) if ctx.request.get("original_job_id") else None
            if set(required) <= complete and source_job and source_job.source_service_outcome in {"running", "stopped"}:
                instance = db.get(Instance, snapshot.instance_id)
                instance.last_complete_at = snapshot.captured_at
                instance.backup_health = "healthy"
                db.get(Job, ctx.id).required_copy_outcome = "complete"
                db.get(Job, ctx.id).source_service_outcome = source_job.source_service_outcome
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_verify(self, ctx):
        with self.sessions() as db:
            snapshot = db.get(Snapshot, ctx.request["snapshot_id"])
            copy = db.get(SnapshotCopy, ctx.request["copy_id"])
            if not snapshot or not copy or copy.state != "complete":
                raise VaultRewindError("SNAPSHOT_INCOMPLETE", "Verification needs a complete copy.")
        ctx.reserve(snapshot.logical_bytes if ctx.request["level"] != "full_data" else 0)
        ctx.phase("verifying")
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            run = db.scalar(select(VerificationRun).where(VerificationRun.job_id == ctx.id))
            if not run:
                run = VerificationRun(id=uid(), snapshot_id=snapshot.id, copy_id=copy.id, job_id=ctx.id,
                                      runner_id=ctx.request.get("runner_id"))
                db.add(run)
            run_id = run.id
        evidence = {"user_login_tested": False}
        if ctx.request["level"] == "full_data":
            def full_check():
                with self.adapters.repository(copy.repository_id, ctx.root, ctx.guard) as repo:
                    result = repo.check(read_data=True)
                    # Calling the full-data operation is essential; metadata-only success cannot pass this level.
                    if result.get("full_data_verified") is not True:
                        raise VaultRewindError("VERIFICATION_FAILED", "The repository did not complete a full data read.")
                return {"full_data_verified": True}
            evidence.update(ctx.step("full_data_check", full_check, reconcile=full_check))
        else:
            self.restore_input(ctx, snapshot, copy, "verification")
            evidence["restored_bytes_verified"] = True
            if ctx.request["level"] == "application":
                # This requires a dedicated helper primitive that proves no production mounts/routes/egress.
                # The normal public restore activation primitive must never be used for this purpose.
                method = getattr(self.adapters, "test_application", None)
                if method is None:
                    raise VaultRewindError("EXTERNAL_PREREQUISITE_MISSING", "The isolated application runner adapter is not installed.")
                runner_id = ctx.request.get("runner_id")
                with self.sessions() as db:
                    runner = db.get(Instance, runner_id)
                    source = db.get(Instance, snapshot.instance_id)
                    if not runner or not runner.is_runner or runner.host_id == source.host_id:
                        raise VaultRewindError("RUNNER_UNSAFE", "A separate isolated verification runner is mandatory.")
                result = ctx.step("application_test", lambda: method(runner_id, ctx.root / "verification", ctx.id, ctx.token),
                                  reconcile=lambda: method(runner_id, ctx.root / "verification", ctx.id, ctx.token))
                if (not result.get("application_started") or not result.get("isolated") or
                        result.get("outbound_access") or result.get("production_mounts") or result.get("public_ports")):
                    raise VaultRewindError("RUNNER_UNSAFE", "The runner did not prove the required isolation boundary.")
                if result.get("cleanup_result") != "complete":
                    raise VaultRewindError("RUNNER_CLEANUP_FAILED", "The isolated test runner cleanup did not complete.")
                evidence["application_started"] = True
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            run = db.get(VerificationRun, run_id)
            run.evidence, run.result, run.cleanup_result = evidence, "succeeded", "complete"
            run.duration_seconds = int((now() - utc(run.created_at)).total_seconds())
            snapshot = db.get(Snapshot, snapshot.id)
            # Snapshot content fields never change; verification annotations live in VerificationRun.
            if evidence.get("full_data_verified"):
                db.get(SnapshotCopy, copy.id).data_verified_at = now()
                db.get(Repository, copy.repository_id).last_full_check_at = now()
                db.get(Repository, copy.repository_id).health = "healthy"
            if evidence.get("application_started"):
                db.get(Instance, snapshot.instance_id).last_test_at = now()
        ctx.update(result={"verification_id": run_id, **evidence})
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_retention(self, ctx):
        self.delete_eligible(ctx, explicit=False)

    def handle_delete(self, ctx):
        self.delete_eligible(ctx, explicit=True)

    def delete_eligible(self, ctx, explicit):
        ctx.phase("retention_planning")
        ctx.reserve()
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            preview = retention_preview(db, ctx.instance_id)
            requested = set(ctx.request.get("copy_ids", preview["copy_ids"]))
            if explicit and (preview["policy_revision"] != ctx.request["policy_revision"] or
                             not requested <= set(preview["copy_ids"])):
                raise VaultRewindError("RETENTION_PROTECTED", "Deletion eligibility changed.")
            ids = sorted(requested & set(preview["copy_ids"]))
        deleted, retained = [], []
        by_repo = {}
        with self.sessions() as db:
            for ident in ids:
                copy = db.get(SnapshotCopy, ident)
                by_repo.setdefault(copy.repository_id, []).append(ident)
        for repo_id, copy_ids in sorted(by_repo.items()):
            ctx.phase("forgetting")
            # Recheck under the physical repository lease immediately before exact-ID forget.
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                preview = retention_preview(db, ctx.instance_id)
                if not set(copy_ids) <= set(preview["copy_ids"]):
                    raise VaultRewindError("RETENTION_PROTECTED", "A recovery point gained protection before deletion.")
                copies = [db.get(SnapshotCopy, c) for c in copy_ids]
                restic_ids = [c.restic_snapshot_id for c in copies]
                if any(c.repository_id != repo_id or c.state != "complete" or not c.restic_snapshot_id for c in copies):
                    raise VaultRewindError("RETENTION_PROTECTED", "The deletion set no longer matches its repository.")
            def forget(repo_id=repo_id, copy_ids=copy_ids, restic_ids=restic_ids):
                with self.adapters.repository(repo_id, ctx.root, ctx.guard) as repo:
                    known = {x["restic_snapshot_id"] for x in repo.list_snapshots()}
                    active = [ident for ident in restic_ids if ident in known]
                    # A missing ID after acknowledgement loss is reconciled rather than broadening deletion.
                    if active:
                        repo.forget(active)
                    remaining = {x["restic_snapshot_id"] for x in repo.list_snapshots()}
                    return {"deleted": [c for c, rid in zip(copy_ids, restic_ids) if rid not in remaining],
                            "retained": [c for c, rid in zip(copy_ids, restic_ids) if rid in remaining]}
            result = ctx.step(f"forget:{repo_id}", forget, reconcile=forget)
            deleted.extend(result["deleted"])
            retained.extend(result["retained"])
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                for ident in result["deleted"]:
                    db.get(SnapshotCopy, ident).state = "deleted"
                for ident in result["retained"]:
                    db.get(SnapshotCopy, ident).error_code = "STORAGE_DELETE_DENIED"
                if result["deleted"]:
                    # Pruning is separate, serialized and followed by a repository consistency check.
                    from .queue import resources_for_instance
                    enqueue(db, kind="prune", request={"repository_id": repo_id}, key=f"prune:{ctx.id}:{repo_id}",
                            instance_id=ctx.instance_id, resources=resources_for_instance(db, ctx.instance_id, [repo_id]))
        ctx.update(result={"deleted_copies": deleted, "retained_copies": retained})
        ctx.finish("partial" if retained else "succeeded")
        ctx.cleanup()

    def handle_prune(self, ctx):
        ctx.reserve()
        ctx.phase("pruning")
        with self.sessions() as db:
            preview = retention_preview(db, ctx.instance_id)
            if preview["frozen"]:
                raise VaultRewindError("RETENTION_PROTECTED", "Pruning is frozen while protection is degraded.")
        def prune():
            with self.adapters.repository(ctx.request["repository_id"], ctx.root, ctx.guard) as repo:
                repo.prune()
                checked = repo.check(read_data=False)
                if checked.get("ok") is not True:
                    raise VaultRewindError("REPOSITORY_CHECK_FAILED", "Post-prune repository verification failed.")
            return {"repository_consistent": True}
        ctx.step("prune", prune, reconcile=prune)
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_discover(self, ctx):
        ctx.phase("discovering")
        remote_id = ctx.request.get("instance_id")
        if not remote_id:
            # Unactivated discovery needs the installer/read-only discovery transport, not arbitrary shell.
            method = getattr(self.adapters, "discover_host", None)
            if method is None:
                raise VaultRewindError("EXTERNAL_PREREQUISITE_MISSING", "Install the read-only discovery transport or select an enrolled helper instance ID.")
            result = ctx.step("host_discovery", lambda: method(ctx.request["host_id"]))
        else:
            remote, rid = ctx.remote(host_id=ctx.request["host_id"], remote_id=remote_id)
            view = ctx.request_remote(remote, rid, "discover")
            preflight = ctx.request_remote(remote, rid, "preflight", {"controller_time": now().isoformat(),
                                          "expected_fingerprint": view["fingerprint"]})
            result = {**view, **preflight}
            with self.sessions() as db:
                activation = next((j for j in db.scalars(select(Job).where(Job.kind == "activate", Job.state == "succeeded")
                                                        .order_by(Job.created_at.desc()))
                                   if j.request.get("host_id") == ctx.request["host_id"]), None)
                if activation:
                    approved = db.get(ActivationPlan, activation.request["plan_id"])
                    approved_policy = self.store.get(db, approved.secret_id)["policy"]
                    profile = approved_policy["instances"].get(rid)
                    if profile:
                        result["enrolled_profile"] = {k: profile.get(k) for k in (
                            "capture_budget", "restore_budget", "validation_window", "recovery_profile")}
        ctx.adopt_fence_floor(result.get("fencing_floor", 0))
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            evidence = self.store.put(db, "discovery_evidence", ctx.request["host_id"], result)
            host = db.get(Host, ctx.request["host_id"])
            host.helper_protocol = result.get("protocol_version")
            job = db.get(Job, ctx.id)
            job.result = {"private_evidence_id": evidence, "readiness": "supported" if result.get("recovery_verified") else "blocked",
                          "discovered_instances": [{"remote_instance_id": remote_id, "database_engine": result.get("database_engine"),
                                                    "source_state": result.get("source_state"), "restore_enabled": bool(result.get("restore_enabled"))}]}
        ctx.finish("succeeded")

    def handle_reconcile_host(self, ctx):
        ctx.phase("reconciling_remote")
        from .provisioning import Provisioner
        discovered = Provisioner(self.adapters).admin_request(ctx.request["host_id"], {"mode": "discover"})
        ctx.adopt_fence_floor(discovered.get("fencing_floor", 0))
        remote, rid = ctx.remote(host_id=ctx.request["host_id"], remote_id=ctx.request["remote_instance_id"])
        status = asyncio.run(remote.request("status", rid, ctx.request["operation_id"], ctx.token))
        if status.get("exists") and status.get("phase") not in {"complete", "data_restored_service_stopped", "rolled_back", "cancelled", "captured", "failed_safe", "cleaned"}:
            if status.get("activation_started") or status.get("phase") in POST_ACTIVATION:
                raise VaultRewindError("RESTORE_ACTIVATION_UNCERTAIN", "Preserve the active generation; reconcile it on the host.")
            raise VaultRewindError("RECONCILIATION_REQUIRED", "The previous operation has not reached a confirmed safe terminal state.")
        ctx.update(result={"readiness": "reconciled"})
        ctx.finish("succeeded")

    def handle_activation_plan(self, ctx):
        ctx.phase("planning_activation")
        with self.sessions() as db:
            value = self.store.get(db, ctx.request["secret_id"])
            host = db.get(Host, value["host_id"])
        # The adapter must calculate exact pinned artifact/policy/recovery-unit changes read-only.
        method = getattr(self.adapters, "activation_plan", None)
        if method is None:
            raise VaultRewindError("EXTERNAL_PREREQUISITE_MISSING", "The pinned helper provisioning adapter is not installed.")
        result = ctx.step("activation_plan", lambda: method(host.id, value["policy"]))
        ctx.adopt_fence_floor(result.get("fencing_floor", 0))
        if not result.get("checksum_verified") or result.get("protocol_version") != 1:
            raise VaultRewindError("HELPER_NOT_READY", "Activation requires a pinned artifact checksum and compatible protocol.")
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            private_id = self.store.put(db, "activation_plan", host.id, result)
            plan = ActivationPlan(id=uid(), host_id=host.id, host_revision=value["host_revision"],
                                  plan_hash=digest(result), secret_id=private_id, expires_at=now() + timedelta(minutes=30))
            db.add(plan)
            db.get(Job, ctx.id).result = {"plan_id": plan.id, "plan_hash": plan.plan_hash,
                "expires_at": plan.expires_at.isoformat(), "changes": result.get("safe_changes", []),
                "prerequisites": result.get("safe_prerequisites", [])}
        ctx.finish("succeeded")

    def handle_activate(self, ctx):
        ctx.phase("activating_helper")
        with self.sessions() as db:
            plan = db.get(ActivationPlan, ctx.request["plan_id"])
            host = db.get(Host, ctx.request["host_id"])
            value = self.store.get(db, plan.secret_id)
            if plan.plan_hash != ctx.request["plan_hash"] or host.revision != plan.host_revision:
                raise VaultRewindError("TARGET_CHANGED", "The reviewed helper activation plan changed.")
        method = getattr(self.adapters, "activate", None)
        if method is None:
            raise VaultRewindError("EXTERNAL_PREREQUISITE_MISSING", "The pinned helper provisioning adapter is not installed.")
        result = ctx.step("activate_helper", lambda: method(host.id, value, ctx.id, ctx.token),
                          reconcile=lambda: method(host.id, value, ctx.id, ctx.token, reconcile=True))
        if result.get("protocol_version") != 1 or not result.get("recovery_verified") or not result.get("checksum_verified"):
            raise VaultRewindError("HELPER_NOT_READY", "Helper installation and recovery could not be verified.")
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            host = db.get(Host, host.id)
            host.readiness, host.helper_protocol = "ready", 1
            host.revision += 1
            for instance in db.scalars(select(Instance).where(Instance.host_id == host.id)):
                configuration = self.store.get(db, instance.configuration_secret_id)
                profile = value["policy"]["instances"].get(configuration.get("remote_instance_id"))
                if profile is None:
                    continue
                configuration["recovery_profile"] = profile.get("recovery_profile", {})
                observed = result.get("instance_readiness", {}).get(configuration.get("remote_instance_id"), {})
                if (not observed.get("fingerprint") or
                        set(observed.get("resource_keys") or []) != set(instance.physical_keys)):
                    raise VaultRewindError("TARGET_CHANGED", "Activation could not verify the enrolled physical target.")
                if observed["fingerprint"] != instance.fingerprint:
                    # An empty target's fingerprint includes its approved profile. Accept
                    # that reviewed change, while preserving the enrolled physical roots.
                    # An existing application's descriptor must not change implicitly.
                    if observed.get("empty_target") is not True or profile.get("container_id") is not None:
                        raise VaultRewindError("TARGET_CHANGED", "The enrolled application configuration changed during activation.")
                    instance.fingerprint = observed["fingerprint"]
                configuration["restore_enabled"] = observed.get("restore_ready") is True
                configuration["restore_error_code"] = observed.get("restore_error_code")
                configuration["source_public_ports_ready"] = observed.get("current_public_ports_ready")
                self.store.replace(db, instance.configuration_secret_id, configuration)
                policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == instance.id))
                if policy:
                    policy.outage_seconds = profile.get("capture_budget", 300)
                    policy.maintenance_seconds = profile.get("restore_budget", 900)
                    policy.validation_seconds = profile.get("validation_window", 180)
                    policy.revision += 1
                instance.revision += 1
            job = assert_fence(db, ctx.id, self.owner, ctx.token)
            job.result = {**job.result, "readiness": "ready"}
            # Installation acceptance, enrollment revisions and terminal success are one commit.
            finish(db, job, "succeeded")

    def handle_storage_test(self, ctx):
        ctx.reserve()
        ctx.phase("testing_storage")
        destination_id = ctx.request["destination_id"]
        with self.sessions() as db:
            dest = db.get(StorageDestination, destination_id)
            repos = list(db.scalars(select(Repository).where(Repository.destination_id == dest.id)))
        if dest.backend in {"local", "s3", "drive"} or not repos:
            method = getattr(self.adapters, "test_destination", None)
            if method is None:
                raise VaultRewindError("STORAGE_NOT_CONFIGURED", "Attach the destination to an instance policy before testing its scoped repository.")
            ctx.step("test_destination", lambda: method(destination_id, ctx.root, ctx.guard))
        if repos:
            for repo in repos:
                def test(repository_id=repo.id):
                    with self.adapters.repository(repository_id, ctx.root, ctx.guard) as adapter:
                        adapter.initialize()
                        adapter.list_snapshots()
                        checked = adapter.check(read_data=False)
                        if checked.get("ok") is not True:
                            raise VaultRewindError("REPOSITORY_CHECK_FAILED", "Repository structural verification failed.")
                    return {"accessible": True}
                ctx.step(f"storage_test:{repo.id}", test, reconcile=test)
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            dest = db.get(StorageDestination, destination_id)
            dest.health, dest.last_test_at = "healthy", now()
        ctx.update(result={"destination_id": destination_id})
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_drive_exchange(self, ctx):
        import httpx

        from vaultrewind.storage.drive import GoogleApi, GoogleClient, _finalize
        ctx.phase("authorizing_storage")
        with self.sessions() as db:
            private = self.store.get(db, ctx.request["secret_id"])
            dest = db.get(StorageDestination, private["destination_id"])
            config = self.store.get(db, dest.configuration_secret_id)
            credential = self.store.get(db, dest.credential_id) if dest.credential_id else {}
        client = GoogleClient(credential.get("client_id"), credential.get("client_secret"))
        def exchange():
            with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as http:
                api = GoogleApi(http)
                token = api.exchange_code(client, private["code"], private["verifier"],
                                          self.settings.public_origin + self.settings.drive_redirect_path)
                return _finalize(api, client, token, destination_id=dest.id,
                    previous_refresh=credential.get("token", {}).get("refresh_token"),
                    existing_folder_id=config.get("folder_id"), folder_name=config.get("folder_name"), now=now())
        def ambiguous_exchange():
            raise VaultRewindError("STORAGE_AUTH_EXPIRED", "Authorization exchange was interrupted; reconnect Google Drive.")
        finalized = ctx.step("exchange_code", exchange, reconcile=ambiguous_exchange)
        self.persist_drive(ctx, dest.id, finalized)

    def handle_drive_import(self, ctx):
        import httpx

        from vaultrewind.storage.drive import GoogleClient, import_headless_token
        ctx.phase("authorizing_storage")
        with self.sessions() as db:
            private = self.store.get(db, ctx.request["secret_id"])
            dest = db.get(StorageDestination, private["destination_id"])
            credential = self.store.get(db, dest.credential_id) if dest.credential_id else {}
            config = self.store.get(db, dest.configuration_secret_id)
        client = GoogleClient(credential.get("client_id"), credential.get("client_secret"))
        def refresh():
            with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as http:
                return import_headless_token(client, json.dumps(private["token"]), destination_id=dest.id,
                    existing_folder_id=config.get("folder_id"), folder_name=config.get("folder_name"), http=http)
        finalized = ctx.step("refresh_imported_token", refresh, reconcile=refresh)
        self.persist_drive(ctx, dest.id, finalized)

    def persist_drive(self, ctx, destination_id, finalized):
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            dest = db.get(StorageDestination, destination_id)
            credential = finalized["credential"]
            if dest.credential_id:
                self.store.replace(db, dest.credential_id, credential)
            else:
                dest.credential_id = self.store.put(db, "provider_credentials", dest.id, credential)
            self.store.replace(db, dest.configuration_secret_id, finalized["configuration"])
            dest.health = "authorized_untested"
            dest.revision += 1
            audit(db, db.get(Job, ctx.id).actor_id, "storage.authorized", destination_id, "succeeded")
        ctx.update(result={"destination_id": destination_id})
        ctx.finish("succeeded")

    def catalog_export(self, db):
        from .services import instance_view, job_view, snapshot_view
        return {"schema_version": 1, "exported_at": now().isoformat(),
                "instances": [instance_view(db, i) for i in db.scalars(select(Instance))],
                "snapshots": [snapshot_view(db, s) for s in db.scalars(select(Snapshot))],
                "repositories": [{"id": r.id, "instance_id": r.instance_id, "destination_id": r.destination_id,
                                  "storage_format": r.storage_format, "health": r.health, "imported": r.imported}
                                 for r in db.scalars(select(Repository))],
                "jobs": [job_view(j) for j in db.scalars(select(Job))]}

    def write_artifact(self, ctx, filename, content):
        path = ctx.root / filename
        temporary = path.with_suffix(path.suffix + ".partial")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        ctx.usage()
        ctx.update(result={"artifact_ready": True, "artifact_expires_at": (now() + timedelta(hours=1)).isoformat()})

    def handle_metadata_export(self, ctx):
        ctx.reserve()
        ctx.phase("exporting_metadata")
        with self.sessions() as db:
            catalog = self.catalog_export(db)
        self.write_artifact(ctx, "catalog.json", json.dumps(catalog, sort_keys=True).encode())
        ctx.finish("succeeded")
        ctx.cleanup(preserve=True)

    def handle_recovery_export(self, ctx):
        ctx.reserve()
        ctx.phase("exporting_recovery_kit")
        from .controller_backup import _controller_identity
        with self.sessions.begin() as db:
            controller_id = _controller_identity(db)
        with self.sessions() as db:
            request = self.store.get(db, ctx.request["secret_id"])
            entries = []
            for repo in db.scalars(select(Repository)):
                config = self.store.get(db, repo.configuration_secret_id)
                dest = db.get(StorageDestination, repo.destination_id)
                credentials = self.store.get(db, dest.credential_id) if dest.credential_id else {}
                entries.append({"id": repo.id, "instance_id": repo.instance_id or config.get("controller_id") or controller_id,
                    "purpose": repo.purpose, "destination_id": repo.destination_id,
                    "location": config["location"], "password": self.store.get(db, repo.key_id),
                    "restic_repository_id": config.get("restic_repository_id"),
                    "backend": dest.backend, "credentials": credentials,
                    "configuration": self.store.get(db, dest.configuration_secret_id)})
            payload = {"schema_version": 1, "repositories": entries, "catalog": self.catalog_export(db)}
        from .services import recovery_root
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            root_secret = recovery_root(db, self.store)
            from .models import Secret
            historical_roots = {row.owner_scope: self.store.get(db, row.id) for row in db.scalars(
                select(Secret).where(Secret.kind == "controller_recovery_root"))}
            if controller_id in historical_roots and historical_roots[controller_id] != root_secret:
                raise VaultRewindError("CONTROLLER_RECOVERY_ROOT_CONFLICT", "The controller recovery material conflicts with its imported history.")
            historical_roots[controller_id] = root_secret
        try:
            from vaultrewind.recovery.kit import build_recovery_kit, seal_recovery_kit
        except ImportError:
            raise VaultRewindError("EXTERNAL_PREREQUISITE_MISSING", "The independent recovery-kit implementation is unavailable.") from None
        destinations = {}
        for entry in entries:
            destinations[entry["destination_id"]] = {"destination_id": entry["destination_id"],
                "backend": entry["backend"], "configuration": entry["configuration"],
                "credential": entry["credentials"], "name": entry["backend"]}
        contents = build_recovery_kit(controller_id=controller_id,
            controller_recovery_roots=historical_roots,
            recovery_root_secret=root_secret, destinations=list(destinations.values()),
            repositories=[{**e, "repository_id": e["id"]} for e in entries],
            instances=[{"instance_id": x["id"], "name": x["name"]} for x in payload["catalog"]["instances"]])
        encrypted = seal_recovery_kit(contents, request["passphrase"])
        if isinstance(encrypted, str):
            encrypted = encrypted.encode()
        self.write_artifact(ctx, "recovery-kit.enc", encrypted)
        ctx.finish("succeeded")
        ctx.cleanup(preserve=True)

    def handle_recovery_import(self, ctx):
        ctx.reserve()
        ctx.phase("discovering_recovery_repositories")
        with self.sessions() as db:
            private = self.store.get(db, ctx.request["secret_id"])
        try:
            from vaultrewind.recovery.kit import open_recovery_kit
        except ImportError:
            raise VaultRewindError("EXTERNAL_PREREQUISITE_MISSING", "The independent recovery-kit implementation is unavailable.") from None
        value = open_recovery_kit(private["kit"].encode(), private["passphrase"])
        from .recovery_import import discover_and_plan, private_materials, summarize_plan

        def plan():
            ctx.guard()
            return discover_and_plan(value, ctx.root)[1]
        result = ctx.step("discover_recovery", plan, reconcile=plan)
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            private_id = self.store.put(db, "recovery_import_plan", ctx.id, result)
            materials_id = self.store.put(db, "recovery_import_materials", ctx.id, private_materials(value, work_dir=ctx.root))
            # The kit and passphrase are no longer needed once the plan and its private materials are stored.
            self.store.replace(db, ctx.request["secret_id"], {"consumed": True})
            db.get(Job, ctx.id).result = {"private_evidence_id": private_id, "private_materials_id": materials_id,
                                          "readiness": "review_required", "import_summary": summarize_plan(result)}
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_recovery_apply(self, ctx):
        """Create protected catalog rows from a reviewed import plan; no deletion, restore or schedule."""
        from .recovery_import import apply_import_plan
        ctx.phase("applying_import_plan")
        with self.sessions() as db:
            source = db.get(Job, ctx.request["plan_job_id"])
            if (not source or source.kind != "recovery_import" or source.state != "succeeded"
                    or not source.result.get("private_materials_id")):
                raise VaultRewindError("IMPORT_PLAN_INVALID", "The import plan job is unavailable.")
            plan = self.store.get(db, source.result["private_evidence_id"])
            materials = self.store.get(db, source.result["private_materials_id"])
            actor = db.get(Job, ctx.id).actor_id
            if ctx.request.get("plan_hash") != digest(plan):
                raise VaultRewindError("IMPORT_PLAN_INVALID", "The reviewed import plan changed.")

        def apply():
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                return apply_import_plan(db, self.store, plan, materials, actor_id=actor, job_id=ctx.id)
        summary = ctx.step("apply_import_plan", apply, reconcile=apply)
        ctx.update(result={"apply_summary": {k: v for k, v in summary.items() if k != "conflict_details"},
                           "readiness": "imported_protected"})
        ctx.finish("succeeded")

    def handle_controller_backup(self, ctx):
        from .controller_backup import run_controller_backup
        run_controller_backup(self, ctx)

    def handle_remote_inventory(self, ctx):
        from .remote_maintenance import run_inventory
        run_inventory(self, ctx)

    def handle_remote_cleanup(self, ctx):
        from .remote_maintenance import run_cleanup
        run_cleanup(self, ctx)

    def handle_doctor(self, ctx):
        from .doctor import inspect_catalog
        ctx.phase("inspecting")
        with self.sessions() as db:
            result = inspect_catalog(db)
        # Explicit diagnostic worker may inspect filesystem identity, but does not mutate remote sources.
        ctx.reserve()
        private = ctx.step("doctor_report", lambda: result)
        ctx.update(result={"readiness": private["status"]})
        ctx.finish("succeeded")
        ctx.cleanup()

    def handle_notification(self, ctx):
        from .models import Alert, NotificationChannel, NotificationDelivery
        from .notifications import send
        ctx.phase("delivering_notification")
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            delivery = db.get(NotificationDelivery, ctx.request["delivery_id"])
            channel = db.get(NotificationChannel, delivery.channel_id)
            alert = db.get(Alert, delivery.event_id)
            config = self.store.get(db, channel.configuration_secret_id)
            delivery.attempt += 1
            kind = channel.kind
            payload = {"event_id": alert.id, "instance_id": alert.instance_id, "code": alert.code,
                       "status": "recovered" if delivery.recovery else "active"}
        try:
            # At-least-once delivery after lost acknowledgement; recipients deduplicate by event_id/status.
            ctx.step("deliver", lambda: (send(self.settings, kind, config, payload) or {"delivered": True}),
                     reconcile=lambda: (send(self.settings, kind, config, payload) or {"delivered": True}))
        except VaultRewindError as exc:
            with self.sessions.begin() as db:
                assert_fence(db, ctx.id, self.owner, ctx.token)
                delivery = db.get(NotificationDelivery, ctx.request["delivery_id"])
                delivery.state, delivery.error_code = "failed", safe_code(exc.code)
            raise
        with self.sessions.begin() as db:
            assert_fence(db, ctx.id, self.owner, ctx.token)
            delivery = db.get(NotificationDelivery, ctx.request["delivery_id"])
            delivery.state, delivery.error_code = "delivered", None
        ctx.finish("succeeded")

    def cleanup_expired(self):
        with self.sessions() as db:
            expired = list(db.scalars(select(StagingAllocation).join(Job).where(
                StagingAllocation.state.in_(["retained", "cleanup_failed"]),
                StagingAllocation.retry_until <= now(), Job.state.in_(TERMINAL - {"needs_attention", "rollback_failed"}))))
        for allocation in expired[:20]:
            # Provider configs retained after a failed token persistence must never be discarded blindly.
            root = self.settings.staging_dir / allocation.job_id
            from vaultrewind.storage.credentials import (
                has_pending_credentials,
                has_unrecovered_drive_sessions,
            )
            if (list(root.glob("drive-*.conf")) or any(root.rglob("rclone.conf")) or has_pending_credentials(root)
                    or has_unrecovered_drive_sessions(root)):
                continue
            try:
                if root.exists() and not root.is_symlink():
                    shutil.rmtree(root)
                state, error = "released", None
            except OSError:
                state, error = "cleanup_failed", "CLEANUP_FAILED"
            with self.sessions.begin() as db:
                row = db.get(StagingAllocation, allocation.id)
                row.state, row.error_code = state, error
                row.retry_until = now() + timedelta(hours=1)


def main():
    settings = Settings()
    worker = Worker(settings)
    if worker.engine.dialect.name != "postgresql":
        raise SystemExit("Production workers require PostgreSQL.")
    from vaultrewind.security.redaction import install_log_redaction
    install_log_redaction()
    from .scheduler import tick
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    while not stopping.is_set():
        try:
            with worker.sessions.begin() as db:
                tick(db, settings=settings, store=worker.store)
            worker.cleanup_expired()
            if not worker.run_once():
                time.sleep(settings.poll_seconds)
        except KeyboardInterrupt:
            return
        except Exception as exc:  # noqa: BLE001 - crash boundary preserves leases and never logs raw exceptions
            # Never print connection strings, tool stderr or raw exception objects; the type name is enough.
            logging.getLogger("vaultrewind.worker").error("WORKER_LOOP_ERROR type=%s", type(exc).__name__)
            time.sleep(settings.poll_seconds)


if __name__ == "__main__":
    main()

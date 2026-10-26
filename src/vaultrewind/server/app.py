# ruff: noqa: B008
"""Versioned API. Operational endpoints persist jobs and return without running tools."""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException

from vaultrewind.core.errors import VaultRewindError

from . import auth
from . import schemas as s
from . import services as domain
from .db import make_engine, now, sessions, uid, utc
from .errors import error_body
from .errors import response as error_response
from .models import (
    ActivationPlan,
    Alert,
    AuditEvent,
    BackupPolicy,
    Host,
    Instance,
    Job,
    JobEvent,
    NotificationChannel,
    NotificationDelivery,
    Repository,
    ResourceLease,
    Session,
    Snapshot,
    SnapshotProtection,
    StorageDestination,
    User,
)
from .policy import TERMINAL, next_run, retention_preview
from .queue import audit, digest, enqueue, event, resources_for_instance
from .secrets import Secrets
from .settings import Settings


def create_app(settings: Settings | None = None, *, engine=None):
    settings = settings or Settings()
    engine = engine or make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.dispose()

    app = FastAPI(title="VaultRewind", version="1.0", openapi_url="/api/v1/openapi.json",
                  docs_url=None, redoc_url=None, lifespan=lifespan)
    from vaultrewind.security.redaction import OAuthCallbackScrubber, install_log_redaction
    install_log_redaction()
    from .http_security import BoundedBody
    app.state.settings, app.state.engine = settings, engine
    app.state.sessions, app.state.secrets = sessions(engine), Secrets(settings)

    @app.middleware("http")
    async def security_headers(request, call_next):
        # Reject oversized JSON before its secrets can be buffered by a request parser.
        length = request.headers.get("content-length", "0")
        if not length.isdigit() or int(length) > 6 * 1024 * 1024:
            return JSONResponse(status_code=413, content=error_body("VALIDATION_ERROR"))
        result = await call_next(request)
        result.headers["Cache-Control"] = "no-store"
        result.headers["X-Content-Type-Options"] = "nosniff"
        result.headers["Referrer-Policy"] = "no-referrer"
        result.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        return result

    @app.exception_handler(VaultRewindError)
    async def domain_error(_, exc):
        return error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_, exc):
        return JSONResponse(status_code=422, content=error_body("VALIDATION_ERROR"))

    @app.exception_handler(HTTPException)
    async def http_error(_, exc):
        return JSONResponse(status_code=exc.status_code,
                            content=error_body("NOT_FOUND" if exc.status_code == 404 else "VALIDATION_ERROR"))

    @app.exception_handler(Exception)
    async def unknown_error(_, exc):
        return JSONResponse(status_code=503, content=error_body("INTERNAL_ERROR"))

    def db_session():
        with app.state.sessions() as db:
            try:
                yield db
                db.commit()
            except IntegrityError:
                db.rollback()
                raise VaultRewindError("CONFIGURATION_CONFLICT", "A conflicting registration already exists.") from None
            except BaseException:
                db.rollback()
                raise

    def viewer(request: Request, db=Depends(db_session, scope="function")):
        return auth.current(request, db)[0]

    def administrator(request: Request, db=Depends(db_session, scope="function")):
        return auth.admin(request, db)[0]

    def idem(idempotency_key: str | None = Header(None)):
        if not idempotency_key or len(idempotency_key) > 160:
            raise VaultRewindError("IDEMPOTENCY_KEY_REQUIRED", "Supply an Idempotency-Key.")
        return idempotency_key

    def pagination(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        return limit, offset

    def policy(db, ident):
        row = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == ident))
        if row is None:
            raise VaultRewindError("NOT_FOUND", "The policy does not exist.")
        return row

    def private_job(db, kind, body, key, actor, *, resources=None):
        # Fingerprint plaintext transiently; persist input only in an authenticated encrypted envelope.
        import hmac

        from vaultrewind.security.secrets import load_master_key_file
        fingerprint = hmac.digest(load_master_key_file(settings.master_key_file),
                                  ("private-job-input:" + digest(body)).encode(), "sha256").hex()
        existing = db.scalar(select(Job).where(Job.idempotency_scope == f"{actor.id}:{kind}", Job.idempotency_key == key))
        if existing:
            if existing.request.get("input_hash") != fingerprint:
                raise VaultRewindError("IDEMPOTENCY_CONFLICT", "The private request changed.")
            return existing
        secret_id = app.state.secrets.put(db, "job_input", kind, body)
        return enqueue(db, kind=kind, request={"secret_id": secret_id, "input_hash": fingerprint},
                       key=key, actor_id=actor.id, resources=resources or [])

    prefix = "/api/v1"

    @app.post(prefix + "/setup")
    def setup(body: s.Setup, request: Request, response: Response, db=Depends(db_session, scope="function")):
        return auth.setup(db, request, response, body)

    @app.post(prefix + "/sessions")
    def login(body: s.Login, request: Request, response: Response, db=Depends(db_session, scope="function")):
        return auth.login(db, request, response, body)

    @app.get(prefix + "/sessions/current")
    def session_current(request: Request, user=Depends(viewer)):
        return {"user": auth.user_view(user), "csrf_token": request.cookies.get("vr_csrf")}

    @app.delete(prefix + "/sessions/current", status_code=204)
    def logout(request: Request, response: Response, db=Depends(db_session, scope="function"), user=Depends(viewer)):
        _, session = auth.current(request, db)
        session.revoked_at = now()
        response.delete_cookie("vr_session", path="/")
        response.delete_cookie("vr_csrf", path="/")

    @app.post(prefix + "/sessions/revoke")
    def revoke(body: s.Revoke, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        target = domain.get(db, User, body.user_id or user.id)
        for session in db.scalars(select(Session).where(Session.user_id == target.id, Session.revoked_at.is_(None))):
            session.revoked_at = now()
        audit(db, user.id, "session.revoke", target.id)
        return {"revoked": True}

    @app.post(prefix + "/users", status_code=201)
    def create_user(body: s.UserCreate, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        new = User(id=uid(), username=body.username, password_hash=auth.PASSWORDS.hash(body.password),
                   role=body.role, timezone=body.timezone)
        db.add(new)
        db.flush()
        audit(db, user.id, "user.create", new.id)
        return auth.user_view(new)

    @app.patch(prefix + "/users/{ident}")
    def patch_user(ident: str, body: s.UserPatch, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        admins = list(db.scalars(select(User).where(User.role == "administrator", User.active.is_(True))
                                .order_by(User.id).with_for_update()))
        target = domain.get(db, User, ident)
        if target in admins and len(admins) == 1 and (body.active is False or body.role == "viewer"):
            raise VaultRewindError("LAST_ADMINISTRATOR", "Retain at least one active administrator.")
        for field, value in body.model_dump(exclude_unset=True).items():
            if value is None:
                raise VaultRewindError("VALIDATION_ERROR", "Null is not a valid account update.")
            setattr(target, "password_hash" if field == "password" else field,
                    auth.PASSWORDS.hash(value) if field == "password" else value)
        for row in db.scalars(select(Session).where(Session.user_id == target.id)):
            row.revoked_at = now()
        audit(db, user.id, "user.change", target.id, changes={"fields": sorted(body.model_fields_set)})
        return auth.user_view(target) | {"active": target.active}

    @app.get(prefix + "/hosts")
    def hosts(page=Depends(pagination), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        rows = db.scalars(select(Host).order_by(Host.created_at).limit(page[0]).offset(page[1]))
        return {"items": [{k: getattr(h, k) for k in ("id", "name", "endpoint", "port", "username", "readiness",
                           "revision", "helper_protocol", "archived")} for h in rows]}

    @app.post(prefix + "/hosts", status_code=201)
    def create_host(body: s.HostCreate, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        import asyncssh
        try:
            key = asyncssh.import_public_key(body.host_public_key)
            asyncssh.import_private_key(body.private_key, body.passphrase)
            normalized_key = key.export_public_key().decode().strip()
        except (ValueError, asyncssh.Error):
            raise VaultRewindError("VALIDATION_ERROR", "Use valid OpenSSH keys and passphrase.") from None
        ident = uid()
        credential = app.state.secrets.put(db, "ssh", ident, {"private_key": body.private_key,
                                                             "passphrase": body.passphrase})
        host = Host(id=ident, name=body.name, endpoint=body.endpoint, port=body.port, username=body.username,
                    host_public_key=normalized_key, credential_id=credential,
                    physical_identity=digest({"ssh_host_key": normalized_key}),
                    activation_credential_id=app.state.secrets.put(db, "activation_ssh", ident,
                        body.activation_credential.model_dump()) if body.activation_credential else None)
        db.add(host)
        db.flush()
        audit(db, user.id, "host.register", host.id)
        return {"id": host.id, "name": host.name, "readiness": host.readiness, "revision": host.revision,
                "host_key_fingerprint": key.get_fingerprint()}

    @app.post(prefix + "/hosts/{ident}/discover", status_code=202, response_model=s.JobAccepted)
    def discover(ident: str, body: s.Discover, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, ident)
        return domain.accepted(enqueue(db, kind="discover", request={"host_id": host.id, "instance_id": body.instance_id},
                    key=key, actor_id=user.id, resources=[f"host:{host.physical_identity}"]))

    @app.post(prefix + "/hosts/{ident}/reconcile", status_code=202, response_model=s.JobAccepted)
    def reconcile_host(ident: str, body: s.HostReconcile, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, ident)
        return domain.accepted(enqueue(db, kind="reconcile_host", request={"host_id": host.id, **body.model_dump()},
            key=key, actor_id=user.id, resources=[f"host:{host.physical_identity}"]))

    @app.post(prefix + "/hosts/{ident}/activation-plans", status_code=202, response_model=s.JobAccepted)
    def activation_plan(ident: str, body: s.Activation, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, ident)
        return domain.accepted(private_job(db, "activation_plan", {"host_id": host.id, "host_revision": host.revision,
               "policy": body.policy}, key, user, resources=[f"host:{host.physical_identity}"]))

    @app.post(prefix + "/hosts/{ident}/activate", status_code=202, response_model=s.JobAccepted)
    def activate(ident: str, body: s.Activate, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, ident)
        plan = domain.get(db, ActivationPlan, body.plan_id)
        if plan.host_id != host.id or plan.host_revision != host.revision or plan.plan_hash != body.plan_hash:
            raise VaultRewindError("TARGET_CHANGED", "Activation prerequisites changed.")
        if utc(plan.expires_at) <= now() or plan.consumed_at:
            raise VaultRewindError("PLAN_INVALID", "The activation plan expired or was consumed.")
        job = enqueue(db, kind="activate", request={"host_id": host.id, "plan_id": plan.id,
                      "plan_hash": plan.plan_hash}, key=key, actor_id=user.id, resources=[f"host:{host.physical_identity}"])
        plan.consumed_at = now()
        return domain.accepted(job)

    @app.put(prefix + "/hosts/{ident}/activation-credential")
    def set_activation_credential(ident: str, body: s.ActivationCredential, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, ident)
        import asyncssh
        try:
            asyncssh.import_private_key(body.private_key, body.passphrase)
        except (ValueError, asyncssh.Error):
            raise VaultRewindError("VALIDATION_ERROR", "Invalid activation key.") from None
        host.activation_credential_id = app.state.secrets.put(db, "activation_ssh", host.id, body.model_dump())
        audit(db, user.id, "host.activation_credential", host.id)
        return {"configured": True}

    @app.delete(prefix + "/hosts/{ident}/activation-credential")
    def remove_activation_credential(ident: str, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, ident)
        if host.activation_credential_id:
            secret = domain.get(db, __import__("vaultrewind.server.models", fromlist=["Secret"]).Secret, host.activation_credential_id)
            host.activation_credential_id = None
            db.flush()
            db.delete(secret)
        audit(db, user.id, "host.activation_credential_remove", host.id)
        return {"configured": False}

    @app.get(prefix + "/jobs/{ident}/enrollment")
    def enrollment_result(ident: str, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        job = domain.get(db, Job, ident)
        if job.kind != "discover" or job.state != "succeeded" or not job.result.get("private_evidence_id"):
            raise VaultRewindError("DISCOVERY_REQUIRED", "A completed discovery result is required.")
        private = app.state.secrets.get(db, job.result["private_evidence_id"])
        # Purpose-specific administrator setup data. Never include raw Docker environment/inspect output.
        if private.get("proposals") is not None:
            return {"host_id": job.request["host_id"], "discovery_job_id": job.id,
                    "machine_id": private["machine_id"], "daemon_id": private["daemon_id"],
                    "systemd": private["systemd"], "proposals": private["proposals"],
                    "pending_operations": private.get("pending_operations", [])}
        return {"host_id": job.request["host_id"], "discovery_job_id": job.id,
                "configuration": {"discovery_job_id": job.id, "remote_instance_id": job.request["instance_id"]},
                "ready": bool(private.get("recovery_verified")), "restore_enabled": bool(private.get("restore_enabled"))}

    @app.get(prefix + "/instances")
    def instances(include_runners: bool = Query(False), page=Depends(pagination),
                  db=Depends(db_session, scope="function"), user=Depends(viewer)):
        query = select(Instance).where(Instance.archived.is_(False))
        if not include_runners:
            query = query.where(Instance.is_runner.is_(False))
        return {"items": [domain.instance_view(db, x, app.state.secrets) for x in db.scalars(
            query.order_by(Instance.created_at).limit(page[0]).offset(page[1]))]}

    @app.get(prefix + "/instances/{ident}")
    def instance(ident: str, db=Depends(db_session, scope="function"), user=Depends(viewer)):
        obj = domain.get(db, Instance, ident)
        return domain.instance_view(db, obj, app.state.secrets) | {"policy": domain.policy_view(db, policy(db, ident))}

    @app.post(prefix + "/instances", status_code=201)
    def create_instance(body: s.InstanceCreate, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        host = domain.get(db, Host, body.host_id)
        config = body.configuration
        discovery = domain.get(db, Job, config.get("discovery_job_id", ""))
        remote_id = config.get("remote_instance_id")
        if (discovery.kind != "discover" or discovery.state != "succeeded" or
                discovery.request.get("host_id") != host.id or discovery.request.get("instance_id") != remote_id or
                not discovery.result.get("private_evidence_id")):
            raise VaultRewindError("DISCOVERY_REQUIRED", "Enroll using a completed read-only discovery.")
        from uuid import UUID
        try:
            if str(UUID(remote_id)) != remote_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise VaultRewindError("VALIDATION_ERROR", "A canonical remote instance ID is required.") from None
        evidence = app.state.secrets.get(db, discovery.result["private_evidence_id"])
        if evidence.get("database_engine") != "sqlite" or not evidence.get("recovery_verified") or not evidence.get("resource_keys"):
            raise VaultRewindError("UNSUPPORTED_INSTALLATION", "Discovery did not prove a supported recovery boundary.")
        if host.readiness != "ready":
            raise VaultRewindError("INSTANCE_NOT_READY", "Accept and complete helper activation first.")
        if body.is_runner and not evidence.get("empty_target"):
            raise VaultRewindError("RUNNER_UNSAFE", "Verification runners must use a proven empty dedicated target.")
        profile = evidence.get("enrolled_profile") or {}
        approved = {"remote_instance_id": remote_id, "resource_keys": evidence["resource_keys"],
                    "restore_enabled": bool(evidence.get("restore_enabled")),
                    "restore_error_code": evidence.get("restore_error_code"),
                    "source_public_ports_ready": evidence.get("current_public_ports_ready"),
                    "recovery_profile": profile.get("recovery_profile") or {}, "discovery_job_id": discovery.id}
        ident = remote_id
        obj = db.scalar(select(Instance).where(Instance.id == ident).with_for_update())
        binding_import = obj is not None and obj.host_id is None and obj.readiness == "imported"
        if obj is not None and not binding_import:
            raise VaultRewindError("CONFIGURATION_CONFLICT", "This remote instance is already enrolled.")
        if binding_import and body.is_runner:
            raise VaultRewindError("RUNNER_UNSAFE", "A recovered instance must be rebound as an application target.")
        secret_id = app.state.secrets.put(db, "instance_configuration", ident, approved)
        if obj is None:
            obj = Instance(id=ident)
            db.add(obj)
        obj.host_id, obj.name, obj.container_id = host.id, body.name, body.container_id
        obj.physical_identity, obj.physical_keys = digest(sorted(evidence["resource_keys"])), evidence["resource_keys"]
        obj.configuration_secret_id, obj.fingerprint = secret_id, evidence["fingerprint"]
        obj.readiness, obj.source_health, obj.is_runner = "ready", evidence["source_state"], body.is_runner
        if binding_import:
            obj.revision += 1
        db.flush()
        new_policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == ident)) if binding_import else None
        if new_policy is None:
            new_policy = BackupPolicy(instance_id=ident, enabled=not body.is_runner and not binding_import)
            db.add(new_policy)
        new_policy.outage_seconds = profile.get("capture_budget") or 300
        new_policy.maintenance_seconds = profile.get("restore_budget") or 900
        new_policy.validation_seconds = profile.get("validation_window") or 180
        if binding_import:
            new_policy.enabled, new_policy.next_run_at, new_policy.retention_days = False, None, None
        db.flush()
        new_policy.next_run_at = next_run(new_policy, now()) if new_policy.enabled else None
        new_policy.next_verify_at = None if binding_import else now() + timedelta(days=7)
        new_policy.next_test_at = None if binding_import else now() + timedelta(days=7)
        domain.ensure_safety_repository(db, app.state.secrets, settings, ident, user.id)
        # Individual mount identities preserve conflicts for partially overlapping registrations.
        for resource in evidence["resource_keys"]:
            from .queue import ensure_resource
            ensure_resource(db, f"mount:{resource}")
        audit(db, user.id, "instance.rebind_import" if binding_import else "instance.enroll", obj.id)
        return domain.instance_view(db, obj, app.state.secrets)

    @app.post(prefix + "/instances/{ident}/backups", status_code=202, response_model=s.JobAccepted)
    def backup(ident: str, body: s.Backup, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        req = domain.backup_request(db, ident, body.label)
        return domain.accepted(enqueue(db, kind="backup", request=req, key=key, actor_id=user.id, instance_id=ident))

    @app.get(prefix + "/instances/{ident}/remote-storage")
    def remote_storage(ident: str, db=Depends(db_session, scope="function"), user=Depends(viewer)):
        from .remote_maintenance import storage_view
        return storage_view(db, ident)

    @app.post(prefix + "/instances/{ident}/remote-storage/refresh", status_code=202, response_model=s.JobAccepted)
    def remote_storage_refresh(ident: str, body: s.Empty, key=Depends(idem),
                               db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .remote_maintenance import queue_inventory
        return domain.accepted(queue_inventory(db, ident, key=key, actor_id=user.id))

    @app.post(prefix + "/jobs/{ident}/remote-cleanup", status_code=202, response_model=s.JobAccepted)
    def remote_cleanup(ident: str, body: s.RemoteCleanup, key=Depends(idem),
                       db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .remote_maintenance import queue_cleanup
        return domain.accepted(queue_cleanup(db, ident, body.kind, key=key, actor_id=user.id))

    @app.get(prefix + "/instances/{ident}/snapshots")
    def snapshots(ident: str, before: datetime | None = Query(None), before_id: s.Id | None = Query(None),
                  page=Depends(pagination), db=Depends(db_session, scope="function"), user=Depends(viewer)):
        domain.get(db, Instance, ident)
        query = select(Snapshot).where(Snapshot.instance_id == ident)
        if before is not None or before_id is not None:
            if before is None or before_id is None or before.utcoffset() is None:
                raise VaultRewindError("VALIDATION_ERROR", "Snapshot paging needs an exact UTC capture time and snapshot ID.")
            instant = utc(before)
            query = query.where((Snapshot.captured_at < instant) |
                                ((Snapshot.captured_at == instant) & (Snapshot.id < before_id)))
        rows = db.scalars(query.order_by(Snapshot.captured_at.desc(), Snapshot.id.desc()).limit(page[0]).offset(page[1]))
        return {"items": [domain.snapshot_view(db, row) for row in rows]}

    @app.get(prefix + "/snapshots/{ident}", response_model=s.SnapshotView)
    def snapshot(ident: str, db=Depends(db_session, scope="function"), user=Depends(viewer)):
        return domain.snapshot_view(db, domain.get(db, Snapshot, ident))

    @app.post(prefix + "/snapshot-copies/{ident}/retry", status_code=202, response_model=s.JobAccepted)
    def retry_copy(ident: str, body: s.Empty, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .models import SnapshotCopy
        copy = domain.get(db, SnapshotCopy, ident)
        snapshot = domain.get(db, Snapshot, copy.snapshot_id)
        if copy.state not in {"failed", "uncertain", "pending", "committing"}:
            raise VaultRewindError("COPY_RETRY_UNAVAILABLE", "Only an incomplete storage copy can be retried.")
        original = next((j for j in db.scalars(select(Job).where(Job.kind == "backup", Job.instance_id == snapshot.instance_id)
                                              .order_by(Job.created_at.desc()))
                         if j.result.get("snapshot_id") == snapshot.id), None)
        req = {"snapshot_id": snapshot.id, "repository_id": copy.repository_id,
               "original_job_id": original.id if original else None}
        return domain.accepted(enqueue(db, kind="retry_copy", request=req, key=key, actor_id=user.id,
                                      instance_id=snapshot.instance_id))

    @app.post(prefix + "/snapshots/{ident}/restore-plans", status_code=201)
    def restore_plan(ident: str, body: s.Restore, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.new_restore_plan(db, app.state.secrets, ident, user.id, body)

    @app.post(prefix + "/restore-plans/{ident}/execute", status_code=202, response_model=s.JobAccepted)
    def restore_execute(ident: str, body: s.Execute, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(domain.execute_restore(db, ident, body.confirmation_token, user.id, key))

    @app.post(prefix + "/snapshots/{ident}/verify", status_code=202, response_model=s.JobAccepted)
    def verify(ident: str, body: s.Verify, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        snap, copy = domain.select_copy(db, ident, body.copy_id)
        runner_id = body.runner_id or policy(db, snap.instance_id).runner_id
        keys = resources_for_instance(db, snap.instance_id, [copy.repository_id])
        if body.level == "application":
            runner = domain.get(db, Instance, runner_id) if runner_id else None
            source = domain.get(db, Instance, snap.instance_id)
            if not runner or not runner.is_runner or runner.host_id == source.host_id:
                raise VaultRewindError("RESTORE_RUNNER_NOT_CONFIGURED", "Configure a separate isolated runner.")
            keys += resources_for_instance(db, runner.id, [])
        job = enqueue(db, kind="verify", request={"snapshot_id": snap.id, "copy_id": copy.id,
                      "level": body.level, "runner_id": runner_id}, key=key, actor_id=user.id,
                      instance_id=snap.instance_id, resources=keys)
        return domain.accepted(job)

    @app.post(prefix + "/snapshots/{ident}/pin")
    def pin(ident: str, body: s.Empty, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        snap = db.scalar(select(Snapshot).where(Snapshot.id == ident).with_for_update())
        if not snap:
            raise VaultRewindError("NOT_FOUND", "Snapshot not found.")
        # Serialize pin changes against retention/restore using the same repository leases.
        from .queue import ensure_resource
        for resource in resources_for_instance(db, snap.instance_id):
            ensure_resource(db, resource)
            lease = db.scalar(select(ResourceLease).where(ResourceLease.resource_key == resource).with_for_update())
            if lease.owner_job_id:
                raise VaultRewindError("RESOURCE_BUSY", "Wait for active repository work before changing pins.")
        if not db.scalar(select(SnapshotProtection.id).where(SnapshotProtection.snapshot_id == ident,
                                                            SnapshotProtection.reason == "pin")):
            db.add(SnapshotProtection(snapshot_id=ident, reason="pin", actor_id=user.id))
        audit(db, user.id, "snapshot.pin", ident)
        return {"pinned": True}

    @app.delete(prefix + "/snapshots/{ident}/pin")
    def unpin(ident: str, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        snap = domain.get(db, Snapshot, ident)
        for resource in resources_for_instance(db, snap.instance_id):
            lease = db.scalar(select(ResourceLease).where(ResourceLease.resource_key == resource).with_for_update())
            if lease and lease.owner_job_id:
                raise VaultRewindError("RESOURCE_BUSY", "Wait for active repository work before changing pins.")
        removable = ["pin"]
        if snap.safety_for_job_id:
            restore_job = domain.get(db, Job, snap.safety_for_job_id)
            if restore_job.state != "succeeded":
                raise VaultRewindError("RETENTION_PROTECTED", "Keep safety protection until the associated restore completes successfully.")
            removable.append("safety")
        for row in db.scalars(select(SnapshotProtection).where(SnapshotProtection.snapshot_id == ident,
                                                              SnapshotProtection.reason.in_(removable))):
            db.delete(row)
        audit(db, user.id, "snapshot.unpin", ident)
        return {"pinned": False, "other_protections_preserved": True}

    @app.post(prefix + "/snapshots/{ident}/deletion-plans", status_code=201)
    def deletion_plan(ident: str, body: s.Empty, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.deletion_plan(db, ident, user.id)

    @app.post(prefix + "/deletion-plans/{ident}/execute", status_code=202, response_model=s.JobAccepted)
    def delete_execute(ident: str, body: s.Execute, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(domain.execute_deletion(db, ident, body.confirmation_token, user.id, key))

    @app.get(prefix + "/jobs")
    def jobs(page=Depends(pagination), db=Depends(db_session, scope="function"), user=Depends(viewer)):
        return {"items": [domain.job_view(j) for j in db.scalars(select(Job).order_by(Job.created_at.desc())
                                                               .limit(page[0]).offset(page[1]))]}

    @app.get(prefix + "/jobs/{ident}")
    def job(ident: str, db=Depends(db_session, scope="function"), user=Depends(viewer)):
        return domain.job_view(domain.get(db, Job, ident))

    @app.get(prefix + "/jobs/{ident}/events")
    def events(ident: str, after: int = Query(0, ge=0), last_event_id: str | None = Header(None),
               db=Depends(db_session, scope="function"), user=Depends(viewer)):
        obj = domain.get(db, Job, ident)
        if last_event_id:
            try:
                after = max(after, int(last_event_id))
            except ValueError:
                raise VaultRewindError("VALIDATION_ERROR", "Invalid event sequence.") from None
        rows = list(db.scalars(select(JobEvent).where(JobEvent.job_id == ident, JobEvent.sequence > after)
                               .order_by(JobEvent.sequence).limit(200)))
        return {"events": [{"sequence": r.sequence, "created_at": domain.iso(r.created_at), "phase": r.phase,
                            "code": r.code, "progress": r.progress} for r in rows], "state": obj.state,
                "next_sequence": rows[-1].sequence if rows else after, "job": domain.job_view(obj)}

    @app.post(prefix + "/jobs/{ident}/cancel", status_code=202, response_model=s.JobAccepted)
    def cancel(ident: str, body: s.Empty, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        obj = db.scalar(select(Job).where(Job.id == ident).with_for_update())
        if not obj:
            raise VaultRewindError("NOT_FOUND", "The job does not exist.")
        if obj.state not in TERMINAL:
            obj.state = "cancel_requested"
            event(db, obj, "CANCEL_REQUESTED")
            audit(db, user.id, "job.cancel", ident)
        return domain.accepted(obj)

    @app.post(prefix + "/jobs/{ident}/reconcile", status_code=202, response_model=s.JobAccepted)
    def reconcile_job(ident: str, body: s.Empty, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        obj = db.scalar(select(Job).where(Job.id == ident).with_for_update())
        if not obj or obj.kind not in {"backup", "restore", "verify"}:
            raise VaultRewindError("NOT_FOUND", "The recoverable job does not exist.")
        if obj.state in {"queued", "running", "cancel_requested"} and obj.result.get("reconcile_requested"):
            return domain.accepted(obj)
        if obj.state not in {"needs_attention", "rollback_failed", "waiting_retry"}:
            raise VaultRewindError("RESOURCE_BUSY", "This job is already active or completed.")
        # Keep the operation ID and every physical lease. Only remote journal reconciliation may release them.
        obj.state, obj.lease_expires_at = "queued", None
        obj.reconcile_required = True
        obj.result = {**obj.result, "reconcile_requested": True}
        audit(db, user.id, "job.reconcile", obj.id)
        return domain.accepted(obj)

    @app.get(prefix + "/storage-destinations")
    def destinations(page=Depends(pagination), db=Depends(db_session, scope="function"), user=Depends(viewer)):
        return {"items": [domain.destination_view(db, app.state.secrets, settings, d)
            for d in db.scalars(select(StorageDestination).where(StorageDestination.archived.is_(False))
                               .order_by(StorageDestination.created_at).limit(page[0]).offset(page[1]))]}

    @app.post(prefix + "/storage-destinations", status_code=201)
    def create_destination(body: s.DestinationCreate, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        ident = uid()
        config = dict(body.configuration)
        if body.backend == "local":
            config.pop("root", None)
        elif body.backend == "s3":
            if "addressing_mode" in config:
                config["bucket_lookup"] = config.pop("addressing_mode")
            if "allow_insecure_local" in config:
                config["development_http"] = config.pop("allow_insecure_local")
        if body.backend == "drive":
            config.pop("client_id", None)
            config.pop("root_folder_id", None)
        if body.backend != "drive":
            from vaultrewind.storage.providers import validate_destination
            validate_destination(body.backend, config, body.credentials, ident)
        config_id = app.state.secrets.put(db, "destination_configuration", ident, config)
        credential_id = app.state.secrets.put(db, "provider_credentials", ident, body.credentials) if body.credentials else None
        obj = StorageDestination(id=ident, name=body.name, backend=body.backend,
                 configuration_secret_id=config_id, credential_id=credential_id, quota_bytes=body.quota_bytes)
        db.add(obj)
        db.flush()
        audit(db, user.id, "storage.create", ident)
        return {"id": ident, "name": obj.name, "backend": obj.backend, "health": obj.health, "revision": obj.revision}

    @app.get(prefix + "/storage-destinations/{ident}")
    def destination_detail(ident: str, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .destination_updates import destination_view
        return destination_view(db, app.state.secrets, ident)

    @app.patch(prefix + "/storage-destinations/{ident}")
    def destination_update(ident: str, body: s.DestinationPatch, if_match: str | None = Header(None),
                           db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .destination_updates import update_destination
        try:
            revision = int((if_match or "").strip('"'))
        except ValueError:
            raise VaultRewindError("REVISION_CONFLICT", "Supply the current If-Match revision.") from None
        return update_destination(db, app.state.secrets, settings, ident, body.model_dump(exclude_unset=True),
                                  revision, user.id)

    @app.post(prefix + "/storage-destinations/{ident}/test", status_code=202, response_model=s.JobAccepted)
    def destination_test(ident: str, body: s.Empty, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        domain.get(db, StorageDestination, ident)
        repos = list(db.scalars(select(Repository).where(Repository.destination_id == ident)))
        keys = [f"repository:{r.physical_identity}" for r in repos] + [f"credential:{ident}"]
        return domain.accepted(enqueue(db, kind="storage_test", request={"destination_id": ident},
                               key=key, actor_id=user.id, resources=keys))

    @app.post(prefix + "/storage-destinations/{ident}/authorize")
    def authorize(ident: str, body: s.Authorize, request: Request, key=Depends(idem),
                  db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .oauth import start
        obj = domain.get(db, StorageDestination, ident)
        if obj.backend != "drive":
            raise VaultRewindError("PROVIDER_UNSUPPORTED", "Authorization applies to Google Drive.")
        if body.mode == "headless":
            if not body.token:
                raise VaultRewindError("VALIDATION_ERROR", "A private headless authorization token is required.")
            return JSONResponse(status_code=202, content=domain.accepted(private_job(db, "drive_import",
                {"destination_id": ident, "token": body.token}, key, user, resources=[f"credential:{ident}"])))
        _, session = auth.current(request, db)
        return start(db, app.state.secrets, settings, obj, session)

    @app.get(prefix + "/oauth/drive/callback")
    def oauth_callback(request: Request, state: str = "", code: str = "", error: str = "",
                       db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from vaultrewind.security.redaction import callback_params

        from .oauth import callback
        params = callback_params(request)
        state, code, error = params.get("state", ""), params.get("code", ""), params.get("error", "")
        if str(request.base_url).rstrip("/") != settings.public_origin:
            raise VaultRewindError("PLAN_INVALID", "The callback origin does not match the configured origin.")
        _, session = auth.current(request, db)
        return callback(db, app.state.secrets, settings, session, user.id, state, code, error)

    @app.get(prefix + "/instances/{ident}/policy")
    def get_policy(ident: str, response: Response, db=Depends(db_session, scope="function"), user=Depends(viewer)):
        obj = policy(db, ident)
        response.headers["ETag"] = f'"{obj.revision}"'
        return domain.policy_view(db, obj)

    @app.patch(prefix + "/instances/{ident}/policy")
    def patch_policy(ident: str, body: s.PolicyPatch, if_match: str | None = Header(None),
                     db=Depends(db_session, scope="function"), user=Depends(administrator)):
        try:
            revision = int((if_match or "").strip('"'))
        except ValueError:
            raise VaultRewindError("REVISION_CONFLICT", "Supply the current If-Match revision.") from None
        result = domain.patch_policy(db, app.state.secrets, settings, ident, body, revision, user.id)
        return domain.policy_view(db, result)

    @app.post(prefix + "/instances/{ident}/retention-preview")
    def retention(ident: str, body: s.RetentionPreviewInput, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        if body.keep_forever:
            return retention_preview(db, ident, retention_days=None)
        if "retention_days" in body.model_fields_set:
            return retention_preview(db, ident, retention_days=body.retention_days)
        return retention_preview(db, ident)

    @app.post(prefix + "/instances/{ident}/schedule-preview")
    def schedule_preview(ident: str, body: s.Empty, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        obj, cursor, values = policy(db, ident), now(), []
        for _ in range(5):
            cursor = next_run(obj, cursor)
            values.append(domain.iso(cursor))
        return {"timezone": obj.timezone, "next_occurrences": values}

    @app.post(prefix + "/recovery-kits/export", status_code=202, response_model=s.JobAccepted)
    def recovery_export(body: s.RecoveryExport, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(private_job(db, "recovery_export", body.model_dump(), key, user,
                                          resources=["controller:catalog"]))

    @app.post(prefix + "/recovery/import-plans", status_code=202, response_model=s.JobAccepted)
    def recovery_import(body: s.RecoveryImport, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(private_job(db, "recovery_import", body.model_dump(), key, user,
                                          resources=["controller:catalog"]))

    @app.post(prefix + "/metadata/export", status_code=202, response_model=s.JobAccepted)
    def metadata_export(body: s.Empty, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(enqueue(db, kind="metadata_export", request={}, key=key, actor_id=user.id,
                                      resources=["controller:catalog"]))

    def reviewed_import(db, ident):
        obj = domain.get(db, Job, ident)
        if obj.kind != "recovery_import" or obj.state != "succeeded" or not obj.result.get("private_materials_id"):
            raise VaultRewindError("IMPORT_PLAN_INVALID", "A completed recovery discovery plan is required.")
        plan = app.state.secrets.get(db, obj.result["private_evidence_id"])
        return obj, plan

    @app.get(prefix + "/recovery/import-plans/{ident}")
    def import_plan_review(ident: str, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .recovery_import import summarize_plan
        obj, plan = reviewed_import(db, ident)
        return {"plan_job_id": obj.id, "plan_hash": digest(plan), "summary": summarize_plan(plan),
                "snapshots": [{k: item.get(k) for k in ("snapshot_uuid", "instance_id", "captured_at", "manifest_hash", "kind", "future_dated")}
                              for item in plan.get("snapshots", [])]}

    @app.post(prefix + "/recovery/import-plans/{ident}/apply", status_code=202, response_model=s.JobAccepted)
    def import_plan_apply(ident: str, body: s.RecoveryApply, key=Depends(idem),
                          db=Depends(db_session, scope="function"), user=Depends(administrator)):
        obj, plan = reviewed_import(db, ident)
        if body.plan_hash != digest(plan):
            raise VaultRewindError("IMPORT_PLAN_INVALID", "The reviewed import plan changed.")
        audit(db, user.id, "recovery.import_confirm", ident)
        return domain.accepted(enqueue(db, kind="recovery_apply", request={"plan_job_id": obj.id, "plan_hash": body.plan_hash},
                                      key=key, actor_id=user.id, resources=["controller:catalog"]))

    @app.get(prefix + "/controller-backups")
    def controller_backups(db=Depends(db_session, scope="function"), user=Depends(viewer)):
        from .controller_backup import list_status, public_status
        return {"items": list_status(db), "status": public_status(db, settings.controller_backup_max_age_days)}

    @app.post(prefix + "/controller-backups", status_code=202, response_model=s.JobAccepted)
    def controller_backup(body: s.ControllerBackupRequest, key=Depends(idem),
                          db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(domain.enqueue_controller_backup(db, app.state.secrets, settings,
                               body.destination_id, key=key, actor_id=user.id))

    def controller_policy_view(db):
        from .controller_backup import public_status
        from .models import ControllerBackupPolicy
        row = db.get(ControllerBackupPolicy, 1)
        status = public_status(db, settings.controller_backup_max_age_days)
        return {k: status[k] for k in ("configured", "enabled", "destination_id", "timezone", "daily_time", "next_run_at")} | {"revision": row.revision if row else 0}

    @app.get(prefix + "/controller-backup-policy")
    def controller_policy(db=Depends(db_session, scope="function"), user=Depends(viewer)):
        return controller_policy_view(db)

    @app.put(prefix + "/controller-backup-policy")
    def configure_controller_policy(body: s.ControllerBackupPolicyInput, if_match: str | None = Header(None),
                                    db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .controller_backup import configure_policy
        from .models import ControllerBackupPolicy
        from .queue import ensure_resource
        ensure_resource(db, "controller:metadata-policy")
        db.scalar(select(ResourceLease).where(ResourceLease.resource_key == "controller:metadata-policy").with_for_update())
        current = db.get(ControllerBackupPolicy, 1)
        try:
            revision = int((if_match or "").strip('"'))
        except ValueError:
            raise VaultRewindError("REVISION_CONFLICT", "Supply the current If-Match revision.") from None
        if revision != (current.revision if current else 0):
            raise VaultRewindError("REVISION_CONFLICT", "The controller policy changed.")
        configure_policy(db, **body.model_dump())
        audit(db, user.id, "controller_backup.policy_change", "controller", changes={"revision": revision + 1})
        return controller_policy_view(db)

    @app.get(prefix + "/jobs/{ident}/artifact")
    def artifact(ident: str, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        obj = domain.get(db, Job, ident)
        if (obj.kind not in {"recovery_export", "metadata_export"} or obj.state != "succeeded" or
                not obj.result.get("artifact_expires_at") or
                utc(__import__("datetime").datetime.fromisoformat(obj.result["artifact_expires_at"])) <= now()):
            raise VaultRewindError("ARTIFACT_UNAVAILABLE", "The export is unavailable or expired.")
        path = settings.staging_dir / obj.id / ("recovery-kit.enc" if obj.kind == "recovery_export" else "catalog.json")
        if not path.is_file() or path.is_symlink():
            raise VaultRewindError("ARTIFACT_UNAVAILABLE", "The export is unavailable.")
        audit(db, user.id, "export.download", obj.id)
        return FileResponse(path, media_type="application/octet-stream", filename=path.name)

    @app.get(prefix + "/audit-events")
    def audit_events(page=Depends(pagination), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return {"items": [{"id": a.id, "actor_id": a.actor_id, "action": a.action, "object_id": a.object_id,
                           "outcome": a.outcome, "created_at": domain.iso(a.created_at), "changes": a.changes}
                          for a in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc())
                                              .limit(page[0]).offset(page[1]))]}

    @app.get(prefix + "/notifications")
    def notifications(page=Depends(pagination), db=Depends(db_session, scope="function"), user=Depends(viewer)):
        return {"items": [{"id": a.id, "instance_id": a.instance_id, "code": a.code, "active": a.active,
                "created_at": domain.iso(a.created_at), "resolved_at": domain.iso(a.resolved_at),
                "deliveries": [{"channel_id": d.channel_id, "state": d.state, "attempt": d.attempt,
                                "error_code": d.error_code} for d in db.scalars(select(NotificationDelivery)
                                                        .where(NotificationDelivery.event_id == a.id))]}
                for a in db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(page[0]).offset(page[1]))]}

    @app.post(prefix + "/notification-channels", status_code=201)
    def notification_channel(body: s.NotificationCreate, db=Depends(db_session, scope="function"), user=Depends(administrator)):
        from .notifications import validate_channel
        validate_channel(settings, body.kind, body.configuration)
        ident = uid()
        secret_id = app.state.secrets.put(db, "notification", ident, body.configuration)
        channel = NotificationChannel(id=ident, kind=body.kind, configuration_secret_id=secret_id)
        db.add(channel)
        audit(db, user.id, "notification.configure", ident)
        return {"id": ident, "kind": body.kind, "enabled": True}

    @app.get(prefix + "/doctor")
    def doctor(db=Depends(db_session, scope="function"), user=Depends(viewer)):
        from .doctor import inspect_catalog
        return inspect_catalog(db)

    @app.post(prefix + "/doctor", status_code=202, response_model=s.JobAccepted)
    def doctor_run(body: s.Empty, key=Depends(idem), db=Depends(db_session, scope="function"), user=Depends(administrator)):
        return domain.accepted(enqueue(db, kind="doctor", request={}, key=key, actor_id=user.id,
                                      resources=["controller:doctor"]))

    @app.get(prefix + "/health/live")
    def live():
        return {"status": "alive"}

    from alembic.script import ScriptDirectory
    try:
        migration_heads = set(ScriptDirectory(str(settings.migrations_dir or Path(__file__).resolve().parents[3] / "migrations")).get_heads())
    except (OSError, ValueError):
        migration_heads = set()

    @app.get(prefix + "/health/ready")
    def ready():
        try:
            with engine.connect() as conn:
                versions = set(conn.execute(text("SELECT version_num FROM alembic_version")).scalars())
                if not migration_heads or versions != migration_heads:
                    raise ValueError()
            return {"status": "ready"}
        except (SQLAlchemyError, ValueError):
            return JSONResponse(status_code=503, content={"status": "not_ready"})

    # API registrations precede the SPA catch-all. Unknown API paths stay JSON 404s.
    frontend = settings.frontend_dir or Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if (frontend / "index.html").is_file():
        @app.get("/{path:path}", include_in_schema=False)
        def frontend_file(path: str):
            if path == "api" or path.startswith("api/"):
                return JSONResponse(status_code=404, content=error_body("NOT_FOUND"))
            candidate = (frontend / path).resolve()
            if not candidate.is_relative_to(frontend.resolve()):
                return JSONResponse(status_code=404, content=error_body("NOT_FOUND"))
            return FileResponse(candidate if candidate.is_file() else frontend / "index.html")

    from .http_security import SanitizedUnexpectedErrors
    app.add_middleware(BoundedBody)
    app.add_middleware(SanitizedUnexpectedErrors)
    app.add_middleware(OAuthCallbackScrubber, paths=[settings.drive_redirect_path])
    return app

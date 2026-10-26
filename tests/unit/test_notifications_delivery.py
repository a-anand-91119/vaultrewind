"""Real loopback TLS transports and relational notification jobs, with no shared fixtures.

The standalone drill imports this harness. Only fixture DNS, process-local CA trust,
and retry eligibility timestamps are adapted; delivery/TLS/queue/worker are real.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import socketserver
import ssl
import threading
from collections import deque
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server import notifications
from vaultrewind.server.db import Base, make_engine, now, sessions, uid, utc
from vaultrewind.server.models import (
    Alert,
    Instance,
    Job,
    JobEvent,
    JobStep,
    NotificationChannel,
    NotificationDelivery,
    Repository,
    ResourceLease,
    Secret,
    Snapshot,
    SnapshotCopy,
    StorageDestination,
)
from vaultrewind.server.queue import claim, enqueue, finish
from vaultrewind.server.secrets import Secrets
from vaultrewind.server.settings import Settings
from vaultrewind.server.worker import Worker

FIXTURE_HOST = "notifications.fixture.invalid"
WRONG_HOST = "wrong.notifications.fixture.invalid"
STATUS_FIELDS = {"event_id", "instance_id", "code", "status"}


def _private_write(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(value)


def _certificates(root):
    """Ephemeral ECDSA CA/leaf; the CA private key never leaves memory."""
    current = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic notification test CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(current - timedelta(minutes=1))
          .not_valid_after(current + timedelta(minutes=15))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                         key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FIXTURE_HOST)]))
            .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(minutes=1)).not_valid_after(current + timedelta(minutes=15))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                           key_encipherment=False, data_encipherment=False, key_agreement=False,
                           key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(FIXTURE_HOST), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = root / "ca.pem", root / "server.pem", root / "server.key"
    _private_write(ca_path, ca.public_bytes(serialization.Encoding.PEM))
    _private_write(cert_path, leaf.public_bytes(serialization.Encoding.PEM))
    _private_write(key_path, leaf_key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return ca_path, context


class _SMTP(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        conn = self.request
        conn.settimeout(2)
        reader = conn.makefile("rb")
        tls, authenticated = False, False

        def reply(value):
            conn.sendall(value + b"\r\n")

        try:
            reply(b"220 synthetic fixture ESMTP")
            while line := reader.readline(65537):
                verb = line.split(b" ", 1)[0].strip().upper()
                if verb in {b"EHLO", b"HELO"}:
                    if tls:
                        reply(b"250-fixture\r\n250 AUTH PLAIN")
                    elif server.starttls:
                        reply(b"250-fixture\r\n250 STARTTLS")
                    else:
                        reply(b"250 fixture")
                elif verb == b"STARTTLS" and not tls and server.starttls:
                    reply(b"220 ready for TLS")
                    reader.close()
                    conn = server.context.wrap_socket(conn, server_side=True)
                    reader = conn.makefile("rb")
                    tls = True
                    server.tls_sessions += 1
                elif verb == b"AUTH":
                    server.auth_attempts += 1
                    decoded = base64.b64decode(line.strip().split()[2])
                    authenticated = tls and decoded == b"\0" + server.username.encode() + b"\0" + server.password.encode()
                    server.authenticated += int(authenticated)
                    reply(b"235 authenticated" if authenticated else b"535 rejected")
                elif verb in {b"MAIL", b"RCPT"}:
                    server.envelopes_before_tls += int(not tls)
                    reply(b"250 accepted" if tls and authenticated else b"530 TLS and authentication required")
                elif verb == b"DATA":
                    if not tls or not authenticated:
                        reply(b"530 TLS and authentication required")
                        continue
                    reply(b"354 end with dot")
                    chunks = []
                    while (chunk := reader.readline(65537)) not in {b".\r\n", b""}:
                        chunks.append(chunk[1:] if chunk.startswith(b"..") else chunk)
                    message = b"".join(chunks)
                    server.received.append(message)
                    status = server.responses.popleft() if server.responses else 250
                    if status == 250:
                        server.accepted.append(message)
                    reply(f"{status} synthetic fixture result".encode())
                elif verb == b"QUIT":
                    reply(b"221 goodbye")
                    break
                elif verb == b"RSET":
                    reply(b"250 reset")
                else:
                    reply(b"500 unsupported fixture command")
        except ssl.SSLError:
            server.tls_rejections += 1
        finally:
            reader.close()
            conn.close()


class _SMTPServer(socketserver.TCPServer):
    def handle_error(self, request, client_address):
        self.errors += 1  # Never print protocol data, addresses, or raw exceptions.


class _HTTPS(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        status = self.server.responses.popleft() if self.server.responses else 204
        self.server.received.append({"body": body, "headers": dict(self.headers), "path": self.path,
                                     "tls": isinstance(self.connection, ssl.SSLSocket), "status": status})
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


class _HTTPSServer(HTTPServer):
    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(2)
        try:
            return self.context.wrap_socket(conn, server_side=True), address
        except ssl.SSLError:
            self.tls_rejections += 1
            conn.close()
            raise

    def handle_error(self, request, client_address):
        self.errors += 1


@contextmanager
def _serving(server):
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert server.errors == 0


class NotificationLab:
    def __init__(self, root, settings, smtp, https):
        self.root, self.settings, self.smtp, self.https = root, settings, smtp, https
        self.engine = make_engine(settings.database_url)
        Base.metadata.create_all(self.engine)
        self.sessions, self.store = sessions(self.engine), Secrets(settings)
        self.worker = Worker(settings, engine=self.engine, owner="synthetic-notification-worker")

    def add_channel(self, kind, *, enabled=True):
        config = ({"url": f"https://{FIXTURE_HOST}/status", "signing_secret": secrets.token_urlsafe(32)}
                  if kind == "webhook" else {"recipients": ["recipient@fixture.invalid"],
                      "username": self.smtp.username, "password": self.smtp.password})
        with self.sessions.begin() as db:
            ident = uid()
            secret_id = self.store.put(db, "notification", ident, config)
            secret = db.get(Secret, secret_id)
            for value in config.values():
                assert str(value) not in secret.envelope
            assert self.store.get(db, secret_id) == config
            db.add(NotificationChannel(id=ident, kind=kind, enabled=enabled,
                                       configuration_secret_id=secret_id))
        return ident, config

    def raise_incident(self, instance_id=None, code="REQUIRED_COPY_FAILED"):
        with self.sessions.begin() as db:
            return notifications.raise_alert(db, instance_id, code).id

    def drain(self, expected):
        for _ in range(expected):
            assert self.worker.run_once()
        assert not self.worker.run_once()

    def deliveries(self):
        with self.sessions() as db:
            return list(db.scalars(select(NotificationDelivery).order_by(NotificationDelivery.created_at)))

    def jobs(self):
        with self.sessions() as db:
            return list(db.scalars(select(Job).where(Job.kind == "notification").order_by(Job.created_at)))

    def due_retry(self, job_id):
        # Move only persisted retry eligibility; do not sleep or replace backoff/claim logic.
        with self.sessions.begin() as db:
            db.get(Job, job_id).next_attempt_at = now() - timedelta(seconds=1)

    def seed_complete_backup(self):
        """Persisted synthetic validity witness; does not claim a new backup ran."""
        with self.sessions.begin() as db:
            config = self.store.put(db, "instance", "synthetic", {"environment_secret": secrets.token_urlsafe()})
            instance = Instance(name="Synthetic private label", container_id="synthetic-not-running",
                                physical_identity="synthetic-notification-instance", physical_keys=[],
                                configuration_secret_id=config, fingerprint="f" * 64,
                                source_health="running", backup_health="protected", last_complete_at=now())
            db.add(instance)
            db.flush()
            destination = StorageDestination(name="Synthetic catalog only", backend="local",
                                             configuration_secret_id=config, health="healthy")
            db.add(destination)
            db.flush()
            repository = Repository(instance_id=instance.id, destination_id=destination.id,
                                    configuration_secret_id=config, key_id=config,
                                    physical_identity="synthetic-notification-repository", health="healthy")
            db.add(repository)
            db.flush()
            job = enqueue(db, kind="backup", instance_id=instance.id, request={},
                          key="synthetic-completed-backup", resources=[])
            job.content_commit, job.required_copy_outcome, job.source_service_outcome = "complete", "complete", "running"
            finish(db, job, "succeeded")
            snapshot = Snapshot(instance_id=instance.id, captured_at=now(), capture_started_at=now(),
                                trigger="manual", manifest_hash="f" * 64, completeness="complete",
                                image_id="sha256:" + "f" * 64, vaultwarden_version="synthetic", source_state="running")
            db.add(snapshot)
            db.flush()
            copy = SnapshotCopy(snapshot_id=snapshot.id, repository_id=repository.id, state="complete",
                                restic_snapshot_id="f" * 64, manifest_hash=snapshot.manifest_hash, verified_at=now())
            db.add(copy)
            db.flush()
            self.witness_ids = instance.id, job.id, snapshot.id, copy.id
        return self.backup_witness()

    def backup_witness(self):
        with self.sessions() as db:
            instance, job, snapshot, copy = (db.get(model, ident) for model, ident in zip(
                (Instance, Job, Snapshot, SnapshotCopy), self.witness_ids, strict=True))
            return (instance.backup_health, instance.source_health, instance.last_complete_at,
                    job.state, job.content_commit, job.required_copy_outcome, job.source_service_outcome,
                    snapshot.completeness, copy.state, copy.verified_at, copy.error_code)


@contextmanager
def notification_lab(root: Path, monkeypatch):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    ca_path, context = _certificates(root)
    _private_write(root / "master", os.urandom(32))
    _private_write(root / "catalog.sqlite", b"")
    smtp = _SMTPServer(("127.0.0.1", 0), _SMTP)
    https = _HTTPSServer(("127.0.0.1", 0), _HTTPS)
    for server in (smtp, https):
        server.context, server.responses, server.received = context, deque(), []
        server.tls_rejections, server.errors = 0, 0
    smtp.username, smtp.password = secrets.token_urlsafe(), secrets.token_urlsafe()
    smtp.accepted, smtp.starttls = [], True
    smtp.tls_sessions = smtp.auth_attempts = smtp.authenticated = smtp.envelopes_before_tls = 0
    https.sni_matches = 0

    def sni(_socket, hostname, _context):
        https.sni_matches += int(hostname == FIXTURE_HOST)

    context.set_servername_callback(sni)
    real_resolve = socket.getaddrinfo
    real_connect = socket.socket.connect

    def fixture_connect(conn, address):
        assert address[0] == "127.0.0.1" and address[1] in {
            smtp.server_address[1], https.server_address[1],
        }, "NONFIXTURE_CONNECTION_BLOCKED"
        return real_connect(conn, address)

    def fixture_dns(host, port, *args, **kwargs):
        if host in {FIXTURE_HOST, WRONG_HOST}:
            assert port == 443
            return real_resolve("127.0.0.1", https.server_address[1], *args, **kwargs)
        assert host == "127.0.0.1" and port == smtp.server_address[1], "NONFIXTURE_NETWORK_BLOCKED"
        return real_resolve(host, port, *args, **kwargs)

    settings = Settings(_env_file=None, database_url=f"sqlite:///{root / 'catalog.sqlite'}",
                        master_key_file=root / "master", staging_dir=root / "staging",
                        smtp_host="127.0.0.1", smtp_port=smtp.server_address[1], smtp_from="sender@fixture.invalid",
                        webhook_allowed_hosts=[FIXTURE_HOST, WRONG_HOST], allow_private_webhooks=True,
                        retry_limit=1, min_free_bytes=0)
    with monkeypatch.context() as scoped, _serving(smtp), _serving(https):
        scoped.setenv("SSL_CERT_FILE", str(ca_path))
        scoped.setattr(socket, "getaddrinfo", fixture_dns)
        scoped.setattr(socket.socket, "connect", fixture_connect)
        lab = NotificationLab(root, settings, smtp, https)
        try:
            yield lab
        finally:
            lab.engine.dispose()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    with notification_lab(tmp_path / "notification-lab", monkeypatch) as result:
        yield result


def _webhook_payloads(lab, config):
    payloads = []
    for request in lab.https.received:
        body = request["body"]
        expected = "sha256=" + hmac.new(config["signing_secret"].encode(), body, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(request["headers"]["X-VaultRewind-Signature"], expected)
        assert request["headers"]["Content-Type"] == "application/json"
        assert request["headers"]["Host"] == FIXTURE_HOST
        assert request["path"] == "/status" and request["tls"]
        payload = json.loads(body)
        assert set(payload) == STATUS_FIELDS
        assert config["signing_secret"].encode() not in body
        payloads.append(payload)
    return payloads


def _smtp_payloads(lab, config):
    payloads = []
    for raw in lab.smtp.accepted:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        payload = json.loads(message.get_content())
        assert set(payload) == STATUS_FIELDS
        assert message["Subject"] == "VaultRewind status: " + payload["code"]
        assert message["From"] == lab.settings.smtp_from
        assert message["To"] == config["recipients"][0]
        assert not message.is_multipart()
        assert config["password"].encode() not in raw
        assert config["username"].encode() not in raw
        payloads.append(payload)
    assert lab.smtp.envelopes_before_tls == 0
    assert lab.smtp.tls_sessions == lab.smtp.authenticated
    return payloads


def exercise_lifecycle(lab):
    _, smtp_config = lab.add_channel("smtp")
    _, hook_config = lab.add_channel("webhook")
    lab.add_channel("webhook", enabled=False)
    before = lab.seed_complete_backup()
    instance_id = lab.witness_ids[0]
    first = lab.raise_incident(instance_id)
    assert lab.raise_incident(instance_id) == first
    assert len(lab.deliveries()) == 2
    lab.drain(2)
    with lab.sessions.begin() as db:
        notifications.clear_alerts(db, instance_id, {"BACKUP_OVERDUE"})
    assert len(lab.deliveries()) == 2  # Clearing another condition must not send a recovery.
    with lab.sessions.begin() as db:
        notifications.clear_alerts(db, instance_id, {"REQUIRED_COPY_FAILED"})
        notifications.clear_alerts(db, instance_id, {"REQUIRED_COPY_FAILED"})
    assert len(lab.deliveries()) == 4
    lab.drain(2)
    second = lab.raise_incident(instance_id)
    assert second != first and lab.raise_incident(instance_id) == second
    lab.drain(2)
    expected = [{"event_id": event, "instance_id": instance_id, "code": "REQUIRED_COPY_FAILED", "status": status}
                for event, status in ((first, "active"), (first, "recovered"), (second, "active"))]
    assert _webhook_payloads(lab, hook_config) == expected
    assert _smtp_payloads(lab, smtp_config) == expected
    assert lab.https.sni_matches == 3
    assert len(lab.deliveries()) == 6
    assert all(row.state == "delivered" and row.attempt == 1 for row in lab.deliveries())
    assert all(row.state == "succeeded" for row in lab.jobs())
    with lab.sessions() as db:
        alerts = list(db.scalars(select(Alert).order_by(Alert.created_at)))
        assert len(alerts) == 2 and not alerts[0].active and alerts[0].resolved_at
        assert alerts[1].active and alerts[1].resolved_at is None
    assert lab.backup_witness() == before
    return {"smtp_starttls_messages": 3, "smtp_authenticated_sessions": 3, "https_signed_requests": 3,
            "logical_incidents": 2, "delivered_rows": 6, "recovery_events_per_channel": 1,
            "repeated_alert_deduplicated": True, "repeated_clear_deduplicated": True,
            "new_incident_has_new_identity": True, "disabled_channel_deliveries": 0,
            "status_only_payloads": True, "hmac_verified": True, "sni_verified": True}


def test_real_starttls_https_status_only_deduplication_and_recovery(lab):
    exercise_lifecycle(lab)


def exercise_retry(lab):
    _, config = lab.add_channel("webhook")
    before = lab.seed_complete_backup()
    lab.https.responses.append(503)
    lab.raise_incident(lab.witness_ids[0])
    assert lab.worker.run_once()
    job = lab.jobs()[0]
    assert job.state == "waiting_retry" and job.error_code == "NOTIFICATION_FAILED" and job.attempts == 1
    assert 0 < (utc(job.next_attempt_at) - now()).total_seconds() <= 12
    assert lab.deliveries()[0].state == "failed" and lab.deliveries()[0].error_code == "NOTIFICATION_FAILED"
    assert not lab.worker.run_once()  # Real claim must respect the scheduled backoff.
    assert lab.backup_witness() == before
    with lab.sessions() as db:
        assert db.scalar(select(JobEvent.id).where(JobEvent.job_id == job.id, JobEvent.code == "RETRY_SCHEDULED"))
    lab.due_retry(job.id)
    # Recreate worker/store to show retry is in the catalog, not an in-memory callback.
    lab.worker = Worker(lab.settings, engine=lab.engine, owner="synthetic-retry-worker")
    lab.drain(1)
    delivery = lab.deliveries()[0]
    assert delivery.state == "delivered" and delivery.error_code is None and delivery.attempt == 2
    assert lab.jobs()[0].state == "succeeded" and lab.jobs()[0].attempts == 2
    payloads = _webhook_payloads(lab, config)
    assert len(payloads) == 2 and payloads[0] == payloads[1]
    assert [request["status"] for request in lab.https.received] == [503, 204]
    assert lab.backup_witness() == before
    return {"attempts": 2, "http_status_codes": [503, 204], "backoff_enforced": True,
            "retry_survives_worker_recreation": True, "same_event_on_retry": True,
            "delivery_error_cleared": True, "backup_catalog_unchanged": True}


def test_real_https_retries_persist_without_invalidating_complete_backup(lab):
    exercise_retry(lab)


def exercise_terminal_failure(lab, kind):
    lab.add_channel(kind)
    before = lab.seed_complete_backup()
    receiver = lab.smtp if kind == "smtp" else lab.https
    receiver.responses.extend([451, 451] if kind == "smtp" else [503, 503])
    lab.raise_incident(lab.witness_ids[0])
    assert lab.worker.run_once()
    assert lab.jobs()[0].state == "waiting_retry"
    lab.due_retry(lab.jobs()[0].id)
    lab.drain(1)
    job, delivery = lab.jobs()[0], lab.deliveries()[0]
    assert job.state == delivery.state == "failed"
    assert job.error_code == delivery.error_code == "NOTIFICATION_FAILED"
    assert job.attempts == delivery.attempt == 2
    assert len(receiver.received) == 2
    assert lab.backup_witness() == before
    with lab.sessions() as db:
        assert len(list(db.scalars(select(Alert)))) == 1  # Failure must not recursively alert itself.
        assert not list(db.scalars(select(ResourceLease).where(ResourceLease.owner_job_id == job.id)))
    return {"attempts": 2, "terminal_code": "NOTIFICATION_FAILED", "delivery_failed_separately": True,
            "backup_catalog_unchanged": True, "recursive_alerts": 0, "leases_released": True}


@pytest.mark.parametrize("kind", ["smtp", "webhook"])
def test_real_transport_terminal_failure_is_bounded_and_separate_from_backup(lab, kind):
    exercise_terminal_failure(lab, kind)


def exercise_tls_rejection(lab, monkeypatch, kind, reason):
    _, config = lab.add_channel(kind)
    payload = {"event_id": uid(), "instance_id": None, "code": "BACKUP_OVERDUE", "status": "active"}
    with monkeypatch.context() as scoped:
        if reason == "untrusted_ca":
            untrusted = lab.root / "untrusted"
            untrusted.mkdir(mode=0o700)
            other_ca, _ = _certificates(untrusted)
            scoped.setenv("SSL_CERT_FILE", str(other_ca))
        elif kind == "webhook":
            config["url"] = f"https://{WRONG_HOST}/status"
        else:
            # Both fixture hostnames route to HTTPS; SMTP needs its own fixture-only DNS answer.
            resolver = socket.getaddrinfo

            def smtp_wrong_host(host, port, *args, **kwargs):
                if host == WRONG_HOST:
                    return resolver("127.0.0.1", lab.smtp.server_address[1], *args, **kwargs)
                return resolver(host, port, *args, **kwargs)

            scoped.setattr(socket, "getaddrinfo", smtp_wrong_host)
            scoped.setattr(lab.settings, "smtp_host", WRONG_HOST)
        with pytest.raises(VaultRewindError) as error:
            notifications.send(lab.settings, kind, config, payload)
    assert error.value.code == "NOTIFICATION_FAILED" and error.value.retryable
    assert not lab.smtp.received and not lab.https.received
    assert lab.smtp.auth_attempts == lab.smtp.envelopes_before_tls == 0
    return {"code": "NOTIFICATION_FAILED", "messages_sent": 0, "auth_before_valid_tls": 0}


@pytest.mark.parametrize("kind", ["smtp", "webhook"])
@pytest.mark.parametrize("reason", ["untrusted_ca", "hostname_mismatch"])
def test_real_tls_rejects_untrusted_ca_and_wrong_hostname(lab, monkeypatch, kind, reason):
    exercise_tls_rejection(lab, monkeypatch, kind, reason)


def exercise_starttls_required(lab):
    _, config = lab.add_channel("smtp")
    lab.smtp.starttls = False
    with pytest.raises(VaultRewindError) as error:
        notifications.send(lab.settings, "smtp", config,
                           {"event_id": uid(), "instance_id": None, "code": "BACKUP_OVERDUE", "status": "active"})
    assert error.value.code == "NOTIFICATION_FAILED"
    assert lab.smtp.auth_attempts == lab.smtp.envelopes_before_tls == 0
    assert not lab.smtp.received
    return {"code": "NOTIFICATION_FAILED", "plaintext_messages": 0, "plaintext_authentication": 0}


def test_smtp_without_starttls_never_receives_credentials_or_message(lab):
    exercise_starttls_required(lab)


def exercise_destination_guards(lab, monkeypatch):
    _, config = lab.add_channel("webhook")
    payload = {"event_id": uid(), "instance_id": None, "code": "BACKUP_OVERDUE", "status": "active"}
    defaults = Settings(_env_file=None, webhook_allowed_hosts=[], allow_private_webhooks=False)
    with pytest.raises(VaultRewindError) as error:
        notifications.send(defaults, "webhook", config, payload)
    assert error.value.code == "WEBHOOK_DESTINATION_BLOCKED"
    defaults.webhook_allowed_hosts = [FIXTURE_HOST]
    with pytest.raises(VaultRewindError) as error:
        notifications.send(defaults, "webhook", config, payload)
    assert error.value.code == "WEBHOOK_DESTINATION_BLOCKED"  # Allowlisting alone does not allow loopback.
    blocked = [f"http://{FIXTURE_HOST}/status", f"https://{FIXTURE_HOST}:8443/status",
               f"https://user:fixture@{FIXTURE_HOST}/status", f"https://{FIXTURE_HOST}/status?secret=fixture",
               f"https://{FIXTURE_HOST}/status#fragment", "https://169.254.169.254/latest/meta-data/"]
    for url in blocked:
        with pytest.raises(VaultRewindError) as error:
            notifications.send(lab.settings, "webhook", {"url": url}, payload)
        assert error.value.code == "WEBHOOK_DESTINATION_BLOCKED"
    # A safe first answer must not bypass a private second answer (DNS rebinding boundary).
    with monkeypatch.context() as scoped:
        scoped.setattr(socket, "getaddrinfo", lambda *_a, **_kw: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ])
        with pytest.raises(VaultRewindError) as error:
            notifications.send(defaults, "webhook", config, payload)
        assert error.value.code == "WEBHOOK_DESTINATION_BLOCKED"
    assert not lab.https.received
    return {"blocked_configurations": 9, "code": "WEBHOOK_DESTINATION_BLOCKED", "requests_sent": 0,
            "allowlist_required": True, "private_network_blocked": True, "mixed_dns_answers_blocked": True}


def test_webhook_allowlist_private_network_and_url_guards(lab, monkeypatch):
    exercise_destination_guards(lab, monkeypatch)


def exercise_lost_acknowledgement(lab):
    _, config = lab.add_channel("webhook")
    event_id = lab.raise_incident()
    with lab.sessions.begin() as db:
        job = claim(db, "synthetic-lost-ack-worker")
        # Persist the ambiguous checkpoint a terminated worker would leave.
        db.add(JobStep(job_id=job.id, name="deliver", sequence=1, fencing_token=job.fencing_token))
    payload = {"event_id": event_id, "instance_id": None, "code": "REQUIRED_COPY_FAILED", "status": "active"}
    notifications.send(lab.settings, "webhook", config, payload)
    with lab.sessions.begin() as db:
        db.get(Job, job.id).lease_expires_at = now() - timedelta(seconds=1)
    # No process termination: the next real claim observes and reconciles the expired lease.
    lab.drain(1)
    payloads = _webhook_payloads(lab, config)
    assert len(payloads) == 2 and payloads[0] == payloads[1] == payload
    assert len(lab.deliveries()) == 1 and lab.deliveries()[0].state == "delivered"
    assert lab.jobs()[0].reconcile_required and lab.jobs()[0].state == "succeeded"
    assert lab.jobs()[0].fencing_token > job.fencing_token
    with lab.sessions() as db:
        step = db.scalar(select(JobStep).where(JobStep.job_id == job.id))
        assert step.state == "complete" and step.attempt == 2
    return {"https_requests": 2, "delivery_rows": 1, "same_event_status": True,
            "at_least_once_reconciliation": True, "fence_advanced": True}


def test_real_expired_lease_reconciliation_reuses_event_status_for_recipient_dedupe(lab):
    exercise_lost_acknowledgement(lab)


def run_notification_proof(root: Path, monkeypatch):
    """Run the same integration assertions and export only counts/booleans/codes."""
    checks = {}
    scenarios = [("lifecycle", exercise_lifecycle), ("retry", exercise_retry),
                 ("smtp_terminal_failure", lambda lab: exercise_terminal_failure(lab, "smtp")),
                 ("webhook_terminal_failure", lambda lab: exercise_terminal_failure(lab, "webhook")),
                 ("starttls_required", exercise_starttls_required),
                 ("destination_guards", lambda lab: exercise_destination_guards(lab, monkeypatch)),
                 ("lost_acknowledgement", exercise_lost_acknowledgement)]
    for kind in ("smtp", "webhook"):
        for reason in ("untrusted_ca", "hostname_mismatch"):
            scenarios.append((f"{kind}_{reason}",
                              lambda lab, k=kind, r=reason: exercise_tls_rejection(lab, monkeypatch, k, r)))
    for name, scenario in scenarios:
        with notification_lab(root / name, monkeypatch) as lab:
            checks[name] = scenario(lab)
    return {"schema_version": 1, "result_code": "PASS", "scenario_count": len(scenarios), "checks": checks,
            "boundaries": {"real_smtp_starttls": True, "real_https": True, "real_sqlite_queue_worker": True,
                           "encrypted_channel_configuration": True, "loopback_only": True,
                           "ephemeral_certificates_minutes": 15, "host_trust_modified": False,
                           "product_tls_modified": False, "external_mail_delivery_verified": False,
                           "postgresql_concurrency_verified": False, "backup_witness_seeded_catalog_only": True,
                           "dns_fixture_port_redirect": True, "shared_fixture_calls": 0,
                           "native_controller_calls": 0, "processes_killed": 0}}

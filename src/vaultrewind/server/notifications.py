"""Deduplicated status-only alerts. Notification failures do not alter backup validity."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import smtplib
import socket
import ssl
from email.message import EmailMessage
from urllib.parse import urlsplit

from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .db import now, uid
from .errors import safe_code
from .models import Alert, NotificationChannel, NotificationDelivery
from .queue import enqueue


def validate_channel(settings, kind, config):
    if kind == "webhook":
        url = urlsplit(config.get("url", ""))
        if (url.scheme != "https" or not url.hostname or url.hostname not in settings.webhook_allowed_hosts or
                url.username or url.password or url.fragment or url.query or url.port not in {None, 443}):
            raise VaultRewindError("WEBHOOK_DESTINATION_BLOCKED", "Select a verified HTTPS host on the webhook allowlist.")
    elif kind == "smtp":
        if not settings.smtp_host or not settings.smtp_from or not config.get("recipients"):
            raise VaultRewindError("SMTP_NOT_CONFIGURED", "Configure the controller SMTP connection and recipients.")
        if not isinstance(config["recipients"], list) or len(config["recipients"]) > 20:
            raise VaultRewindError("VALIDATION_ERROR", "Invalid SMTP recipients.")
        if any(not isinstance(v, str) or "@" not in v or "\n" in v or "\r" in v for v in config["recipients"]):
            raise VaultRewindError("VALIDATION_ERROR", "Invalid SMTP recipients.")


def raise_alert(db, instance_id, code):
    code = safe_code(code)
    key = f"{instance_id or 'controller'}:{code}"
    alert = db.scalar(select(Alert).where(Alert.dedupe_key == key).with_for_update())
    if alert and alert.active:
        return alert
    if alert:
        # Each incident receives its own identity; keep previous delivery history.
        alert.dedupe_key = f"history:{alert.id}"
        db.flush()
    alert = Alert(id=uid(), instance_id=instance_id, code=code, dedupe_key=key, active=True)
    db.add(alert)
    db.flush()
    deliver_alert(db, alert, False)
    return alert


def clear_alerts(db, instance_id, codes=None):
    for alert in db.scalars(select(Alert).where(Alert.instance_id == instance_id, Alert.active.is_(True)).with_for_update()):
        if codes is not None and alert.code not in codes:
            continue
        alert.active, alert.resolved_at = False, now()
        deliver_alert(db, alert, True)


def deliver_alert(db, alert, recovery):
    for channel in db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True))):
        delivery = NotificationDelivery(id=uid(), event_id=alert.id, channel_id=channel.id, recovery=recovery)
        db.add(delivery)
        db.flush()
        enqueue(db, kind="notification", request={"delivery_id": delivery.id}, key=f"notification:{delivery.id}",
                resources=[f"notification:{delivery.id}"])


def webhook(settings, config, body: bytes):
    validate_channel(settings, "webhook", config)
    url = urlsplit(config["url"])
    addresses = socket.getaddrinfo(url.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise VaultRewindError("NOTIFICATION_FAILED", "The webhook host could not be resolved.")
    if not settings.allow_private_webhooks and any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise VaultRewindError("WEBHOOK_DESTINATION_BLOCKED", "The webhook address is outside the allowed network boundary.")
    # Connect to the address we checked; keep SNI and certificate hostname validation.
    family, socktype, proto, _, sockaddr = addresses[0]
    raw = socket.socket(family, socktype, proto)
    raw.settimeout(15)
    connection = http.client.HTTPSConnection(url.hostname, 443, timeout=15, context=ssl.create_default_context())
    try:
        raw.connect(sockaddr)
        connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=url.hostname)
        headers = {"Content-Type": "application/json", "User-Agent": "VaultRewind/1"}
        if config.get("signing_secret"):
            headers["X-VaultRewind-Signature"] = "sha256=" + hmac.new(config["signing_secret"].encode(), body, hashlib.sha256).hexdigest()
        connection.request("POST", url.path or "/", body=body, headers=headers)
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise VaultRewindError("NOTIFICATION_FAILED", "The webhook did not accept the status notification.", retryable=True)
        response.read(1024)
    finally:
        connection.close()
        raw.close()


def send(settings, kind, config, payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    try:
        if kind == "webhook":
            webhook(settings, config, body)
        else:
            validate_channel(settings, "smtp", config)
            message = EmailMessage()
            message["Subject"] = "VaultRewind status: " + payload["code"]
            message["From"] = settings.smtp_from
            message["To"] = ", ".join(config["recipients"])
            message.set_content(body.decode())
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                if config.get("username"):
                    smtp.login(config["username"], config.get("password", ""))
                smtp.send_message(message)
    except VaultRewindError:
        raise
    except (OSError, ValueError, smtplib.SMTPException, http.client.HTTPException):
        raise VaultRewindError("NOTIFICATION_FAILED", "Status notification delivery failed.", retryable=True) from None

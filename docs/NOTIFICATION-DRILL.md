# Local notification delivery drill

This drill verifies specification section 20 and the notification confidentiality
portion of AC31. It uses real SMTP STARTTLS and HTTPS sockets with a real relational
SQLite catalog, encrypted channel configuration, transactional queue claims and
`Worker.run_once()`. It needs no external account or service.

Run from the repository using the locked development environment:

```sh
uv run --locked pytest tests/unit/test_notifications_delivery.py -q
uv run --locked python scripts/prove_notifications.py
uv run --locked ruff check tests/unit/test_notifications_delivery.py scripts/prove_notifications.py
uv run --locked python -m py_compile tests/unit/test_notifications_delivery.py scripts/prove_notifications.py
```

The standalone proof deliberately reuses the focused test harness and all its
integration assertions. It regenerates the fixture for each scenario, exits
nonzero on failure, and writes `docs/evidence/notifications.json` only after every
scenario passes. Its stdout and saved evidence contain counts, booleans and stable
codes; it suppresses raw exceptions and protocol transcripts. A prior evidence
file is not a successful result for a subsequent failed run: check the exit code.

The successful local run covered 11 scenarios:

- One incident delivered through both channels, one recovery delivered through
  both, then a new incident with a new event ID: three accepted SMTP messages,
  three signed HTTPS requests, six delivered queue rows. Repeated active alerts
  and repeated clears created no additional deliveries. Clearing an unrelated
  condition sent no recovery. A disabled third channel received nothing.
- The SMTP fixture required STARTTLS and authenticated the generated synthetic
  credentials over TLS before accepting an envelope. The test parsed the actual
  received MIME messages and checked their status payloads and subjects.
- HTTPS requests used verified TLS and the fixture hostname as SNI and HTTP Host.
  The receiver independently verified HMAC-SHA256 over the exact received bytes.
  Both transports contained exactly `event_id`, `instance_id`, `code` and `status`
  in their JSON payloads. Configuration, credentials and private instance labels
  were absent. Mail necessarily included fixture From/To headers.
- An HTTPS 503 scheduled a durable retry; another claim before its deadline did
  nothing. After advancing only the persisted eligibility timestamp, a new worker
  delivered the same event successfully. The delivery's current error cleared.
- Two SMTP 451 responses and, separately, two HTTPS 503 responses exhausted the
  configured one-retry fixture budget. Each notification job and delivery ended
  failed with `NOTIFICATION_FAILED`, released its leases and created no recursive
  notification alert.
- Both transports rejected an unrelated CA and a hostname mismatch, with no
  message or credential transmission. A server without STARTTLS received neither
  plaintext credentials nor a plaintext message.
- Nine destination checks blocked an absent allowlist, loopback under the
  private-network default, HTTP, an alternate URL port, embedded credentials,
  query, fragment, a metadata destination, and mixed public/private DNS answers.
  The mixed-address test connects to neither address.
- A real accepted HTTPS request followed by a seeded unfinished delivery checkpoint
  and expired lease caused the next worker to reconcile and resend the same event
  ID/status with an advanced fence. There was one logical delivery row and two
  requests. This establishes at-least-once behavior; receivers must deduplicate on
  `(event_id, status)`. No process was killed.

All notification failure/retry checks preserved a seeded complete backup job,
snapshot and verified copy plus the instance's backup/source health. This proves
catalog isolation for notification work; this drill does not execute a backup,
run restic, contact a source, or prove backup content validity.

## Isolation and TLS

Every server binds `127.0.0.1` on an ephemeral port. The harness refuses nonfixture
DNS lookups and socket connections outside those two loopback ports. The webhook
product accepts HTTPS on logical port 443 only, so a
scoped fixture DNS answer maps its reserved `.invalid` hostname to the ephemeral
loopback receiver. TCP, TLS, SNI/hostname verification, HTTP, signing and delivery
are real. No sender, TLS verifier, queue or worker is mocked.

The private CA and server certificate expire after 15 minutes. Certificates use
strict-verification-compatible key usage and authority/subject key identifiers.
The CA private key stays in memory. Leaf keys, the random controller key and
SQLite catalog live under a temporary mode-0700 root; key files are mode 0600.
Synthetic SMTP passwords and webhook secrets are generated per scenario, held in
memory and stored encrypted in the disposable catalog. Temporary files are
deleted on exit, servers are closed, and threads are joined.

Only the proof/test process trusts the generated CA through scoped `SSL_CERT_FILE`;
the previous value is restored afterward. No OS trust store changes occur.
The fixture explicitly enables private webhooks only in its own `Settings`
instance. Separate negative tests retain the restrictive network defaults.
Product source, TLS rules, allowlist rules and production defaults are untouched.

## Limits

This is local protocol and notification-worker evidence, not external mail
delivery, mailbox receipt, provider interoperability, public DNS verification,
SMTP OAuth, PostgreSQL concurrency, browser notification configuration, or an
end-to-end backup proof. It makes no claim of exactly-once transport delivery.
Retry waiting is shortened by moving only an isolated SQLite job's persisted
deadline; the actual backoff deadline and claim gate are checked first. The lost
acknowledgement state is seeded without killing a process.

No native controller/API/database, `.runtime/controller`, shared source fixture,
SSH, Docker, MinIO, VM, browser, production environment or external recipient is
accessed. This drill adds no host services or dependencies.

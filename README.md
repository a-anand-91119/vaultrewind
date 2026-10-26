# VaultRewind

**One-click backup. One-click restore.** A self-hosted recovery manager for multiple Linux/Docker Vaultwarden instances using SQLite.

VaultRewind captures the complete persistent instance, deployment material and exact saved application image. A brief controlled source stop produces coherent database/filesystem content; the source resumes before normalization, transfer or cloud upload. Standard encrypted restic repositories store dated immutable recovery points on persistent local disk, S3-compatible storage or Google Drive.

The engineering contract is [VAULTREWIND-SPEC.md](VAULTREWIND-SPEC.md); execution constraints are [AGENT-HANDOFF.md](AGENT-HANDOFF.md). See [acceptance evidence](docs/ACCEPTANCE.md) for verified behavior and remaining release gates. Passing a storage round trip alone does not prove safe application replacement.

For an owner-reviewed installation, use the [production plan](docs/PRODUCTION-PLAN.md) and [release checklist](docs/RELEASE-CHECKLIST.md). These identify the required host, storage, HTTPS and recovery decisions; production access and deployment require separate authorization.

## Local installation

Supported controller build: Linux amd64, Docker Engine with Compose v2.24+ (the development override uses `!override`), persistent storage and HTTPS behind an existing reverse proxy. The controller does not mount the Docker socket. Source/target hosts require Linux, Docker, Python 3.13+ and functioning systemd recovery units. Other controller architectures require reviewed binary checksums before building.

The supported Vaultwarden health profile uses container HTTP port 80; the published host port is configurable. Running restores require approved fixed host bindings on a compatible non-internal bridge. Custom internal ports, host/shared networking and unsupported dependencies fail during discovery/preflight. See the [operator boundary](docs/OPERATIONS.md).

```sh
# From this checkout; this prepares private files but starts no service.
sudo python3 scripts/prepare-install.py \
  --data-dir /srv/vaultrewind-controller \
  --origin https://recovery.example.invalid

# Local installation only; review configuration before starting.
docker compose build
docker compose up -d
```

Production API/UI is bound to `127.0.0.1:8097`. Route your selected HTTPS origin to it. Keep the database private. No public registration/default password exists: privately read `.secrets/bootstrap`, enter it in first-run setup, and choose the administrator password/timezone. Never paste the bootstrap secret into chat or logs. Back up `.secrets` separately with restrictive permissions; loss of the controller master key makes its database secrets unreadable. The independently encrypted recovery kit still opens application repositories.

The installer creates separate `backups`, `staging`, `cache`, `metadata` and `provider-credentials` directories owned by UID/GID 10001, three mode-0600 secret files and a nonsecret `.env`. Provider credential recovery state is persistent: preserve it with the controller keys and never clear it as cache. If running without root, arrange the displayed ownership before startup. The PostgreSQL data is in the named `database` volume. Preserve it when recreating containers; do not use `down --volumes` on a real installation.

Loopback development exception:

```sh
docker compose -f compose.yml -f compose.dev.yml up --build -d
# Open http://127.0.0.1:8000 (or forward that loopback port securely).
```

This exception disables Secure cookies only for a loopback origin. Source hosts and cloud endpoints retain their own identity/TLS checks.

## Onboard, then operate

1. Connect a host with an independently verified SSH host public key. Read-only discovery makes no host changes.
2. Review the helper activation plan, enrolled filesystem roots, exact container/image identities, dependencies and maintenance budget. Activation explicitly installs a root helper, constrained sudo policy, independent watchdog and boot reconciliation unit. A separate setup credential can be removed after activation; routine operation uses the constrained account.
3. Enroll each supported instance and any prepared alternate target. Resolve external network/proxy/hostname dependencies before advertising readiness.
4. Add/test destinations and choose at least one required copy in the instance policy. Set daily/hourly schedule, IANA timezone, rolling-day retention and a separate isolated restore-test runner.
5. Export an independently encrypted recovery kit. Store its passphrase and kit outside Vaultwarden and VaultRewind.

After onboarding, **Backup now** queues the complete job in one action. **Restore** opens one compact confirmation bound to the exact snapshot and target. Replacing an existing target always commits a pinned encrypted local safety snapshot before switching; the old generation is retained. Alternate restores do not reconfigure the original, DNS or external identity providers.

## Development and verification

Dependencies are pinned in `uv.lock`, `frontend/package-lock.json` and `tools/*lock.json`. Official release tool archives are checksum checked during image build.

```sh
uv sync --frozen
npm ci --prefix frontend
uv run pytest tests/unit -q
npm run build --prefix frontend
uv run python -m scripts.prove_core
uv run python -m scripts.prove_application
# Explicit disposable localhost/systemd activation, never a production target:
uv run python -m scripts.prepare_ssh_fixture
uv run python -m scripts.prove_ssh
# Requires the synthetic MinIO fixture described in the evidence procedures:
uv run python -m scripts.prove_s3
```

`prove_core` proves real SQLite WAL/restic storage. `prove_application` boots real Vaultwarden from the saved image without a registry pull. They explicitly distinguish application startup from authenticated login and from transactional SSH replacement.

The separate [authenticated recovery drill](docs/AUTHENTICATED-RECOVERY-DRILL.md) proves a real official-client login, unlock and sync after a LOCAL replacement restore, including decrypted login content and an attachment downloaded byte-for-byte. It uses a dedicated synthetic account and disposable instance.

See [reproducible test procedures](docs/TESTING.md) for the disposable SSH/systemd VM and MinIO fixtures. The [dedicated Google Drive report](docs/evidence/drive-release.json) records real authorization, persisted token refresh, backup, alternate restore, retention, revoked-credential failure, Reconnect and same-snapshot retry. The [acceptance ledger](docs/ACCEPTANCE.md) distinguishes recorded proof scopes and remaining limitations.

[Operator guide](docs/OPERATIONS.md) · [Testing](docs/TESTING.md) · [Remote helper](docs/REMOTE.md) · [Storage](docs/STORAGE.md) · [Recovery](docs/RECOVERY.md) · [API](docs/API-CONTRACT.md) · [Acceptance](docs/ACCEPTANCE.md)

[Dashboard review](docs/DASHBOARD-REVIEW.md) · [Production plan](docs/PRODUCTION-PLAN.md) · [Release checklist](docs/RELEASE-CHECKLIST.md)

No telemetry by default. No production deployment or publication is implied by this repository.

# Operating VaultRewind

## Supported boundary

Release one supports one Vaultwarden Linux Docker container per enrolled instance with `/data` on a host bind directory or supported local named volume, using SQLite. Multiple instances/hosts are supported. Native/systemd Vaultwarden, official Bitwarden, PostgreSQL/MySQL application databases, Kubernetes and unsupported volume drivers are rejected. The supported application boundary is not an entire VM, DNS account, reverse proxy or identity provider.

The supported health profile uses `ROCKET_PORT=80` and a container listener on `0.0.0.0` or `::`. Host port mappings are configurable; a running restore needs an approved fixed mapping for container HTTP port 80 and a non-internal bridge capable of publishing it. Custom internal ports and host/shared network namespaces are rejected before capture or replacement. Prepared isolated test runners use no public ports and never cross the activation boundary.

Every persistent mount and required deployment/configuration/secret file must be enrolled. Unknown regular files are captured. Unreadable required files, special files, unsafe external links, unknown writers or unsupported metadata fail completeness. Do not change source permissions to work around an error. Root-owned private files are expected and handled through the constrained privileged helper.

## Source pause and consistency

A backup records the original service state, verifies remote recovery, exports the immutable image, arms a watchdog, stops every enrolled writer cleanly and copies the complete instance to private remote staging. It restores the original running/stopped state before normalizing only the staged database through SQLite's backup API, transferring or uploading. WAL content participates in normalization; staged WAL/SHM companions are removed only after success. Production database companions are never deleted by backup.

The default capture budget is 300 seconds. It is an outage ceiling enforced independently on the source, not a performance guarantee. Source failure and stored-copy validity are independent outcomes. A valid local copy can remain restorable after a required cloud copy fails, while the overall job is partial/failed. Retry the same immutable capture where possible rather than pausing the changing source again.

## Restore and the activation boundary

Choose a dated snapshot, inspect capture time/age, exact image and copy evidence, then confirm the bound target. Download, checksum/database validation, image import and target-generation staging precede downtime.

For replacement, a pinned durable encrypted local safety snapshot is mandatory. If it cannot be committed/read back, the old target resumes and switching is aborted. No normal API or UI switch skips this protection. The old container/descriptor and data generation remain available, with visible storage accounting.

The candidate is booted privately with no published application ports and no outbound network. Startup/structure/attachment validation uses a disposable candidate copy. It cannot send notifications or contact identity providers. Public activation is a separate durable decision. Before activation, a failure recovers and verifies the old generation. After `activation_started`, the new generation is preserved: a client might already have written to it. An unresolved state becomes `needs_attention`; a later rollback is a newly confirmed restore with its own safety capture.

An initially stopped instance remains stopped after backup and after a data-only restore unless start-on-completion was explicitly selected. Its isolated candidate can still be validated. Do not interpret `data_restored_service_stopped` as a running service.

Alternate targets must already have approved data paths, compatible architecture, Docker/systemd/helper, image approval, networks/ports, hostname/public URL and dependencies. An alternate restore leaves the original source running and unchanged. Domain changes may require WebAuthn/identity-provider re-enrollment. DNS/proxy changes are separate authorized work.

## Retention and schedules

Keep every completed snapshot captured at or after `retention_run_utc - X*24 hours`, including multiple captures per day and the exact cutoff. Keep forever is explicit. Pin/safety/active-input/administrator holds, each destination's newest complete point, and newest successful application-tested point remain protected. Imported/future-dated captures stay protected for review.

Automatic deletion freezes during failure, degraded required copies, overdue backup or uncertainty. VaultRewind computes exact eligible copy IDs under locks and rechecks before deletion. Forgetting a snapshot and reclaiming chunk space through pruning are separate operations; object locks or missing delete permission can leave actual copies retained. Never run broad restic retention flags around the controller or force-unlock a live repository owner.

Daily schedules use an IANA timezone. A repeated DST time runs at its first occurrence; a nonexistent time moves to the first valid minute. Hourly intervals are UTC-based. Restart coalesces missed runs into one catch-up per policy. Manual backup does not erase the next scheduled occurrence. Pausing the schedule leaves Vaultwarden running.

## Trust labels

- Capture validated: complete inventory, normalized SQLite and reference checks.
- Stored copy verified: exact committed snapshot and manifest readback.
- Full data verified: every repository data pack read cryptographically; metadata/subset checks carry narrower labels.
- Restored bytes verified: extracted content matches the manifest.
- Application started: recorded image starts and structural health passes in isolation.
- User login tested: only a separately configured dedicated synthetic account/procedure can establish this. Routine backups do not request master passwords.

No configured runner means “Restore testing not configured”, never “Restore tested”. Keep weekly full checks and isolated restore tests separate from regular backup success.

## Keys, controller backup and recovery

Keep the controller master key outside PostgreSQL, outside source control, and outside every controller backup repository. Provider/SSH/repository secrets use authenticated encryption at rest. Rotating provider authorization is distinct from rotating repository unlock keys; preserve historical readability and export an updated kit when repository unlock material changes.

Export the encrypted recovery kit with a separate user-held passphrase. Store both outside the protected vault and controller. Do not send the kit in notifications. Follow [RECOVERY.md](RECOVERY.md) to drill recovery with a fresh controller and no original database/master key. Imported repositories start protected with automatic retention disabled.

Preserve the Compose PostgreSQL volume and private master key. Configure **Controller backup policy** in Settings with a durable destination and daily time (or trigger **Back up controller now**). This backs up PostgreSQL metadata plus the independently sealed catalog to an encrypted restic controller repository, reads the exact snapshot back, and records status. Review **Controller backups** for last result and staleness. The controller backup policy is separate from each Vaultwarden instance's backup/retention policy. The master key is intentionally excluded; keep it in a separate protected recovery location. The encrypted recovery kit is independently required to unlock application repositories if the controller database and master key are lost.

For HTTP automation, use `PUT /api/v1/controller-backup-policy` with the current `If-Match` revision and `{destination_id,enabled,timezone,daily_time}`; run an immediate job with `POST /api/v1/controller-backups` and optional `{destination_id}`. Do not make an ad hoc `pg_dump` the operating procedure: it does not create or verify the sealed catalog/restic recovery point tracked by the application. Follow [CONTROLLER-BACKUP.md](CONTROLLER-BACKUP.md) for standalone validation and deliberate offline restore.

## Errors and recovery

`SSH_HOST_KEY_CHANGED`: stop work; verify the changed host identity independently before reviewing enrollment. Never disable checking.

`SOURCE_RESTART_CONFLICT`: identify the competing writer/auto-healer/deployment controller and establish a supported maintenance agreement. Do not disable arbitrary host jobs automatically.

`REQUIRED_FILE_UNREADABLE` / `SNAPSHOT_INCOMPLETE`: inspect only privileged host diagnostics and approved paths; no Complete label is valid until resolved.

`INSUFFICIENT_SPACE` / `LOCAL_MOUNT_UNAVAILABLE`: restore the approved persistent mount/capacity; do not evict protected recovery points to make room.

`STORAGE_AUTH_EXPIRED`: reconnect the provider privately. Refresh-token changes must be persisted under the credential lock. Inspect provider quota/rate limits without exposing raw output.

`SOURCE_RECOVERY_FAILED`: source service recovery takes priority over uploads; inspect the durable remote journal and systemd watchdog. Stored-copy validity remains visible independently.

`CREDENTIAL_PERSIST_FAILED`: a Drive refresh produced rotated credentials that could not be durably committed. The encrypted pending credential state and scratch files are deliberately retained; do not clean staging, delete pending state, or reconnect using an older token. Restore persistent credential storage, then retry/reconcile the pending persistence path or complete a fresh private grant if the error says the prior grant is unusable. A retry must reserve its full staging budget again before doing work.

`provider-credentials` is a dedicated persistent host mount, distinct from cache. Its encrypted pending updates and Drive session registry allow another worker to recover a token after abrupt process death, including across job directories. Do not apply TTL cleanup to this directory or remove registered `rclone.conf` files from retained staging. Preserve master keys until both pending updates and registered sessions have been reconciled. `CREDENTIAL_SESSION_BUSY` means a prior writer may still be alive; resolve that process before retrying. A pre-release installation using `cache/provider-credentials` must stop workers and preserve/move that entire directory to the configured `VAULTREWIND_PROVIDER_CREDENTIAL_STATE_DIR` before upgrading; never start with an empty replacement while unrecovered state exists.

`REMOTE_JOURNAL_MISSING`: the controller cannot prove what an issued remote operation did. Preserve all source/target generations and local resource leases. Do not resubmit capture or restore as a new operation, and do not manually delete helper journal/generation data. Inspect the host locally, restore the journal from its protected recovery copy if available, then use the job reconciliation action only after journal evidence is available. Missing journal is an unresolved state, not evidence that the operation never ran.

Controller staging quota tracks both reserved and observed retained bytes across jobs. A retry that resumes work must reserve the full configured per-job allowance again; old observed bytes count against global quota until cleanup succeeds. Failed/ambiguous operations can retain staging for recovery, so quota pressure may persist until an operator resolves the underlying state. `INSUFFICIENT_SPACE` requires adding capacity or safely resolving eligible retained scratch; it never authorizes eviction of protected snapshots or generations.

`rolled_back`: the original service state was verified. `rollback_failed`: preserve both generations/journal for operator repair. `needs_attention` after activation: preserve the new generation and possible client writes; do not blindly revert.

After controller/worker/SSH failure, restart the controller normally and let it reconcile helper journals and stored commits. An expired controller lease does not prove the remote operation stopped. Cancellation during downtime completes only after required recovery. Closing a browser has no effect on operation lifetime.

## Upgrade and removal

Back up metadata/private keys and export a fresh recovery kit before upgrading. Stop queue intake, finish/reconcile armed source/restore transactions, migrate the controller schema and verify readiness. Helper upgrades are explicit checksum-reviewed administrative operations, blocked while a recovery journal is armed. Compare protocol compatibility before source changes. Existing application snapshots retain their old manifest schema/content identity; a controller upgrade never upgrades Vaultwarden implicitly.

An upgrade plan may explicitly include reconciliation of superseded legacy status records. Admission requires the reviewed helper to prove a newer completed, currently owned and healthy generation for every affected record; it rechecks the same operation IDs and journal hashes under the host lock through installation. Only historical metadata changes afterward. Original warnings/history remain, old public readiness stays unverified, and no retired container is restarted. Current uncertain operations and armed recovery transactions continue to block upgrades. Never clear journal phases by hand to bypass that gate.

Review Alembic migration downgrade behavior on a disposable copy. A downgrade that drops newly introduced catalog tables is destructive; preserve an independent metadata backup and prefer restoring the known previous controller/catalog pair. Never delete application repositories as part of schema rollback.

Archive dashboard registrations without deleting repositories. Storage deletion is a separate confirmed preview. To remove helper access, first confirm no armed recovery work, preserve/export journals as needed, remove the restricted SSH key/sudo rule, disable the recovery units and explicitly remove the root-owned helper/policy bundle. Do not remove application data or old generations while a recovery decision is unresolved.

# Controller metadata backup and recovery

Controller backup protects VaultRewind's PostgreSQL metadata, including every database table and row, encrypted secret envelopes, policy state, repository identity, and audit history. It does not replace the independently passphrase-encrypted recovery kit, and it does not contain the controller master key. Keep the master key outside the controller database and backups. The encrypted database can only decrypt its stored secret envelopes when the original master key is available; the recovery kit independently unlocks the application repositories.

## Backup format and guarantees

A controller repository is a standard encrypted restic repository stored under the selected destination's `vaultrewind/<controller UUID>/<destination UUID>` path. Its repository password is derived from the controller recovery root and those stable UUIDs. `Repository.purpose="controller"` and `instance_id=NULL` mark it as a controller repository. Provider credentials continue to come from the existing encrypted destination records and are passed through the provider adapter's private credential channel.

Each backup is a new immutable restic snapshot, even when the database contents did not change. Its root contains a PostgreSQL custom-format `database.dump`, a separately sealed all-table/all-row catalog, `controller-manifest.json`, and `controller-inventory.json`. The controller manifest and inventory have independent schema versioning and are not passed through the Vaultwarden snapshot verifier. The manifest records the PostgreSQL server version and the `pg_dump`/`pg_restore` client versions. Restic provides repository encryption, chunking and standard storage behavior; the controller adapter verifies the exact snapshot tags, reads the snapshot back, compares its manifest/inventory, and hashes every restored file before the `ControllerBackup` row becomes `complete`.

The catalog is exported in the same PostgreSQL `REPEATABLE READ` snapshot as `pg_dump`, using `pg_export_snapshot()` and `pg_dump --snapshot`. Catalog values use explicit JSON encodings for timestamps, UUIDs, bytes, decimals and intervals. The catalog is chunked and authenticated with the established SecretBox implementation. Its key is HKDF-derived from the independent recovery root, controller UUID and physical repository identity; each descriptor and chunk uses a context bound to the controller, repository and snapshot. The recovery root can be supplied from the recovery kit, so catalog verification does not need the controller master key. Restic encryption remains required in addition to catalog sealing.

`Settings.controller_backup_max_bytes` is applied to the dump, catalog, sealed files and final staged inventory. `Settings.controller_backup_max_age_days` is used by `public_status()` to report stale protection. A database dump is never considered successful when `pg_dump` is absent, returns nonzero, produces an empty archive, fails `pg_restore --list`, exceeds the size limit, or fails exact restic readback. Passwords are written only to a mode-0600 `PGPASSFILE`; no password appears in process arguments or persisted command output. The pgpass file is removed before the capture tree is inventoried.

Restic provider work is stored below the private persistent state cache at `staging_dir.parent/cache/controller-backup/<job UUID>`, never inside the controller capture root or disposable job staging. Restic creates its own transient repository-password file under that work directory, so this placement is part of the backup boundary: if provider scratch is put below the captured root after inventory creation, restic can commit files absent from the inventory and readback must fail. Per-job work directories are scrubbed when the worker exits; restic's own repository encryption remains required.

Controller snapshots are retained as historical snapshots. The controller module does not apply a retention rule; the policy/API wiring must not automatically remove recovery history. Repository commits use restic's normal lock and the controller layer holds an additional process lock keyed by the physical repository identity. Enqueue controller jobs with the matching `repository:<physical_identity>` and `credential:<destination_id>` resources so the worker's durable leases also serialize repository and credential use. Reserve normal job staging quota, and do not route controller work through an instance lease.

## Server integration contract

The API and scheduler layer owns HTTP schemas and queue wiring. The controller module exports these functions:

- `configure_policy(db, destination_id, *, enabled=True, schedule_kind="daily", timezone="UTC", daily_time="02:00")` selects the active durable destination and writes the singleton `ControllerBackupPolicy`.
- `schedule_due(db, current=None)` advances one due occurrence under a row lock and returns its `policy_id`, `revision`, `destination_id`, `scheduled_at`, and `next_run_at`, or `None`. Call it in the same transaction as enqueueing `kind="controller_backup"`; use the scheduled occurrence in a stable idempotency key.
- `run_controller_backup(worker, ctx)` is the worker handler. The request may include `destination_id`; otherwise the configured policy destination is used.
- `public_status(db, max_age_days=7)` and `list_status(db)` return deliberately allowlisted status dictionaries. Do not serialize ORM rows wholesale.

Recovery-kit export must include each active `purpose="controller"` repository, its exact restic repository ID/location/password, and its destination credentials. Since its relational `Repository.instance_id` is intentionally NULL, the kit adapter must use the stable `ControllerState.controller_id` as the repository's identity input for location and derived-password recovery; do not omit controller repositories or treat NULL as a missing repository.

The expected API shape is `POST /api/v1/controller-backups` with an optional selected `destination_id`, returning `202` and a durable `job_id`; `GET /api/v1/controller-backups` returns `list_status(db)`, and a controller status view can include `public_status(db, settings.controller_backup_max_age_days)`. Keep any passphrase or key-bearing request data out of the public `Job.request`: store it through the existing private job evidence/secrets path. No passphrase is needed by this dump implementation because it excludes the master key.

The root route/scheduler implementation must also ensure the stable `ControllerState.controller_id`, persist `ControllerBackupPolicy`, pass the destination in the job request, attach durable repository/credential resource leases, and surface `ControllerBackup.state`, `error_code`, `pg_dump_included`, table/row counts, byte count, and exact restic snapshot ID. Do not mark the controller protected based only on a queued job or metadata-only check.

## Offline validation and database restore

A recovery operator needs the recovery kit (or its recovery root and provider material), provider access, compatible restic, PostgreSQL 17 client tools, and an empty prepared PostgreSQL database. Recovery is a deliberate operator action; no helper below targets the current controller database implicitly.

1. Stop the restored controller's API, scheduler and worker processes.
2. Open the selected standard restic repository with `providers.open_repository(...)`, using the controller UUID as `instance_id`, the recorded repository UUID and exact location, the repository password from the kit (or its derivation from the recovery root), and provider credentials from the kit/private recovery file.
3. Restore the selected exact restic snapshot into a fresh mode-0700 staging directory with `restore_controller_snapshot(repository, restic_snapshot_id, target, expected_manifest_hash=...)`. It refuses a nonempty target and validates the controller schema, manifest hash, inventory hash, exact file list, file modes and file contents.
4. Call `validate_controller_snapshot(repository, restic_snapshot_id, target, recovery_root_secret=..., expected_manifest_hash=...)` when a combined offline check is needed. It also authenticates/decrypts the independent catalog and checks the PostgreSQL archive hash. `decrypt_catalog(...)` can validate the sealed catalog alone without PostgreSQL or the original master key.
5. Restore only the verified `database.dump` to an explicitly prepared empty PostgreSQL database by calling `restore_dump_to_empty_database(dump_path, target_database_url, operator_authorized=True, source_database_url=old_database_url)`. The function rejects the source-equivalent database URL, any nonempty target schema/tables, and missing operator authorization; `pg_restore` runs without `--clean` and in one transaction.
6. The restore function runs `hold_restored_policies()` before returning. It disables scheduled instance and controller backups, marks restored snapshots imported, and adds `imported_review` protections. It revokes restored web sessions, consumes outstanding OAuth states, and invalidates unconsumed restore/deletion-plan confirmations.

Before workers may resume, every restored unfinished job is quarantined in the same transaction. A queued job is cancelled with `CONTROLLER_RECOVERY_REVIEW_REQUIRED` only when it is demonstrably unstarted (`attempts=0`, no `started_at`, no `JobStep`, and no job or resource lease ownership); the cancellation is recorded in both job events and audit history. That cancelled destructive intent cannot be reconciled and requires a new restore plan and confirmation. Any other unfinished job is moved to `needs_attention`, marked `reconcile_required`, and given the same review error. Stale job-worker ownership and expiry are cleared; physical `ResourceLease.owner_job_id` is retained and its time expiry cleared, and missing vacant resource leases are reacquired for the old job. An operator may explicitly request reconciliation of uncertain issued work so the worker consults the existing journal; it is never resumed automatically. `hold_restored_policies()` reports quarantine counts and `workers_may_resume=False`.

**Queue integration requirement:** `queue.claim()` must preserve an already-true `Job.reconcile_required` when an administrator explicitly requeues a `needs_attention` job. Since the hold clears stale `lease_owner`, claim must set the flag to `job.reconcile_required or stale_owner`; assigning only `stale_owner` would erase the hold's journal-reconciliation requirement. Keep that claim-path change with the server queue owner. Review provider credentials, repository identities, policy and pins before enabling any schedule.

A failed protected-mode preparation is a recovery failure: keep workers stopped. Never treat missing catalog rows as evidence that stored restic snapshots can be deleted. Do not restore controller metadata directly over a live database or use `pg_restore --clean` against one.

## Standalone operator workflow

The recovery CLI works without the VaultRewind API, its PostgreSQL database, or the controller master key. It does not execute arbitrary shell commands or start the restored application. Use the encrypted kit, provider access, compatible VaultRewind/restic tooling, and PostgreSQL 17 client tools for a database restore. Keep the kit passphrase out of command arguments: the CLI prompts when attached to a terminal, or accepts a mode-0600 passphrase file.

1. Stop the restored controller's API, scheduler and worker. Prepare a private work directory and an **empty** restore directory on a filesystem with enough free space. For a remounted local destination, supply its UUID and new mount path with `--local-path`; supply rotated cloud credentials through an owner-only `--credentials-file` when needed.
2. Inspect available controller recovery points and select a full restic ID from the chosen destination:

   ```sh
   python -m vaultrewind.recovery controller-snapshots \
     --kit /recovery/controller.vrkit --work-dir /recovery/work \
     --local-path DESTINATION_UUID=/mnt/backup-disk
   ```

   The command lists only snapshots whose exact controller, destination, schema, snapshot and manifest tags match the kit identity. Pass `--destination DESTINATION_UUID` to restrict the search. These are controller metadata snapshots, not Vaultwarden instance snapshots.
3. Restore and validate one exact snapshot into an empty directory:

   ```sh
   python -m vaultrewind.recovery controller-restore \
     --kit /recovery/controller.vrkit --work-dir /recovery/work \
     --destination DESTINATION_UUID --snapshot FULL_RESTIC_SNAPSHOT_ID \
     --target /recovery/controller-files
   ```

   The command verifies restic readback, the controller manifest and inventory, the authenticated catalog, and the PostgreSQL archive. It does not modify a database unless an optional target URL file is supplied.
4. To apply the database archive, create and verify a **separate empty PostgreSQL database**. Put its URL in a regular mode-0600 file, such as `/recovery/target-db.url`, and pass `--target-database-url-file /recovery/target-db.url`. The CLI prints only the non-secret `host/database` identity and requires you to type `RESTORE host/database`. It rejects non-PostgreSQL and nonempty targets. Never point it at the old/live controller database. The URL itself is not accepted on the command line.
5. Before restarting workers, review the restored records and repository/provider credentials. Imported snapshots and policies are held in protected review mode, and automatic deletion stays disabled. If you lost the controller master key, restore it from its separately maintained protected copy before expecting encrypted credentials in the database to work. Keep workers stopped until the restored configuration is reviewed and required secrets are available.

The local restored directory contains the verified `database.dump`, manifest and inventory. Protect or securely remove it after recovery according to the operator's data-handling policy.

## Tests

`tests/unit/test_controller_backup.py` covers policy scheduling and safe status shaping, authenticated catalog sealing/tamper detection, and (when the private PostgreSQL fixture is available) a complete synthetic PostgreSQL snapshot exported with a shared snapshot token, real `pg_dump`/`pg_restore`, actual local restic commit/readback with provider runtime/cache paths outside both the captured tree and job staging, catalog decryption without the master key, and an empty-database restore. The restored-database probe checks that never-issued queued restores are audited and cancelled, issued restores remain in `needs_attention` with reconciliation required and their physical lease held, restored sessions/OAuth states/plan confirmations are invalidated, and `queue.claim()` cannot claim quarantined jobs. The integration fixture creates only randomly named `vr_ctrl_test_*` and `vr_ctrl_restore_*` databases and drops those exact names; it does not inspect, rename or drop the configured application database. The test calls the queue claim function directly and never starts a worker.

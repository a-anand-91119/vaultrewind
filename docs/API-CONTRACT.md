# VaultRewind HTTP contract

Version 1, same-origin JSON API at `/api/v1`. `create_app(Settings(...))` is the ASGI factory; environment names use `VAULTREWIND_`. Apply `alembic upgrade head` before API/worker startup. PostgreSQL is required in production. SQLite is supported only for isolated unit/API tests.

Authentication uses the HttpOnly `vr_session` cookie and the readable `vr_csrf` cookie. Copy `vr_csrf` to `X-CSRF-Token` for authenticated mutations, and send `Origin` matching `VAULTREWIND_PUBLIC_ORIGIN`. Bootstrap/login require that same Origin. Cookies default Secure/SameSite=Lax (for the OAuth return redirect). Bootstrap requires the private mounted secret in the JSON body, once. There is no public registration. Viewer accounts can read status; all operational/configuration/secret/export actions require administrator. Lists use bounded integer `limit` (1–200). General lists support `offset`; the snapshot timeline uses its returned `next_cursor` (`before`, `before_id`) for stable descending capture-time/UUID pagination, including equal timestamps.

Every operational POST returns **202** `{job_id,state,status_url,events_url}`. Supply `Idempotency-Key` (1–160 characters). Exact retries return the original job; changed inputs return 409 `IDEMPOTENCY_CONFLICT`. Work survives browser disconnects. Job events are persisted JSON `{events:[{sequence,created_at,phase,code,progress}],state,next_sequence}`; poll `GET .../events?after=N` (or `Last-Event-ID`). No raw helper/subprocess text, secrets, inventory paths, or manifest documents appear in status responses. All errors are `{error:{code,message,retryable,phase,job_id}}`, including validation errors. The generated `/api/v1/openapi.json` is the authoritative field schema.

| Method/path | Request and response |
| --- | --- |
| POST `/setup` | `{bootstrap_secret,username,password,timezone,local_storage_directory?}` → administrator session. Password 12–1024 characters. |
| POST `/sessions` | `{username,password}` → `{user:{id,username,role},csrf_token}` and session cookies. Rate limited by account and peer. |
| GET `/sessions/current` | Current sanitized user and CSRF cookie. |
| DELETE `/sessions/current` | Revoke current session, expire cookies. |
| POST `/sessions/revoke` | `{user_id?}` revoke all sessions for that user; admin only. |
| POST `/users` | `{username,password,role,timezone}` create administrator/viewer. |
| PATCH `/users/{id}` | `{active?,role?,password?}`; revokes sessions, cannot disable/demote last administrator. |
| GET `/hosts` | Sanitized host registration/readiness. |
| POST `/hosts` | `{name,endpoint,port,username,host_public_key,private_key,passphrase?}` verified pinned OpenSSH host key; key values encrypted, never returned. |
| POST `/hosts/{id}/discover` | `{instance_id?}` → read-only discovery job. No activation implied. |
| POST `/hosts/{id}/activation-plans` | `{policy:object}` → worker produces bounded safe changes plus activation plan ID. |
| POST `/hosts/{id}/activate` | `{plan_id,plan_hash}` → explicit activation job. Missing installation integration fails closed. |
| GET `/instances` | Fleet list, independent source/backup health, capture/test times. `include_runners=true` includes dedicated verification runners for administrator selection. |
| GET `/instances/{id}` | Fleet item plus policy and readiness, including desired-profile `restore_ready`, `restore_error_code`, current `source_public_ports_ready` and protection issues. |
| GET `/instances/{id}/remote-storage` | Cached verified remote staging, generation and image accounting; unavailable counters remain null. |
| POST `/instances/{id}/remote-storage/refresh` | `{}` → administrator inventory job. Full staging can return partial accounting while preserving independently verified cleanup eligibility. |
| POST `/jobs/{id}/remote-cleanup` | `{kind:"staging"|"generations"|"discard_candidate"}` → administrator cleanup job bound to the historical operation, current target identity, leases and preservation grace. |
| POST `/instances` | `{host_id,name,container_id,configuration:object,is_runner?}` uses verified discovery evidence and canonical physical identity; not arbitrary enrollment success. |
| POST `/instances/{id}/backups` | `{label?}` → backup job. |
| GET `/instances/{id}/snapshots` | Dated immutable snapshots and independently tracked copies. |
| GET `/snapshots/{id}` | Same sanitized snapshot/copy details and trust levels. |
| POST `/snapshots/{id}/restore-plans` | `{target_id?,copy_id?,start_on_completion:false}` → `{id,confirmation_token,expires_at,snapshot_id,target_id,captured_at,target_revision,...}`. Original target default. Token is short-lived, immutable, single use, bound to exact content/target/config and creator. |
| POST `/restore-plans/{id}/execute` | `{confirmation_token}` → restore job. Changed target/policy/content → 409 `TARGET_CHANGED`. Safety cannot be disabled. |
| POST `/snapshots/{id}/verify` | `{level:"full_data"|"restore"|"application",copy_id?,runner_id?}` → verification job. No runner is an explicit setup error; login is never claimed. |
| POST `/snapshots/{id}/pin` | `{}` → pin status. |
| DELETE `/snapshots/{id}/pin` | Remove explicit user pins, preserving all other protections. |
| POST `/snapshots/{id}/deletion-plans` | `{}` → explicit eligible copy IDs, confirmation token. Protected copies cannot enter a deletion plan. |
| POST `/deletion-plans/{id}/execute` | `{confirmation_token}` → deletion job; eligibility rechecked under repository locks immediately before forgetting IDs. |
| GET `/jobs` | Bounded persisted jobs. |
| GET `/jobs/{id}` | State, phase, outcomes, safe result/error code. |
| GET `/jobs/{id}/events` | Authorized resumable persisted progress. |
| POST `/jobs/{id}/cancel` | `{}` → safe cancellation request; recovering source remains active until verified. |
| GET `/storage-destinations` | Sanitized destination health/type, credential configured flag. |
| GET `/storage-destinations/{id}` | Administrator-only configuration allowlist, current revision and credential-presence flags; no stored credentials. |
| PATCH `/storage-destinations/{id}` | `If-Match: "revision"`; `{name?,configuration?,credentials?}` updates settings or complete credential pairs. Existing repository location identity is immutable. Drive client replacement creates a fresh grant boundary and requires private reauthorization. |
| POST `/storage-destinations` | `{name,backend:"local"|"s3"|"drive",configuration:object,credentials?:object,quota_bytes?}` → destination. Configuration/credentials encrypted. |
| POST `/storage-destinations/{id}/test` | `{}` → worker connection/probe job (may write scoped probe data). |
| POST `/storage-destinations/{id}/authorize` | `{mode:"browser"}` → one-time Google authorization URL (state and PKCE, no tokens); `{mode:"headless",token:object}` → enqueue private token validation/import. |
| GET `/oauth/drive/callback` | Bound server-side state/session, consumes code into encrypted private job input; redirect is fixed same-origin. No access/refresh token accepted in URL. |
| GET `/instances/{id}/policy` | Current revision, schedule, repository IDs/required flags, budgets, retention, runner. |
| PATCH `/instances/{id}/policy` | `If-Match: "revision"`; `{enabled?,schedule_kind?,timezone?,daily_time?,interval_hours?,retention_days?:1..3650|null,destinations?:[{destination_id,required}],runner_id?,outage_seconds?,maintenance_seconds?,validation_seconds?}`. null retention means forever. |
| POST `/instances/{id}/retention-preview` | `{}` previews the saved policy; `{retention_days:1..3650}` or `{keep_forever:true}` previews a hypothetical policy without saving it. Response includes UTC cutoff, exact copy IDs, protections, freeze reasons and expirations. |
| POST `/instances/{id}/schedule-preview` | `{}` → next five UTC occurrences under stored civil-time rules. |
| POST `/recovery-kits/export` | `{passphrase}` → job with short-lived administrator-only encrypted artifact download link. |
| POST `/recovery/import-plans` | `{kit,passphrase}` → discover/import planning job; imported content protected, no implicit deletion or restore. |
| GET `/recovery/import-plans/{job_id}` | Review a completed import discovery job: `{plan_job_id,plan_hash,summary,snapshots}`. This review does not apply it. |
| POST `/recovery/import-plans/{job_id}/apply` | `{plan_hash}` → 202 apply job. The hash must match the reviewed plan; import remains protected and retention-disabled. |
| POST `/snapshot-copies/{copy_id}/retry` | `{}` → 202 retry for a copy in `failed`, `uncertain`, `pending` or `committing`; retries the same immutable snapshot/copy. |
| POST `/jobs/{job_id}/reconcile` | `{}` → 202 reconciliation for recoverable backup/restore/verify jobs in `needs_attention`, `rollback_failed` or `waiting_retry`. It retains remote resource leases until journal evidence resolves ownership. |
| GET `/controller-backups` | Controller backup status/list, including public status and stale protection state. |
| POST `/controller-backups` | `{destination_id?}` → 202 PostgreSQL metadata backup job. Uses PostgreSQL 17 `pg_dump`/`pg_restore`, encrypted restic storage and exact readback. Does not include the controller master key. |
| GET `/controller-backup-policy` | Current `{configured,enabled,destination_id,timezone,daily_time,next_run_at,revision}`. |
| PUT `/controller-backup-policy` | `If-Match: "revision"`; `{destination_id,enabled?,timezone?,daily_time?}` selects durable daily metadata backup. |
| POST `/metadata/export` | `{}` → sanitized controller catalog export job and protected download. Does not substitute for independent recovery kit or PostgreSQL backup. |
| GET `/jobs/{id}/artifact` | Administrator-only download; only completed, unexpired export artifacts. |
| GET `/audit-events` | Administrator-only sanitized append-only application audit. |
| GET `/notifications` | Active/recovered alerts and delivery status. |
| POST `/notification-channels` | `{kind:"webhook"|"smtp",configuration:object}`; encrypted integration config, worker validates TLS/allowlist before sending. |
| GET `/doctor` | Read-only catalog readiness, stale leases, failed cleanup, repository/test/recovery setup issues. No probes/credential refresh. |
| POST `/doctor` | `{}` → explicit worker inspection/probe job. |
| GET `/health/live` | Public process liveness only. |
| GET `/health/ready` | Public sanitized database/migration readiness only; no private status. |

Snapshots use UTC ISO timestamps. `verification` contains explicit boolean evidence, never a blanket “tested” label. `source_service_outcome`, `content_commit`, `required_copy_outcome`, and `target_activation_outcome` remain separate. Retention keeps every snapshot at/after `now - days*24h`, protects the newest complete copy per repository, newest application-tested copy, pins, safety, active inputs and imported/future captures, and freezes on uncertainty/failure/overdue state.

A running restore can complete only with helper evidence `public_ports_verified=true` and `public_endpoint_verified=true`, verified against approved host bindings and endpoint probes. Isolated candidate startup alone does not establish public readiness. Explicit stopped data-only restores report `data_restored_service_stopped` and do not claim a running application. After public activation may have occurred, missing proof preserves the active generation and requires reconciliation.

Daily DST schedules use the first occurrence in a fold and the first valid minute following a gap. Hourly schedules use UTC intervals. A restart coalesces missed occurrences into one catch-up job per policy; manual backups do not alter `next_run_at`.

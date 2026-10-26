# VaultRewind product and engineering specification

Version 1.0 specification dated 25 October 2026. Intended recipient: an implementation agent building and testing the complete application. Product decisions below are requirements unless explicitly marked as a proposed default or future work.

## 1 Product purpose and name

Build **VaultRewind**, a self-hosted application for backing up and restoring multiple Vaultwarden instances over SSH. The name connects a password vault with returning to an earlier saved state. Use vaultrewind for repository, executable, package and image names. The name is a working product name; domain and package registration are separate release tasks.

The golden rule is **One-click backup. One-click restore.** After initial connection and policy setup, neither operation may require terminal commands, copying files, entering database commands, editing Compose files, or reconstructing a deployment manually. A restore that replaces an existing instance has one concise confirmation showing the exact snapshot and destination. That confirmation does not turn the workflow into a multistep wizard.

Users can take a backup now, schedule dated snapshots, retain the last X days, and restore any retained snapshot to its original instance or a prepared alternate server. A backup captures a complete recoverable application instance. An upload that silently omits unreadable files is a failure.

## 2 Confirmed scope and delivery contract

The owner confirmed these choices:

- Support Vaultwarden only. Official Bitwarden is outside this product's initial scope.
- Release one supports Linux servers running a single Vaultwarden Docker container with a SQLite database, matching the owner's existing deployment.
- Support both a host bind directory and a local Docker named volume for persistent data. Block unsupported volume drivers with an explanation.
- Restore defaults to the original instance. Restore to another server is an additional supported action.
- Release one includes local disk on the machine running VaultRewind, S3-compatible object storage, and Google Drive.
- Provide snapshots, configurable retention in days, manual backup, scheduled backup and one-click restore.
- Capture all persistent instance data and the deployment material needed to recreate it.

All release-one requirements in this document are required for the first complete release. The implementation sequence is an internal build order, not permission to deliver a UI prototype or local-only backup as the finished tool. Cloud integrations, replacement restores, alternate-server restores and disaster recovery are part of the delivery.

Future adapters may add native/systemd Vaultwarden installations and PostgreSQL or MySQL/MariaDB backends. Design explicit interfaces for them, but do not implement or imply support in release one. Detect unsupported database URLs and stop before touching the instance.

Building and testing this tool does not authorize using the owner's production server. Treat that server as read-only until the owner separately authorizes a production rollout. Use synthetic vaults and disposable hosts throughout development. Never embed the owner's IP address, paths, SSH keys, configuration, vault contents or backup archives in code, fixtures, documentation or screenshots.

## 3 User outcomes and terms

An **instance** is a specific Vaultwarden container and its complete persistent data and deployment configuration. A **host** is the SSH-accessible Docker server. A host may contain multiple instances.

A **snapshot** is an immutable, application-consistent recovery point with a unique ID, capture time, manifest, content checksums and a recorded Vaultwarden image version. A **snapshot copy** is that recovery point committed to a particular storage repository. One snapshot may have several independently tracked copies.

Snapshotting means dated backup recovery points. It does not mean hypervisor snapshots, storage-provider versions, a continuously replicated standby, or recovery to every instant between backups. Data created after the chosen capture point will not be present in a restore. Show the capture time and its age explicitly.

**Backup success** means required content was captured, validated and committed to every destination required by the instance policy, and the source's final service state is known. Track those facts independently: a stored copy can be valid even if restarting the source failed, but the overall job must report that operational failure.

**Restore success** means the selected content was verified, deployed to the selected target, and passed startup and application-level structural checks. A restore test without user credentials must not claim that a real user's login, decryption or synchronization was tested.

## 4 Defaults

Use these proposed product defaults so the agent can proceed without further product decisions:

| Setting | Default |
| --- | --- |
| Deployment | Self-hosted Docker Compose on a Linux controller |
| Accounts | Single workspace; administrator and viewer roles |
| Schedule | Daily at 02:00 in the instance policy's selected IANA timezone |
| Retention | Keep every completed snapshot from the last 30 rolling days |
| Manual snapshots | Same retention as scheduled snapshots unless pinned |
| Minimum recovery points | Always retain the newest complete snapshot; protect the newest successful restore-tested snapshot too |
| Storage policy | One required destination; optional additional required or best-effort destinations |
| Encryption | Mandatory for local and cloud repositories |
| Backup consistency | Controlled brief stop for capture, then restart before transfer and cloud upload |
| Maximum capture outage | 300 seconds; configurable at onboarding, enforced remotely |
| Restore maintenance budget | 15 minutes after quiescing the target; separate from preflight/download time |
| Restore validation window | 180 seconds after container start; configurable |
| Global job concurrency | Two jobs, with one mutating job per host by default |
| Scheduled restore test | Weekly on a separately configured disposable Docker runner |
| Alerts | In-app plus optional SMTP email and HTTP webhook |
| Automatic upgrades | Disabled; recorded image version is used for recovery |

Outage and duration values are budgets and timeouts, not guaranteed performance. Expose any source pause honestly. Users who require uninterrupted operation should receive an unsupported-mode explanation in release one, rather than a weaker snapshot labeled complete.

## 5 What backup everything means

### 5.1 Required data

Capture the following as one recovery point:

- A consistent SQLite database containing all server-side accounts, organizations, vault records, authentication state and other database-backed information. Never export selected users' vaults as a substitute.
- Every attachment and every Send file, including empty directories and private files readable only by root or the service UID.
- Every signing key and other persistent key file, including all rsa_key variants that exist.
- The administrator configuration file if present, effective container environment, and all referenced environment/configuration/secret files needed by the instance.
- The complete persistent data tree, including unknown regular files and dotfiles. Inventory first; use a small documented list of regenerable runtime exclusions rather than an allowlist that silently misses new Vaultwarden files.
- File ownership, permissions, symlink and hardlink relationships where supported, timestamps, and relevant extended attributes/ACLs. Preserve these in a manifest even when the controller cannot apply foreign numeric ownership to its staging files.
- A validated deployment descriptor with image content identity, CPU architecture, entrypoint/command, environment, user/group, mount mappings, ports, network settings, restart policy, health check and supported security settings.
- Original Compose documents and their includes/environment files when available, plus a normalized recovery definition generated from the actual running deployment. Existing deployments may have been started manually and may have no complete Compose document.
- The exact Vaultwarden Docker image as a portable saved-image archive in the encrypted snapshot. Cache it by immutable image identity to avoid repeated export. A mutable latest tag or registry URL alone is insufficient for recovery when a registry disappears.
- Manifest metadata recording the app/helper/schema versions, source configuration fingerprint, source service state, consistency method, image identities, capture time, file inventory, validation results and dependencies.

The manifest must distinguish a registry digest from a local Docker image ID and from the digest of an exported image archive. Do not label them interchangeably. Verify the image identity after importing an archive on a recovery host.

### 5.2 Transient files and dependencies

Database WAL contents must be included in normalization when present. The final portable snapshot contains a standalone normalized db.sqlite3 and must not contain a stale WAL or SHM file alongside it. Runtime sockets, locks and temporary in-progress upload files may be excluded only by a versioned, documented policy that does not remove committed data. Include icon caches by default for faithful recovery; allow their exclusion only as an explicit regenerable-cache setting recorded in the manifest.

Inspect all instance mounts and referenced files. If a required configuration file or external data path is inaccessible, outside the approved roots, or unsupported, onboarding must identify the dependency and block the Complete protection status. Never accept only /data if the actual deployment requires something elsewhere.

Maintain an external dependency inventory for reverse proxies, certificates, SMTP, DNS, external identity providers and host networking. Back up explicitly enrolled local proxy/certificate configuration and secret files; do not automatically crawl unrelated host directories or copy host-wide SSH keys. If service recovery depends on an unenrolled external component, show the exact remaining prerequisite. The label Complete instance refers to the supported application recovery boundary, not the entire VM, cloud account, external DNS service or unrelated containers.

Release one may require an existing reverse proxy/network to be selected during alternate-target enrollment. The UI must explain that requirement before a backup is advertised as ready for that target. Do not execute arbitrary captured Compose projects, image entrypoints or host mounts without schema validation and target policy checks.

### 5.3 Completeness rule

Required files have three possible outcomes: captured and checked, explicitly absent when optional by the supported application contract, or failed. Permission errors, truncated transfers, unknown persistent mounts and unsupported metadata are never converted to success by logging a warning. An instance with root-owned mode-0600 files must be a passing acceptance fixture. Do not change live file permissions to make backups easier.

## 6 Main user experiences

### 6.1 First run

Provide a first-run administrator setup protected by a one-time bootstrap secret supplied through a mounted file or private installation output. Public users must not be able to claim the application before its owner. The owner sets a password, timezone and local storage directory, receives the recovery-kit instructions, then adds a host and instance. No default password or public registration.

Onboarding first performs read-only discovery: verify the SSH host fingerprint, inspect Docker containers and mounts, identify SQLite, inventory files and dependencies, estimate space, and detect conflicting backup/restart processes. Show all proposed host changes before activation. Discovery never installs packages, writes helper files, starts containers or runs a backup.

Activation explicitly provisions the narrow remote helper and its recovery mechanism, approved filesystem roots and instance identities. Show the maintenance window implication. Activation is a one-time administrative setup step; normal backup/restore use must not require repeating it.

### 6.2 Dashboard and instance detail

The fleet page shows instance name, host, current reachability, last complete backup, capture age, last successful restore test and protection issues. Separate source-health status from backup-health status. A healthy Vaultwarden container must not cause a failing backup job to appear healthy.

Each instance has a prominent Backup now action. Show progress by named phase, bytes and elapsed time, without inventing percentage estimates for unknown-duration phases. Instance details show storage copies, schedule, retention and a dated snapshot timeline/list. Provide desktop and mobile layouts, keyboard navigation, accessible dialogs and text labels in addition to status colors.

Snapshots show capture time in the selected timezone and UTC on inspection, trigger type, logical size, stored size when measurable, completeness, copy status, verification level, pin state and Restore. Counts and labels must reflect real persisted jobs. Include loading, empty, offline, expired-credential, insufficient-space, partial-copy and failed-restore states.

### 6.3 One-click backup

Click Backup now once. The API returns a job immediately and the background worker performs the complete workflow. Repeated clicks and retried HTTP requests must not create overlapping captures. Closing the browser does not stop the job. The user can inspect progress and a sanitized error explanation with the next useful action.

### 6.4 One-click restore

On a selected snapshot, Restore opens a compact confirmation with original target preselected, snapshot time, source version, validation status, expected downtime and the consequence that later changes will be replaced. Confirm restore starts the complete job. No user-managed staging, extraction or file replacement.

Offer Restore to another server beside the default action. A previously enrolled ready target requires only target selection and confirmation. Enrolling an unprepared target is a separate setup flow. Restore to another server creates a separate enrolled instance identity; it does not silently repoint the original instance's schedule or DNS.

Disable unavailable targets or snapshots with a precise reason. Do not require routinely typing an instance name; reserve stronger checks for exceptional administrator actions. No unattended production restore is scheduled by default.

### 6.5 Restore tests

Provide Test restore as a separate action. It restores into a disposable, isolated Docker environment without stopping or overwriting the source. Show Integrity checked, Application started and User login tested as different evidence levels. The last level is available only when a dedicated synthetic test account and explicit test procedure were configured. Never request or store users' master passwords for routine backup.

## 7 System architecture and implementation choices

Use a modular monolith with a separate worker process. Avoid a fleet of services for the initial release.

| Component | Proposed implementation and responsibility |
| --- | --- |
| Browser UI | React and TypeScript with Vite; accessible components; responsive fleet, snapshots and jobs views |
| API | Python with FastAPI; validated request/response models and generated OpenAPI |
| Persistence | PostgreSQL with SQLAlchemy and Alembic migrations |
| Durable queue | PostgreSQL job records, transactional claims, leases and recovery journals; no Redis dependency initially |
| Worker | Same backend image, separate process; SSH orchestration, validation and repository operations |
| SSH | AsyncSSH with pinned host keys; structured remote-helper protocol |
| Remote helper | Versioned Python executable plus narrowly configured sudo policy, local locking and recovery units |
| Snapshot storage | Pinned restic binary and standard repositories |
| Cloud bridge | Pinned rclone for Google Drive; native restic S3 backend for S3-compatible stores |
| Delivery | Controller Docker Compose stack containing API/UI, worker and PostgreSQL |

Resolve current supported dependency versions at implementation time, pin them in lockfiles/images, and document the tested versions. Do not copy speculative library syntax from this specification. Use official documentation and current Context7 documentation where available.

The controller is Linux-first. Docker Desktop may run the controller for development on macOS/Windows, with clearly documented host-directory mounts and networking. Production source/target hosts require Linux, Docker and the tested systemd recovery facilities in release one. The controller must not require the host Docker socket; use a separately enrolled SSH-accessible verification runner for restore tests.

Put database-engine logic, deployment lifecycle and storage access behind separate interfaces. A database adapter handles capture normalization, integrity checks and version evidence. A deployment adapter handles discovery, image export/import, stopping, starting and target materialization. A repository adapter handles initialization, snapshot commit, restore, list, verify and deletion. Do not spread Docker commands or provider-specific conditionals through HTTP handlers.

## 8 Remote access and helper protocol

Use existing SSH transport. The helper is not a permanently running network agent. Activation installs a root-owned versioned executable and tightly scoped root-owned policy for enrolled instance IDs, container IDs, data roots, staging roots and allowed operations. It also installs the local recovery-on-boot facility needed to recover from interrupted work. Document these host changes accurately; do not call this zero-install access.

The SSH account may invoke only the approved helper entrypoint through sudo. Send bounded JSON requests on stdin; stdout is structured JSON events or a framed export stream. No user-controlled shell fragments, commands, paths, Docker arguments or repository URLs may be interpolated into a shell. Validate each path, verb and instance identity against the root-owned policy. Handle quoting at the transport boundary, use argument arrays wherever the API permits, and test shell metacharacter payloads explicitly.

Required verbs are discover, preflight, capture, export, stage_restore, commit_restore, rollback, status, cancel and cleanup. Give every request an immutable operation ID, request schema version, idempotency key and fencing token. Root policy changes, helper upgrades and onboarding writes are distinct administrative operations. Read-only discovery must remain possible without activating backup behavior.

Pin SSH host fingerprints after the user verifies the enrollment fingerprint. A changed key blocks jobs until explicitly reviewed. Do not disable host-key checking. Store private keys/passphrases encrypted in the controller, redact them in all logs, and disable SSH agent forwarding. A backup-only connection and a restore-enabled connection may have different policies; the UI must explain when restore capability is absent.

The helper must reject symlink/path traversal, mount-root escapes, unsupported volume drivers, changed container identities, unexpected mounts, device files and unsafe captured deployment settings. Permit internal symlinks/hardlinks only within the declared instance boundary and verify targets during export and restore. Preserving numeric UID/GID must not grant the controller arbitrary host ownership powers.

## 9 Locks and durable operation records

Lock the physical resource, not merely the UI instance ID. Derive a resource identity from the verified host/daemon identity and canonical data mounts. Duplicate registrations pointing to the same data must share a lock. Backups, restores, retention and verification must also acquire the appropriate repository locks.

Use controller database leases with fencing tokens and helper-side OS locks/journals. A worker that loses its lease must not continue destructive work. A second worker must reconcile the existing remote journal and operation ID before resuming. Never assume lease expiration proves that a remote process has stopped. Avoid automatic force-unlock of restic repositories when a live process might still own the lock.

The remote helper records each state transition durably with an operation ID, original container state, intended outcome, active data generation and rollback locations. Use atomic write and fsync semantics appropriate to the host filesystem. Neither a Python finally block nor the SSH connection staying alive is sufficient recovery protection.

Arm a host-local recovery watchdog before stopping a source or entering a restore commit. It runs independently of the controller and SSH session and is coupled with boot-time reconciliation for host reboot. During capture, its fallback is restarting the original service if it was originally running. During restore, its action depends on the durable transaction stage: recover the known original generation before public activation, or preserve the committed restored generation afterward. Never blindly start whichever half-written directory happens to exist.

Persist separate deadlines for the backup capture outage and the restore maintenance budget. Restoring/download preparation before quiescence does not consume target downtime. Extending an outage budget requires an explicit policy change before the operation; a stalled worker must not keep extending its own deadline indefinitely.

If a watchdog, helper policy or transaction journal cannot be verified, fail preflight before downtime. Timeouts and cancellation do not bypass recovery. A source that was stopped before an operation remains stopped afterward unless the owner explicitly selected start-on-completion.

## 10 Snapshot format and catalog

Store snapshots as standard encrypted restic snapshots of a canonical directory tree. Keep one repository per instance per storage destination, under stable UUID-based prefixes. This makes isolation, retention and disaster import easier and prevents one instance policy from deleting another's data. Do not use changing hostnames, staging paths or display names as the primary identity.

The logical snapshot tree contains data, deployment, images and manifest directories. Data contains the complete normalized persistent content. Deployment contains original and normalized definitions plus encrypted-at-rest secrets within the repository. Images contains the exact saved image archive. Manifest contains a schema-versioned manifest and per-file inventory. All plaintext staging is temporary and access restricted; repository encryption does not encrypt files before they enter the repository.

The manifest must include snapshot_uuid, instance_uuid, capture_started_at, captured_at, source_state, consistency_mode, app_version, helper_version, database_engine, database_schema_evidence, Vaultwarden version, registry digest when available, image ID, image archive hash, platform, deployment fingerprint, inventory entries, declared exclusions, dependency inventory and verification evidence. Each inventory entry includes logical path, type, size, SHA-256 for regular file content, UID/GID, mode and supported link/extended metadata. Persist the manifest hash in the controller catalog and compare it on readback. Never expose manifest secrets in normal API responses.

Use controller UTC as the scheduling/retention authority, record remote clock offset and capture start/end evidence, and fail preflight on excessive unaccounted clock skew. Do not let an arbitrary source-host timestamp make a new backup expire immediately or permanently suppress overdue detection. Future-dated imported snapshots are protected for review rather than used to advance retention cutoffs.

Every storage copy has its own repository ID, restic snapshot ID, commit state, byte counts, verification timestamps and error history. A retry reuses the logical snapshot UUID and immutable captured content. A later capture always creates a new snapshot UUID, even when its files are unchanged and physical deduplication saves space.

Commit a copy only after all expected paths were accepted without restic missing-file warnings or partial exit status, the snapshot can be rediscovered by operation UUID, and its stored manifest can be retrieved and verified. A failed or incomplete copy is not restorable through the normal UI. Reconcile committed restic snapshots after worker crashes before scheduling a duplicate upload.

## 11 Backup workflow

Implement these phases as durable state transitions. Each phase has entry checks, an idempotent remote operation, persisted evidence and an explicit failure path.

1. **Queue and lock.** Authenticate the caller, deduplicate the request, obtain source/host/repository coordination locks, and record the instance policy and configuration versions being used.
2. **Preflight.** Verify SSH identity, helper version, source identity, supported database, approved mounts, required file accessibility, source and controller free space, repository access and the local recovery mechanism. Inventory competing restart/backup jobs. Detecting an external auto-healer that may restart the source during capture is a blocker until a supported maintenance integration is configured. Do not disable arbitrary cron entries automatically.
3. **Prepare.** Export/cache the immutable image and collect deployment files before downtime. Create an operation-specific remote staging directory outside the live data tree with restrictive permissions. Space estimates must cover source staging, controller staging, images and a conservative margin. Never put staging or repositories inside the protected data directory.
4. **Quiesce.** Arm the remote recovery watchdog and record the original state. Gracefully stop the enrolled Vaultwarden writer. Confirm that every enrolled writer to the data roots is stopped. A forced kill after a graceful-stop timeout is a failed capture, not a shortcut to success. Initially stopped instances remain stopped.
5. **Capture.** While writers are stopped, copy the complete approved persistent tree and associated deployment files to remote staging with ownership/metadata evidence. Preserve any SQLite WAL with its matching database during this raw copy. Confirm the container did not restart, the captured configuration fingerprint did not change, no required reads failed and the capture stayed within the outage budget. Unknown writers or inconsistent capture evidence invalidate the snapshot.
6. **Resume source.** Once the raw local copy is complete, restart the source if it was originally running, then record its health. Do this before normalization, SSH transfer or uploads. Clear the capture watchdog only after the source's intended state is confirmed. An independent watchdog must still recover if the manager disappears before this step.
7. **Normalize and validate.** On the isolated staged copy, use SQLite's supported backup API to produce a standalone normalized database incorporating committed WAL data. Do not use immutable mode on a database with an unapplied WAL. Replace only the staged database, then remove staged WAL/SHM companions after successful normalization. Never delete companions from the production data directory as part of backup. Run integrity checks and schema-aware attachment/reference completeness checks. Retain orphan files; missing required referenced files fail completeness. Treat expired Sends according to the tested Vaultwarden version's semantics.
8. **Transfer.** Export the staged tree through the bounded helper protocol over SSH into an operation-private controller directory. Validate archive entries before extraction; do not blindly extract as root. Stream where practical, limit size/member counts, preserve logical metadata in the manifest, and compare every required file hash after transfer. Resume interrupted transfers from the same immutable capture when safe, rather than recapturing a changing source.
9. **Commit storage copies.** Back up the canonical tree into each selected repository using restic. Collect structured output and exit status. Read back the stored manifest and verify completeness. Best-effort destination failures produce a degraded protection warning. A required destination failure prevents the overall job being successful, while retaining independently valid copies.
10. **Finalize.** Persist snapshot/copy evidence, send notifications, schedule eligible retention work and remove staging after a bounded retry window. If source recovery failed, surface that prominently even if valid storage copies exist. If upload failed, retain the local immutable staging for configurable retry while respecting disk limits; never leave the source stopped for retries.

For a normal source originally running, the success path ends with it healthy. Cancellation before quiesce can terminate immediately. Cancellation during quiesce/capture must resume the original service first. After source recovery, cancellation may stop uploads and leave no completed snapshot, or leave independently committed copies accurately cataloged.

Do not implement a purported online full-instance backup by taking a database snapshot and later copying arbitrary live attachments. A consistent database alone does not establish consistency between database records and filesystem content. An online mode can be a later separately tested consistency contract.

## 12 Restore workflow and transaction boundaries

### 12.1 Preparation before downtime

The server resolves the selected immutable snapshot UUID and exact copy, rather than interpreting latest at some later worker step. The confirmation plan is bound to that snapshot, target UUID, target fingerprint and policy revision by a short-lived single-use token. If any of those change, refresh the confirmation. Browser confirmation is not sufficient authorization without backend role checks.

Download and restore the chosen copy to private controller staging, verify manifest/checksums/completeness, and run database integrity checks. Transfer it to a new target staging generation, verify it again and import/verify the saved image. Reject unsupported architecture, missing dependencies, unavailable external networks, conflicting ports and unsafe mount destinations. Use the source image content identity for initial recovery; do not upgrade or downgrade during restore.

Resolve target-specific values such as hostname, ports, data path, proxy association and public URL from the enrolled recovery profile. Show those substitutions in the plan. Preserve original secrets by default; allow only explicitly configured target overlays. Store the exact overlay version in the job record. Never silently keep a source public URL when cloning to a different host.

For external identity providers/WebAuthn, a changed hostname may require a provider-side change or re-enrollment. Such requirements are explicit target-readiness conditions; do not promise that a hostname-changing clone preserves every external authentication flow automatically.

### 12.2 Preserve the current target

For replacing an existing instance, acquire its physical resource lock, arm the restore watchdog, stop its writers cleanly, and create a mandatory pre-restore safety capture. Commit that safety snapshot to a durable encrypted local safety repository on the controller before destructive switching. Also preserve the original data generation, container descriptor and deployment files on the target. A configured cloud copy of the safety snapshot may happen afterward; the restore must not depend on cloud upload while the target is stopped.

If safety capture, safety storage, free space or rollback preparation fails, abort and restore the target's original service state. Release one has no skip-safety or destructive-force shortcut in its normal UI or API. Provisioning a genuinely empty alternate target has no previous application data to capture, but must prove the target is empty and its paths are approved.

Safety snapshots are automatically pinned and have their own reserved-space accounting. They do not expire through ordinary daily retention until the administrator unpins them after a completed restore. Display their space cost and allow deliberate cleanup; do not leak unlimited hidden safety captures.

### 12.3 Transactional switching

Never unpack the selected snapshot over live files. Maintain a complete new data generation and a recoverable old generation. For bind directories, stage on the same filesystem as the canonical data path and use journaled rename/switch operations while the service is stopped. For named volumes, create a new approved local volume and materialize the recovered container against it. Do not rename Docker's internal volume directories manually.

Multiple directory/configuration switches are not one atomic filesystem action. Journal each step and make it recoverable. Recreate the container from the validated recovery descriptor so mounts are re-resolved; do not assume an existing bind mount follows a renamed directory. Preserve the original container/configuration as a stopped rollback candidate until recovery succeeds.

Write/update a managed recovery Compose definition and target metadata so subsequent VaultRewind discovery, backup and Docker recreation use the active generation. Retain the previous original deployment definition. Where an external deployment controller would recreate an obsolete generation, require a supported ownership/maintenance agreement during enrollment and block restore if that agreement cannot be honored. Do not leave a successful restore one external Compose run away from reverting to old data.

### 12.4 Validate before exposure

Boot the restored candidate using the recorded image in an isolated network with no published application ports and no outbound access. Verify expected schema, application startup, attachment coverage and internal health. Ensure application startup cleanup can only affect the candidate generation. It must not send email, webhooks, push requests or communicate with identity providers during this validation stage.

If candidate validation fails before public activation, stop/discard the candidate, restore the old data generation and deployment mapping, restart the original container if it was originally running, and verify its health. Preserve diagnostic evidence without leaking secrets. Report rolled_back only after the original service state is confirmed. If rollback itself fails, report rollback_failed and retain both generations and the recovery journal for repair.

### 12.5 Public activation and later failures

After isolated validation passes, record a durable activation decision, then perform the supported final container/network/port activation and verify final health. Record activation_started before the first action that could expose the recovered instance to clients. This is a separate boundary from file switching.

Once public activation may have happened, do not automatically revert to an older generation: clients may already have written new data. On controller/SSH loss or a post-activation health failure, reconcile the activation state, preserve the new generation, attempt bounded non-destructive recovery and surface needs_attention if unresolved. A later rollback requires a new confirmed recovery operation with its own safety capture. Do not promise automatic rollback after every conceivable restore failure.

The target can become publicly available only after candidate validation and the activation decision. Source originally stopped remains stopped on a data-only restore unless start-on-completion was selected explicitly; it can still be validated using an isolated candidate. Mark data_restored_service_stopped distinctly from a running healthy restore.

### 12.6 Completion

On success, record active generation, exact image, final deployment fingerprint, restored capture time, safety snapshot ID, timing and validation evidence. Keep the old generation for an explicit configurable rollback grace period, proposed default seven days, with visible disk usage and cleanup controls. Do not classify rollback generations as regular snapshot copies.

Restore-to-other-server must not stop, reconfigure or delete the original source. It must not automatically change DNS, proxy routes or external identity-provider registrations. Those are separate explicit integrations. A prepared alternate target can still be recovered and served at its configured URL in one job.

## 13 Retention and scheduling

### 13.1 Retention in days

Keep every completed snapshot with captured_at greater than or equal to a fixed UTC cutoff of retention_run_time minus X times 24 hours. Retention applies to capture time, not file mtime, upload time or a local timezone date string. X is a positive integer, proposed supported range 1 through 3650, default 30. A separate explicit Keep forever choice means no automatic expiration; do not overload zero ambiguously.

Within that window, retain all snapshots, including multiple manual backups on the same day. Do not interpret Keep 30 days as Keep the last 30 backups or Keep one backup per day. Snapshots exactly on the cutoff are retained. Present the policy in human terms and show each snapshot's planned expiry and any protection exception.

Always protect pinned snapshots, the newest complete recoverable snapshot for the instance/destination, the newest successful restore-tested snapshot until superseded, safety snapshots, active restore/test inputs and copies under a legal or administrator hold when configured. Required destinations must retain their own complete recovery point. Unpinning does not immediately bypass other protections.

Calculate the exact eligible deletion set in VaultRewind from stable IDs and the persisted policy, under repository coordination. Present a dry-run preview when a policy changes. Verify the set again immediately before forgetting those exact copy IDs. Do not implement this by blindly passing a broad policy to restic: its keep-within reference-time semantics differ from this product's wall-clock rule. Pin state must be enforced by the deletion planner; a display badge or tag alone does not protect a snapshot.

Freeze automatic deletion when the instance's required-backup policy is degraded, the newest backup is overdue, repository state is uncertain, or the latest operation failed. Keep older recovery points during an outage even when they exceed X days. Expired snapshots are not a promise of immediate freed disk space; restic forgetting and physical pruning are separate operations. Schedule pruning outside captures/restores and verify repository consistency afterward. If object locks or provider permissions prevent deletion, record and show the actual retained state.

### 13.2 Schedules

Support hourly intervals and daily selected times in an IANA timezone; expose an advanced validated cron schedule only if fully tested. Persist next_run_at in UTC and the timezone rule separately. On daylight-saving transitions, run once at the first valid occurrence; if a configured local time does not exist, run at the next valid local time. Document and test that behavior.

On controller restart after missed runs, enqueue one catch-up backup per enabled policy. Do not flood the host with every missed interval. Store an immutable scheduled occurrence key so two schedulers cannot enqueue duplicates. Manual backup does not erase the next scheduled occurrence. Record skipped/coalesced runs.

Provide pause/resume per instance policy, schedule preview, next run, last result and overdue alerts. Pausing backup schedules does not pause or stop Vaultwarden. Never schedule automatic replacement restores by default.

## 14 Storage implementations

### 14.1 Shared contract

Every backend must support repository init/open, private credential handling, connection test, snapshot list, commit, verified read/restore, retention deletion, capacity/quota where available, and actionable failures. Use standard restic repository format; do not implement custom cryptography or a proprietary chunk store.

Each destination has a stable ID, display name, type, repository prefix, credentials reference, encryption-key reference, health, last test and optional quota. A repository belongs to exactly one instance/destination pairing. Changing a display name never changes its repository path. Changing a destination does not silently move or delete existing backups; migration/import is explicit.

Connection tests may create, read and delete a uniquely named probe object only after the user requests Test connection or saves the destination. Scope probes to the selected repository namespace. An inspection-only action must not refresh remote credentials or create probes without disclosing its writes.

### 14.2 Local disk

Local means a persistent directory mounted from the machine running VaultRewind, not the remote Vaultwarden host and not the controller container's disposable writable layer. Default internal mount is /var/lib/vaultrewind/backups; the installer maps an owner-selected host path there. Show that host path and filesystem free space in the UI.

Reject application/source/staging directory overlap, root directories, unexpected symlink escapes and unsupported filesystems. Detect a missing mount and fail rather than writing to an empty underlying directory. Permissions must allow only the controller service identity. Preflight quota/space, include minimum free-space thresholds and warn that local copies alone do not survive loss of the controller disk. Local-only backup remains fully supported.

### 14.3 S3-compatible storage

Collect endpoint, bucket, prefix, region, access key/secret or supported workload credentials, addressing mode and optional custom CA. Support AWS S3 and validate compatibility against a local MinIO fixture. Permit HTTP only for explicitly selected local development fixtures; normal remote connections require certificate-verified HTTPS.

Store credentials encrypted and scope permissions to the selected prefix. Expose permission failures precisely: backup may require list/read/write, and retention requires appropriate deletion permissions. Do not automatically create cloud accounts, weaken bucket policy, enable public access or disable TLS verification. Warn when provider lifecycle rules can remove chunks still needed by retained snapshots. Object versioning is distinct from VaultRewind's logical snapshot history.

### 14.4 Google Drive

Use restic's supported rclone backend, isolated per destination, with a guided browser authorization/headless-token setup flow. Support the owner's OAuth client ID/secret rather than relying on a shared built-in client remaining available. Show the selected Drive folder and its stable ID. Choose and document the least-privileged workable scope; validate personal-drive support first and explicitly document whether shared drives are tested.

The UI must complete provider setup without requiring recurring terminal commands. A one-time headless authorization/import flow can be offered as an advanced setup path. No credentials or OAuth tokens appear in URLs, browser storage, logs, process command arguments or generated examples. Use protected server-side storage and strict callback origin/state validation.

rclone can write refreshed OAuth tokens back to its configuration. Provide a private writable per-destination configuration with a credential lock, detect successful refreshes and atomically persist changed tokens into encrypted controller storage before cleanup. Do not mount this configuration read-only or discard rotated tokens after every job. Concurrent jobs must not overwrite newer tokens with older copies. Credential revocation, consent expiry, quota/rate limits and reconnect must have explicit recoverable states.

### 14.5 Multiple copies

An instance can select one or more destinations. Mark each required or best effort. Capture once, then commit the same logical snapshot to those destinations. Allow retry of a failed copy without another source pause. All-required-success produces job success; any required failure produces partial/failure status with valid copies preserved and selectable. Restoring may use any verified complete copy. Automatic fallback may choose an equivalent copy of the exact same logical snapshot, never a different date without user agreement.

## 15 Verification and trust levels

Separate these checks and persist their timestamps:

1. **Capture validation:** required inventory, hashes, consistent normalized SQLite and attachment/reference checks.
2. **Stored-copy validation:** committed snapshot exists and its manifest is readable and correct.
3. **Repository data verification:** read and cryptographically verify stored content, such as a full restic data check or an explicitly recorded subset. A metadata-only check is not full data verification.
4. **Restore verification:** restore bytes into an empty staging location and verify them against the manifest and repository.
5. **Application startup test:** boot the recorded image with a disposable copy, run structural checks and prove the instance starts.
6. **Optional authenticated test:** a dedicated synthetic account performs approved login/sync/attachment checks. It never substitutes for testing real user access when that is actually required.

Run capture/stored-copy checks on every backup; verify restored bytes on every restore; schedule full repository data checks and isolated application tests weekly by default. Prevent data checks and pruning from creating unsafe repository lock conflicts. A failed check raises an alert and protects earlier known-good snapshots from automatic deletion.

Verification runners must use a dedicated Docker host/profile, no public ports, no production routes, no outbound network, no production mounts and no source SSH keys or cloud credentials inside the test container. Use a private copy of restored data so application startup migrations or expiry cleanup cannot modify the stored recovery point. Cleanup has an auditable outcome and bounded retry policy.

The UI should say exactly what was tested. Application started does not prove every password decrypts. Backup success must not be represented as Restore tested. If no verification runner is configured, show Restore testing not configured and keep the feature visible with setup instructions.

## 16 Secrets authentication and recovery kit

Use a randomly generated controller master key mounted from a protected secret file, outside PostgreSQL and source control. Encrypt SSH private keys/passphrases, provider tokens, SMTP credentials, repository passwords and sensitive manifests at rest with an established authenticated-encryption library. Version the ciphertext envelope for key rotation. Database-only theft must not reveal those secrets.

Generate a unique strong repository secret per instance/destination. Backups are encrypted even on local disk. Use protected files/file descriptors or appropriate private credential channels to invoke restic/rclone; never put passwords directly in process argument lists. Restrict worker environments and staging files, and redact nested tool output and exception details before persistence.

Provide an encrypted, exportable **recovery kit** containing repository locations/IDs, repository unlock material, relevant provider recovery instructions, instance identifiers, manifest schema details and standalone recovery commands. Export requires administrator authentication and a user-held recovery passphrase handled privately. The kit must be recoverable without the original controller database or its master key. A copy of the controller master key encrypted only by itself is not a recovery mechanism.

Tell the owner to keep the kit and its passphrase outside both Vaultwarden and VaultRewind. Do not store the only SSH credentials, storage credentials or recovery secrets inside the vault being protected. Do not send a recovery kit through email/webhook notifications. Distinguish repository encryption-key rotation from provider credential rotation; neither may make historical snapshots unreadable.

Authentication requires modern password hashing, secure HTTP-only session cookies, CSRF protection for browser mutations, login rate limiting and session invalidation. Administrator role can manage hosts, credentials, policies, backup, restore and deletion. Viewer role sees sanitized status and jobs but cannot reveal/download secrets or mutate anything. Authorize every endpoint server-side. Add scoped API tokens only if needed for the required CLI; never reuse a browser session secret as a remote credential.

Serve the application behind HTTPS, with a documented loopback development exception. Disable unauthenticated job streams and debug endpoints. No telemetry by default. System logs and audit history contain IDs and high-level results, not vault entries, attachment names, email addresses, secret environment values or raw command output. Treat snapshot labels/manifests as potentially sensitive even when the vault payload itself is encrypted by clients.

Serve UI and API from the same origin by default and explicitly configure any cross-origin deployment. Verify packaged helper/binary checksums and protocol versions during activation and upgrade; never fetch and execute an unpinned remote installer inside a normal backup job.

## 17 Persistence model

Implement real relational models and migrations. The following entities define the minimum domain model; combine purely internal tables only if equivalent invariants remain enforceable.

| Entity | Essential fields and invariants |
| --- | --- |
| User | ID, role, password hash, status and timestamps |
| Host | UUID, display name, endpoint, port, SSH user, pinned host identity, credentials reference, helper protocol version and readiness |
| Instance | UUID, host ID, container/resource identity, display name, database type, data mounts, active generation, validated deployment profile and configuration revision |
| InstanceDependency | Instance ID, dependency kind, approved root/reference, required flag, enrollment/readiness state and recovery mapping |
| Secret | UUID, typed encrypted envelope, key version, owner scope and rotation metadata; never plaintext in normal queries |
| StorageDestination | UUID, backend type, endpoint/prefix/folder identity, credentials reference, status and last test |
| Repository | Instance ID plus destination ID uniqueness, repository ID/path, key reference, storage format and lock state |
| BackupPolicy | Instance ID, schedule/timezone, enabled state, retention days or forever, destinations with required flags, outage budget and revision |
| Snapshot | Immutable UUID, instance ID, capture times, trigger, source image/schema evidence, manifest hash, completeness, logical size and parent safety/restore relation |
| SnapshotCopy | Snapshot ID plus repository ID uniqueness, restic snapshot identity, commit/verification state and last error |
| SnapshotProtection | Snapshot/copy scope, pin or protection reason, actor, expiry if any and related job ID |
| Job | UUID, kind, state, phase, actor, idempotency key, immutable request/plan fingerprint, lease owner, fencing token, timestamps and sanitized results |
| JobStep and JobEvent | Ordered durable phase records, remote journal references, retry counters, progress and sanitized structured error codes |
| RestorePlan | Source snapshot/copy, target, mappings, preconditions, configuration fingerprints, confirmation-token hash and expiry |
| VerificationRun | Snapshot/copy, runner, evidence levels, durations, result and cleanup result |
| ResourceLease | Physical source/repository resource key, owner job, lease expiry and fencing generation |
| ScheduleOccurrence | Policy ID plus scheduled UTC occurrence uniqueness, resulting job and catch-up/coalescing metadata |
| AuditEvent | Actor, action, object IDs, outcome, timestamp and sanitized change description |
| NotificationDelivery | Event ID, channel, attempt, destination reference, delivery state and sanitized error |

Use timezone-aware UTC timestamps, UUID-based stable identity, database constraints for uniqueness and explicit foreign-key deletion behavior. Deleting a host, instance, destination or policy must not delete its repositories or snapshots implicitly. A remove-from-dashboard action should archive registration metadata while keeping recovery access. Storage deletion is a distinct confirmed operation with a preview.

Persist secrets separately from normal view models and never return them by serializing ORM objects wholesale. Snapshot metadata is immutable apart from independently stored protection/verification annotations. Imported historical snapshots retain their capture time and source identity; changing a label does not rewrite backup content.

## 18 Job states retries and recovery

Job lifecycle states are queued, running, waiting_retry, succeeded, partial, failed, cancel_requested, cancelled, rolled_back, rollback_failed and needs_attention. The state alone is not sufficient evidence: store content_commit, required_copy_outcome, source_service_outcome and target_activation_outcome separately.

Backup phases are preflight, preparing, quiescing, capturing, resuming_source, validating, transferring, committing_copies and finalizing. Restore phases are planning, reading_snapshot, staging, verifying, preparing_safety, quiescing_target, capturing_safety, switching, validating_candidate, activating and finalizing. Recovery/rollback have their own recorded phases.

Retries are bounded with exponential backoff and jitter. Retry transport and provider failures from a known safe checkpoint. Do not blindly repeat stop, rename, create-container, delete or activation commands after an ambiguous timeout. Ask the helper for its operation journal and reconcile first. Authentication failures, changed host keys, bad credentials, unsupported schema and insufficient space are not endless retry conditions.

On worker/controller restart, reconcile unfinished jobs, remote journals and repository commits before accepting overlapping work. Use a consistent lock ordering to prevent deadlocks. UI streams reconnect using event sequence IDs and receive a current persisted state after gaps. Closing a tab has no lifecycle effect. Cancellation becomes effective only after required recovery completes; show Recovering source rather than falsely reporting cancellation while the vault remains down.

Do not mark a job successful on the existence of an archive, a zero exit code from one subprocess, a healthy source container, or the lack of recent error logs. Success is derived from the workflow invariants.

## 19 HTTP API and CLI contracts

Expose an authenticated, versioned JSON API under /api/v1, publish OpenAPI and validate request/response contracts. All potentially long actions return HTTP 202 with a job ID and status/event links. A browser/API retry carrying the same idempotency key returns the original job. Reusing a key with different inputs is a conflict. Backend authorization and target preconditions are mandatory even if the UI disables a button.

Minimum endpoints:

| Method and route | Purpose |
| --- | --- |
| POST /setup and POST /sessions | Bootstrap and login through their respective security rules |
| GET /instances and GET /instances/{id} | Fleet and instance status |
| POST /hosts and POST /hosts/{id}/discover | Register an SSH identity and perform read-only discovery |
| POST /hosts/{id}/activation-plans | Preview helper/policy installation and prerequisites |
| POST /hosts/{id}/activate | Apply an explicitly accepted setup plan |
| POST /instances | Enroll a discovered supported instance |
| POST /instances/{id}/backups | One-click backup; accepts an idempotency key and optional label |
| GET /instances/{id}/snapshots | Filtered, paginated dated recovery points and copy status |
| GET /snapshots/{id} | Sanitized completeness and verification evidence |
| POST /snapshots/{id}/restore-plans | Validate and preview original/alternate-target restoration |
| POST /restore-plans/{id}/execute | Consume confirmation token and enqueue the bound restore |
| POST /snapshots/{id}/verify | Enqueue repository/read/application verification as supported |
| POST and DELETE /snapshots/{id}/pin | Explicitly change pin state with audit history |
| POST /snapshots/{id}/deletion-plans | Preview eligible explicit deletion without bypassing protections |
| POST /deletion-plans/{id}/execute | Execute a confirmed eligible deletion plan |
| GET /jobs/{id} and GET /jobs/{id}/events | Persisted status and authorized resumable event stream |
| POST /jobs/{id}/cancel | Request safe cancellation |
| GET and POST /storage-destinations | List/create storage configurations |
| POST /storage-destinations/{id}/test | Run a scoped storage connection test |
| POST /storage-destinations/{id}/authorize | Start/reconnect provider authentication without exposing tokens |
| GET and PATCH /instances/{id}/policy | View/change schedule and retention with revision checks |
| POST /instances/{id}/retention-preview | Calculate exact candidate expirations and protections |
| POST /recovery-kits/export | Produce an encrypted owner-held recovery kit |
| POST /recovery/import-plans | Discover repositories/manifests using supplied private recovery material |
| GET /audit-events | Authorized paginated audit history |
| GET /health/live and GET /health/ready | Process liveness and sanitized controller readiness |

Use If-Match or an equivalent revision guard on policy/configuration mutations. Sanitize server-side validation errors. Errors use a stable code, safe human explanation, retryable flag, phase and job ID where applicable. Typical codes include SSH_HOST_KEY_CHANGED, UNSUPPORTED_INSTALLATION, REQUIRED_FILE_UNREADABLE, SOURCE_RESTART_CONFLICT, INSUFFICIENT_SPACE, SNAPSHOT_INCOMPLETE, TARGET_CHANGED, IMAGE_UNAVAILABLE, STORAGE_AUTH_EXPIRED, SOURCE_RECOVERY_FAILED and RESTORE_ACTIVATION_UNCERTAIN.

Publish a CLI named vaultrewind using the same domain services. Required commands are backup, snapshots, restore-plan, restore, verify, jobs, retention-preview, recovery-export, recovery-import and doctor. Normal authenticated CLI operations follow the same permissions and safety rules as the UI.

Also ship a documented **offline recovery** mode that works without the running controller or its database. Given the owner-held recovery kit, provider access and standard restic/rclone dependencies, it can discover snapshots, restore a chosen snapshot to a local directory, validate it and generate the supported target deployment plan. Applying that plan to a prepared host must use the same helper safety protocol or a clearly documented equivalent, never a silent unsafe overwrite. The standalone mode is essential disaster-recovery functionality, not an optional admin convenience.

## 20 Observability and notifications

Keep an append-only application audit trail for registration, policy changes, secret rotation, backup, restore, pinning, deletion, imports and manual recovery decisions. Record actor, target and outcome. Database administrators can still alter an ordinary database; do not advertise this as tamper-proof evidence without an additional external mechanism.

Provide structured logs with correlation IDs, job phases, durations and safe error codes. Expose optional authenticated/privately bound metrics for backup age, job outcomes, bytes, duration, quota and verification age. No vault contents or high-cardinality private paths in metrics.

Alert on failed/partial required backups, overdue backups, source restart failure, restore failure/rollback, unresolved activation, failed verification, expiring/revoked storage authorization and low storage. Deduplicate repeated alerts and send recovery notifications when the condition clears. SMTP/webhook delivery failure must not change a valid backup into an invalid one, but must be visible separately.

Webhook configuration is administrator-only, restricts unsafe destinations according to a configured allowlist, verifies TLS, and cannot access controller/cloud metadata endpoints by default. Because source SSH hosts may intentionally use private networks, apply private-network restrictions per integration rather than blocking all private addresses globally. Sign outbound webhook requests when configured and store signing secrets privately. Webhook payloads contain sanitized instance labels/IDs and status only.

## 21 Installation upgrades and disaster recovery of VaultRewind

Ship a production Compose file, development Compose file, environment example without secrets, health checks, migrations and a clean first-run flow. Mount separate persistent locations for controller metadata, repositories, credentials/key material, caches and staging. Do not mount /var/run/docker.sock into the controller. Images run with the least privilege needed for their controller role.

Document supported host/controller platforms, helper installation/removal, required SSH/sudo policy, filesystem requirements, outbound cloud access, TLS/proxy setup, source pause behavior and complete recovery prerequisites. Source Docker service access through the helper is privileged access; it is not equivalent to an ordinary unprivileged file reader.

Upgrades must preserve existing repositories and historical manifest readability. Include schema migrations, migration rollback guidance, helper protocol compatibility checks and a minimum tested-version policy. Snapshot restores use recorded Vaultwarden images; application/controller upgrades must not silently migrate protected Vaultwarden instances.

Back up VaultRewind's own PostgreSQL metadata and exported encrypted catalog to a selected durable destination. The recovery kit independently unlocks application repositories. Test loss of the entire controller, its database and its original master key: a fresh installation with only the recovery kit and provider/disk access must discover and restore a snapshot. Import recovered repositories in protected mode, with automatic retention disabled and imported snapshots protected until the owner reviews policy and pin state. Do not infer that missing catalog rows mean repository snapshots should be deleted.

Build an integrity/doctor page and command reporting helper protocol mismatches, repository accessibility, stale jobs, failed cleanup, source readiness and incomplete recovery setup. Diagnostic actions must identify which checks write probe data or refresh credentials.

## 22 Testing strategy and synthetic fixtures

Create a fully synthetic test Vaultwarden instance with multiple users, organizations, records, attachments and Send content. Include empty directories, dotfiles, nested directories, filenames with spaces/Unicode, mixed UID/GID ownership, root-owned private files, a SQLite WAL, configuration secrets and a deployment started without Compose. Never import the owner's actual vault for development.

Unit/property tests cover inventory boundaries, manifest versioning, path validation, retention cutoffs/protections, schedule/DST behavior, idempotency, policy revisions, secret redaction, unsafe deployment options, lock ordering and state-machine transitions. Use fixed clocks and generated paths/metadata to find boundary errors. Do not write tests that merely repeat constants or mock every correctness boundary away.

Integration tests run a real Vaultwarden image, real SQLite capture/normalization, real SSH/helper execution on a disposable Linux/systemd environment, real restic local repositories, and MinIO for S3-compatible behavior. A Docker-only environment without meaningful systemd/boot behavior is insufficient evidence for remote watchdog/reboot guarantees. Provide a reproducible VM-based test harness for those cases.

Google Drive must have deterministic provider-adapter tests and an opt-in live test against an owner-supplied dedicated test account. Live credentials belong in CI secrets, not fixtures. Before declaring the integration release-ready, record successful real authorization, refresh, backup, restore, retention and revoked-token behavior. If no test credentials are available, report that release blocker honestly rather than labeling the integration verified.

End-to-end browser tests cover enrollment, Backup now, dated snapshot selection, original-target confirmation, progress/reconnect, restore completion, alternate-target recovery, retention preview, pinning, failed copies and actionable errors. Verify keyboard/focus management and narrow screens. UI-only mocks do not satisfy backup/restore acceptance.

## 23 Required acceptance matrix

Every requirement below must have an automated test where feasible and a recorded integration/manual procedure where external credentials or host reboot are required. Reference the IDs in the final implementation report.

| ID | Passing evidence |
| --- | --- |
| AC01 | One Backup now action creates a complete dated snapshot without manual file or terminal work after onboarding. |
| AC02 | Scheduled and manual backups create distinct logical snapshots even with identical content. |
| AC03 | Root-owned mode-0600 attachments/configuration are captured without changing live permissions. |
| AC04 | A nonempty SQLite WAL is incorporated into the normalized backup; restored database integrity and committed-record checks pass. |
| AC05 | Database, attachments, Sends, keys, unknown persistent files, environment and deployment metadata all survive a round trip. |
| AC06 | A manually launched instance with no usable Compose file can be restored using the captured normalized deployment definition. |
| AC07 | Restore to the original instance returns synthetic vault content to the selected capture point; changes made afterward are absent. |
| AC08 | That replacement creates a pinned safety snapshot and preserves the previous target generation. |
| AC09 | Restore to a prepared alternate server works while the original remains running and unchanged. |
| AC10 | A source that was initially stopped remains stopped after backup or a data-only restore. |
| AC11 | Restore uses the recorded image from the backup when the registry is unavailable; unsupported architecture fails before target downtime. |
| AC12 | Local storage survives controller recreation because it is stored on a real persistent host mount. |
| AC13 | S3-compatible backup, restore and expiration pass against MinIO; missing deletion permission produces an accurate retained-copy state. |
| AC14 | Google Drive real authorization, token refresh persistence, backup, restore and reconnect work with dedicated test credentials. |
| AC15 | Retention preserves every snapshot within X rolling days, handles the exact boundary and does not confuse days with snapshot counts. |
| AC16 | Pins, newest complete/tested recovery points, active restore inputs and safety snapshots survive retention; failure/overdue protection freezes deletion. |
| AC17 | An unreadable required file, partial transfer or non-successful restic backup cannot produce Complete status. |
| AC18 | Failure of a required cloud copy reports partial/failure while a valid local copy remains restorable. |
| AC19 | SSH host-key change blocks work; injection and traversal payloads cannot escape helper policy or modify unrelated host paths. |
| AC20 | Duplicate clicks, two workers and duplicate registrations cannot overlap work on the same physical instance. |
| AC21 | Closing/reloading the browser does not cancel a job; progress reconnects from persisted state. |
| AC22 | Controller/worker/SSH loss immediately after stopping the source triggers host-local recovery without controller assistance. |
| AC23 | Source host reboot during capture/restore reconciles the journal and chooses the correct preserved generation. |
| AC24 | Failure during staged transfer, file switching or isolated candidate startup restores the original target before public activation; rollback outcome is verified. |
| AC25 | After activation may have occurred, interruption does not silently revert and discard new client writes; it reconciles or reports needs_attention. |
| AC26 | Source full disk, controller full disk, missing local mount, expired cloud credentials and cloud quota failure preserve the live instance and older backups. |
| AC27 | Retention never deletes another instance's snapshots, races an active restore, or force-unlocks an active repository owner. |
| AC28 | An isolated restore test starts the app without production routes, notifications, outbound access or source-volume writes. |
| AC29 | Deliberately corrupted backup data is detected; metadata-only checks are never represented as full data verification. |
| AC30 | Fresh-controller recovery with no original database/master key succeeds using the independently encrypted recovery kit and storage access. |
| AC31 | Secret values cannot be found in API responses, logs, job events, screenshots, command arguments or committed files. |
| AC32 | Viewer-role users cannot trigger backup, restore, deletion, credential access or policy changes through direct API calls. |
| AC33 | First-run bootstrap cannot be claimed by an unauthenticated visitor without the bootstrap secret. |
| AC34 | Unsupported native installations, external databases, volume drivers or required dependencies fail clearly during discovery/preflight. |
| AC35 | Updating VaultRewind/helper versions preserves old snapshots and validates protocol compatibility before source changes. |
| AC36 | The production controller starts cleanly from the supplied Compose file and documentation on a fresh supported machine. |

## 24 Failure injection checklist

Add deterministic fault hooks in the test harness, disabled in release builds/configuration. Inject process death or transport loss immediately before/after these boundaries: watchdog arming, source stop, first/last copied file, source restart, image export, manifest creation, storage commit acknowledgment, first target rename, volume/container creation, candidate boot, activation decision, first public start and retention deletion. Run each against the expected journal state and recovery rule.

At minimum test manager termination, worker termination, SSH disconnect, helper termination, Docker daemon restart, host reboot, stale lease, corrupt journal, partial journal write, duplicate remote request, provider timeout after a successful commit, corrupted image archive and unsafe archive member. A host that is physically down cannot be made healthy by software; the requirement is correct boot recovery and truthful status when reachability returns.

Verify that the system does not leave the source stopped waiting for a slow cloud, retry a destructive ambiguous command blindly, delete the last good snapshot during a failure streak, or report rollback completion before the original target actually recovers.

## 25 Implementation sequence and deliverables

Build and verify in this order:

1. Establish domain models, schema, manifest format, versioned interfaces, synthetic fixtures and a tested command-line local backup/restore round trip.
2. Implement SSH discovery, policy-scoped helper activation, source/resource locks, remote journals, watchdog and boot recovery. Demonstrate source recovery under controller loss before any UI claims reliability.
3. Implement complete consistent captures, normalization, image/deployment capture, local encrypted repository storage and durable copy reconciliation.
4. Implement transactional original-target restore, mandatory safety snapshots, isolated candidate checks, public activation boundary and alternate-target recovery.
5. Implement retention/pinning, durable schedules, crash reconciliation and repository verification.
6. Complete S3-compatible and Google Drive setup, lifecycle/credential handling and integration evidence.
7. Build the full responsive UI on the proven backend; complete authentication, roles, progress streams, audit and notifications.
8. Finish restore-test automation, independent recovery kit/import/offline CLI, controller disaster recovery, packaging, documentation and the acceptance matrix.

Each milestone ends with working code and tests, not a slide or architecture-only document. During implementation, simplify internal plumbing when possible without reducing required recovery guarantees. Do not replace a missing integration with a decorative UI control or mocked success response.

Required repository outputs are backend and worker source, frontend source, versioned remote helper, database migrations, production/development Compose files, dependency lockfiles, synthetic integration fixtures, Linux/systemd failure-test harness, OpenAPI, CLI/offline recovery tooling, sample configuration with no secrets, operator documentation and a completed acceptance evidence report.

Documentation must include quick start, onboarding and exact host changes, supported installation matrix, backup/restore consistency guarantees, storage/provider setup, retention rules, key/recovery-kit handling, alternate-host recovery, backup of VaultRewind itself, upgrade procedure, failure/rollback troubleshooting and a complete fresh-controller recovery drill. Include an end-to-end demo using synthetic data, with a screenshot or recording showing real backup and restore results.

Use the MIT license as the proposed default unless the owner chooses another before publication. Do not invent a copyright owner. Do not publish, deploy to production, create cloud accounts, upload real vault data or send messages to others as part of implementing this specification without separate authorization.

## 26 Performance and operational expectations

API job creation should return within two seconds under normal load; job progress should become visible within five seconds. These are implementation targets to measure with the documented reference fixture. Long transfers run outside HTTP request lifetimes, avoid unbounded memory buffering and support configured transfer limits.

Test small and attachment-heavy synthetic instances and report actual capture outage, transfer duration, logical/stored bytes, restore duration and verification duration. Do not publish a universal backup/restore speed promise. The pause depends on source data size and disk throughput; fail before capture or recover automatically when the configured budget cannot be met.

The worker must enforce total staging quotas, per-job quotas, remote free-space reserves and cleanup retries. Source staging, controller staging, safety captures, rollback generations and image caches each have visible retention/space accounting. Do not silently evict a protected snapshot to make room for a new backup.

## 27 Design decisions and implementation boundaries

The first release deliberately accepts a brief source pause to obtain a complete application recovery point. It uses SSH plus an explicitly installed constrained helper and recovery facility, not a permanently listening custom agent. It stores immutable dated content snapshots, not continuous database point-in-time recovery. It supports complete Vaultwarden application recovery on a prepared compatible Docker host, not automatic provisioning of an entire cloud account or VM.

The product owns capture orchestration, completeness, recovery planning, safety snapshots, retention policy and user experience. Established tools own repository encryption, content storage and provider transport. New storage or database engines must implement the typed interfaces and acceptance contract rather than bypass it with shell commands in route handlers.

Avoid expanding version one to official Bitwarden, multiple database engines, arbitrary shell hooks, public SaaS tenancy, Kubernetes, multi-controller high availability, continuous replication, cross-architecture image conversion or automatic DNS failover. Leave documented extension points and release these only after the matching recovery contract is tested.

## 28 Primary technical references

These references establish underlying tool behavior. Product-specific decisions, defaults, boundaries and acceptance criteria above are VaultRewind requirements rather than promises made by those projects. Recheck current official documentation during implementation.

- [Vaultwarden backup and restore guidance](https://github.com/dani-garcia/vaultwarden/wiki/Backing-up-your-vault) describes required data, SQLite backup methods and WAL handling. Database backup does not replace attachment/configuration capture.
- [SQLite backup API](https://www.sqlite.org/backup.html) documents supported database snapshot creation. Use it for the staged database normalization contract.
- [restic repository preparation](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html) covers local/cloud repository configuration, encryption credentials and provider backends.
- [restic backup documentation](https://restic.readthedocs.io/en/stable/040_backup.html) defines backup behavior and status handling. Review partial-result behavior explicitly.
- [restic restoration](https://restic.readthedocs.io/en/stable/050_restore.html) documents recovery into a target directory. VaultRewind adds the application transaction and activation protocol.
- [restic retention and pruning](https://restic.readthedocs.io/en/stable/060_forget.html) distinguishes logical forgetting, physical pruning and retention-policy semantics. VaultRewind's exact UTC retention/protection planner remains authoritative.
- [restic repository verification](https://restic.readthedocs.io/en/stable/045_working_with_repos.html) distinguishes structural checks from reading stored data.
- [restic scripting](https://restic.readthedocs.io/en/stable/075_scripting.html) documents machine-facing options and private credential channels.
- [rclone restic integration](https://rclone.org/commands/rclone_serve_restic/) describes the cloud bridge. Keep any service endpoint private to the worker rather than exposing it publicly.
- [rclone Google Drive](https://rclone.org/drive/) documents authorization, scopes, client configuration and provider constraints. Persist refreshed tokens safely.
- [Databasement](https://github.com/David-Crty/databasement) is an interaction reference for centralized schedules, storage and recovery. VaultRewind's complete application boundary and transaction guarantees are specified independently.




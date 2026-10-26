# Storage destinations, encryption and secrets

VaultRewind stores every snapshot in a **standard encrypted restic repository**: one repository per instance per
destination. It adds no custom cryptography or chunk format, so any restic 0.18+ installation can read the data with
the repository password. The integration contract for developers is in [STORAGE-CONTRACT.md](STORAGE-CONTRACT.md).
Disaster recovery is covered in [RECOVERY.md](RECOVERY.md).

## Tested versions

| Component | Version | Notes |
| --- | --- | --- |
| restic | 0.19.1 (`tools/binaries.lock.json`, SHA-256 pinned) | minimum supported 0.18.0 (JSON `check`, exit codes 3/10/11/12) |
| rclone | 1.75.2 (pinned) | Google Drive bridge through `rclone serve restic --stdio`, started by restic |
| MinIO | RELEASE.2025-10-15T17-29-55Z (built from official source) | S3-compatible test fixture only |
| Python packages | cryptography 50.0.2, argon2-cffi 25.1.0, boto3 1.43.118, httpx 0.28.1 | see `uv.lock` |

## Repository layout and identity

```
<destination base>/vaultrewind/<instance UUID>/<destination UUID>     # restic repository
```

* The base is the local mount path, the S3 `bucket/prefix`, or the Google Drive folder created for the destination.
* Display names, hostnames and staging paths never appear in a path, so renaming changes nothing on storage.
* Each snapshot carries encrypted restic tags `vaultrewind:snapshot=<uuid>`, `vaultrewind:instance=<uuid>`,
  `vaultrewind:manifest=<sha256>`, `vaultrewind:kind=backup|safety` and `vaultrewind:schema=1`, and its restic
  time is the capture time. Inside every snapshot the tree is always `/data`, `/deployment`, `/images`, `/manifest`.
* The controller records the restic repository ID and refuses to use a repository whose ID differs
  (`REPOSITORY_IDENTITY_MISMATCH`). It never re-initializes a repository that disappeared (`REPOSITORY_NOT_FOUND`).

## When a copy counts as stored

A storage copy is marked committed only when all of these hold:

1. restic exited 0 and reported **no** read errors or warnings. restic still writes a snapshot on a partial run
   (exit 3), so VaultRewind forgets that exact snapshot ID and reports `STORAGE_COMMIT_PARTIAL`.
2. The new snapshot is found again by its snapshot UUID tag.
3. The stored `/manifest/manifest.json` reads back and its canonical SHA-256 equals the staged manifest.
4. The stored file tree has exactly the paths, types and sizes listed in the manifest inventory.

This is *stored-copy validation*. It reads the manifest but not every data blob. Full verification is separate:

* **Repository data verification** (`check --read-data`) reads and decrypts every pack. Only this is reported as
  `full_data_verified`; a structural check is labeled `verification_level: structure`.
* **Restore verification** restores into an empty private directory with `restic restore --verify`, then checks
  every file hash, link and the SQLite database against the manifest.

After a worker crash, a retry first looks up the snapshot UUID in the repository and reuses a valid copy instead
of uploading a duplicate. The same UUID with different content stops with `SNAPSHOT_IDENTITY_CONFLICT`.

## Deletion and pruning

* Retention runs `restic forget <exact 64-hex IDs>` and never passes a restic `--keep-*` policy. It refuses any ID
  that lacks the repository's instance tag, and it re-lists the repository afterwards. The result shows what was
  actually removed and what was **retained** (for example `STORAGE_DELETE_DENIED` when credentials may not delete).
* `prune` (physical space reclamation) is separate and is followed by a structural `check`.
* restic locks are never force-removed. A locked repository returns `REPOSITORY_LOCKED`, which is retryable.
  The explicit administrator action `remove_stale_locks` only removes locks that restic itself considers stale.

## Local persistent disk

The controller container mounts an owner-selected host directory at `/var/lib/vaultrewind/backups`. Requirements
(each is checked before every use):

* A real directory, normalized and free of symlinks. It may not be `/` or a system directory, and it may not overlap
  the controller's state, staging, database, key or cache directories.
* It sits on a **dedicated mount** (not the container root filesystem) with a persistent supported filesystem:
  ext2/3/4, XFS, Btrfs, ZFS, F2FS, JFS, bcachefs, ReiserFS, or NFS (with a warning). tmpfs/ramfs, overlay/aufs (the
  container's writable layer), CIFS/SMB (restic advises against it), FUSE, read-only and unknown filesystems are
  rejected. A development-only setting, `allow_unlisted_filesystems`, exists for Docker Desktop mounts.
* It is owned by the VaultRewind service account with mode `0700`. The first **Test connection** sets `0700` on this
  dedicated directory and writes `.vaultrewind-destination.json`. That marker holds the destination UUID and is how
  a missing mount is detected: an empty underlying directory has no marker, so VaultRewind fails with
  `LOCAL_MOUNT_MISSING` and writes nothing.
* Free space must be at least `min_free_bytes` (default 5 GiB) plus the expected upload.
* The UI shows the host path (`host_path`, display only) and free space. Local copies do not survive loss of the
  controller disk, so add an off-host destination.

## S3-compatible storage (AWS S3, MinIO, …)

Configuration: endpoint, bucket, optional prefix, region, addressing (`auto`, `path`, or `dns`; the UI's `virtual`
means `dns`), an optional custom CA bundle (PEM certificates only), and an access key ID/secret (optionally with a
session token).

* HTTPS with certificate verification is mandatory. Plain HTTP is accepted only when `development_http` is
  explicitly set **and** the host is loopback, a private IP, or a single-label Compose service name such as `minio`.
  TLS verification can never be disabled. A custom CA replaces the system roots for that destination.
* Credentials reach restic only through environment variables of a freshly built process environment and reach
  boto3 only as explicit session arguments. They never appear in command arguments.
* **Test connection** writes, reads and deletes probe objects under `<prefix>/vaultrewind/.probe/<uuid>/` using
  restic-shaped keys (`locks/`, `snapshots/`, `data/`). It reports `list`, `write`, `read` and `delete` separately,
  plus `delete_classes`, so a prefix-scoped "no delete" policy shows up as `retention_ready: false`. Backups need
  list/read/write; retention needs delete. Without delete, restic also cannot remove its own lock files.
* Disable lifecycle/expiration rules on the VaultRewind prefix: they can delete chunks still needed by retained
  snapshots. Bucket versioning is unrelated to VaultRewind's snapshot history.

Minimal IAM policy for the prefix `vaultrewind-backups/` (replace bucket and prefix):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::BUCKET",
     "Condition": {"StringLike": {"s3:prefix": ["vaultrewind-backups/*"]}}},
    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
     "Resource": "arn:aws:s3:::BUCKET/vaultrewind-backups/*"}
  ]
}
```

Workload/instance-role credentials are not supported in this release; use a dedicated access key.

## Google Drive

VaultRewind uses restic's rclone backend with the **`drive.file`** scope (least privilege: VaultRewind can only see
files and folders it created). Personal My Drive is supported. Shared drives are rejected (untested).

### One-time Google Cloud setup (owner)

1. Create a Google Cloud project and enable the **Google Drive API**.
2. Configure the OAuth consent screen, add the scope `https://www.googleapis.com/auth/drive.file` and add the
   dedicated test account as a test user. Keep the app in **Testing** for this drill; no publication is required.
   External Testing grants using this scope receive refresh tokens that expire after seven days; long-term
   operation needs an owner-reviewed Google configuration and may require Reconnect.
   See [Google's refresh-token expiration rules](https://developers.google.com/identity/protocols/oauth2).
3. Create an OAuth client of type **Web application** with the authorized redirect URI
   `<your exact VaultRewind origin>/api/v1/oauth/drive/callback`. For the private forwarded test app, use exactly
   `http://127.0.0.1:8098/api/v1/oauth/drive/callback` and open the app at `http://127.0.0.1:8098`.
   Google permits the [loopback HTTP exception](https://developers.google.com/identity/protocols/oauth2/web-server#redirect-uri-validation-rules)
   for local testing; production uses the configured HTTPS origin.
4. In VaultRewind, add a Google Drive destination with that client ID and secret in its private form, then choose
   **Authorize / reconnect**. You are
   sent to Google and back. VaultRewind validates the callback origin and the single-use state (bound to your
   session, 10-minute expiry, PKCE S256), exchanges the code on the server, and creates a folder for this
   destination. The folder name and stable folder ID are shown afterwards.

Leave *folder ID* empty when creating a destination. Enter one only to reattach a folder that VaultRewind created
earlier with an OAuth client from the same Google Cloud project; `drive.file` cannot see other folders.

### Advanced headless authorization

If the browser flow cannot reach the controller, VaultRewind shows a one-time procedure. On any computer with a
browser and rclone 1.75.2: allow `http://127.0.0.1:53682/` as a redirect URI on the same client (or create a
*Desktop app* client in the same project), then run

```sh
read -r RCLONE_DRIVE_CLIENT_ID        # paste the client ID
read -rs RCLONE_DRIVE_CLIENT_SECRET   # paste the client secret (not echoed)
export RCLONE_DRIVE_CLIENT_ID RCLONE_DRIVE_CLIENT_SECRET RCLONE_DRIVE_SCOPE=drive.file
rclone authorize drive
unset RCLONE_DRIVE_CLIENT_SECRET
```

Paste only the JSON object printed between the arrows into VaultRewind's private token field. VaultRewind
confirms the token by refreshing it with Google, checks the granted scope, and creates or verifies the folder.
The secret never appears in a command line. rclone reads these environment variables (verified with 1.75.2).

### Token handling

* Tokens are kept only as encrypted controller secrets. They never go into URLs, browser storage, logs or process
  arguments. The OAuth callback query is removed from the request before logging (`OAuthCallbackScrubber`) and
  answered with a `303` redirect carrying `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
* Each job gets a private writable rclone config (0600 in a 0700 directory). Before exposing it, VaultRewind
  registers encrypted, fsynced session provenance in persistent `provider-credentials/sessions` state. A later
  process can recover a registered orphan after abrupt worker death, provided no surviving writer still owns it.
* Token changes are encrypted and fsynced before plaintext cleanup, then persisted with grant, row generation,
  revision and refresh-token lineage checks. Access-token expiry alone cannot order independently rotated
  refresh tokens. Conflicts block safely with actionable reconnect/recovery guidance. Reconnect and local
  revocation invalidate the old grant so an old session cannot restore it.
* Preserve persistent credential state and relevant old controller keys until sessions and pending updates are
  recovered. If every durable write channel fails, cleanup is blocked to protect the sole transient token copy;
  repair storage immediately. See [the storage contract](STORAGE-CONTRACT.md) and [recovery guide](RECOVERY.md).
* Deleted repository files bypass the Drive trash (`use_trash = false`) so pruning frees quota. Daily upload and
  download limits are fatal (`stop_on_upload_limit`) instead of retried forever.
* Credential states shown to the user: `authorization_required`, `reconnect_required` (revoked, expired, or
  Testing-mode consent ended), `quota_exceeded`, `rate_limited`, `credentials_invalid`, `folder_unavailable`.
  Reconnect keeps the same folder and repositories.

## Secrets at rest

* The controller master key is 32 random bytes in a mounted secret file (not group-writable, not world-readable).
  It lives outside PostgreSQL and source control.
* Secrets are stored as versioned AES-256-GCM envelopes (`vr1.<key id>.<nonce>.<ciphertext>`) bound to their row
  context. Master-key rotation re-encrypts envelopes with the new key while old keys are still loaded for reading.
  It never changes repository passwords, so historical snapshots stay readable.
* Each repository has its own strong password: derived with HKDF from a recovery root secret (so recovery kits
  exported earlier still open repositories created later) or random. **Repository key rotation** adds a restic key,
  proves it opens the repository and stores it. The old key is kept until a new recovery kit has been exported,
  because older kits still use it.
* restic/rclone run with a rebuilt environment (`PATH=/usr/local/bin:/usr/bin:/bin`, private `HOME`, `TZ=UTC`).
  The repository password is in a temporary 0600 file that is overwritten and removed afterwards. Nothing from the
  controller's own environment is inherited.
* Tool output is classified in memory into stable error codes and never stored. Logs pass through nested redaction
  (`install_log_redaction()`).

## Troubleshooting

| Code | Meaning and next step |
| --- | --- |
| `LOCAL_MOUNT_MISSING` | The backup directory is not mounted or lacks its identity marker. Check the Compose volume; nothing was written. |
| `LOCAL_FILESYSTEM_UNSUPPORTED` | The path is on tmpfs, overlay, CIFS, FUSE or an unknown filesystem. Mount a persistent disk. |
| `LOCAL_PERMISSIONS_UNSAFE` | The directory is not owned by the service account or is not `0700`. |
| `INSUFFICIENT_SPACE` | Free space is below the threshold plus the estimate. Older backups are untouched. |
| `STORAGE_TLS_REQUIRED` / `STORAGE_TLS_FAILED` | Use HTTPS, or add the endpoint's CA bundle. Verification cannot be disabled. |
| `STORAGE_CREDENTIALS_INVALID` / `STORAGE_PERMISSION_DENIED` | The key was rejected, or the policy lacks an operation (see the probe breakdown). |
| `STORAGE_DELETE_DENIED` | Retention could not delete. The copies are still listed as retained; grant delete or delete manually. |
| `STORAGE_AUTH_EXPIRED` | Google revoked or expired the grant. Use **Reconnect**. |
| `STORAGE_QUOTA_EXCEEDED` / `STORAGE_RATE_LIMITED` | The provider quota is full or requests are throttled. Rate limits are retried later; quota needs action. |
| `REPOSITORY_LOCKED` | Another process holds the restic lock. VaultRewind waits and retries and never forces the lock. |
| `REPOSITORY_IDENTITY_MISMATCH` / `REPOSITORY_NOT_FOUND` | The recorded repository was replaced or removed. Investigate before retrying; nothing is recreated. |
| `STORAGE_COMMIT_PARTIAL` | Some staged content could not be read. That copy was discarded and the snapshot is not complete. |
| `SNAPSHOT_IDENTITY_CONFLICT` | The repository holds different content under the same snapshot UUID. Stop and investigate. |

## Verification

Commands run from the repository root, with the pinned binaries installed and the synthetic MinIO fixture running:

```sh
.venv/bin/python -m pytest tests/unit/test_storage_secrets.py tests/unit/test_storage_restic.py \
  tests/unit/test_storage_local.py tests/unit/test_storage_s3.py tests/unit/test_storage_drive.py \
  tests/unit/test_storage_recovery.py tests/unit/test_storage_drive_live.py -q -rs
```

Historical result (2026-10-25): 138 passed, 4 skipped (the opt-in adapter-only Google Drive harness). The exact
coverage is listed in STORAGE-CONTRACT.md §10. Those optional pytest cases remain skipped; they are not
represented as executed live tests.

The subsequent owner-authorized dedicated-account drills completed the real SQL-backed worker workflow:
authorization, rclone refresh persistence, complete local/Drive byte readbacks, actual alternate application
restore with local safety protection, exact retention/prune, revoked-credential failure, private UI Reconnect
and same-snapshot copy retry. [The matched release report](evidence/drive-release.json) binds their component
identities and hashes. It records structural application readiness, not authenticated Vaultwarden login or
decryption; Google quota exhaustion and natural seven-day grant expiry were not attempted.

# Storage, secrets and recovery integration contract

Owner: storage agent (`src/vaultrewind/storage`, `security`, `recovery`). Consumers: server/worker, CLI.
Status: implemented and tested; see "Verification status" at the end for exactly what has and has not been proven.
Everything here is synchronous and suitable for a worker thread. All failures raise
`VaultRewindError(code, message, retryable, **details)`; messages are safe to persist, and
`details` contain only codes, counts and IDs (never tool output, paths inside vaults or secrets).

## 1. Secrets: `vaultrewind.security.secrets`

```python
box = SecretBox(master_key: bytes, previous_keys: Iterable[bytes] = ())
envelope: str = box.encrypt(value: dict | str, *, context: str | None = None)
value = box.decrypt(envelope, *, context=None)      # returns the same type that was encrypted
box.needs_rotation(envelope) -> bool;  box.rotate(envelope, *, context=None) -> str;  box.key_id
generate_master_key() -> bytes;  write_master_key_file(path);  load_master_key_file(path) -> bytes
```

* AES-256-GCM (`cryptography`), 96-bit random nonce, key and public key ID derived with HKDF-SHA256.
* Envelope: `vr1.<16-hex key id>.<nonce b64url>.<ciphertext+tag b64url>`; AAD binds version, key ID and `context`.
* **Use `context`** for row binding, e.g. `context=f"secret:{row.id}"` or `f"destination:{id}:credential"`.
  The same context must be passed to `decrypt`; moving an envelope to another row then fails authentication.
* Master key rotation: construct `SecretBox(new_key, previous_keys=[old_key])` and call `rotate()` on each
  envelope. Repository passwords inside are unchanged, so historical snapshots stay readable.
* Key files: 32 raw bytes, 64 hex characters, or 43/44 base64(url) characters; must not be group-writable or
  world-readable. `write_master_key_file` never overwrites.

## 2. Redaction and OAuth callback hygiene: `vaultrewind.security.redaction`

* `redact(value, secrets=())` deep-copies dict/list/tuple/dataclass/exception values, replacing sensitive keys
  (`password`, `*_secret`, `*_token`, `client_secret`, `refresh_token`, `private_key`, `authorization`, …) and
  scrubbing free text (PEM private keys, bearer tokens, `ya29.`/`1//` Google tokens, `GOCSPX-` client secrets,
  AWS key IDs, `code=`/`state=`/`token=`/`X-Amz-Signature=` query values, URL user-info, registered secrets).
* `register_secret(value)` — every `RepositoryConfig` registers its password/credentials automatically.
* `install_log_redaction()` — attach `RedactingFilter` to root, `uvicorn`, `uvicorn.access`, `uvicorn.error`,
  `httpx`, `asyncssh`. Call once at API and worker start-up.
* **OAuth callback (required):** wrap the outermost ASGI app:
  `app = OAuthCallbackScrubber(app, paths={"/api/v1/oauth/drive/callback"})`.
  It moves `code`/`state`/`error`/`scope` into `scope["state"]["vaultrewind_oauth_callback"]` and blanks
  `query_string`/`raw_path` in place, so uvicorn access logs, exception reporters and handlers never see the
  code. Read the values with `callback_params(request)`. The handler must answer with a `303` redirect to a clean
  UI URL (no tokens or codes) and the headers in `CALLBACK_RESPONSE_HEADERS`
  (`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, …). No token ever goes to the browser.

## 3. Repository naming: `vaultrewind.storage.layout`

* `repository_prefix(instance_id, destination_id) -> "vaultrewind/<instance_uuid>/<destination_uuid>"`
  (canonical lowercase UUIDs; display names, hostnames and staging paths are never part of a path).
* Locations (build them with `vaultrewind.storage.providers.repository_location`, not by hand):
  * local: `<destination path>/vaultrewind/<instance>/<destination>`
  * S3: `s3:https://<endpoint host[:port]>/<bucket>/<optional prefix>/vaultrewind/<instance>/<destination>`
  * Drive: `rclone:vrdrive:vaultrewind/<instance>/<destination>` inside the destination's Drive folder ID.
* Snapshot tags (all restic metadata is encrypted in the repository): `vaultrewind:snapshot=<uuid>`,
  `vaultrewind:instance=<uuid>`, `vaultrewind:manifest=<sha256>`, `vaultrewind:kind=backup|safety`,
  `vaultrewind:schema=1`. Host is always `vaultrewind`; snapshot `time` is the manifest `captured_at` (UTC,
  second precision). Inside every snapshot the canonical tree is rooted at `/data`, `/deployment`, `/images`,
  `/manifest` regardless of staging location.
* Repository secrets: `new_repository_password()` (random, 384 bits) **or**, recommended,
  `derive_repository_password(recovery_root_secret, instance_id, destination_id)` (HKDF-SHA256, unique per pair)
  with one `new_recovery_root_secret()` generated at first run and stored as a SecretBox envelope. With derived
  passwords, a recovery kit exported at first run can open repositories created later. Store each repository's
  current password as its own envelope either way (rotation makes it non-derivable; see §5).

## 4. `vaultrewind.storage.restic`

```python
cfg = RepositoryConfig(location, password, environment={}, cache_dir=None, rclone_config=None,
                       *, instance_uuid=None, expected_repository_id=None, ca_cert_pem=None, options=(),
                       restic_binary="restic", rclone_binary="rclone", runtime_dir=None, temp_dir=None,
                       allow_insecure_http=False, lock_wait="2m", timeouts={})
repo = ResticRepository(cfg, cancel_event: threading.Event | None = None)
```

Prefer `providers.open_repository(...)` (§6), which builds the config per backend. Set `instance_uuid`
(ownership checks) and `expected_repository_id` (detects a substituted/missing repository) from the catalog.

| Method | Result (dict keys) / behavior |
| --- | --- |
| `initialize()` | `{created, repository_id, version, restic_version}`. Idempotent: opens and verifies an existing repo. If `expected_repository_id` is set and the repo is missing, raises `REPOSITORY_NOT_FOUND` instead of recreating. |
| `describe()` | `{repository_id, version}`; raises `REPOSITORY_IDENTITY_MISMATCH` if a different repo is present. |
| `list_snapshots()` | list of `{restic_snapshot_id, short_id, time, hostname, tags, managed, snapshot_uuid, instance_uuid, manifest_hash, kind, schema, total_bytes_processed, data_added_packed}` sorted by time. |
| `find_snapshots(snapshot_uuid)` | the subset carrying that UUID tag. |
| `commit(root, snapshot_uuid, captured_at, *, kind="backup", progress=None)` | `{restic_snapshot_id, snapshot_uuid, instance_uuid, manifest_hash, logical_bytes, stored_bytes, stored_copy_verified: True, reconciled, repository_id, verification{exit_status_clean, rediscovered_by_uuid, manifest_readback, tree_matches_inventory, inventory_members, content_hashes_read: False}, discarded_invalid_ids, committed_at, restic_version}`. |
| `read_manifest(restic_id)` | the stored manifest dict (hash it with `core.manifest.manifest_hash`). |
| `restore(restic_id, target, *, expected_manifest_hash=None)` | target must be absent or empty; restores with `restic restore --verify`, then `core.verify_snapshot`. Returns `{restic_snapshot_id, manifest_hash, snapshot_uuid, instance_uuid, restored_bytes_verified, repository_content_verified, inventory_members, logical_bytes, files_restored, bytes_restored, verified_at}`. |
| `check(read_data=False, *, read_data_subset=None)` | `{ok, verification_level: structure|data_subset|full_data, data_read, full_data_verified, read_data_subset, num_errors, broken_packs, suggest_repair_index, suggest_prune, error_code, started_at, finished_at}`. Corruption returns `ok: False, error_code: REPOSITORY_CHECK_FAILED` (it does not raise). Only `full_data_verified: True` may be shown as full data verification. |
| `forget(ids)` | exact full 64-hex IDs only, never a policy. Refuses (`REPOSITORY_OWNERSHIP_MISMATCH`, nothing deleted) if any ID lacks this repository's instance tag. Returns `{requested, removed, already_absent, retained, complete, exit_code, error_code}` computed by re-listing, so a missing delete permission yields an accurate `retained` list (`error_code: STORAGE_DELETE_DENIED` or the classified code). |
| `prune(*, verify=True)` | `{pruned, started_at, finished_at, check}`; physical deletion, then a structural check. |
| `stats()` | `{stored_bytes, uncompressed_bytes, snapshots}`. |
| `remove_stale_locks()` | explicit admin action; `restic unlock` without `--remove-all` (only locks restic deems stale). Never called automatically. |
| `list_keys()`, `add_key(pw)`, `remove_key(id)`, `rotate_password(new, persist, *, remove_old_key=False)` | repository key rotation. `rotate_password` adds a key, proves it opens the repo, calls `persist(new)` (store the new envelope), and keeps the old key unless told otherwise. Returns `recovery_kit_reexport_required: True`. |

Commit semantics (spec §10): before uploading, existing snapshots with the same UUID tag are verified; a valid
one is returned with `reconciled: True` (no duplicate upload after a worker crash). The same UUID with a different
manifest hash raises `SNAPSHOT_IDENTITY_CONFLICT`. A copy is committed only if restic exits 0 with no read errors
or warnings, the new snapshot is rediscoverable by UUID tag, the stored manifest's canonical hash equals the staged
one, and `restic ls` shows exactly the inventory (types and sizes). Exit 3 (partial) still writes a snapshot in
restic, so that exact ID is forgotten and `STORAGE_COMMIT_PARTIAL` is raised. Timeouts raise `STORAGE_TIMEOUT` with
`outcome_ambiguous=True`. Retry by calling `commit` again with the same root, which reconciles first.

The worker must still hold its controller repository lease (ResourceLease) around commit/forget/prune/check.
restic's own locks are never force-removed (`REPOSITORY_LOCKED` is retryable).

Process safety: fresh environment (`PATH=/usr/local/bin:/usr/bin:/bin`, private `HOME`, `TZ=UTC`); password in
`RESTIC_PASSWORD_FILE` (0600 file in a 0700 temp dir, overwritten and removed afterwards); S3 credentials only via
`AWS_*` env; custom CA via `RESTIC_CACERT` file; rclone config via `RCLONE_CONFIG`. Arguments contain only IDs,
fixed flags and paths, never secrets. The environment allowlist rejects `RESTIC_PASSWORD*` and anything unknown.

## 5. Destination configuration (what the server stores and the UI submits)

Store two SecretBox envelopes per destination: the configuration (`configuration_secret_id`) and the credential
(`credential_id`). Run form input through `providers.normalize_destination_input(backend, configuration, credentials)`
(it accepts the UI's current names: `root`→`path`, `addressing_mode`→`bucket_lookup` with `virtual`=`dns`,
`allow_insecure_local`→`development_http`, `root_folder_id`→`folder_id`, and a Drive `client_id` in the
configuration moves into the credential), then `providers.validate_destination(backend, configuration, credential,
destination_id)` before saving. Unknown keys are rejected.

| backend | canonical configuration | credential |
| --- | --- | --- |
| `local` | `{"path": "/var/lib/vaultrewind/backups", "host_path": "<owner host path, display only>", "min_free_bytes": 5368709120, "require_dedicated_mount": true}` | none |
| `s3` | `{"endpoint": "https://s3.eu-west-1.amazonaws.com", "bucket": "...", "prefix": "optional/sub", "region": "eu-west-1", "bucket_lookup": "auto"\|"path"\|"dns", "ca_cert_pem": null, "development_http": false}` | `{"access_key_id": "...", "secret_access_key": "...", "session_token": null}` |
| `drive` (before authorization) | `{"scope": "drive.file"}` (optional `folder_id` only to reattach a folder VaultRewind created earlier in the same Cloud project) | `{"type": "google_drive_client", "client_id", "client_secret"}` |
| `drive` (authorized) | `{"folder_id": "<stable Drive folder ID>", "folder_name": "VaultRewind ...", "scope": "drive.file"}` | `{"type": "google_drive_oauth", "version": 1, "client_id", "client_secret", "scope", "granted_scopes", "token": {"access_token", "token_type", "refresh_token", "expiry"}, "folder_id", "grant_id", "authorized_at"}` |

UI form fields (frontend): local → `path` (default `/var/lib/vaultrewind/backups`; the host path is display-only
from installation settings). S3 → `endpoint` (https URL), `bucket`, `prefix` (default **empty**: the layout already
adds `vaultrewind/`), `region` (default `us-east-1`), addressing `auto|path|dns` (default `auto`), optional custom CA
PEM (textarea), `access_key_id`/`secret_access_key` (password inputs), and a "local development HTTP fixture"
checkbox mapped to `development_http`. Drive → OAuth client ID, client secret (password input), optional
"reattach existing VaultRewind folder ID"; then **Authorize** (browser) or **Headless token import** (password-type
textarea, POST body only). `validate_destination` returns `authorization_required: true` until a folder exists;
repository operations on such a destination raise `STORAGE_AUTHORIZATION_REQUIRED`
(`credential_state: authorization_required`).

Repository records store `location` (from `repository_location`), the password envelope, the restic `repository_id`
returned by `initialize()`, and `physical_identity = providers.physical_identity(backend, configuration, instance_id,
destination_id)`.

## 6. Provider entry points: `vaultrewind.storage.providers`

```python
normalize_destination_input(backend, configuration, credentials) -> (configuration, credential)
validate_destination(backend, configuration, credential=None, destination_id=...) -> dict  # no writes
repository_location(backend, configuration, instance_id, destination_id) -> str
physical_identity(backend, configuration, instance_id, destination_id) -> str  # sha256 hex
with open_repository(backend, configuration, credential, *, instance_id, destination_id, password,
                     repository_id=None, credential_store=None, box=None, work_dir: Path,
                     cancel_event=None, location=None) as repo:   # -> ResticRepository; location = exact
                                                                # recorded location (validated inside destination)
    repo.commit(...)
test_destination(backend, configuration, credential, *, destination_id, credential_store=None, box=None,
                 work_dir) -> dict   # WRITES a probe object and may refresh OAuth tokens; disclose this in UI
```

* `work_dir` is the controller's private state directory (e.g. `/var/lib/vaultrewind/state`); caches, credential
  locks and per-session rclone configs live below it (all 0700).
* **local** (`storage.local`): verifies the path is absolute, normalized, symlink-free, not `/` or a system
  directory, not overlapping protected controller paths, on a persistent supported filesystem (rejects tmpfs,
  overlay, ramfs, CIFS/SMB, …), on a dedicated mount when `require_dedicated_mount` (the default), owner-only
  permissions, enough free space (`min_free_bytes` + estimate), and that the destination identity marker
  `.vaultrewind-destination.json` matches `destination_id` (a missing mount shows up as an empty directory without
  the marker → `LOCAL_MOUNT_MISSING`, nothing is written). The marker is created only by `test_destination` /
  `initialize_local_destination` on first setup. **`recovery_mode` is rejected in operational configuration**
  (including false/null values), at normalization and every provider boundary. Offline tools instead call
  `open_recovery_repository(...)` and `list_recovery_repositories(...)` with the ordinary configuration. These
  factories use `LocalRecoveryDestination.from_path(path, destination_id)` to read a re-mounted old disk,
  skipping new-backup persistence/ownership/space checks while still checking path and marker identity. Local
  initialization and probes reject this recovery capability. Recovery repositories use `--no-lock` and reject
  init, commit (including safety), forget, prune, unlock and key changes with `STORAGE_READ_ONLY`. Their
  `durable_for_safety` property is false; destination evidence also has `backup_ready: false` and
  `retention_ready: false`. They cannot provide safety durability evidence. Results include `warnings` such as "local copies alone do not
  survive loss of the controller disk".
* **s3** (`storage.s3`): HTTPS required (HTTP only with `development_http: true` and a loopback, private-IP or
  single-label host such as a Compose `minio` service). Optional custom CA bundle (PEM validated). `bucket_lookup`
  maps to restic `-o s3.bucket-lookup`. The probe uses boto3 within `<prefix>/vaultrewind/.probe/<uuid>/` with
  restic-shaped keys (`locks/`, `snapshots/`, `data/`) and reports `list`, `write`, `read`, `delete` plus
  `delete_classes`, `backup_ready` and `retention_ready`. Live finding: with the delete-restricted STS credentials a
  flat probe reported delete OK while `forget` got AccessDenied on `snapshots/`; the shaped probe now reports
  `retention_ready: false`. `forget`'s relisting remains the authoritative deletion outcome.
* **drive** (`storage.drive`): restic rclone backend with a per-session private writable rclone config. See §7.

## 7. Google Drive

Scope: `https://www.googleapis.com/auth/drive.file` (least privilege; the app sees only files it created).
Consequence: recovery must use an OAuth client from the **same Google Cloud project**; the recovery kit therefore
stores the client ID/secret. Personal My Drive is supported; shared drives are rejected (untested).

Server integration as implemented (live note): the server keeps its own single-use OAuth state rows and PKCE
verifier secrets and runs the code exchange in a `drive_exchange` worker job. For that architecture use

```python
from vaultrewind.storage.drive import GoogleClient, exchange_authorization_code
finalized = exchange_authorization_code(GoogleClient(client_id, client_secret), code, verifier,
                                        settings.public_origin + settings.drive_redirect_path,
                                        destination_id=dest.id, existing_folder_id=config.get("folder_id"),
                                        folder_name=config.get("folder_name"), http=httpx.Client(trust_env=False))
# then replace the credential with finalized["credential"] and the configuration with finalized["configuration"]
```

instead of importing the private `_finalize`. It requires a refresh token in the exchange response and requests
offline access with `prompt=consent`; a missing token blocks setup rather than silently reusing a token from
a previous grant. The scrubber must be the
outermost middleware (`app.add_middleware(OAuthCallbackScrubber, ...)` is fine as long as no earlier middleware logs
the URL). The session cookie must be `SameSite=Lax` (not `Strict`), or the top-level redirect back from Google
arrives without the session and fails the session binding.

Alternatively, ``DriveAuthorization`` bundles state, PKCE and exchange for single-process use:

Guided browser flow (Web application OAuth client created by the owner, redirect URI
`<public origin>/api/v1/oauth/drive/callback`):

```python
auth = DriveAuthorization(box, state_store, public_origin="https://vaultrewind.example",
                          callback_path="/api/v1/oauth/drive/callback", http=None)
start = auth.begin(destination_id, session_id, GoogleClient(client_id, client_secret), purpose="authorize")
# -> {"authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...", "expires_at": "..."}
# Browser navigates there (top-level). The URL contains client_id/state/PKCE challenge only, never secrets.
result = auth.complete(request_origin=<scheme://host of the callback request>, params=callback_params(request),
                       session_id=session_id, existing_folder_id=<configured folder or None>,
                       folder_name="VaultRewind <destination name>")
# -> {"credential": <credential dict>, "configuration": {"folder_id", "folder_name", "scope"},
#     "destination_id": ..., "granted_scopes": [...]}
```

* `state_store` implements `AuthorizationStateStore` (`put`, `consume`). Server implementation must be atomic,
  e.g. table `oauth_authorizations(state_hash PK, destination_id, session_binding, redirect_uri,
  verifier_envelope, client_envelope, purpose, created_at, expires_at, consumed_at)` and
  `UPDATE … SET consumed_at=now() WHERE state_hash=:h AND consumed_at IS NULL RETURNING *` (then reject if
  expired). `InMemoryAuthorizationStateStore` exists for tests/single process.
* State is single use, expires after 10 minutes, and is bound to `sha256(session_id)` and the destination.
  `complete` requires the callback origin to equal the configured public origin (`OAUTH_ORIGIN_MISMATCH`),
  rejects `error=` responses (`OAUTH_DENIED`), exchanges the code with PKCE (S256), requires a refresh token and
  the `drive.file` scope, and creates the destination folder (or verifies the existing `folder_id` is reachable and
  not trashed; `DRIVE_FOLDER_UNAVAILABLE` on reconnect with a different account). Reconnect keeps the same folder.
* Advanced headless import: show `headless_instructions(client_id)` (no secrets; uses `read -rs` and
  `RCLONE_DRIVE_CLIENT_SECRET`/`RCLONE_DRIVE_SCOPE` env vars with `rclone authorize drive`, verified with
  rclone 1.75.2). The owner pastes rclone's token JSON into a password-type form field (POST body only), then
  `import_headless_token(GoogleClient(...), token_json, destination_id=..., existing_folder_id=None, folder_name=...)` validates it by
  refreshing against Google, checks scopes, creates/verifies the folder and returns the same structure as `complete`.
* `revoke(credential)` revokes the refresh token at Google (form body, not URL).

Rotated tokens: `open_repository`/`test_destination` for Drive need `credential_store` implementing

```python
class CredentialStore(Protocol):
    state_directory: Path   # persistent private directory, OUTSIDE disposable job/staging trees
    def load(self, destination_id) -> StoredCredential | None  # StoredCredential(envelope, revision, generation)
    def compare_and_swap(self, destination_id, envelope, expected_revision,
                         *, expected_generation=None) -> int              # new revision; raises
                                                                         # VaultRewindError("CREDENTIAL_STALE") on mismatch
```

Server implementation: lock and re-read the destination's current credential row, check both its ID
(`generation`) and revision, then update it. Deleting/recreating a credential must generate a new identity even
if its revision resets to 1. Never recreate a missing credential from a pending refresh. `FileCredentialStore`
implements the same contract, with a random generation persisted alongside the encrypted envelope.

Before writing a usable config, the session fsyncs an **encrypted session provenance record** under
`credential_store.state_directory/sessions/`. It contains the destination/grant, credential record generation,
base revision/token, session UUID, config settings fingerprint and private workspace identity (absolute path,
device/inode/owner). No provider process can start before registration and the initial config are durable.
The session writes a 0600 rclone config in that registered 0700 directory (rclone must be able to rewrite it), runs restic/rclone, then
**first fsyncs an encrypted pending update** under `credential_store.state_directory/pending/`. Only after this
recoverable copy exists may transient rclone scratch be scrubbed following a database failure. Encrypted
pending envelopes are authenticated to their destination and filename. Under a per-destination `flock`, it
reloads the current credential and performs up to three revision/generation-aware CAS attempts, checking grant,
OAuth client, folder, scope and refresh-token lineage on each retry. Later access expiry orders updates sharing
a refresh token; a rotated refresh token is retained even when access expiry did not advance. Divergent rotated
refresh tokens cannot be ordered safely by expiry: preserve the encrypted candidate and require a fresh grant.
Deleted/replaced grants and explicit `revoked`/`revoked_at` tombstones invalidate old updates without reviving
them. Pending updates are replayed before opening the next session; a lost commit acknowledgment reconciles
without another revision bump. Applied or proven superseded entries are removed with directory fsync.

**Abrupt process death before sync:** the next `DriveCredentialSession` recovers registered orphan configs before
loading credentials for another operation. The stable session registry locates old configs even when the new job
uses a different runtime directory. A per-session `flock` excludes active contexts; a bounded Linux `/proc` check
for the exact registered `RCLONE_CONFIG` prevents recovery racing a restic/rclone process that survived its owner.
Busy/uncertain writers yield `CREDENTIAL_PERSIST_FAILED` with `persistence_error_code: CREDENTIAL_SESSION_BUSY`.

Recovery does not scan arbitrary config files. It authenticates the sealed record, traverses the recorded path
without following symlinks, verifies the directory's device/inode/owner and 0700 mode, and requires a regular
0600 owner-only config with one hardlink. Reads are bounded to 64 KiB, session scans to 128 records per destination
(4096 directory entries), and cleanup to 16 config files. Non-token config settings must match the original
fingerprint, while replacement of the config inode itself is permitted for rclone's atomic rewrites. Unregistered
configs are untouched. Invalid identity/settings, replaced or linked files, and missing ready configs fail closed
with `CREDENTIAL_SESSION_UNSAFE`/`CREDENTIAL_SESSION_MISSING` as the persistence code; preserve them for review.

The orphan candidate is encrypted and fsynced into the pending outbox **before** its plaintext config is scrubbed,
even if SQL is down. Existing grant/generation/revision/lineage checks then govern replay; recovery cannot revive
revoked/deleted grants or overwrite a reconnect. Prepared/ready/finalized metadata makes registration and cleanup
crash-recoverable. Explicit mid-session `sync()` checkpoints the token lineage. A normal exit removes the config,
session metadata and lease; encrypted metadata is never a normal long-term plaintext-token storage mechanism.

`CREDENTIAL_PERSIST_FAILED` always surfaces, including when the repository operation also failed. Its details
contain `pending_recovery_required`, `cleanup_blocked`, `pending_encrypted`, `persistence_error_code` and
`operation_error_code` (codes only). `CREDENTIAL_REFRESH_CONFLICT` or `CREDENTIAL_REFRESH_UNREADABLE` as the
persistence code requires a new grant;
other transient failures can retry after the store recovers. Do not delete pending updates. If even the encrypted
journal cannot be written, cleanup is blocked and the sole transient config is retained rather than destroying
the only refreshed token. Resolve local storage immediately; this is not a successful cleanup or a normal token
storage mode. The worker must preserve that job directory, including from expiry cleanup.

Provider stores should expose a stable `state_directory` outside per-job staging; otherwise sessions fall back
to their supplied `lock_dir`. `credentials.has_pending_credentials(root)` is a cleanup guard for fallback trees;
`credentials.has_unrecovered_drive_sessions(root)` detects the separate encrypted session registry. Neither
registry nor referenced `rclone.conf` files may be removed by staging/cache expiry. Existing server recursive
`rclone.conf` cleanup guards protect old per-job runtime trees; keep the SQL store's global state directory on
the persistent controller volume. API signatures and SQL CAS hooks are unchanged by abrupt-death recovery.
Never make cleanup decisions solely from a repository-operation error that preceded credential finalization.
Controller master-key rotation must retain keys needed by pending **and session** envelopes until recovery finishes.

Offline tools call `credentials.open_recovery_credentials(work_dir) -> (SecretBox, FileCredentialStore)`. It
creates a persistent 0600 random key at `work_dir/recovery-credentials/master.key` and a private encrypted store;
symlinks and permissive existing state/key modes are rejected. The helper never replaces a missing key when
encrypted state remains. Reuse stored credentials across sessions, preserving rotations instead of reseeding an
old kit token. A credential override/reconnect must deliberately establish a new grant. Keep this directory and
its key until pending updates are reconciled. No OAuth token is stored in plaintext there.

Credential states for the UI: `classify_credential_state(error_code)` →
`reconnect_required` (revoked, expired, or a Testing-mode consent that expired after 7 days), `quota_exceeded`,
`rate_limited`, `credentials_invalid`, `folder_unavailable`.

## 8. Recovery kit and offline recovery: `vaultrewind.recovery`

```python
from vaultrewind.recovery.kit import build_recovery_kit, seal_recovery_kit, open_recovery_kit
contents = build_recovery_kit(controller_id=..., recovery_root_secret=..., destinations=[...],
                              repositories=[...], instances=[...])
blob: bytes = seal_recovery_kit(contents, passphrase)      # Argon2id + AES-256-GCM; independent of master key
kit: dict = open_recovery_kit(blob, passphrase)
```

* `destinations[]`: `{"destination_id", "backend", "name", "configuration": <§5 dict>, "credential": <§5 dict or None>}`.
* `repositories[]`: `{"repository_id": <catalog id>, "restic_repository_id", "instance_id", "destination_id",
  "location", "password"}`; `instances[]`: `{"instance_id", "name"}`.
* The passphrase arrives only in the export request body (min. 12 characters), is held in encrypted private job
  input until consumed and then replaced with a consumed marker, and the file is
  returned as an attachment with `Cache-Control: no-store`. Never send kits through notifications.
* `POST /recovery/import-plans`: `offline.discover(kit, work_dir=...)` then `offline.import_plan(discovery)` →
  protected-mode plan: every discovered snapshot is listed with `protect: "imported_review"`, retention disabled,
  future-dated snapshots flagged, UUID collisions with differing manifest hashes reported as conflicts, and no
  deletions implied by missing catalog rows.
* Offline CLI (no controller, no database, no master key): `python -m vaultrewind.recovery --help`
  (`inspect`, `discover`, `restore`, `plan`, `import-plan`). Passphrases come from a prompt or
  `--passphrase-file`, never arguments.

## 9. Error codes (stable)

`REPOSITORY_NOT_FOUND`, `REPOSITORY_LOCKED` (retryable), `REPOSITORY_PASSWORD_INVALID`,
`REPOSITORY_IDENTITY_MISMATCH`, `REPOSITORY_OWNERSHIP_MISMATCH`, `REPOSITORY_BACKEND_UNSUPPORTED`,
`STORAGE_COMMIT_PARTIAL`, `STORAGE_COMMIT_UNVERIFIED`, `SNAPSHOT_IDENTITY_CONFLICT`, `STORAGE_TIMEOUT`
(retryable, `outcome_ambiguous`), `STORAGE_OPERATION_CANCELLED`, `STORAGE_AUTH_EXPIRED`, `STORAGE_CLIENT_INVALID`,
`STORAGE_QUOTA_EXCEEDED`, `STORAGE_RATE_LIMITED` (retryable), `STORAGE_CREDENTIALS_INVALID`,
`STORAGE_BUCKET_NOT_FOUND`, `STORAGE_PERMISSION_DENIED`, `STORAGE_TLS_FAILED`, `STORAGE_TLS_REQUIRED`,
`STORAGE_UNREACHABLE` (retryable), `INSUFFICIENT_SPACE`, `STORAGE_DELETE_DENIED` (in `forget` result),
`REPOSITORY_CHECK_FAILED` (in `check` result), `MANIFEST_MISMATCH`, `MANIFEST_HASH_MISMATCH`, `MANIFEST_MISSING`,
`RESTORE_TARGET_NOT_EMPTY`, `LOCAL_MOUNT_MISSING`, `LOCAL_PATH_UNSAFE`, `LOCAL_FILESYSTEM_UNSUPPORTED`,
`LOCAL_PERMISSIONS_UNSAFE`, `OAUTH_STATE_INVALID`, `OAUTH_SESSION_MISMATCH`, `OAUTH_ORIGIN_MISMATCH`,
`OAUTH_DENIED`, `OAUTH_NO_REFRESH_TOKEN`, `OAUTH_SCOPE_INSUFFICIENT`, `DRIVE_FOLDER_UNAVAILABLE`,
`DRIVE_SHARED_DRIVE_UNSUPPORTED`, `CREDENTIAL_STALE`, `CREDENTIAL_PERSIST_FAILED`, `RECOVERY_KIT_INVALID`,
`RECOVERY_KIT_PASSPHRASE_INVALID`, `RECOVERY_PASSPHRASE_WEAK`, `SECRET_DECRYPT_FAILED`, `SECRET_KEY_UNAVAILABLE`,
`STORAGE_AUTHORIZATION_REQUIRED`, `OAUTH_REDIRECT_MISMATCH`, `LOCAL_PATH_OVERLAP`, `LOCAL_DESTINATION_MISMATCH`,
`STORAGE_READ_ONLY`, `REPOSITORY_LOCATION_INVALID`, `SNAPSHOT_COPY_UNAVAILABLE`, `TARGET_PROFILE_REQUIRED`,
`RECOVERY_INPUT_UNSAFE`, `CREDENTIAL_LOCK_TIMEOUT` (retryable).

## 10. Verification status

Command (repository root, pinned restic 0.19.1/rclone 1.75.2 installed, synthetic MinIO fixture on
`127.0.0.1:19000` with credentials read from `.runtime/minio/*.json`, never printed):

```sh
.venv/bin/python -m pytest tests/unit/test_storage_secrets.py tests/unit/test_storage_restic.py \
  tests/unit/test_storage_local.py tests/unit/test_storage_s3.py tests/unit/test_storage_drive.py \
  tests/unit/test_storage_recovery.py tests/unit/test_storage_drive_live.py -q -rs
```

Recorded result (2026-10-25): **138 passed, 4 skipped** in 218 s; the 4 skips are the live Google Drive harness (no credentials supplied yet). Ruff is clean for all storage/security/recovery code and tests. What the suites prove:

* **Real restic 0.19.1** (local repositories): init/open idempotency and identity binding; commit with UUID tags,
  manifest readback and tree/inventory comparison; crash reconciliation by UUID (no duplicate upload); same-UUID
  conflict detection; distinct logical snapshots for identical content (AC02 storage side); verified restore;
  `check --read-data`; exact-ID forget and prune; repository key rotation. A required file unreadable to restic
  (root with `CAP_DAC_*` dropped via `setpriv`) yields exit 3 → `STORAGE_COMMIT_PARTIAL`, the partial snapshot is
  forgotten, and live permissions are untouched (AC17 storage side). Corrupting a pack passes the structural check
  but fails `--read-data` and restore (AC29).
* **Real MinIO** (S3 backend): permission probe, backup → verified restore → full data check → forget → prune →
  repository discovery; invalid secret → `STORAGE_CREDENTIALS_INVALID`; missing bucket → `STORAGE_BUCKET_NOT_FOUND`;
  delete-restricted STS credentials → `forget` reports the copy as retained (`STORAGE_DELETE_DENIED`, AC13
  storage side) and the probe reports `retention_ready: false`.
* **Real rclone 1.75.2**: an expired Drive token is refreshed by rclone against a local fake token endpoint,
  written back to the private config, and persisted encrypted by the session with a revision bump. restic's rclone
  backend completes a full round trip over an rclone `local` remote, using the same `RCLONE_CONFIG` and
  `rclone.program` plumbing that Drive uses.
* **Deterministic**: OAuth begin/complete (PKCE S256, exact redirect, client secret only in the POST body, single-use
  session-bound state, origin check, denied/insufficient-scope/no-refresh-token grants, folder creation and
  reconnect verification, shared drives rejected), headless import, revocation in the POST body, concurrent-session
  stale-write rejection, reconnect-wins, persist-failure reporting, environment isolation (no inherited
  variables, password only in a 0600 temporary file, never in argv), and a real uvicorn access log that never
  contains the callback `code`/`state`.
* **Recovery**: Argon2id/AES-GCM kit round trip with default parameters, tamper/version/bounds/weak-passphrase
  rejection. Controller-loss drill: real local and MinIO repositories, kit exported, controller state and master
  key deleted; discovery (including a repository created after the export, opened by derived password),
  protected import plan, verified restore, target plan with secrets redacted (AC30 storage side). Equivalent-copy
  fallback after corrupting one copy; the CLI end to end with the passphrase from a 0600 file (a 0644 file is
  refused).

**Historical scope of that run:** no real Google account was used. The opt-in adapter harness
`tests/unit/test_storage_drive_live.py` (`-m live_drive`) remains available, but its cases were not executed in
the broad unit suite. It needs private dedicated-account files and a separate writable credential store; do
not run it concurrently against an active controller grant.

The later owner-authorized SQL-backed controller/worker drills establish actual Google behavior through
[matched live release evidence](evidence/drive-release.json): authorization, encrypted refresh persistence,
complete backup/readback, alternate application restore, exact retention, revocation and Reconnect, plus a
required-copy failure and same-snapshot retry. The aggregate binds completed reports rather than treating
the skipped adapter tests as evidence. Its limits preserve the lack of authenticated vault login, natural
seven-day expiry and real Google quota-exhaustion claims.

Safety follow-up (2026-10-25):

```sh
.venv/bin/python -m pytest tests/unit/test_storage_local.py tests/unit/test_storage_drive.py \
  tests/unit/test_storage_credential_recovery.py -q
```

**89 passed in 32.47 s**. Provider-boundary tests reject operational recovery flags before writes; a real
restic markerless-old-copy restore succeeds through the explicit read-only factory and every repository
mutation (including safety commit and restore output overlapping the repository) is blocked. Credential tests
prove encrypted journal preservation, replay in a fresh Python process with a persistent private key, revision
and generation CAS races, refresh-token rotation without later access expiry, lost acknowledgment, key rotation,
revocation/reconnect boundaries, conflicting rotations, malformed config preservation and storage fault recovery.
The real-rclone token test uses a local synthetic endpoint plus a refusing proxy, so it never contacts live Drive.

The broader secrets/restic/local/S3/Drive/credential/recovery run passed **168 tests, 4 deselected in 145.37 s**.
MinIO integration cases were deselected and the optional MinIO recovery branch disabled in that test process,
avoiding shared-fixture writes; this run adds no new live S3 or Google evidence. Ruff passed for storage/security
and the modified tests. If both encrypted journal and credential-store writes are unavailable, the tested
emergency path blocks cleanup until a durable encrypted copy can be made; it never deletes the only rotated token.

Abrupt-death follow-up (2026-10-25): the combined secrets, Drive, credential-recovery and new
`tests/unit/test_storage_drive_crash.py` suite, plus the supplied
`test_worker_death_before_exit_replays_rotated_config` review repro, passed **98 tests in 25.32 s**. The new crash
suite alone passed **25 tests in 6.23 s**. Its actual-rclone proof refreshes and rotates the token against a local
synthetic OAuth endpoint behind a refusing external proxy, kills the owner with SIGKILL before any sync, then
opens a fresh Python process with a different job runtime and proves the encrypted credential revision advances
and the orphan config is scrubbed. No external Drive or shared MinIO/source fixture operations were performed.
Additional tests cover active-session leases, lingering providers, revocation/reconnect/generation boundaries,
prepared/ready/finalized interruption points, explicit-sync lineage, unavailable persistence, missing configs,
tampered metadata/settings, symlinks, directory replacement, hardlinks, permission/size bounds and unregistered
configs. The original supplied Drive abrupt-exit repro now passes without changing its assertions.

# Recovery kit and offline disaster recovery

VaultRewind must be recoverable after the controller, its PostgreSQL database and its master key are all lost.
The **recovery kit** makes that possible: it is encrypted only with a passphrase you hold, and the offline
recovery tool needs nothing else besides the kit, access to your storage and the standard restic/rclone binaries.

## What the kit contains

The encrypted contents (JSON, schema 1):

* repository locations, restic repository IDs and each repository's unlock password
* the **recovery root secret**, from which per-repository passwords are derived. Repositories created *after* the
  kit was exported can still be opened, as long as their password was never rotated.
* destination settings and the provider credentials valid at export time: S3 endpoint/bucket/prefix/region/CA plus
  access key; Google Drive OAuth client ID/secret, refresh token and folder ID; local mount path
* instance IDs and names, the manifest schema (canonical tree, tags, hash rule) and pinned tool versions
* step-by-step recovery instructions for general use and for each provider in use

The kit does **not** contain SSH keys, the controller master key, vault data or user master passwords.

## Encryption

Argon2id (argon2-cffi; default 256 MiB memory, 4 passes, 4 lanes, 16-byte random salt) derives a 256-bit key from
the passphrase. AES-256-GCM encrypts the contents, and the whole visible header (format, version, KDF parameters,
salt, nonce, kit ID) is authenticated, so any change to it makes decryption fail. KDF parameters outside safe
bounds are refused before any hashing. The passphrase must be at least 12 varied characters. The kit file is
created with mode 0600 and never overwrites an existing file.

## Handling rules

* Export it (Recovery kit page, or `POST /api/v1/recovery-kits/export`) as an administrator. The passphrase is
  sent only in the request body and held in encrypted private job input until the background export consumes it;
  the input is then replaced with a consumed marker. The file is downloaded with `Cache-Control: no-store`.
* Keep the kit **and** its passphrase outside both Vaultwarden and VaultRewind, for example a printed passphrase in
  a safe and the file on offline media. Never store the only copy inside the vault being protected, and never send
  it by email or webhook.
* Export a new kit after adding an S3 or Drive destination (so its credentials are included), after rotating
  provider credentials or a repository password (the UI flags `recovery_kit_reexport_required`), and after
  enrolling instances whose repositories use random rather than derived passwords.

## Fresh-controller recovery drill

The automated drill (`tests/unit/test_storage_recovery.py::test_controller_loss_drill_kit_only_discovery_import_restore_and_plan`)
creates real restic repositories on a local disk and, when available, the MinIO fixture. It exports a kit, then
deletes the controller state directory and master key. After that it discovers, imports, restores and plans using
only the kit. To do the same by hand:

1. On a clean Linux machine, install Python 3.13 with the `vaultrewind` package, plus restic 0.19.1 and rclone 1.75.2
   (checksums in `tools/binaries.lock.json`). A full controller install also works.
2. Reattach storage: mount the old local backup disk, or make sure the bucket or Google account is reachable.
3. Put the passphrase in an owner-only file, or omit `--passphrase-file` to be prompted:

   ```sh
   install -m 600 /dev/null ~/kit.pass && "${EDITOR:-vi}" ~/kit.pass
   ```

4. Inspect the kit (shows no secrets):

   ```sh
   python -m vaultrewind.recovery inspect --kit owner.vrkit --passphrase-file ~/kit.pass
   ```

5. Discover snapshots (reads manifests and checks each against its tag hash):

   ```sh
   python -m vaultrewind.recovery discover --kit owner.vrkit --passphrase-file ~/kit.pass --work-dir ~/vr-work \
     [--local-path <destination_id>=/mnt/old-backups] [--credentials-file ~/replacement-credentials.json]
   ```

6. Restore one snapshot into a new, empty directory. restic verifies the restored bytes, then every file hash,
   link and the SQLite database are checked against the manifest. If one copy is damaged or unreachable, the tool
   tries other copies of the **same** snapshot (same manifest hash) and never a different date:

   ```sh
   python -m vaultrewind.recovery restore --kit owner.vrkit --passphrase-file ~/kit.pass --work-dir ~/vr-work \
     --snapshot <snapshot UUID> --target ~/restored
   ```

7. Generate the target deployment plan. It executes nothing; it validates the descriptor fingerprint and image
   archive hash, lists environment variables with secret values redacted, the mounts, ports, network, external
   prerequisites and required substitutions:

   ```sh
   python -m vaultrewind.recovery plan --restored ~/restored --target-profile target.json   # or --same-instance
   ```

   `target.json` example: `{"public_url": "https://vault-dr.example.org", "network": "proxy",
   "port_bindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}}`. Restoring under another identity
   without `public_url` is a blocking issue (`TARGET_PROFILE_REQUIRED`).

8. Recreate service through VaultRewind, not by hand: install a fresh controller, import the kit (step 9), enroll
   the prepared target host (helper activation), then choose **Restore to another server** (or the original
   instance). The helper stages the snapshot, verifies the saved image, validates the candidate in isolation, and
   only then activates it. Replacing an existing instance creates a pinned safety snapshot first. VaultRewind never
   changes DNS or proxy routes.

9. Import into the fresh controller (Recovery → Import, or `POST /api/v1/recovery/import-plans`). To preview offline:

   ```sh
   python -m vaultrewind.recovery import-plan --kit owner.vrkit --passphrase-file ~/kit.pass --work-dir ~/vr-work \
     --output ~/import-plan.json
   ```

   The plan is **protected mode**: automatic deletion is disabled, every imported snapshot is protected with
   `imported_review` (safety snapshots also with `safety`), future-dated snapshots are flagged and do not move
   retention cutoffs, a UUID present with two different manifest hashes is reported as a conflict, and the plan
   never contains deletions. Missing catalog rows never imply deleting repository snapshots. The plan file has
   no secrets; the controller takes passwords and credentials from the kit during import.

## Replacing provider credentials during recovery

`--credentials-file` points to an owner-only (0600) JSON file keyed by destination ID. Its fields are merged over
the kit's stored credential:

* **S3**: `{"<destination_id>": {"access_key_id": "...", "secret_access_key": "..."}}`. Create a key limited to the
  bucket prefix if the exported key was rotated or revoked.
* **Google Drive**: `{"<destination_id>": {"token": { ...JSON from rclone authorize... }}}`. Run the headless
  procedure from [STORAGE.md](STORAGE.md#advanced-headless-authorization) with the **same OAuth client** stored in
  the kit (`inspect` shows which destinations include credentials). `drive.file` only lets clients from the same
  Google Cloud project see the folder. If that project is gone, download the folder through Google Drive's web
  interface and use the download as a local destination copy (`--local-path`).
* **Local disk**: no credential. If the disk is mounted somewhere else, use `--local-path <destination_id>=<path>`.
  The offline recovery factory skips ownership, permission, filesystem and free-space checks meant for new
  backups. The identity marker must still match if present. Repository reads use `--no-lock`, supporting a
  read-only mounted old copy. This recovery capability cannot initialize, probe, commit, delete, prune, unlock
  or change repository keys and cannot satisfy safety-snapshot durability. `recovery_mode` is not accepted in
  normal destination settings.

Offline Drive recovery keeps a private `recovery-credentials` directory under `--work-dir`, with a 0600 random
encryption key, an encrypted credential store, and encrypted pending token updates. Keep this directory across
retries: a refresh token may rotate and make the older recovery-kit token unusable. Never reseed an old kit
token over a stored rotation. If persistence fails, `CREDENTIAL_PERSIST_FAILED` requires preserving credential
state and retrying after the local store recovers. The next session replays pending updates before using Drive.
The kit seeds only an empty credential store. Reopening a work directory without an override always retains
its stored authorization, including a fresh grant previously supplied with `--credentials-file`. Repeating that
same override retains later rotations too. Replacing authorization requires an explicit changed credentials
file; merely selecting another kit cannot establish which of two independent grants is newer.
Encrypted session metadata is registered before rclone starts. If a worker is killed after rewriting its private
config but before saving the new token, the next session locates that registered config, verifies its provenance,
saves the recovered token encrypted and scrubs the plaintext file before replay. Keep both the credential-state
directory and old job runtime directories until recovery completes. A surviving provider process temporarily
blocks replay; an unsafe or missing registered config requires review rather than silently reusing an old token.
A conflicting pair of independently rotated refresh tokens requires explicit reconnect with a fresh grant;
old pending updates never overwrite a new or revoked grant. Retain old decryption keys until pending updates
are reconciled, and export a new recovery kit when provider credentials change.

## Limitations

* Repositories whose password was rotated after the kit was exported, or that use a random password and were
  created after the export, need a newer kit.
* Offline recovery restores to a local directory and produces a plan. Activating a recovered instance on a server
  always goes through the enrolled helper; there is no manual overwrite mode.
* [Dedicated live Drive evidence](evidence/drive-release.json) now proves full byte recovery and actual alternate
  activation using the controller's current grant, including historical access after private UI Reconnect.
  The kit-only fresh-controller application drill uses local storage; no live Drive kit-only controller-loss
  rehearsal is claimed. Persistent offline credential replay has separate deterministic/real-rclone coverage.
